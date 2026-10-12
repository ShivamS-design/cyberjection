"""SafeTensors-only enforcement, strict header validation, and SHA-256
integrity verification.

SafeTensors is safe to *load* because its format is data-only: an 8-byte
little-endian header length, a JSON header mapping tensor names to
`{dtype, shape, data_offsets}`, then raw bytes. There is nothing to
execute. That only holds if the file really is well-formed, so
`validate_safetensors_header` re-implements the reference loader's own
checks (header size ceiling, JSON object, known dtypes, offsets that tile
the data buffer exactly with no gaps, overlaps or trailing bytes) and adds
two the reference loader doesn't make:

- **Duplicate JSON keys.** Different JSON parsers keep the first or the
  last duplicate, so a file can present different tensors to different
  tools -- a parser-differential smuggling channel. Rejected.
- **Non-whitespace header padding.** The header may be space-padded for
  alignment; anything else in the padding is hidden payload space.

Validation needs only the header bytes, so remote files are checked with
two HTTP Range requests rather than a full download (see
`cyberjection.hubguard.client`).

Integrity has three tiers, each optional and each stricter than the last:
the Hub's own LFS SHA-256 claim compared against an enterprise
`HashManifest` (no download); the actual bytes streamed through SHA-256
and compared against both (`verify_downloads`); and Git blob SHA-1
verification of every small file HubGuard fetches anyway (`git_blob_sha1`).
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import IO, Any, Dict, Iterable, List, Optional, Tuple, Union

import yaml
from pydantic import BaseModel, Field, field_validator

from cyberjection.hubguard.models import FindingCategory, HubFinding, Severity

MAX_HEADER_BYTES = 100_000_000  # the reference implementation's own ceiling
_SHA256_HEX_LEN = 64

# dtype -> bits per element (sub-byte float formats included).
DTYPE_BITS: Dict[str, int] = {
    "BOOL": 8,
    "U8": 8,
    "I8": 8,
    "F8_E5M2": 8,
    "F8_E4M3": 8,
    "F8_E8M0": 8,
    "I16": 16,
    "U16": 16,
    "F16": 16,
    "BF16": 16,
    "I32": 32,
    "U32": 32,
    "F32": 32,
    "I64": 64,
    "U64": 64,
    "F64": 64,
    "C64": 64,
    "F4": 4,
    "F6_E2M3": 6,
    "F6_E3M2": 6,
}

SAFE_WEIGHT_EXTENSIONS = frozenset({".safetensors", ".gguf", ".onnx", ".msgpack", ".tflite"})
PICKLE_WEIGHT_EXTENSIONS = frozenset({".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".dill", ".npy", ".npz", ".pdparams", ".mar"})
CODE_CAPABLE_WEIGHT_EXTENSIONS = frozenset({".h5", ".keras", ".hdf5", ".pb"})


class EnforcementLevel(str, Enum):
    """How a repository's weight formats are policed.

    - `OFF`: formats are recorded, nothing is flagged.
    - `WARN`: pickle-format weights are MEDIUM findings.
    - `STRICT`: pickle-format weights are blocking HIGH findings, and a
      repository with no SafeTensors weights at all is blocked.
    """

    OFF = "off"
    WARN = "warn"
    STRICT = "strict"


class WeightFormat(str, Enum):
    SAFETENSORS = "safetensors"
    SAFE_OTHER = "safe_other"
    PICKLE = "pickle"
    CODE_CAPABLE = "code_capable"
    NOT_WEIGHTS = "not_weights"


def classify_weight_file(path: str) -> WeightFormat:
    suffix = Path(path).suffix.lower()
    name = Path(path).name.lower()
    if suffix == ".safetensors":
        return WeightFormat.SAFETENSORS
    if suffix in SAFE_WEIGHT_EXTENSIONS:
        return WeightFormat.SAFE_OTHER
    if suffix in PICKLE_WEIGHT_EXTENSIONS:
        # `training_args.bin`, `optimizer.pt` etc. are pickles too -- the
        # format matters, not the role.
        return WeightFormat.PICKLE
    if suffix in CODE_CAPABLE_WEIGHT_EXTENSIONS or name == "saved_model.pb":
        return WeightFormat.CODE_CAPABLE
    return WeightFormat.NOT_WEIGHTS


@dataclass(frozen=True)
class TensorInfo:
    name: str
    dtype: str
    shape: Tuple[int, ...]
    begin: int
    end: int

    @property
    def numel(self) -> int:
        count = 1
        for dim in self.shape:
            count *= dim
        return count


@dataclass
class SafetensorsHeader:
    header_size: int
    data_size: int
    tensors: Dict[str, TensorInfo] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)
    findings: List[HubFinding] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not any(f.severity.rank >= Severity.HIGH.rank for f in self.findings)

    @property
    def data_start(self) -> int:
        return 8 + self.header_size


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    seen: Dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateKeyError(key)
        seen[key] = value
    return seen


def read_header_length(prefix: bytes) -> int:
    if len(prefix) < 8:
        raise ValueError("file shorter than the 8-byte header-length prefix")
    return int(struct.unpack("<Q", prefix[:8])[0])


def validate_safetensors_header(header_bytes: bytes, *, file_size: int, label: str = "<file>") -> SafetensorsHeader:
    """Validates a SafeTensors header. `header_bytes` is the JSON header
    *without* the 8-byte length prefix; `file_size` is the whole file's
    size, used to check the data buffer is exactly tiled."""

    header_size = len(header_bytes)
    data_size = file_size - 8 - header_size
    result = SafetensorsHeader(header_size=header_size, data_size=max(data_size, 0))

    def fail(rule: str, message: str, severity: Severity = Severity.HIGH) -> SafetensorsHeader:
        result.findings.append(
            HubFinding(
                rule_id=f"safetensors.{rule}",
                category=FindingCategory.SAFETENSORS,
                severity=severity,
                description=f"Malformed SafeTensors file: {message}",
                file=label,
                remediation="Re-export the weights with the reference `safetensors` library and verify their hash.",
            )
        )
        return result

    if header_size > MAX_HEADER_BYTES:
        return fail("header_too_large", f"header is {header_size} bytes (limit {MAX_HEADER_BYTES})")
    if data_size < 0:
        return fail("truncated", "declared header extends past end of file")
    try:
        text = header_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return fail("not_utf8", "header is not valid UTF-8")
    if not text.startswith("{"):
        return fail("not_object", "header does not start with '{'")
    stripped = text.rstrip(" ")
    if not stripped.endswith("}"):
        return fail("bad_padding", "header padding contains non-space bytes after the JSON object")
    try:
        parsed = json.loads(stripped, object_pairs_hook=_reject_duplicates)
    except _DuplicateKeyError as exc:
        return fail("duplicate_key", f"duplicate JSON key `{exc}` (parser-differential smuggling risk)")
    except (json.JSONDecodeError, RecursionError) as exc:
        return fail("bad_json", f"header is not valid JSON ({exc})")
    if not isinstance(parsed, dict):
        return fail("not_object", "header JSON is not an object")

    metadata = parsed.pop("__metadata__", None)
    if metadata is not None:
        if not isinstance(metadata, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in metadata.items()):
            return fail("bad_metadata", "__metadata__ must map strings to strings")
        result.metadata = metadata

    tensors: List[TensorInfo] = []
    for name, info in parsed.items():
        if not isinstance(info, dict):
            return fail("bad_tensor", f"entry `{name}` is not an object")
        extra = set(info) - {"dtype", "shape", "data_offsets"}
        if extra:
            result.findings.append(
                HubFinding(
                    rule_id="safetensors.unknown_fields",
                    category=FindingCategory.SAFETENSORS,
                    severity=Severity.LOW,
                    description=f"Tensor `{name}` carries unexpected header fields {sorted(extra)}.",
                    file=label,
                )
            )
        dtype, shape, offsets = info.get("dtype"), info.get("shape"), info.get("data_offsets")
        if dtype not in DTYPE_BITS:
            return fail("unknown_dtype", f"tensor `{name}` has unknown dtype {dtype!r}")
        if not isinstance(shape, list) or not all(isinstance(d, int) and not isinstance(d, bool) and d >= 0 for d in shape):
            return fail("bad_shape", f"tensor `{name}` has invalid shape {shape!r}")
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(isinstance(o, int) and not isinstance(o, bool) and o >= 0 for o in offsets)
            or offsets[1] < offsets[0]
        ):
            return fail("bad_offsets", f"tensor `{name}` has invalid data_offsets {offsets!r}")
        tensor = TensorInfo(name, dtype, tuple(shape), offsets[0], offsets[1])
        bits = tensor.numel * DTYPE_BITS[dtype]
        if bits % 8 or bits // 8 != tensor.end - tensor.begin:
            return fail(
                "size_mismatch",
                f"tensor `{name}` declares {tensor.end - tensor.begin} bytes but {dtype}{list(shape)} needs {bits / 8:g}",
            )
        tensors.append(tensor)

    cursor = 0
    for tensor in sorted(tensors, key=lambda t: (t.begin, t.end)):
        if tensor.begin != cursor:
            kind = "overlap" if tensor.begin < cursor else "gap"
            return fail(f"offset_{kind}", f"tensor `{tensor.name}` starts at {tensor.begin}, expected {cursor} ({kind} in data buffer)")
        cursor = tensor.end
    if cursor != data_size:
        return fail(
            "trailing_data" if data_size > cursor else "truncated",
            f"tensors cover {cursor} bytes but the data buffer is {data_size} bytes"
            + (" (unaccounted trailing bytes can hide a payload)" if data_size > cursor else ""),
        )

    result.tensors = {t.name: t for t in tensors}
    return result


def read_safetensors_header(stream: IO[bytes], *, file_size: int, label: str = "<file>") -> SafetensorsHeader:
    """Reads and validates the header from a seekable stream positioned at 0."""

    try:
        length = read_header_length(stream.read(8))
    except ValueError as exc:
        return _header_failure(label, str(exc))
    if length > MAX_HEADER_BYTES:
        return _header_failure(label, f"header is {length} bytes (limit {MAX_HEADER_BYTES})", rule="header_too_large")
    if 8 + length > file_size:
        return _header_failure(label, "declared header extends past end of file", rule="truncated")
    return validate_safetensors_header(stream.read(length), file_size=file_size, label=label)


def _header_failure(label: str, message: str, *, rule: str = "truncated") -> SafetensorsHeader:
    result = SafetensorsHeader(header_size=0, data_size=0)
    result.findings.append(
        HubFinding(
            rule_id=f"safetensors.{rule}",
            category=FindingCategory.SAFETENSORS,
            severity=Severity.HIGH,
            description=f"Malformed SafeTensors file: {message}",
            file=label,
        )
    )
    return result


def validate_safetensors_file(path: Union[str, Path]) -> SafetensorsHeader:
    file_path = Path(path)
    with file_path.open("rb") as handle:
        return read_safetensors_header(handle, file_size=file_path.stat().st_size, label=file_path.name)


# --- policy ----------------------------------------------------------------


def enforce_format_policy(paths: Iterable[str], level: EnforcementLevel) -> List[HubFinding]:
    """Applies the SafeTensors-only policy to a repository file listing."""

    findings: List[HubFinding] = []
    if level == EnforcementLevel.OFF:
        return findings
    paths = list(paths)
    formats = {p: classify_weight_file(p) for p in paths}
    has_safetensors = any(f == WeightFormat.SAFETENSORS for f in formats.values())
    strict = level == EnforcementLevel.STRICT

    for path, fmt in sorted(formats.items()):
        if fmt == WeightFormat.PICKLE:
            findings.append(
                HubFinding(
                    rule_id="safetensors.pickle_weights",
                    category=FindingCategory.POLICY,
                    severity=Severity.HIGH if strict else Severity.MEDIUM,
                    blocking=strict,
                    description=(
                        f"Pickle-format file `{path}` is present"
                        + (" (SafeTensors-only policy)." if strict else "; loaders may fall back to it.")
                        + (" A SafeTensors copy also exists, but some loaders still pick the pickle." if has_safetensors else "")
                    ),
                    file=path,
                    remediation="Remove pickle-format files from the deployment, or convert them with the safetensors converter.",
                )
            )
        elif fmt == WeightFormat.CODE_CAPABLE:
            findings.append(
                HubFinding(
                    rule_id="safetensors.code_capable_weights",
                    category=FindingCategory.POLICY,
                    severity=Severity.MEDIUM,
                    description=f"`{path}` is a Keras/TensorFlow format that can embed executable layers (e.g. Lambda).",
                    file=path,
                )
            )
    if strict and not has_safetensors:
        findings.append(
            HubFinding(
                rule_id="safetensors.missing",
                category=FindingCategory.POLICY,
                severity=Severity.HIGH,
                blocking=True,
                description="SafeTensors-only policy: the repository has no .safetensors weights.",
                remediation="Request or produce a SafeTensors export of this model.",
            )
        )
    return findings


# --- hashing ----------------------------------------------------------------


def sha256_stream(chunks: Iterable[bytes]) -> str:
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Union[str, Path], *, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha1(data: bytes) -> str:
    """The object id Git (and the Hub's `blobId`) assigns to file content."""

    return hashlib.sha1(b"blob %d\x00" % len(data) + data, usedforsecurity=False).hexdigest()


def verify_file_sha256(path: Union[str, Path], expected: str) -> bool:
    return sha256_file(path) == expected.lower()


class HashManifest(BaseModel):
    """An enterprise allowlist of exact file hashes for one repository.

    ```yaml
    repo_id: meta-llama/Llama-3-8B-Instruct
    revision: 5f0b02c75b57c5855da9ae460ce51323ea669d8a   # optional pin
    files:
      model-00001-of-00004.safetensors: 7f5c...e1
    ```
    """

    repo_id: str
    revision: Optional[str] = None
    files: Dict[str, str] = Field(default_factory=dict)

    @field_validator("files")
    @classmethod
    def _validate_hashes(cls, value: Dict[str, str]) -> Dict[str, str]:
        normalized: Dict[str, str] = {}
        for path, digest in value.items():
            digest = str(digest).lower().removeprefix("sha256:")
            if len(digest) != _SHA256_HEX_LEN or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError(f"manifest entry for {path!r} is not a SHA-256 hex digest")
            normalized[path] = digest
        return normalized

    @classmethod
    def load(cls, path: Union[str, Path]) -> "HashManifest":
        text = Path(path).read_text(encoding="utf-8")
        data = json.loads(text) if str(path).endswith(".json") else yaml.safe_load(text)
        return cls.model_validate(data)

    def dump(self, path: Union[str, Path]) -> None:
        target = Path(path)
        payload = self.model_dump(exclude_none=True)
        if target.suffix == ".json":
            target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            target.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")


def compare_against_manifest(
    manifest: HashManifest,
    *,
    repo_id: str,
    commit_sha: Optional[str],
    hub_hashes: Dict[str, Optional[str]],
    integrity_relevant: Iterable[str],
) -> List[HubFinding]:
    """Compares the Hub's claimed SHA-256s (`hub_hashes`, path -> digest
    or None for non-LFS files) against the manifest.

    Every manifest entry must exist and match; every integrity-relevant
    repo file (weights and code) must be pinned by the manifest.
    """

    findings: List[HubFinding] = []
    if manifest.repo_id != repo_id:
        findings.append(
            HubFinding(
                rule_id="integrity.manifest_repo_mismatch",
                category=FindingCategory.INTEGRITY,
                severity=Severity.HIGH,
                blocking=True,
                description=f"Hash manifest is for `{manifest.repo_id}`, not `{repo_id}`.",
            )
        )
        return findings
    if manifest.revision and commit_sha and manifest.revision != commit_sha:
        findings.append(
            HubFinding(
                rule_id="integrity.revision_drift",
                category=FindingCategory.INTEGRITY,
                severity=Severity.MEDIUM,
                description=f"Manifest is pinned to commit {manifest.revision[:12]} but the scanned revision is {commit_sha[:12]}.",
            )
        )
    for path, expected in sorted(manifest.files.items()):
        if path not in hub_hashes:
            findings.append(
                HubFinding(
                    rule_id="integrity.missing_file",
                    category=FindingCategory.INTEGRITY,
                    severity=Severity.HIGH,
                    blocking=True,
                    description=f"Manifest-pinned file `{path}` is missing from the repository.",
                    file=path,
                )
            )
            continue
        claimed = hub_hashes[path]
        if claimed is not None and claimed.lower() != expected:
            findings.append(
                HubFinding(
                    rule_id="integrity.hash_mismatch",
                    category=FindingCategory.INTEGRITY,
                    severity=Severity.CRITICAL,
                    description=f"`{path}` SHA-256 on the Hub ({claimed[:16]}...) differs from the manifest ({expected[:16]}...).",
                    file=path,
                    remediation="Treat the repository as tampered with until the change is explained.",
                )
            )
    for path in sorted(set(integrity_relevant) - set(manifest.files)):
        executable = path.endswith(".py")
        findings.append(
            HubFinding(
                rule_id="integrity.unpinned_file",
                category=FindingCategory.INTEGRITY,
                severity=Severity.HIGH if executable else Severity.MEDIUM,
                description=f"`{path}` is not pinned by the hash manifest" + (" and is executable code." if executable else "."),
                file=path,
            )
        )
    return findings
