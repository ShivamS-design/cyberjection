"""Tests for cyberjection.hubguard.safetensors."""

from __future__ import annotations

import hashlib
import io
import struct
from pathlib import Path

import pytest

from cyberjection.hubguard.models import Severity
from cyberjection.hubguard.safetensors import (
    EnforcementLevel,
    HashManifest,
    WeightFormat,
    classify_weight_file,
    compare_against_manifest,
    enforce_format_policy,
    git_blob_sha1,
    read_safetensors_header,
    sha256_file,
    validate_safetensors_file,
    verify_file_sha256,
)
from tests.unit.hubguard_helpers import f32, safetensors_bytes


def validate(data: bytes):  # type: ignore[no-untyped-def]
    return read_safetensors_header(io.BytesIO(data), file_size=len(data), label="model.safetensors")


def rules(header) -> set:  # type: ignore[no-untyped-def]
    return {f.rule_id for f in header.findings}


VALID = {"a": ("F32", [2, 2], f32([1, 2, 3, 4])), "b": ("F16", [3], b"\x00" * 6)}


class TestHeaderValidation:
    def test_valid_file(self) -> None:
        header = validate(safetensors_bytes(VALID, metadata={"format": "pt"}))
        assert header.valid and header.findings == []
        assert set(header.tensors) == {"a", "b"}
        assert header.tensors["a"].numel == 4
        assert header.metadata == {"format": "pt"}

    def test_empty_tensor_and_scalar(self) -> None:
        header = validate(safetensors_bytes({"empty": ("F32", [0, 3], b""), "scalar": ("I64", [], b"\x00" * 8)}))
        assert header.valid, header.findings

    def test_sub_byte_dtype(self) -> None:
        assert validate(safetensors_bytes({"q": ("F4", [4], b"\x00\x00")})).valid

    def test_matches_reference_library_when_installed(self, tmp_path: Path) -> None:
        st = pytest.importorskip("safetensors")
        np = pytest.importorskip("numpy")
        from safetensors.numpy import save_file

        path = tmp_path / "ref.safetensors"
        save_file({"w": np.ones((3, 5), dtype=np.float32), "b": np.zeros(7, dtype=np.float16)}, str(path), metadata={"k": "v"})
        assert validate_safetensors_file(path).valid
        assert st is not None

    @pytest.mark.parametrize(
        "name,expect_reference",
        [("trailing", "reject"), ("gap", "reject"), ("overlap", "reject"), ("size", "reject"), ("dup", "accept"), ("valid", "accept")],
    )
    def test_differential_against_reference_loader(self, name: str, expect_reference: str) -> None:
        """We reject everything the reference loader rejects, plus duplicate
        keys, which it silently accepts (the parser-differential gap)."""

        st_numpy = pytest.importorskip("safetensors.numpy")
        fixtures = {
            "valid": safetensors_bytes(VALID),
            "trailing": safetensors_bytes(VALID, trailing=b"XX"),
            "gap": safetensors_bytes({}, raw_header=b'{"a": {"dtype": "U8", "shape": [2], "data_offsets": [2, 4]}}') + b"\x00" * 4,
            "overlap": safetensors_bytes(
                {},
                raw_header=b'{"a": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]}, "b": {"dtype": "U8", "shape": [4], "data_offsets": [2, 6]}}',
            )
            + b"\x00" * 6,
            "size": safetensors_bytes({}, raw_header=b'{"a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 4]}}') + b"\x00" * 4,
            "dup": safetensors_bytes(
                {},
                raw_header=b'{"a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}, "a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}',
            )
            + b"\x00",
        }
        data = fixtures[name]
        try:
            st_numpy.load(data)
            reference = "accept"
        except Exception:  # noqa: BLE001
            reference = "reject"
        assert reference == expect_reference
        ours = validate(data).valid
        assert ours is (name == "valid")

    @pytest.mark.parametrize(
        "data,rule",
        [
            (b"\x01\x02", "safetensors.truncated"),
            (struct.pack("<Q", 200_000_000) + b"{}", "safetensors.header_too_large"),
            (struct.pack("<Q", 100) + b"{}", "safetensors.truncated"),
            (struct.pack("<Q", 4) + b"\xff\xfe{}", "safetensors.not_utf8"),
            (struct.pack("<Q", 2) + b"[]", "safetensors.not_object"),
            (struct.pack("<Q", 3) + b"{x}", "safetensors.bad_json"),
            (struct.pack("<Q", 8) + b"{}  \x00\x00\x00\x00", "safetensors.bad_padding"),
        ],
    )
    def test_structural_failures(self, data: bytes, rule: str) -> None:
        header = validate(data)
        assert rule in rules(header)
        assert not header.valid

    def test_duplicate_keys_rejected(self) -> None:
        raw = b'{"a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}, "a": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}'
        assert "safetensors.duplicate_key" in rules(validate(safetensors_bytes({}, raw_header=raw) + b"\x00" * 4))

    def test_trailing_bytes_rejected(self) -> None:
        header = validate(safetensors_bytes(VALID, trailing=b"\x80\x02cos\nsystem\n."))
        assert "safetensors.trailing_data" in rules(header)

    def test_gap_rejected(self) -> None:
        raw = b'{"a": {"dtype": "U8", "shape": [2], "data_offsets": [2, 4]}}'
        assert "safetensors.offset_gap" in rules(validate(safetensors_bytes({}, raw_header=raw) + b"\x00" * 4))

    def test_overlap_rejected(self) -> None:
        raw = (
            b'{"a": {"dtype": "U8", "shape": [4], "data_offsets": [0, 4]},'
            b' "b": {"dtype": "U8", "shape": [4], "data_offsets": [2, 6]}}'
        )
        assert "safetensors.offset_overlap" in rules(validate(safetensors_bytes({}, raw_header=raw) + b"\x00" * 6))

    def test_size_mismatch_rejected(self) -> None:
        raw = b'{"a": {"dtype": "F32", "shape": [2], "data_offsets": [0, 4]}}'
        assert "safetensors.size_mismatch" in rules(validate(safetensors_bytes({}, raw_header=raw) + b"\x00" * 4))

    @pytest.mark.parametrize(
        "entry,rule",
        [
            (b'{"dtype": "F99", "shape": [1], "data_offsets": [0, 4]}', "safetensors.unknown_dtype"),
            (b'{"dtype": "F32", "shape": [-1], "data_offsets": [0, 4]}', "safetensors.bad_shape"),
            (b'{"dtype": "F32", "shape": [true], "data_offsets": [0, 4]}', "safetensors.bad_shape"),
            (b'{"dtype": "F32", "shape": [1], "data_offsets": [4, 0]}', "safetensors.bad_offsets"),
            (b'{"dtype": "F32", "shape": [1]}', "safetensors.bad_offsets"),
            (b'"nope"', "safetensors.bad_tensor"),
        ],
    )
    def test_bad_tensor_entries(self, entry: bytes, rule: str) -> None:
        raw = b'{"a": ' + entry + b"}"
        assert rule in rules(validate(safetensors_bytes({}, raw_header=raw) + b"\x00" * 4))

    def test_bad_metadata(self) -> None:
        raw = b'{"__metadata__": {"k": 1}}'
        assert "safetensors.bad_metadata" in rules(validate(safetensors_bytes({}, raw_header=raw)))

    def test_unknown_fields_are_low(self) -> None:
        raw = b'{"a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1], "exec": "x"}}'
        header = validate(safetensors_bytes({}, raw_header=raw) + b"\x00")
        assert "safetensors.unknown_fields" in rules(header)
        assert header.valid  # LOW doesn't invalidate

    def test_file_on_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "w.safetensors"
        path.write_bytes(safetensors_bytes(VALID))
        assert validate_safetensors_file(path).valid


class TestFormatPolicy:
    @pytest.mark.parametrize(
        "path,fmt",
        [
            ("model.safetensors", WeightFormat.SAFETENSORS),
            ("pytorch_model.bin", WeightFormat.PICKLE),
            ("training_args.bin", WeightFormat.PICKLE),
            ("sub/dir/model.ckpt", WeightFormat.PICKLE),
            ("model.gguf", WeightFormat.SAFE_OTHER),
            ("tf_model.h5", WeightFormat.CODE_CAPABLE),
            ("README.md", WeightFormat.NOT_WEIGHTS),
        ],
    )
    def test_classify(self, path: str, fmt: WeightFormat) -> None:
        assert classify_weight_file(path) == fmt

    def test_strict_blocks_pickles_and_missing_safetensors(self) -> None:
        findings = enforce_format_policy(["pytorch_model.bin", "config.json"], EnforcementLevel.STRICT)
        ids = {f.rule_id for f in findings}
        assert ids == {"safetensors.pickle_weights", "safetensors.missing"}
        assert all(f.blocking for f in findings)

    def test_strict_flags_pickle_even_alongside_safetensors(self) -> None:
        findings = enforce_format_policy(["model.safetensors", "pytorch_model.bin"], EnforcementLevel.STRICT)
        assert [f.rule_id for f in findings] == ["safetensors.pickle_weights"]
        assert "also exists" in findings[0].description

    def test_strict_clean_repo(self) -> None:
        assert enforce_format_policy(["model.safetensors", "config.json"], EnforcementLevel.STRICT) == []

    def test_warn_is_non_blocking_medium(self) -> None:
        findings = enforce_format_policy(["pytorch_model.bin"], EnforcementLevel.WARN)
        assert len(findings) == 1 and findings[0].severity == Severity.MEDIUM and not findings[0].blocking

    def test_off(self) -> None:
        assert enforce_format_policy(["pytorch_model.bin"], EnforcementLevel.OFF) == []

    def test_code_capable_flagged(self) -> None:
        assert enforce_format_policy(["model.safetensors", "tf_model.h5"], EnforcementLevel.WARN)[0].rule_id == "safetensors.code_capable_weights"


class TestHashing:
    def test_git_blob_sha1_matches_git(self) -> None:
        # `printf 'hello\n' | git hash-object --stdin`
        assert git_blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"

    def test_sha256_file(self, tmp_path: Path) -> None:
        path = tmp_path / "x"
        path.write_bytes(b"abc" * 1_000_000)
        expected = hashlib.sha256(b"abc" * 1_000_000).hexdigest()
        assert sha256_file(path) == expected
        assert verify_file_sha256(path, expected.upper())
        assert not verify_file_sha256(path, "0" * 64)


class TestManifest:
    DIGEST = "a" * 64

    def test_round_trip_yaml_and_json(self, tmp_path: Path) -> None:
        manifest = HashManifest(repo_id="org/m", revision="c" * 40, files={"m.safetensors": "sha256:" + self.DIGEST.upper()})
        assert manifest.files["m.safetensors"] == self.DIGEST
        for name in ("m.yaml", "m.json"):
            manifest.dump(tmp_path / name)
            assert HashManifest.load(tmp_path / name) == manifest

    def test_rejects_non_sha256(self) -> None:
        with pytest.raises(ValueError):
            HashManifest(repo_id="org/m", files={"x": "deadbeef"})

    def test_compare(self) -> None:
        manifest = HashManifest(
            repo_id="org/m",
            revision="b" * 40,
            files={"ok.safetensors": self.DIGEST, "bad.safetensors": self.DIGEST, "gone.safetensors": self.DIGEST},
        )
        findings = compare_against_manifest(
            manifest,
            repo_id="org/m",
            commit_sha="c" * 40,
            hub_hashes={"ok.safetensors": self.DIGEST, "bad.safetensors": "f" * 64, "modeling_x.py": None, "new.bin": "e" * 64},
            integrity_relevant=["ok.safetensors", "bad.safetensors", "modeling_x.py", "new.bin"],
        )
        by_rule = {}
        for f in findings:
            by_rule.setdefault(f.rule_id, []).append(f)
        assert by_rule["integrity.hash_mismatch"][0].file == "bad.safetensors"
        assert by_rule["integrity.hash_mismatch"][0].severity == Severity.CRITICAL
        assert by_rule["integrity.missing_file"][0].file == "gone.safetensors"
        assert by_rule["integrity.revision_drift"][0].severity == Severity.MEDIUM
        unpinned = {f.file: f.severity for f in by_rule["integrity.unpinned_file"]}
        assert unpinned == {"modeling_x.py": Severity.HIGH, "new.bin": Severity.MEDIUM}

    def test_repo_mismatch(self) -> None:
        findings = compare_against_manifest(
            HashManifest(repo_id="org/other"), repo_id="org/m", commit_sha=None, hub_hashes={}, integrity_relevant=[]
        )
        assert findings[0].rule_id == "integrity.manifest_repo_mismatch" and findings[0].blocking
