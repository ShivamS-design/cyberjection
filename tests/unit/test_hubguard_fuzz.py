"""Deterministic fuzzing of every HubGuard parser.

HubGuard's inputs are, by definition, hostile. These tests mutate valid
and malicious fixtures at random (fixed seeds, so failures reproduce) and
assert the properties that must hold for *any* input:

- no scanner raises -- malformed input becomes a finding, never a crash;
- no payload is ever executed (a pickle that would create a marker file
  on load is among the mutation seeds);
- no regex exhibits catastrophic backtracking on adversarial text;
- a mutated pickle that still decodes to a dangerous import is still
  reported.

`CYBERJECTION_FUZZ_ITERATIONS` scales the iteration count for a longer
local campaign (the default keeps the unit suite fast).
"""

from __future__ import annotations

import io
import os
import pickle
import random
import struct
import time
from pathlib import Path

import pytest

from cyberjection.hubguard.models import Severity
from cyberjection.hubguard.picklescan import scan_pickle_bytes
from cyberjection.hubguard.remotecode import analyze_python_source, parse_auto_map
from cyberjection.hubguard.safetensors import read_safetensors_header
from cyberjection.hubguard.secrets import find_secrets
from tests.unit.hubguard_helpers import (
    benign_torch_data_pkl,
    call_global,
    f32,
    npy_object_array,
    safetensors_bytes,
    stack_global_call,
    torch_zip,
)

ITERATIONS = int(os.environ.get("CYBERJECTION_FUZZ_ITERATIONS", "300"))


def mutate(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        op = rng.random()
        if op < 0.35 and buf:
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        elif op < 0.55:
            buf.insert(rng.randrange(len(buf) + 1), rng.randrange(256))
        elif op < 0.75 and buf:
            del buf[rng.randrange(len(buf))]
        elif op < 0.85 and buf:
            start = rng.randrange(len(buf))
            buf[start:start] = buf[start : start + rng.randint(1, 16)]  # duplicate a chunk
        else:
            buf = buf[: rng.randrange(len(buf) + 1)]  # truncate
    return bytes(buf)


class _Sentinel:
    def __init__(self, path: str) -> None:
        self.path = path

    def __reduce__(self):  # type: ignore[no-untyped-def]
        return (open, (self.path, "w"))


def test_pickle_scanner_never_crashes_or_executes(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    seeds = [
        pickle.dumps(_Sentinel(str(marker)), protocol=p) for p in (0, 2, 4, 5)
    ] + [
        call_global("os", "system", "id"),
        stack_global_call("builtins", "exec", "import os"),
        benign_torch_data_pkl(),
        torch_zip(call_global("subprocess", "Popen", "sh")),
        npy_object_array(call_global("os", "system", "id")),
        pickle.dumps({"weights": [1.0, 2.0], "name": "x" * 50}, protocol=4),
    ]
    rng = random.Random(1337)
    for _ in range(ITERATIONS):
        sample = mutate(rng, rng.choice(seeds))
        result = scan_pickle_bytes(sample)  # must not raise
        assert result.format in {"pickle", "torch-zip", "zip", "torch-legacy", "npy"}
    for _ in range(ITERATIONS // 3):
        scan_pickle_bytes(bytes(rng.randrange(256) for _ in range(rng.randint(0, 300))))
    assert not marker.exists()


def test_mutated_pickles_keep_reporting_dangerous_imports() -> None:
    """Appending junk after STOP or flipping bytes in trailing data must not
    hide an import the unpickler would still perform."""

    rng = random.Random(7)
    payload = call_global("os", "system", "id")
    for _ in range(ITERATIONS // 3):
        tail = bytes(rng.randrange(256) for _ in range(rng.randint(0, 64)))
        result = scan_pickle_bytes(payload + tail)
        assert any(i.qualified == "os.system" for i in result.imports)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_safetensors_validator_never_crashes() -> None:
    valid = safetensors_bytes({"a": ("F32", [2, 3], f32([0.0] * 6)), "b": ("BF16", [4], b"\x00" * 8)}, metadata={"k": "v"})
    rng = random.Random(42)
    for _ in range(ITERATIONS):
        sample = mutate(rng, valid)
        header = read_safetensors_header(io.BytesIO(sample), file_size=len(sample), label="f")
        assert isinstance(header.valid, bool)
    # Header-length field fuzzing: huge, zero, and off-by-one lengths.
    for length in (0, 1, len(valid) - 8, len(valid), 2**63 - 1, 2**64 - 1, 100_000_001):
        sample = struct.pack("<Q", length) + valid[8:]
        header = read_safetensors_header(io.BytesIO(sample), file_size=len(sample), label="f")
        assert isinstance(header.valid, bool)


def test_safetensors_mutations_that_change_bytes_are_rejected_or_consistent() -> None:
    """Any mutation either still yields a self-consistent file (offsets tile
    the buffer exactly) or is rejected -- never a 'valid' file whose
    tensors overrun the data."""

    valid = safetensors_bytes({"a": ("F32", [8], f32([1.0] * 8))})
    rng = random.Random(99)
    for _ in range(ITERATIONS):
        sample = mutate(rng, valid)
        header = read_safetensors_header(io.BytesIO(sample), file_size=len(sample), label="f")
        if header.valid and header.tensors:
            covered = sum(t.end - t.begin for t in header.tensors.values())
            assert covered == header.data_size
            assert header.data_start + header.data_size == len(sample)


def test_remote_code_analyzer_never_crashes() -> None:
    corpus = [
        "import os\nos.system('id')\n",
        "exec(__import__('base64').b64decode('aW1wb3J0IG9z'))\n",
        "class M:\n    def __init__(self):\n        import subprocess as s\n        s.run(['x'])\n",
        "from os import *\nx = getattr(os, 'sys' + 'tem')\n",
        "eval(\"exec('import socket')\")\n",
    ]
    rng = random.Random(5)
    for _ in range(ITERATIONS):
        source = mutate(rng, rng.choice(corpus).encode()).decode("utf-8", "replace")
        analysis = analyze_python_source(source, filename="m.py")
        assert analysis.parse_error is None or any(f.rule_id == "remote_code.unparseable" for f in analysis.findings)


def test_deeply_nested_source_does_not_crash() -> None:
    for source in ("(" * 5000 + ")" * 5000, "x = " + "[" * 3000 + "]" * 3000, "a" + ".b" * 20000):
        analysis = analyze_python_source(source, filename="deep.py")
        assert analysis is not None


def test_nested_exec_recursion_is_bounded() -> None:
    source = "x = 1"
    for _ in range(12):
        source = f"exec({source!r})"
    analysis = analyze_python_source(source, filename="nest.py")  # depth-limited, must terminate
    assert analysis.parse_error is None


def test_auto_map_parser_handles_garbage() -> None:
    rng = random.Random(3)
    base = b'{"auto_map": {"AutoModel": "org/repo--modeling.M", "AutoConfig": ["c.C", null]}}'
    for _ in range(ITERATIONS):
        parse_auto_map(mutate(rng, base).decode("utf-8", "replace"), source_file="config.json")


@pytest.mark.parametrize(
    "text",
    [
        "a" * 50_000,
        "postgres://" + "a:" * 20_000 + "@",
        "api_key = \"" + "A" * 50_000,
        "https://hooks.slack.com/services/T" + "A" * 30_000,
        "-----BEGIN " * 5_000,
        "eyJ" + "a" * 20_000 + ".eyJ" + "b" * 20_000,
        ("hf_" + "x" * 33 + " ") * 2_000,
        "http://10.0.0." + "1" * 30_000,
    ],
    ids=["plain", "db-url", "assignment", "webhook", "pem", "jwt", "hf-tokens", "internal-ip"],
)
def test_secret_patterns_have_no_catastrophic_backtracking(text: str) -> None:
    start = time.perf_counter()
    find_secrets(text)
    assert time.perf_counter() - start < 2.0


def test_secret_scanner_random_text() -> None:
    rng = random.Random(11)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-=:/@.\"' \n{}[]"
    for _ in range(ITERATIONS // 3):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 2000)))
        for match in find_secrets(text):
            assert match.redacted not in ("",)
