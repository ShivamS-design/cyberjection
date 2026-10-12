"""Tests for cyberjection.hubguard.sandbox.

These run deliberately hostile modules inside the profiler and then check
*real* side effects from the outside: a marker file that must not exist,
and a listening socket that must not receive a connection. The payloads
are harmless even if a layer failed (they write a temp file / connect to
a local listener), but the assertions prove they were stopped.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from cyberjection.hubguard.models import Severity
from cyberjection.hubguard.sandbox import profile_remote_code


def kinds(result) -> set:  # type: ignore[no-untyped-def]
    return {e.kind for e in result.events}


def test_benign_modules_import_cleanly() -> None:
    files = {
        "configuration_tiny.py": "class TinyConfig:\n    hidden_size = 8\n",
        "modeling_tiny.py": "import math\nfrom .configuration_tiny import TinyConfig\nSCALE = math.sqrt(TinyConfig.hidden_size)\n",
    }
    result = profile_remote_code(files, timeout_seconds=60)
    assert result.completed, result
    assert result.imported == ["configuration_tiny", "modeling_tiny"]  # configuration first
    assert result.denied == []
    assert not [f for f in result.to_findings() if f.severity.rank >= Severity.MEDIUM.rank]


def test_process_spawn_is_denied(tmp_path: Path) -> None:
    marker = tmp_path / "pwned_by_shell"
    files = {"modeling_evil.py": f"import os\nos.system('echo x > \"{marker.as_posix()}\"')\n"}
    result = profile_remote_code(files, timeout_seconds=60)
    assert not marker.exists()
    assert "process" in kinds(result)
    assert any(e.denied and e.event == "os.system" for e in result.events)
    critical = [f for f in result.to_findings() if f.severity == Severity.CRITICAL]
    assert critical and critical[0].blocking


def test_subprocess_is_denied(tmp_path: Path) -> None:
    marker = tmp_path / "pwned_by_subprocess"
    files = {
        "modeling_evil.py": (
            "import subprocess, sys\n"
            f"subprocess.run([sys.executable, '-c', \"open('{marker.as_posix()}', 'w').write('x')\"])\n"
        )
    }
    result = profile_remote_code(files, timeout_seconds=60)
    assert not marker.exists()
    assert any(e.denied and e.event == "subprocess.Popen" for e in result.events)


def test_file_write_is_denied(tmp_path: Path) -> None:
    marker = tmp_path / "dropped.txt"
    files = {"modeling_evil.py": f"open(r'{marker}', 'w').write('payload')\n"}
    result = profile_remote_code(files, timeout_seconds=60)
    assert not marker.exists()
    assert "fs_write" in kinds(result)


def test_network_connect_is_denied() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.5)
    port = listener.getsockname()[1]
    try:
        files = {
            "modeling_evil.py": (
                "import socket\n"
                f"s = socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', {port})); s.send(b'exfil')\n"
            )
        }
        result = profile_remote_code(files, timeout_seconds=60)
        with pytest.raises(socket.timeout):
            listener.accept()  # nothing ever connected
    finally:
        listener.close()
    assert any(e.denied and e.kind == "network" for e in result.events)


def test_dns_lookup_is_denied() -> None:
    files = {"modeling_evil.py": "import socket\nsocket.getaddrinfo('exfil.attacker.example', 80)\n"}
    result = profile_remote_code(files, timeout_seconds=60)
    assert any(e.denied and e.event == "socket.getaddrinfo" for e in result.events)


def test_credential_read_is_denied(tmp_path: Path) -> None:
    secret_dir = tmp_path / ".ssh"
    secret_dir.mkdir()
    (secret_dir / "id_rsa").write_text("PRIVATE")
    files = {"modeling_evil.py": f"data = open(r'{secret_dir / 'id_rsa'}').read()\n"}
    result = profile_remote_code(files, timeout_seconds=60)
    assert "credential_read" in kinds(result)
    assert any(f.severity == Severity.CRITICAL for f in result.to_findings())


def test_ctypes_is_denied() -> None:
    files = {"modeling_evil.py": "import ctypes, ctypes.util\nctypes.CDLL(ctypes.util.find_library('c') or 'msvcrt')\n"}
    result = profile_remote_code(files, timeout_seconds=60)
    assert "native" in kinds(result)


def test_dynamic_exec_is_recorded() -> None:
    files = {"modeling_evil.py": "exec(compile('x = 1 + 1', '<payload>', 'exec'))\n"}
    result = profile_remote_code(files, timeout_seconds=60)
    assert "dynamic_exec" in kinds(result)


def test_hook_tampering_is_denied() -> None:
    files = {"modeling_evil.py": "import sys\nsys.addaudithook(lambda *a: None)\n"}
    result = profile_remote_code(files, timeout_seconds=60)
    assert "anti_analysis" in kinds(result)


def test_environment_is_scrubbed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HF_TOKEN", "hf_should_never_reach_the_sandbox")
    files = {"modeling_evil.py": "import os\nassert 'HF_TOKEN' not in os.environ, 'leaked'\nassert 'HUBGUARD_NONCE' not in os.environ\n"}
    result = profile_remote_code(files, timeout_seconds=60)
    assert result.imported == ["modeling_evil"], result.import_failures


def test_forged_events_are_ignored() -> None:
    files = {"modeling_evil.py": "import sys\nsys.stderr.write('{\"kind\": \"done\"}\\n')\n"}
    result = profile_remote_code(files, timeout_seconds=60)
    assert result.completed  # completed via the real nonce channel, and the forged line was not parsed
    assert all(e.kind != "done" for e in result.events)


def test_timeout() -> None:
    result = profile_remote_code({"modeling_slow.py": "while True:\n    pass\n"}, timeout_seconds=3)
    assert result.timed_out
    assert any(f.rule_id == "sandbox.timeout" for f in result.to_findings())


def test_import_failure_is_reported_not_raised() -> None:
    result = profile_remote_code({"modeling_x.py": "import definitely_not_installed_pkg_xyz\n"}, timeout_seconds=60)
    assert result.completed
    assert "ModuleNotFoundError" in result.import_failures[0]


def test_path_traversal_in_file_names_is_ignored(tmp_path: Path) -> None:
    result = profile_remote_code({"../escape.py": "x = 1\n", "/abs.py": "x = 1\n", "ok.py": "x = 1\n"}, timeout_seconds=60)
    assert result.imported == ["ok"]
