"""Behavioral profiling of `trust_remote_code` modules in a restricted
child process. **Opt-in: this executes the untrusted code.**

Static analysis (`remotecode.py`) can be evaded by code it can't resolve.
This profiler imports the repository's Python modules the way
`trust_remote_code=True` would and records what they *do*, using layered
restrictions:

1. **PEP 578 audit hooks** installed before any untrusted code runs.
   Process creation, network connects/binds/DNS lookups, file writes and
   deletions, native-library loading (`ctypes`), registry access and
   hook-tampering events are *denied* (the hook raises, so the operation
   never happens) and recorded. Reads of credential-like paths and
   dynamic `exec`/`compile` of strings are recorded.
2. **A fresh interpreter in isolated mode** (`-I -B`): no `PYTHON*`
   environment variables, no user site-packages, no bytecode writes, an
   empty environment (no `HF_TOKEN`, no cloud credentials), and a
   throwaway working directory.
3. **POSIX resource limits** where available: CPU seconds, address space,
   zero-byte file-size limit (writes fail at the kernel even if a hook
   were bypassed), no core dumps, a small open-file ceiling.
4. **A network namespace** (`unshare --net --map-root-user`) when the
   host allows unprivileged user namespaces -- no network interface at
   all, independent of the audit hook.

Seccomp filtering is not applied: the standard library has no seccomp
binding and this project takes no native dependency for it. Audit hooks
are a monitoring mechanism, not a security boundary (PEP 578 says so
explicitly) -- code written specifically to detect and evade this
profiler may succeed, which is why its output is reported as findings to
review, never as proof of safety, and why layers 2-4 exist. For
production isolation run the profiler inside a disposable container or
VM; `SandboxResult.isolation` records which layers were actually active.
"""

from __future__ import annotations

import json
import os
import secrets as _stdlib_secrets
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence

from cyberjection.hubguard.models import FindingCategory, HubFinding, Severity

_PACKAGE = "hubguard_sandbox_pkg"

# The runner executes inside the child interpreter. It must install the
# hook before importing anything untrusted, and report through a nonce-
# prefixed channel the untrusted code doesn't know.
_RUNNER = r'''
import sys, os
_NONCE = os.environ.pop("HUBGUARD_NONCE", "")
_OUT = os.dup(2)
_write = os.write
_dumps = __import__("json").dumps
_PKG_DIR = os.path.realpath(sys.argv[1])
_ALLOWED_READ_PREFIXES = tuple(os.path.realpath(p) for p in {sys.prefix, sys.base_prefix, sys.exec_prefix, os.path.dirname(_PKG_DIR)} if p)
import importlib, traceback  # imported before the hook so their own setup isn't attributed to the module
_getframe = sys._getframe
_in_hook = [False]

def _untrusted_on_stack():
    # Only attribute dynamic exec to the module when its code is on the stack
    # (stdlib helpers such as namedtuple compile strings internally).
    frame = _getframe(2)
    while frame is not None:
        if frame.f_code.co_filename.startswith(_PKG_DIR):
            return True
        frame = frame.f_back
    return False
_SENSITIVE = ("/.ssh", "\\.ssh", "id_rsa", "id_ed25519", "/.aws", "\\.aws", ".netrc", "/etc/passwd", "/etc/shadow",
              "huggingface/token", "huggingface\\token", ".git-credentials", ".docker/config", ".kube/config", "credentials")

def _emit(kind, event, detail, denied):
    try:
        _write(_OUT, (_NONCE + _dumps({"kind": kind, "event": event, "detail": detail[:300], "denied": denied}) + "\n").encode())
    except Exception:
        pass

_DENY_PREFIXES = {
    "subprocess.": "process", "os.system": "process", "os.exec": "process", "os.spawn": "process",
    "os.posix_spawn": "process", "os.fork": "process", "os.forkpty": "process", "pty.": "process",
    "os.startfile": "process", "_winapi.CreateProcess": "process", "os.kill": "process",
    "socket.connect": "network", "socket.bind": "network", "socket.getaddrinfo": "network",
    "socket.gethostbyname": "network", "socket.gethostbyaddr": "network", "socket.sendto": "network",
    "socket.sendmsg": "network", "urllib.Request": "network", "http.client.connect": "network",
    "ftplib.": "network", "smtplib.": "network", "webbrowser.open": "network",
    "os.remove": "fs_tamper", "os.unlink": "fs_tamper", "os.rmdir": "fs_tamper", "os.rename": "fs_tamper",
    "shutil.rmtree": "fs_tamper", "shutil.move": "fs_tamper", "shutil.copyfile": "fs_tamper",
    "os.chmod": "fs_tamper", "os.chown": "fs_tamper", "os.mkdir": "fs_tamper", "os.symlink": "fs_tamper",
    "os.link": "fs_tamper", "os.truncate": "fs_tamper", "os.putenv": "env_tamper", "os.unsetenv": "env_tamper",
    "ctypes.dlopen": "native", "ctypes.dlsym": "native", "ctypes.call_function": "native",
    "ctypes.string_at": "native", "ctypes.wstring_at": "native", "ctypes.addressof": "native",
    "winreg.": "registry", "sys.addaudithook": "anti_analysis", "sys.settrace": "anti_analysis",
    "sys.setprofile": "anti_analysis", "cpython.PyInterpreterState_Clear": "anti_analysis",
}

def _hook(event, args):
    if _in_hook[0]:
        return
    _in_hook[0] = True
    try:
        _check(event, args)
    finally:
        _in_hook[0] = False

def _check(event, args):
    for prefix, kind in _DENY_PREFIXES.items():
        if event == prefix or (prefix.endswith(".") and event.startswith(prefix)) or (not prefix.endswith(".") and event.startswith(prefix)):
            _emit(kind, event, repr(args), True)
            raise PermissionError("hubguard sandbox: " + event + " denied")
    if event == "open":
        path, mode = args[0], args[1]
        flags = args[2] if len(args) > 2 else 0
        spath = str(path)
        writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND))
        if writing:
            _emit("fs_write", event, spath, True)
            raise PermissionError("hubguard sandbox: write denied")
        if any(s in spath for s in _SENSITIVE):
            _emit("credential_read", event, spath, True)
            raise PermissionError("hubguard sandbox: sensitive read denied")
        if isinstance(path, (str, bytes)) and not os.path.realpath(spath).startswith(_ALLOWED_READ_PREFIXES):
            _emit("fs_read", event, spath, False)
    elif event == "exec":
        code = args[0]
        filename = getattr(code, "co_filename", "")
        if filename.startswith("<") and not filename.startswith("<frozen") and _untrusted_on_stack():
            _emit("dynamic_exec", event, filename, False)
    elif event == "compile":
        source, filename = args[0], args[1]
        if isinstance(filename, str) and filename.startswith("<") and source is not None and _untrusted_on_stack():
            _emit("dynamic_exec", event, repr(source)[:200], False)
    elif event in ("marshal.loads", "pickle.find_class"):
        _emit("deserialization", event, repr(args), False)
    elif event == "os.listdir" or event == "os.scandir":
        spath = str(args[0]) if args else "."
        if not os.path.realpath(spath).startswith(_ALLOWED_READ_PREFIXES):
            _emit("fs_enum", event, spath, False)
    elif event == "import":
        _emit("import", event, str(args[0]), False)

sys.addaudithook(_hook)
sys.path.insert(0, os.path.dirname(_PKG_DIR))
for _mod in sys.argv[2:]:
    try:
        importlib.import_module(_PKG_NAME + "." + _mod)
        _emit("module", "imported", _mod, False)
    except BaseException as _exc:
        _emit("module", "import_failed", _mod + ": " + type(_exc).__name__ + ": " + str(_exc), False)
_emit("done", "done", "", False)
'''

_KIND_SEVERITY: Dict[str, Severity] = {
    "process": Severity.CRITICAL,
    "network": Severity.HIGH,
    "fs_tamper": Severity.HIGH,
    "fs_write": Severity.HIGH,
    "env_tamper": Severity.MEDIUM,
    "native": Severity.HIGH,
    "registry": Severity.HIGH,
    "anti_analysis": Severity.HIGH,
    "credential_read": Severity.CRITICAL,
    "fs_read": Severity.LOW,
    "fs_enum": Severity.LOW,
    "dynamic_exec": Severity.MEDIUM,
    "deserialization": Severity.MEDIUM,
}


@dataclass
class SandboxEvent:
    kind: str
    event: str
    detail: str
    denied: bool


@dataclass
class SandboxResult:
    events: List[SandboxEvent] = field(default_factory=list)
    isolation: List[str] = field(default_factory=list)
    timed_out: bool = False
    completed: bool = False
    exit_code: Optional[int] = None
    imported: List[str] = field(default_factory=list)
    import_failures: List[str] = field(default_factory=list)

    @property
    def denied(self) -> List[SandboxEvent]:
        return [e for e in self.events if e.denied]

    def to_findings(self, *, label: str = "remote code") -> List[HubFinding]:
        findings: List[HubFinding] = []
        seen = set()
        for event in self.events:
            severity = _KIND_SEVERITY.get(event.kind)
            if severity is None:
                continue
            key = (event.kind, event.event, event.detail[:80])
            if key in seen:
                continue
            seen.add(key)
            action = "attempted and was blocked" if event.denied else "performed"
            findings.append(
                HubFinding(
                    rule_id=f"sandbox.{event.kind}",
                    category=FindingCategory.SANDBOX,
                    severity=severity,
                    description=f"During sandboxed import, {label} {action} `{event.event}` ({event.kind.replace('_', ' ')}).",
                    evidence=event.detail[:200],
                    remediation="Do not run this repository with trust_remote_code=True until the behavior is explained.",
                )
            )
        if self.timed_out:
            findings.append(
                HubFinding(
                    rule_id="sandbox.timeout",
                    category=FindingCategory.SANDBOX,
                    severity=Severity.MEDIUM,
                    description=f"Sandboxed import of {label} did not finish before the timeout.",
                )
            )
        elif not self.completed:
            findings.append(
                HubFinding(
                    rule_id="sandbox.abnormal_exit",
                    category=FindingCategory.SANDBOX,
                    severity=Severity.MEDIUM,
                    description=f"Sandboxed interpreter exited abnormally (code {self.exit_code}) before reporting completion.",
                )
            )
        return findings


def _netns_prefix() -> List[str]:
    if not sys.platform.startswith("linux"):
        return []
    unshare = shutil.which("unshare")
    if not unshare:
        return []
    try:
        probe = subprocess.run([unshare, "--net", "--map-root-user", "true"], capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return []
    return [unshare, "--net", "--map-root-user", "--"] if probe.returncode == 0 else []


def _make_preexec(cpu_seconds: int, memory_bytes: int) -> Callable[[], None]:
    def _apply() -> None:
        if sys.platform == "win32":  # never called on Windows; narrows types for mypy
            return
        import resource

        limits = [
            (resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1)),
            (resource.RLIMIT_FSIZE, (0, 0)),
            (resource.RLIMIT_CORE, (0, 0)),
            (resource.RLIMIT_NOFILE, (256, 256)),
        ]
        if memory_bytes:
            limits.append((resource.RLIMIT_AS, (memory_bytes, memory_bytes)))
        for limit, value in limits:
            try:
                resource.setrlimit(limit, value)
            except (ValueError, OSError):
                pass
        os.setsid()

    return _apply


def profile_remote_code(
    files: Dict[str, str],
    *,
    modules: Optional[Sequence[str]] = None,
    timeout_seconds: float = 30.0,
    memory_bytes: int = 4 << 30,
    python_executable: Optional[str] = None,
) -> SandboxResult:
    """Imports `files` (relative path -> source) as a package in a
    restricted child interpreter and returns what happened.

    `modules` defaults to every top-level `.py` file, configuration
    modules first (the order `transformers` imports them in).
    """

    result = SandboxResult(isolation=["audit-hook", "isolated-interpreter", "empty-environment"])
    workdir = Path(tempfile.mkdtemp(prefix="hubguard-sandbox-"))
    try:
        pkg_dir = workdir / _PACKAGE
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("", encoding="utf-8")
        for rel, source in files.items():
            rel_path = Path(rel)
            if rel_path.is_absolute() or rel_path.anchor or ".." in rel_path.parts or rel_path.suffix != ".py":
                continue
            target = pkg_dir / rel_path
            if pkg_dir.resolve() not in target.resolve().parents:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            for parent in target.relative_to(pkg_dir).parents:
                init = pkg_dir / parent / "__init__.py"
                if parent != Path(".") and not init.exists():
                    init.write_text("", encoding="utf-8")
            target.write_text(source, encoding="utf-8")
        if modules is None:
            names = sorted(Path(p).with_suffix("").as_posix().replace("/", ".") for p in files if p.endswith(".py"))
            modules = sorted(names, key=lambda n: (not n.split(".")[-1].startswith("configuration"), n))
        runner_path = workdir / "runner.py"
        runner_path.write_text(_RUNNER.replace("_PKG_NAME", repr(_PACKAGE)), encoding="utf-8")
        scratch = workdir / "cwd"
        scratch.mkdir()

        nonce = "@@HG" + _stdlib_secrets.token_hex(16) + "@@"
        env: Dict[str, str] = {"HUBGUARD_NONCE": nonce, "PYTHONIOENCODING": "utf-8", "HOME": str(scratch)}
        if os.name == "nt":
            for key in ("SYSTEMROOT", "SystemRoot", "TEMP", "TMP"):
                if key in os.environ:
                    env[key] = os.environ[key] if key not in ("TEMP", "TMP") else str(scratch)
        else:
            env["PATH"] = "/usr/bin:/bin"

        command = [python_executable or sys.executable, "-I", "-B", str(runner_path), str(pkg_dir), *modules]
        preexec: Optional[Callable[[], None]] = None
        if os.name == "posix":
            prefix = _netns_prefix()
            if prefix:
                command = prefix + command
                result.isolation.append("network-namespace")
            preexec = _make_preexec(int(timeout_seconds) + 1, memory_bytes)
            result.isolation.append("rlimits")
        try:
            completed = subprocess.run(
                command,
                cwd=str(scratch),
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=timeout_seconds,
                preexec_fn=preexec,
            )
            stderr = completed.stderr
            result.exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            stderr = exc.stderr or b""
            result.timed_out = True

        for raw_line in stderr.decode("utf-8", "replace").splitlines():
            if not raw_line.startswith(nonce):
                continue
            try:
                payload = json.loads(raw_line[len(nonce):])
            except json.JSONDecodeError:
                continue
            kind = str(payload.get("kind", ""))
            if kind == "done":
                result.completed = True
                continue
            if kind == "module":
                (result.imported if payload.get("event") == "imported" else result.import_failures).append(str(payload.get("detail", "")))
                continue
            result.events.append(SandboxEvent(kind, str(payload.get("event", "")), str(payload.get("detail", "")), bool(payload.get("denied"))))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return result
