"""Static security analysis of `trust_remote_code` Python files.

`AutoModel.from_pretrained(repo, trust_remote_code=True)` downloads the
repository's `configuration_*.py` / `modeling_*.py` / `tokenization_*.py`
and imports them -- module-level code runs at import, `__init__` code runs
at instantiation, all with the loading process's full privileges. This
module parses those files with `ast` (parsing never executes anything)
and reports calls that spawn processes, open network connections, tamper
with the filesystem, execute dynamically-built code, deserialize
untrusted data, load native libraries, or read credentials.

Name resolution follows aliases, so `import subprocess as sp; sp.run(...)`,
`from os import system as s; s(...)`, `__import__("os").system(...)`,
`importlib.import_module("subprocess").run(...)` and
`getattr(os, "system")(...)` all resolve to the same qualified name.
Calls made at module level are flagged as executing on import, and a
decode-then-execute chain (`exec(base64.b64decode(...))`) is escalated to
CRITICAL as deliberate obfuscation.

What static analysis can't do: it can't see code that is fetched at
runtime (flagged when the fetch itself is visible), constructed from
non-constant strings in ways the resolver can't follow (flagged as
dynamic `getattr`/`__import__` where visible), or loaded from another
repository through a cross-repo `auto_map` entry (flagged by
`analyze_auto_map`). For behavior, see `cyberjection.hubguard.sandbox`.
"""

from __future__ import annotations

import ast
import builtins
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from cyberjection.hubguard.models import FindingCategory, HubFinding, Severity

# rule_id -> (severity, human label). Matched against fully-qualified call
# targets: an entry "os.exec" matches os.execv, os.execve, ... via the
# prefix table below; exact names go in _EXACT_RULES.
_PREFIX_RULES: List[Tuple[str, str, Severity, str]] = [
    ("subprocess.", "remote_code.process_execution", Severity.CRITICAL, "spawns a subprocess"),
    ("os.exec", "remote_code.process_execution", Severity.CRITICAL, "replaces the process via exec*"),
    ("os.spawn", "remote_code.process_execution", Severity.CRITICAL, "spawns a process"),
    ("os.posix_spawn", "remote_code.process_execution", Severity.CRITICAL, "spawns a process"),
    ("pty.", "remote_code.process_execution", Severity.CRITICAL, "spawns a pseudo-terminal process"),
    ("commands.", "remote_code.process_execution", Severity.CRITICAL, "runs a shell command"),
    ("asyncio.create_subprocess", "remote_code.process_execution", Severity.CRITICAL, "spawns a subprocess"),
    ("socket.", "remote_code.network", Severity.HIGH, "opens a raw network socket"),
    ("requests.", "remote_code.network", Severity.HIGH, "makes an HTTP request"),
    ("httpx.", "remote_code.network", Severity.HIGH, "makes an HTTP request"),
    ("aiohttp.", "remote_code.network", Severity.HIGH, "makes an HTTP request"),
    ("urllib.request.", "remote_code.network", Severity.HIGH, "makes an HTTP request"),
    ("urllib3.", "remote_code.network", Severity.HIGH, "makes an HTTP request"),
    ("http.client.", "remote_code.network", Severity.HIGH, "makes an HTTP request"),
    ("ftplib.", "remote_code.network", Severity.HIGH, "opens an FTP connection"),
    ("smtplib.", "remote_code.network", Severity.HIGH, "sends email"),
    ("telnetlib.", "remote_code.network", Severity.HIGH, "opens a telnet connection"),
    ("paramiko.", "remote_code.network", Severity.HIGH, "opens an SSH connection"),
    ("websocket.", "remote_code.network", Severity.HIGH, "opens a websocket"),
    ("websockets.", "remote_code.network", Severity.HIGH, "opens a websocket"),
    ("ctypes.", "remote_code.native_code", Severity.HIGH, "loads or calls native code via ctypes"),
    ("cffi.", "remote_code.native_code", Severity.HIGH, "loads native code via cffi"),
    ("huggingface_hub.", "remote_code.runtime_download", Severity.MEDIUM, "downloads additional artifacts at runtime"),
    ("torch.hub.", "remote_code.runtime_download", Severity.HIGH, "downloads and may execute code via torch.hub"),
    ("webbrowser.", "remote_code.network", Severity.MEDIUM, "opens a browser"),
    ("winreg.", "remote_code.system_tamper", Severity.HIGH, "accesses the Windows registry"),
]

_EXACT_RULES: Dict[str, Tuple[str, Severity, str]] = {
    "os.system": ("remote_code.process_execution", Severity.CRITICAL, "runs a shell command"),
    "os.popen": ("remote_code.process_execution", Severity.CRITICAL, "runs a shell command"),
    "os.fork": ("remote_code.process_execution", Severity.HIGH, "forks the process"),
    "os.forkpty": ("remote_code.process_execution", Severity.HIGH, "forks the process"),
    "os.startfile": ("remote_code.process_execution", Severity.CRITICAL, "launches a program"),
    "os.kill": ("remote_code.process_execution", Severity.HIGH, "signals another process"),
    "platform.popen": ("remote_code.process_execution", Severity.CRITICAL, "runs a shell command"),
    "builtins.eval": ("remote_code.dynamic_code", Severity.HIGH, "evaluates a dynamically-built expression"),
    "builtins.exec": ("remote_code.dynamic_code", Severity.HIGH, "executes dynamically-built code"),
    "builtins.compile": ("remote_code.dynamic_code", Severity.MEDIUM, "compiles dynamically-built code"),
    "builtins.__import__": ("remote_code.dynamic_import", Severity.MEDIUM, "imports a module dynamically"),
    "importlib.import_module": ("remote_code.dynamic_import", Severity.MEDIUM, "imports a module dynamically"),
    "importlib.util.spec_from_file_location": ("remote_code.dynamic_import", Severity.HIGH, "loads a module from an arbitrary file"),
    "importlib.util.spec_from_loader": ("remote_code.dynamic_import", Severity.HIGH, "loads a module from a custom loader"),
    "runpy.run_path": ("remote_code.dynamic_code", Severity.HIGH, "executes a file as a script"),
    "runpy.run_module": ("remote_code.dynamic_code", Severity.HIGH, "executes a module as a script"),
    "types.CodeType": ("remote_code.dynamic_code", Severity.HIGH, "constructs a raw code object"),
    "types.FunctionType": ("remote_code.dynamic_code", Severity.HIGH, "constructs a function from a code object"),
    "marshal.loads": ("remote_code.deserialization", Severity.HIGH, "deserializes a code object"),
    "pickle.load": ("remote_code.deserialization", Severity.HIGH, "unpickles data (arbitrary code execution)"),
    "pickle.loads": ("remote_code.deserialization", Severity.HIGH, "unpickles data (arbitrary code execution)"),
    "pickle.Unpickler": ("remote_code.deserialization", Severity.HIGH, "unpickles data (arbitrary code execution)"),
    "_pickle.loads": ("remote_code.deserialization", Severity.HIGH, "unpickles data (arbitrary code execution)"),
    "dill.load": ("remote_code.deserialization", Severity.HIGH, "unpickles data with dill"),
    "dill.loads": ("remote_code.deserialization", Severity.HIGH, "unpickles data with dill"),
    "cloudpickle.load": ("remote_code.deserialization", Severity.HIGH, "unpickles data with cloudpickle"),
    "cloudpickle.loads": ("remote_code.deserialization", Severity.HIGH, "unpickles data with cloudpickle"),
    "joblib.load": ("remote_code.deserialization", Severity.HIGH, "unpickles data with joblib"),
    "shelve.open": ("remote_code.deserialization", Severity.HIGH, "opens a pickle-backed shelf"),
    "yaml.unsafe_load": ("remote_code.deserialization", Severity.HIGH, "parses YAML with arbitrary object construction"),
    "yaml.full_load": ("remote_code.deserialization", Severity.MEDIUM, "parses YAML with the full (non-safe) loader"),
    "os.remove": ("remote_code.filesystem_tamper", Severity.HIGH, "deletes a file"),
    "os.unlink": ("remote_code.filesystem_tamper", Severity.HIGH, "deletes a file"),
    "os.rmdir": ("remote_code.filesystem_tamper", Severity.HIGH, "deletes a directory"),
    "os.removedirs": ("remote_code.filesystem_tamper", Severity.HIGH, "deletes directories"),
    "os.rename": ("remote_code.filesystem_tamper", Severity.MEDIUM, "renames a file"),
    "os.replace": ("remote_code.filesystem_tamper", Severity.MEDIUM, "replaces a file"),
    "os.chmod": ("remote_code.filesystem_tamper", Severity.HIGH, "changes file permissions"),
    "os.chown": ("remote_code.filesystem_tamper", Severity.HIGH, "changes file ownership"),
    "os.symlink": ("remote_code.filesystem_tamper", Severity.MEDIUM, "creates a symlink"),
    "os.truncate": ("remote_code.filesystem_tamper", Severity.HIGH, "truncates a file"),
    "shutil.rmtree": ("remote_code.filesystem_tamper", Severity.HIGH, "recursively deletes a directory"),
    "shutil.move": ("remote_code.filesystem_tamper", Severity.MEDIUM, "moves files"),
    "shutil.copy": ("remote_code.filesystem_tamper", Severity.LOW, "copies files"),
    "shutil.copyfile": ("remote_code.filesystem_tamper", Severity.LOW, "copies files"),
    "shutil.copytree": ("remote_code.filesystem_tamper", Severity.LOW, "copies a directory tree"),
    "os.putenv": ("remote_code.system_tamper", Severity.MEDIUM, "modifies the process environment"),
    "sys.settrace": ("remote_code.anti_analysis", Severity.HIGH, "installs a trace hook"),
    "sys.setprofile": ("remote_code.anti_analysis", Severity.HIGH, "installs a profile hook"),
    "sys.addaudithook": ("remote_code.anti_analysis", Severity.HIGH, "installs an audit hook"),
    "sys._getframe": ("remote_code.anti_analysis", Severity.LOW, "inspects interpreter frames"),
    "atexit.register": ("remote_code.persistence", Severity.LOW, "registers an exit handler"),
    "builtins.setattr": ("remote_code.monkeypatch", Severity.LOW, "sets an attribute dynamically"),
}

_DECODERS = {
    "base64.b64decode",
    "base64.b32decode",
    "base64.b16decode",
    "base64.a85decode",
    "base64.b85decode",
    "base64.decodebytes",
    "base64.urlsafe_b64decode",
    "binascii.a2b_base64",
    "binascii.a2b_hex",
    "binascii.unhexlify",
    "codecs.decode",
    "zlib.decompress",
    "gzip.decompress",
    "bz2.decompress",
    "lzma.decompress",
    "bytes.fromhex",
    "marshal.loads",
}
_EXECUTORS = {"builtins.eval", "builtins.exec", "builtins.compile", "marshal.loads", "pickle.loads", "types.FunctionType"}

_SENSITIVE_PATH_RE = re.compile(
    r"(\.ssh|id_rsa|id_ed25519|authorized_keys|\.aws|credentials|\.netrc|\.pgpass|\.docker/config|"
    r"\.kube/config|\.git-credentials|/etc/passwd|/etc/shadow|\.bashrc|\.zshrc|\.profile|crontab|"
    r"\.cache/huggingface/token|huggingface/token|\.config/gcloud|\.azure|keychain|\.gnupg)",
    re.IGNORECASE,
)
_SENSITIVE_ENV_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE|CREDENTIAL|AWS_|HF_|OPENAI|ANTHROPIC)", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_BENIGN_URL_HOSTS = ("huggingface.co", "arxiv.org", "github.com/huggingface", "pytorch.org", "apache.org/licenses")
_WRITE_METHODS = {"write_text", "write_bytes", "unlink", "rmdir", "rmtree", "chmod", "symlink_to", "hardlink_to"}
_IMPORT_WATCHLIST = {"ctypes": Severity.LOW, "socket": Severity.LOW, "subprocess": Severity.LOW, "pty": Severity.LOW, "marshal": Severity.LOW, "cffi": Severity.LOW}

_BUILTIN_NAMES = set(dir(builtins))


@dataclass
class RemoteCodeAnalysis:
    filename: str
    findings: List[HubFinding] = field(default_factory=list)
    imports: Set[str] = field(default_factory=set)
    parse_error: Optional[str] = None

    @property
    def risk_score(self) -> float:
        from cyberjection.hubguard.models import compute_risk_score

        return compute_risk_score(self.findings)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class _Analyzer(ast.NodeVisitor):
    def __init__(self, filename: str, source: str, *, depth: int = 0) -> None:
        self.depth = depth
        self.filename = filename
        self.lines = source.splitlines()
        self.aliases: Dict[str, str] = {}
        self.findings: List[HubFinding] = []
        self.imports: Set[str] = set()
        self._scope_depth = 0
        self._seen: Set[Tuple[str, int]] = set()

    # -- helpers ---------------------------------------------------------

    def _snippet(self, node: ast.AST) -> str:
        line = getattr(node, "lineno", 0)
        if 1 <= line <= len(self.lines):
            text = self.lines[line - 1].strip()
            return text if len(text) <= 160 else text[:157] + "..."
        return ""

    def _add(self, node: ast.AST, rule_id: str, severity: Severity, description: str) -> None:
        line = getattr(node, "lineno", None)
        key = (rule_id + description, line or 0)
        if key in self._seen:
            return
        self._seen.add(key)
        at_import = self._scope_depth == 0
        if at_import and severity.rank >= Severity.MEDIUM.rank and severity != Severity.CRITICAL:
            severity = severity.bump()
        if at_import:
            description += " (module level: runs as soon as the file is imported)"
        self.findings.append(
            HubFinding(
                rule_id=rule_id,
                category=FindingCategory.REMOTE_CODE,
                severity=severity,
                description=description,
                file=self.filename,
                line=line,
                evidence=self._snippet(node),
                remediation="Review this file by hand before enabling trust_remote_code, or pin a revision you have reviewed.",
            )
        )

    def resolve(self, node: ast.AST) -> Optional[str]:
        """Best-effort fully-qualified dotted name for an expression."""

        if isinstance(node, ast.Name):
            if node.id in self.aliases:
                return self.aliases[node.id]
            if node.id in _BUILTIN_NAMES:
                return f"builtins.{node.id}"
            return node.id
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            func = self.resolve(node.func)
            first = node.args[0] if node.args else None
            if func in {"builtins.__import__", "importlib.import_module"} and isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
            if func == "builtins.getattr" and len(node.args) >= 2:
                target = node.args[1]
                if isinstance(target, ast.Constant) and isinstance(target.value, str):
                    base = self.resolve(node.args[0])
                    return f"{base}.{target.value}" if base else None
            if func and func.endswith("Path") and func.startswith("pathlib"):
                return "pathlib.Path()"
        if isinstance(node, ast.Subscript):
            base = self.resolve(node.value)
            if base in {"builtins.__builtins__", "builtins.globals()", "builtins.vars"}:
                return "builtins"
        return None

    # -- scope tracking --------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
            self.visit(default)
        self._scope_depth += 1
        for stmt in node.body:
            self.visit(stmt)
        self._scope_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    # Class bodies execute at import time, so they intentionally do *not*
    # increase the scope depth.

    # -- imports ---------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name)
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                top = alias.name.split(".")[0]
                self.aliases[top] = top
            top = alias.name.split(".")[0]
            if top in _IMPORT_WATCHLIST:
                self.findings.append(
                    HubFinding(
                        rule_id="remote_code.sensitive_import",
                        category=FindingCategory.REMOTE_CODE,
                        severity=_IMPORT_WATCHLIST[top],
                        description=f"Imports `{alias.name}`",
                        file=self.filename,
                        line=node.lineno,
                        evidence=self._snippet(node),
                    )
                )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if node.level:
            module = "." * node.level + module
        self.imports.add(module)
        for alias in node.names:
            if alias.name == "*":
                top = module.lstrip(".").split(".")[0]
                if top in {"os", "subprocess", "socket", "ctypes", "pty", "shutil", "pickle", "marshal"}:
                    self._add(node, "remote_code.star_import", Severity.HIGH, f"Star-imports dangerous module `{module}`, hiding which names are used")
                continue
            self.aliases[alias.asname or alias.name] = f"{module.lstrip('.')}.{alias.name}" if module.strip(".") else alias.name
        top = module.lstrip(".").split(".")[0]
        if top in _IMPORT_WATCHLIST and not node.level:
            self.findings.append(
                HubFinding(
                    rule_id="remote_code.sensitive_import",
                    category=FindingCategory.REMOTE_CODE,
                    severity=_IMPORT_WATCHLIST[top],
                    description=f"Imports from `{module}`",
                    file=self.filename,
                    line=node.lineno,
                    evidence=self._snippet(node),
                )
            )

    # -- calls -----------------------------------------------------------

    def _contains_decoder(self, node: ast.AST) -> Optional[str]:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self.resolve(child.func)
                if name in _DECODERS or (name and name.endswith(".decode") and child.args and isinstance(child.args[0], ast.Constant) and str(child.args[0].value).lower() in {"rot13", "rot_13", "hex", "base64", "zlib"}):
                    return name
                if name == "builtins.chr" or (isinstance(child.func, ast.Attribute) and child.func.attr == "join" and any(isinstance(a, (ast.GeneratorExp, ast.ListComp, ast.Call)) for a in child.args)):
                    for sub in ast.walk(child):
                        if isinstance(sub, ast.Name) and sub.id == "chr":
                            return "chr-join"
        return None

    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolve(node.func)
        self.generic_visit(node)
        if not name:
            if isinstance(node.func, ast.Attribute) and node.func.attr in _WRITE_METHODS:
                self._add(node, "remote_code.filesystem_tamper", Severity.MEDIUM, f"Calls `.{node.func.attr}()` (filesystem modification)")
            return

        if name in _EXECUTORS:
            decoder = next((self._contains_decoder(a) for a in node.args if self._contains_decoder(a)), None)
            if decoder:
                self._add(node, "remote_code.obfuscated_execution", Severity.CRITICAL, f"`{name.split('.')[-1]}` runs code decoded at runtime via `{decoder}` (obfuscated payload)")
                return
            if name in {"builtins.eval", "builtins.exec", "builtins.compile"} and node.args and isinstance(node.args[0], ast.Constant):
                self._add(node, "remote_code.dynamic_code", Severity.MEDIUM, f"`{name.split('.')[-1]}` of a constant string")
                self._analyze_nested(node, node.args[0].value, name.split(".")[-1])
                return

        if name in {"builtins.__import__", "importlib.import_module"} and node.args and not isinstance(node.args[0], ast.Constant):
            self._add(node, "remote_code.dynamic_import", Severity.HIGH, f"`{name}` with a computed module name")
            return
        if name in {"builtins.__import__", "importlib.import_module"} and node.args:
            target = str(node.args[0].value).split(".")[0]  # type: ignore[attr-defined]
            if target in _IMPORT_WATCHLIST or target in {"os", "shutil", "pickle", "runpy", "importlib", "sys", "builtins"}:
                self._add(node, "remote_code.dynamic_import", Severity.MEDIUM, f"`{name}('{target}')` hides an import of a sensitive module")
            return
        if name == "builtins.getattr" and len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
            base = self.resolve(node.args[0]) or ""
            if base.split(".")[0] in {"os", "subprocess", "builtins", "socket", "sys", "ctypes", "importlib", "shutil"}:
                self._add(node, "remote_code.dynamic_attribute", Severity.HIGH, f"`getattr` on `{base}` with a computed attribute name")
                return

        if name in {"builtins.open", "io.open", "codecs.open", "os.open"}:
            self._check_open(node, name)
            return
        if name in {"os.getenv", "os.environ.get", "os.environ.__getitem__"}:
            self._check_env(node, node.args[0] if node.args else None)
            return
        if name == "torch.load":
            weights_only = next((kw.value for kw in node.keywords if kw.arg == "weights_only"), None)
            if not (isinstance(weights_only, ast.Constant) and weights_only.value is True):
                self._add(node, "remote_code.deserialization", Severity.HIGH, "`torch.load` without `weights_only=True` unpickles arbitrary objects")
            return
        if name in {"numpy.load", "np.load"}:
            allow = next((kw.value for kw in node.keywords if kw.arg == "allow_pickle"), None)
            if isinstance(allow, ast.Constant) and allow.value is True:
                self._add(node, "remote_code.deserialization", Severity.HIGH, "`numpy.load(allow_pickle=True)` unpickles arbitrary objects")
            return
        if name == "yaml.load":
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"), node.args[1] if len(node.args) > 1 else None)
            loader_name = self.resolve(loader) if loader is not None else None
            if not loader_name or "Safe" not in loader_name:
                self._add(node, "remote_code.deserialization", Severity.HIGH, "`yaml.load` without a SafeLoader can construct arbitrary objects")
            return

        rule = _EXACT_RULES.get(name)
        if rule:
            rule_id, severity, label = rule
            self._add(node, rule_id, severity, f"Calls `{name}`: {label}")
            return
        for prefix, rule_id, severity, label in _PREFIX_RULES:
            if name.startswith(prefix) or name == prefix.rstrip("."):
                if prefix == "huggingface_hub." and not name.split(".")[-1].startswith(("hf_hub_download", "snapshot_download", "cached", "HfApi", "hf_api")):
                    continue
                self._add(node, rule_id, severity, f"Calls `{name}`: {label}")
                return
        if name.startswith("pathlib.Path()") and name.split(".")[-1] in _WRITE_METHODS:
            self._add(node, "remote_code.filesystem_tamper", Severity.MEDIUM, f"Calls `Path.{name.split('.')[-1]}()` (filesystem modification)")

    def _analyze_nested(self, node: ast.Call, payload: Any, via: str) -> None:
        """Code hidden in a string passed to exec/eval runs exactly like
        top-level code; analyze it and report its findings at this line."""

        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", "replace")
        if not isinstance(payload, str) or self.depth >= 3:
            return
        try:
            tree = ast.parse(payload)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return
        inner = _Analyzer(self.filename, payload, depth=self.depth + 1)
        inner._scope_depth = self._scope_depth
        inner.visit(tree)
        for finding in inner.findings:
            if finding.rule_id == "remote_code.sensitive_import":
                continue
            self._add(node, finding.rule_id, finding.severity, f"Inside `{via}` payload: {finding.description}")

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            if isinstance(target, ast.Subscript) and self.resolve(target.value) == "sys.modules":
                self._add(node, "remote_code.anti_analysis", Severity.HIGH, "Deletes an entry from `sys.modules` (hides an import after use)")
        self.generic_visit(node)

    def _check_open(self, node: ast.Call, name: str) -> None:
        path_arg = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in {"file", "path"}), None)
        mode_arg = node.args[1] if len(node.args) > 1 else next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
        path_text = _constant_text(path_arg)
        if path_text and _SENSITIVE_PATH_RE.search(path_text):
            self._add(node, "remote_code.credential_access", Severity.CRITICAL, f"Opens sensitive path `{path_text}`")
            return
        mode = mode_arg.value if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str) else ("r" if mode_arg is None else "?")
        if name == "os.open" or any(c in mode for c in "wax+?"):
            self._add(node, "remote_code.filesystem_write", Severity.MEDIUM, f"Opens a file for writing (mode `{mode}`)")

    def _check_env(self, node: ast.AST, key: Optional[ast.AST]) -> None:
        key_text = _constant_text(key)
        if key_text and _SENSITIVE_ENV_RE.search(key_text):
            self._add(node, "remote_code.credential_access", Severity.HIGH, f"Reads credential-like environment variable `{key_text}`")

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self.resolve(node.value) == "os.environ":
            self._check_env(node, node.slice)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            name = self.resolve(target)
            if name and (name.startswith(("builtins.", "torch.load", "pickle.", "sys.modules", "os.")) or name in {"torch.load", "transformers.modeling_utils.load_state_dict"}):
                self._add(node, "remote_code.monkeypatch", Severity.HIGH, f"Overwrites `{name}` (monkeypatches a library/builtin)")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            text = node.value
            if _SENSITIVE_PATH_RE.search(text) and len(text) < 300:
                self._add(node, "remote_code.credential_path_reference", Severity.MEDIUM, f"References sensitive path `{text[:80]}`")
            if len(text) >= 200 and " " not in text[:200] and _shannon_entropy(text) > 4.5:
                self._add(node, "remote_code.encoded_blob", Severity.MEDIUM, f"High-entropy {len(text)}-character string literal (possible encoded payload)")
            for url in _URL_RE.findall(text):
                if not any(host in url for host in _BENIGN_URL_HOSTS):
                    self._add(node, "remote_code.external_url", Severity.LOW, f"References external URL `{url[:100]}`")


def _constant_text(node: Optional[ast.AST]) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _constant_text(node.left), _constant_text(node.right)
        return (left or "") + (right or "") or None
    if isinstance(node, ast.Call) and node.args:
        return _constant_text(node.args[0])
    return None


def analyze_python_source(source: str, *, filename: str = "<source>") -> RemoteCodeAnalysis:
    """Parses `source` (never executes it) and returns every finding."""

    analysis = RemoteCodeAnalysis(filename=filename)
    if "\x00" in source:
        analysis.parse_error = "source contains NUL bytes"
    else:
        try:
            tree = ast.parse(source, filename=filename)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            analysis.parse_error = f"{type(exc).__name__}: {exc}"
        else:
            analyzer = _Analyzer(filename, source)
            analyzer.visit(tree)
            analysis.findings = analyzer.findings
            analysis.imports = analyzer.imports
    if analysis.parse_error:
        analysis.findings.append(
            HubFinding(
                rule_id="remote_code.unparseable",
                category=FindingCategory.REMOTE_CODE,
                severity=Severity.HIGH,
                description=f"Python file could not be parsed ({analysis.parse_error}); it cannot be statically verified.",
                file=filename,
            )
        )
    return analysis


def analyze_source_for_findings(source: str, *, filename: str = "<source>") -> List[HubFinding]:
    return analyze_python_source(source, filename=filename).findings


# --- repository-level remote-code requirements ------------------------------


@dataclass(frozen=True)
class AutoMapEntry:
    auto_class: str
    reference: str
    source_file: str  # config file the entry came from
    module: str
    class_name: str
    external_repo: Optional[str]


def parse_auto_map(config_text: str, *, source_file: str) -> List[AutoMapEntry]:
    """Extracts `auto_map` entries from a `config.json` /
    `tokenizer_config.json`. Each value names `module.Class`, or
    `org/repo--module.Class` for code hosted in *another* repository."""

    try:
        data = json.loads(config_text)
    except (json.JSONDecodeError, ValueError):
        return []
    auto_map = data.get("auto_map") if isinstance(data, dict) else None
    if not isinstance(auto_map, dict):
        return []
    entries: List[AutoMapEntry] = []
    for auto_class, value in auto_map.items():
        references: Iterable[Any] = value if isinstance(value, list) else [value]
        for reference in references:
            if not isinstance(reference, str) or not reference:
                continue
            external = None
            local = reference
            if "--" in reference:
                external, local = reference.split("--", 1)
            module, _, class_name = local.rpartition(".")
            entries.append(AutoMapEntry(str(auto_class), reference, source_file, module, class_name, external))
    return entries


def analyze_auto_map(entries: List[AutoMapEntry], repo_files: Set[str], *, block_remote_code: bool) -> List[HubFinding]:
    findings: List[HubFinding] = []
    if not entries:
        return findings
    modules = sorted({e.module for e in entries})
    findings.append(
        HubFinding(
            rule_id="remote_code.required",
            category=FindingCategory.POLICY if block_remote_code else FindingCategory.REMOTE_CODE,
            severity=Severity.HIGH if block_remote_code else Severity.LOW,
            blocking=block_remote_code,
            description=(
                "Repository requires trust_remote_code=True (auto_map references "
                + ", ".join(f"`{m}`" for m in modules)
                + ")"
                + ("; policy forbids remote code." if block_remote_code else ".")
            ),
            file=entries[0].source_file,
            remediation="Use a natively-supported architecture, or vendor and review the code before loading.",
        )
    )
    for entry in entries:
        if entry.external_repo:
            findings.append(
                HubFinding(
                    rule_id="remote_code.cross_repo",
                    category=FindingCategory.REMOTE_CODE,
                    severity=Severity.HIGH,
                    description=(
                        f"auto_map `{entry.auto_class}` loads code from a different repository "
                        f"(`{entry.external_repo}`), which this scan does not cover and whose owner can change it independently."
                    ),
                    file=entry.source_file,
                    evidence=entry.reference,
                    remediation=f"Scan `{entry.external_repo}` as well and pin its revision, or vendor the code.",
                )
            )
        elif f"{entry.module.replace('.', '/')}.py" not in repo_files:
            findings.append(
                HubFinding(
                    rule_id="remote_code.missing_module",
                    category=FindingCategory.REMOTE_CODE,
                    severity=Severity.MEDIUM,
                    description=f"auto_map references `{entry.module}.py`, which is not in the repository at this revision.",
                    file=entry.source_file,
                    evidence=entry.reference,
                )
            )
    return findings
