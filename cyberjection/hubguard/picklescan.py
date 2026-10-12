"""Static pickle / PyTorch checkpoint inspection -- never unpickles anything.

`torch.load()` on a legacy checkpoint is `pickle.load()`, and `pickle.load()`
is a small stack-machine interpreter whose `GLOBAL`/`STACK_GLOBAL`
opcodes import any callable by name and whose `REDUCE` opcode calls it.
A `pytorch_model.bin` can therefore run `os.system(...)` the moment it is
loaded. This module walks the opcode stream with `pickletools.genops` --
which only *decodes* opcodes, it never executes them -- and reports every
import the stream would perform.

How the scan resists the usual evasions:

- **Symbolic stack.** `STACK_GLOBAL` (protocol 4+) takes its module and
  attribute names from the stack rather than an inline argument, so a
  naive scanner that only reads `GLOBAL`'s argument misses it entirely.
  `_SymbolicMachine` mirrors the unpickler's stack and memo using
  `pickletools`' own per-opcode stack-effect metadata (the same metadata
  `pickletools.dis` uses to validate stacks), so names that were pushed,
  memoized and fetched back via `BINGET` still resolve. A `STACK_GLOBAL`
  whose operands *can't* be resolved to constant strings is reported as
  CRITICAL -- the scan fails closed rather than guessing.
- **Dotted attribute names.** `find_class` resolves `name` with
  `getattr` per dot-separated segment, so `("torch._utils", "os.system")`
  reaches `os.system` through a module that merely imported `os`. Every
  segment of the fully-qualified path is checked, not just the module.
- **Python 2 aliases.** `__builtin__.eval`, `copy_reg`, etc. are
  normalized through `_compat_pickle` exactly as the unpickler does for
  protocol < 3, so they match the same rules as their Python 3 names.
- **Container formats.** Modern `torch.save` output is a ZIP archive with
  the pickle at `<archive>/data.pkl`; legacy output is several pickles
  concatenated; `.npy` object arrays embed a pickle after the header;
  `.npz` is a ZIP of `.npy` files. All four are unwrapped and every
  embedded pickle is scanned. Bytes constants that are themselves pickles
  (`torch.storage._load_from_bytes`) are scanned recursively.
- **Embedded code.** String constants that parse as Python (the argument
  to a pickled `exec`, say) or that base64-decode to Python or to another
  pickle are run through `cyberjection.hubguard.remotecode`'s AST
  analyzer, so the report says what the payload *does*, not only that a
  dangerous import exists.

Allowlisting is exact-match on `(module, name)`; anything not allowlisted
and not denylisted is reported as MEDIUM "non-allowlisted import" because
it still executes that class's construction logic during load.
"""

from __future__ import annotations

import _compat_pickle
import ast
import base64
import binascii
import io
import pickletools
import re
import warnings
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Dict, Iterator, List, Optional, Set, Tuple, Union

from cyberjection.hubguard.models import FindingCategory, HubFinding, Severity
from cyberjection.utils.exceptions import CyberjectionException

PICKLE_EXTENSIONS = frozenset(
    {".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".dill", ".npy", ".npz", ".mar", ".pdparams"}
)

# Hard ceilings so a hostile file can't turn the scanner itself into a DoS.
DEFAULT_MAX_PICKLE_BYTES = 1 << 30  # 1 GiB of opcode stream per embedded pickle
DEFAULT_MAX_ZIP_MEMBER_BYTES = 512 << 20
_MAX_NESTED_DEPTH = 3
_MAX_CODE_STRING_LEN = 200_000
_MAX_REPORTED_UNKNOWN = 25

# --- rule tables -----------------------------------------------------------

# Exact (module, name) pairs that appear in ordinary PyTorch / NumPy /
# scikit-learn style checkpoints and do nothing beyond rebuilding data.
SAFE_GLOBALS: Dict[str, Set[str]] = {
    "collections": {"OrderedDict", "defaultdict", "deque", "Counter"},
    "torch._utils": {
        "_rebuild_tensor",
        "_rebuild_tensor_v2",
        "_rebuild_tensor_v3",
        "_rebuild_parameter",
        "_rebuild_parameter_with_state",
        "_rebuild_sparse_tensor",
        "_rebuild_sparse_csr_tensor",
        "_rebuild_qtensor",
        "_rebuild_nested_tensor",
        "_rebuild_meta_tensor_no_storage",
        "_rebuild_wrapper_subclass",
        "_rebuild_device_tensor_from_numpy",
    },
    "torch._tensor": {"_rebuild_from_type_v2", "_rebuild_from_type"},
    "torch.nn.parameter": {"Parameter"},
    "torch.serialization": {"_get_layout"},
    "torch.storage": {"UntypedStorage", "TypedStorage"},
    "torch": {
        "Size",
        "Tensor",
        "device",
        "dtype",
        "layout",
        "memory_format",
        "strided",
        "sparse_coo",
        "float16",
        "float32",
        "float64",
        "bfloat16",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint8",
        "bool",
        "complex64",
        "complex128",
        "contiguous_format",
        "channels_last",
        "preserve_format",
        "FloatStorage",
        "HalfStorage",
        "BFloat16Storage",
        "DoubleStorage",
        "LongStorage",
        "IntStorage",
        "ShortStorage",
        "CharStorage",
        "ByteStorage",
        "BoolStorage",
        "ComplexFloatStorage",
        "ComplexDoubleStorage",
        "QUInt8Storage",
        "QInt8Storage",
        "QInt32Storage",
        "QUInt4x2Storage",
        "QUInt2x4Storage",
    },
    "numpy": {"ndarray", "dtype", "float16", "float32", "float64", "int8", "int16", "int32", "int64", "uint8", "bool_"},
    "numpy.core.multiarray": {"_reconstruct", "scalar"},
    "numpy._core.multiarray": {"_reconstruct", "scalar"},
    "numpy.dtypes": {
        "Float16DType",
        "Float32DType",
        "Float64DType",
        "Int8DType",
        "Int16DType",
        "Int32DType",
        "Int64DType",
        "UInt8DType",
        "BoolDType",
    },
    "builtins": {"set", "frozenset", "slice", "range", "complex", "bytearray", "bytes", "dict", "list", "tuple", "int", "float", "str", "bool"},
    "_codecs": {"encode"},
    "copyreg": {"_reconstructor"},
    "argparse": {"Namespace"},
    "pathlib": {"PosixPath", "WindowsPath", "PurePosixPath", "PureWindowsPath", "Path"},
    "datetime": {"datetime", "date", "time", "timedelta", "timezone"},
    "decimal": {"Decimal"},
    "uuid": {"UUID"},
    "types": {"SimpleNamespace"},
    "joblib.numpy_pickle": {"NumpyArrayWrapper"},
}

# Any import whose fully-qualified path is, or is inside, one of these
# modules is CRITICAL: each offers direct process, filesystem, network,
# code-loading or native-memory access.
DANGEROUS_MODULES: Tuple[str, ...] = (
    "os",
    "posix",
    "nt",
    "subprocess",
    "sys",
    "socket",
    "_socket",
    "shutil",
    "pty",
    "commands",
    "popen2",
    "platform",
    "runpy",
    "importlib",
    "imp",
    "zipimport",
    "pkgutil",
    "pickle",
    "_pickle",
    "cPickle",
    "dill",
    "cloudpickle",
    "joblib.load",
    "joblib.numpy_pickle.load",
    "marshal",
    "types",
    "code",
    "codeop",
    "ctypes",
    "_ctypes",
    "cffi",
    "webbrowser",
    "requests",
    "httpx",
    "urllib",
    "urllib2",
    "urllib3",
    "http",
    "httplib",
    "ftplib",
    "smtplib",
    "telnetlib",
    "asyncio",
    "multiprocessing",
    "signal",
    "pdb",
    "bdb",
    "timeit",
    "trace",
    "profile",
    "cProfile",
    "pydoc",
    "shelve",
    "tempfile",
    "glob",
    "io",
    "_io",
    "site",
    "sysconfig",
    "venv",
    "ensurepip",
    "distutils",
    "setuptools",
    "pip",
    "builtins.__import__",
    "torch.hub",
    "torch.load",
    "torch.serialization.load",
    "torch.storage._load_from_bytes",
    "torch.jit",
    "torch._C",
    "torch.ops",
    "numpy.load",
    "numpy.testing",
    "numpy.f2py",
    "numpy.distutils",
    "_posixsubprocess",
    "_winapi",
    "winreg",
    "_thread",
    "threading",
    "concurrent",
    "socketserver",
    "xmlrpc",
    "ssl",
    "paramiko",
)

# Builtins that directly execute code, touch files, or import modules.
_CRITICAL_BUILTINS = frozenset(
    {"eval", "exec", "compile", "open", "__import__", "execfile", "apply", "input", "breakpoint", "file", "reload", "exit", "quit"}
)
# Builtins that are code-execution *gadgets*: harmless alone, but let a
# pickle walk attributes or build new types to reach something that isn't.
_HIGH_BUILTINS = frozenset({"getattr", "setattr", "delattr", "globals", "locals", "vars", "type", "super", "object", "memoryview", "help", "dir"})
_GADGETS: Dict[str, Set[str]] = {
    "operator": {"attrgetter", "methodcaller", "itemgetter", "call"},
    "_operator": {"attrgetter", "methodcaller", "itemgetter", "call"},
    "functools": {"partial", "reduce", "partialmethod"},
    "_functools": {"partial", "reduce"},
    "copyreg": {"__newobj__", "__newobj_ex__", "add_extension"},
    "codecs": {"open", "decode"},
    "collections": {"UserDict"},
}

_BUILTIN_MODULES = {"builtins", "__builtin__", "__builtins__", "__main__"}

_STRING_PUSH_OPS = {
    "STRING",
    "BINSTRING",
    "SHORT_BINSTRING",
    "UNICODE",
    "BINUNICODE",
    "SHORT_BINUNICODE",
    "BINUNICODE8",
}
_BYTES_PUSH_OPS = {"BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8"}
_GET_OPS = {"GET", "BINGET", "LONG_BINGET"}
_PUT_OPS = {"PUT", "BINPUT", "LONG_BINPUT"}
_CALL_OPS = {"REDUCE", "NEWOBJ", "NEWOBJ_EX", "BUILD", "INST", "OBJ"}
_EXT_OPS = {"EXT1", "EXT2", "EXT4"}

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s_-]{24,}$")
_TORCH_LEGACY_MAGIC = 0x1950A86A20F9469CFC6C


# --- results ---------------------------------------------------------------


@dataclass(frozen=True)
class GlobalImport:
    module: str
    name: str
    opcode: str
    position: int
    severity: Severity
    reason: str

    @property
    def qualified(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass
class PickleScanResult:
    """Everything the scanner learned about one file."""

    path: str
    format: str = "unknown"
    pickles_scanned: int = 0
    opcode_count: int = 0
    imports: List[GlobalImport] = field(default_factory=list)
    findings: List[HubFinding] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return not any(f.severity.rank >= Severity.MEDIUM.rank for f in self.findings)

    @property
    def dangerous_imports(self) -> List[GlobalImport]:
        return [g for g in self.imports if g.severity.rank >= Severity.HIGH.rank]


# --- classification --------------------------------------------------------


def _normalize(module: str, name: str) -> Tuple[str, str]:
    """Apply the unpickler's own Python 2 -> 3 name mapping (`fix_imports`)."""

    if (module, name) in _compat_pickle.NAME_MAPPING:
        module, name = _compat_pickle.NAME_MAPPING[(module, name)]
    elif module in _compat_pickle.IMPORT_MAPPING:
        module = _compat_pickle.IMPORT_MAPPING[module]
    return module.strip(), name.strip()


def classify_global(module: str, name: str) -> Tuple[Severity, str]:
    """Returns `(severity, reason)` for one import. `Severity.INFO` means
    allowlisted (safe)."""

    module, name = _normalize(module, name)
    qualified = f"{module}.{name}"
    segments = qualified.split(".")
    name_segments = name.split(".")

    if not module or not name or any(not s for s in segments):
        return Severity.CRITICAL, "malformed import target"

    if module in _BUILTIN_MODULES:
        head = name_segments[0]
        if head in _CRITICAL_BUILTINS:
            return Severity.CRITICAL, f"builtin `{head}` executes code or performs I/O"
        if head in _HIGH_BUILTINS or len(name_segments) > 1:
            return Severity.HIGH, f"builtin `{name}` is an attribute-traversal / type-construction gadget"
        if name in SAFE_GLOBALS["builtins"]:
            return Severity.INFO, "allowlisted builtin"
        return Severity.MEDIUM, f"non-allowlisted builtin `{name}`"

    if "." not in name and name in SAFE_GLOBALS.get(module, ()):
        return Severity.INFO, "allowlisted"

    for dangerous in DANGEROUS_MODULES:
        if qualified == dangerous or qualified.startswith(dangerous + "."):
            return Severity.CRITICAL, f"`{qualified}` is inside dangerous module `{dangerous}`"

    # `getattr`-per-segment resolution: ("torch._utils", "os.system")
    # reaches os.system through a module that merely imported os.
    for segment in name_segments[:-1] if len(name_segments) > 1 else []:
        if segment in {d.split(".")[0] for d in DANGEROUS_MODULES} or segment in _BUILTIN_MODULES:
            return Severity.CRITICAL, f"dotted name `{name}` traverses into `{segment}`"
    if len(name_segments) > 1 and (name_segments[-1] in _CRITICAL_BUILTINS or name_segments[-1] in {"system", "popen"}):
        return Severity.CRITICAL, f"dotted name `{name}` reaches `{name_segments[-1]}`"
    if any(seg.startswith("__") and seg.endswith("__") and seg not in {"__new__"} for seg in name_segments):
        return Severity.HIGH, f"dunder attribute traversal in `{name}`"

    gadget_names = _GADGETS.get(module)
    if gadget_names and name in gadget_names:
        return Severity.HIGH, f"`{qualified}` is a known pickle code-execution gadget"

    if len(name_segments) > 1:
        return Severity.HIGH, f"dotted attribute path `{name}` on non-allowlisted module"
    return Severity.MEDIUM, f"non-allowlisted import `{qualified}` (its construction logic runs during load)"


# --- symbolic unpickler ----------------------------------------------------


class _Mark:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<MARK>"


class _Unknown:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<?>"


_MARK = _Mark()
_UNKNOWN = _Unknown()


@dataclass(frozen=True)
class _GlobalRef:
    module: str
    name: str


@dataclass(frozen=True)
class _CallResult:
    callee: Any
    args: Any


class _SymbolicMachine:
    """Tracks the unpickler's stack/memo just precisely enough to resolve
    `STACK_GLOBAL` operands and the argument tuples handed to `REDUCE`."""

    def __init__(self) -> None:
        self.stack: List[Any] = []
        self.memo: Dict[int, Any] = {}
        self.anomalies: List[str] = []

    def _pop_to_mark(self) -> List[Any]:
        items: List[Any] = []
        while self.stack:
            top = self.stack.pop()
            if top is _MARK:
                items.reverse()
                return items
            items.append(top)
        self.anomalies.append("pop-to-mark with no MARK on the stack")
        items.reverse()
        return items

    def _pop(self, n: int) -> List[Any]:
        if n <= 0:
            return []
        if len(self.stack) < n:
            self.anomalies.append(f"stack underflow ({n} > {len(self.stack)})")
            popped = self.stack[:]
            self.stack.clear()
            return [_UNKNOWN] * (n - len(popped)) + popped
        popped = self.stack[-n:]
        del self.stack[-n:]
        return popped

    def peek(self, depth: int = 1) -> Any:
        return self.stack[-depth] if len(self.stack) >= depth else _UNKNOWN

    def step(self, op: pickletools.OpcodeInfo, arg: Any) -> Tuple[List[Any], Any]:
        """Applies one opcode. Returns `(consumed_items, pushed_value)`."""

        name = op.name
        before, after = op.stack_before, op.stack_after

        if name == "MARK":
            self.stack.append(_MARK)
            return [], _MARK
        if name in _PUT_OPS:
            self.memo[int(arg)] = self.peek()
            return [], None
        if name == "MEMOIZE":
            self.memo[len(self.memo)] = self.peek()
            return [], None
        if name in _GET_OPS:
            value = self.memo.get(int(arg), _UNKNOWN)
            if int(arg) not in self.memo:
                self.anomalies.append(f"memo get of unset index {arg}")
            self.stack.append(value)
            return [], value
        if name == "DUP":
            value = self.peek()
            self.stack.append(value)
            return [], value

        consumed: List[Any]
        if pickletools.markobject in before:
            marked = self._pop_to_mark()
            extra = self._pop(before.index(pickletools.markobject))
            consumed = extra + marked
        elif name == "POP" and self.stack and self.stack[-1] is _MARK:
            self.stack.pop()
            consumed = []
        else:
            consumed = self._pop(len(before))

        pushed: Any = _UNKNOWN
        if name in _STRING_PUSH_OPS:
            pushed = arg.decode("latin-1") if isinstance(arg, bytes) else arg
        elif name in _BYTES_PUSH_OPS:
            pushed = bytes(arg)
        elif name == "GLOBAL" or name == "INST":
            module, _, attr = str(arg).partition(" ")
            pushed = _GlobalRef(module, attr) if name == "GLOBAL" else _CallResult(_GlobalRef(module, attr), tuple(consumed))
        elif name == "STACK_GLOBAL":
            operands: Tuple[Any, Any] = (consumed[0], consumed[1]) if len(consumed) == 2 else (_UNKNOWN, _UNKNOWN)
            module, attr = operands
            if isinstance(module, str) and isinstance(attr, str):
                pushed = _GlobalRef(module, attr)
            else:
                pushed = _GlobalRef("<unresolved>", "<unresolved>")
        elif name in {"TUPLE", "TUPLE1", "TUPLE2", "TUPLE3"}:
            pushed = tuple(consumed)
        elif name == "EMPTY_TUPLE":
            pushed = ()
        elif name in {"REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ"} and consumed:
            pushed = _CallResult(consumed[0], tuple(consumed[1:]))
        elif name in {"BUILD", "APPEND", "APPENDS", "SETITEM", "SETITEMS", "ADDITEMS"}:
            # These mutate and leave the target object on the stack; keep
            # whatever we knew about it.
            pushed = consumed[0] if consumed else _UNKNOWN

        if after:
            for _ in after[:-1]:
                self.stack.append(_UNKNOWN)
            self.stack.append(pushed)
        return consumed, pushed


# --- core scan -------------------------------------------------------------


def _short(value: Any, limit: int = 120) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _string_constants(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, tuple):
        for item in value:
            yield from _string_constants(item)


class _ScanContext:
    def __init__(self, label: str, result: PickleScanResult, max_pickle_bytes: int) -> None:
        self.label = label
        self.result = result
        self.max_pickle_bytes = max_pickle_bytes
        self.unknown_reported: Set[str] = set()
        self.analyzed_strings: Set[int] = set()  # hashes of strings already analyzed

    def add(self, **kwargs: Any) -> None:
        self.result.findings.append(
            HubFinding(category=FindingCategory.PICKLE, file=self.label, **kwargs)
        )


def _record_import(ctx: _ScanContext, ref: _GlobalRef, opcode: str, pos: int, member: str) -> None:
    where = f"{member}@{pos}" if member else f"offset {pos}"
    if ref.module == "<unresolved>":
        ctx.result.imports.append(GlobalImport("<unresolved>", "<unresolved>", opcode, pos, Severity.CRITICAL, "unresolved"))
        ctx.add(
            rule_id="pickle.unresolved_stack_global",
            severity=Severity.CRITICAL,
            description=(
                f"{opcode} at {where} imports a callable whose module/name are computed at load time "
                "and cannot be resolved statically -- a common scanner-evasion technique."
            ),
            remediation="Do not load this file with pickle/torch.load. Request a SafeTensors export.",
        )
        return

    severity, reason = classify_global(ref.module, ref.name)
    module, name = _normalize(ref.module, ref.name)
    ctx.result.imports.append(GlobalImport(module, name, opcode, pos, severity, reason))
    if severity == Severity.INFO:
        return
    qualified = f"{module}.{name}"
    if severity == Severity.MEDIUM:
        if qualified in ctx.unknown_reported:
            return
        ctx.unknown_reported.add(qualified)
        if len(ctx.unknown_reported) > _MAX_REPORTED_UNKNOWN:
            return
    ctx.add(
        rule_id="pickle.dangerous_import" if severity.rank >= Severity.HIGH.rank else "pickle.unknown_import",
        severity=severity,
        description=f"Pickle {opcode} at {where} imports `{qualified}`: {reason}.",
        evidence=qualified,
        remediation=(
            "Never load with torch.load()/pickle.load(). Use a SafeTensors export, or "
            "torch.load(..., weights_only=True) only if you also trust the producer."
            if severity.rank >= Severity.HIGH.rank
            else "Confirm this class is expected for this checkpoint; prefer SafeTensors."
        ),
    )


def _analyze_string(ctx: _ScanContext, text: str, where: str, depth: int, *, invoked_by: Optional[str]) -> None:
    """Heuristic AST pass over strings that might be embedded code."""

    key = hash(text)
    if len(text) < 8 or len(text) > _MAX_CODE_STRING_LEN or key in ctx.analyzed_strings:
        return
    ctx.analyzed_strings.add(key)

    candidates: List[Tuple[str, str]] = [(text, "literal")]
    stripped = text.strip()
    if _BASE64_RE.match(stripped) and len(stripped) % 4 in (0, 2, 3):
        try:
            decoded = base64.b64decode(stripped + "=" * (-len(stripped) % 4), altchars=b"-_" if "-" in stripped or "_" in stripped else None)
        except (binascii.Error, ValueError):
            decoded = b""
        if decoded[:1] == b"\x80" and decoded[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05") and depth < _MAX_NESTED_DEPTH:
            ctx.add(
                rule_id="pickle.nested_encoded_pickle",
                severity=Severity.HIGH,
                description=f"Base64 string at {where} decodes to another pickle stream; scanning it recursively.",
            )
            _scan_stream(ctx, io.BytesIO(decoded), member=f"{where}/base64", depth=depth + 1)
        else:
            try:
                candidates.append((decoded.decode("utf-8"), "base64-decoded"))
            except UnicodeDecodeError:
                pass

    from cyberjection.hubguard.remotecode import analyze_source_for_findings

    for candidate, how in candidates:
        try:
            tree = ast.parse(candidate)
        except (SyntaxError, ValueError, MemoryError, RecursionError):
            continue
        if not any(isinstance(n, (ast.Call, ast.Import, ast.ImportFrom)) for n in ast.walk(tree)):
            continue
        code_findings = analyze_source_for_findings(candidate, filename=f"{ctx.label}:{where}")
        significant = [f for f in code_findings if f.severity.rank >= Severity.MEDIUM.rank]
        if not significant and invoked_by is None:
            continue
        worst = max((f.severity for f in significant), key=lambda s: s.rank, default=Severity.MEDIUM)
        if invoked_by is not None:
            worst = Severity.CRITICAL
        summary = "; ".join(sorted({f.description.removesuffix(" (module level: runs as soon as the file is imported)") for f in significant})) or "parses as Python"
        ctx.add(
            rule_id="pickle.embedded_code",
            severity=worst,
            description=(
                f"{how.capitalize()} string at {where} is Python source"
                + (f" passed to `{invoked_by}`" if invoked_by else "")
                + f" ({summary})."
            ),
            evidence=_short(candidate, 160),
        )


def _scan_stream(ctx: _ScanContext, stream: IO[bytes], *, member: str = "", depth: int = 0) -> bool:
    """Scans one pickle from the current stream position up to and
    including its STOP opcode. Returns True if a complete pickle was read.
    Raises `ValueError` if the stream at this position isn't a pickle."""

    machine = _SymbolicMachine()
    start = stream.tell() if stream.seekable() else 0
    saw_stop = False
    count = 0
    for op, arg, pos in pickletools.genops(stream):
        count += 1
        if pos is not None and pos - start > ctx.max_pickle_bytes:
            ctx.add(
                rule_id="pickle.too_large",
                severity=Severity.HIGH,
                description=f"Pickle stream exceeds the {ctx.max_pickle_bytes}-byte scan ceiling; remainder not inspected.",
            )
            break
        consumed, pushed = machine.step(op, arg)
        where = f"{member}@{pos}" if member else f"offset {pos}"

        if op.name in {"GLOBAL", "STACK_GLOBAL", "INST"}:
            ref = pushed.callee if isinstance(pushed, _CallResult) else pushed
            if isinstance(ref, _GlobalRef):
                _record_import(ctx, ref, op.name, pos or 0, member)
        elif op.name in _EXT_OPS:
            ctx.add(
                rule_id="pickle.extension_registry",
                severity=Severity.HIGH,
                description=(
                    f"{op.name} at {where} fetches a callable from the copyreg extension registry, "
                    "which can map to any object registered in the loading process."
                ),
            )
        elif op.name in _STRING_PUSH_OPS and isinstance(pushed, str):
            _analyze_string(ctx, pushed, where, depth, invoked_by=None)
        elif op.name in _BYTES_PUSH_OPS and isinstance(pushed, bytes):
            if pushed[:1] == b"\x80" and pushed[1:2] in (b"\x02", b"\x03", b"\x04", b"\x05") and depth < _MAX_NESTED_DEPTH:
                inner = io.BytesIO(pushed)
                try:
                    _scan_stream(ctx, inner, member=f"{where}/bytes", depth=depth + 1)
                except ValueError:
                    pass

        if op.name == "REDUCE" and len(consumed) == 2:
            callee, args = consumed
            if isinstance(callee, _GlobalRef):
                severity, _ = classify_global(callee.module, callee.name)
                if severity.rank >= Severity.HIGH.rank:
                    module, name = _normalize(callee.module, callee.name)
                    for text in _string_constants(args):
                        _analyze_string(ctx, text, where, depth, invoked_by=f"{module}.{name}")
                    ctx.add(
                        rule_id="pickle.dangerous_call",
                        severity=Severity.CRITICAL,
                        description=f"REDUCE at {where} calls `{module}.{name}` during deserialization.",
                        evidence=f"{module}.{name}{_short(args, 100)}",
                    )

        if op.name == "STOP":
            saw_stop = True
            break

    ctx.result.opcode_count += count
    if saw_stop:
        ctx.result.pickles_scanned += 1
    for anomaly in sorted(set(machine.anomalies))[:5]:
        ctx.add(
            rule_id="pickle.stack_anomaly",
            severity=Severity.MEDIUM,
            description=f"Pickle stack anomaly ({anomaly}) -- malformed or crafted to confuse scanners.",
        )
    if not saw_stop:
        raise ValueError("pickle stream ended without STOP")
    return True


def _scan_concatenated(ctx: _ScanContext, stream: IO[bytes], *, member: str = "") -> None:
    """Scans consecutive pickles the way legacy `torch.load` reads them
    (magic number, protocol, sys_info, payload, storage keys, then raw
    storage bytes). Stops quietly at the first non-pickle data once at
    least one pickle parsed; fails loudly if the first one doesn't."""

    # Legacy torch.load reads exactly five pickles (magic, protocol,
    # sys_info, payload, storage keys) and then raw tensor bytes; parsing
    # past them would interpret float data as opcodes.
    start = stream.tell()
    max_pickles = 5 if _looks_like_legacy_torch(stream, start) else None
    stream.seek(start)
    count = 0
    while max_pickles is None or count < max_pickles:
        pos = stream.tell()
        head = stream.read(1)
        if not head:
            return
        stream.seek(pos)
        checkpoint = (len(ctx.result.findings), len(ctx.result.imports), ctx.result.opcode_count, set(ctx.unknown_reported))
        try:
            _scan_stream(ctx, stream, member=member)
        except ValueError as exc:
            if count == 0:
                ctx.add(
                    rule_id="pickle.unparseable",
                    severity=Severity.HIGH,
                    description=f"File is in a pickle-capable format but could not be parsed as pickle ({exc}); its safety cannot be verified.",
                )
            else:
                # Trailing non-pickle data (which the loader never reads as
                # a pickle either): discard anything recorded while
                # misreading it, so binary noise can't produce findings.
                del ctx.result.findings[checkpoint[0]:]
                del ctx.result.imports[checkpoint[1]:]
                ctx.result.opcode_count = checkpoint[2]
                ctx.unknown_reported = checkpoint[3]
            return
        count += 1


def _read_npy_header(stream: IO[bytes]) -> Dict[str, Any]:
    magic = stream.read(6)
    if magic != b"\x93NUMPY":
        raise ValueError("not an .npy file")
    major = stream.read(2)[0]
    if major == 1:
        header_len = int.from_bytes(stream.read(2), "little")
    elif major in (2, 3):
        header_len = int.from_bytes(stream.read(4), "little")
    else:
        raise ValueError(f"unsupported .npy version {major}")
    if header_len > 1 << 20:
        raise ValueError("oversized .npy header")
    header = stream.read(header_len).decode("latin-1")
    parsed = ast.literal_eval(header)  # literal_eval: no code execution
    if not isinstance(parsed, dict):
        raise ValueError("malformed .npy header")
    return parsed


def _scan_npy(ctx: _ScanContext, stream: IO[bytes], member: str) -> None:
    try:
        header = _read_npy_header(stream)
    except (ValueError, SyntaxError, IndexError) as exc:
        ctx.add(rule_id="pickle.unparseable", severity=Severity.MEDIUM, description=f".npy header in {member or 'file'} is malformed ({exc}).")
        return
    if "O" in str(header.get("descr", "")):
        ctx.add(
            rule_id="pickle.npy_object_array",
            severity=Severity.MEDIUM,
            description=f".npy array {member or ''} has dtype=object: its payload is a pickle and np.load(allow_pickle=True) would execute it.",
        )
        _scan_concatenated(ctx, stream, member=member)


def _scan_zip(ctx: _ScanContext, raw: IO[bytes], max_member_bytes: int) -> None:
    ctx.result.format = "zip"
    try:
        archive = zipfile.ZipFile(raw)
    except CyberjectionException:
        raise
    except Exception as exc:  # noqa: BLE001 -- BadZipFile, NotImplementedError (unsupported version), ...
        ctx.add(rule_id="pickle.unparseable", severity=Severity.HIGH, description=f"Corrupt ZIP container ({exc}).")
        return
    with archive:
        names = archive.namelist()
        is_torch = any(n.endswith("data.pkl") for n in names)
        ctx.result.format = "torch-zip" if is_torch else "zip"
        if any(n.split("/")[-2:-1] == ["code"] or "/code/" in n for n in names) and is_torch:
            ctx.add(
                rule_id="pickle.torchscript_code",
                severity=Severity.LOW,
                description="Archive contains TorchScript code; torch.jit.load would compile and run it.",
            )
        for info in archive.infolist():
            name = info.filename
            lower = name.lower()
            if not (lower.endswith(".pkl") or lower.endswith(".npy") or lower.endswith(".pickle")):
                continue
            if info.file_size > max_member_bytes:
                ctx.add(rule_id="pickle.too_large", severity=Severity.HIGH, description=f"ZIP member {name} ({info.file_size} bytes) exceeds scan ceiling.")
                continue
            if info.compress_size and info.file_size / max(info.compress_size, 1) > 200 and info.file_size > 50 << 20:
                ctx.add(rule_id="pickle.zip_bomb", severity=Severity.HIGH, description=f"ZIP member {name} has a suspicious compression ratio.")
                continue
            try:
                data = archive.read(info)
            except CyberjectionException:
                raise
            except Exception as exc:  # noqa: BLE001 -- hostile input: any failure is a finding
                # Corrupt local header, bad CRC, encrypted or unsupported
                # compression: the member's contents can't be verified.
                ctx.add(
                    rule_id="pickle.unparseable",
                    severity=Severity.HIGH,
                    description=f"ZIP member {name} could not be read ({type(exc).__name__}: {exc}); its safety cannot be verified.",
                )
                continue
            member_stream = io.BytesIO(data)
            if lower.endswith(".npy"):
                _scan_npy(ctx, member_stream, name)
            else:
                _scan_concatenated(ctx, member_stream, member=name)
        if is_torch and ctx.result.pickles_scanned == 0:
            ctx.add(rule_id="pickle.unparseable", severity=Severity.HIGH, description="PyTorch archive contained no parseable data.pkl.")


def scan_pickle_stream(
    stream: IO[bytes],
    *,
    label: str = "<stream>",
    max_pickle_bytes: int = DEFAULT_MAX_PICKLE_BYTES,
    max_zip_member_bytes: int = DEFAULT_MAX_ZIP_MEMBER_BYTES,
) -> PickleScanResult:
    """Scans a seekable binary stream, auto-detecting raw pickle,
    PyTorch ZIP, legacy PyTorch, `.npy` and `.npz` by magic bytes."""

    result = PickleScanResult(path=label)
    ctx = _ScanContext(label, result, max_pickle_bytes)
    head = stream.read(8)
    stream.seek(0)

    # pickletools emits DeprecationWarnings while decoding malformed
    # protocol-0 string escapes; for hostile input that's noise, not news.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        _dispatch(ctx, stream, head, max_zip_member_bytes)
    return result


def _dispatch(ctx: _ScanContext, stream: IO[bytes], head: bytes, max_zip_member_bytes: int) -> None:
    result = ctx.result
    try:
        if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
            _scan_zip(ctx, stream, max_zip_member_bytes)
        elif head.startswith(b"\x93NUMPY"):
            result.format = "npy"
            _scan_npy(ctx, stream, "")
        else:
            result.format = "pickle"
            _scan_concatenated(ctx, stream)
            if result.pickles_scanned >= 1 and _looks_like_legacy_torch(stream):
                result.format = "torch-legacy"
    except CyberjectionException:
        raise  # transport errors (unreadable remote file) are reported by the caller
    except Exception as exc:  # noqa: BLE001 -- the input is hostile; never crash on it
        ctx.add(
            rule_id="pickle.scan_failed",
            severity=Severity.HIGH,
            description=f"Scanner could not finish this file ({type(exc).__name__}: {exc}); its safety cannot be verified.",
        )


def _looks_like_legacy_torch(stream: IO[bytes], start: int = 0) -> bool:
    stream.seek(start)
    try:
        for op, arg, _ in pickletools.genops(stream):
            if op.name in {"LONG1", "LONG4"} and arg == _TORCH_LEGACY_MAGIC:
                return True
            if op.name == "STOP":
                return False
    except ValueError:
        return False
    return False


def scan_pickle_bytes(data: bytes, *, label: str = "<bytes>") -> PickleScanResult:
    return scan_pickle_stream(io.BytesIO(data), label=label)


def scan_pickle_file(path: Union[str, Path], **kwargs: Any) -> PickleScanResult:
    with open(path, "rb") as handle:
        return scan_pickle_stream(handle, label=str(kwargs.pop("label", Path(path).name)), **kwargs)


def is_pickle_candidate(path: str) -> bool:
    return Path(path).suffix.lower() in PICKLE_EXTENSIONS
