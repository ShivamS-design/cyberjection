"""Shared builders for the Phase 11 HubGuard tests.

Malicious fixtures are built as *raw opcode bytes* (or with
`pickle.dumps`, which only serializes) and are only ever handed to the
static scanner -- nothing in the test suite unpickles them.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import struct
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple

# --- raw pickle builders ------------------------------------------------------

PROTO2 = b"\x80\x02"
PROTO4 = b"\x80\x04"
STOP = b"."
EMPTY_TUPLE = b")"
REDUCE = b"R"
MARK = b"("
TUPLE = b"t"
TUPLE1 = b"\x85"
POP = b"0"


def global_op(module: str, name: str) -> bytes:
    return b"c" + module.encode() + b"\n" + name.encode() + b"\n"


def short_unicode(text: str) -> bytes:
    data = text.encode("utf-8")
    assert len(data) < 256
    return b"\x8c" + bytes([len(data)]) + data


def binput(index: int) -> bytes:
    return b"q" + bytes([index])


def binget(index: int) -> bytes:
    return b"h" + bytes([index])


def binbytes(data: bytes) -> bytes:
    return b"B" + struct.pack("<I", len(data)) + data


def binint1(value: int) -> bytes:
    return b"K" + bytes([value])


def call_global(module: str, name: str, *string_args: str, proto: bytes = PROTO2) -> bytes:
    """`module.name(*string_args)` as a complete pickle."""

    args = MARK + b"".join(short_unicode(a) for a in string_args) + TUPLE if string_args else EMPTY_TUPLE
    return proto + global_op(module, name) + args + REDUCE + STOP


def stack_global_call(module: str, name: str, *string_args: str) -> bytes:
    args = MARK + b"".join(short_unicode(a) for a in string_args) + TUPLE if string_args else EMPTY_TUPLE
    return PROTO4 + short_unicode(module) + short_unicode(name) + b"\x93" + args + REDUCE + STOP


def benign_torch_data_pkl() -> bytes:
    """A minimal state-dict-shaped pickle: OrderedDict with one rebuilt tensor."""

    return (
        PROTO2
        + global_op("collections", "OrderedDict")
        + EMPTY_TUPLE
        + REDUCE
        + binput(0)
        + short_unicode("weight")
        + global_op("torch._utils", "_rebuild_tensor_v2")
        + MARK
        + MARK
        + short_unicode("storage")
        + global_op("torch", "FloatStorage")
        + short_unicode("0")
        + short_unicode("cpu")
        + binint1(4)
        + TUPLE
        + b"Q"  # BINPERSID
        + binint1(0)
        + MARK
        + binint1(4)
        + TUPLE
        + MARK
        + binint1(1)
        + TUPLE
        + b"\x89"  # NEWFALSE
        + global_op("collections", "OrderedDict")
        + EMPTY_TUPLE
        + REDUCE
        + TUPLE
        + REDUCE
        + b"s"  # SETITEM
        + STOP
    )


def torch_zip(data_pkl: bytes, *, prefix: str = "archive", extra: Optional[Dict[str, bytes]] = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(f"{prefix}/data.pkl", data_pkl)
        archive.writestr(f"{prefix}/version", b"3\n")
        archive.writestr(f"{prefix}/data/0", b"\x00" * 16)
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return buffer.getvalue()


def npy_object_array(pickle_payload: bytes) -> bytes:
    header = "{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
    header = header + " " * (63 - (10 + len(header)) % 64) + "\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header.encode("latin-1") + pickle_payload


# --- safetensors builder -----------------------------------------------------


def safetensors_bytes(
    tensors: Dict[str, Tuple[str, List[int], bytes]],
    *,
    metadata: Optional[Dict[str, str]] = None,
    raw_header: Optional[bytes] = None,
    trailing: bytes = b"",
    pad_to: int = 8,
) -> bytes:
    header: Dict[str, object] = {}
    if metadata is not None:
        header["__metadata__"] = metadata
    data = b""
    for name, (dtype, shape, payload) in tensors.items():
        header[name] = {"dtype": dtype, "shape": shape, "data_offsets": [len(data), len(data) + len(payload)]}
        data += payload
    encoded = raw_header if raw_header is not None else json.dumps(header).encode()
    if raw_header is None and pad_to:
        encoded += b" " * (-len(encoded) % pad_to)
    return struct.pack("<Q", len(encoded)) + encoded + data + trailing


def f32(values: List[float]) -> bytes:
    return struct.pack(f"<{len(values)}f", *values)


# --- fake Hub ----------------------------------------------------------------


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


class _QuickServer(ThreadingHTTPServer):
    """Skips `HTTPServer.server_bind`'s reverse-DNS `getfqdn()` lookup,
    which takes seconds on some hosts."""

    daemon_threads = True

    def server_bind(self) -> None:
        import socketserver

        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name, self.server_port = str(host), port


class FakeHub:
    """An in-process HTTP server speaking the subset of the Hub API HubGuard
    uses: model info with `?blobs=true`, commit listing, and file resolve
    with Range support. Files marked `lfs` are served via a redirect to a
    *different host* (127.0.0.1 vs localhost), like the real Hub's CDN, so
    tests can check the bearer token isn't forwarded across hosts."""

    def __init__(self) -> None:
        self.revisions: Dict[str, Dict[str, bytes]] = {}
        self.lfs: set = set()
        self.commits: List[Dict[str, object]] = []
        self.lfs_sha_override: Dict[str, str] = {}
        self.blob_override: Dict[str, str] = {}
        self.extra_info: Dict[str, object] = {}
        self.requests: List[Tuple[str, Dict[str, str]]] = []
        self.ignore_range = False
        hub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # silence
                pass

            def _send(self, status: int, body: bytes, headers: Optional[Dict[str, str]] = None) -> None:
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                hub.requests.append((self.path, {k: v for k, v in self.headers.items()}))
                path = self.path.split("?")[0]
                m = re.match(r"^/api/models/(.+)/revision/([^/]+)$", path)
                if m:
                    return self._info(m.group(1), m.group(2))
                m = re.match(r"^/api/models/(.+)/commits/([^/]+)$", path)
                if m:
                    return self._send(200, json.dumps(hub.commits).encode(), {"Content-Type": "application/json"})
                m = re.match(r"^/cdn/([^/]+)/(.+)$", path)
                if m:
                    return self._file(m.group(1), m.group(2))
                m = re.match(r"^/(.+?)/resolve/([^/]+)/(.+)$", path)
                if m:
                    rev, file_path = m.group(2), m.group(3)
                    if file_path in hub.lfs:
                        location = f"http://{hub.cdn_host}:{hub.cdn_port}/cdn/{rev}/{file_path}"
                        return self._send(302, b"", {"Location": location})
                    return self._file(rev, file_path)
                self._send(404, b"not found")

            def _info(self, repo: str, rev: str) -> None:
                files = hub.revisions.get(rev)
                if files is None:
                    return self._send(404, b"{}")
                siblings = []
                for name, data in files.items():
                    entry: Dict[str, object] = {"rfilename": name, "size": len(data), "blobId": hub.blob_override.get(name, git_blob_sha1(data))}
                    if name in hub.lfs:
                        entry["lfs"] = {"sha256": hub.lfs_sha_override.get(name, hashlib.sha256(data).hexdigest()), "size": len(data)}
                    siblings.append(entry)
                body = {"id": repo, "sha": rev if len(rev) == 40 else "a" * 40, "siblings": siblings, "author": repo.split("/")[0], **hub.extra_info}
                self._send(200, json.dumps(body).encode(), {"Content-Type": "application/json"})

            def _file(self, rev: str, file_path: str) -> None:
                files = hub.revisions.get(rev) or hub.revisions.get("main", {})
                if rev == "a" * 40:
                    files = hub.revisions["main"]
                data = files.get(file_path)
                if data is None:
                    return self._send(404, b"missing")
                rng = self.headers.get("Range")
                if rng and not hub.ignore_range:
                    start_s, end_s = rng.removeprefix("bytes=").split("-")
                    start, end = int(start_s), min(int(end_s), len(data) - 1)
                    return self._send(206, data[start : end + 1], {"Content-Range": f"bytes {start}-{end}/{len(data)}"})
                self._send(200, data)

        self.server = _QuickServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        # The "CDN" is a second server on a different loopback address, so a
        # redirect to it changes the URL host exactly like the real Hub's CDN.
        try:
            self.cdn = _QuickServer(("127.0.0.2", 0), Handler)
            self.cdn_host = "127.0.0.2"
        except OSError:  # hosts without the full 127/8 loopback range
            self.cdn = _QuickServer(("127.0.0.1", 0), Handler)
            self.cdn_host = "localhost"
        self.cdn_port = self.cdn.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.cdn_thread = threading.Thread(target=self.cdn.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "FakeHub":
        self.thread.start()
        self.cdn_thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for server in (self.server, self.cdn):
            server.shutdown()
            server.server_close()
