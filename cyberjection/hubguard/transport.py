"""Read-only access to model repositories: the Hugging Face Hub over HTTP,
or a local snapshot directory.

HubGuard never needs to *load* a repository, only to read bytes from it,
so a transport exposes four primitives: repository metadata, a bounded
whole-file read (small text/code files), a ranged read (SafeTensors
headers, ZIP central directories, pickle streams), and a streaming
SHA-256. `RangeFile` turns the ranged read into a seekable file object,
which is what lets `zipfile` and `pickletools` read just the `data.pkl`
member of a multi-gigabyte PyTorch checkpoint without downloading the
tensors.

The HTTP transport is stdlib-only (`urllib`) -- no new hard dependency --
and the scanners are synchronous, so `HubGuardClient` runs them in worker
threads. Two details matter for safety:

- The bearer token is attached with `add_unredirected_header` and only
  re-attached on a redirect that stays on the configured endpoint's own
  host. Hub file downloads redirect to a CDN; forwarding the token there
  would leak it.
- Every request after metadata resolution is pinned to the resolved
  commit SHA, not the branch name, so the repository can't change
  between the moment a file is listed and the moment it's read.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol

from cyberjection.utils.exceptions import CyberjectionException

DEFAULT_ENDPOINT = "https://huggingface.co"
_REPO_ID_RE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9_.\-]{0,95}/)?[A-Za-z0-9][A-Za-z0-9_.\-]{0,95}$")
_USER_AGENT = "cyberjection-hubguard/0.11"


class HubAccessError(CyberjectionException):
    """The repository or file could not be read (not found, gated,
    unauthorized, network failure)."""


class FileTooLargeError(CyberjectionException):
    """A bounded read exceeded its byte ceiling."""


def validate_repo_id(repo_id: str) -> str:
    if not _REPO_ID_RE.match(repo_id) or ".." in repo_id or "--" in repo_id or repo_id.endswith((".", "-")):
        raise ValueError(f"Invalid Hugging Face repo id: {repo_id!r}")
    return repo_id


def repo_id_from_model(model: str) -> str:
    """`huggingface/meta-llama/Llama-3-8B-Instruct` -> `meta-llama/Llama-3-8B-Instruct`."""

    for prefix in ("huggingface/", "hf/", "hf://"):
        if model.startswith(prefix):
            model = model[len(prefix):]
            break
    return validate_repo_id(model)


@dataclass(frozen=True)
class RepoFile:
    path: str
    size: Optional[int] = None
    blob_id: Optional[str] = None  # git blob SHA-1
    lfs_sha256: Optional[str] = None


@dataclass
class CommitInfo:
    commit_id: str
    title: str = ""
    message: str = ""
    date: Optional[str] = None
    authors: List[str] = field(default_factory=list)


@dataclass
class RepoInfo:
    repo_id: str
    commit_sha: Optional[str]
    files: List[RepoFile]
    author: Optional[str] = None
    gated: Any = False
    private: bool = False
    disabled: bool = False
    tags: List[str] = field(default_factory=list)
    card_data: Dict[str, Any] = field(default_factory=dict)
    downloads: Optional[int] = None
    likes: Optional[int] = None
    created_at: Optional[str] = None
    last_modified: Optional[str] = None

    def file(self, path: str) -> Optional[RepoFile]:
        return next((f for f in self.files if f.path == path), None)


class HubTransport(Protocol):
    def repo_info(self, repo_id: str, revision: str) -> RepoInfo: ...

    def read_bytes(self, repo_id: str, path: str, revision: str, *, max_bytes: int) -> bytes: ...

    def read_range(self, repo_id: str, path: str, revision: str, start: int, end: int) -> bytes:
        """Inclusive byte range [start, end]."""
        ...

    def sha256(self, repo_id: str, path: str, revision: str) -> str: ...

    def list_commits(self, repo_id: str, revision: str, *, limit: int) -> List[CommitInfo]: ...


class RangeFile(io.RawIOBase):
    """A seekable read-only file backed by a ranged-read callable."""

    def __init__(self, fetch: Callable[[int, int], bytes], size: int) -> None:
        super().__init__()
        self._fetch = fetch
        self._size = size
        self._pos = 0
        self.bytes_fetched = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self._size + offset
        else:
            raise ValueError(f"invalid whence {whence}")
        self._pos = max(0, self._pos)
        return self._pos

    def readinto(self, buffer: Any) -> int:
        if self._pos >= self._size:
            return 0
        want = min(len(buffer), self._size - self._pos)
        data = self._fetch(self._pos, self._pos + want - 1)
        n = len(data)
        buffer[:n] = data
        self._pos += n
        self.bytes_fetched += n
        return n


def open_range_file(transport: HubTransport, repo_id: str, path: str, revision: str, size: int, *, buffer_size: int = 1 << 20) -> io.BufferedReader:
    raw = RangeFile(lambda start, end: transport.read_range(repo_id, path, revision, start, end), size)
    return io.BufferedReader(raw, buffer_size=buffer_size)


# --- HTTP ----------------------------------------------------------------------


class _ScopedAuthRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-attaches Authorization only on same-host redirects."""

    def __init__(self, auth_host: str, token: Optional[str]) -> None:
        super().__init__()
        self._auth_host = auth_host
        self._token = token

    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Optional[urllib.request.Request]:
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        if self._token and urllib.parse.urlsplit(newurl).netloc == self._auth_host:
            new.add_unredirected_header("Authorization", f"Bearer {self._token}")
        for key in ("Range",):
            value = req.get_header(key)
            if value:
                new.add_header(key, value)
        return new


class HTTPHubTransport:
    """Hugging Face Hub REST transport (stdlib `urllib`)."""

    def __init__(self, *, endpoint: Optional[str] = None, token: Optional[str] = None, timeout: float = 30.0) -> None:
        self.endpoint = (endpoint or os.environ.get("HF_ENDPOINT") or DEFAULT_ENDPOINT).rstrip("/")
        parts = urllib.parse.urlsplit(self.endpoint)
        local = parts.hostname in {"localhost", "127.0.0.1", "::1"}
        if parts.scheme != "https" and not (parts.scheme == "http" and local):
            raise ValueError(f"Hub endpoint must use https (got {self.endpoint!r})")
        self._host = parts.netloc
        self._token = token if token is not None else (os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN"))
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_ScopedAuthRedirectHandler(self._host, self._token))
        # file URL -> final (post-redirect) URL, so repeated range reads of
        # one file skip the redirect hop. Hub CDN URLs are pre-signed.
        self._resolved: Dict[str, str] = {}

    # -- plumbing ------------------------------------------------------------

    def _request(self, url: str, *, headers: Optional[Dict[str, str]] = None) -> Any:
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, **(headers or {})})
        if self._token and urllib.parse.urlsplit(url).netloc == self._host:
            request.add_unredirected_header("Authorization", f"Bearer {self._token}")
        try:
            return self._opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if status == 404:
                raise HubAccessError(f"Not found: {self._redact(url)}") from None
            if status in (401, 403):
                raise HubAccessError(
                    f"Access denied ({status}) for {self._redact(url)} -- the repository may be gated or private; set HF_TOKEN."
                ) from None
            if status == 416:
                raise HubAccessError(f"Range not satisfiable for {self._redact(url)}") from None
            raise HubAccessError(f"HTTP {status} from {self._redact(url)}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise HubAccessError(f"Network error for {self._redact(url)}: {exc}") from None

    @staticmethod
    def _redact(url: str) -> str:
        return url.split("?", 1)[0]

    def _json(self, url: str) -> Any:
        with self._request(url) as response:
            raw = response.read(64 << 20)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HubAccessError(f"Malformed JSON from {self._redact(url)}: {exc}") from None

    @staticmethod
    def _q(value: str) -> str:
        return urllib.parse.quote(value, safe="")

    def _file_url(self, repo_id: str, path: str, revision: str) -> str:
        quoted_path = "/".join(urllib.parse.quote(part, safe="") for part in path.split("/"))
        return f"{self.endpoint}/{validate_repo_id(repo_id)}/resolve/{self._q(revision)}/{quoted_path}"

    # -- transport API --------------------------------------------------------

    def repo_info(self, repo_id: str, revision: str) -> RepoInfo:
        url = f"{self.endpoint}/api/models/{validate_repo_id(repo_id)}/revision/{self._q(revision)}?blobs=true"
        data = self._json(url)
        if not isinstance(data, dict):
            raise HubAccessError("Unexpected repository metadata shape")
        files: List[RepoFile] = []
        for sibling in data.get("siblings") or []:
            if not isinstance(sibling, dict) or not isinstance(sibling.get("rfilename"), str):
                continue
            raw_lfs = sibling.get("lfs")
            lfs: Dict[str, Any] = raw_lfs if isinstance(raw_lfs, dict) else {}
            files.append(
                RepoFile(
                    path=sibling["rfilename"],
                    size=sibling.get("size") if isinstance(sibling.get("size"), int) else lfs.get("size"),
                    blob_id=sibling.get("blobId"),
                    lfs_sha256=lfs.get("sha256"),
                )
            )
        raw_card = data.get("cardData")
        card_data: Dict[str, Any] = raw_card if isinstance(raw_card, dict) else {}
        return RepoInfo(
            repo_id=repo_id,
            commit_sha=data.get("sha"),
            files=files,
            author=data.get("author"),
            gated=data.get("gated", False),
            private=bool(data.get("private", False)),
            disabled=bool(data.get("disabled", False)),
            tags=[t for t in data.get("tags") or [] if isinstance(t, str)],
            card_data=card_data,
            downloads=data.get("downloads"),
            likes=data.get("likes"),
            created_at=data.get("createdAt"),
            last_modified=data.get("lastModified"),
        )

    def read_bytes(self, repo_id: str, path: str, revision: str, *, max_bytes: int) -> bytes:
        with self._request(self._file_url(repo_id, path, revision)) as response:
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FileTooLargeError(f"{path} is {declared} bytes (limit {max_bytes})")
            data: bytes = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise FileTooLargeError(f"{path} exceeds {max_bytes} bytes")
        return data

    def read_range(self, repo_id: str, path: str, revision: str, start: int, end: int) -> bytes:
        if end < start:
            return b""
        file_url = self._file_url(repo_id, path, revision)
        target = self._resolved.get(file_url, file_url)
        try:
            response = self._request(target, headers={"Range": f"bytes={start}-{end}"})
        except HubAccessError:
            if target == file_url:
                raise
            self._resolved.pop(file_url, None)  # signed URL expired: re-resolve
            response = self._request(file_url, headers={"Range": f"bytes={start}-{end}"})
        with response:
            final_url = response.geturl()
            if final_url and final_url != file_url:
                self._resolved[file_url] = final_url
            want = end - start + 1
            if response.status == 206:
                partial: bytes = response.read(want)
                return partial
            # Server ignored the Range header: skip forward without
            # buffering the skipped bytes.
            remaining = start
            while remaining > 0:
                chunk = response.read(min(remaining, 1 << 20))
                if not chunk:
                    return b""
                remaining -= len(chunk)
            tail: bytes = response.read(want)
            return tail

    def sha256(self, repo_id: str, path: str, revision: str) -> str:
        digest = hashlib.sha256()
        with self._request(self._file_url(repo_id, path, revision)) as response:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def list_commits(self, repo_id: str, revision: str, *, limit: int) -> List[CommitInfo]:
        url = f"{self.endpoint}/api/models/{validate_repo_id(repo_id)}/commits/{self._q(revision)}"
        data = self._json(url)
        commits: List[CommitInfo] = []
        for item in data if isinstance(data, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            authors = [a.get("user", "") for a in item.get("authors") or [] if isinstance(a, dict)]
            commits.append(
                CommitInfo(
                    commit_id=item["id"],
                    title=str(item.get("title") or ""),
                    message=str(item.get("message") or ""),
                    date=item.get("date"),
                    authors=authors,
                )
            )
            if len(commits) >= limit:
                break
        return commits


# --- local snapshot -------------------------------------------------------------


class LocalDirectoryTransport:
    """Treats a directory (e.g. a downloaded snapshot) as a repository.

    `repo_id` and `revision` arguments are accepted for interface
    compatibility and ignored. Symlinks that resolve outside the root are
    refused, so a snapshot can't make the scanner read arbitrary files.
    There is no commit history.
    """

    def __init__(self, root: "Path | str") -> None:
        self.root = Path(root).resolve()
        if not self.root.is_dir():
            raise HubAccessError(f"Not a directory: {self.root}")

    def _resolve(self, path: str) -> Path:
        candidate = (self.root / path).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise HubAccessError(f"Path escapes snapshot root: {path}")
        return candidate

    def repo_info(self, repo_id: str, revision: str) -> RepoInfo:
        files: List[RepoFile] = []
        for item in sorted(self.root.rglob("*")):
            if ".git" in item.relative_to(self.root).parts or not item.is_file():
                continue
            try:
                self._resolve(str(item.relative_to(self.root)))
            except HubAccessError:
                continue
            files.append(RepoFile(path=item.relative_to(self.root).as_posix(), size=item.stat().st_size))
        return RepoInfo(repo_id=repo_id, commit_sha=None, files=files)

    def read_bytes(self, repo_id: str, path: str, revision: str, *, max_bytes: int) -> bytes:
        target = self._resolve(path)
        if target.stat().st_size > max_bytes:
            raise FileTooLargeError(f"{path} exceeds {max_bytes} bytes")
        return target.read_bytes()

    def read_range(self, repo_id: str, path: str, revision: str, start: int, end: int) -> bytes:
        with self._resolve(path).open("rb") as handle:
            handle.seek(start)
            return handle.read(max(0, end - start + 1))

    def sha256(self, repo_id: str, path: str, revision: str) -> str:
        from cyberjection.hubguard.safetensors import sha256_file

        return sha256_file(self._resolve(path))

    def list_commits(self, repo_id: str, revision: str, *, limit: int) -> List[CommitInfo]:
        return []
