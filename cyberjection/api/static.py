"""Serves the built web dashboard (`apps/dashboard/dist`) from the same
process and origin as the API.

The dashboard's code fetches relative `/api/...` paths (see
`apps/dashboard/src/api/client.ts`), so in production something has to
serve the static bundle *and* answer `/api/` on one origin. Rather than
requiring a separate web server or reverse-proxy configuration,
`cyberjection serve --dashboard-dir apps/dashboard/dist` does both: API
routes are matched first, everything else falls through to this module.

Behavior:

- Real files under the dashboard directory are served with an explicit
  content type. JavaScript and CSS types are hard-coded rather than taken
  from `mimetypes`, because on Windows `mimetypes` reads the registry and
  commonly reports `.js` as `text/plain`, which browsers refuse to execute
  as a module script.
- Paths without a file extension fall back to `index.html`, because the
  dashboard is a client-side-routed single-page app: a reload of
  `/campaigns/<id>` must return the app, not a 404. A missing path *with*
  an extension (`/assets/missing.js`) is a genuine 404.
- `/api/...` never falls back to the SPA, so a typo'd API call gets a JSON
  404 instead of a 200 HTML page.
- Every resolved path must stay inside the dashboard directory after
  symlinks are resolved; `..` segments, encoded traversal, backslashes,
  NUL bytes and symlink escapes are all refused.
- Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options:
  DENY`, `Referrer-Policy: no-referrer` and a same-origin
  `Content-Security-Policy`. `index.html` is `no-cache`; Vite's
  content-hashed `assets/` files are cached as immutable.
"""

from __future__ import annotations

import mimetypes
from pathlib import Path
from typing import List, Optional, Tuple

from cyberjection.api.asgi import Response

_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json",
    ".map": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".txt": "text/plain; charset=utf-8",
}

SECURITY_HEADERS: List[Tuple[str, str]] = [
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
    (
        "content-security-policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
    ),
]


class DashboardNotBuiltError(ValueError):
    """The dashboard directory doesn't contain a built `index.html`."""


class DashboardStatic:
    def __init__(self, root: "Path | str") -> None:
        self.root = Path(root).resolve()
        self.index = self.root / "index.html"
        if not self.index.is_file():
            raise DashboardNotBuiltError(
                f"{self.root} has no index.html -- build the dashboard first "
                "(cd apps/dashboard && npm install && npm run build)."
            )

    def _safe_path(self, request_path: str) -> Optional[Path]:
        relative = request_path.lstrip("/")
        if "\x00" in relative or "\\" in relative:
            return None
        parts = [p for p in relative.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            return None
        candidate = self.root.joinpath(*parts).resolve() if parts else self.index
        if candidate != self.root and self.root not in candidate.parents:
            return None  # symlink escape
        return candidate

    def response_for(self, method: str, request_path: str) -> Response:
        if method not in ("GET", "HEAD"):
            return self._plain(405, "method not allowed", extra=[("allow", "GET, HEAD")])
        target = self._safe_path(request_path)
        if target is None:
            return self._plain(404, "not found")
        if not target.is_file():
            last_segment = request_path.rstrip("/").rsplit("/", 1)[-1]
            if "." in last_segment:
                return self._plain(404, "not found")
            target = self.index  # client-side route
        body = target.read_bytes()
        content_type = _CONTENT_TYPES.get(target.suffix.lower()) or mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if target == self.index:
            cache = "no-cache"
        elif "assets" in target.relative_to(self.root).parts:
            cache = "public, max-age=31536000, immutable"
        else:
            cache = "public, max-age=3600"
        headers = [("content-type", content_type), ("cache-control", cache), ("content-length", str(len(body)))]
        return Response(status_code=200, body=b"" if method == "HEAD" else body, headers=headers + SECURITY_HEADERS)

    @staticmethod
    def _plain(status: int, text: str, extra: Optional[List[Tuple[str, str]]] = None) -> Response:
        body = text.encode("utf-8")
        headers = [("content-type", "text/plain; charset=utf-8"), ("content-length", str(len(body)))]
        return Response(status_code=status, body=body, headers=headers + (extra or []) + SECURITY_HEADERS)
