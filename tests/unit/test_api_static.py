"""Tests for cyberjection.api.static: the built dashboard served from the
same origin as the API (`cyberjection serve --dashboard-dir`)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from cyberjection.api.app import build_app
from cyberjection.api.static import DashboardNotBuiltError, DashboardStatic

INDEX = b"<!doctype html><div id=root></div><script type=module src=/assets/index-abc123.js></script>"


@pytest.fixture
def dist(tmp_path: Path) -> Path:
    root = tmp_path / "dist"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_bytes(INDEX)
    (root / "assets" / "index-abc123.js").write_bytes(b"console.log('app')")
    (root / "assets" / "index-abc123.css").write_bytes(b"body{}")
    (root / "favicon.svg").write_bytes(b"<svg/>")
    (tmp_path / "secret.txt").write_text("outside the dashboard dir")
    return root


async def call(app: Any, method: str, path: str) -> Tuple[int, Dict[str, str], bytes]:
    sent: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    await app({"type": "http", "method": method, "path": path, "query_string": b"", "headers": []}, receive, send)
    headers = {k.decode(): v.decode() for k, v in sent[0]["headers"]}
    return sent[0]["status"], headers, sent[1]["body"]


class TestServing:
    async def test_index_and_assets(self, dist: Path) -> None:
        app = build_app(dashboard_dir=str(dist))
        status, headers, body = await call(app, "GET", "/")
        assert status == 200 and body == INDEX
        assert headers["content-type"].startswith("text/html")
        assert headers["cache-control"] == "no-cache"
        status, headers, body = await call(app, "GET", "/assets/index-abc123.js")
        assert status == 200 and body == b"console.log('app')"
        assert headers["content-type"].startswith("text/javascript")  # never registry-derived text/plain
        assert "immutable" in headers["cache-control"]
        assert (await call(app, "GET", "/assets/index-abc123.css"))[1]["content-type"].startswith("text/css")
        assert (await call(app, "GET", "/favicon.svg"))[1]["content-type"] == "image/svg+xml"

    async def test_security_headers(self, dist: Path) -> None:
        _, headers, _ = await call(build_app(dashboard_dir=str(dist)), "GET", "/")
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in headers["content-security-policy"]

    async def test_client_side_routes_fall_back_to_index(self, dist: Path) -> None:
        app = build_app(dashboard_dir=str(dist))
        for path in ("/campaigns", "/campaigns/abc-123", "/campaigns/abc/tests/xyz", "/plugins/"):
            status, _, body = await call(app, "GET", path)
            assert status == 200 and body == INDEX, path

    async def test_missing_asset_is_404_not_index(self, dist: Path) -> None:
        status, _, body = await call(build_app(dashboard_dir=str(dist)), "GET", "/assets/missing-999.js")
        assert status == 404 and body != INDEX

    async def test_api_routes_still_win_and_unknown_api_is_json_404(self, dist: Path) -> None:
        app = build_app(dashboard_dir=str(dist))
        status, _, body = await call(app, "GET", "/api/health")
        assert status == 200 and json.loads(body) == {"status": "ok"}
        status, headers, body = await call(app, "GET", "/api/nope")
        assert status == 404 and headers["content-type"] == "application/json"
        assert json.loads(body)["error"] == "not_found"

    async def test_head_and_method_not_allowed(self, dist: Path) -> None:
        app = build_app(dashboard_dir=str(dist))
        status, headers, body = await call(app, "HEAD", "/")
        assert status == 200 and body == b"" and headers["content-length"] == str(len(INDEX))
        status, headers, _ = await call(app, "POST", "/")
        assert status == 405 and headers["allow"] == "GET, HEAD"

    @pytest.mark.parametrize(
        "path",
        [
            "/../secret.txt",
            "/assets/../../secret.txt",
            "/..%2fsecret.txt",
            "/assets\\..\\..\\secret.txt",
            "/index.html\x00.js",
            "/C:/Windows/win.ini",
            "//etc/passwd",
        ],
    )
    async def test_traversal_is_refused(self, dist: Path, path: str) -> None:
        status, _, body = await call(build_app(dashboard_dir=str(dist)), "GET", path)
        assert b"outside the dashboard dir" not in body
        assert status in (200, 404)  # 200 only ever means index.html (SPA fallback)
        if status == 200:
            assert body == INDEX

    async def test_symlink_escape_is_refused(self, dist: Path) -> None:
        link = dist / "leak.txt"
        try:
            link.symlink_to(dist.parent / "secret.txt")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not permitted on this host")
        status, _, body = await call(build_app(dashboard_dir=str(dist)), "GET", "/leak.txt")
        assert status == 404 and b"outside" not in body

    async def test_without_dashboard_dir_non_api_is_json_404(self) -> None:
        status, headers, _ = await call(build_app(), "GET", "/campaigns")
        assert status == 404 and headers["content-type"] == "application/json"


def test_unbuilt_dashboard_rejected(tmp_path: Path) -> None:
    with pytest.raises(DashboardNotBuiltError):
        DashboardStatic(tmp_path)
    with pytest.raises(DashboardNotBuiltError):
        build_app(dashboard_dir=str(tmp_path))
