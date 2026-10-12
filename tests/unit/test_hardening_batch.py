"""Audit-finding fixes: SSRF guard encodings (M1), no exception text in API
500s (M2), optional API bearer-token auth (M5), plugin discovery once per
process (L1), and HMAC-keyed audit log chains (L2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from cyberjection.api.app import build_app
from cyberjection.api.asgi import ASGIApp, Request, Response, Router
from cyberjection.security.audit_log import AuditLogger, verify_chain
from cyberjection.security.input_validation import assert_safe_target_url
from cyberjection.utils.exceptions import UnsafeTargetURLError


async def call(app: ASGIApp, path: str, headers: Dict[str, str] | None = None, method: str = "GET") -> Tuple[int, Dict[str, str], bytes]:
    sent: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    await app({"type": "http", "method": method, "path": path, "query_string": b"", "headers": raw}, receive, send)
    return sent[0]["status"], {k.decode(): v.decode() for k, v in sent[0]["headers"]}, sent[1]["body"]


class TestSSRFGuard:
    @pytest.mark.parametrize(
        "url",
        [
            "http://2852039166/",  # decimal 169.254.169.254
            "http://0xA9FEA9FE/",  # hex
            "http://0251.0376.0251.0376/",  # octal
            "http://169.254.43518/",  # two-part
            "http://127.1/",  # short loopback
            "http://0/",  # 0.0.0.0
            "http://localhost./",
            "http://LOCALHOST/",
            "http://api.localhost/",
            "http://metadata.google.internal./",
            "http://instance-data/",
            "http://[::ffff:10.0.0.1]/",
            "http://[::]/",
            "http://[fe80::1]/",
            "http://10.0.0.1:11434/",
        ],
    )
    def test_blocked(self, url: str) -> None:
        with pytest.raises(UnsafeTargetURLError):
            assert_safe_target_url(url)

    @pytest.mark.parametrize(
        "url",
        ["https://api.openai.com/v1", "https://8.8.8.8/", "https://models.example.com:8443/v1", "http://123abc.example/", "http://1.2.3/"],
    )
    def test_public_allowed(self, url: str) -> None:
        assert assert_safe_target_url(url) == url

    def test_opt_in_still_allows_local(self) -> None:
        assert assert_safe_target_url("http://127.1/", allow_private_networks=True)


class TestApiErrors:
    async def test_500_does_not_leak_exception_text(self, caplog: pytest.LogCaptureFixture) -> None:
        router = Router()

        async def boom(request: Request) -> Response:
            raise RuntimeError("sqlite:///C:/secret/path/results.db: SELECT password FROM users")

        router.add_route("GET", "/api/boom", boom)
        status, _, body = await call(ASGIApp(router), "/api/boom")
        payload = json.loads(body)
        assert status == 500 and payload["error"] == "internal_error"
        assert "secret" not in body.decode() and "SELECT" not in body.decode()
        assert len(payload["incident"]) == 12
        assert payload["incident"] in caplog.text and "SELECT password" in caplog.text  # logged server-side


class TestApiAuth:
    TOKEN = "s3cret-token-value"

    async def test_no_token_configured_keeps_open_access(self) -> None:
        assert (await call(build_app(), "/api/plugins"))[0] == 200

    @pytest.mark.parametrize(
        "headers",
        [{}, {"Authorization": "Bearer wrong"}, {"Authorization": "Basic czNjcmV0"}, {"Authorization": "Bearer "}, {"Authorization": "s3cret-token-value"}],
    )
    async def test_missing_or_wrong_token_is_401(self, headers: Dict[str, str]) -> None:
        status, response_headers, body = await call(build_app(api_token=self.TOKEN), "/api/plugins", headers)
        assert status == 401 and json.loads(body) == {"error": "unauthorized"}
        assert response_headers["www-authenticate"].startswith("Bearer")

    async def test_correct_token_is_accepted(self) -> None:
        status, _, _ = await call(build_app(api_token=self.TOKEN), "/api/plugins", {"Authorization": f"Bearer {self.TOKEN}"})
        assert status == 200

    async def test_scheme_is_case_insensitive(self) -> None:
        status, _, _ = await call(build_app(api_token=self.TOKEN), "/api/plugins", {"Authorization": f"bearer {self.TOKEN}"})
        assert status == 200

    async def test_health_probe_stays_open(self) -> None:
        assert (await call(build_app(api_token=self.TOKEN), "/api/health"))[0] == 200

    async def test_unknown_api_path_is_401_not_404(self) -> None:
        # Unauthenticated callers can't enumerate which API routes exist.
        assert (await call(build_app(api_token=self.TOKEN), "/api/nope"))[0] == 401

    async def test_dashboard_assets_stay_public(self, tmp_path: Path) -> None:
        (tmp_path / "index.html").write_text("<html></html>")
        app = build_app(api_token=self.TOKEN, dashboard_dir=str(tmp_path))
        assert (await call(app, "/campaigns"))[0] == 200  # the page loads, then asks for the token


class TestPluginDiscoveryOnce:
    async def test_discovery_runs_once_per_app(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import cyberjection.api.app as app_module

        runs: List[int] = []
        real = app_module.discover_plugins

        def counting() -> Any:
            runs.append(1)
            return real()

        monkeypatch.setattr(app_module, "discover_plugins", counting)
        app = build_app()
        for _ in range(5):
            assert (await call(app, "/api/plugins"))[0] == 200
        assert len(runs) == 1


class TestKeyedAuditLog:
    KEY = b"audit-key-kept-elsewhere"

    def _write(self, path: Path, key: bytes | None, n: int = 3) -> None:
        logger = AuditLogger(path, key=key)
        for i in range(n):
            logger.log("event", resource=f"r{i}")

    def test_keyed_chain_verifies_only_with_the_key(self, tmp_path: Path) -> None:
        path = tmp_path / "a.jsonl"
        self._write(path, self.KEY)
        assert verify_chain(path, key=self.KEY).valid
        assert not verify_chain(path, key=b"wrong").valid
        unkeyed = verify_chain(path)
        assert not unkeyed.valid and "supply the key" in (unkeyed.reason or "")

    def test_rewritten_chain_without_key_is_detected(self, tmp_path: Path) -> None:
        """An attacker with write access edits an entry and recomputes the
        whole chain -- possible for plain SHA-256, impossible for HMAC."""

        path = tmp_path / "a.jsonl"
        self._write(path, self.KEY)
        records = [json.loads(line) for line in path.read_text().splitlines()]
        records[1]["outcome"] = "success-forged"
        forged = tmp_path / "forged.jsonl"
        forger = AuditLogger(forged)  # no key: plain SHA-256 chain
        for r in records:
            forger.log(r["action"], actor=r["actor"], resource=r["resource"], outcome=r["outcome"], metadata=r["metadata"])
        assert verify_chain(forged).valid  # plain chains *can* be recomputed...
        result = verify_chain(forged, key=self.KEY)  # ...but a keyed verifier rejects the downgrade
        assert not result.valid and "not HMAC-keyed" in (result.reason or "")

    def test_tampered_keyed_entry_is_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "a.jsonl"
        self._write(path, self.KEY)
        lines = path.read_text().splitlines()
        record = json.loads(lines[2])
        record["resource"] = "tampered"
        lines[2] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n")
        result = verify_chain(path, key=self.KEY)
        assert not result.valid and result.first_broken_index == 2

    def test_unkeyed_logs_keep_working(self, tmp_path: Path) -> None:
        path = tmp_path / "a.jsonl"
        self._write(path, None)
        assert verify_chain(path).valid


class TestCliVerifyLogAndServeWarning:
    def test_verify_log(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        typer_testing = pytest.importorskip("typer.testing")
        import cyberjection.cli.main as cli

        path = tmp_path / "audit.jsonl"
        monkeypatch.setattr(cli, "_audit_logger", AuditLogger(path))
        monkeypatch.delenv("CYBERJECTION_AUDIT_KEY", raising=False)
        cli._audit_logger.log("seed")
        runner = typer_testing.CliRunner()
        ok = runner.invoke(cli.app, ["audit", "--verify-log"])
        assert ok.exit_code == cli.EXIT_OK and "intact" in ok.output
        record = json.loads(path.read_text().splitlines()[0])
        record["actor"] = "intruder"
        path.write_text(json.dumps(record) + "\n")
        bad = runner.invoke(cli.app, ["audit", "--verify-log"])
        assert bad.exit_code == cli.EXIT_QUALITY_GATE_FAILED and "FAILED" in bad.output

    @pytest.mark.parametrize("host,token,warned", [("0.0.0.0", None, True), ("0.0.0.0", "t", False), ("127.0.0.1", None, False)])
    def test_serve_warns_when_exposed_without_auth(self, monkeypatch: pytest.MonkeyPatch, host: str, token: Any, warned: bool) -> None:
        import sys
        import types

        typer_testing = pytest.importorskip("typer.testing")
        import cyberjection.cli.main as cli

        captured: Dict[str, Any] = {}
        fake = types.ModuleType("uvicorn")
        fake.run = lambda app, host, port: captured.update(app=app)  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "uvicorn", fake)
        monkeypatch.delenv("CYBERJECTION_API_TOKEN", raising=False)
        args = ["serve", "--host", host] + (["--api-token", token] if token else [])
        result = typer_testing.CliRunner().invoke(cli.app, args)
        assert result.exit_code == cli.EXIT_OK, result.output
        assert ("WARNING" in result.output) is warned
        assert captured["app"].api_token == token
