"""Phase 11 integration surface: campaign schema, the LiteLLM model-name
fix for `huggingface` targets, the `hubguard` CLI group, and the
supply-chain gate inside `cyberjection run`."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict

import pytest

typer = pytest.importorskip("typer")
from typer.testing import CliRunner  # noqa: E402

from cyberjection.cli.main import EXIT_OK, EXIT_SUPPLY_CHAIN_BLOCKED, EXIT_USAGE_ERROR, app  # noqa: E402
from cyberjection.config.loader import load_config, load_config_from_string  # noqa: E402
from cyberjection.config.schema import ProviderType, TargetConfig  # noqa: E402
from cyberjection.providers.litellm_provider import _litellm_model_name  # noqa: E402
from cyberjection.utils.exceptions import ConfigValidationError  # noqa: E402
from tests.unit.hubguard_helpers import call_global, f32, safetensors_bytes, torch_zip  # noqa: E402

runner = CliRunner()
ROOT = Path(__file__).resolve().parents[2]

CLEAN: Dict[str, bytes] = {
    "model.safetensors": safetensors_bytes({"w": ("F32", [2], f32([1.0, 2.0]))}),
    "config.json": b'{"model_type": "llama"}',
}
EVIL: Dict[str, bytes] = {"pytorch_model.bin": torch_zip(call_global("os", "system", "id")), "config.json": b"{}"}


def _repo(root: Path, files: Dict[str, bytes]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (root / name).write_bytes(data)
    return root


def _plain(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)


class TestSchema:
    YAML = """
version: "2.0"
name: "enterprise-secure-deployment"
hubguard:
  enforce_safetensors: true
  block_remote_code: true
  max_allowed_risk_score: 2.0
  allowed_organizations: ["openai", "anthropic", "meta-llama"]
targets:
  - id: "production-candidate"
    provider: "huggingface"
    model: "huggingface/meta-llama/Llama-3-8B-Instruct"
    trust_remote_code: {trust}
"""

    def test_example_campaign_file_loads(self) -> None:
        config = load_config(ROOT / "examples" / "hubguard_campaign.yaml")
        assert config.hubguard is not None and config.hubguard.max_allowed_risk_score == 2.0
        assert config.targets[0].provider == ProviderType.HUGGINGFACE

    def test_spec_yaml_loads(self) -> None:
        config = load_config_from_string(self.YAML.format(trust="false"))
        assert config.hubguard.allowed_organizations == ["openai", "anthropic", "meta-llama"]
        assert config.targets[0].trust_remote_code is False

    def test_trust_remote_code_rejected_when_blocked(self) -> None:
        with pytest.raises(ConfigValidationError, match="trust_remote_code"):
            load_config_from_string(self.YAML.format(trust="true"))

    def test_disallowed_org_rejected_at_load(self) -> None:
        with pytest.raises(ConfigValidationError, match="not in hubguard.allowed_organizations"):
            load_config_from_string(self.YAML.format(trust="false").replace("meta-llama/Llama", "sketchy-org/Llama"))

    def test_invalid_repo_id_rejected(self) -> None:
        with pytest.raises(ConfigValidationError, match="Invalid Hugging Face repo id"):
            load_config_from_string(self.YAML.format(trust="false").replace("meta-llama/Llama-3-8B-Instruct", "../../etc/passwd"))

    def test_no_hubguard_section_is_backward_compatible(self) -> None:
        config = load_config_from_string('name: x\ntargets: [{id: t, provider: huggingface, model: "a/b", trust_remote_code: true}]\n')
        assert config.hubguard is None

    def test_risk_bounds(self) -> None:
        with pytest.raises(ConfigValidationError):
            load_config_from_string(self.YAML.format(trust="false").replace("max_allowed_risk_score: 2.0", "max_allowed_risk_score: 11.0"))


class TestModelName:
    def test_prefix_not_doubled(self) -> None:
        target = TargetConfig(id="t", provider=ProviderType.HUGGINGFACE, model="huggingface/meta-llama/Llama-3-8B-Instruct")
        assert _litellm_model_name(target) == "huggingface/meta-llama/Llama-3-8B-Instruct"

    def test_prefix_added(self) -> None:
        assert _litellm_model_name(TargetConfig(id="t", provider=ProviderType.OPENAI, model="gpt-4o")) == "openai/gpt-4o"


class TestHubguardCLI:
    def test_scan_clean_local(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path / "clean", CLEAN)
        result = runner.invoke(app, ["hubguard", "scan", "org/clean", "--local-dir", str(repo), "--json-out", "r.json", "--sarif-out", "r.sarif", "--markdown-out", "r.md"])
        assert result.exit_code == EXIT_OK, result.output
        assert "PASS" in _plain(result.output)
        report = json.loads((tmp_path / "r.json").read_text())
        assert report["verdict"] == "PASS" and report["repo_id"] == "org/clean"
        assert json.loads((tmp_path / "r.sarif").read_text())["version"] == "2.1.0"
        assert (tmp_path / "r.md").exists()

    def test_scan_malicious_local_blocks(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path / "evil", EVIL)
        result = runner.invoke(app, ["hubguard", "scan", "org/evil", "--local-dir", str(repo)])
        assert result.exit_code == EXIT_SUPPLY_CHAIN_BLOCKED
        out = _plain(result.output)
        assert "BLOCK" in out and "CRITICAL" in out

    def test_scan_bad_policy_is_usage_error(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["hubguard", "scan", "org/x", "--policy", "lenient", "--local-dir", str(tmp_path)])
        assert result.exit_code == EXIT_USAGE_ERROR

    def test_scan_bad_repo_id_is_usage_error(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["hubguard", "scan", "../x", "--local-dir", str(tmp_path)])
        assert result.exit_code == EXIT_USAGE_ERROR

    def test_scan_rejects_escaping_report_path(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path / "clean", CLEAN)
        result = runner.invoke(app, ["hubguard", "scan", "org/c", "--local-dir", str(repo), "--json-out", "../../escape.json"])
        assert result.exit_code == EXIT_USAGE_ERROR

    def test_file_command(self, tmp_path: Path) -> None:
        evil = tmp_path / "pytorch_model.bin"
        evil.write_bytes(EVIL["pytorch_model.bin"])
        good = tmp_path / "model.safetensors"
        good.write_bytes(CLEAN["model.safetensors"])
        code = tmp_path / "modeling_x.py"
        code.write_text("import os\nos.system('id')\n")
        assert runner.invoke(app, ["hubguard", "file", str(good)]).exit_code == EXIT_OK
        assert runner.invoke(app, ["hubguard", "file", str(evil)]).exit_code == EXIT_SUPPLY_CHAIN_BLOCKED
        assert runner.invoke(app, ["hubguard", "file", str(code)]).exit_code == EXIT_SUPPLY_CHAIN_BLOCKED
        assert runner.invoke(app, ["hubguard", "file", str(tmp_path / "nope.bin")]).exit_code == EXIT_USAGE_ERROR

    def test_manifest_then_verify(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path / "clean", CLEAN)
        result = runner.invoke(app, ["hubguard", "manifest", "org/clean", "--local-dir", str(repo), "--out", "pins.yaml"])
        assert result.exit_code == EXIT_OK, result.output
        assert runner.invoke(app, ["hubguard", "scan", "org/clean", "--local-dir", str(repo), "--manifest", "pins.yaml"]).exit_code == EXIT_OK
        (repo / "model.safetensors").write_bytes(safetensors_bytes({"w": ("F32", [2], f32([6.0, 6.0]))}))
        tampered = runner.invoke(app, ["hubguard", "scan", "org/clean", "--local-dir", str(repo), "--manifest", "pins.yaml", "--json-out", "t.json"])
        assert tampered.exit_code == EXIT_SUPPLY_CHAIN_BLOCKED
        rules = {f["rule_id"] for f in json.loads((tmp_path / "t.json").read_text())["findings"]}
        assert "integrity.hash_mismatch" in rules


def _campaign_file(tmp_path: Path, model: str, hubguard: bool = True) -> Path:
    section = "hubguard:\n  allowed_organizations: [good-org]\n" if hubguard else ""
    path = tmp_path / "campaign.yaml"
    path.write_text(
        f"version: '2.0'\nname: gate-test\n{section}targets:\n  - id: cand\n    provider: huggingface\n    model: '{model}'\n",
        encoding="utf-8",
    )
    return path


class TestRunGate:
    """`cyberjection run` audits the target's repository before any prompt is sent."""

    @pytest.fixture
    def local_hub(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):  # type: ignore[no-untyped-def]
        repos: Dict[str, Path] = {}
        from cyberjection.hubguard import gate as gate_module
        from cyberjection.hubguard.client import HubGuardClient

        def factory(repo_id, policy, **kwargs):  # type: ignore[no-untyped-def]
            return HubGuardClient.from_policy(repo_id, policy, local_dir=repos[repo_id], **{k: v for k, v in kwargs.items() if k != "local_dir"})

        original = gate_module.gate_campaign

        async def patched(config, **kwargs):  # type: ignore[no-untyped-def]
            return await original(config, client_factory=factory, **kwargs)

        monkeypatch.setattr(gate_module, "gate_campaign", patched)
        return repos

    def test_blocked_model_never_runs(self, tmp_path: Path, local_hub: Dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
        local_hub["good-org/evil"] = _repo(tmp_path / "evil", EVIL)
        executed = []
        import cyberjection.cli.main as cli

        async def fake_pipeline(*args, **kwargs):  # type: ignore[no-untyped-def]
            executed.append(True)
            return []

        monkeypatch.setattr(cli, "_execute_pipeline", fake_pipeline)
        result = runner.invoke(app, ["run", "-c", str(_campaign_file(tmp_path, "huggingface/good-org/evil")), "-t", "cand"])
        assert result.exit_code == EXIT_SUPPLY_CHAIN_BLOCKED, result.output
        assert executed == []
        assert "SUPPLY-CHAIN GATE BLOCKED" in _plain(result.output)

    def test_clean_model_proceeds(self, tmp_path: Path, local_hub: Dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> None:
        local_hub["good-org/clean"] = _repo(tmp_path / "clean", CLEAN)
        import cyberjection.cli.main as cli

        async def fake_pipeline(*args, **kwargs):  # type: ignore[no-untyped-def]
            return []

        monkeypatch.setattr(cli, "_execute_pipeline", fake_pipeline)
        result = runner.invoke(app, ["run", "-c", str(_campaign_file(tmp_path, "huggingface/good-org/clean")), "-t", "cand"])
        assert result.exit_code == EXIT_OK, result.output

    def test_gate_command(self, tmp_path: Path, local_hub: Dict[str, Path]) -> None:
        local_hub["good-org/evil"] = _repo(tmp_path / "evil", EVIL)
        result = runner.invoke(app, ["hubguard", "gate", "-c", str(_campaign_file(tmp_path, "good-org/evil"))])
        assert result.exit_code == EXIT_SUPPLY_CHAIN_BLOCKED
        assert "GATE BLOCKED" in _plain(result.output)

    def test_gate_command_requires_section(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["hubguard", "gate", "-c", str(_campaign_file(tmp_path, "a/b", hubguard=False))])
        assert result.exit_code == EXIT_USAGE_ERROR


class TestUntrustedOutput:
    """Repository content is attacker-controlled and is echoed into finding
    descriptions; it must never be interpreted as Rich markup (a stray
    closing tag used to crash the CLI with MarkupError)."""

    @pytest.mark.parametrize("payload", ["[/bold]", "[/]", "[link=http://x]y[/link]", "[green]PASS[/green]"])
    def test_markup_in_repo_content_cannot_crash_or_restyle_output(self, tmp_path: Path, payload: str) -> None:
        source = f'URL = "http://203.0.113.5/{payload}x"\n'
        repo = _repo(tmp_path / "r", {"config.json": b"{}", "modeling_x.py": source.encode()})
        result = runner.invoke(app, ["hubguard", "scan", "org/x", "--local-dir", str(repo), "--policy", "off", "--json-out", "o.json"])
        assert not (result.exception and not isinstance(result.exception, SystemExit)), repr(result.exception)
        assert result.exit_code == EXIT_OK, result.output
        descriptions = [f["description"] for f in json.loads((tmp_path / "o.json").read_text())["findings"]]
        assert any(payload in d for d in descriptions)
        # Escaped markup is printed literally: the bracketed text survives.
        assert "[" in _plain(result.output) and "PASS" not in _plain(result.output).split("Safety Verdict:")[1][:12]
