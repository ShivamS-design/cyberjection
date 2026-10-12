"""HubGuard (Phase 11): model supply-chain security for Hugging Face-style
model repositories.

Phases 1-10 test what a model *says*. HubGuard vets what a model repository
*is* before it is ever loaded: pickle checkpoints that execute code on
`torch.load`, `trust_remote_code` Python files, malformed or tampered
SafeTensors, leaked credentials in model cards and Git history, and
weight-level backdoors.

- `client`: `HubGuardClient.audit_repository()` -- the full pipeline.
- `picklescan`: static opcode analysis of pickle / PyTorch / NumPy files.
- `remotecode`: AST analysis of remote code and `auto_map` resolution.
- `sandbox`: opt-in behavioral profiling of remote code in a restricted
  child interpreter.
- `safetensors`: SafeTensors-only policy, strict header validation,
  SHA-256 manifests and Git blob verification.
- `secrets`: credential and internal-endpoint leak detection.
- `weightscan`: tensor statistics, embedding-outlier trigger candidates,
  and a differential trigger-activation probe over any Phase 1 target.
- `transport`: read-only Hub (HTTP, range reads) and local-snapshot access.
- `gate`: campaign-level enforcement for `huggingface` targets.
"""

from cyberjection.hubguard.client import HubGuardClient, generate_manifest
from cyberjection.hubguard.models import (
    FindingCategory,
    HubFinding,
    HubGuardReport,
    ScannedFile,
    Severity,
    Verdict,
    compute_risk_score,
)
from cyberjection.hubguard.picklescan import PickleScanResult, scan_pickle_bytes, scan_pickle_file, scan_pickle_stream
from cyberjection.hubguard.remotecode import analyze_python_source
from cyberjection.hubguard.safetensors import EnforcementLevel, HashManifest, validate_safetensors_file
from cyberjection.hubguard.secrets import find_secrets, scan_text_for_leaks
from cyberjection.hubguard.transport import HTTPHubTransport, HubAccessError, LocalDirectoryTransport

__all__ = [
    "EnforcementLevel",
    "FindingCategory",
    "HTTPHubTransport",
    "HashManifest",
    "HubAccessError",
    "HubFinding",
    "HubGuardClient",
    "HubGuardReport",
    "LocalDirectoryTransport",
    "PickleScanResult",
    "ScannedFile",
    "Severity",
    "Verdict",
    "analyze_python_source",
    "compute_risk_score",
    "find_secrets",
    "generate_manifest",
    "scan_pickle_bytes",
    "scan_pickle_file",
    "scan_pickle_stream",
    "scan_text_for_leaks",
    "validate_safetensors_file",
]
