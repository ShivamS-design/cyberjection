"""`HubGuardClient`: one async call that vets a model repository before a
single weight is loaded or a prompt is sent.

```python
scanner = HubGuardClient(
    repo_id="suspicious-org/custom-llama-3-weights",
    safetensors_policy=EnforcementLevel.STRICT,
    scan_remote_code=True,
    scan_pickles=True,
)
report = await scanner.audit_repository()
```

Pipeline (each stage optional, all feeding one `HubGuardReport`):

1. **Resolve** the revision to a commit SHA and pin every later read to it.
2. **Provenance / policy**: organization allowlist, disabled or empty repos.
3. **Format policy**: SafeTensors-only enforcement over the file listing.
4. **SafeTensors headers**: strict validation via two ranged reads per file.
5. **Pickles**: opcode scan of every pickle-capable file; for PyTorch ZIP
   checkpoints only the `data.pkl` member is fetched, not the tensors.
6. **Remote code**: AST analysis of every `.py` file, `auto_map`
   resolution (including cross-repository references), and -- opt-in --
   sandboxed behavioral profiling.
7. **Secrets**: every text file at HEAD, commit messages, and earlier
   revisions of text files within `history_depth` commits.
8. **Integrity**: Git blob SHA-1 of every fetched file checked against the
   Hub's `blobId`; Hub SHA-256 claims checked against a `HashManifest`;
   optionally the real bytes streamed through SHA-256 (`verify_downloads`).
9. **Weights** (opt-in): tensor statistics, embedding-outlier trigger
   candidates, and a behavioral trigger probe against a live target.

The scan **fails closed**: any file that can't be read or parsed becomes a
HIGH `scan_error` finding, the report is marked `incomplete`, and an
incomplete report can never `PASS`.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Set, Union

from cyberjection.hubguard.models import FindingCategory, HubFinding, HubGuardReport, ScannedFile, Severity
from cyberjection.hubguard.picklescan import scan_pickle_stream
from cyberjection.hubguard.remotecode import analyze_auto_map, analyze_python_source, parse_auto_map
from cyberjection.hubguard.safetensors import (
    EnforcementLevel,
    HashManifest,
    WeightFormat,
    classify_weight_file,
    compare_against_manifest,
    enforce_format_policy,
    git_blob_sha1,
    read_safetensors_header,
)
from cyberjection.hubguard.secrets import is_text_candidate, scan_text_for_leaks
from cyberjection.hubguard.transport import (
    FileTooLargeError,
    HTTPHubTransport,
    HubAccessError,
    HubTransport,
    LocalDirectoryTransport,
    RepoFile,
    RepoInfo,
    open_range_file,
    validate_repo_id,
)

_AUTO_MAP_FILES = ("config.json", "tokenizer_config.json", "preprocessor_config.json", "processor_config.json")
_MAX_HISTORY_BYTES = 32 << 20


class HubGuardClient:
    """Supply-chain auditor for one model repository."""

    def __init__(
        self,
        repo_id: str,
        *,
        revision: str = "main",
        safetensors_policy: EnforcementLevel = EnforcementLevel.STRICT,
        scan_pickles: bool = True,
        scan_remote_code: bool = True,
        scan_secrets: bool = True,
        scan_history: bool = True,
        history_depth: int = 10,
        block_remote_code: bool = False,
        allowed_organizations: Optional[Iterable[str]] = None,
        max_allowed_risk_score: float = 7.0,
        manifest: Union[HashManifest, str, Path, None] = None,
        verify_downloads: bool = False,
        profile_remote_code: bool = False,
        sandbox_timeout_seconds: float = 30.0,
        scan_weights: bool = False,
        probe_target: Any = None,
        transport: Optional[HubTransport] = None,
        local_dir: Union[str, Path, None] = None,
        token: Optional[str] = None,
        endpoint: Optional[str] = None,
        max_text_bytes: int = 2 << 20,
        max_concurrency: int = 4,
        audit_logger: Any = None,
    ) -> None:
        self.repo_id = validate_repo_id(repo_id)
        self.revision = revision
        self.safetensors_policy = EnforcementLevel(safetensors_policy)
        self.scan_pickles = scan_pickles
        self.scan_remote_code = scan_remote_code
        self.scan_secrets = scan_secrets
        self.scan_history = scan_history
        self.history_depth = max(0, history_depth)
        self.block_remote_code = block_remote_code
        self.allowed_organizations = {o.lower() for o in allowed_organizations} if allowed_organizations else set()
        self.max_allowed_risk_score = max_allowed_risk_score
        self.manifest = HashManifest.load(manifest) if isinstance(manifest, (str, Path)) else manifest
        self.verify_downloads = verify_downloads
        self.profile_remote_code = profile_remote_code
        self.sandbox_timeout_seconds = sandbox_timeout_seconds
        self.scan_weights = scan_weights
        self.probe_target = probe_target
        if transport is not None:
            self.transport: HubTransport = transport
        elif local_dir is not None:
            self.transport = LocalDirectoryTransport(local_dir)
        else:
            self.transport = HTTPHubTransport(endpoint=endpoint, token=token)
        self.max_text_bytes = max_text_bytes
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self.audit_logger = audit_logger
        self.trigger_candidates: List[str] = []

    @classmethod
    def from_policy(cls, repo_id: str, policy: Any, **overrides: Any) -> "HubGuardClient":
        """Builds a client from a campaign's `HubGuardConfig` section."""

        kwargs: Dict[str, Any] = dict(
            safetensors_policy=EnforcementLevel.STRICT if policy.enforce_safetensors else EnforcementLevel.WARN,
            block_remote_code=policy.block_remote_code,
            max_allowed_risk_score=policy.max_allowed_risk_score,
            allowed_organizations=policy.allowed_organizations or None,
            scan_pickles=policy.scan_pickles,
            scan_remote_code=policy.scan_remote_code,
            scan_secrets=policy.scan_secrets,
            history_depth=policy.history_depth,
            manifest=policy.manifest,
            verify_downloads=policy.verify_downloads,
            profile_remote_code=policy.profile_remote_code,
        )
        kwargs.update(overrides)
        return cls(repo_id, **kwargs)

    # -- helpers ----------------------------------------------------------------

    async def _run(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        async with self._semaphore:
            return await asyncio.to_thread(fn, *args, **kwargs)

    @staticmethod
    def _scan_error(path: Optional[str], stage: str, exc: BaseException) -> HubFinding:
        return HubFinding(
            rule_id=f"scan_error.{stage}",
            category=FindingCategory.SCAN_ERROR,
            severity=Severity.HIGH,
            description=f"{stage.replace('_', ' ').capitalize()} could not be completed: {type(exc).__name__}: {exc}",
            file=path,
            remediation="The file could not be verified; treat it as unsafe until it can be scanned.",
        )

    async def _guarded(self, path: Optional[str], stage: str, coro: Awaitable[List[HubFinding]]) -> List[HubFinding]:
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001 -- fail closed on anything
            return [self._scan_error(path, stage, exc)]

    # -- stages --------------------------------------------------------------------

    def _provenance(self, info: RepoInfo) -> List[HubFinding]:
        findings: List[HubFinding] = []
        org = self.repo_id.split("/")[0].lower() if "/" in self.repo_id else None
        if self.allowed_organizations and (org is None or org not in self.allowed_organizations):
            findings.append(
                HubFinding(
                    rule_id="policy.organization_not_allowed",
                    category=FindingCategory.POLICY,
                    severity=Severity.HIGH,
                    blocking=True,
                    description=f"Organization `{org or '(none)'}` is not in the allowed list {sorted(self.allowed_organizations)}.",
                    remediation="Use a model published by an approved organization, or have it added to the allowlist.",
                )
            )
        if info.disabled:
            findings.append(
                HubFinding(
                    rule_id="provenance.disabled",
                    category=FindingCategory.PROVENANCE,
                    severity=Severity.HIGH,
                    blocking=True,
                    description="The Hub has disabled this repository (commonly after a malware or abuse report).",
                )
            )
        if not info.files:
            findings.append(
                HubFinding(
                    rule_id="provenance.empty",
                    category=FindingCategory.PROVENANCE,
                    severity=Severity.MEDIUM,
                    description="Repository lists no files at this revision.",
                )
            )
        if info.commit_sha is None and not isinstance(self.transport, LocalDirectoryTransport):
            findings.append(
                HubFinding(
                    rule_id="provenance.unpinned",
                    category=FindingCategory.PROVENANCE,
                    severity=Severity.LOW,
                    description="Could not resolve the revision to a commit SHA; reads are not pinned.",
                )
            )
        return findings

    def _fetch(self, file: RepoFile, rev: str, cache: Dict[str, bytes]) -> bytes:
        if file.path in cache:
            return cache[file.path]
        data = self.transport.read_bytes(self.repo_id, file.path, rev, max_bytes=self.max_text_bytes)
        cache[file.path] = data
        return data

    def _blob_check(self, file: RepoFile, data: bytes) -> List[HubFinding]:
        if not file.blob_id or file.lfs_sha256:
            return []
        actual = git_blob_sha1(data)
        if actual != file.blob_id:
            return [
                HubFinding(
                    rule_id="integrity.blob_mismatch",
                    category=FindingCategory.INTEGRITY,
                    severity=Severity.CRITICAL,
                    description=f"Downloaded content of `{file.path}` does not match the Hub's Git blob id (expected {file.blob_id[:12]}, got {actual[:12]}).",
                    file=file.path,
                    remediation="Content was altered in transit or by a mirror/proxy; do not trust this download.",
                )
            ]
        return []

    def _scan_safetensors(self, file: RepoFile, rev: str) -> List[HubFinding]:
        if file.size is None:
            raise HubAccessError("file size unknown; cannot validate SafeTensors layout")
        with open_range_file(self.transport, self.repo_id, file.path, rev, file.size, buffer_size=64 << 10) as stream:
            header = read_safetensors_header(stream, file_size=file.size, label=file.path)
            findings = list(header.findings)
            if self.scan_weights and header.valid:
                findings += self._scan_weights(stream, header, file)
        return findings

    def _scan_weights(self, stream: Any, header: Any, file: RepoFile) -> List[HubFinding]:
        from cyberjection.hubguard.weightscan import (
            analyze_safetensors_weights,
            embedding_outlier_rows,
            find_embedding_tensor,
            trigger_candidates_from_embeddings,
            vocab_from_tokenizer_json,
        )

        findings, _ = analyze_safetensors_weights(stream, header, label=file.path)
        embedding = find_embedding_tensor(header)
        if embedding is not None:
            try:
                outliers = embedding_outlier_rows(stream, header, embedding)
            except ImportError:
                findings.append(
                    HubFinding(
                        rule_id="weights.numpy_unavailable",
                        category=FindingCategory.WEIGHTS,
                        severity=Severity.INFO,
                        description="NumPy is not installed (`pip install cyberjection[weights]`); embedding outlier analysis skipped.",
                        file=file.path,
                    )
                )
                outliers = []
            if outliers:
                vocab: Dict[int, str] = {}
                try:
                    vocab = vocab_from_tokenizer_json(
                        self.transport.read_bytes(self.repo_id, "tokenizer.json", self._pinned, max_bytes=64 << 20).decode("utf-8", "replace")
                    )
                except (HubAccessError, FileTooLargeError, OSError):
                    pass
                candidates = trigger_candidates_from_embeddings(outliers, vocab)
                self.trigger_candidates.extend(c for c in candidates if c not in self.trigger_candidates)
                findings.append(
                    HubFinding(
                        rule_id="weights.embedding_outliers",
                        category=FindingCategory.WEIGHTS,
                        severity=Severity.LOW,
                        description=(
                            f"{len(outliers)} embedding rows in `{embedding.name}` have extreme norms "
                            f"(max robust z={outliers[0][1]:.1f}); their tokens are trigger candidates for behavioral probing."
                        ),
                        file=file.path,
                        evidence=", ".join(repr(c) for c in candidates[:8]) or ", ".join(str(i) for i, _ in outliers[:8]),
                    )
                )
        return findings

    def _scan_pickle(self, file: RepoFile, rev: str) -> List[HubFinding]:
        if file.size is None:
            raise HubAccessError("file size unknown; cannot scan")
        with open_range_file(self.transport, self.repo_id, file.path, rev, file.size) as stream:
            result = scan_pickle_stream(stream, label=file.path)
        self._pickle_formats[file.path] = result.format
        return result.findings

    def _scan_code(self, file: RepoFile, rev: str, cache: Dict[str, bytes]) -> List[HubFinding]:
        data = self._fetch(file, rev, cache)
        findings = self._blob_check(file, data)
        source = data.decode("utf-8", "replace")
        self._code_sources[file.path] = source
        findings += analyze_python_source(source, filename=file.path).findings
        return findings

    def _scan_text(self, file: RepoFile, rev: str, cache: Dict[str, bytes]) -> List[HubFinding]:
        data = self._fetch(file, rev, cache)
        findings = [] if file.path.endswith(".py") else self._blob_check(file, data)
        return findings + scan_text_for_leaks(data.decode("utf-8", "replace"), source=file.path)

    def _scan_history(self, info: RepoInfo) -> List[HubFinding]:
        findings: List[HubFinding] = []
        commits = self.transport.list_commits(self.repo_id, self._pinned, limit=self.history_depth + 1)
        head_blobs = {f.blob_id for f in info.files if f.blob_id}
        seen_blobs: Set[str] = set(head_blobs)
        budget = _MAX_HISTORY_BYTES
        for commit in commits:
            text = f"{commit.title}\n{commit.message}"
            findings += scan_text_for_leaks(text, source=f"commit {commit.commit_id[:12]}", context="commit message")
        for commit in commits[1:]:
            try:
                past = self.transport.repo_info(self.repo_id, commit.commit_id)
            except HubAccessError:
                continue
            for file in past.files:
                if not file.blob_id or file.blob_id in seen_blobs or file.lfs_sha256 or not is_text_candidate(file.path, file.size):
                    continue
                seen_blobs.add(file.blob_id)
                if file.size is not None:
                    if budget - file.size < 0:
                        continue
                    budget -= file.size
                try:
                    data = self.transport.read_bytes(self.repo_id, file.path, commit.commit_id, max_bytes=self.max_text_bytes)
                except (HubAccessError, FileTooLargeError):
                    continue
                if git_blob_sha1(data) != file.blob_id:
                    continue
                for finding in scan_text_for_leaks(
                    data.decode("utf-8", "replace"),
                    source=file.path,
                    context=f"historical revision {commit.commit_id[:12]}, no longer at HEAD -- still downloadable",
                ):
                    findings.append(finding)
        return findings

    def _profile(self) -> List[HubFinding]:
        from cyberjection.hubguard.sandbox import profile_remote_code

        result = profile_remote_code(self._code_sources, timeout_seconds=self.sandbox_timeout_seconds)
        findings = result.to_findings(label=f"`{self.repo_id}` remote code")
        findings.append(
            HubFinding(
                rule_id="sandbox.summary",
                category=FindingCategory.SANDBOX,
                severity=Severity.INFO,
                description=(
                    f"Sandboxed import ran with isolation layers {result.isolation}; imported {len(result.imported)} module(s), "
                    f"{len(result.import_failures)} failed, {len(result.denied)} operation(s) denied."
                ),
                evidence="; ".join(result.import_failures)[:200] or None,
            )
        )
        return findings

    def _integrity(self, info: RepoInfo, cache: Dict[str, bytes]) -> List[HubFinding]:
        findings: List[HubFinding] = []
        relevant = [
            f.path
            for f in info.files
            if classify_weight_file(f.path) != WeightFormat.NOT_WEIGHTS or f.path.endswith(".py")
        ]
        hub_hashes: Dict[str, Optional[str]] = {}
        for file in info.files:
            if file.lfs_sha256:
                hub_hashes[file.path] = file.lfs_sha256.lower()
            elif file.path in cache:
                hub_hashes[file.path] = hashlib.sha256(cache[file.path]).hexdigest()
            elif self.manifest and file.path in self.manifest.files:
                hub_hashes[file.path] = self.transport.sha256(self.repo_id, file.path, self._pinned)
            else:
                hub_hashes[file.path] = None
        if self.manifest is not None:
            findings += compare_against_manifest(
                self.manifest,
                repo_id=self.repo_id,
                commit_sha=info.commit_sha,
                hub_hashes=hub_hashes,
                integrity_relevant=relevant,
            )
        if self.verify_downloads:
            for file in info.files:
                if classify_weight_file(file.path) == WeightFormat.NOT_WEIGHTS:
                    continue
                actual = self.transport.sha256(self.repo_id, file.path, self._pinned)
                self._verified_hashes[file.path] = actual
                expectations = {
                    "Hub LFS metadata": file.lfs_sha256.lower() if file.lfs_sha256 else None,
                    "hash manifest": self.manifest.files.get(file.path) if self.manifest else None,
                }
                for source, expected in expectations.items():
                    if expected and expected != actual:
                        findings.append(
                            HubFinding(
                                rule_id="integrity.download_mismatch",
                                category=FindingCategory.INTEGRITY,
                                severity=Severity.CRITICAL,
                                description=f"Downloaded bytes of `{file.path}` hash to {actual[:16]}..., not the {source} value {expected[:16]}....",
                                file=file.path,
                            )
                        )
        return findings

    # -- entry point -----------------------------------------------------------------

    async def audit_repository(self) -> HubGuardReport:
        started_at = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        findings: List[HubFinding] = []
        scanned: List[ScannedFile] = []
        self._pickle_formats: Dict[str, str] = {}
        self._code_sources: Dict[str, str] = {}
        self._verified_hashes: Dict[str, str] = {}
        self._pinned = self.revision
        commit_sha: Optional[str] = None

        try:
            info: RepoInfo = await self._run(self.transport.repo_info, self.repo_id, self.revision)
        except Exception as exc:  # noqa: BLE001
            findings.append(self._scan_error(None, "repository_metadata", exc))
            return self._finish(findings, scanned, None, started_at, t0)

        commit_sha = info.commit_sha
        self._pinned = commit_sha or self.revision
        findings += self._provenance(info)
        findings += enforce_format_policy((f.path for f in info.files), self.safetensors_policy)

        cache: Dict[str, bytes] = {}
        tasks: List[Awaitable[List[HubFinding]]] = []
        file_kinds: Dict[str, List[str]] = {}

        def plan(file: RepoFile, scanner: str, coro: Awaitable[List[HubFinding]]) -> None:
            file_kinds.setdefault(file.path, []).append(scanner)
            tasks.append(self._guarded(file.path, scanner, coro))

        for file in info.files:
            fmt = classify_weight_file(file.path)
            if fmt == WeightFormat.SAFETENSORS:
                plan(file, "safetensors", self._run(self._scan_safetensors, file, self._pinned))
            elif fmt == WeightFormat.PICKLE and self.scan_pickles:
                plan(file, "pickle", self._run(self._scan_pickle, file, self._pinned))
            if file.path.endswith(".py") and (self.scan_remote_code or self.profile_remote_code):
                if file.size is not None and file.size > self.max_text_bytes:
                    findings.append(self._scan_error(file.path, "remote_code", FileTooLargeError(f"{file.size} bytes")))
                else:
                    plan(file, "remote_code", self._run(self._scan_code, file, self._pinned, cache))

        # Code first so the text pass reuses its downloads.
        findings += [f for group in await asyncio.gather(*tasks) for f in group]

        if self.scan_remote_code:
            auto_map_entries = []
            for name in _AUTO_MAP_FILES:
                cfg = info.file(name)
                if cfg is None:
                    continue
                try:
                    data = await self._run(self._fetch, cfg, self._pinned, cache)
                    findings += self._blob_check(cfg, data)
                    auto_map_entries += parse_auto_map(data.decode("utf-8", "replace"), source_file=name)
                    file_kinds.setdefault(name, []).append("auto_map")
                except Exception as exc:  # noqa: BLE001
                    findings.append(self._scan_error(name, "auto_map", exc))
            findings += analyze_auto_map(auto_map_entries, {f.path for f in info.files}, block_remote_code=self.block_remote_code)
        elif self.block_remote_code and any(f.path.endswith(".py") for f in info.files):
            findings.append(
                HubFinding(
                    rule_id="remote_code.unscanned",
                    category=FindingCategory.POLICY,
                    severity=Severity.MEDIUM,
                    description="Remote-code scanning is disabled but the repository ships Python files.",
                )
            )

        if self.profile_remote_code and self._code_sources:
            findings += await self._guarded(None, "sandbox_profile", self._run(self._profile))

        if self.scan_secrets:
            text_tasks = []
            for file in info.files:
                if is_text_candidate(file.path, file.size):
                    file_kinds.setdefault(file.path, []).append("secrets")
                    text_tasks.append(self._guarded(file.path, "secrets", self._run(self._scan_text, file, self._pinned, cache)))
                elif is_text_candidate(file.path) and file.size is not None:
                    findings.append(
                        HubFinding(
                            rule_id="secrets.file_skipped",
                            category=FindingCategory.SECRETS,
                            severity=Severity.INFO,
                            description=f"Text file of {file.size} bytes exceeds the secret-scan size limit and was skipped.",
                            file=file.path,
                        )
                    )
            findings += [f for group in await asyncio.gather(*text_tasks) for f in group]
            if self.scan_history and self.history_depth > 0:
                findings += await self._guarded(None, "history", self._run(self._scan_history, info))

        findings += await self._guarded(None, "integrity", self._run(self._integrity, info, cache))

        if self.probe_target is not None:
            findings += await self._guarded(None, "trigger_probe", self._probe())

        for file in info.files:
            fmt = classify_weight_file(file.path)
            kind = self._pickle_formats.get(file.path) or (fmt.value if fmt != WeightFormat.NOT_WEIGHTS else ("code" if file.path.endswith(".py") else "other"))
            sha = self._verified_hashes.get(file.path) or (file.lfs_sha256.lower() if file.lfs_sha256 else None)
            if sha is None and file.path in cache:
                sha = hashlib.sha256(cache[file.path]).hexdigest()
            scanned.append(ScannedFile(path=file.path, size=file.size, kind=kind, sha256=sha, scanners=file_kinds.get(file.path, [])))

        return self._finish(findings, scanned, commit_sha, started_at, t0)

    async def _probe(self) -> List[HubFinding]:
        from cyberjection.hubguard.weightscan import DEFAULT_TRIGGER_CANDIDATES, TriggerProbe

        probe = TriggerProbe(
            self.probe_target,
            triggers=list(DEFAULT_TRIGGER_CANDIDATES) + self.trigger_candidates,
            label=self.repo_id,
        )
        report = await probe.run()
        return report.findings

    def _finish(self, findings: List[HubFinding], scanned: List[ScannedFile], commit_sha: Optional[str], started_at: datetime, t0: float) -> HubGuardReport:
        report = HubGuardReport.build(
            repo_id=self.repo_id,
            revision=self.revision,
            commit_sha=commit_sha,
            findings=findings,
            files=scanned,
            max_allowed_risk_score=self.max_allowed_risk_score,
            started_at=started_at,
            duration_seconds=round(time.perf_counter() - t0, 3),
        )
        if self.audit_logger is not None:
            self.audit_logger.log(
                "hubguard.audit",
                resource=f"hf://{self.repo_id}@{commit_sha or self.revision}",
                outcome=report.verdict.value.lower(),
                metadata={"risk_score": report.risk_score, "findings": len(report.findings), "incomplete": report.incomplete},
            )
        return report


async def generate_manifest(client: HubGuardClient, *, include: Optional[Callable[[str], bool]] = None) -> HashManifest:
    """Builds a `HashManifest` pinning every weight and code file at the
    client's resolved revision. LFS files use the Hub's SHA-256 unless
    `client.verify_downloads` is set, in which case the bytes are hashed."""

    info: RepoInfo = await asyncio.to_thread(client.transport.repo_info, client.repo_id, client.revision)
    pinned = info.commit_sha or client.revision
    files: Dict[str, str] = {}
    for file in info.files:
        relevant = classify_weight_file(file.path) != WeightFormat.NOT_WEIGHTS or file.path.endswith(".py") or PurePosixPath(file.path).name in _AUTO_MAP_FILES
        if include is not None:
            relevant = include(file.path)
        if not relevant:
            continue
        if file.lfs_sha256 and not client.verify_downloads:
            files[file.path] = file.lfs_sha256.lower()
        else:
            files[file.path] = await asyncio.to_thread(client.transport.sha256, client.repo_id, file.path, pinned)
    return HashManifest(repo_id=client.repo_id, revision=info.commit_sha, files=files)
