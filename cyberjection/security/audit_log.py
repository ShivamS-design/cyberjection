"""Structured, hash-chained audit logging for security-relevant events.

A plain log line ("user ran `cyberjection run`") is easy to append to but
just as easy to quietly delete or edit after the fact if an operator's
disk access is compromised. Each `AuditEvent` written here carries a
SHA-256 hash of its own canonical JSON plus the *previous* entry's hash
(`prev_hash`), forming a hash chain: altering or removing any entry
breaks every hash computed after it, which `verify_chain` detects. This
doesn't prevent tampering (an attacker with write access can always
truncate the file and recompute a fresh chain from that point), but it
does make silent, undetected tampering of an *existing* entry impossible
without also being caught by `verify_chain` -- the same tamper-evidence
model as, e.g., a Merkle-chained changelog, implemented here with nothing
beyond the standard library.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEvent:
    """One audit log entry.

    `outcome` is a free-text status (`"success"`, `"failure"`, `"denied"`,
    ...) rather than a bool, since some events (e.g. a quality-gate result)
    have more than two meaningful outcomes.
    """

    action: str
    actor: str
    resource: str
    outcome: str
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def canonical_payload(self) -> Dict[str, Any]:
        """The fields that participate in hashing -- everything except the
        hash fields themselves, which are computed *from* this payload and
        appended afterward by `AuditLogger`."""

        return {
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "outcome": self.outcome,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


def _canonical_json(payload: Dict[str, Any]) -> str:
    # sort_keys + fixed separators: two logically-identical payloads must
    # always hash identically regardless of dict insertion order, and the
    # hash must be reproducible across Python versions/processes.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _compute_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    digest_input = prev_hash + _canonical_json(payload)
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()


class AuditLogger:
    """Appends hash-chained `AuditEvent` records as JSON lines to `log_path`.

    A single `AuditLogger` instance is safe to call from multiple threads
    (guarded by an internal lock) but is *not* safe to share across
    multiple processes writing to the same file concurrently -- the chain
    is only coherent if entries are appended in a single, serialized
    order, which a lock enforces within one process but can't enforce
    across processes without a file lock this class doesn't take.
    """

    def __init__(self, log_path: "Path | str") -> None:
        self.log_path = Path(log_path)
        self._lock = threading.Lock()

    def log(
        self,
        action: str,
        *,
        actor: str = "cyberjection",
        resource: str = "",
        outcome: str = "success",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            action=action,
            actor=actor,
            resource=resource,
            outcome=outcome,
            metadata=metadata or {},
        )
        with self._lock:
            prev_hash = self._last_hash()
            entry_hash = _compute_hash(prev_hash, event.canonical_payload())
            record = {**event.canonical_payload(), "prev_hash": prev_hash, "entry_hash": entry_hash}
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(_canonical_json(record) + "\n")
        return event

    def _last_hash(self) -> str:
        if not self.log_path.exists():
            return GENESIS_HASH
        last_line: Optional[str] = None
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if last_line is None:
            return GENESIS_HASH
        return json.loads(last_line)["entry_hash"]

    def read_all(self) -> Iterator[Dict[str, Any]]:
        if not self.log_path.exists():
            return
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    yield json.loads(stripped)


@dataclass(frozen=True)
class ChainVerificationResult:
    valid: bool
    entries_checked: int
    first_broken_index: Optional[int] = None
    reason: Optional[str] = None


def verify_chain(log_path: "Path | str") -> ChainVerificationResult:
    """Re-walks every entry in `log_path`, recomputing each entry's hash
    from its own payload and the previous entry's recorded hash, and
    confirms it matches what was stored. Returns as soon as the first
    mismatch is found (the index of which entry broke, and why), rather
    than silently reporting only a final pass/fail.
    """

    path = Path(log_path)
    if not path.exists():
        return ChainVerificationResult(valid=True, entries_checked=0)

    expected_prev = GENESIS_HASH
    count = 0
    with path.open("r", encoding="utf-8") as f:
        for index, line in enumerate(f):
            stripped = line.strip()
            if not stripped:
                continue
            count += 1
            record = json.loads(stripped)
            recorded_prev = record.get("prev_hash")
            recorded_hash = record.get("entry_hash")
            payload = {k: v for k, v in record.items() if k not in ("prev_hash", "entry_hash")}

            if recorded_prev != expected_prev:
                return ChainVerificationResult(
                    valid=False,
                    entries_checked=count,
                    first_broken_index=index,
                    reason=(
                        f"entry {index}'s prev_hash {recorded_prev!r} does not match the "
                        f"previous entry's actual hash {expected_prev!r}"
                    ),
                )

            recomputed = _compute_hash(expected_prev, payload)
            if recomputed != recorded_hash:
                return ChainVerificationResult(
                    valid=False,
                    entries_checked=count,
                    first_broken_index=index,
                    reason=f"entry {index}'s stored hash does not match its recomputed content hash",
                )

            expected_prev = recorded_hash

    return ChainVerificationResult(valid=True, entries_checked=count)
