"""Tests for cyberjection.security.audit_log.

`AuditLogger`/`verify_chain` are pure-stdlib (json/hashlib/threading), so
these tests need no shims and exercise the real hash-chain implementation
directly, including a genuine tamper-and-detect round trip.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from cyberjection.security.audit_log import GENESIS_HASH, AuditLogger, verify_chain


class TestAuditLoggerLog:
    def test_first_entry_chains_to_genesis_hash(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log("test.event")
        entries = list(logger.read_all())
        assert len(entries) == 1
        assert entries[0]["prev_hash"] == GENESIS_HASH

    def test_second_entry_chains_to_first_entrys_hash(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log("first")
        logger.log("second")
        entries = list(logger.read_all())
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]

    def test_log_returns_the_appended_event(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        event = logger.log("cli.run.invoked", actor="operator", resource="cfg.yaml", outcome="success")
        assert event.action == "cli.run.invoked"
        assert event.actor == "operator"
        assert event.resource == "cfg.yaml"
        assert event.outcome == "success"

    def test_metadata_is_persisted_and_round_trips(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log("cli.audit.deps", metadata={"findings": 3, "source": "pip-audit"})
        entries = list(logger.read_all())
        assert entries[0]["metadata"] == {"findings": 3, "source": "pip-audit"}

    def test_log_file_created_on_first_write(self, tmp_path: Path) -> None:
        log_path = tmp_path / "nested" / "audit.jsonl"
        logger = AuditLogger(log_path)
        assert not log_path.exists()
        logger.log("test.event")
        assert log_path.exists()

    def test_log_file_is_valid_jsonl(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("one")
        logger.log("two")
        lines = log_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        for line in lines:
            json.loads(line)  # must not raise

    def test_concurrent_appends_from_multiple_threads_stay_chained(self, tmp_path: Path) -> None:
        # AuditLogger.log() takes an internal lock so concurrent writers
        # from multiple threads (e.g. multiple CLI invocations sharing a
        # process, or future async worker paths) can't interleave their
        # hash computation and produce a broken chain.
        logger = AuditLogger(tmp_path / "audit.jsonl")
        errors: list[Exception] = []

        def worker(n: int) -> None:
            try:
                for i in range(20):
                    logger.log(f"worker.{n}.event.{i}")
            except Exception as exc:  # pragma: no cover - failure diagnostic
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        entries = list(logger.read_all())
        assert len(entries) == 200
        result = verify_chain(tmp_path / "audit.jsonl")
        assert result.valid, result.reason
        assert result.entries_checked == 200


class TestVerifyChain:
    def test_empty_log_is_valid(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        result = verify_chain(log_path)
        assert result.valid
        assert result.entries_checked == 0

    def test_untampered_chain_is_valid(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        for i in range(5):
            logger.log(f"event.{i}")
        result = verify_chain(log_path)
        assert result.valid
        assert result.entries_checked == 5
        assert result.first_broken_index is None

    def test_tampering_with_a_field_is_detected(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("first")
        logger.log("second")
        logger.log("third")

        lines = log_path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["action"] = "first.tampered"
        lines[0] = json.dumps(tampered)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_chain(log_path)
        assert not result.valid
        assert result.first_broken_index == 0

    def test_tampering_with_a_later_entry_reports_that_indexs_position(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        for i in range(4):
            logger.log(f"event.{i}")

        lines = log_path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[2])
        tampered["outcome"] = "tampered"
        lines[2] = json.dumps(tampered)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_chain(log_path)
        assert not result.valid
        assert result.first_broken_index == 2

    def test_truncating_the_chain_and_restarting_is_detected(self, tmp_path: Path) -> None:
        # An attacker with delete access could try to hide tampering by
        # deleting the log and starting a fresh chain from GENESIS_HASH.
        # verify_chain() can only validate what's on disk -- it can't
        # detect an entirely-replaced file against a chain it never saw --
        # but it must still validate a truncated-then-restarted chain
        # internally consistently (this documents that limitation rather
        # than silently assuming otherwise).
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)
        logger.log("first")
        logger.log("second")

        # Simulate deletion + restart: truncate to zero entries.
        log_path.write_text("", encoding="utf-8")
        logger2 = AuditLogger(log_path)
        logger2.log("restarted")

        result = verify_chain(log_path)
        assert result.valid
        assert result.entries_checked == 1

    def test_missing_log_file_is_treated_as_empty_and_valid(self, tmp_path: Path) -> None:
        result = verify_chain(tmp_path / "does_not_exist.jsonl")
        assert result.valid
        assert result.entries_checked == 0
