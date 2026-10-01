"""Append-only evidence ledger.

Every MCP tool call appends one JSON line with the run id, tool name,
exact normalized query, its SHA-256 hash, result count, and the document
ids it returned. This is what makes each claim in the hunt report
traceable back to a reproducible query.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

MAX_DOC_IDS_IN_LEDGER = 100


def canonical_query_json(query: Any) -> str:
    """Stable serialization so the same query always hashes the same."""
    return json.dumps(query, sort_keys=True, separators=(",", ":"), default=str)


def query_hash(query: Any) -> str:
    return hashlib.sha256(canonical_query_json(query).encode("utf-8")).hexdigest()


@dataclass
class LedgerRecord:
    seq: int
    run_id: str
    ts: str
    tool: str
    status: str
    query: dict
    query_hash: str
    result_count: int
    doc_ids: list[str] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0

    def to_json_line(self) -> str:
        payload: dict[str, Any] = {
            "seq": self.seq,
            "run_id": self.run_id,
            "ts": self.ts,
            "tool": self.tool,
            "status": self.status,
            "query": self.query,
            "query_hash": self.query_hash,
            "result_count": self.result_count,
            "doc_ids": self.doc_ids[:MAX_DOC_IDS_IN_LEDGER],
            "doc_ids_truncated": len(self.doc_ids) > MAX_DOC_IDS_IN_LEDGER,
            "duration_ms": self.duration_ms,
        }
        if self.error is not None:
            payload["error"] = self.error
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


class EvidenceLedger:
    """JSONL append-only ledger with fsync and a process-local lock."""

    def __init__(self, path: str, run_id: str):
        self.path = path
        self.run_id = run_id
        self._lock = threading.Lock()
        self._seq = 0
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        if os.path.exists(path):
            self._seq = self._count_existing(path)

    @staticmethod
    def _count_existing(path: str) -> int:
        count = 0
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    count += 1
        return count

    def record_ok(self, tool: str, query: dict, result_count: int,
                  doc_ids: list[str], duration_ms: int) -> LedgerRecord:
        return self._append(tool, "ok", query, result_count, doc_ids, None, duration_ms)

    def record_error(self, tool: str, query: dict, error: str, duration_ms: int) -> LedgerRecord:
        return self._append(tool, "error", query, 0, [], error, duration_ms)

    def _append(self, tool: str, status: str, query: dict, result_count: int,
                doc_ids: list[str], error: str | None, duration_ms: int) -> LedgerRecord:
        with self._lock:
            self._seq += 1
            rec = LedgerRecord(
                seq=self._seq,
                run_id=self.run_id,
                ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                tool=tool,
                status=status,
                query=query,
                query_hash=query_hash(query),
                result_count=result_count,
                doc_ids=doc_ids,
                error=error,
                duration_ms=duration_ms,
            )
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(rec.to_json_line() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return rec

    def history(self, only_this_run: bool = True) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        out: list[dict] = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if only_this_run and rec.get("run_id") != self.run_id:
                    continue
                out.append(rec)
        return out


def timed() -> "_Timer":
    return _Timer()


class _Timer:
    def __init__(self) -> None:
        self._start = time.monotonic()

    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self._start) * 1000)
