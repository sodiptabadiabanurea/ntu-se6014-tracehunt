"""Shared fixtures for the m4-mcp unit tests."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from tracehunt_mcp.backend import EsBackend
from tracehunt_mcp.config import Config
from tracehunt_mcp.errors import BackendError
from tracehunt_mcp.ledger import EvidenceLedger
from tracehunt_mcp.tools import ToolSet


class FakeBackend(EsBackend):
    """In-memory stand-in for Elasticsearch.

    Understands the exact query shapes the tools produce: bool/filter with
    range on @timestamp, term, match_phrase, exists clauses; size/sort;
    aggs with min/max, terms, date_histogram.
    """

    def __init__(self, docs: dict[str, list[dict]]):
        self.docs = {k: [dict(d, _id=f"{k}-{i}") for i, d in enumerate(v)] for k, v in docs.items()}
        self.calls: list[tuple[str, dict]] = []
        self._fail = False

    def set_fail(self, fail: bool) -> None:
        self._fail = fail

    def _match(self, doc: dict, clause: dict) -> bool:
        if "range" in clause:
            field, spec = next(iter(clause["range"].items()))
            value = doc.get(field)
            if value is None:
                return False
            if "gte" in spec and not (value >= spec["gte"]):
                return False
            if "lt" in spec and not (value < spec["lt"]):
                return False
            return True
        if "term" in clause:
            field, value = next(iter(clause["term"].items()))
            return doc.get(field) == value
        if "match_phrase" in clause:
            field, value = next(iter(clause["match_phrase"].items()))
            doc_value = doc.get(field)
            return isinstance(doc_value, str) and str(value) in doc_value
        if "exists" in clause:
            return clause["exists"]["field"] in doc
        if "match_all" in clause:
            return True
        raise AssertionError(f"unexpected clause {clause}")

    def _hits(self, index: str, query: dict) -> list[dict]:
        bool_spec = query.get("bool", {})
        filters = bool_spec.get("filter", [])
        out = []
        for doc in self.docs.get(index, []):
            if all(self._match(doc, c) for c in filters):
                out.append(doc)
        return out

    def index_exists(self, index: str) -> bool:
        if self._fail:
            raise BackendError("simulated outage")
        return index in self.docs

    def count(self, index: str, query: dict) -> int:
        if self._fail:
            raise BackendError("simulated outage")
        self.calls.append(("count", {"index": index, "query": query}))
        if query.get("match_all") is not None:
            return len(self.docs.get(index, []))
        return len(self._hits(index, query))

    def mget(self, index: str, ids: list[str]) -> list[dict]:
        if self._fail:
            raise BackendError("simulated outage")
        self.calls.append(("mget", {"index": index, "ids": ids}))
        by_id = {d["_id"]: d for d in self.docs.get(index, [])}
        return [
            {"_index": index, "_id": i, "_source": by_id[i], "found": True}
            if i in by_id
            else {"_index": index, "_id": i, "_source": None, "found": False}
            for i in ids
        ]

    def search(self, index: str, body: dict) -> dict:
        if self._fail:
            raise BackendError("simulated outage")
        self.calls.append(("search", {"index": index, "body": body}))
        query = body.get("query", {"match_all": {}})
        hits = self._hits(index, query)
        size = body.get("size", 10)
        sort = body.get("sort")
        if sort and hits:
            field = next(iter(sort[0]))
            order = sort[0][field].get("order", "asc")
            hits = sorted(hits, key=lambda d: str(d.get(field, "")), reverse=(order == "desc"))
        resp: dict = {
            "hits": {
                "total": {"value": len(hits), "relation": "eq"},
                "hits": [
                    {"_index": index, "_id": d["_id"], "_source": {k: v for k, v in d.items() if k != "_id"}}
                    for d in hits[:size]
                ],
            }
        }
        aggs = body.get("aggs")
        if aggs:
            resp["aggregations"] = {}
            for name, spec in aggs.items():
                if "min" in spec:
                    field = spec["min"]["field"]
                    values = [d.get(field) for d in hits if d.get(field) is not None]
                    resp["aggregations"][name] = {
                        "value": min(values) if values else None,
                        "value_as_string": min(values) if values else None,
                    }
                elif "max" in spec:
                    field = spec["max"]["field"]
                    values = [d.get(field) for d in hits if d.get(field) is not None]
                    resp["aggregations"][name] = {
                        "value": max(values) if values else None,
                        "value_as_string": max(values) if values else None,
                    }
                elif "terms" in spec:
                    field = spec["terms"]["field"]
                    counts: dict[str, int] = {}
                    for d in hits:
                        key = d.get(field)
                        if key is not None:
                            counts[str(key)] = counts.get(str(key), 0) + 1
                    resp["aggregations"][name] = {
                        "buckets": [{"key": k, "doc_count": c} for k, c in sorted(counts.items())]
                    }
                elif "date_histogram" in spec:
                    resp["aggregations"][name] = {
                        "buckets": [
                            {"key": i, "key_as_string": str(d.get("@timestamp")), "doc_count": 1}
                            for i, d in enumerate(hits)
                        ]
                    }
                else:
                    raise AssertionError(f"unexpected agg {spec}")
        return resp


LAB_DOCS = {
    "windows-security": [
        {"@timestamp": "2026-09-30T06:40:00Z", "event_id": 4624, "host": "WS-02", "user_name": "office-user"},
        {"@timestamp": "2026-09-30T07:00:00Z", "event_id": 4625, "host": "WS-01", "user_name": "lab-user"},
        {"@timestamp": "2026-09-30T07:05:00Z", "event_id": 4625, "host": "WS-01", "user_name": "lab-user"},
        {"@timestamp": "2026-09-30T07:09:00Z", "event_id": 4624, "host": "WS-01", "user_name": "lab-user"},
        {"@timestamp": "2026-09-30T08:10:00Z", "event_id": 4625, "host": "WS-03", "user_name": "intern"},
    ],
    "sysmon": [
        {"@timestamp": "2026-09-30T07:12:00Z", "event_id": 1, "host": "WS-01", "user_name": "lab-user",
         "command_line": "powershell.exe -NoProfile -EncodedCommand SQBuAHYAbwBrAGUALQ=="},
    ],
    "zeek": [],
}


@pytest.fixture()
def cfg(tmp_path) -> Config:
    return Config(
        es_url="http://fake:9200",
        es_username=None,
        es_password=None,
        es_ca_cert=None,
        indices=("windows-security", "sysmon", "zeek"),
        ledger_path=str(tmp_path / "ledger.jsonl"),
        run_id="run-test-1",
        default_size=50,
        max_size=100,
        max_window_hours=24,
        request_timeout_s=5,
        max_scan=100,
        max_doc_ids=50,
        max_seq_steps=5,
        max_agg_buckets=100,
    )


@pytest.fixture()
def toolset(cfg) -> tuple[ToolSet, FakeBackend, EvidenceLedger]:
    backend = FakeBackend({k: [dict(d) for d in v] for k, v in LAB_DOCS.items()})
    ledger = EvidenceLedger(cfg.ledger_path, cfg.run_id)
    return ToolSet(cfg, backend, ledger), backend, ledger
