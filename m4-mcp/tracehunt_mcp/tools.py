"""The seven typed read-only tools.

Each tool validates its input, runs at most one bounded query, records an
evidence ledger entry, and returns a structured result. Validation errors
raise ToolInputError; backend failures raise BackendError. Both are
surfaced to the agent verbatim by the MCP layer.
"""

from __future__ import annotations

from typing import Any

from . import queries as q
from . import validation as v
from .backend import EsBackend
from .config import Config
from .errors import BackendError, ToolInputError
from .ledger import EvidenceLedger, timed


class ToolSet:
    def __init__(self, cfg: Config, backend: EsBackend, ledger: EvidenceLedger):
        self.cfg = cfg
        self.backend = backend
        self.ledger = ledger

    # 1. list_data_sources ----------------------------------------------

    def list_data_sources(self) -> dict:
        timer = timed()
        sources = []
        for index in self.cfg.indices:
            entry: dict[str, Any] = {"index": index, "available": False, "doc_count": None}
            try:
                if self.backend.index_exists(index):
                    entry["available"] = True
                    entry["doc_count"] = self.backend.count(index, {"match_all": {}})
            except BackendError as exc:
                entry["error"] = str(exc)
            sources.append(entry)
        result = {
            "run_id": self.cfg.run_id,
            "sources": sources,
            "indices_allowlist": list(self.cfg.indices),
        }
        self.ledger.record_ok("list_data_sources", {"indices": list(self.cfg.indices)},
                              len(sources), [], timer.elapsed_ms())
        return result

    # 2. get_time_bounds --------------------------------------------------

    def get_time_bounds(self, index: str) -> dict:
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        agg_query = {
            "size": 0,
            "aggs": {
                "min_ts": {"min": {"field": "@timestamp"}},
                "max_ts": {"max": {"field": "@timestamp"}},
            },
        }
        resp = self.backend.search(idx, agg_query)
        aggs = resp.get("aggregations", {})
        result = {
            "index": idx,
            "earliest": (aggs.get("min_ts") or {}).get("value_as_string"),
            "latest": (aggs.get("max_ts") or {}).get("value_as_string"),
            "doc_count": int(resp.get("hits", {}).get("total", {}).get("value", 0)),
        }
        self.ledger.record_ok("get_time_bounds", {"index": idx, "agg": agg_query},
                              1, [], timer.elapsed_ms())
        return result

    # 3. search_events ----------------------------------------------------

    def search_events(self, index: str, start: str, end: str,
                      filters: list[dict] | None = None,
                      size: int | None = None, sort: str | None = None) -> dict:
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        start_dt, end_dt = v.validate_window(self.cfg, start, end)
        checked_filters = v.validate_filters(self.cfg, filters)
        n = v.validate_size(self.cfg, size)
        order = v.validate_sort(self.cfg, sort)

        query = q.build_query(start_dt, end_dt, checked_filters)
        body = q.search_body(query, n, order)
        canonical = {"index": idx, "start": start_dt.isoformat(), "end": end_dt.isoformat(),
                     "filters": checked_filters, "size": n, "sort": order}
        resp = self.backend.search(idx, body)
        hits = resp.get("hits", {}).get("hits", [])
        total = resp.get("hits", {}).get("total", {})
        doc_ids = [h.get("_id") for h in hits]
        events = [{"_id": h.get("_id"), **h.get("_source", {})} for h in hits]
        result = {
            "index": idx,
            "total_matches": total.get("value", 0),
            "total_relation": total.get("relation", "eq"),
            "returned": len(events),
            "events": events,
            "doc_ids": doc_ids,
        }
        self.ledger.record_ok("search_events", canonical, int(total.get("value", 0)),
                              doc_ids, timer.elapsed_ms())
        return result

    # 4. aggregate_events -------------------------------------------------

    def aggregate_events(self, index: str, start: str, end: str,
                         kind: str, field: str, interval: str | None = None,
                         filters: list[dict] | None = None) -> dict:
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        start_dt, end_dt = v.validate_window(self.cfg, start, end)
        agg_spec = v.validate_agg(self.cfg, kind, field, interval)
        checked_filters = v.validate_filters(self.cfg, filters)

        query = q.build_query(start_dt, end_dt, checked_filters)
        body = {
            "size": 0,
            "query": query,
            "aggs": {"result": q.build_agg(agg_spec)},
        }
        canonical = {"index": idx, "start": start_dt.isoformat(), "end": end_dt.isoformat(),
                     "agg": agg_spec, "filters": checked_filters}
        resp = self.backend.search(idx, body)
        buckets = (resp.get("aggregations", {}).get("result") or {}).get("buckets", [])
        parsed = []
        for b in buckets:
            if b.get("key_as_string") is not None and kind == "date_histogram":
                parsed.append({"bucket": b["key_as_string"], "count": b["doc_count"]})
            else:
                parsed.append({"bucket": b.get("key"), "count": b["doc_count"]})
        result = {
            "index": idx,
            "agg": agg_spec,
            "bucket_count": len(parsed),
            "buckets": parsed[: self.cfg.max_agg_buckets],
            "truncated": len(parsed) > self.cfg.max_agg_buckets,
        }
        self.ledger.record_ok("aggregate_events", canonical, len(parsed), [], timer.elapsed_ms())
        return result

    # 5. run_sequence_query ------------------------------------------------

    def run_sequence_query(self, index: str, start: str, end: str,
                           entity_field: str, steps: list[dict]) -> dict:
        """Find entity values that appear in every step, in order.

        Each step is a named filter set. The tool returns the entity values
        present in all steps plus per-step evidence so the caller can verify
        the sequence actually happened.
        """
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        start_dt, end_dt = v.validate_window(self.cfg, start, end)
        ent = v.validate_entity_field(entity_field)
        checked_steps = v.validate_seq_steps(self.cfg, steps)

        canonical = {"index": idx, "start": start_dt.isoformat(), "end": end_dt.isoformat(),
                     "entity_field": ent, "steps": checked_steps}

        per_step_entities: list[set[str]] = []
        per_step_counts: list[dict] = []
        for step in checked_steps:
            query = q.build_query(start_dt, end_dt, step["filters"])
            body = {
                "size": 0,
                "query": query,
                "aggs": {"entities": {"terms": {"field": ent, "size": self.cfg.max_scan}}},
            }
            resp = self.backend.search(idx, body)
            buckets = (resp.get("aggregations", {}).get("entities") or {}).get("buckets", [])
            entities = {str(b.get("key")) for b in buckets}
            per_step_entities.append(entities)
            per_step_counts.append({"step": step["name"], "entity_count": len(entities)})

        survivors = set.intersection(*per_step_entities) if per_step_entities else set()
        result = {
            "index": idx,
            "entity_field": ent,
            "steps_checked": len(checked_steps),
            "per_step": per_step_counts,
            "entities_matching_all_steps": sorted(survivors),
            "matched_entity_count": len(survivors),
        }
        self.ledger.record_ok("run_sequence_query", canonical, len(survivors), [], timer.elapsed_ms())
        return result

    # 6. fetch_evidence ----------------------------------------------------

    def fetch_evidence(self, index: str, doc_ids: list[str]) -> dict:
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        ids = v.validate_doc_ids(doc_ids)
        canonical = {"index": idx, "doc_ids": ids}
        docs = self.backend.mget(idx, ids)
        found = [d for d in docs if d.get("found")]
        missing = [d["_id"] for d in docs if not d.get("found")]
        result = {
            "index": idx,
            "requested": len(ids),
            "found": len(found),
            "missing_ids": missing,
            "documents": [
                {"_id": d["_id"], **d.get("_source", {})} for d in found
            ],
        }
        self.ledger.record_ok("fetch_evidence", canonical, len(found),
                              [d["_id"] for d in found], timer.elapsed_ms())
        return result

    # 7. get_query_history --------------------------------------------------

    def get_query_history(self) -> dict:
        timer = timed()
        history = self.ledger.history(only_this_run=True)
        result = {
            "run_id": self.cfg.run_id,
            "call_count": len(history),
            "calls": [
                {
                    "seq": h.get("seq"),
                    "ts": h.get("ts"),
                    "tool": h.get("tool"),
                    "status": h.get("status"),
                    "query_hash": h.get("query_hash"),
                    "result_count": h.get("result_count"),
                }
                for h in history
            ],
        }
        self.ledger.record_ok("get_query_history", {"run_id": self.cfg.run_id},
                              len(history), [], timer.elapsed_ms())
        return result
