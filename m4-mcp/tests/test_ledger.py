"""Unit tests for the evidence ledger."""

import json

from tracehunt_mcp.ledger import EvidenceLedger, canonical_query_json, query_hash


def test_hash_is_stable_under_key_order():
    a = {"index": "zeek", "filters": [{"op": "eq", "field": "x", "value": 1}]}
    b = {"filters": [{"value": 1, "field": "x", "op": "eq"}], "index": "zeek"}
    assert query_hash(a) == query_hash(b)
    assert len(query_hash(a)) == 64


def test_hash_changes_with_query():
    assert query_hash({"a": 1}) != query_hash({"a": 2})


def test_records_are_jsonl_and_append_only(cfg):
    ledger = EvidenceLedger(cfg.ledger_path, cfg.run_id)
    ledger.record_ok("search_events", {"index": "sysmon"}, 3, ["d1", "d2", "d3"], 12)
    ledger.record_error("search_events", {"index": "zeek"}, "backend down", 5)

    with open(cfg.ledger_path, encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh if line.strip()]
    assert len(lines) == 2
    assert lines[0]["seq"] == 1 and lines[0]["status"] == "ok"
    assert lines[0]["doc_ids"] == ["d1", "d2", "d3"]
    assert lines[0]["query_hash"] == query_hash({"index": "sysmon"})
    assert lines[1]["seq"] == 2 and lines[1]["status"] == "error"
    assert lines[1]["error"] == "backend down"


def test_seq_continues_after_reload(cfg):
    first = EvidenceLedger(cfg.ledger_path, cfg.run_id)
    first.record_ok("t", {}, 0, [], 1)
    first.record_ok("t", {}, 0, [], 1)

    second = EvidenceLedger(cfg.ledger_path, cfg.run_id)
    rec = second.record_ok("t", {}, 0, [], 1)
    assert rec.seq == 3


def test_history_filters_other_runs(cfg):
    ledger = EvidenceLedger(cfg.ledger_path, "run-A")
    ledger.record_ok("t", {}, 0, [], 1)
    other = EvidenceLedger(cfg.ledger_path, "run-B")
    other.record_ok("t", {}, 0, [], 1)

    assert len(ledger.history(only_this_run=True)) == 1
    assert len(ledger.history(only_this_run=False)) == 2


def test_doc_ids_truncated_in_ledger(cfg):
    ledger = EvidenceLedger(cfg.ledger_path, cfg.run_id)
    ledger.record_ok("search_events", {}, 250, [f"id{i}" for i in range(250)], 3)
    with open(cfg.ledger_path, encoding="utf-8") as fh:
        rec = json.loads(fh.readline())
    assert len(rec["doc_ids"]) == 100
    assert rec["doc_ids_truncated"] is True
