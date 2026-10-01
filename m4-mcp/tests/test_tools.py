"""Unit tests for the seven tools against the fake backend."""

import pytest

from tracehunt_mcp.errors import BackendError, ToolInputError


def test_list_data_sources(toolset):
    tools, backend, ledger = toolset
    out = tools.list_data_sources()
    assert out["run_id"] == "run-test-1"
    by_index = {s["index"]: s for s in out["sources"]}
    assert by_index["windows-security"]["available"] is True
    assert by_index["windows-security"]["doc_count"] == 5
    assert by_index["zeek"]["doc_count"] == 0
    assert len(ledger.history()) == 1


def test_list_data_sources_backend_down(cfg, toolset):
    tools, backend, ledger = toolset
    backend.set_fail(True)
    out = tools.list_data_sources()
    # availability check fails per index but the tool still returns a result
    assert all(s["available"] is False for s in out["sources"])
    assert all("error" in s for s in out["sources"])


def test_get_time_bounds(toolset):
    tools, backend, ledger = toolset
    out = tools.get_time_bounds("windows-security")
    assert out["earliest"] == "2026-09-30T06:40:00Z"
    assert out["latest"] == "2026-09-30T08:10:00Z"
    assert out["doc_count"] == 5
    with pytest.raises(ToolInputError):
        tools.get_time_bounds("not-in-allowlist")


def test_search_events_basic(toolset):
    tools, backend, ledger = toolset
    out = tools.search_events(
        "windows-security",
        "2026-09-30T06:00:00Z",
        "2026-09-30T09:00:00Z",
        filters=[{"field": "user_name", "op": "eq", "value": "lab-user"}],
    )
    assert out["total_matches"] == 3
    assert out["returned"] == 3
    assert all(e["user_name"] == "lab-user" for e in out["events"])
    assert len(out["doc_ids"]) == 3
    # ledger recorded the call with doc ids
    rec = ledger.history()[0]
    assert rec["tool"] == "search_events"
    assert rec["result_count"] == 3
    assert rec["doc_ids"] == out["doc_ids"]


def test_search_events_respects_size_and_sort(toolset):
    tools, backend, ledger = toolset
    out = tools.search_events(
        "windows-security", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        size=2, sort="desc",
    )
    assert out["returned"] == 2
    assert out["total_matches"] == 5
    timestamps = [e["@timestamp"] for e in out["events"]]
    assert timestamps == sorted(timestamps, reverse=True)


def test_search_events_time_window_is_enforced(toolset):
    tools, backend, ledger = toolset
    with pytest.raises(ToolInputError, match="maximum of 24 hours"):
        tools.search_events("sysmon", "2026-09-28T00:00:00Z", "2026-09-30T09:00:00Z")
    # rejected call must not hit the backend
    assert backend.calls == []


def test_search_events_invalid_index(toolset):
    tools, backend, ledger = toolset
    with pytest.raises(ToolInputError, match="not allowed"):
        tools.search_events("*", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z")


def test_search_events_match_op(toolset):
    tools, backend, ledger = toolset
    out = tools.search_events(
        "sysmon", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        filters=[{"field": "command_line", "op": "match", "value": "EncodedCommand"}],
    )
    assert out["total_matches"] == 1


def test_aggregate_terms(toolset):
    tools, backend, ledger = toolset
    out = tools.aggregate_events(
        "windows-security", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        kind="terms", field="user_name",
    )
    counts = {b["bucket"]: b["count"] for b in out["buckets"]}
    assert counts == {"lab-user": 3, "office-user": 1, "intern": 1}


def test_aggregate_date_histogram(toolset):
    tools, backend, ledger = toolset
    out = tools.aggregate_events(
        "windows-security", "2026-09-30T07:00:00Z", "2026-09-30T08:00:00Z",
        kind="date_histogram", field="@timestamp", interval="1h",
    )
    assert out["bucket_count"] == 3


def test_aggregate_rejects_unknown_kind(toolset):
    tools, backend, ledger = toolset
    with pytest.raises(ToolInputError):
        tools.aggregate_events(
            "windows-security", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
            kind="scripted_metric", field="user_name",
        )


def test_sequence_query_finds_lab_user(toolset):
    tools, backend, ledger = toolset
    out = tools.run_sequence_query(
        "windows-security", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        entity_field="user_name",
        steps=[
            {"name": "failed-logons", "filters": [{"field": "event_id", "op": "eq", "value": 4625}]},
            {"name": "successful-logon", "filters": [{"field": "event_id", "op": "eq", "value": 4624}]},
        ],
    )
    assert out["entities_matching_all_steps"] == ["lab-user"]
    assert out["matched_entity_count"] == 1
    assert out["steps_checked"] == 2


def test_sequence_query_no_false_positive(toolset):
    tools, backend, ledger = toolset
    out = tools.run_sequence_query(
        "windows-security", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        entity_field="user_name",
        steps=[
            {"name": "failed", "filters": [{"field": "event_id", "op": "eq", "value": 4625}]},
            {"name": "powershell", "filters": [{"field": "event_id", "op": "eq", "value": 1}]},
        ],
    )
    # event_id 1 only exists in sysmon, so no windows-security user matches both
    assert out["entities_matching_all_steps"] == []


def test_fetch_evidence_roundtrip(toolset):
    tools, backend, ledger = toolset
    found = tools.search_events(
        "windows-security", "2026-09-30T07:00:00Z", "2026-09-30T08:00:00Z",
        filters=[{"field": "event_id", "op": "eq", "value": 4625}],
    )
    ids = found["doc_ids"]
    out = tools.fetch_evidence("windows-security", ids)
    assert out["found"] == len(ids) == 2
    assert all(d["event_id"] == 4625 for d in out["documents"])
    # missing id is reported, not hidden
    out2 = tools.fetch_evidence("windows-security", ids + ["does-not-exist"])
    assert out2["missing_ids"] == ["does-not-exist"]
    assert out2["found"] == 2


def test_query_history_covers_run(toolset):
    tools, backend, ledger = toolset
    tools.search_events("sysmon", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z")
    tools.aggregate_events(
        "windows-security", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        kind="terms", field="host",
    )
    hist = tools.get_query_history()
    assert hist["run_id"] == "run-test-1"
    # the snapshot covers prior calls; the history call itself lands in the
    # ledger after the snapshot is taken
    tools_called = [c["tool"] for c in hist["calls"]]
    assert tools_called == ["search_events", "aggregate_events"]
    assert all(len(c["query_hash"]) == 64 for c in hist["calls"])
    recorded = [r["tool"] for r in ledger.history()]
    assert recorded == ["search_events", "aggregate_events", "get_query_history"]


def test_backend_failure_surfaces(toolset):
    tools, backend, ledger = toolset
    backend.set_fail(True)
    with pytest.raises(BackendError, match="simulated outage"):
        tools.search_events("sysmon", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z")
