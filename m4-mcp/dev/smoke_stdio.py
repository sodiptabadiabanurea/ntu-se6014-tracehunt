#!/usr/bin/env python3
"""End-to-end smoke test: spawn the server over stdio with a real MCP
client, list tools, and exercise each one against the seeded dev ES.

Run from m4-mcp/ with the venv:
    .venv/bin/python dev/smoke_stdio.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ES_URL = os.environ.get("TRACEHUNT_ES_URL", "http://localhost:19200")
LEDGER = os.environ.get("TRACEHUNT_LEDGER_PATH", "/tmp/m4-smoke-ledger.jsonl")
EXPECTED_TOOLS = {
    "list_data_sources", "get_time_bounds", "search_events",
    "aggregate_events", "run_sequence_query", "fetch_evidence",
    "get_query_history",
}


def content_dict(result):
    """Extract the structured JSON payload from a CallToolResult (SDK 2.x)."""
    sc = getattr(result, "structured_content", None)
    if sc:
        if isinstance(sc, dict) and set(sc.keys()) == {"result"}:
            return sc["result"]
        return sc
    text = result.content[0].text
    return json.loads(text)


async def main() -> int:
    if os.path.exists(LEDGER):
        os.remove(LEDGER)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "tracehunt_mcp.server"],
        env={
            **os.environ,
            "TRACEHUNT_ES_URL": ES_URL,
            "TRACEHUNT_LEDGER_PATH": LEDGER,
            "TRACEHUNT_RUN_ID": "run-smoke-1",
            "PYTHONPATH": os.path.join(os.path.dirname(__file__), ".."),
        },
    )
    failures = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools_resp = await session.list_tools()
            names = {t.name for t in tools_resp.tools}
            print("tools advertised:", sorted(names))
            if names != EXPECTED_TOOLS:
                failures.append(f"tool set mismatch: missing={EXPECTED_TOOLS-names} extra={names-EXPECTED_TOOLS}")

            r = content_dict(await session.call_tool("list_data_sources", {}))
            counts = {s["index"]: s["doc_count"] for s in r["sources"]}
            print("sources:", counts)
            if counts.get("windows-security") != 11:
                failures.append(f"unexpected doc counts {counts}")

            r = content_dict(await session.call_tool("get_time_bounds", {"index": "zeek"}))
            print("zeek bounds:", r["earliest"], r["latest"])

            r = content_dict(await session.call_tool("search_events", {
                "index": "windows-security",
                "start": "2026-09-30T07:00:00Z",
                "end": "2026-09-30T07:30:00Z",
                "filters": [
                    {"field": "user_name", "op": "eq", "value": "lab-user"},
                    {"field": "event_id", "op": "eq", "value": 4625},
                ],
            }))
            print("failed logons found:", r["total_matches"])
            if r["total_matches"] != 8:
                failures.append(f"expected 8 failed logons, got {r['total_matches']}")

            r = content_dict(await session.call_tool("aggregate_events", {
                "index": "windows-security",
                "start": "2026-09-30T06:30:00Z",
                "end": "2026-09-30T08:30:00Z",
                "kind": "terms",
                "field": "host",
            }))
            print("hosts:", [(b["bucket"], b["count"]) for b in r["buckets"]])

            r = content_dict(await session.call_tool("run_sequence_query", {
                "index": "windows-security",
                "start": "2026-09-30T06:30:00Z",
                "end": "2026-09-30T08:00:00Z",
                "entity_field": "user_name",
                "steps": [
                    {"name": "failed", "filters": [{"field": "event_id", "op": "eq", "value": 4625}]},
                    {"name": "success", "filters": [{"field": "event_id", "op": "eq", "value": 4624}]},
                ],
            }))
            print("sequence survivors:", r["entities_matching_all_steps"])
            if "lab-user" not in r["entities_matching_all_steps"]:
                failures.append("sequence query missed lab-user")

            r = content_dict(await session.call_tool("search_events", {
                "index": "sysmon",
                "start": "2026-09-30T07:00:00Z",
                "end": "2026-09-30T07:30:00Z",
                "filters": [{"field": "command_line", "op": "match", "value": "EncodedCommand"}],
            }))
            ps_ids = r["doc_ids"]
            print("powershell evidence ids:", ps_ids)
            if r["total_matches"] != 1:
                failures.append(f"expected 1 encoded powershell event, got {r['total_matches']}")

            r = content_dict(await session.call_tool("fetch_evidence", {
                "index": "sysmon", "doc_ids": ps_ids,
            }))
            print("evidence fetched:", r["found"])
            if r["found"] != len(ps_ids):
                failures.append(f"fetch_evidence lost docs: found {r['found']} of {len(ps_ids)}")
            if "EncodedCommand" not in r["documents"][0].get("command_line", ""):
                failures.append("fetched powershell doc missing EncodedCommand")

            # invalid input must come back as a clean error payload
            r = content_dict(await session.call_tool("search_events", {
                "index": "*",
                "start": "2026-09-30T06:00:00Z",
                "end": "2026-09-30T09:00:00Z",
            }))
            print("wildcard index rejected:", r.get("error"))
            if r.get("error") != "invalid_input":
                failures.append(f"wildcard index not rejected: {r}")

            r = content_dict(await session.call_tool("get_query_history", {}))
            print("history calls:", r["call_count"], "run:", r["run_id"])
            if r["run_id"] != "run-smoke-1":
                failures.append("run id mismatch")

    with open(LEDGER, encoding="utf-8") as fh:
        lines = [json.loads(l) for l in fh if l.strip()]
    print(f"ledger lines on disk: {len(lines)}")
    if len(lines) < 7:
        failures.append(f"ledger too short: {len(lines)} lines")
    if any(len(l["query_hash"]) != 64 for l in lines):
        failures.append("ledger has malformed hashes")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(" -", f)
        return 1
    print("\nSMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
