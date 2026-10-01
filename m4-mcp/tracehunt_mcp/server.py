"""TraceHunt MCP server: stdio transport, seven typed read-only tools.

Run with:  tracehunt-mcp
Configure the agent client to spawn that command. Every tool result is
also written to the evidence ledger before it is returned.
"""

from __future__ import annotations

import functools
import logging
import sys

from mcp.server.mcpserver import MCPServer

from .backend import EsBackend
from .config import Config
from .errors import BackendError, ToolInputError
from .ledger import EvidenceLedger
from .tools import ToolSet

logger = logging.getLogger("tracehunt_mcp")


def build(cfg: Config | None = None) -> tuple[MCPServer, ToolSet]:
    cfg = cfg or Config.from_env()
    backend = EsBackend(cfg)
    ledger = EvidenceLedger(cfg.ledger_path, cfg.run_id)
    tools = ToolSet(cfg, backend, ledger)
    mcp = MCPServer(
        "tracehunt",
        instructions=(
            "TraceHunt read-only ELK search tools with an evidence ledger. "
            "Every call is recorded with its exact query, hash, and returned "
            "document ids. Use get_query_history to audit a hunt run."
        ),
    )

    def register(name: str, fn, doc: str):
        # Wrap so input/backend errors come back as clean tool errors
        # instead of transport-level exceptions. functools.wraps keeps the
        # real signature so the SDK builds a correct input schema.
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except ToolInputError as exc:
                return {"error": "invalid_input", "message": str(exc)}
            except BackendError as exc:
                return {"error": "backend_unavailable", "message": str(exc)}

        mcp.tool(name=name, description=doc)(wrapper)

    register(
        "list_data_sources",
        tools.list_data_sources,
        "List the allowlisted log indices, whether each exists, and its document count. No arguments.",
    )
    register(
        "get_time_bounds",
        tools.get_time_bounds,
        "Earliest and latest @timestamp plus total document count for one index. Args: index.",
    )
    register(
        "search_events",
        tools.search_events,
        "Bounded event search. Args: index, start (ISO-8601), end (ISO-8601), "
        "filters (list of {field, op: eq|match|exists, value}), size (max capped), "
        "sort (asc|desc). Returns events, total_matches, and doc_ids for citations.",
    )
    register(
        "aggregate_events",
        tools.aggregate_events,
        "Aggregate over a window. Args: index, start, end, kind (terms|date_histogram), "
        "field, interval (e.g. 5m, 1h; required for date_histogram), filters.",
    )
    register(
        "run_sequence_query",
        tools.run_sequence_query,
        "Find entities present in every named step within a window. Args: index, start, "
        "end, entity_field (e.g. user.name), steps (list of {name, filters}). Returns the "
        "entity values matching all steps plus per-step counts.",
    )
    register(
        "fetch_evidence",
        tools.fetch_evidence,
        "Fetch full source documents by id (max 50 per call). Args: index, doc_ids. "
        "Use with doc_ids from search_events to cite exact evidence.",
    )
    register(
        "get_query_history",
        tools.get_query_history,
        "Audit trail of this hunt run: every tool call with timestamp, query hash, "
        "and result count. No arguments.",
    )

    return mcp, tools


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=__import__("sys").stderr)
    mcp, _ = build()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
