"""Error types for the TraceHunt MCP tools."""


class ToolInputError(ValueError):
    """Raised when a tool argument fails validation.

    The message is returned verbatim to the calling agent, so it must
    state what was wrong and what the allowed shape is.
    """


class BackendError(RuntimeError):
    """Raised when Elasticsearch is unreachable or returns an error."""
