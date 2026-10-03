"""Structured failures used by validation, batch processing, and quarantine."""


class SchemaError(ValueError):
    """An invalid parser definition or registry operation."""


class RecordError(ValueError):
    def __init__(self, code: str, message: str, field: str | None = None,
                 *, raw_bytes_base64: str | None = None):
        super().__init__(message)
        self.code = code
        self.field = field
        self.raw_bytes_base64 = raw_bytes_base64

    def as_dict(self) -> dict:
        return {"code": self.code, "field": self.field, "message": str(self)}
