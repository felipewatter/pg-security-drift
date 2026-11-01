"""Public errors contain no DSNs, SQL source, passwords or catalog payloads."""
class DriftError(Exception):
    """A checked operation could not be completed safely."""

class InputError(DriftError):
    """Invalid or incomplete snapshot input."""

class CaptureError(DriftError):
    """Unable to obtain complete catalog metadata via PostgreSQL."""
