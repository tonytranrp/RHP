"""RHP errors as Python exceptions (core/error.hpp: a code, a message, where it happened, a traceback)."""

from __future__ import annotations

from typing import Any, Mapping

__all__ = ["RhpError"]


class RhpError(Exception):
    """An RHP error: `code` is the errc name ("forbidden", "runtime", "timeout", "transport", ...)."""

    def __init__(self, code: str, message: str = "", where: str = "", traceback: str = ""):
        self.code = code
        self.message = message
        self.where = where
        self.traceback = traceback
        text = "[%s]" % code
        if where:
            text += " %s:" % where
        if message:
            text += " " + message
        super().__init__(text)

    @classmethod
    def from_value(cls, value: Any) -> "RhpError":
        """An error map from the wire ({code, message, where, traceback}); unknown codes stay as sent."""
        if not isinstance(value, Mapping):
            return cls("protocol", "an error must be a map, got %r" % (value,), "wire")

        def text(key: str) -> str:
            item = value.get(key)
            return item if isinstance(item, str) else ""

        return cls(text("code") or "runtime", text("message"), text("where"), text("traceback"))

    def to_value(self) -> dict:
        out = {"code": self.code}
        if self.message:
            out["message"] = self.message
        if self.where:
            out["where"] = self.where
        if self.traceback:
            out["traceback"] = self.traceback
        return out
