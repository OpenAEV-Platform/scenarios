"""Findings: what every command reports, in one stable shape.

A finding has a code (two or three capital letters, a hyphen and three digits), a severity, the
path of the file relative to the repository root (empty when the input is not a file), the JSON
pointer of the field (empty for the whole input) and a message. The path, the field and the
message are shortened to ``MESSAGE_LIMIT`` characters regardless of who builds the finding, since
all three may carry contributor content. A report is ok when it holds no blocking finding, lists
its findings in a stable order, and shows at most ``REPORT_LIMIT`` of them: one last finding
counts the rest.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

_CODE = re.compile(r"[A-Z]{2,3}-[0-9]{3}")
_DRIVE = re.compile(r"[A-Za-z]:")
_POINTER = re.compile(r"(?:/(?:[^~/]|~[01])*)*")  # RFC 6901: "~" only as "~0" or "~1"


MESSAGE_LIMIT = 300
REPORT_LIMIT = 100


def shorten(message: str) -> str:
    """A message is shortened to ``MESSAGE_LIMIT`` characters, so that a long value read from the
    content is never echoed in full."""
    return message if len(message) <= MESSAGE_LIMIT else message[: MESSAGE_LIMIT - 1] + "…"


def _shorten_pointer(pointer: str) -> str:
    """A pointer shortened like a message, without leaving a "~" whose escape was cut off."""
    if len(pointer) <= MESSAGE_LIMIT:
        return pointer
    return pointer[: MESSAGE_LIMIT - 1].removesuffix("~") + "…"


class Severity(Enum):
    BLOCKING = "blocking"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    path: str
    field: str
    message: str

    def __post_init__(self) -> None:
        if not _CODE.fullmatch(self.code):
            raise ValueError(f"finding code {self.code!r} is not like ABC-123")
        if (
            self.path.startswith("/")
            or "\\" in self.path
            or _DRIVE.match(self.path)
            or ".." in self.path.split("/")
        ):
            raise ValueError(f"finding path {self.path!r} is not relative to the repository")
        if not _POINTER.fullmatch(self.field):
            raise ValueError(f"finding field {self.field!r} is not a JSON pointer")
        if not self.message:
            raise ValueError("finding message is empty")
        object.__setattr__(self, "path", shorten(self.path))
        object.__setattr__(self, "field", _shorten_pointer(self.field))
        object.__setattr__(self, "message", shorten(self.message))

    def _sort_key(self) -> tuple[str, str, str, str, str]:
        return (self.path, self.field, self.code, self.message, self.severity.value)


@dataclass(frozen=True)
class Report:
    command: str
    findings: tuple[Finding, ...] = field(default=())

    def __post_init__(self) -> None:
        findings = tuple(sorted(self.findings, key=Finding._sort_key))
        if len(findings) > REPORT_LIMIT:
            shown, hidden = findings[:REPORT_LIMIT], findings[REPORT_LIMIT:]
            blocking = any(finding.severity is Severity.BLOCKING for finding in hidden)
            count = Finding(
                "IO-016",
                Severity.BLOCKING if blocking else Severity.INFO,
                "",
                "",
                f"{len(hidden)} more findings not shown",
            )
            findings = (*shown, count)  # last, out of the sorted order
        object.__setattr__(self, "findings", findings)

    @property
    def ok(self) -> bool:
        return all(finding.severity is not Severity.BLOCKING for finding in self.findings)

    def document(self) -> dict[str, Any]:
        """The JSON document of the contract: ``{command, ok, findings}``."""
        return {
            "command": self.command,
            "ok": self.ok,
            "findings": [
                {
                    "code": finding.code,
                    "severity": finding.severity.value,
                    "path": finding.path,
                    "field": finding.field,
                    "message": finding.message,
                }
                for finding in self.findings
            ],
        }
