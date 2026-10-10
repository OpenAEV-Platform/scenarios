"""Port: validation of a document against one of the repository's schemas."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class SchemaViolation:
    """Where a document breaks its schema: the JSON pointer (RFC 6901) of the offending value,
    empty for the document itself, and why."""

    pointer: str
    message: str


class SchemaValidator(Protocol):
    def validate(self, schema: str, document: object) -> tuple[SchemaViolation, ...]:
        """The violations of ``document`` against the schema named ``schema``, in a stable
        order; an empty tuple when it conforms. A hostile document could break the schema in
        millions of places, so an adapter may stop after a bounded number of violations (100
        for the repository's validator): a non-empty result then means the document is refused,
        not that every violation is listed."""
        ...
