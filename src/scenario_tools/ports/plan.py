"""Port: the plan of a pull request, published in a place reserved for it."""

from contextlib import AbstractContextManager
from typing import Protocol


class PlanReservation(Protocol):
    """A plan's place, reserved."""

    def publish(self, data: bytes) -> None:
        """Write ``data`` as the plan; once published, it stays, however the block ends."""
        ...


class PlanSink(Protocol):
    """Where the plan goes."""

    def reserving(self) -> AbstractContextManager[PlanReservation]:
        """Reserve the plan's place for as long as a block runs, so that no other run takes it;
        a block that ends before publishing gives it back. A place that cannot be used raises
        ``EnvironmentProblemError``."""
        ...
