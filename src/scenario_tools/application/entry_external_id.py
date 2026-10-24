"""The external ID an entry is prepared under: the one its metadata declares, or the one given."""

import re
from pathlib import Path

from scenario_tools.domain.shared.finding import shorten
from scenario_tools.ports.errors import UsageProblemError

CANONICAL_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def entry_external_id(metadata: Path, declared: object, given: str | None) -> str:
    """The external ID of the entry: what its ``scenario.yaml``, at ``metadata``, declares,
    ``None`` when it has none or declares none, otherwise ``given`` on the command line.
    Anything else is a ``UsageProblemError``, raised before anything is written."""
    if given is not None and declared is not None and given != declared:
        raise UsageProblemError(f"--external-id contradicts {metadata}: {shorten(repr(declared))}")
    if given is None and declared is not None:
        if not isinstance(declared, str) or not CANONICAL_UUID.fullmatch(declared):
            raise UsageProblemError(
                f"the external_id of {metadata} is not a UUID in lower case with hyphens: "
                f"{shorten(repr(declared))}"
            )
        return declared
    if given is None or not CANONICAL_UUID.fullmatch(given):
        raise UsageProblemError(
            "give --external-id, a UUID in lower case with hyphens, for a first preparation"
        )
    return given
