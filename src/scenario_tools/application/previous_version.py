"""An entry's previous version: the entry as the root of a checkout of the base branch holds it,
at its path or, moved, at the one its external ID has there."""

from scenario_tools.ports.repository import EntrySource


def previous_version(
    entry: str, external_id: object, previous: EntrySource
) -> tuple[object, object] | None:
    """Its metadata and its stored scenario, ``None`` for a file it lacks; ``None`` when the base
    branch holds no such entry, a new one. A file the readers refuse raises their error."""
    if not previous.exists(entry):
        moved = previous.external_ids().get(str(external_id), ())
        if not moved:
            return None
        entry = moved[0]
    names = previous.names(entry)
    metadata = previous.read_yaml(f"{entry}/scenario.yaml") if "scenario.yaml" in names else None
    stored = previous.read_json(f"{entry}/scenario.json")[1] if "scenario.json" in names else None
    return metadata, stored
