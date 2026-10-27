"""A copy of the hand-built payload catalogue in a repository of its own, and its variants made
by one change each, so that every defect of the catalogue can be shown alone."""

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.domain.verification.payload_hash import UnhashablePayloadError, payload_hash
from scenario_tools.domain.verification.payload_references import derived_id

ROOT = Path(__file__).resolve().parents[2]
TREE = ROOT / "tests" / "golden" / "payloads"
PS = "process-discovery-ps"
PS_LATER = f"{PS}/1.1.0.json"
PS_FIRST = f"{PS}/1.0.0.json"
WHOAMI = "system-owner-user-discovery-whoami/1.0.0.json"


def repository(tmp_path: Path) -> Path:
    """A repository holding this one's policy data, its schemas and the hand-built catalogue as
    its payloads/; the catalogue's directory is returned."""
    root = tmp_path / "repository"
    for part in ("policy", "schemas"):
        shutil.copytree(ROOT / part, root / part)
    shutil.copytree(TREE, root / "payloads")
    return root / "payloads"


def with_id(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` with the ID its content has, so that a variant has one defect only; a
    document the canonical form cannot read is left as it is."""
    fields = {
        key: value
        for key, value in document.items()
        if key not in {"payload_external_id", "payload_attack_patterns", "payload_domains"}
    }
    try:
        digest = payload_hash(
            fields, document.get("payload_attack_patterns", []), lambda _: None
        ).hex
    except UnhashablePayloadError:
        return document  # a variant the schema refuses: its ID is never read
    return {**document, "payload_external_id": derived_id(digest)}


def edit(catalogue: Path, file: str, change: Callable[[dict[str, Any]], None]) -> None:
    """Change the document of ``file`` and write it back in the stored form: a first version
    with the ID its new content has, which its later versions then carry, a later one with its
    payload's ID, as it was."""
    path = catalogue / file
    document: dict[str, Any] = json.loads(path.read_text("utf-8"))
    change(document)
    if path.name != "1.0.0.json":
        path.write_bytes(stored_form(document))
        return
    document = with_id(document)
    path.write_bytes(stored_form(document))
    for later in sorted(set(path.parent.glob("*.json")) - {path}):
        held: dict[str, Any] = json.loads(later.read_text("utf-8"))
        held["payload_external_id"] = document.get("payload_external_id")
        later.write_bytes(stored_form(held))
