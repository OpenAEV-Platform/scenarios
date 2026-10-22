"""The payload ID registry and the catalogue agree: every ID the registry agrees names a version
file with that ID and that hash, and every version file whose ID is not derived from its hash is
in the registry."""

import json
from pathlib import Path

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.verification.payload_references import AgreedIds, derived_id
from scenario_tools.domain.verification.payload_version import PayloadVersion

ROOT = Path(__file__).parents[1]
AGREED = AgreedIds.from_document(YamlDataLoader(ROOT / "policy" / "data").load("payload-ids"))


def _versions() -> list[PayloadVersion]:
    return [
        PayloadVersion(
            path.parent.name,
            path.stem,
            path.relative_to(ROOT).as_posix(),
            json.loads(path.read_text(encoding="utf-8")),
        )
        for path in sorted((ROOT / "payloads").glob("*/*.json"))
    ]


def test_every_agreed_id_names_a_version_file_with_its_hash() -> None:
    held = {version.identifier: version.digest() for version in _versions()}
    for digest, agreed in AGREED.by_hash.items():
        assert held.get(agreed.id) == digest, agreed.name


def test_every_version_file_whose_id_is_not_derived_is_in_the_registry() -> None:
    for version in _versions():
        digest = version.digest()
        if version.identifier != derived_id(digest):
            assert AGREED.id_for(digest) == version.identifier, version.path


def test_the_registry_names_each_version_as_its_file_does() -> None:
    names = {version.digest(): version.name for version in _versions()}
    for digest, agreed in AGREED.by_hash.items():
        assert names[digest] == agreed.name
