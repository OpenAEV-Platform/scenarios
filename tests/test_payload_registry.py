"""The payload ID registry and the catalogue agree: every ID the registry agrees names a first
version file with that ID and that hash, and every version file carries its payload's ID, the one
of its first version, unless the registry lists it as keeping its own."""

import json
from pathlib import Path

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.domain.verification.payload_references import AgreedIds
from scenario_tools.domain.verification.payload_version import PayloadVersion

ROOT = Path(__file__).parents[1]
FIRST = "1.0.0"
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


def test_every_agreed_id_names_a_first_version_file_with_its_hash() -> None:
    held = {v.identifier: v.digest() for v in _versions() if v.version == FIRST}
    for digest, agreed in AGREED.by_hash.items():
        assert held.get(agreed.id) == digest, agreed.name


def test_every_version_file_carries_its_payloads_id() -> None:
    versions = _versions()
    first = {v.slug: AGREED.id_for(v.digest()) for v in versions if v.version == FIRST}
    for version in versions:
        digest = version.digest()
        if AGREED.keeps_own_id(version.slug, version.version, digest):
            assert version.identifier == AGREED.id_for(digest), version.path
        else:
            assert version.identifier == first[version.slug], version.path


def test_the_registry_names_each_version_as_its_file_does() -> None:
    names = {version.digest(): version.name for version in _versions()}
    for digest, agreed in AGREED.by_hash.items():
        assert names[digest] == agreed.name
