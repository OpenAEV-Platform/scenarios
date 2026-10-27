"""The payload catalogue as a tree of files: one folder per payload, named by its slug, one file
per version, and nothing else; and the index of its versions, which never holds two payloads or
two versions a lookup would have to choose between."""

import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.verification.payload_catalogue import (
    BASE_NAME_DIFFERS,
    BASE_NAME_TAKEN,
    ENTRY_NOT_FOLDER,
    ENTRY_NOT_VERSION_FILE,
    ENTRY_SPECIAL,
    FIRST_MISSING,
    FOLDER_NOT_SLUG,
    FOLDER_WITHOUT_VERSION,
    HASH_TWICE,
    ID_NOT_THE_PAYLOAD_S,
    ID_TWICE,
    OUT_OF_SCHEMA,
    OVER_SIZE,
    VERSION_CHANGED,
    VERSION_NOT_HIGHER,
    VERSION_REMOVED,
    Catalogue,
    CatalogueCollisionError,
    EntryKind,
    TreeEntry,
    catalogue_findings,
    immutability_findings,
    layout,
    schema_findings,
)
from scenario_tools.domain.verification.payload_references import PayloadReference
from scenario_tools.domain.verification.payload_version import VERSION_FILE_LIMIT, PayloadVersion

ROOT = Path(__file__).resolve().parents[3]
TREE = ROOT / "tests" / "golden" / "payloads"
FOLDER, FILE, SPECIAL = EntryKind.FOLDER, EntryKind.FILE, EntryKind.SPECIAL


def _entries() -> list[TreeEntry]:
    return [
        TreeEntry(path.relative_to(TREE).parts, FOLDER if path.is_dir() else FILE, 10)
        for path in sorted(TREE.rglob("*"))
    ]


def _found(entries: list[TreeEntry]) -> list[tuple[str, str]]:
    findings, _ = layout("payloads", entries)
    return [(f.path, f.message) for f in findings]


def test_the_hand_built_tree_is_laid_out_as_a_catalogue() -> None:
    findings, places = layout("payloads", _entries())
    assert findings == ()
    assert [(p.slug, p.version, p.path) for p in places] == [
        ("process-discovery-ps", "1.0.0", "payloads/process-discovery-ps/1.0.0.json"),
        ("process-discovery-ps", "1.1.0", "payloads/process-discovery-ps/1.1.0.json"),
        (
            "system-owner-user-discovery-whoami",
            "1.0.0",
            "payloads/system-owner-user-discovery-whoami/1.0.0.json",
        ),
    ]


def test_the_layout_does_not_depend_on_the_order_entries_come_in() -> None:
    assert layout("payloads", list(reversed(_entries()))) == layout("payloads", _entries())


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (TreeEntry(("README.md",), FILE, 1), ENTRY_NOT_FOLDER),
        (TreeEntry(("Process_Discovery",), FOLDER, 0), FOLDER_NOT_SLUG),
        (TreeEntry(("-ps",), FOLDER, 0), FOLDER_NOT_SLUG),
        (TreeEntry(("a" * 65,), FOLDER, 0), FOLDER_NOT_SLUG),
        (TreeEntry(("link",), SPECIAL, 0), ENTRY_SPECIAL),
    ],
)
def test_an_entry_of_the_catalogue_that_is_not_a_payload_folder_is_refused(
    entry: TreeEntry, message: str
) -> None:
    entries = [*_entries(), entry]
    if entry.kind is FOLDER and len(entry.path[0]) <= 64 and message == FOLDER_NOT_SLUG:
        entries.append(TreeEntry((*entry.path, "1.0.0.json"), FILE, 1))
    assert _found(entries) == [(f"payloads/{entry.path[0]}", message)]


def test_a_slug_at_its_longest_is_a_payload_folder() -> None:
    slug = "a" * 64
    entries = [*_entries(), TreeEntry((slug,), FOLDER, 0), TreeEntry((slug, "1.0.0.json"), FILE, 1)]
    assert _found(entries) == []


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (TreeEntry(("process-discovery-ps", "notes.txt"), FILE, 1), ENTRY_NOT_VERSION_FILE),
        (TreeEntry(("process-discovery-ps", "1.2.json"), FILE, 1), ENTRY_NOT_VERSION_FILE),
        (TreeEntry(("process-discovery-ps", "01.2.0.json"), FILE, 1), ENTRY_NOT_VERSION_FILE),
        (TreeEntry(("process-discovery-ps", "1.2.0.JSON"), FILE, 1), ENTRY_NOT_VERSION_FILE),
        (TreeEntry(("process-discovery-ps", "1.2.0"), FOLDER, 0), ENTRY_NOT_VERSION_FILE),
        (TreeEntry(("process-discovery-ps", "1.2.0.json"), SPECIAL, 0), ENTRY_SPECIAL),
        (
            TreeEntry(("process-discovery-ps", "1.2.0.json"), FILE, VERSION_FILE_LIMIT + 1),
            OVER_SIZE,
        ),
    ],
)
def test_an_entry_of_a_payload_folder_that_is_not_a_version_file_is_refused(
    entry: TreeEntry, message: str
) -> None:
    assert _found([*_entries(), entry]) == [(f"payloads/{'/'.join(entry.path)}", message)]


def test_a_version_file_at_the_size_limit_is_read() -> None:
    entry = TreeEntry(("process-discovery-ps", "1.2.0.json"), FILE, VERSION_FILE_LIMIT)
    findings, places = layout("payloads", [*_entries(), entry])
    assert findings == ()
    assert "1.2.0" in [place.version for place in places]


def test_a_payload_folder_without_a_version_is_refused() -> None:
    assert _found([*_entries(), TreeEntry(("empty",), FOLDER, 0)]) == [
        ("payloads/empty", FOLDER_WITHOUT_VERSION)
    ]


def test_a_payload_folder_without_its_first_version_is_refused() -> None:
    """Its lowest version would carry any ID: only a first version is judged by its content."""
    alone = [TreeEntry(("p",), FOLDER, 0), TreeEntry(("p", "1.1.0.json"), FILE, 1)]
    assert _found([*_entries(), *alone]) == [("payloads/p", FIRST_MISSING)]


def test_an_entry_inside_a_folder_that_is_refused_is_neither_reported_nor_read() -> None:
    entries = [
        *_entries(),
        TreeEntry(("Bad",), FOLDER, 0),
        TreeEntry(("Bad", "1.0.0.json"), FILE, 1),
        TreeEntry(("Bad", "notes.txt"), FILE, 1),
    ]
    findings, places = layout("payloads", entries)
    assert [(f.path, f.message) for f in findings] == [("payloads/Bad", FOLDER_NOT_SLUG)]
    assert "Bad" not in {place.slug for place in places}
    assert len(places) == 3  # the folders after it are still read


def test_a_schema_violation_is_one_finding_at_its_pointer_with_a_fixed_message() -> None:
    found = schema_findings("payloads/p/1.0.0.json", ["/payload_type", ""])
    assert [(f.code, f.field, f.message) for f in found] == [
        ("PAY-009", "/payload_type", OUT_OF_SCHEMA),
        ("PAY-009", "", OUT_OF_SCHEMA),
    ]


# Across versions and payloads


def _version(slug: str, version: str, **changes: Any) -> PayloadVersion:
    source = TREE / slug / f"{version}.json"
    document = json.loads(source.read_text("utf-8")) if source.exists() else _variant(slug, version)
    document.update(changes)
    return PayloadVersion(slug, version, f"payloads/{slug}/{version}.json", document)


def _variant(slug: str, version: str) -> dict[str, Any]:
    """A version under a folder of its own: ps 1.0.0 with its payload's ID."""
    document: dict[str, Any] = json.loads(
        (TREE / "process-discovery-ps" / "1.0.0.json").read_text("utf-8")
    )
    return {**document, "payload_external_id": f"id-{slug}"}


def _tree() -> list[PayloadVersion]:
    return [
        _version("process-discovery-ps", "1.0.0"),
        _version("process-discovery-ps", "1.1.0"),
        _version("system-owner-user-discovery-whoami", "1.0.0"),
    ]


def _across(
    versions: list[PayloadVersion], own: frozenset[tuple[str, str, str]] = frozenset()
) -> list[tuple[str, str, str]]:
    return [(f.path, f.field, f.message) for f in catalogue_findings(versions, own)]


def test_the_hand_built_versions_form_a_catalogue() -> None:
    assert _across(_tree()) == []
    catalogue = Catalogue.of(_tree())
    ps = catalogue.by_slug["process-discovery-ps"]
    assert [version.version for version in ps] == ["1.0.0", "1.1.0"]
    assert catalogue.by_id[ps[1].identifier] == (ps[0], ps[1])
    assert catalogue.by_key[(ps[1].identifier, "1.1.0")] == ps[1]
    assert catalogue.by_hash[ps[0].digest()] == ps[0]
    assert catalogue.by_base_name["process discovery - ps"] == "process-discovery-ps"


def test_versions_with_two_base_names_are_refused_at_the_later_one() -> None:
    first = _tree()[0]
    versions = [
        first,
        _version(
            "process-discovery-ps",
            "1.1.0",
            payload_name="Other (1.1.0)",
            payload_external_id=first.identifier,
        ),
    ]
    assert _across(versions) == [
        ("payloads/process-discovery-ps/1.1.0.json", "/payload_name", BASE_NAME_DIFFERS)
    ]


@pytest.mark.parametrize(
    "name", ["Process Discovery - ps", "process discovery  -  PS", "Process Discovery - ps (1.1.0)"]
)
def test_a_base_name_two_payloads_share_is_refused_at_the_second(name: str) -> None:
    version = "1.1.0" if name.endswith(")") else "1.0.0"
    other = _version("zz-other-ps", version, payload_name=name, command_content="ps -e")
    assert _across([*_tree(), other]) == [
        (f"payloads/zz-other-ps/{version}.json", "/payload_name", BASE_NAME_TAKEN)
    ]


def test_an_id_two_payloads_share_is_refused_at_the_second() -> None:
    first = _tree()[0]
    other = _version(
        "zz-other-ps", "1.0.0", payload_name="Another", payload_external_id=first.identifier
    )
    assert _across([*_tree(), other]) == [
        ("payloads/zz-other-ps/1.0.0.json", "/payload_external_id", ID_TWICE)
    ]


def test_the_versions_of_a_payload_share_its_first_version_s_id() -> None:
    first = _version("p", "1.0.0")
    later = _version(
        "p", "1.1.0", payload_name="Process Discovery - ps (1.1.0)", command_content="ps"
    )
    assert first.identifier == later.identifier == "id-p"
    assert _across([first, later]) == []


def test_a_later_version_with_another_id_is_refused() -> None:
    first = _version("p", "1.0.0")
    later = _version(
        "p",
        "1.1.0",
        payload_name="Process Discovery - ps (1.1.0)",
        command_content="ps",
        payload_external_id="another-id",
    )
    assert _across([first, later]) == [
        ("payloads/p/1.1.0.json", "/payload_external_id", ID_NOT_THE_PAYLOAD_S)
    ]
    ((code, severity),) = {(f.code, f.severity) for f in catalogue_findings([first, later])}
    assert (code, severity) == ("PAY-003", Severity.BLOCKING)
    # A version the registry lists as keeping its own ID is judged by its content instead.
    assert _across([first, later], own=frozenset({("p", "1.1.0", later.digest())})) == []


def test_a_hash_two_versions_share_is_refused_at_the_second() -> None:
    copy = _version("zz-other-ps", "1.0.0", payload_external_id="other-id")
    copy_named = PayloadVersion(copy.slug, copy.version, copy.path, dict(copy.document))
    found = _across([_tree()[0], copy_named])
    assert ("payloads/zz-other-ps/1.0.0.json", "", HASH_TWICE) in found


def test_an_unhashable_version_is_left_to_its_own_finding() -> None:
    broken = _version("zz-other-ps", "1.0.0", payload_name="Another", payload_platforms=["a", "a"])
    assert _across([*_tree(), broken]) == []


def test_the_index_refuses_to_build_on_a_collision() -> None:
    other = _version(
        "zz-other-ps", "1.0.0", payload_external_id=_tree()[0].identifier, payload_name="X"
    )
    with pytest.raises(CatalogueCollisionError):
        Catalogue.of([*_tree(), other])


def test_findings_across_the_catalogue_do_not_depend_on_the_order_of_the_versions() -> None:
    other = _version("zz-other-ps", "1.0.0", command_content="ps -e")
    versions = [*_tree(), other]
    assert _across(versions) == _across(list(reversed(versions)))


def test_the_size_limit_of_a_version_file_is_256_kib() -> None:
    assert VERSION_FILE_LIMIT == 262_144


def test_findings_on_the_catalogue_block() -> None:
    findings, _ = layout("payloads", [*_entries(), TreeEntry(("README.md",), FILE, 1)])
    assert [finding.severity.value for finding in findings] == ["blocking"]


def test_an_entry_deeper_than_a_version_file_is_refused() -> None:
    entries = [*_entries(), TreeEntry(("process-discovery-ps", "x", "1.0.0.json"), FILE, 1)]
    assert _found(entries) == [
        ("payloads/process-discovery-ps/x/1.0.0.json", ENTRY_NOT_VERSION_FILE)
    ]


def test_versions_are_in_semantic_order_not_in_text_order() -> None:
    entries = [
        TreeEntry(("p",), FOLDER, 0),
        TreeEntry(("p", "1.10.0.json"), FILE, 1),
        TreeEntry(("p", "1.9.0.json"), FILE, 1),
    ]
    _, places = layout("payloads", entries)
    assert [place.version for place in places] == ["1.9.0", "1.10.0"]
    first = _version(
        "p", "1.9.0", payload_name="Process Discovery - ps (1.9.0)", payload_external_id="a"
    )
    later = _version("p", "1.10.0", payload_name="Other (1.10.0)", payload_external_id="a")
    assert _across([later, first]) == [
        ("payloads/p/1.10.0.json", "/payload_name", BASE_NAME_DIFFERS)
    ]


def test_the_base_name_of_a_payload_is_its_first_version_s() -> None:
    versions = [
        _version("p", "1.0.0", payload_external_id="a"),
        _version("p", "1.1.0", payload_name="Other (1.1.0)", payload_external_id="a"),
        _version(
            "p", "1.2.0", payload_name="Process Discovery - ps (1.2.0)", payload_external_id="a"
        ),
    ]
    assert _across(versions) == [("payloads/p/1.1.0.json", "/payload_name", BASE_NAME_DIFFERS)]


def test_a_base_name_that_differs_is_compared_exactly_within_a_payload() -> None:
    versions = [
        _version("p", "1.0.0", payload_name="Foo", payload_external_id="a"),
        _version("p", "1.1.0", payload_name="foo (1.1.0)", payload_external_id="a"),
    ]
    assert _across(versions) == [("payloads/p/1.1.0.json", "/payload_name", BASE_NAME_DIFFERS)]


def test_a_base_name_that_differs_and_another_payload_has_is_reported_once() -> None:
    versions = [*_tree(), _version("zz-other-ps", "1.0.0", payload_name="Other")]
    versions.append(
        _version(
            "zz-other-ps",
            "1.1.0",
            payload_name="Process Discovery - ps (1.1.0)",
            payload_external_id="id-zz-other-ps",
            command_content="ps -e",
        )
    )
    assert _across(versions) == [
        ("payloads/zz-other-ps/1.1.0.json", "/payload_name", BASE_NAME_DIFFERS)
    ]


def test_the_index_reads_its_versions_in_order_whatever_they_come_in() -> None:
    catalogue = Catalogue.of(list(reversed(_tree())))
    assert [v.version for v in catalogue.by_slug["process-discovery-ps"]] == ["1.0.0", "1.1.0"]


def test_the_index_refuses_a_version_it_cannot_hash() -> None:
    broken = _version("zz-other-ps", "1.0.0", payload_name="Another", payload_platforms=["a", "a"])
    with pytest.raises(CatalogueCollisionError) as refused:
        Catalogue.of([*_tree(), broken])
    assert str(refused.value) == "a version cannot be hashed: it has no place by hash"


def test_the_index_says_why_it_refuses_a_collision() -> None:
    other = _version(
        "zz-other-ps", "1.0.0", payload_external_id=_tree()[0].identifier, payload_name="X"
    )
    with pytest.raises(CatalogueCollisionError) as refused:
        Catalogue.of([*_tree(), other])
    assert str(refused.value) == "the versions do not form a catalogue"


def test_an_entry_deeper_than_a_version_file_is_refused_whatever_its_name() -> None:
    entries = [*_entries(), TreeEntry(("process-discovery-ps", "1.2.0.json", "x"), FILE, 1)]
    assert _found(entries) == [
        ("payloads/process-discovery-ps/1.2.0.json/x", ENTRY_NOT_VERSION_FILE)
    ]


def test_a_folder_holding_only_refused_entries_holds_no_version() -> None:
    entries = [
        *_entries(),
        TreeEntry(("empty",), FOLDER, 0),
        TreeEntry(("empty", "x.txt"), FILE, 1),
    ]
    assert _found(entries) == [
        ("payloads/empty/x.txt", ENTRY_NOT_VERSION_FILE),
        ("payloads/empty", FOLDER_WITHOUT_VERSION),
    ]


def test_the_catalogue_gives_each_version_as_the_reference_that_names_it() -> None:
    versions = _tree()
    held = Catalogue.of(versions).held()

    assert sorted(held.by_key.values(), key=lambda r: (r.id, r.version)) == sorted(
        (PayloadReference(v.identifier, v.version, v.digest()) for v in versions),
        key=lambda r: (r.id, r.version),
    )


BASE = {("ps", "1.0.0"): b"one\n", ("ps", "1.1.0"): b"two\n", ("whoami", "1.0.0"): b"me\n"}


def _immutability(current: dict[tuple[str, str], bytes]) -> list[tuple[str, str, str]]:
    return [(f.code, f.path, f.message) for f in immutability_findings(BASE, current, "payloads")]


def test_a_catalogue_that_keeps_the_base_and_adds_higher_versions_is_accepted() -> None:
    current = {
        **BASE,
        ("ps", "1.2.0"): b"three\n",
        ("ps", "2.0.0"): b"four\n",
        ("new", "1.0.0"): b"",
    }

    assert _immutability(current) == []


def test_an_empty_base_accepts_any_catalogue() -> None:
    assert immutability_findings({}, BASE, "payloads") == ()


def test_a_version_the_base_holds_edited_or_removed_is_refused() -> None:
    current = {("ps", "1.0.0"): b"changed\n", ("whoami", "1.0.0"): b"me\n"}

    assert _immutability(current) == [
        ("VER-022", "payloads/ps/1.0.0.json", VERSION_CHANGED),
        ("VER-022", "payloads/ps/1.1.0.json", VERSION_REMOVED),
    ]


def test_a_payload_folder_the_base_holds_removed_is_refused_for_each_version() -> None:
    assert _immutability({("whoami", "1.0.0"): b"me\n"}) == [
        ("VER-022", "payloads/ps/1.0.0.json", VERSION_REMOVED),
        ("VER-022", "payloads/ps/1.1.0.json", VERSION_REMOVED),
    ]


@pytest.mark.parametrize("version", ["1.0.1", "0.9.0", "1.0.9"])
def test_a_new_version_not_higher_than_the_base_s_highest_is_refused(version: str) -> None:
    assert _immutability({**BASE, ("ps", version): b"late\n"}) == [
        ("VER-023", f"payloads/ps/{version}.json", VERSION_NOT_HIGHER)
    ]


def test_every_finding_of_immutability_blocks() -> None:
    found = immutability_findings(BASE, {("ps", "1.0.0"): b"x", ("ps", "0.1.0"): b"x"}, "payloads")

    assert {f.message for f in found} == {VERSION_CHANGED, VERSION_REMOVED, VERSION_NOT_HIGHER}

    assert {f.severity for f in found} == {Severity.BLOCKING}
    assert {f.field for f in found} == {""}


def test_versions_are_compared_by_their_numbers_never_as_text() -> None:
    base = {("ps", "1.9.0"): b"a"}
    later = {("ps", "1.10.0"): b"b"}

    assert immutability_findings(base, {**base, **later}, "payloads") == ()
    assert [
        f.code for f in immutability_findings(later, {**later, ("ps", "1.9.5"): b"c"}, "payloads")
    ] == ["VER-023"]


def test_immutability_findings_are_in_the_order_of_the_slugs_then_of_the_numbers() -> None:
    base = {("b", "3.0.0"): b"b", ("a", "1.10.0"): b"a", ("a", "1.9.0"): b"a", ("a", "2.0.0"): b"a"}
    current = {("a", "2.0.0"): b"a", ("b", "1.0.0"): b"", ("a", "1.11.0"): b"", ("a", "1.2.0"): b""}

    assert [f.path for f in immutability_findings(base, current, "p")] == [
        "p/a/1.9.0.json",
        "p/a/1.10.0.json",
        "p/b/3.0.0.json",
        "p/a/1.2.0.json",
        "p/a/1.11.0.json",
        "p/b/1.0.0.json",
    ]


def test_the_highest_version_of_the_base_is_its_highest_whatever_the_order_it_is_read_in() -> None:
    base = {("ps", "2.0.0"): b"two", ("ps", "1.0.0"): b"one"}

    assert [f.code for f in immutability_findings(base, {**base, ("ps", "1.5.0"): b""}, "p")] == [
        "VER-023"
    ]


def test_a_new_version_the_same_number_as_the_highest_written_otherwise_is_not_higher() -> None:
    base = {("ps", "1.1.0"): b"one"}

    assert [f.code for f in immutability_findings(base, {**base, ("ps", "1.01.0"): b""}, "p")] == [
        "VER-023"
    ]
