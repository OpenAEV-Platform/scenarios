"""One version file of the payload catalogue: its hash is the hash of the same payload embedded
in a scenario, its ID is the one its content has, its name carries its version, and it is stored
as the repository stores every file."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.shared.canonical import stored_form
from scenario_tools.domain.verification.payload_hash import (
    UnhashablePayloadError,
    embedded_payloads,
    payload_hash,
)
from scenario_tools.domain.verification.payload_references import AgreedIds, derived_id
from scenario_tools.domain.verification.payload_version import (
    ID_NOT_ITS_CONTENT,
    NAME_NO_SUFFIX,
    NAME_SUFFIX_ON_FIRST,
    NOT_HASHABLE,
    NOT_STORED_FORM,
    REGISTRY_OTHER_NAME,
    SET_NOT_SORTED,
    PayloadVersion,
    version_findings,
)

ROOT = Path(__file__).resolve().parents[3]
TREE = ROOT / "tests" / "golden" / "payloads"
PS = "payloads/process-discovery-ps/1.0.0.json"
NO_AGREED = AgreedIds({})


def _document(slug: str = "process-discovery-ps", version: str = "1.0.0") -> dict[str, Any]:
    document: dict[str, Any] = json.loads((TREE / slug / f"{version}.json").read_text("utf-8"))
    return document


def _version(document: dict[str, Any], version: str = "1.0.0") -> PayloadVersion:
    return PayloadVersion(
        "process-discovery-ps", version, f"payloads/process-discovery-ps/{version}.json", document
    )


def _findings(
    document: dict[str, Any], version: str = "1.0.0", agreed: AgreedIds = NO_AGREED
) -> list[tuple[str, str, str]]:
    found = version_findings(_version(document, version), stored_form(document), agreed)
    return [(f.code, f.field, f.message) for f in found]


def _with_id(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` with the ID its content has."""
    return {**document, "payload_external_id": derived_id(_version(document).digest())}


@pytest.mark.parametrize(
    ("slug", "version"),
    [
        ("process-discovery-ps", "1.0.0"),
        ("process-discovery-ps", "1.1.0"),
        ("system-owner-user-discovery-whoami", "1.0.0"),
    ],
)
def test_the_files_of_the_hand_built_tree_pass(slug: str, version: str) -> None:
    document = _document(slug, version)
    found = version_findings(
        PayloadVersion(slug, version, f"payloads/{slug}/{version}.json", document),
        (TREE / slug / f"{version}.json").read_bytes(),
        NO_AGREED,
    )
    assert found == ()


def test_the_hash_leaves_the_id_and_the_domains_out() -> None:
    document = _document("system-owner-user-discovery-whoami")
    version = PayloadVersion("s", "1.0.0", "payloads/s/1.0.0.json", document)
    other = {**document, "payload_external_id": "another-id", "payload_domains": []}
    assert PayloadVersion("s", "1.0.0", "payloads/s/1.0.0.json", other).digest() == version.digest()
    assert version.techniques == ("T1033",)
    assert version.identifier == document["payload_external_id"]
    assert version.name == "System Owner/User Discovery - whoami"


def test_a_version_file_has_the_hash_of_the_same_payload_embedded_in_a_scenario() -> None:
    stored = json.loads(
        (ROOT / "tests" / "golden" / "chaining" / "two-steps.normalised.json").read_text("utf-8")
    )
    embedded = next(embedded_payloads(stored))
    in_scenario = payload_hash(embedded.payload, embedded.attack_patterns, lambda _: None)
    file_hash = _version(_document()).digest()
    # The hand-built file differs from the embedded copy by its output parsers only.
    assert isinstance(embedded.payload, dict)
    copy_fields = copy.deepcopy(embedded.payload)
    copy_fields["payload_output_parsers"] = _document()["payload_output_parsers"]
    copy_hash = payload_hash(copy_fields, embedded.attack_patterns, lambda _: None)
    assert copy_hash.hex == file_hash
    assert in_scenario.hex != file_hash


def test_the_domains_change_no_hash() -> None:
    document = _document("system-owner-user-discovery-whoami")
    without = {key: value for key, value in document.items() if key != "payload_domains"}
    first = PayloadVersion("s", "1.0.0", "payloads/s/1.0.0.json", document).digest()
    second = PayloadVersion("s", "1.0.0", "payloads/s/1.0.0.json", without).digest()
    assert first == second


def test_an_id_that_is_not_the_one_its_content_has_is_refused() -> None:
    document = {**_document(), "payload_external_id": "not-its-id"}
    assert _findings(document) == [("PAY-003", "/payload_external_id", ID_NOT_ITS_CONTENT)]


def test_a_later_version_is_not_judged_by_the_id_of_its_content() -> None:
    # A later version carries its payload's ID, which the catalogue checks across versions.
    document = {**_document(), "payload_name": "Process Discovery - ps (1.1.0)"}
    assert _findings({**document, "payload_external_id": "the-payload-s-id"}, "1.1.0") == []


def test_a_version_listed_as_keeping_its_own_id_is_judged_by_its_content() -> None:
    document = {**_document(), "payload_name": "Process Discovery - ps (1.1.0)"}
    listed = {
        "payload": "process-discovery-ps",
        "version": "1.1.0",
        "sha256": _version(document, "1.1.0").digest(),
    }
    agreed = AgreedIds.from_document({"payloads": [], "own_ids": [listed]})
    found = _findings({**document, "payload_external_id": "not-its-id"}, "1.1.0", agreed)
    assert found == [("PAY-003", "/payload_external_id", ID_NOT_ITS_CONTENT)]


def test_the_id_the_registry_agrees_for_the_content_is_its_id() -> None:
    digest = _version(_document()).digest()
    agreed = AgreedIds.from_document(
        {"payloads": [{"id": "agreed-ps", "name": "Process Discovery - ps", "sha256": digest}]}
    )
    assert _findings({**_document(), "payload_external_id": "agreed-ps"}, agreed=agreed) == []
    assert _findings(_document(), agreed=agreed) == [
        ("PAY-003", "/payload_external_id", ID_NOT_ITS_CONTENT)
    ]


def test_the_registry_names_a_first_version_by_its_base_name() -> None:
    digest = _version(_document()).digest()
    agreed = AgreedIds.from_document(
        {"payloads": [{"id": "agreed-ps", "name": "Another name", "sha256": digest}]}
    )
    found = _findings({**_document(), "payload_external_id": "agreed-ps"}, agreed=agreed)
    assert found == [("PAY-003", "/payload_name", REGISTRY_OTHER_NAME)]


def test_a_first_version_with_a_version_in_its_name_is_refused() -> None:
    document = _with_id({**_document(), "payload_name": "Process Discovery - ps (1.0.0)"})
    assert _findings(document) == [("PAY-009", "/payload_name", NAME_SUFFIX_ON_FIRST)]


@pytest.mark.parametrize(
    "name",
    ["Process Discovery - ps", "Process Discovery - ps (1.2.0)", "Process Discovery - ps(1.1.0)"],
)
def test_a_later_version_without_its_own_version_in_its_name_is_refused(name: str) -> None:
    document = _with_id({**_document("process-discovery-ps", "1.1.0"), "payload_name": name})
    assert _findings(document, "1.1.0") == [("PAY-009", "/payload_name", NAME_NO_SUFFIX)]


@pytest.mark.parametrize("key", ["payload_attack_patterns", "payload_domains"])
def test_a_set_that_is_not_sorted_is_refused(key: str) -> None:
    document = _document("system-owner-user-discovery-whoami")
    document["payload_attack_patterns"] = ["T1033", "T1007"]
    document["payload_domains"] = sorted(
        document["payload_domains"], key=lambda d: d["domain_name"]
    )
    if key == "payload_domains":
        document["payload_attack_patterns"] = ["T1007", "T1033"]
        document["payload_domains"].reverse()
    found = version_findings(
        PayloadVersion("s", "1.0.0", "payloads/s/1.0.0.json", _with_id(document)),
        stored_form(_with_id(document)),
        NO_AGREED,
    )
    assert [(f.code, f.field, f.message) for f in found] == [("PAY-009", f"/{key}", SET_NOT_SORTED)]


@pytest.mark.parametrize(
    "data",
    [
        lambda d: json.dumps(d, indent=2).encode(),  # keys not sorted, no final newline
        lambda d: stored_form(d).replace(b"\n", b"\r\n"),
        lambda d: b"\xef\xbb\xbf" + stored_form(d),
        lambda d: stored_form(d).rstrip(b"\n"),
        lambda d: json.dumps(d, indent=4, sort_keys=True).encode() + b"\n",
    ],
)
def test_a_file_not_in_the_stored_form_is_refused(data: Any) -> None:
    document = _document()
    reordered = dict(reversed(list(document.items())))
    found = version_findings(_version(document), data(reordered), NO_AGREED)
    assert [(f.code, f.field, f.message) for f in found] == [("PAY-009", "", NOT_STORED_FORM)]


def test_a_payload_that_cannot_be_hashed_is_refused_once() -> None:
    document = {**_document(), "payload_platforms": ["Linux", "Linux"]}
    assert _findings(document) == [("PAY-009", "", NOT_HASHABLE)]


def test_findings_are_reported_at_the_file() -> None:
    document = {**_document(), "payload_external_id": "not-its-id"}
    (found,) = version_findings(_version(document), stored_form(document), NO_AGREED)
    assert found.path == PS


_INSTANCE = {
    "payload_id",
    "payload_external_id",
    "payload_source",
    "payload_status",
    "payload_collector_type",
    "payload_author_user",
    "payload_author_team",
    "payload_author_organization",
    "payload_tags",
    "payload_created_at",
    "payload_updated_at",
}


def _cleaned(value: Any) -> Any:
    """``value`` as a version file stores it: no identifier, tag or date of the instance at any
    depth, and no null or empty value."""
    if isinstance(value, dict):
        kept = {
            key: _cleaned(item)
            for key, item in value.items()
            if key not in _INSTANCE and not key.endswith(("_id", "_tags"))
        }
        return {key: item for key, item in kept.items() if item not in (None, "", [], {})}
    if isinstance(value, list):
        return [_cleaned(item) for item in value]
    return value


def _embedded_everywhere() -> list[Any]:
    found = []
    for name in (
        "chaining/two-steps.normalised.json",
        "normalised/salt-typhoon-cve-ttps-validation.json",
    ):
        stored = json.loads((ROOT / "tests" / "golden" / name).read_text("utf-8"))
        found += [
            e
            for e in embedded_payloads(stored)
            if isinstance(e.payload, dict) and e.payload.get("payload_type") == "Command"
        ]
    return found


@pytest.mark.parametrize("embedded", _embedded_everywhere(), ids=lambda e: e.pointer)
def test_a_version_file_has_the_hash_of_each_golden_payload_it_stores(embedded: Any) -> None:
    techniques = sorted(str(technique) for technique in embedded.attack_patterns)
    document = {**_cleaned(embedded.payload), "payload_attack_patterns": techniques}
    document["payload_external_id"] = "any"
    version = PayloadVersion("p", "1.0.0", "payloads/p/1.0.0.json", document)
    in_scenario = payload_hash(embedded.payload, embedded.attack_patterns, lambda _: None)
    assert version.digest() == in_scenario.hex
    with_domains = {**document, "payload_domains": [{"domain_color": "#000", "domain_name": "D"}]}
    assert PayloadVersion("p", "1.0.0", "p", with_domains).digest() == in_scenario.hex


def test_a_finding_on_a_version_file_blocks() -> None:
    document = {**_document(), "payload_external_id": "not-its-id"}
    (found,) = version_findings(_version(document), stored_form(document), NO_AGREED)
    assert found.severity.value == "blocking"


def test_a_version_that_would_attach_a_file_cannot_be_hashed() -> None:
    document = {**_document(), "payload_type": "Executable", "executable_file": "document"}
    document.pop("command_content")
    document.pop("command_executor")
    with pytest.raises(UnhashablePayloadError):
        _version(document).digest()


@pytest.mark.parametrize(
    ("change", "pointer"),
    [
        (lambda d: d.__setitem__("payload_platforms", ["MacOS", "Linux"]), "/payload_platforms"),
        (
            lambda d: d.__setitem__("payload_expectations", ["PREVENTION", "DETECTION"]),
            "/payload_expectations",
        ),
        (
            lambda d: d.__setitem__(
                "payload_expected_security_platforms", {"DETECTION": ["XDR", "EDR"]}
            ),
            "/payload_expected_security_platforms/DETECTION",
        ),
    ],
)
def test_every_set_of_text_is_stored_sorted(change: Any, pointer: str) -> None:
    document = _document()
    change(document)
    document = _with_id(document)
    assert _findings(document) == [("PAY-009", pointer, SET_NOT_SORTED)]


def test_sets_are_sorted_by_utf16_code_units_as_the_hash_sorts_them() -> None:
    # U+FF5E sorts after U+1F600 by code point, before it by UTF-16 code unit.
    document = _with_id({**_document(), "payload_platforms": ["\U0001f600", "\uff5e"]})
    assert _findings(document) == []


@pytest.mark.parametrize(
    ("key", "token"), [("DETECTION/EDR", "DETECTION~1EDR"), ("DETECTION~EDR", "DETECTION~0EDR")]
)
def test_a_key_of_the_security_platforms_is_escaped_in_its_pointer(key: str, token: str) -> None:
    document = _with_id(
        {**_document(), "payload_expected_security_platforms": {key: ["XDR", "EDR"]}}
    )
    assert _findings(document) == [
        ("PAY-009", f"/payload_expected_security_platforms/{token}", SET_NOT_SORTED)
    ]
