"""Vendor-neutral payloads and privileges for the reviewer: a payload never names a security
product, and one that asks for elevated privileges is pointed out."""

from typing import Any

import pytest

from scenario_tools.domain.policy.registry import policy_findings
from scenario_tools.domain.policy.rules.elevation import RULE as ELEVATION_RULE
from scenario_tools.domain.policy.rules.vendors import RULE as VENDOR_RULE
from scenario_tools.domain.policy.vendors import vendors_from_document
from scenario_tools.domain.shared.finding import Finding, Severity
from tests.domain.policy.cases import DATA, ENTRY, PAYLOAD, VENDORS, with_payload

JSON = f"{ENTRY}/scenario.json"
VENDOR_MESSAGE = (
    "this text names a security product: a shared scenario stays vendor-neutral; describe the "
    "behaviour instead"
)


def _found(findings: tuple[Finding, ...], code: str) -> list[str]:
    return [f.field for f in findings if f.code == code]


def test_the_rules_are_pol_006_blocking_and_pol_007_informative() -> None:
    assert (VENDOR_RULE.code, VENDOR_RULE.severity) == ("POL-006", Severity.BLOCKING)
    assert (ELEVATION_RULE.code, ELEVATION_RULE.severity) == ("POL-007", Severity.INFO)


def test_the_list_is_read() -> None:
    pattern = vendors_from_document(VENDORS)

    assert pattern.search("x crowdstrike y")
    assert pattern.search("carbon_black")
    assert pattern.search("crowdstrikefalcon")  # a product's name fused to another word
    assert pattern.search("x eset y")
    assert not pattern.search("reset")  # a short name only as a whole word


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "vendor-names: the document must be a mapping holding products and words"),
        (
            {"products": "x", "words": []},
            "vendor-names: the document must be a mapping holding products and words",
        ),
        (
            {"products": ["x"]},
            "vendor-names: the document must be a mapping holding products and words",
        ),
        ({"products": [], "words": [], "x": 1, "a": 2}, "vendor-names: unknown keys a, x"),
        ({"products": [], "words": []}, "vendor-names: products must name at least one product"),
        ({"products": ["x"], "words": ["x"]}, "vendor-names: each product once"),
        (
            {"products": ["x"], "words": ["a b c d e f"]},
            "vendor-names: a product must be a name in lower case",
        ),
        ({"products": [1], "words": []}, "vendor-names: a product must be a name in lower case"),
        (
            {"products": ["Sophos"], "words": []},
            "vendor-names: a product must be a name in lower case",
        ),
        (
            {"products": ["a(b"], "words": []},
            "vendor-names: a product must be a name in lower case",
        ),
        ({"products": [" x"], "words": []}, "vendor-names: a product must be a name in lower case"),
        (
            {"products": ["x" * 101], "words": []},
            "vendor-names: a product must be a name in lower case",
        ),
        ({"products": ["x", "x"], "words": []}, "vendor-names: each product once"),
    ],
)
def test_a_malformed_list_is_refused(document: object, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        vendors_from_document(document)


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({"command_content": "sc query CrowdStrike"}, "/command_content"),
        ({"command_content": "Get-Service | ? Name -match 'Carbon Black'"}, "/command_content"),
        ({"command_content": "x carbon-black y"}, "/command_content"),
        ({"command_content": "sc query CarbonBlack"}, "/command_content"),  # words joined
        ({"command_content": "Get-Service CrowdStrikeFalcon"}, "/command_content"),  # fused
        ({"command_content": "echo crowdstrike's agent"}, "/command_content"),
        ({"command_content": "Stop-Service Sentinel-One"}, "/command_content"),
        ({"command_content": "dir C:\\ESET\\x"}, "/command_content"),  # a short name, whole
        ({"payload_cleanup_command": "echo trend micro"}, "/payload_cleanup_command"),
        ({"payload_name": "Disable CrowdStrike sensor"}, "/payload_name"),
        (
            {"payload_arguments": [{"key": "p", "default_value": "CROWDSTRIKE"}]},
            "/payload_arguments/0/default_value",
        ),
        (
            {
                "command_content": "echo #{p}",
                "payload_arguments": [{"key": "p", "default_value": "Cr^owdStrike"}],
            },
            "/command_content",
        ),
        (
            {"payload_output_parsers": [{"rules": [{"name": "CrowdStrike agents"}]}]},
            "/payload_output_parsers/0/rules/0/name",
        ),
    ],
)
def test_a_payload_naming_a_security_product_is_refused(
    payload: dict[str, Any], field: str
) -> None:
    findings = policy_findings(DATA, with_payload(**payload))

    vendors = [f for f in findings if f.code == "POL-006"]
    assert PAYLOAD + field in [f.field for f in vendors]
    assert all(
        (f.severity, f.path, f.message) == (Severity.BLOCKING, JSON, VENDOR_MESSAGE)
        for f in vendors
    )


@pytest.mark.parametrize(
    "command",
    [
        "whoami",
        "Get-MpPreference",  # a component built into the system
        "reset the password",  # a short name inside a word
        "titanium",
    ],
)
def test_vendor_neutral_commands_pass(command: str) -> None:
    findings = policy_findings(DATA, with_payload(command_content=command))

    assert _found(findings, "POL-006") == []


def test_a_payload_asking_for_elevated_privileges_is_pointed_out() -> None:
    (finding,) = (
        f
        for f in policy_findings(DATA, with_payload(payload_elevation_required=True))
        if f.code == "POL-007"
    )

    assert (finding.severity, finding.path, finding.field, finding.message) == (
        Severity.INFO,
        JSON,
        PAYLOAD + "/payload_elevation_required",
        "this payload asks for elevated privileges: check why it needs them",
    )


@pytest.mark.parametrize("value", [False, None, "true", 1])
def test_only_an_explicit_request_for_privileges_is_pointed_out(value: object) -> None:
    findings = policy_findings(DATA, with_payload(payload_elevation_required=value))

    assert _found(findings, "POL-007") == []


def test_a_name_of_100_characters_with_five_words_is_allowed() -> None:
    name = " ".join(["a" * 19] * 5)  # 99 characters

    assert vendors_from_document({"products": [name], "words": []}).search(name)


def test_every_field_of_a_vendor_neutral_payload_passes() -> None:
    payload = with_payload(
        command_content="whoami",
        payload_cleanup_command="del x",
        payload_name="Discovery",
        payload_output_parsers=[{"rules": [{"name": "usernames"}]}],
        payload_arguments=[{"key": "x", "default_value": "y"}],
    )

    assert _found(policy_findings(DATA, payload), "POL-006") == []


def test_a_name_of_100_characters_is_allowed() -> None:
    name = "a" * 100

    assert vendors_from_document({"products": [name], "words": []}).search(name)
