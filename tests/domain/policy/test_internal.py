"""Spacing and internal data: the injects that run on an endpoint are spaced out, and a shared
scenario holds no user, team member, variable value or e-mail address of a real domain."""

from typing import Any

import pytest

from scenario_tools.domain.policy.registry import policy_findings
from scenario_tools.domain.policy.rules.internal import RULE as INTERNAL_RULE
from scenario_tools.domain.policy.rules.spacing import RULE as SPACING_RULE
from scenario_tools.domain.shared.finding import Finding, Severity
from tests.domain.policy.cases import DATA, ENTRY, METADATA, content, timed

JSON = f"{ENTRY}/scenario.json"
EMAIL = (
    "this value holds an e-mail address outside the example domains: use one such as "
    "user@example.com"
)


def _found(findings: tuple[Finding, ...], code: str) -> list[tuple[str, Severity]]:
    return [(f.field, f.severity) for f in findings if f.code == code]


def test_the_rules_are_pol_009_and_pol_010_and_block() -> None:
    assert (SPACING_RULE.code, SPACING_RULE.severity) == ("POL-009", Severity.BLOCKING)
    assert (INTERNAL_RULE.code, INTERNAL_RULE.severity) == ("POL-010", Severity.BLOCKING)


def _offset(index: int) -> str:
    return f"/scenario_injects/{index}/inject_depends_duration"


def test_injects_closer_than_60_seconds_are_refused() -> None:
    (finding,) = (
        f for f in policy_findings(DATA, timed((0, True), (59, True))) if f.code == "POL-009"
    )

    assert (finding.severity, finding.path, finding.field, finding.message) == (
        Severity.BLOCKING,
        JSON,
        _offset(1),
        "this inject starts 59 seconds after the previous one that runs on the endpoint: space "
        "them by at least 60 seconds",
    )


def test_injects_are_ordered_by_their_offset_and_the_same_offset_is_0_seconds() -> None:
    findings = policy_findings(DATA, timed((120, True), (0, True), (120, True)))

    assert _found(findings, "POL-009") == [(_offset(2), Severity.BLOCKING)]


@pytest.mark.parametrize(
    "injects",
    [
        ((0, True), (60, True)),
        ((0, True), (10, False), (60, True)),  # an inject without payload runs on no endpoint
        ((0, False), (5, False)),
        ((0, True),),
        (),
    ],
)
def test_spaced_or_platform_injects_pass(injects: tuple[tuple[int, bool], ...]) -> None:
    assert _found(policy_findings(DATA, timed(*injects)), "POL-009") == []


def test_a_chained_scenario_is_not_timed() -> None:
    assert (
        _found(policy_findings(DATA, timed((0, True), (5, True), kind="chained")), "POL-009") == []
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"payload_type": "Executable"},
        {"payload_type": "FileDrop"},
        {"payload_prerequisites": [{"get_command": "x"}]},
    ],
)
def test_a_heavy_payload_between_60_and_120_seconds_is_pointed_out(
    payload: dict[str, Any],
) -> None:
    findings = policy_findings(DATA, timed((0, True), (90, True), **payload))

    assert _found(findings, "POL-009") == [(_offset(1), Severity.INFO)]
    assert [f.message for f in findings if f.code == "POL-009"] == [
        "this inject starts 90 seconds after the previous one that runs on the endpoint: space "
        "them by at least 120 seconds"
    ]


def test_a_heavy_payload_under_60_seconds_is_refused() -> None:
    findings = policy_findings(DATA, timed((0, True), (30, True), payload_type="Executable"))

    assert _found(findings, "POL-009") == [(_offset(1), Severity.BLOCKING)]
    assert [f.message for f in findings if f.code == "POL-009"] == [
        "this inject starts 30 seconds after the previous one that runs on the endpoint: space "
        "them by at least 60 seconds"
    ]


@pytest.mark.parametrize("offset", ["60", 30.0, True, None, [60], "absent"])
def test_a_payload_inject_without_a_whole_number_of_seconds_is_refused(offset: object) -> None:
    inject: dict[str, Any] = {
        "inject_injector_contract": {"injector_contract_payload": {"command_content": "x"}}
    }
    if offset != "absent":
        inject["inject_depends_duration"] = offset
    entry = content(
        declared={**METADATA, "type": "time-based"}, stored={"scenario_injects": [inject]}
    )

    (finding,) = (f for f in policy_findings(DATA, entry) if f.code == "POL-009")
    assert (finding.severity, finding.field) == (Severity.BLOCKING, _offset(0))
    assert "a whole number of seconds" in finding.message


@pytest.mark.parametrize("offset", [120, 200])
def test_a_heavy_payload_from_120_seconds_passes(offset: int) -> None:
    findings = policy_findings(DATA, timed((0, True), (offset, True), payload_type="Executable"))

    assert _found(findings, "POL-009") == []


@pytest.mark.parametrize(
    "stored",
    [
        None,
        {"scenario_injects": "x"},
        {
            "scenario_injects": [
                "x",
                {"inject_depends_duration": "60"},
                {"inject_depends_duration": True},
            ]
        },
    ],
)
def test_odd_shapes_are_left_to_their_own_checks(stored: object) -> None:
    entry = content(declared={**METADATA, "type": "time-based"}, stored=stored)

    assert _found(policy_findings(DATA, entry), "POL-009") == []


@pytest.mark.parametrize("declared", [None, {"type": 1}, {}])
def test_a_scenario_whose_kind_is_unknown_is_not_timed(declared: object) -> None:
    entry = timed((0, True), (5, True))
    unknown = content(declared=declared, stored=entry.stored)

    assert _found(policy_findings(DATA, unknown), "POL-009") == []


@pytest.mark.parametrize(
    ("stored", "field"),
    [
        (
            {"scenario_information": {"scenario_mail_from": "a@corp.com"}},
            "/scenario_information/scenario_mail_from",
        ),
        (
            {"scenario_injects": [{"inject_content": {"body": "Write to it@corp.example.net.fr"}}]},
            "/scenario_injects/0/inject_content/body",
        ),
        (
            {"scenario_articles": [{"article_content": "Ask J.Doe@Corp.COM now"}]},
            "/scenario_articles/0/article_content",
        ),
        ({"y": "a@b.c.d.e.f.g.h.example.com.evil.com"}, "/y"),  # deep domain, a real tail
        ({"z": "clone git@github.com:x/y"}, "/z"),  # a real domain, even in a git URL
    ],
)
def test_an_e_mail_address_outside_the_example_domains_is_refused(
    stored: dict[str, Any], field: str
) -> None:
    findings = policy_findings(DATA, content(stored=stored))

    (finding,) = (f for f in findings if f.code == "POL-010")
    assert (finding.severity, finding.path, finding.field, finding.message) == (
        Severity.BLOCKING,
        JSON,
        field,
        EMAIL,
    )


@pytest.mark.parametrize(
    "text",
    [
        "simulation@example.org",
        "a@www.example.com and b@host.test",
        "no address here, nor @ alone, nor a@b",
        "#{user.email}",
        "install lodash@4.17.21",  # a version, not an e-mail
        "1.2@3.4",
        "ssh user@10.0.0.5",  # no alphabetic top-level name
    ],
)
def test_example_addresses_and_no_address_pass(text: str) -> None:
    findings = policy_findings(DATA, content(stored={"x": text}))

    assert _found(findings, "POL-010") == []


@pytest.mark.parametrize(
    ("stored", "field", "message"),
    [
        ({"scenario_users": [{"user_id": "1"}]}, "/scenario_users", "the scenario holds users"),
        (
            {"scenario_teams": [{"team_name": "a", "team_users": ["1"]}]},
            "/scenario_teams/0/team_users",
            "this team holds members",
        ),
        (
            {"scenario_variables": [{"variable_key": "k", "variable_value": "v"}]},
            "/scenario_variables/0/variable_value",
            "this variable holds a value",
        ),
    ],
)
def test_users_team_members_and_variable_values_are_refused(
    stored: dict[str, Any], field: str, message: str
) -> None:
    (finding,) = (f for f in policy_findings(DATA, content(stored=stored)) if f.code == "POL-010")

    assert (finding.field, finding.message) == (
        field,
        f"{message}: normalise the export again, which removes them",
    )


@pytest.mark.parametrize(
    "stored",
    [
        {
            "scenario_users": [],
            "scenario_teams": [{"team_users": []}, "x"],
            "scenario_variables": [{"variable_value": None}, {"variable_value": ""}, "x"],
        },
        {"scenario_users": None, "scenario_teams": None, "scenario_variables": None},
        None,
    ],
)
def test_empty_users_members_and_values_pass(stored: object) -> None:
    assert _found(policy_findings(DATA, content(stored=stored)), "POL-010") == []


def test_a_value_is_reported_once_whatever_it_holds() -> None:
    findings = policy_findings(DATA, content(stored={"x": "a@corp.com b@corp.org"}))

    assert _found(findings, "POL-010") == [("/x", Severity.BLOCKING)]


def test_an_invisible_character_inside_a_domain_is_folded_away() -> None:
    # A zero-width space inside the domain: dropped, so the address is read and refused.
    findings = policy_findings(DATA, content(stored={"x": "a@cor" + chr(0x200B) + "p.com"}))

    assert _found(findings, "POL-010") == [("/x", Severity.BLOCKING)]


def test_an_address_hidden_by_a_compatibility_form_is_folded_and_refused() -> None:
    # A fullwidth "@" folds to "@": the address is read.
    findings = policy_findings(DATA, content(stored={"x": "admin" + chr(0xFF20) + "corp.com"}))

    assert _found(findings, "POL-010") == [("/x", Severity.BLOCKING)]


def test_a_second_team_is_read_after_a_first_without_members() -> None:
    stored = {
        "scenario_teams": [
            {"team_name": "a", "team_users": []},
            {"team_name": "b", "team_users": ["1"]},
        ]
    }

    assert _found(policy_findings(DATA, content(stored=stored)), "POL-010") == [
        ("/scenario_teams/1/team_users", Severity.BLOCKING)
    ]


def test_an_inject_without_a_contract_is_not_an_endpoint_inject() -> None:
    # An inject with no contract runs on the platform: it never makes a pair with POL-009.
    stored = {
        "scenario_injects": [
            {
                "inject_depends_duration": 0,
                "inject_injector_contract": {"injector_contract_payload": {"x": 1}},
            },
            {"inject_depends_duration": 5},
            {
                "inject_depends_duration": 10,
                "inject_injector_contract": {"injector_contract_payload": {"x": 1}},
            },
        ]
    }
    entry = content(declared={**METADATA, "type": "time-based"}, stored=stored)

    assert _found(policy_findings(DATA, entry), "POL-009") == [(_offset(2), Severity.BLOCKING)]


def test_two_values_each_with_an_address_are_both_reported() -> None:
    findings = policy_findings(DATA, content(stored={"a": "x@corp.com", "b": "y@corp.org"}))

    assert _found(findings, "POL-010") == [("/a", Severity.BLOCKING), ("/b", Severity.BLOCKING)]


def test_a_bad_offset_does_not_stop_the_spacing_of_the_rest() -> None:
    stored = {
        "scenario_injects": [
            {
                "inject_depends_duration": "x",
                "inject_injector_contract": {"injector_contract_payload": {"x": 1}},
            },
            {
                "inject_depends_duration": 0,
                "inject_injector_contract": {"injector_contract_payload": {"x": 1}},
            },
            {
                "inject_depends_duration": 10,
                "inject_injector_contract": {"injector_contract_payload": {"x": 1}},
            },
        ]
    }
    entry = content(declared={**METADATA, "type": "time-based"}, stored=stored)

    assert _found(policy_findings(DATA, entry), "POL-009") == [
        (_offset(0), Severity.BLOCKING),  # the bad offset
        (_offset(2), Severity.BLOCKING),  # 0 and 10 are 10 seconds apart
    ]


def test_a_part_that_is_not_a_list_does_not_stop_the_later_parts() -> None:
    stored = {
        "scenario_users": "not a list",
        "scenario_variables": [{"variable_key": "k", "variable_value": "v"}],
    }

    assert _found(policy_findings(DATA, content(stored=stored)), "POL-010") == [
        ("/scenario_variables/0/variable_value", Severity.BLOCKING)
    ]


def test_a_payload_that_is_not_a_mapping_is_no_payload() -> None:
    stored = {
        "scenario_injects": [
            {
                "inject_depends_duration": 0,
                "inject_injector_contract": {"injector_contract_payload": "x"},
            },
            {
                "inject_depends_duration": 5,
                "inject_injector_contract": {"injector_contract_payload": {"x": 1}},
            },
        ]
    }
    entry = content(declared={**METADATA, "type": "time-based"}, stored=stored)

    # The first inject has no real payload, so there is no pair closer than 60 seconds.
    assert _found(policy_findings(DATA, entry), "POL-009") == []


def test_users_and_a_later_variable_value_are_both_reported() -> None:
    stored = {
        "scenario_users": [{"user_id": "1"}],
        "scenario_variables": [{"variable_key": "k", "variable_value": "v"}],
    }

    assert _found(policy_findings(DATA, content(stored=stored)), "POL-010") == [
        ("/scenario_users", Severity.BLOCKING),
        ("/scenario_variables/0/variable_value", Severity.BLOCKING),
    ]


def test_a_non_mapping_inject_before_a_close_pair_does_not_hide_it() -> None:
    stored = {
        "scenario_injects": [
            "x",
            {
                "inject_depends_duration": 0,
                "inject_injector_contract": {"injector_contract_payload": {"a": 1}},
            },
            {
                "inject_depends_duration": 30,
                "inject_injector_contract": {"injector_contract_payload": {"a": 1}},
            },
        ]
    }
    entry = content(declared={**METADATA, "type": "time-based"}, stored=stored)

    assert _found(policy_findings(DATA, entry), "POL-009") == [(_offset(2), Severity.BLOCKING)]
