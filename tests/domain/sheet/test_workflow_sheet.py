"""The sheet of a scenario in chaining: its settings, then its steps in the order they can run,
each with what it waits for and what it runs, its commands shown as code, and the caveats a
reader needs before importing it."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scenario_tools.domain.policy.payloads import COMMAND_LIMIT
from scenario_tools.domain.sheet.markdown import block, code
from scenario_tools.domain.sheet.sheet import SHEET_LIMIT, render_sheet

ROOT = Path(__file__).resolve().parents[3]
STORED: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "two-steps.normalised.json").read_text("utf-8")
)
METADATA: dict[str, Any] = {
    "name": "Two steps",
    "description": "Lists the processes, then lists them again.",
    "version": "1.0.0",
    "status": "VERIFIED",
    "type": "chained",
    "requires": {"openaev": ">=3.261005.0", "edition": "EE", "injectors": ["openaev_implant"]},
}
CONTRACT, PAYLOAD = "inject_injector_contract", "injector_contract_payload"


def _sheet(stored: dict[str, Any] = STORED) -> str:
    return render_sheet(METADATA, stored, ())


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = document["scenario_workflow"]["workflow_steps"]
    return steps


def test_the_sheet_of_a_workflow_shows_its_steps_not_a_chain_of_injects() -> None:
    sheet = _sheet()
    assert "## Chain of injects" not in sheet
    assert sheet.index("## Workflow") < sheet.index("## Steps") < sheet.index("## Payloads")


def test_the_steps_come_in_the_order_they_can_run() -> None:
    sheet = _sheet()
    first = sheet.index("### 1\\. Step 1 \\- list processes")
    second = sheet.index("### 2\\. Step 2 \\- list processes again")
    assert first < second
    assert "- Starts when the scenario is launched." in sheet[first:second]
    assert "- Waits for: step 1." in sheet[second:]


def test_a_step_shows_its_injector_payload_and_command_as_code() -> None:
    sheet = _sheet()
    assert "- Injector: openaev\\_implant" in sheet
    assert "- Payload: Process Discovery \\- ps" in sheet
    assert "Command (sh):\n\n```\nps aux --no-headers\n```" in sheet


def test_a_step_shows_its_cleanup_prerequisites_and_effective_arguments() -> None:
    stored = copy.deepcopy(STORED)
    payload = _steps(stored)[0]["step_data"][CONTRACT][PAYLOAD]
    payload.update(
        command_content="ps #{options}",
        payload_cleanup_command="rm -f /tmp/x",
        payload_cleanup_executor="sh",
        payload_arguments=[{"key": "options", "type": "text", "default_value": "aux"}],
        payload_prerequisites=[
            {"executor": "sh", "get_command": "apt install procps", "check_command": "which ps"}
        ],
    )
    sheet = _sheet(stored)
    assert "Command (sh):\n\n```\nps aux\n```" in sheet  # the value it runs with
    assert "Cleanup (sh):\n\n```\nrm -f /tmp/x\n```" in sheet
    assert "Prerequisite check (sh):\n\n```\nwhich ps\n```" in sheet
    assert "Prerequisite install (sh):\n\n```\napt install procps\n```" in sheet
    assert "- Argument `options`: `aux`" in sheet


def test_the_settings_and_the_caveats_are_shown() -> None:
    sheet = _sheet()
    assert "- Each step times out after 1 h." in sheet
    assert "- Safe mode: on." in sheet
    assert "- Pace: none, each step starts as soon as it can." in sheet
    caveats = sheet[sheet.index("## Caveats") :]
    assert "OpenAEV does not enforce safe mode" in caveats
    assert "targets are set by the operator after import" in caveats


def test_the_payloads_of_the_steps_are_listed_once() -> None:
    payloads = _sheet()[_sheet().index("## Payloads") :]
    assert payloads.count("Process Discovery \\- ps") == 1


def test_the_sheet_is_the_same_whatever_the_order_of_the_steps_in_the_file() -> None:
    reordered = copy.deepcopy(STORED)
    _steps(reordered).reverse()
    assert _sheet(reordered) == _sheet()


@pytest.mark.parametrize(
    ("text", "fenced"),
    [
        ("ps aux", "```\nps aux\n```"),
        ("echo ```", "````\necho ```\n````"),
        ("a\nb", "```\na\nb\n```"),
    ],
)
def test_a_block_of_code_is_fenced_longer_than_any_run_of_backticks_in_it(
    text: str, fenced: str
) -> None:
    assert block(text) == fenced


def _with_payload(**changes: object) -> dict[str, Any]:
    stored = copy.deepcopy(STORED)
    payload = _steps(stored)[0]["step_data"][CONTRACT][PAYLOAD]
    payload.update(changes)
    return stored


def test_a_tab_in_a_command_is_shown_as_it_runs() -> None:
    assert "```\necho\tx\n```" in _sheet(_with_payload(command_content="echo\tx"))


def test_a_value_too_long_to_show_is_said_so() -> None:
    long = "x" * 70_000
    sheet = _sheet(
        _with_payload(
            command_content="echo #{value}",
            payload_arguments=[{"key": "value", "type": "text", "default_value": long}],
        )
    )
    assert long not in sheet
    assert (
        "Command (sh): too long to show, more than 65536 characters once its arguments are set."
        in sheet
    )
    assert "- Argument `value`: too long to show, more than 65536 characters." in sheet


def test_an_empty_value_is_said_so() -> None:
    sheet = _sheet(
        _with_payload(payload_arguments=[{"key": "value", "type": "text", "default_value": ""}])
    )
    assert "- Argument `value`: empty." in sheet


def test_a_value_on_several_lines_is_shown_as_a_block() -> None:
    sheet = _sheet(
        _with_payload(payload_arguments=[{"key": "value", "type": "text", "default_value": "a\nb"}])
    )
    assert "- Argument `value`:\n\n```\na\nb\n```" in sheet


def test_the_prerequisites_are_shown_with_the_values_they_run_with() -> None:
    sheet = _sheet(
        _with_payload(
            payload_arguments=[{"key": "tool", "type": "text", "default_value": "ps"}],
            payload_prerequisites=[{"executor": "sh", "check_command": "which #{tool}"}],
        )
    )
    assert "Prerequisite check (sh):\n\n```\nwhich ps\n```" in sheet


def test_a_dependency_on_no_step_of_the_scenario_is_said_so() -> None:
    stored = copy.deepcopy(STORED)
    waiting = next(step for step in _steps(stored) if step["step_conditions"])
    waiting["step_conditions"][0]["condition_value"] = "00000000-0000-4000-8000-0000000000aa"
    assert "- Waits for: a step the scenario does not have." in _sheet(stored)


def test_a_condition_the_sheet_cannot_read_is_said_so() -> None:
    stored = copy.deepcopy(STORED)
    waiting = next(step for step in _steps(stored) if step["step_conditions"])
    waiting["step_conditions"][0]["condition_type"] = "EQ"
    assert "- Holds a condition of type EQ, which the checks refuse for now." in _sheet(stored)


def test_each_caveat_has_its_own_line() -> None:
    caveats = _sheet()[_sheet().index("## Caveats") :]
    assert "- OpenAEV does not enforce safe mode" in caveats
    assert "- The limit of runs of a step is not enforced by OpenAEV" in caveats


def test_a_sheet_renders_whatever_the_shape_of_what_it_reads() -> None:
    # The checks refuse these; the sheet still renders, so that its own check can be reported.
    stored = _with_payload(payload_prerequisites=["not a prerequisite"], payload_arguments=["x"])
    without_payload = copy.deepcopy(_steps(stored)[1])
    without_payload["step_data"] = {"inject_title": "No payload"}
    without_payload["step_conditions"] = ["not a condition"]
    steps: list[Any] = _steps(stored)
    steps.extend(["not a step", without_payload])
    sheet = _sheet(stored)
    assert "\\. No payload\n" in sheet
    assert sheet.count("Prerequisite") == 0
    assert "- Argument" not in sheet


def test_the_sheet_of_the_hand_built_entry_is_the_reviewed_one() -> None:
    from tests.golden.test_chaining import SHEET, SHEET_METADATA

    assert render_sheet(SHEET_METADATA, STORED, ()) == SHEET.read_text(encoding="utf-8")


def test_settings_that_are_off_or_on_are_said_so() -> None:
    stored = copy.deepcopy(STORED)
    stored["scenario_workflow"].update(
        workflow_timeout_enabled=False,
        workflow_safe_mode_enabled=False,
        workflow_rate_limit_enabled=True,
        workflow_max_attempts=3,
        workflow_max_temporal_rate_seconds=120,
    )
    sheet = _sheet(stored)
    assert "- No step times out.\n- Safe mode: off.\n- Pace: at most 3 attempts per 2 min." in sheet
    assert "Safe mode is on" not in sheet


def _chain(*steps: tuple[str, str, list[str]]) -> dict[str, Any]:
    """A stored scenario of steps, each an identifier, a title and the steps it waits for."""
    template = _steps(STORED)[0]
    stored = copy.deepcopy(STORED)
    built = []
    for identifier, title, awaited in steps:
        step = copy.deepcopy(template)
        step["step_id"] = identifier
        step["step_data"]["inject_title"] = title
        step["step_conditions"] = [
            {"condition_type": "DEPEND_ON", "condition_value": name} for name in awaited
        ]
        built.append(step)
    stored["scenario_workflow"]["workflow_steps"] = built
    return stored


def _titles(sheet: str) -> list[str]:
    return [line.split(" ", 2)[2] for line in sheet.splitlines() if line.startswith("### ")]


def test_steps_come_after_those_they_wait_for_whatever_their_identifiers() -> None:
    stored = _chain(
        ("0", "Loops", ["0"]),
        ("a", "Third", ["b"]),
        ("b", "Second", ["c"]),
        ("c", "First", []),
        ("d", "Also second", ["c"]),
    )
    assert _titles(_sheet(stored)) == ["First", "Second", "Also second", "Third", "Loops"]


def test_a_step_that_waits_for_two_steps_names_both() -> None:
    stored = _chain(("a", "One", []), ("b", "Two", []), ("c", "Three", ["b", "a"]))
    assert "- Waits for: step 1, step 2." in _sheet(stored)


def test_a_step_without_an_identifier_is_waited_for_by_none() -> None:
    stored = _chain(("", "Unnamed", []), ("b", "Waits", [""]))
    assert "- Waits for: a step the scenario does not have." in _sheet(stored)


def test_lists_of_another_shape_and_odd_items_are_skipped() -> None:
    sheet = _sheet(_with_payload(payload_prerequisites=5, payload_arguments=5))
    assert "Prerequisite" not in sheet
    assert "- Argument" not in sheet
    sheet = _sheet(
        _with_payload(
            payload_prerequisites=["x", {"executor": "sh", "check_command": "true"}],
            payload_arguments=["x", {"key": "k", "type": "text", "default_value": "v"}],
        )
    )
    assert "Prerequisite check (sh):\n\n```\ntrue\n```" in sheet
    assert "- Argument `k`: `v`" in sheet


def test_a_value_with_a_carriage_return_is_shown_as_a_block() -> None:
    sheet = _sheet(
        _with_payload(payload_arguments=[{"key": "v", "type": "text", "default_value": "a\rb"}])
    )
    assert "- Argument `v`:\n\n```\na\nb\n```" in sheet


def test_a_step_whose_inject_is_not_an_object_still_renders() -> None:
    stored = copy.deepcopy(STORED)
    _steps(stored)[0]["step_data"] = "text"
    assert "\\. —\n" in _sheet(stored)


@pytest.mark.parametrize(
    ("text", "fenced"),
    [("ab ", "```\nab \n```"), ("\nab", "```\n\nab\n```"), ("aX", "```\naX\n```")],
)
def test_a_block_keeps_its_text_but_the_last_line_breaks(text: str, fenced: str) -> None:
    assert block(text) == fenced


def test_a_span_is_one_line_and_shows_its_tabs() -> None:
    assert code("a\nb") == "`a b`"
    assert code("a\tb") == "`aU+0009b`"


def test_steps_ready_together_come_by_identifier_not_by_place_in_the_file() -> None:
    stored = _chain(("b", "Second by identifier", []), ("a", "First by identifier", []))
    assert _titles(_sheet(stored)) == ["First by identifier", "Second by identifier"]


def test_a_value_too_long_is_never_expanded_to_be_measured() -> None:
    huge = "x" * 1_000_000
    sheet = _sheet(
        _with_payload(
            command_content=" ".join(["#{value}"] * 10_000),
            payload_arguments=[{"key": "value", "type": "text", "default_value": huge}],
        )
    )
    assert (
        "Command (sh): too long to show, more than 65536 characters once its arguments are set."
        in sheet
    )
    assert "- Argument `value`: too long to show, more than 65536 characters." in sheet


def test_a_span_keeps_the_spaces_around_a_value() -> None:
    assert code(" value ") == "`  value  `"
    assert code(" ") == "` `"


def test_the_targets_of_a_workflow_are_set_after_import() -> None:
    targets = _sheet()[_sheet().index("## Targets to fill in") :]
    assert targets.startswith(
        "## Targets to fill in\n\nSet by the operator after import, on the platform that runs it: "
        "the scenario names no target of its own."
    )


def test_the_steps_waiting_for_a_step_are_freed_once_whatever_the_steps_of_its_identifier() -> None:
    stored = _chain(
        ("a", "First a", []),
        ("a", "Second a", []),
        ("b", "B", []),
        ("e", "Waits for a", ["a"]),
        ("c", "Waits for b", ["b"]),
        ("x", "Waits for e", ["e"]),
    )
    assert _titles(_sheet(stored)) == [
        "First a",
        "Second a",
        "B",
        "Waits for b",
        "Waits for a",
        "Waits for e",
    ]


def _described(size: int) -> str:
    """The sheet whose description makes what comes up to it ``size`` characters long, the
    separators aside."""
    probe = render_sheet({**METADATA, "description": "x"}, STORED, ())
    before = len(probe[: probe.index("x\n\n## At a glance")]) - len("\n\n") * 3
    return render_sheet({**METADATA, "description": "x" * (size - before)}, STORED, ())


def test_a_sheet_is_built_up_to_its_limit_and_no_further() -> None:
    at_limit = _described(SHEET_LIMIT)
    assert at_limit.endswith("\n\n## At a glance\n")  # the part that goes past it, then none
    beyond = _described(SHEET_LIMIT + 1)
    assert "## At a glance" not in beyond
    assert len(beyond) > SHEET_LIMIT  # still past the limit, so refused as too long


def test_values_repeated_across_commands_never_build_a_sheet_far_past_its_limit() -> None:
    value = "v" * (COMMAND_LIMIT - 100)
    sheet = _sheet(
        _with_payload(
            payload_prerequisites=[{"executor": "sh", "check_command": "#{k}"}] * 100,
            payload_arguments=[{"key": "k", "type": "text", "default_value": value}],
        )
    )
    assert SHEET_LIMIT < len(sheet) < SHEET_LIMIT + 2 * COMMAND_LIMIT
