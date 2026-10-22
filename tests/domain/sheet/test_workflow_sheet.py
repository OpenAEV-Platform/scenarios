"""The sheet of a scenario in chaining: its settings, then its steps in the order they can run,
each with what it waits for and what it runs, its commands shown as code, and the caveats a
reader needs before importing it."""

import copy
import json
import time
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
    waiting["step_conditions"][0]["condition_type"] = "SOMETHING"
    assert (
        "- Runs only if:\n  - A condition of type `SOMETHING`, which this sheet does not describe."
        in _sheet(stored)
    )


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


@pytest.mark.parametrize("key", ["value}suffix", "k" * 201])
@pytest.mark.parametrize(
    ("default", "shown"),
    [
        ("actual value", "`actual value`"),
        ("", "empty."),
        ("x" * (COMMAND_LIMIT + 1), f"too long to show, more than {COMMAND_LIMIT} characters."),
    ],
)
def test_an_argument_no_command_can_name_still_shows_its_value(
    key: str, default: str, shown: str
) -> None:
    sheet = _sheet(
        _with_payload(payload_arguments=[{"key": key, "type": "text", "default_value": default}])
    )
    assert f"- Argument {code(key)}: {shown}" in sheet


def test_an_argument_without_a_value_shows_its_placeholder() -> None:
    sheet = _sheet(_with_payload(payload_arguments=[{"key": "k", "type": "text"}]))
    assert "- Argument `k`: `#{k}`" in sheet


def test_a_value_as_long_as_the_limit_is_shown() -> None:
    value = "x" * COMMAND_LIMIT
    sheet = _sheet(
        _with_payload(payload_arguments=[{"key": "k", "type": "text", "default_value": value}])
    )
    assert f"- Argument `k`: `{value}`" in sheet


# Filters and AND / OR, in plain words

FILTERED: dict[str, Any] = json.loads(
    (ROOT / "tests" / "golden" / "chaining" / "filters.normalised.json").read_text("utf-8")
)


def _filtered_step(*conditions: dict[str, Any]) -> dict[str, Any]:
    stored = copy.deepcopy(STORED)
    _steps(stored)[1]["step_conditions"] = list(conditions)
    return stored


def _filter(
    identifier: str, kind: object, parent: str | None = None, **fields: Any
) -> dict[str, Any]:
    return {
        "condition_id": identifier,
        "condition_type": kind,
        "condition_parent_id": parent,
        "condition_is_root": parent is None,
        **fields,
    }


def test_a_tree_of_filters_is_said_in_plain_words_nested_as_it_is() -> None:
    sheet = _sheet(FILTERED)
    assert (
        "- Runs only if:\n"
        "  - All of:\n"
        "    - Any of:\n"
        "      - `pid` has a value.\n"
        "      - `user` contains one of: `root`, `admin`.\n"
        "    - `process` is `sshd`.\n"
    ) in sheet
    assert "does not describe" not in sheet


@pytest.mark.parametrize(
    ("kind", "value", "said"),
    [
        ("EQ", "a", "- `k` is `a`."),
        ("NEQ", "a", "- `k` is not `a`."),
        ("GT", "3", "- `k` is greater than `3`."),
        ("GTE", "3", "- `k` is at least `3`."),
        ("LT", "3", "- `k` is less than `3`."),
        ("LTE", "3", "- `k` is at most `3`."),
        ("IN", " a, ,b ", "- `k` contains one of: `a`, `b`."),
        ("NIN", "a", "- `k` contains none of: `a`."),
        ("IS_NULL", None, "- `k` has no value."),
        ("IS_NOT_NULL", None, "- `k` has a value."),
        ("EQ", None, "- `k` is no value."),
        ("EQ", "", "- `k` is an empty text."),
    ],
)
def test_each_filter_is_said_in_plain_words(kind: str, value: object, said: str) -> None:
    stored = _filtered_step(_filter("c1", kind, condition_key="k", condition_value=value))
    assert f"- Runs only if:\n  {said}" in _sheet(stored)


def test_a_filter_without_a_key_says_so() -> None:
    stored = _filtered_step(_filter("c1", "EQ", condition_value="a"))
    assert "- Runs only if:\n  - a value with no key is `a`." in _sheet(stored)


@pytest.mark.parametrize(("kind", "said"), [("AND", "All of:"), ("OR", "Any of:")])
def test_a_group_lists_its_conditions_below_it(kind: str, said: str) -> None:
    stored = _filtered_step(
        _filter("c1", kind),
        _filter("c2", "EQ", "c1", condition_key="k", condition_value="a"),
        _filter("c2", "EQ", "c1", condition_key="k", condition_value="a"),  # a copy, said once
    )
    sheet = _sheet(stored)
    assert f"- Runs only if:\n  - {said}\n    - `k` is `a`.\n" in sheet
    assert sheet.count("`k` is `a`.") == 1


def test_a_condition_the_sheet_cannot_say_is_named_by_its_type() -> None:
    stored = _filtered_step(_filter("c1", "SOMETHING"))
    assert "  - A condition of type `SOMETHING`, which this sheet does not describe." in _sheet(
        stored
    )


def test_conditions_that_loop_are_all_said() -> None:
    looping = _filtered_step(
        _filter("c1", "AND", "c2"), _filter("c2", "OR", "c1"), _filter("c3", "EQ", "c3")
    )
    sheet = _sheet(looping)
    step = sheet.split("### 2")[1]
    assert "Starts when the scenario is launched" not in step
    assert "All of:" in step
    assert "Any of:" in step
    assert "- `k` is" not in step  # c3 has no key
    assert "a value with no key is no value." in step


def test_a_branch_beyond_the_depth_the_sheet_reads_is_said_to_be_cut() -> None:
    deep = [_filter("c0", "AND")] + [_filter(f"c{i}", "AND", f"c{i - 1}") for i in range(1, 40)]
    sheet = _sheet(_filtered_step(*deep))
    assert sheet.count("All of:") == 17
    assert sheet.count("- More conditions below, not shown.") == 1


def test_a_condition_whose_parent_the_step_lacks_is_said_at_the_root() -> None:
    stored = _filtered_step(
        _filter("c1", "EQ", "elsewhere", condition_key="k", condition_value="a")
    )
    assert "- Runs only if:\n  - `k` is `a`." in _sheet(stored)


def test_the_comparison_caveats_come_with_a_filter_only() -> None:
    caveats = _sheet(FILTERED).split("## Caveats")[1]
    assert "- Comparisons are case-sensitive" in caveats
    assert "- `IN` and `NIN` compare by substring" in caveats
    assert "case-sensitive" not in _sheet().split("## Caveats")[1]
    groups_only = _filtered_step(_filter("c1", "AND"))
    assert "case-sensitive" not in _sheet(groups_only).split("## Caveats")[1]


def test_a_step_that_waits_and_filters_says_both() -> None:
    stored = copy.deepcopy(STORED)
    waiting = next(step for step in _steps(stored) if step["step_conditions"])
    waiting["step_conditions"].append(_filter("c9", "EQ", condition_key="k", condition_value="a"))
    sheet = _sheet(stored)
    assert "- Waits for: step 1.\n- Runs only if:\n  - `k` is `a`." in sheet


def test_copies_of_a_condition_that_differ_are_each_said() -> None:
    stored = _filtered_step(
        _filter("c1", "EQ", condition_key="k", condition_value="a"),
        _filter("c1", "NEQ", condition_key="z", condition_value="b"),
    )
    sheet = _sheet(stored)
    assert "- `k` is `a`." in sheet
    assert "- `z` is not `b`." in sheet


@pytest.mark.parametrize("value", [None, 5, ["s1"]])
def test_a_dependency_the_sheet_cannot_read_is_said_not_dropped(value: object) -> None:
    stored = _filtered_step(_filter("c1", "DEPEND_ON", condition_value=value))
    step = _sheet(stored).split("### 2")[1]
    assert "Starts when the scenario is launched" not in step
    assert "A condition of type `DEPEND_ON`, which this sheet does not describe." in step


def test_a_dependency_holding_a_condition_says_both() -> None:
    stored = copy.deepcopy(STORED)
    waiting = next(step for step in _steps(stored) if step["step_conditions"])
    root = waiting["step_conditions"][0]
    waiting["step_conditions"].append(
        _filter("c9", "EQ", root["condition_id"], condition_key="k", condition_value="a")
    )
    sheet = _sheet(stored)
    assert "- Waits for: step 1.\n- Runs only if:\n  - A condition of type `DEPEND_ON`" in sheet
    assert "    - `k` is `a`." in sheet


@pytest.mark.parametrize(
    ("key", "said"), [(5, "`5`"), (["k"], "`['k']`"), ("", "a value with no key")]
)
def test_a_key_that_is_not_text_is_shown(key: object, said: str) -> None:
    stored = _filtered_step(_filter("c1", "EQ", condition_key=key, condition_value="a"))
    assert f"- Runs only if:\n  - {said} is `a`." in _sheet(stored)


@pytest.mark.parametrize(
    ("value", "said"),
    [(5, "a value that is not a list of text"), (" , ", "no value"), ("a", "`a`")],
)
def test_a_list_is_said_as_it_reads(value: object, said: str) -> None:
    stored = _filtered_step(_filter("c1", "IN", condition_key="k", condition_value=value))
    assert f"- Runs only if:\n  - `k` contains one of: {said}." in _sheet(stored)


def test_a_key_or_value_too_long_is_said_not_shown() -> None:
    long = "x" * (COMMAND_LIMIT + 1)
    stored = _filtered_step(_filter("c1", "EQ", condition_key=long, condition_value=long))
    sheet = _sheet(stored)
    assert long not in sheet
    assert "- a text too long to show is a text too long to show." in sheet
    exact = "y" * COMMAND_LIMIT
    assert exact in _sheet(
        _filtered_step(_filter("c1", "EQ", condition_key="k", condition_value=exact))
    )


def test_zero_and_false_are_values_not_nothing() -> None:
    for value, said in ((0, "`0`"), (False, "`False`")):
        stored = _filtered_step(_filter("c1", "EQ", condition_key="k", condition_value=value))
        assert f"- `k` is {said}." in _sheet(stored)


def test_a_filter_under_a_group_alone_brings_the_comparison_caveats() -> None:
    stored = _filtered_step(_filter("c1", "OR"), _filter("c2", "IS_NULL", "c1", condition_key="k"))
    assert "- Comparisons are case-sensitive" in _sheet(stored).split("## Caveats")[1]


@pytest.mark.parametrize("kind", [["EQ"], {"AND": 1}, 5, None])
def test_a_type_that_is_not_text_is_named_as_it_is(kind: object) -> None:
    stored = _filtered_step(_filter("c1", kind, condition_key="k"))
    assert "  - A condition of type " in _sheet(stored)


def test_a_loop_of_parents_longer_than_the_depth_read_is_cut_and_said() -> None:
    count = 20
    loop = [_filter(f"c{i}", "AND", f"c{(i + 1) % count}") for i in range(count)]
    sheet = _sheet(_filtered_step(*loop))
    assert "- More conditions below, not shown." in sheet
    assert "Starts when the scenario is launched" not in sheet.split("### 2")[1]


def test_a_condition_no_json_reader_gives_is_still_said() -> None:
    stored = _filtered_step(_filter("c1", "EQ", condition_key="k", condition_value=float("nan")))
    assert "- `k` is `nan`." in _sheet(stored)


@pytest.mark.parametrize("parent", ["c1", "elsewhere"])
def test_a_dependency_with_a_parent_is_said_not_taken_for_a_plain_one(parent: str) -> None:
    stored = _filtered_step(_filter("c1", "DEPEND_ON", parent, condition_value="s1"))
    step = _sheet(stored).split("### 2")[1]
    assert "- Runs only if:\n  - A condition of type `DEPEND_ON`" in step


@pytest.mark.parametrize(("text", "shown"), [("a\nb", "`aU+000Ab`"), ("a\rb", "`aU+000Db`")])
def test_a_line_break_in_a_key_or_a_value_is_shown_not_flattened(text: str, shown: str) -> None:
    sheet = _sheet(_filtered_step(_filter("c1", "EQ", condition_key=text, condition_value=text)))
    assert f"- Runs only if:\n  - {shown} is {shown}." in sheet


def test_a_condition_below_a_loop_of_parents_is_said_once_whatever_its_place() -> None:
    leaf = _filter("c0", "EQ", "c1", condition_key="k", condition_value="a")
    loop = [_filter("c1", "AND", "c2"), _filter("c2", "OR", "c1")]
    for order in ([leaf, *loop], [*loop, leaf]):
        sheet = _sheet(_filtered_step(*order))
        assert sheet.count("`k` is `a`.") == 1


@pytest.mark.timing
def test_a_long_loop_of_parents_is_found_in_linear_time() -> None:
    """Each parent is followed once: a file with a long loop never hangs a run."""
    count = 30_000
    loop = [_filter(f"c{i}", "AND", f"c{(i + 1) % count}") for i in range(count)]
    stored = _filtered_step(*loop)
    started = time.perf_counter()

    sheet = _sheet(stored)

    assert time.perf_counter() - started < 3.0
    assert "- More conditions below, not shown." in sheet
