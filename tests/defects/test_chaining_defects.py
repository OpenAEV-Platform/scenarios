"""Deliberate defects of a scenario in chaining: for each, `validate` reports exactly the check that
names it, at its node.

Each defect is made from the hand-built scenario in chaining, as an entry of a repository of the
test's own, by one change, followed by what a contributor runs next (the payload references
assigned again, the sheet rendered), so that no defective file is ever committed. The entry as it
is passes; each change then makes one check fail, and no other. A change to the payload the two
steps share fails that check at both steps.
"""

import copy
import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.domain.shared.workflow import WORKFLOW_NO_STEP
from scenario_tools.interface.cli import main
from tests.support.catalogue import write_catalogue
from tests.support.chaining import CHAINED, CHAINED_METADATA

ROOT = Path(__file__).parents[2]
STEPS = "/scenario_workflow/workflow_steps"
CONTRACT = "step_data/inject_injector_contract/injector_contract_payload"
Change = Callable[[dict[str, Any]], object]


def _entry(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    for part in ("policy", "schemas"):
        shutil.copytree(ROOT / part, root / part)
    entry = root / CHAINED
    entry.mkdir(parents=True)
    shutil.copyfile(
        ROOT / "tests/golden/chaining/two-steps.normalised.json", entry / "scenario.json"
    )
    (entry / "scenario.yaml").write_text(CHAINED_METADATA)
    (entry / "CHANGELOG.md").write_text("# Changelog\n\n## 1.0.0 — 2026-10-22\n\nFirst version.\n")
    write_catalogue(root, json.loads((entry / "scenario.json").read_text("utf-8")))
    for command in (["payloads", str(entry), "--assign"], ["render", str(entry)]):
        result = CliRunner().invoke(main, command)
        assert result.exit_code == 0, result.output
    return entry


def _validate(entry: Path) -> tuple[int, set[tuple[str, str]]]:
    """The exit code and each finding as code and field, once the references are assigned again
    and the sheet rendered, as a contributor does after a change. Their exit codes are not read:
    a defect may make them refuse the entry, which `validate` then reports. The information that
    a payload is new, which every run without a base branch gives, is left out. A payload the
    change made is added to the catalogue first, as its contributor adds it."""
    stored = json.loads((entry / "scenario.json").read_text("utf-8"))
    write_catalogue(entry.parents[len(Path(CHAINED).parts) - 1], stored)
    CliRunner().invoke(main, ["payloads", str(entry), "--assign"])
    CliRunner().invoke(main, ["render", str(entry)])
    result = CliRunner().invoke(main, ["--format", "json", "validate", str(entry)])
    findings = json.loads(result.stdout)["findings"]
    return result.exit_code, {(f["code"], f["field"]) for f in findings if f["code"] != "POL-008"}


def _steps(document: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = document["scenario_workflow"]["workflow_steps"]
    return steps


def _waiting(document: dict[str, Any]) -> dict[str, Any]:
    return next(step for step in _steps(document) if step["step_conditions"])


def _first(document: dict[str, Any]) -> dict[str, Any]:
    return next(step for step in _steps(document) if not step["step_conditions"])


def _payload(step: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = step["step_data"]["inject_injector_contract"][
        "injector_contract_payload"
    ]
    return payload


def _both(change: Change) -> Change:
    """``change`` made to the payload the two steps share."""

    def apply(document: dict[str, Any]) -> None:
        for step in _steps(document):
            change(_payload(step))

    return apply


def _another_type(payload: dict[str, Any]) -> None:
    for key in ("command_content", "command_executor", "payload_output_parsers"):
        payload.pop(key, None)
    payload.update(payload_type="DnsResolution", dns_resolution_hostname="example.com")


def _cycle(document: dict[str, Any]) -> None:
    dependency = _waiting(document)["step_conditions"][0]
    _first(document)["step_conditions"].append(
        {
            **dependency,
            "condition_id": "00000000-0000-4000-8000-0000000000fe",
            "condition_value": _waiting(document)["step_id"],
        }
    )


def _oversized(document: dict[str, Any]) -> None:
    template = _first(document)
    _steps(document).extend(
        {**copy.deepcopy(template), "step_id": f"00000000-0000-4000-8000-0000000002{i:02d}"}
        for i in range(50)
    )


_SCOPE_RULE = {
    "workflow_scope_rule_selected_mode": "x",
    "workflow_scope_rule_source": "x",
    "workflow_scope_rule_value": "x",
    "workflow_scope_rule_value_type": "x",
    "workflow_scope_rule_value_label": "x",
}
_STEP_1, _STEP_0 = f"{STEPS}/1", f"{STEPS}/0"

DEFECTS: list[tuple[str, Change, set[tuple[str, str]]]] = [
    (
        "a mapper",
        lambda d: _waiting(d)["step_conditions"][0].update(condition_type="MAPPER"),
        {("IO-014", f"{_STEP_1}/step_conditions/0")},
    ),
    (
        "an empty IN list",
        lambda d: _waiting(d)["step_conditions"][0].update(
            condition_type="IN", condition_value=" , ", condition_key="k"
        ),
        {("IO-014", f"{_STEP_1}/step_conditions/0/condition_value")},
    ),
    (
        "a dependency on no step",
        lambda d: _waiting(d)["step_conditions"][0].update(
            condition_value="00000000-0000-4000-8000-0000000000ff"
        ),
        {("IO-014", f"{_STEP_1}/step_conditions/0/condition_value")},
    ),
    ("a cycle", _cycle, {("IO-014", _STEP_0)}),
    (
        "a duplicate step identifier",
        lambda d: _waiting(d).update(step_id=_first(d)["step_id"]),
        {("IO-014", f"{_STEP_1}/step_id")},
    ),
    (
        "a shared condition",
        lambda d: _first(d)["step_conditions"].append(
            copy.deepcopy(_waiting(d)["step_conditions"][0])
        ),
        {("IO-014", f"{_STEP_1}/step_conditions/0/condition_id")},
    ),
    (
        "a scope rule",
        lambda d: d["scenario_workflow"].update(workflow_scope_rules=[_SCOPE_RULE]),
        {("IO-014", "/scenario_workflow/workflow_scope_rules")},
    ),
    (
        "an asset on a step",
        lambda d: _first(d)["step_data"].update(
            inject_assets=["00000000-0000-4000-8000-0000000000fd"]
        ),
        {("IO-014", f"{_STEP_0}/step_data/inject_assets")},
    ),
    (
        "another payload type",
        _both(_another_type),
        {("IO-014", f"{_STEP_0}/{CONTRACT}")},
    ),
    (
        "an external injector",
        lambda d: _first(d)["step_data"].update(
            inject_injector="00000000-0000-4000-8000-0000000000fc"
        ),
        {("IO-014", f"{_STEP_0}/step_data/inject_injector")},
    ),
    ("an oversized workflow", _oversized, {("IO-014", STEPS)}),
    (
        "an unknown key",
        lambda d: d["scenario_workflow"].update(added=True),
        {("IO-014", "/scenario_workflow/added")},
    ),
    (
        "a text-form step_data",
        lambda d: _first(d).update(step_data=json.dumps(_first(d)["step_data"])),
        {("IO-014", "")},
    ),
    (
        "a forbidden command in a step",
        _both(lambda p: p.update(command_content="rm -rf / --no-preserve-root")),
        {("POL-004", f"{s}/{CONTRACT}/command_content") for s in (_STEP_0, _STEP_1)},
    ),
    (
        "a missing cleanup",
        _both(lambda p: p.update(command_content="touch /tmp/marker")),
        {("POL-005", f"{s}/{CONTRACT}/payload_cleanup_command") for s in (_STEP_0, _STEP_1)},
    ),
    (
        "a vendor name",
        _both(lambda p: p.update(command_content="ps aux | grep crowdstrike")),
        {("POL-006", f"{s}/{CONTRACT}/command_content") for s in (_STEP_0, _STEP_1)},
    ),
    (
        "an address",
        lambda d: _first(d)["step_data"].update(inject_title="Step 1 - mail jane.doe@contoso.com"),
        {("POL-010", f"{_STEP_0}/step_data/inject_title")},
    ),
]


def test_the_entry_as_it_is_passes(tmp_path: Path) -> None:
    assert _validate(_entry(tmp_path)) == (0, set())


@pytest.mark.parametrize(("name", "change", "expected"), DEFECTS, ids=[d[0] for d in DEFECTS])
def test_each_defect_of_the_stored_scenario_fails_on_its_check_only(
    tmp_path: Path, name: str, change: Change, expected: set[tuple[str, str]]
) -> None:
    entry = _entry(tmp_path)
    path = entry / "scenario.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    path.write_text(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    assert _validate(entry) == (1, expected), name


@pytest.mark.parametrize(
    ("old", "new", "field"),
    [
        ("type: chained", "type: time-based", "/type"),
        ("edition: EE", "edition: CE", "/requires/edition"),
    ],
)
def test_a_type_or_edition_out_of_line_with_the_workflow_fails_on_sch_013(
    tmp_path: Path, old: str, new: str, field: str
) -> None:
    entry = _entry(tmp_path)
    path = entry / "scenario.yaml"
    path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
    assert _validate(entry) == (1, {("SCH-013", field)})


@pytest.mark.parametrize("openaev", [">=3.261005.0", ">3.261023.9", "==3.261023.0"])
def test_a_workflow_allowing_a_platform_without_the_dependency_fix_fails_on_sch_015(
    tmp_path: Path, openaev: str
) -> None:
    entry = _entry(tmp_path)
    path = entry / "scenario.yaml"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("openaev: '>=3.261024.0'", f"openaev: '{openaev}'"))
    assert _validate(entry) == (1, {("SCH-015", "/requires/openaev")})


def test_a_stored_workflow_with_no_step_fails_on_its_steps_not_on_its_type(tmp_path: Path) -> None:
    entry = _entry(tmp_path)
    path = entry / "scenario.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["scenario_workflow"]["workflow_steps"] = []
    path.write_text(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    metadata = entry / "scenario.yaml"  # the entry otherwise agrees with its steps: none
    text = metadata.read_text(encoding="utf-8")
    metadata.write_text(text.replace("  injectors:\n  - openaev_implant\n", "  injectors: []\n"))
    assert _validate(entry) == (1, {("IO-014", STEPS)})
    result = CliRunner().invoke(main, ["--format", "json", "validate", str(entry)])
    (finding,) = json.loads(result.stdout)["findings"]
    assert finding["message"].endswith(WORKFLOW_NO_STEP)
