"""The validate command: an entry checked as the data model says, from the repository that holds
it, whatever the working directory; its exit code says whether anything blocks it."""

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.adapters.safe_readers import parse_yaml, yaml_bytes
from scenario_tools.interface.cli import main

REPOSITORY = Path(__file__).parents[2]
EASM = REPOSITORY / "tests" / "golden" / "exports" / "easm-scenario.zip"
ENTRY_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"


def _repository(tmp_path: Path, name: str = "repository") -> Path:
    """A repository of its own, with the policy data and the schemas of this one."""
    root = tmp_path / name
    shutil.copytree(REPOSITORY / "policy" / "data", root / "policy" / "data")
    shutil.copytree(REPOSITORY / "schemas", root / "schemas")
    return root


def _invoke(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> Any:
    monkeypatch.chdir("/")  # the working directory plays no part
    return CliRunner().invoke(main, ["--format", "json", *arguments])


def _complete_entry(
    monkeypatch: pytest.MonkeyPatch, root: Path, relative: str = "scenarios/techniques/easm"
) -> Path:
    """An entry prepared from the EASM export, then completed as a contributor would."""
    entry = root / relative
    entry.mkdir(parents=True)
    prepared = _invoke(
        monkeypatch, "normalize", str(EASM), "--out", str(entry), "--external-id", ENTRY_ID
    )
    assert prepared.exit_code == 0, prepared.output
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    metadata["threat"] = {"ttps": ["T1595"]}
    metadata["sources"] = [
        {"url": "https://attack.mitre.org/techniques/T1595/", "tlp": "TLP:CLEAR"}
    ]
    (entry / "scenario.yaml").write_bytes(yaml_bytes(metadata))
    (entry / "CHANGELOG.md").write_text("## 1.0.0 — 2026-10-12\n", encoding="utf-8")
    rendered = _invoke(monkeypatch, "render", str(entry))  # its sheet, as a contributor renders it
    assert rendered.exit_code == 0, rendered.output
    return entry


def _findings(result: Any) -> list[tuple[str, str, str]]:
    return [(f["code"], f["path"], f["field"]) for f in json.loads(result.stdout)["findings"]]


def test_a_completed_entry_validates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path))

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {"command": "validate", "ok": True, "findings": []}


def test_what_blocks_an_entry_is_reported_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    metadata["description"] += chr(0x2026)
    (entry / "scenario.yaml").write_bytes(yaml_bytes(metadata))
    (entry / "README.md").write_text(f"# EASM {chr(0x202E)}\n", encoding="utf-8")
    other = _complete_entry(monkeypatch, root, "scenarios/techniques/easm-copy")
    (other / "scenario.json").unlink()

    result = _invoke(monkeypatch, "validate", str(entry), str(other))

    assert result.exit_code == 1, result.output
    assert _findings(result) == [
        ("SCH-008", "scenarios/techniques/easm-copy/scenario.json", ""),
        ("SCH-010", "scenarios/techniques/easm-copy/scenario.yaml", "/external_id"),
        ("SCH-012", "scenarios/techniques/easm-copy/scenario.yaml", "/name"),
        ("GEN-001", "scenarios/techniques/easm/README.md", ""),  # edited, no longer the sheet
        ("IO-017", "scenarios/techniques/easm/README.md", ""),
        ("SCH-009", "scenarios/techniques/easm/scenario.yaml", "/description"),
        ("SCH-010", "scenarios/techniques/easm/scenario.yaml", "/external_id"),
        ("SCH-012", "scenarios/techniques/easm/scenario.yaml", "/name"),
    ]


def test_a_directory_of_the_path_that_is_a_link_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    _complete_entry(monkeypatch, root, "elsewhere/techniques/easm")
    (root / "scenarios").symlink_to(root / "elsewhere")

    result = _invoke(monkeypatch, "validate", str(root / "scenarios" / "techniques" / "easm"))

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("IO-013", "scenarios", "")]


def test_entries_of_two_repositories_are_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    first = _complete_entry(monkeypatch, _repository(tmp_path, "one"))
    second = _complete_entry(monkeypatch, _repository(tmp_path, "two"))

    result = _invoke(monkeypatch, "validate", str(first), str(second))

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "the entries belong to different repositories" in result.stderr


def test_an_entry_outside_any_repository_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _invoke(monkeypatch, "validate", str(tmp_path))

    assert result.exit_code == 3
    assert json.loads(result.stdout)["ok"] is False


@pytest.mark.parametrize("option", ["--previous-release", "--private-denylist"])
def test_the_options_of_later_checks_are_refused_until_they_come(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, option: str
) -> None:
    result = _invoke(monkeypatch, "validate", str(tmp_path), option, "x")

    assert result.exit_code == 2


def test_validate_needs_an_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _invoke(monkeypatch, "validate").exit_code == 2


def test_unusable_recorded_contracts_are_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    (root / "policy" / "data" / "builtin-contracts.yaml").write_text("contracts: {}\n")

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 3
    assert "policy data cannot be used" in json.loads(result.stdout)["error"]


@pytest.mark.parametrize("text", ["domains: example.com\n", "", "networks: []\n"])
def test_unusable_allowed_targets_are_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    (root / "policy" / "data" / "allowed-targets.yaml").write_text(text)

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 3
    assert "policy data cannot be used" in json.loads(result.stdout)["error"]


@pytest.mark.parametrize(
    "text",
    [
        "exceptions: {}\n",
        "",
        f"exceptions:\n  - entry: x\n    code: POL-006\n    field: ''\n    sha256: {'a' * 64}\n"
        "    justification: a reason long enough to be read\n",
    ],
)
def test_an_unusable_exceptions_registry_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    (root / "policy" / "data" / "exceptions.yaml").write_text(text)

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 3
    assert "policy data cannot be used" in json.loads(result.stdout)["error"]


def test_an_exception_of_the_registry_that_covers_nothing_blocks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    (root / "policy" / "data" / "exceptions.yaml").write_text(
        f"exceptions:\n  - entry: {ENTRY_ID}\n    code: POL-006\n    field: /scenario_name\n"
        f"    sha256: {'a' * 64}\n    justification: a reason long enough to be read\n"
    )
    _invoke(monkeypatch, "render", str(entry))  # the sheet shows the exception granted
    stored = hashlib.sha256((entry / "scenario.json").read_bytes()).hexdigest()

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("POL-011", "policy/data/exceptions.yaml", "/exceptions/0")]
    # The hash the maintainers give the exception once they have reviewed the entry.
    assert f"(sha256 now {stored})" in json.loads(result.stdout)["findings"][0]["message"]


def test_a_directory_that_cannot_be_searched_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def unsearchable(self: Path) -> bool:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "is_dir", unsearchable)

    result = _invoke(monkeypatch, "validate", str(tmp_path))

    assert result.exit_code == 3
    assert "cannot look for policy data above" in json.loads(result.stdout)["error"]


def test_a_stored_scenario_of_another_entry_is_not_what_normalisation_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path))
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    metadata["external_id"] = "0b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
    (entry / "scenario.yaml").write_bytes(yaml_bytes(metadata))
    _invoke(monkeypatch, "render", str(entry))  # the sheet shows the external ID

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("GEN-002", "scenarios/techniques/easm/scenario.json", "")]


def test_an_entry_given_twice_is_checked_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path))
    (entry / "README.md").write_text(f"# EASM {chr(0x202E)}\n", encoding="utf-8")

    result = _invoke(monkeypatch, "validate", str(entry), str(entry / "."))

    assert _findings(result) == [
        ("GEN-001", "scenarios/techniques/easm/README.md", ""),  # edited, no longer the sheet
        ("IO-017", "scenarios/techniques/easm/README.md", ""),
    ]


def test_the_help_says_which_checks_run_yet(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _invoke(monkeypatch, "validate", "--help")

    assert "not run yet" in " ".join(result.output.split())
    assert "data model" not in result.output
    assert "No symbolic link inside the repository is followed" in " ".join(result.output.split())
    assert "private deny-list" in " ".join(result.output.split())


def test_a_repository_reached_through_a_link_of_the_operator_s_is_validated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The links refused are those inside the repository, which a pull request could bring; the
    # path to the repository is the operator's, such as a workspace or /tmp on macOS.
    entry = _complete_entry(monkeypatch, _repository(tmp_path))
    (tmp_path / "workspace").symlink_to(tmp_path / "repository")

    result = _invoke(
        monkeypatch,
        "validate",
        str(tmp_path / "workspace" / entry.relative_to(tmp_path / "repository")),
    )

    assert result.exit_code == 0, result.output


def test_one_repository_reached_by_two_paths_is_one_repository(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path))
    (entry / "README.md").write_text(f"# EASM {chr(0x202E)}\n", encoding="utf-8")
    (tmp_path / "workspace").symlink_to(tmp_path / "repository")
    linked = tmp_path / "workspace" / entry.relative_to(tmp_path / "repository")

    result = _invoke(monkeypatch, "validate", str(entry), str(linked))

    assert result.exit_code == 1, result.output
    assert _findings(result) == [
        ("GEN-001", "scenarios/techniques/easm/README.md", ""),  # edited, no longer the sheet
        ("IO-017", "scenarios/techniques/easm/README.md", ""),
    ]


def test_a_repository_that_cannot_be_looked_at_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    stat = Path.stat

    def failing(self: Path, **options: Any) -> Any:
        if self == root:
            raise PermissionError(13, "Permission denied")
        return stat(self, **options)

    monkeypatch.setattr(Path, "stat", failing)

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 3
    assert "cannot read" in json.loads(result.stdout)["error"]


@pytest.mark.parametrize("damage", ["missing", "no scenario schema", "invalid"])
def test_unusable_schemas_are_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, damage: str
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    if damage == "missing":
        shutil.rmtree(root / "schemas")
    elif damage == "no scenario schema":
        (root / "schemas" / "scenario.schema.json").unlink()
    else:
        (root / "schemas" / "scenario.schema.json").write_text('{"type": 5}')

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 3, result.output
    assert "schemas cannot be used" in json.loads(result.stdout)["error"]


@pytest.mark.parametrize("linked", ["policy", "policy/data", "schemas"])
def test_rules_reached_through_a_link_inside_the_repository_are_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, linked: str
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    (root / linked).rename(tmp_path / "moved")
    (root / linked).symlink_to(tmp_path / "moved")

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 3, result.output  # the maintainers' rules, not the entry
    error = json.loads(result.stdout)["error"]
    assert "cannot be used" in error
    assert "symbolic link" in error


@pytest.mark.skipif(os.geteuid() == 0, reason="permissions do not hold for root")
def test_an_entry_behind_a_directory_that_cannot_be_searched_is_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    locked = root / "scenarios" / "techniques"
    locked.chmod(0o644)
    try:
        result = _invoke(monkeypatch, "validate", str(entry))
    finally:
        locked.chmod(0o755)

    assert result.exit_code == 3, result.output


@pytest.mark.parametrize(
    ("damaged", "content"),
    [
        ("policy/data/builtin-contracts.yaml", "contracts: ["),
        ("schemas/scenario.schema.json", "{"),
    ],
    ids=["policy data", "schema"],
)
def test_rules_that_cannot_be_read_are_the_environment_s_fault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, damaged: str, content: str
) -> None:
    root = _repository(tmp_path)
    entry = _complete_entry(monkeypatch, root)
    (root / damaged).write_text(content)

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 3, result.output
    assert "cannot be used" in json.loads(result.stdout)["error"]


def test_an_entry_is_compared_with_its_previous_version(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path / "pull"))
    base = tmp_path / "base"
    shutil.copytree(entry, base / "scenarios/techniques/easm")
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    metadata["description"] = "Another description"
    (entry / "scenario.yaml").write_bytes(yaml_bytes(metadata))
    _invoke(monkeypatch, "render", str(entry))  # as a contributor renders the sheet again

    result = _invoke(monkeypatch, "validate", "--previous-root", str(base), str(entry))

    assert result.exit_code == 1, result.output
    assert _findings(result) == [("VER-001", "scenarios/techniques/easm/scenario.yaml", "/version")]


def test_an_entry_the_previous_root_does_not_hold_is_new(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entry = _complete_entry(monkeypatch, _repository(tmp_path / "pull"))
    (tmp_path / "base").mkdir()

    result = _invoke(monkeypatch, "validate", "--previous-root", str(tmp_path / "base"), str(entry))

    assert result.exit_code == 0, result.output
    assert result.stderr == ""


def test_without_a_previous_root_the_run_says_versions_are_not_compared(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A green run on a contributor's machine, red in the pull request, would surprise."""
    entry = _complete_entry(monkeypatch, _repository(tmp_path))

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["ok"] is True
    assert result.stderr == (
        "validate: without --previous-root, each entry is checked as a new one: its version is "
        "not compared with the base branch's\n"
    )


CHAINING = REPOSITORY / "tests" / "golden" / "chaining" / "two-steps.json"


@pytest.mark.parametrize("kind", ["MAPPER", []], ids=["mapper", "not-text"])
def test_a_stored_condition_out_of_the_subset_is_a_finding_not_a_crash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: object
) -> None:
    entry = _repository(tmp_path) / "scenarios" / "techniques" / "chained"
    entry.mkdir(parents=True)
    prepared = _invoke(
        monkeypatch, "normalize", str(CHAINING), "--out", str(entry), "--external-id", ENTRY_ID
    )
    assert prepared.exit_code == 0, prepared.output
    metadata = parse_yaml((entry / "scenario.yaml").read_bytes())
    metadata["threat"] = {"ttps": ["T1057"]}
    metadata["sources"] = [
        {"url": "https://attack.mitre.org/techniques/T1057/", "tlp": "TLP:CLEAR"}
    ]
    (entry / "scenario.yaml").write_bytes(yaml_bytes(metadata))
    document = json.loads((entry / "scenario.json").read_text(encoding="utf-8"))
    steps = document["scenario_workflow"]["workflow_steps"]
    index = next(i for i, step in enumerate(steps) if step["step_conditions"])
    steps[index]["step_conditions"][0]["condition_type"] = kind
    (entry / "scenario.json").write_text(json.dumps(document), encoding="utf-8")

    result = _invoke(monkeypatch, "validate", str(entry))

    assert result.exit_code == 1, result.output
    pointer = f"/scenario_workflow/workflow_steps/{index}/step_conditions/0"
    assert ("IO-014", "scenarios/techniques/chained/scenario.json", pointer) in _findings(result)
