"""intake --check: the verdicts of intake on an export's payloads, against a catalogue that may
be a release's version files, without git, writing nothing."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from scenario_tools.interface.cli import main
from tests.interface.test_cli_build import CHAINED, ROOT, _build, _chained_entry, _git, _repository

CHAINING = ROOT / "tests" / "golden" / "chaining" / "two-steps.json"
CHAINED_ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
EASM = "scenarios/techniques/easm"


def _released(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The version files of a release built with the scenario in chaining, laid out as
    ``<slug>/<version>.json`` in a directory of their own, outside any checkout."""
    root = _repository(tmp_path, monkeypatch)
    _chained_entry(root)
    approvals = tmp_path / "approvals.json"
    approved = {"pull_request": 124, "approvers": ["alice"]}
    commit = _git(root, "rev-parse", "HEAD")
    entries = {EASM: approved, CHAINED: approved}
    approvals.write_text(json.dumps({"schema_version": 1, "commit": commit, "entries": entries}))
    out = tmp_path / "release"
    assert _build(root, approvals, out).exit_code == 0
    laid = tmp_path / "sandbox" / "payloads"
    for listed in json.loads((out / "manifest.json").read_bytes())["payloads"]:
        (laid / listed["payload"]).mkdir(parents=True)
        shutil.copyfile(
            out / listed["file"]["name"], laid / listed["payload"] / f"{listed['version']}.json"
        )
    return laid


def _rules(tmp_path: Path) -> Path:
    """The repository's rules, copied outside any checkout."""
    rules = tmp_path / "sandbox" / "rules"
    for path in ("policy", "schemas"):
        shutil.copytree(ROOT / path, rules / path)
    return rules


def _check(*arguments: str) -> tuple[int, dict[str, Any]]:
    result = CliRunner().invoke(main, ["--format", "json", "intake", *arguments])
    return result.exit_code, json.loads(result.output)


def _tree(path: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(path)): p.read_bytes() for p in sorted(path.rglob("*")) if p.is_file()
    }


def test_the_check_runs_on_a_release_s_version_files_without_git_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payloads, rules = _released(tmp_path, monkeypatch), _rules(tmp_path)
    sandbox = tmp_path / "sandbox"
    before = _tree(sandbox)
    monkeypatch.chdir(sandbox)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "no-git"))  # git, if read, finds nothing

    code, document = _check(
        str(CHAINING),
        "--check",
        "--payloads",
        str(payloads),
        "--rules",
        str(rules),
        "--external-id",
        CHAINED_ID,
    )

    assert code == 0, document
    verdicts = [(f["code"], f["message"]) for f in document["findings"]]
    assert verdicts == [("PAY-010", "already there: process-discovery-ps 1.0.0")] * 2
    assert all("/workflow_steps/" in f["field"] for f in document["findings"])
    assert not any(path.name == ".git" for path in sandbox.rglob("*"))
    assert _tree(sandbox) == before


def test_a_refused_claim_fails_the_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payloads, rules = _released(tmp_path, monkeypatch), _rules(tmp_path)
    claims = tmp_path / "claims.yaml"
    claims.write_text("payloads:\n  - name: nothing embedded\n")

    code, document = _check(
        str(CHAINING), "--check", "--payloads", str(payloads), "--rules", str(rules),
        "--claims", str(claims),
    )  # fmt: skip

    assert code == 1
    assert ("ITK-009", "claims.yaml", "/payloads/0/name") in {
        (f["code"], f["path"], f["field"]) for f in document["findings"]
    }


@pytest.mark.parametrize(
    ("arguments", "said"),
    [
        (["--check", "--rules", "r"], "--check needs --payloads and --rules"),
        (["--check", "--payloads", "p", "--rules", "r", "--plan", "x"], "leave out --plan"),
        (["--claims", "c.yaml"], "--claims go with --check only"),
        ([], "intake needs --request, --repo, --plan, or --check"),
    ],
)
def test_the_options_of_each_mode_are_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arguments: list[str], said: str
) -> None:
    for name in ("p", "r"):
        (tmp_path / name).mkdir()
    (tmp_path / "c.yaml").write_text("payloads: []\n")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, ["intake", str(CHAINING), *arguments])

    assert result.exit_code == 2
    assert said in result.output
