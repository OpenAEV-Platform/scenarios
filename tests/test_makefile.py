"""The local pipeline, which the tools CI runs as it is: what it checks of the catalogue itself."""

import fnmatch
import os
import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parents[1]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def _recipe(target: str) -> str:
    match = re.search(rf"^{target}:.*\n((?:\t.*\n)+)", MAKEFILE, re.MULTILINE)
    assert match, target
    return match.group(1)


def test_the_pipeline_checks_every_sheet_of_the_catalogue() -> None:
    """A sheet left out of date by a change elsewhere, an exception granted say, is seen on every
    run, not only when its entry changes."""
    (checks,) = re.findall(r"^checks:(.*)$", MAKEFILE, re.MULTILINE)

    assert "sheets" in checks.split()
    assert "scenario-tools render --check -- {} +" in _recipe("sheets")


def _sheets(root: Path) -> subprocess.CompletedProcess[str]:
    """The target run on the catalogue under ``root``, with the repository's tools."""
    return subprocess.run(  # noqa: S603 - make runs the repository's own target
        ["make", "--no-print-directory", "-f", str(ROOT / "Makefile"), "-C", str(root), "sheets"],  # noqa: S607 - make from the PATH
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "UV_PROJECT": str(ROOT)},
    )


def test_an_entry_s_name_is_never_read_as_an_option(tmp_path: Path) -> None:
    """A directory named like an option is a path render refuses, never a help that passes."""
    (tmp_path / "scenarios" / "techniques" / "x --help").mkdir(parents=True)

    result = _sheets(tmp_path)

    assert result.returncode != 0
    assert "Usage:" not in result.stdout


@pytest.mark.parametrize("link", ["scenarios", "scenarios/techniques"])
def test_a_link_in_place_of_the_catalogue_or_a_domain_is_refused(tmp_path: Path, link: str) -> None:
    """What it leads to is never read: the run says so, never passes over it."""
    shutil.copytree(ROOT / "policy", tmp_path / "policy")
    shutil.copytree(ROOT / "scenarios", tmp_path / "elsewhere")
    (tmp_path / link).parent.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "elsewhere" / Path(link).relative_to("scenarios")
    (tmp_path / link).symlink_to(target, target_is_directory=True)

    result = _sheets(tmp_path)

    assert result.returncode != 0
    assert f"IO-013 {link}:" in result.stdout


def test_a_catalogue_without_an_entry_has_no_sheet_to_check(tmp_path: Path) -> None:
    (tmp_path / "scenarios").mkdir()

    assert _sheets(tmp_path).returncode == 0


def test_the_catalogue_s_sheets_are_up_to_date() -> None:
    """The target run as it is, on the repository; a stale sheet is render --check's to report."""
    result = _sheets(ROOT)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "render: ok" in result.stdout


def _make(
    *targets: str, path: str, lock: Path, dry: bool = True
) -> subprocess.CompletedProcess[str]:
    make = shutil.which("make")
    assert make is not None
    arguments = [make, "--no-print-directory", "-f", str(ROOT / "Makefile"), "-C", str(ROOT)]
    return subprocess.run(  # noqa: S603 - make runs the repository's own targets
        [*arguments, *(["-n"] if dry else []), f"PIPELINE_LOCK={lock}", *targets],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PATH": path},
    )


def test_the_timing_tests_run_once_every_other_check_has_ended_even_in_parallel(
    tmp_path: Path,
) -> None:
    """Not a prerequisite, which make -j may start beside the others, but the recipe of check,
    which make starts once every prerequisite has ended."""
    (prerequisites,) = re.findall(r"^check:(.*)$", MAKEFILE, re.MULTILINE)
    assert "timing" not in prerequisites.split()
    assert "$(MAKE) --no-print-directory timing" in _recipe("check")
    lines = _make("-j4", "check", path=os.environ["PATH"], lock=tmp_path / "lock").stdout
    commands = lines.splitlines()
    timing = next(i for i, line in enumerate(commands) if "pytest -m timing" in line)

    others = [i for i, line in enumerate(commands) if "mutmut run" in line or "ruff check" in line]
    assert others
    assert all(i < timing for i in others)


def test_without_flock_the_steps_run_as_they_are(tmp_path: Path) -> None:
    empty = tmp_path / "bin"
    empty.mkdir()  # no flock on this PATH

    lines = _make("tests", "timing", path=str(empty), lock=tmp_path / "lock").stdout

    assert "flock" not in lines
    assert 'uv run pytest -n auto -m "not timing"' in lines
    assert "uv run pytest -m timing" in lines


@pytest.mark.skipif(shutil.which("flock") is None, reason="flock is not installed")
def test_the_timing_tests_wait_for_another_checkout_s_tests_to_end(tmp_path: Path) -> None:
    """Another checkout holds the lock shared, as its tests or mutation do: the timing tests start
    only once it lets go."""
    stub, log, held, lock = tmp_path / "bin", tmp_path / "log", tmp_path / "held", tmp_path / "lock"
    stub.mkdir()
    (stub / "uv").write_text(f"#!/bin/sh\necho timing >> {log}\n")
    (stub / "uv").chmod(0o755)
    flock = shutil.which("flock")
    assert flock is not None
    holder = subprocess.Popen(  # noqa: S603 - the lock held as another checkout holds it
        [
            flock,
            "-s",
            str(lock),
            "sh",
            "-c",
            f"echo held > {held}; sleep 0.5; echo released >> {log}",
        ]
    )
    try:
        for _ in range(500):  # until the other checkout holds the lock
            if held.exists():
                break
            subprocess.run(["sleep", "0.01"], check=True)  # noqa: S607 - from the PATH
        result = _make("timing", path=f"{stub}:{Path(flock).parent}:/bin", lock=lock, dry=False)
    finally:
        holder.wait()

    assert result.returncode == 0, result.stderr
    assert log.read_text().split() == ["released", "timing"]


def test_check_runs_every_check_the_ci_jobs_run_and_the_mutation() -> None:
    (check,) = re.findall(r"^check:(.*)$", MAKEFILE, re.MULTILINE)
    (checks,) = re.findall(r"^checks:(.*)$", MAKEFILE, re.MULTILINE)

    assert check.split() == ["checks", "mutation"]
    assert set(checks.split()) == {
        "lint", "format", "types", "imports", "tests", "coverage-domain", "security", "audit",
        "secrets", "sheets", "workflows",
    }  # fmt: skip


def _mutated_packages() -> set[str]:
    """The packages of the domain mutmut mutates: each that holds code and that no pattern of
    do_not_mutate leaves out."""
    settings = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    left_out = settings["tool"]["mutmut"]["do_not_mutate"]
    domain = ROOT / "src" / "scenario_tools" / "domain"
    return {
        package.name
        for package in domain.iterdir()
        if package.is_dir()
        and any(
            not any(fnmatch.fnmatch(str(path), pattern) for pattern in left_out)
            for path in package.rglob("*.py")
            if path.name != "__init__.py"
        )
    }


def test_the_shares_of_the_mutation_in_ci_are_every_package_it_mutates_once() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "tools-ci.yml").read_text())
    shares = workflow["jobs"]["mutation"]["strategy"]["matrix"]["include"]
    prefixes = [prefix for share in shares for prefix in share["mutants"].split()]

    assert len(prefixes) == len(set(prefixes))
    assert set(prefixes) == {f"scenario_tools.domain.{name}." for name in _mutated_packages()}
    # A module beside the packages would be mutated in no share.
    domain = ROOT / "src" / "scenario_tools" / "domain"
    assert sorted(path.name for path in domain.glob("*.py")) == ["__init__.py"]


def test_the_required_check_passes_only_when_every_job_has() -> None:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "tools-ci.yml").read_text())
    pipeline = workflow["jobs"]["pipeline"]

    assert pipeline["name"] == "Local pipeline (lint, types, contracts, tests, security)"
    assert set(pipeline["needs"]) == set(workflow["jobs"]) - {"pipeline"}
    assert pipeline["if"] == "always()"
    assert '[ "$CHECKS" = success ] && [ "$MUTATION" = success ]' in pipeline["steps"][-1]["run"]


_MUTMUT_STUB = """#!/bin/sh
case "$*" in
  "run mutmut run"*) exit {run};;
  "run mutmut results") printf '%s' '{results}'; exit {status};;
esac
exit 0
"""
_SURVIVOR = "    scenario_tools.domain.policy.rules.x_f__mutmut_1: survived\n"
_OTHER_SHARE = "    scenario_tools.domain.verification.versioning.x_f__mutmut_1: not checked\n"


@pytest.mark.parametrize(
    ("run", "results", "status", "share", "passes"),
    [
        (3, "", 0, "scenario_tools.domain.policy.", False),  # the run fails
        (0, "", 4, "scenario_tools.domain.policy.", False),  # its results cannot be read
        (0, _SURVIVOR, 0, "scenario_tools.domain.policy.", False),  # a mutant of the share lives
        (0, _OTHER_SHARE, 0, "scenario_tools.domain.policy.", True),  # another share's, unrun
        (0, _OTHER_SHARE, 0, "", False),  # every mutant judged: one was never run
        (0, "", 0, "", True),
    ],
    ids=["run fails", "results fail", "survivor", "other share", "unchecked", "all killed"],
)
def test_the_mutation_fails_unless_every_mutant_it_judges_was_killed(
    tmp_path: Path, run: int, results: str, status: int, share: str, passes: bool
) -> None:
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "uv").write_text(_MUTMUT_STUB.format(run=run, results=results, status=status))
    (stub / "uv").chmod(0o755)
    path = f"{stub}{os.pathsep}{os.environ['PATH']}"

    done = _make("mutation", f"MUTANTS={share}", path=path, lock=tmp_path / "lock", dry=False)

    assert (done.returncode == 0) is passes, done.stdout + done.stderr
