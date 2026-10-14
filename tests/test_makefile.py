"""The local pipeline, which the tools CI runs as it is: what it checks of the catalogue itself."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def _recipe(target: str) -> str:
    match = re.search(rf"^{target}:.*\n((?:\t.*\n)+)", MAKEFILE, re.MULTILINE)
    assert match, target
    return match.group(1)


def test_the_pipeline_checks_every_sheet_of_the_catalogue() -> None:
    """A sheet left out of date by a change elsewhere, an exception granted say, is seen on every
    run, not only when its entry changes."""
    (check,) = re.findall(r"^check:(.*)$", MAKEFILE, re.MULTILINE)

    assert "sheets" in check.split()
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
