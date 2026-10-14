"""The local pipeline, which the tools CI runs as it is: what it checks of the catalogue itself."""

import os
import re
import subprocess
from pathlib import Path

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


def test_a_catalogue_without_an_entry_has_no_sheet_to_check(tmp_path: Path) -> None:
    (tmp_path / "scenarios").mkdir()

    assert _sheets(tmp_path).returncode == 0


def test_the_catalogue_s_sheets_are_up_to_date() -> None:
    """The target run as it is, on the repository; a stale sheet is render --check's to report."""
    result = _sheets(ROOT)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "render: ok" in result.stdout
