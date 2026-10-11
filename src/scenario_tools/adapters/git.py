"""Adapter: what git says about a checkout."""

import os
import re
import shutil

# Only to ask git for the commit, with fixed arguments.
import subprocess  # nosec B404
from pathlib import Path

from scenario_tools.ports.errors import EnvironmentProblemError

_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_TIMEOUT = 30  # seconds


def _git(root: Path, *arguments: str) -> str:
    """What git prints for ``arguments`` on the checkout at ``root``, with no variable of the
    environment pointing it at another repository; empty when it fails."""
    program = shutil.which("git")
    if program is None:
        raise EnvironmentProblemError("cannot read the commit: git is not installed")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        # git itself, with fixed arguments and no shell.
        run = subprocess.run(  # noqa: S603  # nosec B603
            [program, "-C", str(root), *arguments],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EnvironmentProblemError(
            f"cannot read the commit of the repository: {error}"
        ) from error
    return run.stdout.strip() if run.returncode == 0 else ""


def head_commit(root: Path) -> str:
    """The commit the checkout at ``root`` is at, as git names it; ``root`` must be the top of
    that checkout, not a directory inside another one."""
    top = _git(root, "rev-parse", "--show-toplevel")
    if not top or not Path(top).samefile(root):
        raise EnvironmentProblemError(
            "cannot read the commit of the repository: it is not the top of a checkout"
        )
    commit = _git(root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    if not _COMMIT.fullmatch(commit):
        raise EnvironmentProblemError(
            "cannot read the commit of the repository: no commit checked out"
        )
    return commit
