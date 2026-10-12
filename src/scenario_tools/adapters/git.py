"""Adapter: what git says about a checkout."""

import os
import re
import shutil

# Only to ask git for the commit and the changes, with fixed arguments.
import subprocess  # nosec B404
from pathlib import Path

from scenario_tools.ports.errors import EnvironmentProblemError

_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_TIMEOUT = 30  # seconds


def _git(root: Path, *arguments: str, given: str | None = None) -> str | None:
    """What git prints for ``arguments`` on the checkout at ``root``, as it prints it, with no
    variable of the environment pointing it at another repository, ``given`` on its standard
    input; ``None`` when git says it fails. A git that is missing, found inside the checkout,
    or that cannot be run or does not answer is the environment's fault."""
    program = shutil.which("git")
    if program is None:
        raise EnvironmentProblemError("cannot read the checkout: git is not installed")
    found = Path(os.path.realpath(program))
    if Path(os.path.realpath(root)) in (found, *found.parents):  # a PATH holding "." finds it
        raise EnvironmentProblemError(
            "cannot read the checkout: the git found is inside the repository, and is never run"
        )
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    try:
        # git itself, with fixed arguments and no shell.
        run = subprocess.run(  # noqa: S603  # nosec B603
            # Never a monitor the checkout configures, and never a write, the index's included.
            [
                program,
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "attr.tree=",  # attributes from the checkout, never from a tree a config names
                "-C",
                str(root),
                *arguments,
            ],
            capture_output=True,
            input=given,
            encoding="utf-8",
            errors="replace",  # a path git prints in another encoding is compared, never decoded
            timeout=_TIMEOUT,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as error:  # said without the command, which names paths
        raise EnvironmentProblemError("cannot read the checkout: git did not answer") from error
    except OSError as error:
        raise EnvironmentProblemError(f"cannot read the checkout: {error.strerror}") from error
    return run.stdout if run.returncode == 0 else None


def head_commit(root: Path) -> str:
    """The commit the checkout at ``root`` is at, as git names it; ``root`` must be the top of
    that checkout, not a directory inside another one."""
    top = (_git(root, "rev-parse", "--show-toplevel") or "").strip()
    try:
        same = bool(top) and Path(top).samefile(root)
    except OSError:  # a top that cannot be looked at is not known to be this one
        same = False
    if not same:
        raise EnvironmentProblemError(
            "cannot read the commit of the repository: it is not the top of a checkout"
        )
    commit = (_git(root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}") or "").strip()
    if not _COMMIT.fullmatch(commit):
        raise EnvironmentProblemError(
            "cannot read the commit of the repository: no commit checked out"
        )
    return commit


def uncommitted(root: Path, paths: tuple[str, ...]) -> tuple[str, ...]:
    """The files under ``paths`` of the checkout at ``root`` that may differ from its commit, by
    their path in the checkout, sorted: changed, untracked or ignored ones, and those git is
    told to take as unchanged, whatever they hold."""
    listed = _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=traditional",
        "--ignore-submodules=none",  # a submodule told to be ignored is a change all the same
        "--",
        *paths,
    )
    flagged = _git(root, "ls-files", "-v", "-z", "--", *paths)
    if listed is None or flagged is None:
        raise EnvironmentProblemError("cannot read the changes of the checkout")
    found: set[str] = set()
    fields = iter(listed.split("\0"))
    for field in fields:
        if not field:
            continue
        found.add(field[3:])
        if field[0] in "RC":  # a renamed or copied file: its former path follows
            found.add(next(fields, ""))
    for field in flagged.split("\0"):
        # A lower-case tag: taken as unchanged; S: skipped in the work tree.
        if field and (field[0].islower() or field[0] == "S"):
            found.add(field[2:])
    return tuple(sorted(found - {""}))


# What makes git change a file's bytes between the commit and the checkout.
_CONVERTING = ("text", "eol", "crlf", "filter", "ident", "working-tree-encoding")


def converted(root: Path, paths: tuple[str, ...]) -> tuple[str, ...]:
    """The files under ``paths`` of the checkout at ``root`` whose bytes git converts between
    the commit and the checkout, by their attributes or their line ends, sorted: what is read
    there is not what the commit holds."""
    listed = _git(root, "ls-files", "-z", "--", *paths)
    if listed is None:
        raise EnvironmentProblemError("cannot read the attributes of the checkout")
    files = tuple(name for name in listed.split("\0") if name)
    if not files:
        return ()
    return tuple(sorted({*converting(root, files), *_other_line_ends(root, paths)}))


def converting(root: Path, files: tuple[str, ...]) -> tuple[str, ...]:
    """Those of ``files``, paths in the checkout at ``root`` that need not exist yet, whose
    bytes git would convert by their attributes in the checkout, its index or its commit (git
    2.40 or later), sorted."""
    if not files:
        return ()
    found: set[str] = set()
    # The checkout's attributes, the index's and the commit's, which a change outside the paths
    # could undo.
    for source in ((), ("--cached",), ("--source", "HEAD")):
        told = _git(
            root, "check-attr", *source, "-z", "--stdin", *_CONVERTING, given="\0".join(files)
        )
        if told is None:
            needed = " (git 2.40 or later is needed)" if "--source" in source else ""
            raise EnvironmentProblemError(f"cannot read the attributes of the checkout{needed}")
        fields = told.split("\0")
        found.update(
            fields[index]
            for index in range(0, len(fields) - 2, 3)
            if fields[index + 2] not in ("unspecified", "unset")
        )
    return tuple(sorted(found))


_TEXT_ENDS = ("lf", "crlf", "mixed")


def _other_line_ends(root: Path, paths: tuple[str, ...]) -> set[str]:
    """The files under ``paths`` whose line ends in the checkout are not the commit's, as a
    setting such as ``core.autocrlf`` writes them, whatever the attributes say."""
    told = _git(root, "ls-files", "--eol", "-z", "--", *paths)
    if told is None:
        raise EnvironmentProblemError("cannot read the attributes of the checkout")
    found = set()
    for record in told.split("\0"):
        info, _, name = record.partition("\t")
        ends = [part.split("/", 1)[1] for part in info.split()[:2]]  # i/<index> w/<checkout>
        if (
            len(ends) == 2
            and ends[0] in _TEXT_ENDS
            and ends[1] in _TEXT_ENDS
            and ends[0] != ends[1]
        ):
            found.add(name)
    return found
