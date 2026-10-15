"""Commit IDs, as git and GitHub name a commit in full."""

import re

_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")  # SHA-1, or SHA-256, in lower case


def is_commit_id(value: object) -> bool:
    """Whether ``value`` is a full commit ID: never a name, a range nor an option git reads."""
    return isinstance(value, str) and _COMMIT.fullmatch(value) is not None
