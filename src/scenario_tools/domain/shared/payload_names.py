"""The names of the versions of a payload of the catalogue.

The first version of a payload carries its plain name, its base name; every other version carries
the base name followed by ``" (<version>)"``, so that the platform shows two versions a person can
tell apart. The identifiers the repository derives from a payload's name are derived from its base
name, so that every version of one payload shares them."""

import re

FIRST_VERSION = "1.0.0"
SEMVER = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
_SUFFIX = re.compile(rf" \({SEMVER}\)\Z")


def version_key(version: str) -> tuple[int, ...]:
    """The semantic version ``version``, ``MAJOR.MINOR.PATCH``, as numbers to order it by."""
    return tuple(int(part) for part in version.split("."))


def base_name(name: str) -> str:
    """``name`` without a final ``" (<version>)"``, stripped once; a name without one is its own
    base name."""
    found = _SUFFIX.search(name)
    return name if found is None else name[: found.start()]


def versioned_name(base: str, version: str) -> str:
    """The name of the version ``version`` of the payload whose base name is ``base``."""
    return base if version == FIRST_VERSION else f"{base} ({version})"
