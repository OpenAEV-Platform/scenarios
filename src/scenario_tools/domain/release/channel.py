"""The pointer of a release channel: the channel's release, by its name, and the SHA-256 of
its manifest, published at a fixed place for each channel. A consumer reads the pointer, then
the manifest of the release it names, and checks that manifest against it, so that the
releases themselves never change and the channel moves by its pointer alone, never back: a
channel is never rolled back, a later release is published instead."""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scenario_tools.domain.release.manifest import (
    CHANNELS,
    REPOSITORY,
    is_github_login,
    release_key,
)

POINTER_SCHEMA_VERSION = 1
POINTER_LIMIT = 4 * 1024  # bytes of a pointer file, which holds five short fields
_FIELDS = frozenset({"schema_version", "repository", "channel", "release", "manifest_sha256"})
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _refused(why: str) -> ValueError:
    return ValueError(f"channel pointer: {why}")


@dataclass(frozen=True)
class ChannelPointer:
    """A channel, the release it names, and the SHA-256 of that release's manifest; one that is
    not shaped so is never made."""

    channel: str
    release: str
    manifest_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.channel, str) or self.channel not in CHANNELS:
            raise _refused(f"{self.channel!r} is not a channel")
        try:
            release_key(self.release)
        except ValueError as error:
            raise _refused(str(error)) from error
        if not isinstance(self.manifest_sha256, str) or not _SHA256.fullmatch(self.manifest_sha256):
            raise _refused("its manifest_sha256 must be 64 lower-case hex digits")


def channel_pointer(manifest: bytes, document: Mapping[str, Any]) -> ChannelPointer:
    """The pointer to the release whose manifest is ``manifest``, as published: ``document`` is
    what it holds, read and checked by the caller, which gives the channel and the name; the
    bytes give the SHA-256. Only an approved manifest, naming its approver, is pointed at."""
    if document.get("repository") != REPOSITORY:
        raise _refused("the manifest is of another repository")
    if not is_github_login(document.get("release_approver")):
        raise _refused("the manifest is not approved: a channel names an approved release only")
    channel: Any = document.get("channel")  # checked as the pointer is made
    release: Any = document.get("release")
    return ChannelPointer(channel, release, hashlib.sha256(manifest).hexdigest())


def pointer_document(pointer: ChannelPointer) -> dict[str, Any]:
    """``pointer`` as its file holds it."""
    return {
        "schema_version": POINTER_SCHEMA_VERSION,
        "repository": REPOSITORY,
        "channel": pointer.channel,
        "release": pointer.release,
        "manifest_sha256": pointer.manifest_sha256,
    }


def pointer_from_document(document: object) -> ChannelPointer:
    """The pointer a file holds, as ``pointer_document`` writes it; ``ValueError`` otherwise."""
    if not isinstance(document, Mapping):
        raise _refused("it must be an object")
    if set(document) != _FIELDS:
        raise _refused("it holds another field than its five")
    version = document["schema_version"]
    if type(version) is not int or version != POINTER_SCHEMA_VERSION:
        raise _refused(f"its schema_version must be {POINTER_SCHEMA_VERSION}")
    if document["repository"] != REPOSITORY:
        raise _refused("it names another repository")
    return ChannelPointer(document["channel"], document["release"], document["manifest_sha256"])


def check_moved_forward(previous: ChannelPointer | None, pointer: ChannelPointer) -> None:
    """Refuse ``pointer`` unless it may follow ``previous``, the channel's pointer until now, if
    any: the same channel, and a later release, or the same release with the same manifest."""
    if previous is None:
        return
    if pointer.channel != previous.channel:
        raise _refused(f"a pointer of {pointer.channel} cannot follow one of {previous.channel}")
    before, after = release_key(previous.release), release_key(pointer.release)
    if after < before:
        raise _refused(
            f"{pointer.channel} would go back from {previous.release} to {pointer.release}"
        )
    if after == before and pointer.manifest_sha256 != previous.manifest_sha256:
        raise _refused(f"{pointer.channel} already names {pointer.release} with another manifest")


def points_at(pointer: ChannelPointer, manifest: bytes, document: Mapping[str, Any]) -> bool:
    """Whether ``manifest``, as read, and ``document``, what it holds, are those of the release
    ``pointer`` names: its SHA-256, the repository, the channel and the release's name."""
    return (
        hashlib.sha256(manifest).hexdigest() == pointer.manifest_sha256
        and document.get("repository") == REPOSITORY
        and document.get("channel") == pointer.channel
        and document.get("release") == pointer.release
    )
