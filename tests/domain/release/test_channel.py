"""The pointer of a release channel: the channel's release, by its name, and the SHA-256 of its
manifest, so that what a consumer reads next is the release the pointer names."""

import hashlib
import re
from typing import Any

import pytest

from scenario_tools.domain.release.channel import (
    ChannelPointer,
    channel_pointer,
    check_moved_forward,
    pointer_document,
    pointer_from_document,
    points_at,
)
from scenario_tools.domain.release.manifest import release_key

DOCUMENT = {
    "repository": "OpenAEV-Platform/scenarios",
    "channel": "edge",
    "release": "2026.10.15.2",
}
MANIFEST = b'{"channel":"edge","release":"2026.10.15.2","repository":"OpenAEV-Platform/scenarios"}'
SHA = hashlib.sha256(MANIFEST).hexdigest()
POINTER = ChannelPointer("edge", "2026.10.15.2", SHA)


def _refused(why: str) -> Any:
    return pytest.raises(ValueError, match=f"^{re.escape(f'channel pointer: {why}')}$")


def test_a_pointer_names_the_release_of_a_manifest_and_its_hash() -> None:
    assert channel_pointer(MANIFEST, DOCUMENT) == POINTER


@pytest.mark.parametrize(
    ("document", "why"),
    [
        ({**DOCUMENT, "repository": "another/repository"}, "the manifest is of another repository"),
        ({**DOCUMENT, "channel": "nightly"}, "'nightly' is not a channel"),
        ({**DOCUMENT, "release": "2026.13.15.2"}, "'2026.13.15.2' is not a release name"),
        (
            {"repository": "OpenAEV-Platform/scenarios", "channel": "edge"},
            "None is not a release name",
        ),
    ],
)
def test_a_pointer_is_never_made_for_a_manifest_out_of_shape(
    document: dict[str, Any], why: str
) -> None:
    with _refused(why):
        channel_pointer(MANIFEST, document)


@pytest.mark.parametrize(
    ("fields", "why"),
    [
        (("nightly", "2026.10.15.2", SHA), "'nightly' is not a channel"),
        ((["edge"], "2026.10.15.2", SHA), "['edge'] is not a channel"),
        (("edge", 2026, SHA), "2026 is not a release name"),
        (
            ("edge", "2026.10.15.2", "A" * 64),
            "its manifest_sha256 must be 64 lower-case hex digits",
        ),
        (
            ("edge", "2026.10.15.2", "a" * 63),
            "its manifest_sha256 must be 64 lower-case hex digits",
        ),
        (
            ("edge", "2026.10.15.2", "a" * 65),
            "its manifest_sha256 must be 64 lower-case hex digits",
        ),
        (
            ("edge", "2026.10.15.2", "g" * 64),
            "its manifest_sha256 must be 64 lower-case hex digits",
        ),
        (("edge", "2026.10.15.2", None), "its manifest_sha256 must be 64 lower-case hex digits"),
    ],
)
def test_a_pointer_is_never_made_out_of_shape(fields: tuple[Any, Any, Any], why: str) -> None:
    with _refused(why):
        ChannelPointer(*fields)


def test_the_pointer_read_back_is_the_one_written() -> None:
    document = pointer_document(POINTER)

    assert document == {
        "schema_version": 1,
        "repository": "OpenAEV-Platform/scenarios",
        "channel": "edge",
        "release": "2026.10.15.2",
        "manifest_sha256": SHA,
    }
    assert pointer_from_document(document) == POINTER


def _written(**fields: Any) -> dict[str, Any]:
    return {**pointer_document(POINTER), **fields}


@pytest.mark.parametrize(
    ("document", "why"),
    [
        ([], "it must be an object"),
        (_written(more=1), "it holds another field than its five"),
        ({"channel": "edge"}, "it holds another field than its five"),
        (_written(schema_version=2), "its schema_version must be 1"),
        (_written(schema_version=True), "its schema_version must be 1"),
        (_written(schema_version=1.0), "its schema_version must be 1"),
        (_written(repository="another/repository"), "it names another repository"),
        (_written(channel="nightly"), "'nightly' is not a channel"),
        (_written(channel=None), "None is not a channel"),
        (_written(release="2026.02.30.1"), "'2026.02.30.1' is not a release name"),
        (_written(release="2026.10.15.0"), "'2026.10.15.0' is not a release name"),
        (_written(release=["2026.10.15.1"]), "['2026.10.15.1'] is not a release name"),
        (_written(manifest_sha256=7), "its manifest_sha256 must be 64 lower-case hex digits"),
    ],
)
def test_a_pointer_out_of_shape_is_refused(document: object, why: str) -> None:
    with _refused(why):
        pointer_from_document(document)


def test_releases_are_ordered_by_their_day_then_their_rank() -> None:
    names = ["2026.10.15.10", "2026.10.15.2", "2025.12.31.9", "2026.10.16.1"]

    assert sorted(names, key=release_key) == [
        "2025.12.31.9",
        "2026.10.15.2",
        "2026.10.15.10",
        "2026.10.16.1",
    ]


@pytest.mark.parametrize("rank", ["1" + "0" * 9, "9" * 5000], ids=["ten digits", "5000 digits"])
def test_a_rank_over_nine_digits_is_no_release_name(rank: str) -> None:
    with pytest.raises(ValueError, match=r"is not a release name$"):
        release_key(f"2026.10.15.{rank}")


def test_a_rank_of_nine_digits_is_a_release_name() -> None:
    assert release_key("2026.10.15.999999999")[1] == 999_999_999


def test_a_channel_moves_to_a_later_release_or_stays_on_its_own() -> None:
    later = ChannelPointer("edge", "2026.10.15.3", "b" * 64)

    check_moved_forward(None, POINTER)
    check_moved_forward(POINTER, later)
    check_moved_forward(POINTER, POINTER)  # published again: nothing moves


@pytest.mark.parametrize(
    ("pointer", "why"),
    [
        (
            ChannelPointer("edge", "2026.10.15.1", "b" * 64),
            "edge would go back from 2026.10.15.2 to 2026.10.15.1",
        ),
        (
            ChannelPointer("edge", "2026.10.15.2", "b" * 64),
            "edge already names 2026.10.15.2 with another manifest",
        ),
        (
            ChannelPointer("stable", "2026.10.15.3", "b" * 64),
            "a pointer of stable cannot follow one of edge",
        ),
    ],
)
def test_a_channel_never_goes_back_nor_changes_a_release(pointer: ChannelPointer, why: str) -> None:
    with _refused(why):
        check_moved_forward(POINTER, pointer)


def test_a_pointer_points_at_the_manifest_of_its_hash_its_channel_and_its_release_only() -> None:
    stable = ChannelPointer("stable", "2026.10.15.2", SHA)
    later = ChannelPointer("edge", "2026.10.15.3", SHA)

    assert points_at(POINTER, MANIFEST, DOCUMENT)
    assert not points_at(POINTER, MANIFEST + b" ", DOCUMENT)
    assert not points_at(stable, MANIFEST, DOCUMENT)
    assert not points_at(later, MANIFEST, DOCUMENT)
    assert not points_at(POINTER, MANIFEST, {**DOCUMENT, "repository": "another/repository"})
