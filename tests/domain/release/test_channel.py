"""The pointer of a release channel: the channel's release, by its name, and the SHA-256 of its
manifest, so that what a consumer reads next is the release the pointer names."""

import datetime
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
    "release_approver": "laugiov",
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
            {
                "repository": "OpenAEV-Platform/scenarios",
                "channel": "edge",
                "release_approver": "a",
            },
            "None is not a release name",
        ),
        (
            {key: value for key, value in DOCUMENT.items() if key != "release_approver"},
            "the manifest is not approved: a channel names an approved release only",
        ),
        (
            {**DOCUMENT, "release_approver": None},
            "the manifest is not approved: a channel names an approved release only",
        ),
        (
            {**DOCUMENT, "release_approver": ""},
            "the manifest is not approved: a channel names an approved release only",
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
        (_written(release="1.260230.0"), "'1.260230.0' is not a release name"),
        (_written(release="1.261015.01"), "'1.261015.01' is not a release name"),
        (_written(release=["2026.10.15.1"]), "['2026.10.15.1'] is not a release name"),
        (_written(manifest_sha256=7), "its manifest_sha256 must be 64 lower-case hex digits"),
    ],
)
def test_a_pointer_out_of_shape_is_refused(document: object, why: str) -> None:
    with _refused(why):
        pointer_from_document(document)


def test_releases_are_ordered_by_their_format_their_day_then_their_rank() -> None:
    """A name of the old form, YYYY.MM.DD.N, comes before every name of the new one."""
    names = [
        "1.261015.10",
        "2026.10.15.10",
        "1.261015.2",
        "2.250101.0",
        "2026.10.15.2",
        "1.251231.9",
        "2025.12.31.9",
        "2026.10.16.1",
    ]

    assert sorted(names, key=release_key) == [
        "2025.12.31.9",
        "2026.10.15.2",
        "2026.10.15.10",
        "2026.10.16.1",
        "1.251231.9",
        "1.261015.2",
        "1.261015.10",
        "2.250101.0",
    ]


@pytest.mark.parametrize(
    ("name", "key"),
    [
        ("2026.10.29.2", (0, datetime.date(2026, 10, 29), 2)),
        ("1.261030.0", (1, datetime.date(2026, 10, 30), 0)),
        ("12.990101.7", (12, datetime.date(2099, 1, 1), 7)),
    ],
)
def test_a_release_name_gives_its_major_its_day_and_its_rank(
    name: str, key: tuple[int, datetime.date, int]
) -> None:
    assert release_key(name) == key


@pytest.mark.parametrize("rank", ["1" + "0" * 9, "9" * 5000], ids=["ten digits", "5000 digits"])
@pytest.mark.parametrize("day", ["2026.10.15", "1.261015"], ids=["old form", "new form"])
def test_a_rank_over_nine_digits_is_no_release_name(day: str, rank: str) -> None:
    with pytest.raises(ValueError, match=r"is not a release name$"):
        release_key(f"{day}.{rank}")


@pytest.mark.parametrize("day", ["2026.10.15", "1.261015"], ids=["old form", "new form"])
def test_a_rank_of_nine_digits_is_a_release_name(day: str) -> None:
    assert release_key(f"{day}.999999999")[-1] == 999_999_999


def test_a_channel_moves_from_a_name_of_the_old_form_to_one_of_the_new() -> None:
    old = ChannelPointer("edge", "2026.10.29.2", "a" * 64)
    new = ChannelPointer("edge", "1.261030.0", "b" * 64)

    check_moved_forward(old, new)
    with _refused("edge would go back from 1.261030.0 to 2026.10.29.2"):
        check_moved_forward(new, old)


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
    for approver in (None, "", "Not A Login"):
        assert not points_at(POINTER, MANIFEST, {**DOCUMENT, "release_approver": approver})
    without = {key: value for key, value in DOCUMENT.items() if key != "release_approver"}
    assert not points_at(POINTER, MANIFEST, without)
