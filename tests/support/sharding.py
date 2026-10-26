"""Which share of the tests a test belongs to, for the CI's parallel jobs: a stable hash of its
ID, so that every test is in exactly one share and stays there from run to run."""

import re
import zlib

_SHARE = re.compile(r"([1-9][0-9]*)/([1-9][0-9]*)")


def share_of(test: str, count: int) -> int:
    """The share, from 1 to ``count``, that runs the test whose ID is ``test``."""
    return zlib.crc32(test.encode("utf-8")) % count + 1


def parse_share(text: str) -> tuple[int, int]:
    """The share ``index/count`` that ``text`` names, the index from 1 to ``count``."""
    found = _SHARE.fullmatch(text)
    if found is None or int(found[1]) > int(found[2]):
        raise ValueError(
            f"SCENARIOS_TEST_SHARD must be index/count, index from 1 to count: {text!r}"
        )
    return int(found[1]), int(found[2])
