"""The sheet of an entry: what a reader of the catalogue needs to know before running the
scenario, rendered the same way every time, every text of the entry as plain text."""

import copy
import time
from typing import Any

import pytest
from markdown_it import MarkdownIt

from scenario_tools.adapters.safe_readers import TEXT_LIMIT
from scenario_tools.domain.policy.exceptions import PolicyException
from scenario_tools.domain.sheet.sheet import NOTICE, SHEET_LIMIT, depths, duration, render_sheet

ID = "5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42"
METADATA: dict[str, Any] = {
    "external_id": ID,
    "version": "1.2.0",
    "status": "VERIFIED",
    "name": "Scan *everything*",
    "description": "Scans the hosts.\n- one\n\nSee https://example.com/a.",
    "severity": "high",
    "category": "attack-scenario",
    "main_focus": "endpoint-protection",
    "type": "time-based",
    "platforms": ["Linux", "Windows"],
    "threat": {"ttps": ["T1595", "T1046"], "cves": ["CVE-2024-3400"], "intrusion_sets": ["APT|1"]},
    "sources": [
        {
            "url": "https://attack.mitre.org/techniques/T1595/",
            "tlp": "TLP:CLEAR",
            "title": "T1595 [x]",
        },
        {"url": "https://example.org/report", "tlp": "TLP:CLEAR"},
    ],
    "targets": [{"placeholder": "web-hosts", "description": "The hosts, by FQDN."}],
    "requires": {
        "openaev": ">=3.261005.0",
        "edition": "CE",
        "injectors": ["openaev_nmap"],
        "executors": ["openaev_implant", "caldera"],
    },
    "payloads": [],
}


def _after(parent: object, child: str) -> object:
    """A dependency as the platform exports it: the parent's ID in a relationship."""
    relationship = {"inject_parent_id": parent, "inject_children_id": child}
    return {"dependency_relationship": relationship, "dependency_condition": {"mode": "and"}}


def inject(
    identifier: str, title: str, seconds: object, *after: str, **contract: Any
) -> dict[str, Any]:
    return {
        "inject_id": identifier,
        "inject_title": title,
        "inject_depends_duration": seconds,
        "inject_depends_on": [_after(parent, identifier) for parent in after],
        "inject_injector_contract": {"injector_contract_injector_type": "openaev_nmap", **contract},
    }


STORED: dict[str, Any] = {
    "scenario_injects": [
        inject("b", "Second | scan", 90, "a"),
        inject(
            "a",
            "First scan",
            0,
            injector_contract_payload={
                "payload_name": "List shares",
                "payload_external_id": "p-1",
                "payload_type": "Command",
                "payload_platforms": ["Windows", "Linux"],
                "command_content": "net share",
            },
        ),
    ]
}
EXCEPTION = PolicyException(
    ID, "POL-006", "/scenario_injects/1/x", "a" * 64, "The product is named on purpose."
)

EXPECTED = (
    NOTICE
    + r"""

# Scan \*everything\*

Version 1\.2\.0 · VERIFIED · time\-based

Scans the hosts\.\
\- one

See `https://example.com/a.`

## At a glance

|  |  |
|---|---|
| External ID | 5b9a2c84\-3a0e\-4c55\-9a8c\-2a6f0d7e1b42 |
| Severity | high |
| Category | attack\-scenario |
| Main focus | endpoint\-protection |
| Platforms | Linux, Windows |

## Threat

- Techniques: T1595, T1046
- CVEs: CVE\-2024\-3400
- Intrusion sets: APT\|1

## Sources

- [T1595 \[x\]](<https://attack.mitre.org/techniques/T1595/>) \(attack\.mitre\.org\)
- [`https://example.org/report`](<https://example.org/report>) \(example\.org\)

## Requirements

- OpenAEV: \>\=3\.261005\.0
- Edition: CE
- Injectors: openaev\_nmap
- Executors: openaev\_implant, caldera

## Chain of injects

| # | From start | After | Title | Injector |
|---|---|---|---|---|
| 1 | 0 s |  | First scan | openaev\_nmap |
| 2 | 1 min 30 s | 1 | Second \| scan | openaev\_nmap |

## Payloads

| Name | ID | Type | Platforms |
|---|---|---|---|
| List shares | p\-1 | Command | Windows, Linux |

## Targets to fill in

- web\-hosts: The hosts\, by FQDN\.

## Policy exceptions

| Rule | Field | Why |
|---|---|---|
| POL\-006 | \/scenario\_injects\/1\/x | The product is named on purpose\. |

## Versions

What each version changed is in [CHANGELOG.md](CHANGELOG.md).
"""
)


def test_the_sheet_says_what_a_reader_needs_as_plain_text() -> None:
    assert render_sheet(METADATA, STORED, (EXCEPTION,)) == EXPECTED


def test_the_sheet_never_shows_a_command() -> None:
    assert "net share" not in render_sheet(METADATA, STORED, ())


def test_rendering_again_gives_the_same_sheet() -> None:
    assert render_sheet(copy.deepcopy(METADATA), copy.deepcopy(STORED), ()) == render_sheet(
        METADATA, STORED, ()
    )


def test_an_entry_with_less_says_so() -> None:
    metadata = {
        key: value for key, value in METADATA.items() if key not in {"targets", "threat"}
    } | {"threat": {"ttps": ["T1595"]}, "requires": {**METADATA["requires"], "injectors": []}}

    sheet = render_sheet(metadata, {"scenario_injects": []}, ())

    assert "- Techniques: T1595\n\n## Sources" in sheet  # no CVE, no intrusion set
    assert "- Injectors: none\n" in sheet
    assert "## Chain of injects\n\nNone.\n" in sheet
    assert "## Payloads\n\nNone.\n" in sheet
    assert "## Targets to fill in\n\nNone: the scenario needs no target of the platform.\n" in sheet
    assert "## Policy exceptions" not in sheet


@pytest.mark.parametrize(
    ("source", "line"),
    [
        ({"url": 1, "tlp": "TLP:CLEAR"}, "- —"),
        (
            {"url": "https://a b.example", "tlp": "TLP:CLEAR", "title": "T"},
            "- `https://a` b\\.example",
        ),
        ({"url": "http://x.example", "tlp": "TLP:CLEAR"}, "- `http://x.example`"),
        (
            {"url": "https://good.example@evil.example/", "tlp": "TLP:CLEAR", "title": "Good"},
            "- `https://good.example@evil.example/`",  # a user before the host: never a link
        ),
        ({"url": "https://%67oogle.com/", "tlp": "TLP:CLEAR"}, "- `https://%67oogle.com/`"),
        ({"url": "https://[::1]/x", "tlp": "TLP:CLEAR"}, "- `https://[::1]/x`"),
        ({"url": "  https://a b", "tlp": "TLP:CLEAR"}, "- `https://a` b"),  # never a code block
        (
            {"url": "https://x.example/", "tlp": "TLP:CLEAR", "title": "  "},
            "- [`https://x.example/`](<https://x.example/>) \\(x\\.example\\)",  # no title
        ),
        (
            {"url": "https://evil.example/", "tlp": "TLP:CLEAR", "title": "https://www.nist.gov/"},
            "- [`https://www.nist.gov/`](<https://evil.example/>) \\(evil\\.example\\)",
        ),
        (
            {"url": "https://x.example/?a&amp;b=1", "tlp": "TLP:CLEAR"},
            "- [`https://x.example/?a&amp;b=1`](<https://x.example/?a&amp;amp;b=1>) "
            "\\(x\\.example\\)",
        ),
    ],
)
def test_a_source_that_is_no_https_address_is_shown_as_text(
    source: dict[str, Any], line: str
) -> None:
    sheet = render_sheet({**METADATA, "sources": [source]}, STORED, ())

    assert f"## Sources\n\n{line}\n" in sheet


@pytest.mark.parametrize("platforms", ["Linux", None, [1, "Linux"]])
def test_a_list_that_is_no_list_of_texts_shows_its_texts_only(platforms: object) -> None:
    sheet = render_sheet({**METADATA, "platforms": platforms}, STORED, ())

    expected = "Linux" if isinstance(platforms, list) else "none"
    assert f"| Platforms | {expected} |" in sheet


def test_only_the_entry_s_own_exceptions_are_shown() -> None:
    other = PolicyException(
        "0f6a8d2e-1b3c-4d5e-8f90-a1b2c3d4e5f6", "POL-004", "/x", "b" * 64, "Another entry's reason."
    )

    assert "Another entry" not in render_sheet(METADATA, STORED, (other,))


def _rows(stored: dict[str, Any]) -> list[list[str]]:
    sheet = render_sheet(METADATA, stored, ())
    chain = sheet.split("## Chain of injects\n\n")[1].split("\n\n")[0].splitlines()[2:]
    return [row.strip("| ").split(" | ") for row in chain]


def test_the_injects_follow_their_time_then_their_title_then_their_id() -> None:
    stored = {
        "scenario_injects": [
            inject("z", "Same", 10, injector_contract_injector_type="z-type"),
            inject("y", "Same", 10, injector_contract_injector_type="y-type"),
            inject("a", "Zulu", 10),
            inject("b", "Alpha", 10),
            inject("c", "Later", 11),
            inject("d", "Start", 0),
            inject("w", "Zz odd", "soon"),
        ]
    }

    rows = _rows(stored)

    assert [(row[1], row[3], row[4]) for row in rows] == [
        ("—", "Zz odd", "openaev\\_nmap"),  # a time that is no number comes first
        ("0 s", "Start", "openaev\\_nmap"),
        ("10 s", "Alpha", "openaev\\_nmap"),
        ("10 s", "Same", "y\\-type"),  # then by ID
        ("10 s", "Same", "z\\-type"),
        ("10 s", "Zulu", "openaev\\_nmap"),
        ("11 s", "Later", "openaev\\_nmap"),
    ]
    assert [row[0] for row in rows] == ["1", "2", "3", "4", "5", "6", "7"]


def test_a_title_or_id_that_is_no_text_sorts_as_empty() -> None:
    stored = {
        "scenario_injects": [
            {"inject_id": "b", "inject_title": "Alpha", "inject_depends_duration": 5},
            {"inject_id": "a", "inject_title": ["x"], "inject_depends_duration": 5},
            {"inject_id": ["c"], "inject_title": "Alpha", "inject_depends_duration": 5},
        ]
    }

    assert [row[3] for row in _rows(stored)] == ["—", "Alpha", "Alpha"]
    assert [row[4] for row in _rows(stored)] == ["—", "—", "—"]


def test_an_inject_after_several_lists_them_all() -> None:
    stored = {
        "scenario_injects": [
            inject("a", "A", 0),
            inject("b", "B", 1),
            inject("c", "C", 2, "b", "a"),
        ]
    }

    assert _rows(stored)[2][2] == "1, 2"


def test_a_dependency_that_names_no_inject_is_left_out() -> None:
    odd: list[object] = ["a", {"dependency_relationship": "a"}, {"x": 1}, _after(["a"], "b")]
    second = {**inject("b", "B", 1), "inject_depends_on": [_after("a", "b"), *odd]}
    stored = {"scenario_injects": [inject("a", "A", 0), second]}

    assert _rows(stored)[1][2] == "1"


@pytest.mark.parametrize("injects", ["abc", {"a": 1}, None])
def test_injects_that_are_no_list_are_none(injects: object) -> None:
    assert "## Chain of injects\n\nNone.\n" in render_sheet(
        METADATA, {"scenario_injects": injects}, ()
    )


def test_an_inject_of_an_odd_shape_is_shown_as_far_as_it_can_be() -> None:
    stored = {
        "scenario_injects": [
            {"inject_id": "a", "inject_title": ["x"], "inject_injector_contract": "x"},
            "not an inject",
            {
                "inject_id": "b",
                "inject_depends_on": [_after("a", "b"), _after("unknown", "b")],
                "inject_depends_duration": 5,
            },
        ]
    }

    sheet = render_sheet(METADATA, stored, ())

    assert "| 1 | — |  | — | — |" in sheet
    assert "| 2 | 5 s | 1 | — | — |" in sheet


@pytest.mark.parametrize(
    ("seconds", "shown"),
    [
        (0, "0 s"),
        (45, "45 s"),
        (60, "1 min"),
        (125, "2 min 5 s"),
        (3600, "1 h"),
        (5400, "1 h 30 min"),
        (90061, "1 d 1 h 1 min 1 s"),
        (1.5, "—"),
        (-1, "—"),
        (True, "—"),
        (None, "—"),
    ],
)
def test_a_time_is_shown_in_days_hours_minutes_and_seconds(seconds: object, shown: str) -> None:
    assert duration(seconds) == shown


def test_an_inject_without_an_identifier_is_after_nothing_and_nothing_after_it() -> None:
    nameless = {"inject_title": "A", "inject_depends_duration": 0}
    stored = {"scenario_injects": [nameless, inject("b", "B", 1, "")]}

    assert _rows(stored)[1][2] == ""


def test_every_target_is_listed() -> None:
    targets = [
        {"placeholder": "web-hosts", "description": "The hosts."},
        {"placeholder": "mail", "description": "A mailbox."},
        "not a target",
    ]

    sheet = render_sheet({**METADATA, "targets": targets}, STORED, ())

    assert "## Targets to fill in\n\n- web\\-hosts: The hosts\\.\n- mail: A mailbox\\.\n" in sheet


@pytest.mark.parametrize("value", [None, {}, "x", 3])
def test_a_part_missing_or_of_another_shape_says_none(value: object) -> None:
    metadata = {
        **METADATA,
        "description": value,
        "threat": value,
        "sources": value,
        "requires": value,
    }

    sheet = render_sheet(metadata, STORED, ())

    shown = "x\n\n" if value == "x" else ""  # a text is a description
    assert f"· time\\-based\n\n{shown}## At a glance" in sheet
    assert "## Threat\n\nNone.\n" in sheet
    assert "## Sources\n\nNone.\n" in sheet
    assert "## Requirements\n\n- OpenAEV: —\n- Edition: —\n- Injectors: none\n" in sheet


def test_a_blank_description_is_left_out() -> None:
    sheet = render_sheet({**METADATA, "description": "  \n "}, STORED, ())

    assert "· time\\-based\n\n## At a glance" in sheet


def test_at_the_same_time_an_inject_comes_after_those_it_runs_after() -> None:
    """A cleanup after an exfiltration, both at 12 minutes, is listed after it, whatever their
    titles; a cycle, which the platform refuses, never loops."""
    stored = {
        "scenario_injects": [
            inject("c", "Cleanup", 720, "e"),
            inject("e", "Exfiltrate", 720, "d"),
            inject("d", "Discover", 600),
            inject("x", "Loop one", 900, "y"),
            inject("y", "Loop two", 900, "x"),
        ]
    }

    rows = _rows(stored)

    assert [(row[3], row[2]) for row in rows[:3]] == [
        ("Discover", ""),
        ("Exfiltrate", "1"),
        ("Cleanup", "2"),
    ]
    assert sorted((row[3], row[2]) for row in rows[3:]) in (  # either way round, never a loop
        [("Loop one", "5"), ("Loop two", "4")],
        [("Loop one", "4"), ("Loop two", "5")],
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://good.example/?token&equals;abc&sol;x&#x40;y",
        "https://good.example/a?b=1&c=2#f",
        "https://good.example/%41&amp;",
        "https://good.example:8443/a",
    ],
)
def test_a_source_link_goes_where_its_address_says(url: str) -> None:
    """An entity in an address is never decoded on the way: the link is the address checked."""
    parser = MarkdownIt("commonmark")
    sheet = render_sheet({**METADATA, "sources": [{"url": url, "tlp": "TLP:CLEAR"}]}, STORED, ())

    links = [
        child.attrs["href"]
        for token in parser.parse(sheet)
        for child in token.children or []
        if child.type == "link_open"
    ]

    assert url in links


@pytest.mark.timing
def test_an_inject_after_thousands_of_others_is_ordered_in_linear_time() -> None:
    """Each dependency is followed once: a scenario with many parents never hangs a run."""
    parents = [inject(f"p{index:05}", "P", 0) for index in range(20_000)]
    top = inject("top", "Top", 0, *(f"p{index:05}" for index in range(20_000)))
    started = time.perf_counter()

    rows = _rows({"scenario_injects": [top, *parents]})

    assert time.perf_counter() - started < 3.0
    assert rows[-1][3] == "Top"


def test_a_chain_s_depths_count_its_links() -> None:
    """First a plain chain, which any slip in following parents gets wrong at once."""
    chain = [inject("c", "C", 0, "e"), inject("e", "E", 0, "d"), inject("d", "D", 0)]

    assert depths(chain) == {"c": 2, "e": 1, "d": 0}


def test_an_inject_after_a_short_and_a_long_chain_is_after_the_longest() -> None:
    """Placed once its last parent is: never before its deepest one, nor are its children."""
    injects = [
        inject("d0", "D0", 0),
        inject("r", "R", 0),
        inject("p1", "P1", 0, "d0"),
        inject("p2", "P2", 0, "p1"),
        inject("p3", "P3", 0, "p2"),
        inject("c", "C", 0, "r", "p3"),
        inject("g", "G", 0, "c"),
    ]

    assert depths(injects) == {"d0": 0, "r": 0, "p1": 1, "p2": 2, "p3": 3, "c": 4, "g": 5}


def test_a_cycle_never_hangs_and_takes_the_depths_of_the_parents_known_before_it() -> None:
    """The platform refuses a cycle; met anyway, its injects follow the list's order."""
    assert depths([inject("x", "X", 0, "y"), inject("y", "Y", 0, "x")]) == {"x": 0, "y": 1}


def test_each_inject_s_depth_is_its_longest_chain_of_parents() -> None:
    """An inject after a cycle, which the platform refuses, never hangs either; an unknown
    parent, a parent named twice or the inject itself counts for nothing."""
    injects = [
        inject("c", "C", 0, "e"),
        inject("e", "E", 0, "d", "unknown", "d", "e"),
        inject("d", "D", 0),
        inject("s", "S", 0, "a"),
        inject("a", "A", 0, "b"),
        inject("b", "B", 0, "a"),
    ]

    assert depths(injects) == {"c": 2, "e": 1, "d": 0, "s": 0, "a": 0, "b": 1}


def test_an_empty_payload_is_no_payload() -> None:
    """As the export and its normalisation read it."""
    stored = {"scenario_injects": [inject("a", "A", 0, injector_contract_payload={})]}

    assert "## Payloads\n\nNone.\n" in render_sheet(METADATA, stored, ())


def test_the_sheet_limit_is_the_one_a_readme_is_read_with() -> None:
    assert SHEET_LIMIT == TEXT_LIMIT


def test_an_item_that_is_not_an_object_is_left_out_of_the_chain() -> None:
    rows = _rows({"scenario_injects": ["x", inject("a", "Alpha", 0)]})

    assert len(rows) == 1
    assert "Alpha" in rows[0]
