"""One passing and one failing entry for every policy rule, as every rule must have."""

from typing import Any

from scenario_tools.domain.policy.actions import forbidden_from_document, side_effects_from_document
from scenario_tools.domain.policy.rule import EntryContent, PolicyData
from scenario_tools.domain.policy.targets import AllowedTargets
from scenario_tools.domain.policy.vendors import vendors_from_document

ENTRY = "scenarios/techniques/easm"
OWN_FILES = frozenset({"scenario.yaml", "scenario.json"})
METADATA: dict[str, Any] = {
    "sources": [{"url": "https://attack.mitre.org/techniques/T1595/", "tlp": "TLP:CLEAR"}]
}
SCENARIO: dict[str, Any] = {"scenario_information": {"scenario_name": "EASM"}}
TARGETS: dict[str, Any] = {
    "domains": [
        "example",
        "example.com",
        "example.net",
        "example.org",
        "test",
        "invalid",
        "localhost",
    ],
    "networks": [
        "127.0.0.0/8",
        "::1/128",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    ],
    "lab_networks": ["10.42.0.0/16"],
    "external_targets": ["scanme.nmap.org"],
}
FORBIDDEN: dict[str, Any] = {
    "actions": [
        {"steps": [r"\bvssadmin\b", r"\bdelete\b"], "why": "deletes shadow copies"},
        {
            "steps": [r"\bset-mppreference\b", r"\s-disable\w*[\s:]+(\$true|1)\b"],
            "why": "turns off an antivirus protection",
            "restore": [r"set-mppreference\b", r"\s-disable\w*[\s:]+(\$false|0)\b"],
        },
        {"steps": [r"\bformat(\.com)?\s+[a-z]:"], "why": "formats a disk"},
    ]
}
SIDE_EFFECTS: dict[str, Any] = {
    "commands": [
        [r"\b(copy|expand|new-item|set-content)\b"],
        [r"\bsc(\.exe)?\s+create\b"],
        [r"\bcurl\b", r"\s(-[a-z]{0,10}o|--output)(=|\s?)(?!/dev/null\b)\S"],
        [r"(^|[^<>])\d?>{1,2}+\s*+(?!\$null|nul\b|/dev/null|&)\S"],
        [r"\bsed\b", r"\s-\w{0,10}i\b"],
    ]
}
VENDORS: dict[str, Any] = {
    "products": ["crowdstrike", "carbon black", "trend micro", "sentinel one"],
    "words": ["eset", "tanium"],
}
DATA = PolicyData(
    AllowedTargets.from_document(TARGETS),
    forbidden_from_document(FORBIDDEN),
    side_effects_from_document(SIDE_EFFECTS),
    vendors_from_document(VENDORS),
)
PAYLOAD = "/scenario_injects/0/inject_injector_contract/injector_contract_payload"


def content(
    *,
    files: frozenset[str] = OWN_FILES,
    declared: Any = METADATA,
    stored: object = SCENARIO,
) -> EntryContent:
    return EntryContent(ENTRY, files, declared, stored)


def with_source(url: str) -> EntryContent:
    return content(declared={"sources": [{"url": url, "tlp": "TLP:CLEAR"}]})


def with_recurrence(field: str, value: object) -> EntryContent:
    return content(stored={"scenario_information": {"scenario_name": "EASM", field: value}})


def with_inject_content(inject_content: object) -> EntryContent:
    return content(
        stored={
            "scenario_information": {"scenario_name": "EASM"},
            "scenario_injects": [{"inject_content": inject_content}],
        }
    )


def with_payload(**payload: object) -> EntryContent:
    return content(
        stored={
            "scenario_information": {"scenario_name": "EASM"},
            "scenario_injects": [
                {"inject_injector_contract": {"injector_contract_payload": payload}}
            ],
        }
    )


def timed(*injects: tuple[int, bool], kind: str = "time-based", **payload: object) -> EntryContent:
    """A scenario of ``kind`` whose injects start at the given offsets, each embedding a payload
    or not."""
    return content(
        declared={**METADATA, "type": kind},
        stored={
            "scenario_information": {"scenario_name": "EASM"},
            "scenario_injects": [
                {
                    "inject_depends_duration": offset,
                    "inject_injector_contract": (
                        {"injector_contract_payload": {"command_content": "whoami", **payload}}
                        if embeds
                        else {}
                    ),
                }
                for offset, embeds in injects
            ],
        },
    )


CASES: dict[str, tuple[EntryContent, EntryContent]] = {
    "POL-001": (content(), with_source("https://10.0.0.1/report.html")),
    "POL-002": (content(), with_recurrence("scenario_recurrence", "0 0 8 * * MON")),
    "POL-003": (
        with_inject_content({"targets": "192.0.2.10"}),
        with_inject_content({"targets": "10.0.0.5"}),
    ),
    "POL-004": (
        with_payload(command_content="vssadmin list shadows"),
        with_payload(command_content="vssadmin delete shadows /all /quiet"),
    ),
    "POL-006": (
        with_payload(command_content="whoami"),
        with_payload(command_content="sc query CrowdStrike"),
    ),
    "POL-007": (
        with_payload(payload_elevation_required=False),
        with_payload(payload_elevation_required=True),
    ),
    "POL-009": (timed((0, True), (60, True)), timed((0, True), (30, True))),
    "POL-010": (
        content(stored={"scenario_information": {"scenario_mail_from": "a@example.org"}}),
        content(stored={"scenario_information": {"scenario_mail_from": "a@corp.com"}}),
    ),
    "POL-005": (
        with_payload(
            command_content="copy a b",
            payload_cleanup_command="del b",
            payload_cleanup_executor="cmd",
        ),
        with_payload(command_content="copy a b"),
    ),
}
