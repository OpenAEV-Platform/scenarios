"""The registry: every rule once, in code order, each finding with its rule's code and severity,
and every rule proven by a passing and a failing entry."""

import re
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.policy.registry import RULES, findings_of, policy_findings, rule_findings
from scenario_tools.domain.policy.rule import EntryContent, Rule, Violation
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, Severity
from tests.domain.policy.cases import CASES, DATA, ENTRY, content

_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=20), children, max_size=4)
    ),
    max_leaves=12,
)
_SHAPES = _JSON | st.fixed_dictionaries(
    {
        "sources": st.lists(st.fixed_dictionaries({"url": _JSON}) | _JSON, max_size=3),
        "scenario_information": st.dictionaries(
            st.sampled_from(
                ["scenario_recurrence", "scenario_recurrence_start", "scenario_recurrence_end"]
            )
            | st.text(max_size=10),
            _JSON,
        ),
    }
)


def test_every_rule_is_registered_once_in_code_order() -> None:
    codes = [rule.code for rule in RULES]

    assert codes == sorted(set(codes))
    assert all(re.fullmatch(r"POL-[0-9]{3}", code) for code in codes)


def test_every_rule_states_what_it_refuses() -> None:
    assert all(rule.statement.strip() for rule in RULES)


def test_every_rule_has_a_passing_and_a_failing_entry() -> None:
    assert set(CASES) == {rule.code for rule in RULES}


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.code)
def test_the_passing_entry_passes_and_the_failing_one_fails_on_this_rule_only(rule: Rule) -> None:
    passing, failing = CASES[rule.code]

    assert policy_findings(DATA, passing) == ()
    assert {finding.code for finding in policy_findings(DATA, failing)} == {rule.code}


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.code)
def test_a_finding_carries_its_rule_s_code_and_severity(rule: Rule) -> None:
    findings = policy_findings(DATA, CASES[rule.code][1])

    assert findings
    assert all((f.code, f.severity) == (rule.code, rule.severity) for f in findings)


def test_findings_of_turns_violations_into_findings_of_the_rule() -> None:
    rule = Rule("POL-999", Severity.INFO, "A test rule.", lambda _data, _content: ())
    violations = (Violation(f"{ENTRY}/scenario.yaml", "/name", "a message"),)

    (finding,) = findings_of(rule, violations)

    assert (finding.code, finding.severity, finding.path, finding.field, finding.message) == (
        "POL-999",
        Severity.INFO,
        f"{ENTRY}/scenario.yaml",
        "/name",
        "a message",
    )


def test_the_rules_run_in_code_order() -> None:
    failing = content(
        files=frozenset({"scenario.yaml", "scenario.json", "report.pdf"}),
        stored={"scenario_information": {"scenario_recurrence": "0 0 8 * * MON"}},
    )

    assert [finding.code for finding in policy_findings(DATA, failing)] == ["POL-001", "POL-002"]


_URLS = st.builds(
    lambda authority, rest: "https://" + authority + rest,
    st.text(alphabet="abcxyz019.-:@[]%_", max_size=24),
    st.text(alphabet="/?#=&;atokensigkey%", max_size=24),
)
_NAMES = st.text(
    alphabet="ab.-_ /\\" + chr(0x7) + chr(0x202E) + chr(0xDCFF), min_size=0, max_size=8
)


_OWN = "CHANGELOG.md, README.md, scenario.json, scenario.yaml"
_KNOWN = (
    r"the source link (holds user information|has an IP address as its host|has no host"
    r"|has a local, internal or reserved host"
    r"|has a host with no dot, which only a local network resolves"
    r"|has a host that is not a public DNS name"
    r"|carries a credential in its query or fragment)"
    r": link a public page that any reader can open",
    rf"this file is not one of the entry's own \({_OWN}\): sources are linked, never copied "
    r"into an entry",
    r"the entry holds [0-9]+ files? whose name cannot be shown safely, besides its own files "
    rf"\({_OWN}\): sources are linked, never copied into an entry",
    r"scenario_recurrence(_start|_end)? is set: the importer would schedule the scenario, which "
    r"the catalogue never does",
    r"this command [a-z ,]+, which a shared scenario never does: remove it",
    r"this payload changes the endpoint \(it writes, creates or starts something\) but has no "
    r"cleanup command with an executor: add one that undoes it",
    r"this command is longer than 65536 characters, too long to check: shorten it",
    r"this value names a host outside the example names, test addresses and authorised "
    r"targets: use an example name, such as host\.example\.com, or a test address",
)


@given(
    declared=_SHAPES
    | st.fixed_dictionaries({"sources": st.lists(st.fixed_dictionaries({"url": _URLS}))}),
    stored=_SHAPES,
    files=st.frozensets(_NAMES, max_size=6),
)
def test_every_finding_stays_in_the_entry_bounded_and_quotes_nothing(
    declared: Any, stored: object, files: frozenset[str]
) -> None:
    content = EntryContent(ENTRY, files, declared, stored)

    findings = policy_findings(DATA, content)

    assert policy_findings(DATA, content) == findings  # the same, run after run
    for finding in findings:
        assert finding.path == ENTRY or finding.path.startswith(f"{ENTRY}/")
        assert len(finding.message) <= MESSAGE_LIMIT
        assert any(re.fullmatch(known, finding.message) for known in _KNOWN)  # quotes nothing


def test_one_rule_can_be_asked_alone() -> None:
    failing = content(
        files=frozenset({"scenario.yaml", "report.pdf"}),
        stored={"scenario_information": {"scenario_recurrence": "0 0 8 * * MON"}},
    )

    assert [f.code for f in rule_findings("POL-002", DATA, failing)] == ["POL-002"]
    assert [f.code for f in rule_findings("POL-001", DATA, failing)] == ["POL-001"]


def test_asking_a_rule_that_does_not_exist_is_a_defect() -> None:
    with pytest.raises(ValueError, match="not enough values to unpack"):
        rule_findings("POL-999", DATA, content())
