"""Pinned Nuclei templates: a template fetched from a link comes over https from a repository the
maintainers allow, at a full commit hash, never a branch or a tag; the allowed targets leave the
link to this rule.

Characters are written by code point, never raw, so that this file holds none of them."""

from typing import Any

import pytest

from scenario_tools.domain.policy.registry import policy_findings
from scenario_tools.domain.policy.rule import PolicyData
from scenario_tools.domain.policy.rules.templates import RULE
from scenario_tools.domain.policy.templates import PinnedTemplate, TemplateSources
from scenario_tools.domain.shared.finding import MESSAGE_LIMIT, Finding, Severity
from tests.domain.policy.cases import (
    COMMIT,
    DATA,
    ENTRY,
    PINNED,
    SCENARIO,
    TEMPLATES,
    content,
    with_inject_content,
)

JSON = f"{ENTRY}/scenario.json"
FIELD = "/scenario_injects/0/inject_content/template_url"
RAW = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates"
PATH = "http/cves/2023/CVE-2023-22515.yaml"
NOT_HTTPS = "does not start with https://"
NOT_ALLOWED = "does not lead to a repository that policy/data/nuclei-templates.yaml allows"
NOT_PINNED = (
    "is not pinned to a commit's full hash, 40 hexadecimal characters in lower case: a branch "
    "or a tag can move after the review"
)
NOT_PLAIN = (
    "has a path that is not plain (only letters, digits and . _ ~ + - between single slashes, "
    "no . or .. segment, no query nor fragment)"
)
NOT_TEXT = "is not a text"
WHAT_TO_DO = (
    "use a template of an allowed repository, pinned to a commit: "
    "https://raw.githubusercontent.com/<owner>/<repository>/<commit>/<path>"
)


def _sources() -> TemplateSources:
    """Read inside each test, so that a change to the reading is seen by the test."""
    return TemplateSources.from_document(TEMPLATES)


def _message(problem: str) -> str:
    return f"this Nuclei template link {problem}; {WHAT_TO_DO}"


def _found(findings: tuple[Finding, ...]) -> list[tuple[str, str, str]]:
    return [(f.code, f.field, f.message) for f in findings]


def test_the_rule_is_pol_012_and_blocks() -> None:
    assert (RULE.code, RULE.severity) == ("POL-012", Severity.BLOCKING)


# Reading the data.


def test_the_list_is_read() -> None:
    assert _sources() == TemplateSources(("projectdiscovery/nuclei-templates",))


def test_an_empty_list_allows_no_link() -> None:
    sources = TemplateSources.from_document({"github_repositories": []})

    assert sources == TemplateSources(())
    assert sources.problem(PINNED) == NOT_ALLOWED


def test_without_the_data_no_link_is_allowed() -> None:
    data = PolicyData(DATA.targets, DATA.forbidden, DATA.side_effects, DATA.vendors)

    assert data.templates.problem(PINNED) == NOT_ALLOWED


def test_the_document_must_be_a_mapping() -> None:
    with pytest.raises(ValueError, match=r"^nuclei-templates: the document must be a mapping$"):
        TemplateSources.from_document([])


def test_unknown_keys_are_named_in_order() -> None:
    document: dict[Any, Any] = {**TEMPLATES, "b": [], 1: [], "a": []}

    with pytest.raises(ValueError, match=r"^nuclei-templates: unknown keys 1, a, b$"):
        TemplateSources.from_document(document)


@pytest.mark.parametrize(
    "listed",
    [
        None,  # missing
        "projectdiscovery/nuclei-templates",
        [1],
        ["projectdiscovery/nuclei-templates", "projectdiscovery/nuclei-templates"],
    ],
)
def test_the_list_must_hold_distinct_texts(listed: object) -> None:
    document = {} if listed is None else {"github_repositories": listed}

    with pytest.raises(
        ValueError,
        match=r"^nuclei-templates: github_repositories must be a list of distinct texts$",
    ):
        TemplateSources.from_document(document)


@pytest.mark.parametrize(
    "repository",
    [
        "",
        "projectdiscovery",  # no repository
        "ProjectDiscovery/nuclei-templates",  # not in lower case
        "projectdiscovery/Nuclei-Templates",
        "projectdiscovery/nuclei-templates/main",  # a branch, or a path
        "projectdiscovery/",
        "/nuclei-templates",
        "-projectdiscovery/nuclei-templates",  # an account starts with a letter or a digit
        "a" * 40 + "/nuclei-templates",  # an account has 39 characters at most
        "projectdiscovery-/nuclei-templates",  # an account's hyphen is inside it
        "project--discovery/nuclei-templates",  # and single
        "a-" * 19 + "ab/nuclei-templates",  # 40 characters, hyphens included
        "projectdiscovery/" + "a" * 101,  # a repository has 100 characters at most
        "projectdiscovery/.",
        "projectdiscovery/..",
        "projectdiscovery/nuclei templates",
        "raw.githubusercontent.com/projectdiscovery/nuclei-templates",
        "projectdiscovery/nuclei-templates\n",
    ],
)
def test_a_malformed_repository_is_refused(repository: str) -> None:
    with pytest.raises(
        ValueError,
        match=r"^nuclei-templates: github_repositories must hold <owner>/<repository> names "
        r"in lower case$",
    ):
        TemplateSources.from_document({"github_repositories": [repository]})


@pytest.mark.parametrize(
    "repository",
    [
        "a/b",
        "a" * 39 + "/" + "b" * 100,
        "a-" * 19 + "a/b",  # 39 characters, hyphens included
        "my-org/.github",
        "my-org/a..b",
        "0x/n_u.c-l",
        "a-b-c/d",
    ],
)
def test_a_repository_as_github_names_it_is_read(repository: str) -> None:
    assert TemplateSources.from_document({"github_repositories": [repository]}).repositories == (
        repository,
    )


# Reading a link.


@pytest.mark.parametrize(
    "link",
    [
        PINNED,
        f"https://github.com/projectdiscovery/nuclei-templates/raw/{COMMIT}/{PATH}",
        f"{RAW}/{COMMIT}/a-b_c.d~e+f/x.yaml",  # every character a path may hold
        f"{RAW}/{COMMIT}/x.yaml",
        f"{RAW}/{COMMIT}/..a/b.",  # dots inside a segment are no dot segment
    ],
)
def test_a_pinned_template_of_an_allowed_repository_is_allowed(link: str) -> None:
    assert _sources().problem(link) is None


def test_another_allowed_repository_is_read_from_the_data() -> None:
    sources = TemplateSources.from_document(
        {"github_repositories": ["projectdiscovery/nuclei-templates", "my-org/templates"]}
    )

    assert (
        sources.problem(f"https://raw.githubusercontent.com/my-org/templates/{COMMIT}/x.yaml")
        is None
    )
    assert sources.problem(f"https://github.com/my-org/templates/raw/{COMMIT}/x.yaml") is None
    assert sources.problem(PINNED) is None


@pytest.mark.parametrize(
    "link",
    [
        PINNED.replace("https://", "http://"),
        PINNED.replace("https://", "HTTPS://"),
        PINNED.replace("https://", "https:/"),
        " " + PINNED,
        "//raw.githubusercontent.com/projectdiscovery/nuclei-templates/" + COMMIT + "/" + PATH,
        "raw.githubusercontent.com/projectdiscovery/nuclei-templates/" + COMMIT + "/" + PATH,
        "file:///tmp/template.yaml",
        "ftp://example.com/x.yaml",
    ],
)
def test_a_link_that_is_not_https_is_refused(link: str) -> None:
    assert _sources().problem(link) == NOT_HTTPS


@pytest.mark.parametrize(
    "link",
    [
        # Another account or repository, or one of the same name with more to it.
        "https://raw.githubusercontent.com/Ademking/php2shell-nuclei-templates/refs/heads/main"
        "/templates/php2shell/CVE-2026-109618.yaml",
        f"https://raw.githubusercontent.com/someone/nuclei-templates/{COMMIT}/{PATH}",
        f"https://raw.githubusercontent.com/projectdiscovery/templates/{COMMIT}/{PATH}",
        f"{RAW}-extra/{COMMIT}/{PATH}",
        f"https://raw.githubusercontent.com/projectdiscovery-x/nuclei-templates/{COMMIT}/{PATH}",
        f"https://raw.githubusercontent.com/projectdiscovery/{COMMIT}/{PATH}",
        f"https://raw.githubusercontent.com/{COMMIT}/{PATH}",
        # A host that looks like GitHub's, or GitHub's with something before or after it.
        f"https://raw.githubusercontent.com.evil.test/projectdiscovery/nuclei-templates/{COMMIT}"
        f"/{PATH}",
        f"https://raw.githubusercontent.com@evil.test/projectdiscovery/nuclei-templates/{COMMIT}"
        f"/{PATH}",
        f"https://user@raw.githubusercontent.com/projectdiscovery/nuclei-templates/{COMMIT}/{PATH}",
        f"https://raw.githubusercontent.com\\@evil.test/projectdiscovery/nuclei-templates/{COMMIT}"
        f"/{PATH}",
        f"https://raw.githubusercontent.com:443/projectdiscovery/nuclei-templates/{COMMIT}/{PATH}",
        f"https://raw.githubusercontent.com./projectdiscovery/nuclei-templates/{COMMIT}/{PATH}",
        f"https://evil.test/raw.githubusercontent.com/projectdiscovery/nuclei-templates/{COMMIT}"
        f"/{PATH}",
        f"https://rawgithubusercontent.com/projectdiscovery/nuclei-templates/{COMMIT}/{PATH}",
        f"https://www.github.com/projectdiscovery/nuclei-templates/raw/{COMMIT}/{PATH}",
        f"https://gist.githubusercontent.com/projectdiscovery/nuclei-templates/{COMMIT}/{PATH}",
        # Case: the link is compared as written.
        PINNED.replace("raw.githubusercontent.com", "RAW.githubusercontent.com"),
        PINNED.replace("projectdiscovery", "ProjectDiscovery"),
        PINNED.replace("nuclei-templates", "Nuclei-Templates"),
        # Percent-encoding and look-alike characters: never decoded nor folded.
        PINNED.replace("projectdiscovery/nuclei-templates", "projectdiscovery%2Fnuclei-templates"),
        PINNED.replace("raw.githubusercontent.com", "raw%2Egithubusercontent.com"),
        PINNED.replace("nuclei-templates", "nuclei%2Dtemplates"),
        PINNED.replace("raw.githubusercontent.com", "raw\uff0egithubusercontent\uff0ecom"),
        PINNED.replace("projectdiscovery", "pr\u043ejectdiscovery"),  # a Cyrillic o
        PINNED.replace("/projectdiscovery", "/\u200bprojectdiscovery"),  # an invisible space
        # GitHub's pages, not the template itself, and a link that only names the repository.
        f"https://github.com/projectdiscovery/nuclei-templates/blob/{COMMIT}/{PATH}",
        f"https://github.com/projectdiscovery/nuclei-templates/{COMMIT}/{PATH}",
        "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates",
        "https://",
    ],
)
def test_a_link_to_a_repository_not_allowed_is_refused(link: str) -> None:
    assert _sources().problem(link) == NOT_ALLOWED


@pytest.mark.parametrize(
    "reference",
    [
        "main",
        "master",
        "refs/heads/main",
        "refs/tags/v10.0.0",
        "v10.0.0",
        "HEAD",
        COMMIT[:7],  # a short hash
        COMMIT[:39],
        COMMIT + "8",  # 41 characters
        COMMIT.upper(),
        COMMIT[:39] + "g",
        "",  # nothing between the repository and the path
        f"%{COMMIT[:38]}",
        f"{COMMIT[:20]}%2F{COMMIT[20:]}",
    ],
)
def test_a_reference_that_is_not_a_full_commit_hash_is_refused(reference: str) -> None:
    assert _sources().problem(f"{RAW}/{reference}/{PATH}") == NOT_PINNED
    github = f"https://github.com/projectdiscovery/nuclei-templates/raw/{reference}/{PATH}"
    assert _sources().problem(github) == NOT_PINNED


@pytest.mark.parametrize(
    "rest",
    [
        "",  # no path
        "/",
        "/x.yaml/",  # an empty segment
        "/a//x.yaml",
        "/../../../evil/repo/main/x.yaml",
        "/a/../x.yaml",
        "/./x.yaml",
        "/a/.",
        "/%2e%2e/x.yaml",
        "/a%2Fb.yaml",
        "/x.yaml?token=abc",
        "/x.yaml#part",
        "/x.yaml?",
        "/a\\..\\x.yaml",
        "/a b.yaml",
        "/x.yaml\n",
        "/x.yaml\t",
        "/@evil.test/x.yaml",
        "/a:b.yaml",
        "/caf\u00e9.yaml",
        "/x\uff0eyaml",
        "/x.yaml\u200b",
    ],
)
def test_a_path_that_is_not_plain_is_refused(rest: str) -> None:
    assert _sources().problem(f"{RAW}/{COMMIT}{rest}") == NOT_PLAIN


# The rule, on an entry.


def test_a_pinned_template_of_an_allowed_repository_passes_every_rule() -> None:
    assert policy_findings(DATA, with_inject_content({"template_url": PINNED})) == ()


@pytest.mark.parametrize("held", [{}, {"template_url": None}, {"template_url": ""}])
def test_no_link_is_a_template_the_platform_holds(held: dict[str, Any]) -> None:
    assert policy_findings(DATA, with_inject_content({**held, "template": "cves"})) == ()


@pytest.mark.parametrize(
    ("link", "problem"),
    [
        (
            "https://raw.githubusercontent.com/Ademking/php2shell-nuclei-templates/refs/heads/main"
            "/templates/php2shell/CVE-2026-109618.yaml",
            NOT_ALLOWED,
        ),
        (PINNED.replace(COMMIT, "main"), NOT_PINNED),
        (PINNED.replace(COMMIT, "refs/heads/main"), NOT_PINNED),
        (PINNED.replace("https://", "http://"), NOT_HTTPS),
        (PINNED + "?x=1", NOT_PLAIN),
        ("templates/x.yaml", NOT_HTTPS),
    ],
)
def test_a_refused_link_blocks_on_this_rule_only_without_quoting_it(
    link: str, problem: str
) -> None:
    findings = policy_findings(DATA, with_inject_content({"template_url": link}))

    assert _found(findings) == [("POL-012", FIELD, _message(problem))]
    assert all(f.severity is Severity.BLOCKING and f.path == JSON for f in findings)
    assert len(findings[0].message) <= MESSAGE_LIMIT  # never shortened
    assert link.strip() not in findings[0].message


@pytest.mark.parametrize(
    "value",
    [["https://evil.com/x.yaml"], {"url": "https://evil.com/x.yaml"}, 1, True, 0, False, []],
)
def test_a_link_that_is_not_text_is_refused(value: object) -> None:
    findings = policy_findings(DATA, with_inject_content({"template_url": value}))

    assert _found(findings) == [("POL-012", FIELD, _message(NOT_TEXT))]


def test_every_inject_and_every_step_is_read() -> None:
    branch = PINNED.replace(COMMIT, "main")
    stored = {
        **SCENARIO,
        "scenario_injects": [
            {"inject_content": {"template_url": ""}},  # read on after one without a link
            {"inject_content": "not an object"},
            {},
            {"inject_content": {"template_url": branch}},
            {"inject_content": {"template_url": PINNED}},
            {"inject_content": {"template_url": branch}},
        ],
        "scenario_workflow": {
            "workflow_steps": [
                {"step_data": {"inject_content": {"template_url": PINNED}}},
                {"step_data": {"inject_content": {"template_url": branch}}},
            ]
        },
    }

    findings = policy_findings(DATA, content(stored=stored))

    assert [(f.code, f.field) for f in findings] == [
        ("POL-012", "/scenario_injects/3/inject_content/template_url"),
        ("POL-012", "/scenario_injects/5/inject_content/template_url"),
        ("POL-012", "/scenario_workflow/workflow_steps/1/step_data/inject_content/template_url"),
    ]


@pytest.mark.parametrize("stored", [None, [], "x", {"scenario_injects": "x"}])
def test_a_stored_scenario_of_another_shape_gives_nothing(stored: object) -> None:
    assert list(RULE.check(DATA, content(stored=stored))) == []


# The allowed targets leave the link to this rule, and only the link.


def test_the_allowed_targets_still_read_the_rest_of_the_content() -> None:
    findings = policy_findings(
        DATA, with_inject_content({"template_url": PINNED, "targets": "10.0.0.5"})
    )

    assert [(f.code, f.field) for f in findings] == [
        ("POL-003", "/scenario_injects/0/inject_content/targets")
    ]


def test_the_allowed_targets_read_a_content_that_is_not_an_object() -> None:
    findings = policy_findings(DATA, with_inject_content("see https://evil.com/x.yaml"))

    assert [(f.code, f.field) for f in findings] == [
        ("POL-003", "/scenario_injects/0/inject_content")
    ]


def test_a_link_under_another_key_is_still_a_target() -> None:
    findings = policy_findings(DATA, with_inject_content({"template": PINNED}))

    assert [(f.code, f.field) for f in findings] == [
        ("POL-003", "/scenario_injects/0/inject_content/template")
    ]


# The repository and the commit a link names, for whoever asks GitHub whether it holds it.


@pytest.mark.parametrize(
    "link",
    [PINNED, f"https://github.com/projectdiscovery/nuclei-templates/raw/{COMMIT}/{PATH}"],
)
def test_a_pinned_link_names_its_repository_and_its_commit(link: str) -> None:
    assert _sources().pinned(link) == PinnedTemplate("projectdiscovery/nuclei-templates", COMMIT)


def test_the_repository_named_is_the_allowed_one_the_link_leads_to() -> None:
    sources = TemplateSources.from_document(
        {"github_repositories": ["projectdiscovery/nuclei-templates", "my-org/templates"]}
    )
    link = f"https://raw.githubusercontent.com/my-org/templates/{COMMIT}/x.yaml"

    assert sources.pinned(link) == PinnedTemplate("my-org/templates", COMMIT)


@pytest.mark.parametrize(
    "link",
    [
        PINNED.replace("https://", "http://"),
        PINNED.replace("projectdiscovery", "someone"),
        PINNED.replace(COMMIT, "main"),
        PINNED.replace("/http/", "/../"),
    ],
)
def test_a_link_this_rule_refuses_names_nothing(link: str) -> None:
    assert _sources().problem(link) is not None
    assert _sources().pinned(link) is None
