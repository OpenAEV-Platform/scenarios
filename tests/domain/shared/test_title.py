"""Pull request titles follow the shared convention: ``type(scope?)!?: description (#issue)``."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from scenario_tools.domain.shared.title import TYPES, TitleProblem, check_pull_request_title


@pytest.mark.parametrize(
    "title",
    [
        "feat(auth): add login endpoint (#42)",
        "fix: resolve array parsing issue (#99)",
        "feat(api)!: remove deprecated endpoints (#150)",
        "docs: update contributing guide (#7)",
        "revert: undo the release workflow change (#12)",
        "test(tooling): add the starter-pack exports as reference test inputs (#4)",
        "feat(v1.2_x-y): scopes may hold dots, underscores and dashes (#3)",
        "feat: OpenAEV collector support (#5)",
        "fix: close two issues at once (#1, #2)",
        "fix: close two issues at once (#1,#2)",
        "chore(deps): update dependency ruff to v0.9",
        "build(deps): bump the uv group",
    ],
)
def test_valid_titles_pass(title: str) -> None:
    assert check_pull_request_title(title) is None


@pytest.mark.parametrize(
    ("title", "problem"),
    [
        ("Add login endpoint (#1)", TitleProblem.BAD_PREFIX),
        ("feature: add login endpoint (#1)", TitleProblem.BAD_PREFIX),
        ("FEAT: add login endpoint (#1)", TitleProblem.BAD_PREFIX),
        ("feat(): add login endpoint (#1)", TitleProblem.BAD_PREFIX),
        ("feat(api) : add login endpoint (#1)", TitleProblem.BAD_PREFIX),
        ("feat:add login endpoint (#1)", TitleProblem.BAD_PREFIX),
        ("feat(a b): add login endpoint (#1)", TitleProblem.BAD_PREFIX),
        ("feat!(api): add login endpoint (#1)", TitleProblem.BAD_PREFIX),
        ("feat: ", TitleProblem.EMPTY_DESCRIPTION),
        ("feat(api)!: ", TitleProblem.EMPTY_DESCRIPTION),
        ("feat: add login endpoint", TitleProblem.MISSING_ISSUE),
        ("feat: add login endpoint (#)", TitleProblem.MISSING_ISSUE),
        ("feat: add login endpoint (#1) more", TitleProblem.MISSING_ISSUE),
        ("feat: add login endpoint #1", TitleProblem.MISSING_ISSUE),
        ("feat: add login endpoint. (#1)", TitleProblem.TRAILING_PERIOD),
        ("chore(deps): update dependency ruff.", TitleProblem.TRAILING_PERIOD),
    ],
)
def test_invalid_titles_report_the_first_problem(title: str, problem: TitleProblem) -> None:
    assert check_pull_request_title(title) is problem


def test_every_problem_explains_the_expected_format() -> None:
    for problem in TitleProblem:
        assert "type(scope?)!?: description (#issue)" in problem.message


_scopes = st.one_of(
    st.just(""),
    st.from_regex(r"\([a-zA-Z0-9_.\-]+\)", fullmatch=True),
)
_descriptions = st.text(
    alphabet=st.characters(codec="utf-8", exclude_characters="\n\r"), min_size=1
).filter(lambda text: not text.rstrip().endswith("."))
_issues = st.lists(st.integers(min_value=1, max_value=99999), min_size=1, max_size=3)


@given(
    kind=st.sampled_from(TYPES),
    scope=_scopes,
    breaking=st.booleans(),
    description=_descriptions,
    issues=_issues,
)
def test_any_title_built_by_the_convention_passes(
    kind: str, scope: str, breaking: bool, description: str, issues: list[int]
) -> None:
    reference = ", ".join(f"#{number}" for number in issues)
    title = f"{kind}{scope}{'!' if breaking else ''}: {description} ({reference})"

    assert check_pull_request_title(title) is None


@given(kind=st.sampled_from(TYPES), description=_descriptions, issue=st.integers(min_value=1))
def test_a_trailing_period_is_always_refused(kind: str, description: str, issue: int) -> None:
    assert check_pull_request_title(f"{kind}: {description}. (#{issue})") is (
        TitleProblem.TRAILING_PERIOD
    )
