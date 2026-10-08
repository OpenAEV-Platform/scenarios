"""The pull request title workflow keeps its security properties."""

from pathlib import Path

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "pr-title.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8")


def test_the_title_is_passed_after_the_end_of_options() -> None:
    # Without "--", a title such as "--help" is read as an option and the check passes.
    assert 'scenario-tools check-title -- "$TITLE"' in TEXT


def test_the_title_is_read_from_the_environment_only() -> None:
    assert "TITLE: ${{ github.event.pull_request.title }}" in TEXT
    assert TEXT.count("github.event.pull_request.title") == 1


def test_the_pull_request_code_is_never_checked_out() -> None:
    assert "ref: ${{ github.event.pull_request.base.sha }}" in TEXT
    assert "pull_request.head" not in TEXT
    assert "persist-credentials: false" in TEXT


def test_the_token_is_read_only() -> None:
    assert "permissions:\n  contents: read\n" in TEXT
    assert "secrets." not in TEXT
