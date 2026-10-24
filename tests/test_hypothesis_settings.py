"""The settings the property tests run with."""

from hypothesis import settings


def test_property_tests_have_no_deadline() -> None:
    assert settings().deadline is None


def test_the_repository_profile_generates_as_many_examples_as_hypothesis_does() -> None:
    # What make check and CI run: never fewer examples than Hypothesis's own default.
    repository = settings.get_profile("repository")
    assert repository.max_examples == settings.get_profile("default").max_examples
    assert repository.deadline is None
