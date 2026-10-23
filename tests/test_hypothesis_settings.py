"""The settings the property tests run with."""

from hypothesis import settings


def test_property_tests_have_no_deadline() -> None:
    assert settings.default.deadline is None
