"""A command with each argument replaced by the value the payload runs it with, and nothing when
that is longer than a limit, which no rule reads."""

import pytest

from scenario_tools.domain.policy.payloads import substituted


def test_each_argument_is_replaced_by_its_value() -> None:
    assert substituted("echo #{a} #{b} #{c}", {"a": "1", "b": "2"}, 100) == "echo 1 2 #{c}"


@pytest.mark.parametrize(
    ("command", "limit", "expected"),
    [
        ("#{a}#{a}", 10, "xxxxxxxxxx"),  # exactly the limit
        ("#{a}#{a}#{a}", 10, None),  # past it, from the pieces before the end
        ("#{a}tail", 5, None),  # past it with the end of the command
        ("12345", 5, "12345"),
        ("123456", 5, None),
    ],
)
def test_a_command_longer_than_the_limit_is_none(
    command: str, limit: int, expected: str | None
) -> None:
    assert substituted(command, {"a": "xxxxx"}, limit) == expected
