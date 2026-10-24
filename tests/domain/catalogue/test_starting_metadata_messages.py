"""What the starting scenario.yaml says, word for word, of each field it leaves to complete or
to review: in the singular and the plural, and in the order the reasons are given. The texts
are pinned as the tools write them, the singular's grammar included."""

from dataclasses import replace

from scenario_tools.domain.catalogue.metadata import INJECTORS_LIMIT, ExportFacts
from tests.domain.catalogue.test_metadata import FACTS, _inject, _message, _start

LINUX = frozenset({"Linux"})


def test_an_export_without_a_description_asks_for_one() -> None:
    _, findings = _start(description="   ")
    assert _message(findings, "/description") == "write a description: the export has none"


def test_a_severity_outside_the_list_names_the_list() -> None:
    _, findings = _start(replace(FACTS, severity="severe"))
    assert _message(findings, "/severity").startswith(
        "the export's severity is not one of low, medium, high, critical: "
    )


def _with(*injects: object) -> ExportFacts:
    return replace(FACTS, injects=tuple(injects))  # type: ignore[arg-type]


def test_one_platform_outside_the_list_is_said_in_the_singular() -> None:
    _, findings = _start(_with(_inject("openaev_implant", True, frozenset({"Linux", "Amiga"}))))
    assert _message(findings, "/platforms") == (
        "1 platform of the injects that run through an executor is not among Linux, Windows, "
        "MacOS, Android, iOS, Container, Service, Generic, Internal, Unknown: left out"
    )


def test_two_platforms_outside_the_list_are_said_in_the_plural() -> None:
    _, findings = _start(_with(_inject("openaev_implant", True, frozenset({"Amiga", "Atari"}))))
    assert _message(findings, "/platforms") == (
        "2 platforms of the injects that run through an executor are not among Linux, Windows, "
        "MacOS, Android, iOS, Container, Service, Generic, Internal, Unknown: left out"
    )


def test_injects_run_through_an_executor_name_where() -> None:
    _, findings = _start(_with(_inject("openaev_implant", True, LINUX)))
    assert _message(findings, "/requires/executors") == (
        "injects run through an executor on Linux: name the executors they need"
    )


def test_injects_run_through_an_executor_on_no_known_platform_say_so() -> None:
    _, findings = _start(_with(_inject("openaev_implant", True, frozenset({"Amiga"}))))
    assert _message(findings, "/requires/executors") == (
        "injects run through an executor on platforms left out above: name the executors they need"
    )


def test_too_many_injector_types_ask_for_those_needed() -> None:
    many = [_inject(f"injector_{number}") for number in range(INJECTORS_LIMIT + 1)]
    _, findings = _start(_with(*many))
    assert _message(findings, "/requires/injectors") == (
        f"the injects use {INJECTORS_LIMIT + 1} injector types, more than {INJECTORS_LIMIT}: list "
        "those the scenario needs"
    )


def test_one_unknown_inject_is_said_in_the_singular_in_each_field() -> None:
    _, findings = _start(_with(_inject("openaev_email")), unknown_injects=1)
    unknown = "1 inject uses a contract that is not a recorded built-in one"
    assert _message(findings, "/requires/injectors") == f"complete requires.injectors: {unknown}"
    assert _message(findings, "/platforms") == (
        f"check them: {unknown}, so the platforms it run on are unknown"
    )
    assert _message(findings, "/requires/executors") == (
        f"check them: {unknown}, so whether it need an executor is unknown"
    )


def test_two_unknown_injects_are_said_in_the_plural() -> None:
    _, findings = _start(_with(_inject("openaev_email")), unknown_injects=2)
    unknown = "2 injects use a contract that is not a recorded built-in one"
    assert _message(findings, "/platforms") == (
        f"check them: {unknown}, so the platforms they run on are unknown"
    )
    assert _message(findings, "/requires/executors") == (
        f"check them: {unknown}, so whether they need an executor is unknown"
    )


def test_every_reason_of_a_field_is_given_in_order_and_joined() -> None:
    many = [_inject(f"injector_{number}") for number in range(INJECTORS_LIMIT + 1)]
    executor = _inject("openaev_implant", True, frozenset({"Linux", "Amiga"}))
    _, findings = _start(_with(*many, executor), unknown_injects=1)
    unknown = "1 inject uses a contract that is not a recorded built-in one"
    assert _message(findings, "/requires/injectors") == (
        f"the injects use {INJECTORS_LIMIT + 2} injector types, more than {INJECTORS_LIMIT}: list "
        f"those the scenario needs; complete requires.injectors: {unknown}"
    )
    assert _message(findings, "/platforms") == (
        "1 platform of the injects that run through an executor is not among Linux, Windows, "
        "MacOS, Android, iOS, Container, Service, Generic, Internal, Unknown: left out; "
        f"check them: {unknown}, so the platforms it run on are unknown"
    )
    assert _message(findings, "/requires/executors") == (
        "injects run through an executor on Linux: name the executors they need; "
        f"check them: {unknown}, so whether it need an executor is unknown"
    )


def test_injects_run_through_an_executor_on_several_platforms_name_them_all() -> None:
    _, findings = _start(_with(_inject("openaev_implant", True, frozenset({"Windows", "Linux"}))))
    assert _message(findings, "/requires/executors") == (
        "injects run through an executor on Linux, Windows: name the executors they need"
    )


def _asks_something(findings: tuple[object, ...]) -> list[bool]:
    return [not f.asks_nothing for f in findings if f.field == "/description"]  # type: ignore[attr-defined]


def test_a_description_too_long_asks_to_review_its_cut() -> None:
    _, findings = _start(description="word " * 5000)
    assert _asks_something(findings) == [True]


def test_a_missing_description_asks_for_one() -> None:
    _, findings = _start(description="")
    assert _asks_something(findings) == [True]


def test_a_description_as_it_is_says_nothing_of_it() -> None:
    _, findings = _start(description="A crisis exercise.")
    assert all(_asks_something(findings))
