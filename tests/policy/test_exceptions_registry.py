"""The maintainers' exceptions, kept as data they own: each names an entry of the catalogue, so
that none outlives the entry it was granted for, nor passes to another that takes its ID."""

from pathlib import Path

from scenario_tools.adapters.data_files import YamlDataLoader
from scenario_tools.adapters.repository import RepositoryEntries
from scenario_tools.domain.policy.exceptions import exceptions_from_document

REPOSITORY = Path(__file__).parents[2]


def test_every_exception_names_an_entry_of_the_catalogue() -> None:
    exceptions = exceptions_from_document(
        YamlDataLoader(REPOSITORY / "policy" / "data").load("exceptions")
    )
    entries = RepositoryEntries(REPOSITORY).external_ids()

    assert [exception.entry for exception in exceptions if exception.entry not in entries] == []
