"""The pull requests merged before reviews were required are data, read safely."""

from pathlib import Path

from scenario_tools.adapters.safe_readers import read_yaml_file
from scenario_tools.domain.release.manifest import merged_before_review_from_document

DATA = Path(__file__).parents[2] / "policy" / "data" / "merged-before-review.yaml"


def test_the_list_is_read_as_build_reads_it() -> None:
    assert isinstance(merged_before_review_from_document(read_yaml_file(DATA)), frozenset)
