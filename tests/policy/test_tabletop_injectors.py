"""The communication injector list that makes a scenario tabletop is data, read safely."""

from pathlib import Path

from scenario_tools.adapters.safe_readers import read_yaml_file

DATA = Path(__file__).parents[2] / "policy" / "data" / "tabletop-injectors.yaml"


def test_the_list_holds_exactly_the_communication_injectors() -> None:
    document = read_yaml_file(DATA)

    assert document == {
        "injectors": [
            "openaev_challenge",
            "openaev_channel",
            "openaev_email",
            "openaev_manual",
            "openaev_ovh_sms",
        ]
    }


def test_phishing_is_not_a_communication_injector() -> None:
    # It sends real phishing e-mails with a capture page: the scenario stays technical.
    assert "openaev_phishing" not in read_yaml_file(DATA)["injectors"]
