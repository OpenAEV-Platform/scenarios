"""The scenario-publish script neutralises the lab targets before intake.

The lab exercises a real, reachable host; the published entry must ship an example one, as the
catalogue policy (POL-003 / POL-010) requires. These tests cover that sanitisation only; the rest
of the script talks to GitHub and runs in the workflow.
"""

import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

_SCRIPT = Path(__file__).parents[2] / "scripts" / "scenario_publish.py"
_DOMAINS = frozenset({"example.com", "example.net", "example.org", "test", "invalid", "localhost"})


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("scenario_publish", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publish = _module()


def _scenario(uri: str, sender: str) -> dict[str, Any]:
    return {
        "scenario_information": {"scenario_mail_from": sender},
        "scenario_injects": [{"inject_content": {"uri": uri}}],
    }


def test_a_real_host_and_sender_are_neutralised() -> None:
    scenario = _scenario("https://honey.scanme.sh/path?q=1", "demo@filigran.cloud")

    changed = publish._sanitise_scenario(scenario, _DOMAINS)

    assert changed is True
    assert scenario["scenario_injects"][0]["inject_content"]["uri"] == "https://host.example.com/path?q=1"
    assert scenario["scenario_information"]["scenario_mail_from"] == "user@example.com"


def test_the_description_loses_the_neutralised_host() -> None:
    scenario = _scenario("https://honey.scanme.sh/", "x@example.com")
    scenario["scenario_information"]["scenario_description"] = (
        "Two probes against honey.scanme.sh to validate detection."
    )

    changed = publish._sanitise_scenario(scenario, _DOMAINS)

    assert changed is True
    assert "honey.scanme.sh" not in scenario["scenario_information"]["scenario_description"]
    assert "host.example.com" in scenario["scenario_information"]["scenario_description"]


def test_a_port_is_kept_when_the_host_is_replaced() -> None:
    scenario = _scenario("http://10.0.0.5:8443/x", "a@b.test")

    publish._sanitise_scenario(scenario, _DOMAINS)

    # 10.0.0.5 is an IP literal: the policy judges its range, the host is not rewritten here.
    assert scenario["scenario_injects"][0]["inject_content"]["uri"] == "http://10.0.0.5:8443/x"


def test_an_example_host_and_sender_are_left_untouched() -> None:
    scenario = _scenario("https://host.example.com/probe", "user@example.com")

    changed = publish._sanitise_scenario(scenario, _DOMAINS)

    assert changed is False
    assert scenario["scenario_injects"][0]["inject_content"]["uri"] == "https://host.example.com/probe"


def test_a_non_default_port_survives_the_rewrite() -> None:
    scenario = _scenario("https://honey.scanme.sh:9000/", "x@example.com")

    publish._sanitise_scenario(scenario, _DOMAINS)

    assert scenario["scenario_injects"][0]["inject_content"]["uri"] == "https://host.example.com:9000/"


def test_a_json_export_is_sanitised_in_place(tmp_path: Path) -> None:
    export = tmp_path / "export.json"
    export.write_text(json.dumps(_scenario("https://honey.scanme.sh/", "demo@filigran.cloud")))

    publish._sanitise_export(export, _DOMAINS)

    written = json.loads(export.read_text(encoding="utf-8"))
    assert written["scenario_injects"][0]["inject_content"]["uri"] == "https://host.example.com/"
    assert written["scenario_information"]["scenario_mail_from"] == "user@example.com"


def test_a_zip_export_is_rewritten_and_keeps_its_other_members(tmp_path: Path) -> None:
    export = tmp_path / "export.zip"
    scenario = json.dumps(_scenario("https://honey.scanme.sh/", "d@x.io"))
    entry = zipfile.ZipInfo("the scenario.json")
    entry.comment = b"Scenario"  # the platform marks the scenario entry with this comment
    with zipfile.ZipFile(export, "w") as archive:
        archive.writestr(entry, scenario)
        archive.writestr("note.txt", b"keep me")

    publish._sanitise_export(export, _DOMAINS)

    with zipfile.ZipFile(export) as archive:
        [entry_info] = [info for info in archive.infolist() if info.comment == b"Scenario"]
        scenario = json.loads(archive.read("the scenario.json").decode("utf-8"))
        assert archive.read("note.txt") == b"keep me"  # other members survive
    assert entry_info.comment == b"Scenario"  # the entry comment the platform set is preserved
    assert scenario["scenario_injects"][0]["inject_content"]["uri"] == "https://host.example.com/"
    assert scenario["scenario_information"]["scenario_mail_from"] == "user@example.com"


def test_allowed_domains_are_read_from_the_policy() -> None:
    root = Path(__file__).parents[2]

    domains = publish._allowed_domains(root)

    assert "example.com" in domains
    assert "scanme.sh" not in domains
