"""The scenario-publish script neutralises the lab targets before intake, and takes the staging
files of the pull request as data only.

The lab exercises a real, reachable host; the published entry must ship an example one, as the
catalogue policy (POL-003 / POL-010) requires. These tests cover the sanitisation and the reading
of the staging files; the rest of the script talks to GitHub and runs in the workflow.
"""

import importlib.util
import json
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_ROOT = Path(__file__).parents[2]
_SCRIPT = _ROOT / "scripts" / "scenario_publish.py"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("scenario_publish", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publish = _module()
_ALLOWED = publish._allowed_targets(_ROOT)


def _scenario(uri: str, sender: str) -> dict[str, Any]:
    return {
        "scenario_information": {"scenario_mail_from": sender},
        "scenario_injects": [{"inject_content": {"uri": uri}}],
    }


def _scanner(targets: str, selector: str = "manual") -> dict[str, Any]:
    return {
        "scenario_information": {"scenario_description": "Scan honey.scanme.sh for the CVE."},
        "scenario_injects": [
            {
                "inject_title": "Scan honey.scanme.sh",
                "inject_content": {"target_selector": selector, "targets": targets},
            }
        ],
    }


def test_a_real_host_and_sender_are_neutralised() -> None:
    scenario = _scenario("https://honey.scanme.sh/path?q=1", "demo@filigran.cloud")

    changed = publish._sanitise_scenario(scenario, _ALLOWED)

    assert changed is True
    assert (
        scenario["scenario_injects"][0]["inject_content"]["uri"]
        == "https://host.example.com/path?q=1"
    )
    assert scenario["scenario_information"]["scenario_mail_from"] == "user@example.com"


def test_the_description_loses_the_neutralised_host() -> None:
    scenario = _scenario("https://honey.scanme.sh/", "x@example.com")
    scenario["scenario_information"]["scenario_description"] = (
        "Two probes against honey.scanme.sh to validate detection."
    )

    changed = publish._sanitise_scenario(scenario, _ALLOWED)

    assert changed is True
    assert scenario["scenario_information"]["scenario_description"] == (
        "Two probes against host.example.com to validate detection."
    )


def test_a_private_address_becomes_a_documentation_address() -> None:
    scenario = _scenario("http://10.0.0.5:8443/x", "a@b.test")

    publish._sanitise_scenario(scenario, _ALLOWED)

    assert scenario["scenario_injects"][0]["inject_content"]["uri"] == "http://192.0.2.10:8443/x"


def test_an_example_host_and_sender_are_left_untouched() -> None:
    scenario = _scenario("https://host.example.com/probe", "user@example.com")

    changed = publish._sanitise_scenario(scenario, _ALLOWED)

    assert changed is False
    assert (
        scenario["scenario_injects"][0]["inject_content"]["uri"] == "https://host.example.com/probe"
    )


def test_a_non_default_port_survives_the_rewrite() -> None:
    scenario = _scenario("https://honey.scanme.sh:9000/", "x@example.com")

    publish._sanitise_scenario(scenario, _ALLOWED)

    assert (
        scenario["scenario_injects"][0]["inject_content"]["uri"] == "https://host.example.com:9000/"
    )


def test_a_scanner_target_typed_by_hand_is_neutralised_with_its_texts() -> None:
    scenario = _scanner("honey.scanme.sh")

    changed = publish._sanitise_scenario(scenario, _ALLOWED)

    inject = scenario["scenario_injects"][0]
    assert changed is True
    assert inject["inject_content"]["targets"] == "host.example.com"
    assert inject["inject_title"] == "Scan host.example.com"
    assert scenario["scenario_information"]["scenario_description"] == (
        "Scan host.example.com for the CVE."
    )


def test_every_target_of_a_list_is_neutralised_and_its_separators_kept() -> None:
    scenario = _scanner(
        "a.real.com, 10.1.2.3\nhttps://b.real.org:8443/x;host.example.com "
        "2001:4860::8888 [fd00::1]:22"
    )

    publish._sanitise_scenario(scenario, _ALLOWED)

    assert scenario["scenario_injects"][0]["inject_content"]["targets"] == (
        "host.example.com, 192.0.2.10\nhttps://host.example.com:8443/x;host.example.com "
        "2001:db8::10 [2001:db8::10]:22"
    )


def test_a_target_with_a_port_or_a_variable() -> None:
    scenario = _scanner("honey.scanme.sh:8080,#{target},127.0.0.1")

    publish._sanitise_scenario(scenario, _ALLOWED)

    assert scenario["scenario_injects"][0]["inject_content"]["targets"] == (
        "host.example.com:8080,#{target},127.0.0.1"
    )


def test_chosen_assets_are_not_read_as_hosts() -> None:
    scenario = _scanner("honey.scanme.sh", selector="assets")

    changed = publish._sanitise_scenario(scenario, _ALLOWED)

    assert changed is False


def test_a_json_export_is_sanitised_in_place(tmp_path: Path) -> None:
    export = tmp_path / "export.json"
    export.write_text(json.dumps(_scenario("https://honey.scanme.sh/", "demo@filigran.cloud")))

    publish._sanitise_export(export, _ALLOWED)

    written = json.loads(export.read_text(encoding="utf-8"))
    assert written["scenario_injects"][0]["inject_content"]["uri"] == "https://host.example.com/"
    assert written["scenario_information"]["scenario_mail_from"] == "user@example.com"


def test_a_zip_export_is_rewritten_and_keeps_its_other_members(tmp_path: Path) -> None:
    export = tmp_path / "export.zip"
    scenario = json.dumps(_scanner("honey.scanme.sh"))
    entry = zipfile.ZipInfo("the scenario.json")
    entry.comment = b"Scenario"  # the platform marks the scenario entry with this comment
    with zipfile.ZipFile(export, "w") as archive:
        archive.writestr(entry, scenario)
        archive.writestr("note.txt", b"keep me")

    publish._sanitise_export(export, _ALLOWED)

    with zipfile.ZipFile(export) as archive:
        [entry_info] = [info for info in archive.infolist() if info.comment == b"Scenario"]
        written = json.loads(archive.read("the scenario.json").decode("utf-8"))
        assert archive.read("note.txt") == b"keep me"  # other members survive
    assert entry_info.comment == b"Scenario"  # the entry comment the platform set is preserved
    assert written["scenario_injects"][0]["inject_content"]["targets"] == "host.example.com"


def _stage(root: Path, files: dict[str, str]) -> None:
    staging = root / "pull" / ".scenario-publish"
    staging.mkdir(parents=True)
    for name, text in files.items():
        (staging / name).write_text(text, encoding="utf-8")
    (root / "schemas").mkdir()
    schema = (_ROOT / "schemas" / "intake-request.schema.json").read_text(encoding="utf-8")
    (root / "schemas" / "intake-request.schema.json").write_text(schema, encoding="utf-8")


_REQUEST = """mode: {mode}
external_id: "f0e1d2c3-b4a5-4968-8778-695041320000"
domain: vulnerabilities
slug: cve-2024-3400-exploitation-attempt
issue: 337
generated_by: scenario-publish pipeline
threat: {{cves: [CVE-2024-3400]}}
sources: [{{url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400", tlp: "TLP:CLEAR"}}]
"""


def test_the_staging_files_are_copied_out_of_the_pull_request(tmp_path: Path) -> None:
    root, work = tmp_path / "repo", tmp_path / "work"
    work.mkdir()
    _stage(root, {"request.yaml": _REQUEST.format(mode="new"), "export.json": "{}"})

    request, export, request_path, staged = publish._staging(root, work)

    assert request["slug"] == "cve-2024-3400-exploitation-attempt"
    assert export == work / "export.json"
    assert request_path == work / "request.yaml"
    assert staged == [".scenario-publish/export.json", ".scenario-publish/request.yaml"]


def test_a_link_among_the_staging_files_is_refused(tmp_path: Path) -> None:
    root, work = tmp_path / "repo", tmp_path / "work"
    work.mkdir()
    _stage(root, {"request.yaml": _REQUEST.format(mode="new")})
    (root / "pull" / ".scenario-publish" / "export.json").symlink_to("/etc/hostname")

    with pytest.raises(SystemExit) as raised:
        publish._staging(root, work)

    assert raised.value.code == 1


def test_an_update_is_refused_in_v1(tmp_path: Path) -> None:
    root, work = tmp_path / "repo", tmp_path / "work"
    work.mkdir()
    _stage(root, {"request.yaml": _REQUEST.format(mode="update"), "export.json": "{}"})

    with pytest.raises(SystemExit) as raised:
        publish._staging(root, work)

    assert raised.value.code == 1


def test_no_staging_files_is_nothing_to_do(tmp_path: Path) -> None:
    root, work = tmp_path / "repo", tmp_path / "work"
    (root / "pull").mkdir(parents=True)
    work.mkdir()

    with pytest.raises(SystemExit) as raised:
        publish._staging(root, work)

    assert raised.value.code == 0
