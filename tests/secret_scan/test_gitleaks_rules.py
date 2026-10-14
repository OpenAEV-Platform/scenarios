"""The secret scan's rules: gitleaks' own, and the repository's for OpenAEV credentials. An OpenAEV
token is a bare UUID, like every identifier of a scenario, so a rule reads it by its context: sent
as a bearer token, given to a token option or variable. The cases are built at run time, so that
no credential-shaped text is stored in the repository, whose own scan would report it."""

import io
import json
import shutil
import subprocess
import uuid
import zipfile
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).parents[2]
CONFIG = REPOSITORY / ".gitleaks.toml"
LOCAL = REPOSITORY / ".gitleaks.local.toml"  # the local scan's: the shared rules, caches left out
TOKEN = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://example.com/a-test-token"))  # stable ids
LINK = "".join(["Zq8"] * 10 + ["Xy"])  # 32 letters and digits, as a tracking link's token
PASSWORD = "".join(["Tr0ub4dor", "-and-3"])  # joined at run time, never one constant


VERSION = "8.30.1"  # the Makefile's and the workflows'


def _gitleaks() -> str:
    found = shutil.which("gitleaks")
    if found is None:
        pytest.fail(f"gitleaks {VERSION} is required, as `make secrets` says")
    version = subprocess.run(  # noqa: S603 - the gitleaks found on the PATH
        [found, "version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    if version != VERSION:
        pytest.fail(f"gitleaks {VERSION} is required, not {version}")
    return found


def scan(
    tmp_path: Path, text: str | bytes, name: str = "scenario.txt", config: Path = CONFIG
) -> list[str]:
    """The rules that report something in ``text``, written to a file ``name`` of its own."""
    source = tmp_path / "source"
    (source / name).parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        (source / name).write_bytes(text)
    else:
        (source / name).write_text(text, encoding="utf-8")
    report = tmp_path / "report.json"
    subprocess.run(  # noqa: S603 - the pinned gitleaks, on a file of the test
        [
            _gitleaks(),
            "dir",
            str(source),
            "--config",
            str(config),
            "--max-archive-depth",
            "2",
            "--no-banner",
            "--redact",
            "--exit-code",
            "0",
            "--report-format",
            "json",
            "--report-path",
            str(report),
        ],
        check=True,
        capture_output=True,
        cwd=REPOSITORY,  # where the local file's `[extend] path` is read from
    )
    return sorted(finding["RuleID"] for finding in json.loads(report.read_text()))


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (
            f'curl -s -H "Authorization: Bearer {TOKEN}" '
            "https://openaev.example.com/api/agent/installer/openaev/linux | sudo sh",
            "openaev-bearer-token",
        ),
        (
            f'iex (iwr -Headers @{{Authorization="Bearer {TOKEN}"}} '
            "https://openaev.example.com/api/agent/installer/openaev/windows).Content",
            "openaev-bearer-token",
        ),
        (f"Authorization: bearer {TOKEN.upper()}", "openaev-bearer-token"),
        (
            f"implant --uri https://openaev.example.com --token {TOKEN} --agent-id a",
            "openaev-token",
        ),
        (f"implant --token={TOKEN}", "openaev-token"),
        (f'token="{TOKEN}"', "openaev-token"),
        (json.dumps({"command_content": f'agent token="{TOKEN}"'}), "openaev-token"),
        (json.dumps({"token": TOKEN}), "openaev-token"),
        (f"OPENAEV_TOKEN={TOKEN}", "openaev-token"),
        (f'export OPENBAS_ADMIN_TOKEN="{TOKEN}"', "openaev-token"),
        (f"openaev.admin.token: {TOKEN}", "openaev-token"),
        (f"OPENAEV__TOKEN={TOKEN}", "openaev-token"),
        (f"OPENAEV_ADMIN_PASSWORD={PASSWORD}", "openaev-admin-password"),
        (f'openbas.admin.password: "{PASSWORD}"', "openaev-admin-password"),
        (f"https://openaev.example.com/url/access?token={LINK}", "openaev-tracking-link"),
        (
            json.dumps({"command_content": f"curl -H 'Authorization: Bearer\n{TOKEN}'"}),
            "openaev-bearer-token",
        ),
        (f"implant --token \\\n  {TOKEN}", "openaev-token"),
        (f'adminToken = "{TOKEN}"', "openaev-token"),
        (f"access_token: {TOKEN}", "openaev-token"),
    ],
    ids=[
        "agent install, curl",
        "agent install, powershell",
        "bearer in capitals",
        "implant option",
        "implant option with =",
        "token assigned",
        "token in an escaped json string",
        "token as a json key",
        "variable",
        "legacy admin variable",
        "admin property",
        "composer variable",
        "admin password variable",
        "admin password property",
        "tracking link",
        "bearer after an escaped line break",
        "option after a line continuation",
        "camel case key",
        "suffixed key",
    ],
)
def test_an_openaev_credential_is_reported(tmp_path: Path, text: str, rule: str) -> None:
    """By the repository's rule, whatever gitleaks' own report as well (a curl header, say)."""
    assert rule in scan(tmp_path, text)


@pytest.mark.parametrize(
    "text",
    [
        json.dumps({"inject_id": TOKEN, "scenario_id": TOKEN}),  # identifiers, not tokens
        f"the inject {TOKEN} runs first",
        "Authorization: Bearer ${OPENAEV_TOKEN}",
        "Authorization: Bearer <token>",
        "implant --token #{token}",
        "token: <your OpenAEV token>",
        "OPENAEV_TOKEN=${OPENAEV_TOKEN}",
        "OPENAEV_ADMIN_PASSWORD=ChangeMe",
        "OPENAEV_ADMIN_PASSWORD=${OPENAEV_ADMIN_PASSWORD}",
        "openaev.admin.password: <password>",
        "https://openaev.example.com/url/access?token=#{token}",
    ],
    ids=[
        "identifiers",
        "identifier in text",
        "bearer variable",
        "bearer placeholder",
        "option placeholder",
        "key placeholder",
        "variable from variable",
        "documented password placeholder",
        "password variable",
        "password placeholder",
        "link placeholder",
    ],
)
def test_an_identifier_or_a_placeholder_is_not(tmp_path: Path, text: str) -> None:
    assert scan(tmp_path, text) == []


def test_gitleaks_own_rules_still_apply(tmp_path: Path) -> None:
    key = "".join(["ghp_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8"])

    assert scan(tmp_path, f'token = "{key}"') == ["github-pat"]


def test_the_catalogue_s_scenarios_hold_no_credential(tmp_path: Path) -> None:
    """Every identifier of a stored scenario is a UUID: none reads as a token."""
    for stored in sorted((REPOSITORY / "scenarios").glob("*/*/scenario.json")):
        target = tmp_path / stored.parent.name
        target.mkdir()
        assert scan(target, stored.read_text(encoding="utf-8"), "scenario.json") == []


def _zipped(name: str, data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, data)
    return buffer.getvalue()


@pytest.mark.parametrize("depth", [1, 2], ids=["in an archive", "in an archive in an archive"])
def test_a_credential_in_an_archive_is_reported(tmp_path: Path, depth: int) -> None:
    data = f"Authorization: Bearer {TOKEN}".encode()
    for level in range(depth):
        data = _zipped(f"level-{level}.txt" if level == 0 else f"level-{level}.zip", data)

    assert "openaev-bearer-token" in scan(tmp_path, data, "attachments.zip")


@pytest.mark.parametrize("cache", ["x/__pycache__/notes.txt", ".pytest_cache/notes.txt"])
def test_a_cache_s_name_never_hides_a_credential_from_the_pull_request_scans(
    tmp_path: Path, cache: str
) -> None:
    """Only the local scan of a working copy leaves Python's caches out, by its own file."""
    text = f"Authorization: Bearer {TOKEN}"

    assert scan(tmp_path / "shared", text, cache) == ["openaev-bearer-token"]
    assert scan(tmp_path / "local", text, cache, LOCAL) == []
