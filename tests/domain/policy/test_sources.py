"""Linked, never copied: a source link leads to a public page, and an entry holds only its own
files. The schema already holds HTTPS and TLP:CLEAR; this rule checks what it cannot see.

Characters are written by code point, never raw, so that this file holds none of them."""

import time

import pytest

from scenario_tools.domain.policy.registry import policy_findings
from scenario_tools.domain.policy.rules.sources import OWN_FILES, RULE
from scenario_tools.domain.shared.finding import Finding, Severity
from tests.domain.policy.cases import DATA, ENTRY, content, with_source

YAML = f"{ENTRY}/scenario.yaml"
OWN = "CHANGELOG.md, README.md, scenario.json, scenario.yaml"
USER = "holds user information"
IP = "has an IP address as its host"
NO_HOST = "has no host"
LOCAL = "has a local, internal or reserved host"
CREDENTIAL = "carries a credential in its query or fragment"
NO_DOT = "has a host with no dot, which only a local network resolves"
NOT_PUBLIC = "has a host that is not a public DNS name"


def _pol_001(findings: tuple[Finding, ...]) -> list[tuple[str, str]]:
    return [(f.path, f.field) for f in findings if f.code == "POL-001"]


def test_the_rule_is_pol_001_and_blocks() -> None:
    assert (RULE.code, RULE.severity) == ("POL-001", Severity.BLOCKING)


@pytest.mark.parametrize(
    "url",
    [
        "https://attack.mitre.org/techniques/T1595/",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "https://www.cisa.gov:443/known-exploited-vulnerabilities-catalog",
        "https://ATTACK.MITRE.ORG/",  # host names are not case-sensitive
        "https://example.org.",  # a fully qualified name ends with a dot
        "https://xn--bcher-kva.de/",  # an internationalised name, as written in a URI
        "https://www.example.xn--p1ai/",  # an internationalised top-level domain
        "https://a-b.example.org?q=1",
        "https://example.org#part",
        "https://www.example1.org/",  # only the last label must be a top-level name
        "https://example.org/search?q=token&page=2",  # a value, never a key, names it
        "https://example.org/a?keyword=x&page=2&sort=asc",  # other keys
        "https://example.org/a#signature-section",  # an anchor, no parameter
        "https://example.org/a#token-handling",
        "https://example.org/a?token",  # a key with no value carries nothing
        "https://example.org/a?token=",
        "https://example.org/a?x=token=",  # an empty pair inside a value carries nothing
        "https://example.org/search?q=password+spraying",  # a word in a value, not a key
        "https://example.org/rfc#section-token-binding",
        "https://example.org/a?id=CVE-2024-1234&keyword=x&author=y",
        "https://example.org/a?q=%2541",  # decoded twice, still no credential
        # Decoding stops after three rounds: no server decodes a key four times.
        "https://example.org/a?%25252574oken=abc",
        "https://example.org/token/key/sig",  # a path is no query
        "https://example.org/a?%zz=1",  # a malformed escape is kept as it is
        "https://localhost.example.org/",  # reserved names end a host, they do not start it
        "https://www.examples.com/",
        "https://" + ("a" * 63 + ".") * 3 + "a" * 57 + ".org/",  # 253 characters, the bound
        "https://" + ("a" * 63 + ".") * 3 + "a" * 57 + ".org./",  # a final dot is not counted
        "https://www.alternative.org/",
    ],
)
def test_a_link_to_a_public_page_passes(url: str) -> None:
    assert policy_findings(DATA, with_source(url)) == ()


@pytest.mark.parametrize(
    ("url", "why"),
    [
        ("https://user@example.org/", USER),
        ("https://user:secret@example.org/", USER),
        ("https://@example.org/", USER),
        ("https://10.0.0.1/report.html", IP),
        ("https://192.168.1.10:8443/", IP),
        ("https://[::1]/", IP),
        ("https://[fe80::1%25eth0]/", IP),
        ("https://[v1.fe]/", IP),
        ("https://wiki/", NO_DOT),
        ("https://localhost/", LOCAL),
        ("https://localhost:8080/", LOCAL),
        ("https://app.localhost/", LOCAL),
        ("https://printer.local/", LOCAL),
        ("https://wiki.internal/", LOCAL),
        ("https://nas.lan/", LOCAL),
        ("https://git.corp/", LOCAL),
        ("https://home.arpa/", LOCAL),
        ("https://router.home.arpa/", LOCAL),
        ("https://1.0.0.10.in-addr.arpa/", LOCAL),
        ("https://www.example/", LOCAL),
        ("https://site.test/", LOCAL),
        ("https://x.invalid/", LOCAL),
        ("https://abcdefghijklmnop.onion/", LOCAL),
        ("https://nas.localdomain/", LOCAL),
        ("https://portal.intranet/", LOCAL),
        ("https://files.private/", LOCAL),
        ("https://router.home/", LOCAL),
        ("https://service.alt/", LOCAL),  # RFC 9476
        ("https://" + ("a" * 63 + ".") * 3 + "a" * 58 + ".org/", NOT_PUBLIC),  # 254 characters
        ("https://WIKI.Internal./", LOCAL),
        ("https://127.1/", NOT_PUBLIC),  # read as 127.0.0.1 by some clients
        ("https://0x7f.1/", NOT_PUBLIC),
        ("https://example.123/", NOT_PUBLIC),
        ("https://www.example.123/", NOT_PUBLIC),
        ("https://exa_mple.org/", NOT_PUBLIC),
        ("https://ex%61mple.org/", NOT_PUBLIC),
        ("https://-example.org/", NOT_PUBLIC),
        ("https://example-.org/", NOT_PUBLIC),
        ("https://example..org/", NOT_PUBLIC),
        ("https://" + "a" * 64 + ".org/", NOT_PUBLIC),
        ("https://example.o/", NOT_PUBLIC),
        ("https://exampl" + chr(0x212A) + ".org/", NOT_PUBLIC),  # lower() would make it a k
        ("https://x.com/r.pdf?X-Amz-Signature=abc&X-Amz-Credential=def", CREDENTIAL),
        ("https://x.com/r.pdf?x-goog-signature=abc", CREDENTIAL),
        ("https://x.com/?token=abc", CREDENTIAL),
        ("https://x.com/?a=1;access_token=abc", CREDENTIAL),
        ("https://x.com/?api_key=abc", CREDENTIAL),
        ("https://x.com/?apikey=abc", CREDENTIAL),
        ("https://x.com/?key=abc", CREDENTIAL),
        ("https://x.com/?sv=2024&sig=abc", CREDENTIAL),
        ("https://x.com/?password=abc", CREDENTIAL),
        ("https://x.com/?%74oken=abc", CREDENTIAL),  # percent-encoded key
        ("https://x.com/?TOKEN=abc", CREDENTIAL),
        ("https://x.com/?auth_token=abc", CREDENTIAL),  # a credential word inside the key
        ("https://x.com/?session_token=abc", CREDENTIAL),
        ("https://x.com/?accessToken=abc", CREDENTIAL),
        ("https://x.com/?x-api-key=abc", CREDENTIAL),
        ("https://x.com/?client-secret=abc", CREDENTIAL),
        ("https://x.com/?private_key=abc", CREDENTIAL),
        ("https://x.com/?AWSAccessKeyId=abc&Signature=def", CREDENTIAL),
        ("https://x.com/?X-Amz-Security-Token=abc", CREDENTIAL),
        ("https://x.com/?user_password=abc", CREDENTIAL),
        ("https://x.com/?a=1?token=abc", CREDENTIAL),  # a "?" inside the query
        ("https://x.com/#callback?access_token=abc", CREDENTIAL),  # parameters in a fragment
        ("https://x.com/#/route?token=abc", CREDENTIAL),
        ("https://x.com/?%61uth_%74oken=abc", CREDENTIAL),
        ("https://x.com/?api%2Dkey=abc", CREDENTIAL),
        ("https://x.com/?next=https%3A%2F%2Fh.com%2F%3Ftoken%3Dabc", CREDENTIAL),  # in a value
        ("https://x.com/?x=1%26token=abc", CREDENTIAL),  # an encoded separator
        ("https://x.com/?x=token=abc", CREDENTIAL),  # a pair inside a value
        ("https://x.com/?access_token%3Dabc", CREDENTIAL),
        ("https://x.com/#a%26token%3Dabc", CREDENTIAL),
        ("https://x.com/?%2574oken=abc", CREDENTIAL),  # encoded twice
        ("https://x.com/?%252574oken=abc", CREDENTIAL),  # encoded three times, the bound
        ("https://x.com/?q=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc", CREDENTIAL),  # a JWT
        ("https://x.com/?u=https://user:pw@h.com/", CREDENTIAL),  # user information in a value
        ("https://x.com/?jwt=abc", CREDENTIAL),
        ("https://x.com/?bearer=abc", CREDENTIAL),
        ("https://x.com/?authkey=abc", CREDENTIAL),
        ("https://x.com/?passphrase=abc", CREDENTIAL),
        ("https://x.com/?passcode=abc", CREDENTIAL),
        ("https://x.com/?PHPSESSID=abc", CREDENTIAL),
        ("https://x.com/?subscription-key=abc", CREDENTIAL),
        ("https://x.com/?license_key=abc", CREDENTIAL),
        ("https://x.com/?pw=abc", CREDENTIAL),
        ("https://x.com/?sid=abc", CREDENTIAL),
        ("https://x.com/?otp=123456", CREDENTIAL),
        ("https://x.com/?token==abc", CREDENTIAL),  # a value that starts with "="
        ("https://x.com/?a=b&token===abc", CREDENTIAL),
        ("https://x.com/#access_token=abc", CREDENTIAL),
        ("https://x.com/page#id_token=abc&state=1", CREDENTIAL),
        # Not a URI the schema accepts, refused all the same: only the last ":" opens a port.
        ("https://example.org:1:2/", NOT_PUBLIC),
        ("https:///path", NO_HOST),
        ("https://", NO_HOST),
        ("https://:443/", NO_HOST),
        ("https://./", NO_HOST),
    ],
)
def test_a_link_that_does_not_lead_to_a_public_page_is_refused(url: str, why: str) -> None:
    (finding,) = policy_findings(DATA, with_source(url))

    assert (finding.code, finding.severity, finding.path, finding.field, finding.message) == (
        "POL-001",
        Severity.BLOCKING,
        YAML,
        "/sources/0/url",
        f"the source link {why}: link a public page that any reader can open",
    )


def test_each_refused_source_is_reported_at_its_own_pointer() -> None:
    metadata = {
        "sources": [
            {"url": "https://attack.mitre.org/", "tlp": "TLP:CLEAR"},
            {"url": "https://10.0.0.1/", "tlp": "TLP:CLEAR"},
            {"url": "https://wiki.corp/", "tlp": "TLP:CLEAR"},
        ]
    }

    assert _pol_001(policy_findings(DATA, content(declared=metadata))) == [
        (YAML, "/sources/1/url"),
        (YAML, "/sources/2/url"),
    ]


@pytest.mark.parametrize(
    "metadata",
    [
        None,  # the file is missing or breaks its schema: its own check says so
        [],
        {},
        {"sources": None},
        {"sources": "https://10.0.0.1/"},
        {"sources": [None, "https://10.0.0.1/", {"url": None}, {"tlp": "TLP:CLEAR"}]},
        {"sources": [{"url": 10}]},
        {"sources": [{"url": "http://10.0.0.1/"}]},  # not https: the schema refuses it
    ],
)
def test_sources_the_schema_refuses_are_left_to_it(metadata: object) -> None:
    assert _pol_001(policy_findings(DATA, content(declared=metadata))) == []


def test_a_source_the_schema_refuses_never_hides_the_ones_after_it() -> None:
    metadata = {"sources": [{"url": None}, {"url": "https://10.0.0.1/"}]}

    assert _pol_001(policy_findings(DATA, content(declared=metadata))) == [(YAML, "/sources/1/url")]


def test_the_entry_s_own_files_pass() -> None:
    assert frozenset({"scenario.yaml", "scenario.json", "README.md", "CHANGELOG.md"}) == OWN_FILES
    assert policy_findings(DATA, content(files=OWN_FILES)) == ()


def test_a_missing_own_file_is_not_this_rule_s_matter() -> None:
    assert policy_findings(DATA, content(files=frozenset())) == ()


def test_each_file_that_is_not_the_entry_s_own_is_refused() -> None:
    files = frozenset({"scenario.yaml", "scenario.json", "report.pdf", "notes", ".DS_Store"})

    findings = policy_findings(DATA, content(files=files))

    assert _pol_001(findings) == [
        (f"{ENTRY}/.DS_Store", ""),
        (f"{ENTRY}/notes", ""),
        (f"{ENTRY}/report.pdf", ""),
    ]
    assert all(f.severity is Severity.BLOCKING for f in findings)
    assert {f.message for f in findings} == {
        f"this file is not one of the entry's own ({OWN}): sources are linked, never copied "
        "into an entry"
    }


@pytest.mark.parametrize(
    "name",
    ["Scenario.yaml", "scenario.yml", "README", "readme.md", "attachments.zip", "scenario.json~"],
)
def test_a_name_close_to_an_own_file_is_not_one(name: str) -> None:
    assert _pol_001(policy_findings(DATA, content(files=frozenset({name})))) == [
        (f"{ENTRY}/{name}", "")
    ]


@pytest.mark.parametrize(
    "name",
    [
        "a\\b",  # a path separator elsewhere
        "line\nbreak",
        "bell" + chr(0x07),
        "rlo" + chr(0x202E) + "fdp.exe",
        "zero" + chr(0x200B) + "width",
        "lone" + chr(0xDCFF),  # a byte that is not UTF-8, as the file system gives it
        chr(0x2028),
        " leading",
        "README.md ",  # a blank a reader cannot see, next to an own file's name
        # Names a directory listing never gives, which would change the finding's path.
        "",
        ".",
        "..",
        "a/b",
        "../outside",
    ],
)
def test_a_name_that_cannot_be_shown_is_reported_at_the_entry_without_it(name: str) -> None:
    (finding,) = policy_findings(DATA, content(files=frozenset({"scenario.yaml", name})))

    assert (finding.code, finding.path, finding.field, finding.message) == (
        "POL-001",
        ENTRY,
        "",
        f"the entry holds 1 file whose name cannot be shown safely, besides its own files "
        f"({OWN}): sources are linked, never copied into an entry",
    )


def test_names_that_cannot_be_shown_are_counted_in_one_finding() -> None:
    files = frozenset({"a\\b", "c\\d", "e\\f", "report.pdf"})

    findings = policy_findings(DATA, content(files=files))

    assert _pol_001(findings) == [(ENTRY, ""), (f"{ENTRY}/report.pdf", "")]
    assert findings[0].message.startswith("the entry holds 3 files whose name cannot be shown")


def test_two_names_that_cannot_be_shown_are_counted_as_files() -> None:
    (finding,) = policy_findings(DATA, content(files=frozenset({"a\\b", "c\\d"})))

    assert finding.message.startswith("the entry holds 2 files whose name cannot be shown")


def test_a_name_in_another_script_is_shown() -> None:
    name = "rapport-" + chr(0xE9) + "t" + chr(0xE9) + ".pdf"

    assert _pol_001(policy_findings(DATA, content(files=frozenset({name})))) == [
        (f"{ENTRY}/{name}", "")
    ]


def _seconds(rest: str) -> float:
    """The shortest of three runs on a link that ends with ``rest``."""
    content = with_source("https://example.org/" + rest)
    runs = []
    for _ in range(3):
        start = time.perf_counter()
        policy_findings(DATA, content)
        runs.append(time.perf_counter() - start)
    return min(runs)


@pytest.mark.parametrize(
    "unit", ["=", "a=", "/", "%2541", "a=b&"], ids=["equals", "pairs", "slashes", "escapes", "and"]
)
def test_a_long_link_is_read_in_linear_time(unit: str) -> None:
    # Four times the text must cost far less than sixteen times the time: linear, never
    # quadratic, whatever a tracer or a mutation run adds to every step.
    small, large = _seconds("?" + unit * 10_000), _seconds("?" + unit * 40_000)

    assert large < 8 * small + 0.05
