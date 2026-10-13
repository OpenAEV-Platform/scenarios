"""Allowed targets: an inject or an exercise text names only example names, loopback and test
addresses, the test environment's ranges and authorised external targets.

Characters are written by code point, never raw, so that this file holds none of them."""

import ipaddress
import time
from typing import Any

import pytest

from scenario_tools.domain.policy.registry import policy_findings, rule_findings
from scenario_tools.domain.policy.rules.targets import RULE
from scenario_tools.domain.policy.targets import AllowedTargets
from scenario_tools.domain.shared.finding import Finding, Severity
from tests.domain.policy.cases import DATA, ENTRY, TARGETS, content, with_inject_content

JSON = f"{ENTRY}/scenario.json"
MESSAGE = (
    "this value names a host outside the example names, test addresses and authorised targets: "
    "use an example name, such as host.example.com, or a test address"
)


def _allowed() -> AllowedTargets:
    """Read inside each test, so that a change to the reading is seen by the test."""
    return AllowedTargets.from_document(TARGETS)


def _pol_003(findings: tuple[Finding, ...]) -> list[str]:
    return [f.field for f in findings if f.code == "POL-003"]


def test_the_rule_is_pol_003_and_blocks() -> None:
    assert (RULE.code, RULE.severity) == ("POL-003", Severity.BLOCKING)


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "www.example.com",
        "a.b.example.org",
        "host.example",
        "site.test",
        "x.invalid",
        "localhost",
        "app.localhost",
        "WWW.EXAMPLE.COM.",
        "scanme.nmap.org",  # an authorised external target
    ],
)
def test_example_names_and_authorised_targets_are_allowed(host: str) -> None:
    assert _allowed().allows(host)


@pytest.mark.parametrize(
    "host",
    [
        "evil.com",
        "example.com.evil.org",
        "notexample.com",
        "a.scanme.nmap.org",  # an external target is exact, never its subdomains
        "nmap.org",
        "intranet",
        "%31%30.0.0.1",  # a host that cannot be read is never allowed
        "",
    ],
)
def test_other_names_are_not_allowed(host: str) -> None:
    assert not _allowed().allows(host)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.8.9.10",
        "::1",
        "192.0.2.10",
        "198.51.100.7",
        "203.0.113.200",
        "2001:db8::1",
        "10.42.3.4",
        "::ffff:127.0.0.1",
    ],
)
def test_loopback_test_and_lab_addresses_are_allowed(address: str) -> None:
    assert _allowed().allows(address)


@pytest.mark.parametrize(
    "address", ["10.0.0.5", "192.168.1.1", "8.8.8.8", "fe80::1", "2001:db9::1", "::ffff:10.0.0.5"]
)
def test_other_addresses_are_not_allowed(address: str) -> None:
    assert not _allowed().allows(address)


@pytest.mark.parametrize(
    ("change", "why"),
    [
        (lambda d: d.pop("domains"), "domains"),
        (lambda d: d.__setitem__("networks", "127.0.0.0/8"), "networks"),
        (lambda d: d.__setitem__("domains", ["Example.com"]), "domains"),
        (lambda d: d.__setitem__("domains", ["exa mple.com"]), "domains"),
        (lambda d: d.__setitem__("domains", ["example.com", "example.com"]), "domains"),
        (lambda d: d.__setitem__("networks", ["127.0.0.1/8"]), "networks"),  # host bits set
        (lambda d: d.__setitem__("networks", ["not a network"]), "networks"),
        (lambda d: d.__setitem__("lab_networks", [1]), "lab_networks"),
        (lambda d: d.__setitem__("external_targets", ["*.example.net"]), "external_targets"),
        (lambda d: d.__setitem__("extra", []), "unknown"),
    ],
)
def test_a_malformed_list_is_refused(change: Any, why: str) -> None:
    document = {key: list(value) for key, value in TARGETS.items()}
    change(document)

    with pytest.raises(ValueError, match=why):
        AllowedTargets.from_document(document)


def test_the_document_must_be_a_mapping() -> None:
    with pytest.raises(ValueError, match=r"^allowed-targets: the document must be a mapping$"):
        AllowedTargets.from_document([])


def test_every_list_is_read() -> None:
    assert AllowedTargets.from_document(TARGETS) == AllowedTargets(
        tuple(TARGETS["domains"]),
        tuple(ipaddress.ip_network(n) for n in TARGETS["networks"] + TARGETS["lab_networks"]),
        frozenset(TARGETS["external_targets"]),
    )


def test_unknown_keys_are_named_in_order() -> None:
    document: dict[Any, Any] = {**TARGETS, "b": [], 1: [], "a": []}

    with pytest.raises(ValueError, match=r"^allowed-targets: unknown keys 1, a, b$"):
        AllowedTargets.from_document(document)


@pytest.mark.parametrize(
    ("key", "values", "message"),
    [
        ("domains", "x", "domains must be a list of distinct texts"),
        ("domains", ["Example.com"], "domains must hold host names in lower case"),
        ("external_targets", ["a b"], "external_targets must hold host names in lower case"),
        ("networks", ["127.0.0.1/8"], "networks must hold networks without host bits"),
        ("lab_networks", ["10.0.0.1/8"], "lab_networks must hold networks without host bits"),
    ],
)
def test_each_refusal_names_its_list(key: str, values: object, message: str) -> None:
    with pytest.raises(ValueError, match=f"^allowed-targets: {message}$"):
        AllowedTargets.from_document({**TARGETS, key: values})


@pytest.mark.parametrize(
    ("inject_content", "field"),
    [
        ({"targets": "10.0.0.5"}, "/targets"),  # a whole address
        ({"targets": "evil.com"}, "/targets"),  # a whole host name
        ({"targets": " evil.com. "}, "/targets"),
        ({"key": "user.email"}, "/key"),  # a whole value that reads as a host name is one
        ({"url": "http://10.0.0.5/admin"}, "/url"),
        ({"url": "https://user:pw@intranet.corp:8443/x"}, "/url"),
        ({"url": "ftp://[fe80::1]/x"}, "/url"),
        ({"url": "HTTP://EVIL.COM"}, "/url"),
        ({"url": "://evil.com/x"}, "/url"),  # no scheme, still a link
        ({"url": "smb://%31%30.0.0.1/share"}, "/url"),
        ({"body": "Open http://intranet.local/reset to reset."}, "/body"),
        ({"command": "ping -c 1 10.1.2.3"}, "/command"),
        ({"command": "curl 10.1.2.3:8080/x"}, "/command"),
        ({"command": "ssh fe80::1"}, "/command"),
        ({"command": "ping ::ffff:10.0.0.5"}, "/command"),
        ({"nested": [{"deep": {"host": "8.8.8.8"}}]}, "/nested/0/deep/host"),
        ({"a~b/c": "10.0.0.5"}, "/a~0b~1c"),
        # A variable next to a host: what the platform fills in still reaches the host.
        ({"url": "http://${x}.evil.com/"}, "/url"),
        ({"url": "http://example.com${x}.evil.com"}, "/url"),
        ({"url": "http://evil.com{{x}}"}, "/url"),
        ({"url": "http://#{x}@evil.com"}, "/url"),
        ({"url": "http://#{x}.evil.com"}, "/url"),
        # Quotes a shell removes.
        ({"command": "curl http://example.com''.evil.com"}, "/command"),
        ({"command": 'curl http://example""@evil.com'}, "/command"),
        # Links without "://".
        ({"html": '<a href="//evil.com/x">'}, "/html"),
        ({"css": "url(//evil.com/a.png)"}, "/css"),
        ({"command": "copy x \\\\evil.com\\share"}, "/command"),
        ({"command": "start http:\\\\evil.com"}, "/command"),
        ({"command": "start http:/\\evil.com"}, "/command"),
        # A whole value that is a host with a port or a path.
        ({"targets": "evil.com:443"}, "/targets"),
        ({"targets": "evil.com/path?x=1"}, "/targets"),
        ({"targets": "evil.com#a"}, "/targets"),
        ({"targets": "evil.exe:80"}, "/targets"),  # a port makes it a host
        # IPv4 glued to letters, and the forms a resolver reads as an address.
        ({"command": "feed:8.8.8.8"}, "/command"),
        ({"command": "cafe8.8.8.8"}, "/command"),
        ({"command": "ping 010.010.010.010"}, "/command"),
        ({"command": "ping 0010.0.0.5"}, "/command"),  # octal: 8.0.0.5
        ({"command": "ping 0x0a.0.0.5"}, "/command"),
        ({"targets": "0x08080808"}, "/targets"),  # one part, the whole value: 8.8.8.8
        ({"targets": "0x0000000008080808"}, "/targets"),  # zeros a resolver ignores
        ({"command": "ping 000000000010.8.8.8"}, "/command"),
        ({"command": "target is 8.8.8.8."}, "/command"),  # a sentence ends after it
        ({"command": "ping 0x08.0x08.0x0808."}, "/command"),
        ({"command": "addr:2001:4860::1"}, "/command"),  # one colon before an IPv6 address
        ({"command": "ssh root@8.8.8.8"}, "/command"),  # an address after "@" is no e-mail
        ({"command": "scp f root@10.0.0.5:/tmp"}, "/command"),
        ({"command": "ssh root@[2001:4860::1]"}, "/command"),
        ({"targets": "admin@[10.0.0.5]"}, "/targets"),  # a domain literal names an address
        ({"command": "x@evil.com10.0.0.5"}, "/command"),
        ({"command": "a@b.co.8.8.8.8"}, "/command"),
        ({"command": "ping 0x100.0.0.1"}, "/command"),  # 100.0.0.1 glued to "0x": refused
        ({"command": "ping 0x0a.0.0.255"}, "/command"),
        ({"command": "ping 0xff.0.0.1"}, "/command"),
        ({"command": "error 0x80070005, then ping 0x08.0x08.0x0808"}, "/command"),
        ({"command": "mail a@b.com, then ping 0x08.0x08.0x0808"}, "/command"),
        ({"command": "ping 0x08.0x08.0x0808"}, "/command"),  # three parts: 8.8.8.8
        ({"command": "ping 010.0x80808"}, "/command"),  # two parts: 8.8.8.8
        ({"targets": "01002004010"}, "/targets"),  # octal, one part, the whole value: 8.8.8.8
        ({"command": "ping 999.1.1.1"}, "/command"),
        # What a compatibility form or an IDNA tool turns into a host.
        ({"targets": "evil" + chr(0x3002) + "com"}, "/targets"),
        ({"targets": "evil" + chr(0xFF0E) + "com"}, "/targets"),
        ({"targets": chr(0xFF45) + "vil.com"}, "/targets"),
        ({"targets": "ev" + chr(0xAD) + "il.com"}, "/targets"),
        ({"targets": "evil.com" + chr(0)}, "/targets"),
        ({"targets": "b" + chr(0xFC) + "cher.de"}, "/targets"),
        ({"targets": "b" + chr(0xFC) + "cher.example"}, "/targets"),  # not ASCII: never allowed
        ({"url": "http://[evil.com]/"}, "/url"),  # brackets around a name
        ({"url": "http://www.example.orgX/"}, "/url"),
        ({"url": "http://www.example.com:1:2/"}, "/url"),  # several colons: no host
        ({"command": "ping fe80::"}, "/command"),
        ({"command": "ping fe80::1."}, "/command"),
        ({"command": "ping ::1 then fe80::1"}, "/command"),
        ({"targets": ("a" * 63 + ".") * 3 + "a" * 57 + ".com."}, "/targets"),  # 254, the bound
        # A key holding a link or an address.
        ({"http://evil.com": 1}, "/http:~1~1evil.com"),
        ({"10.0.0.5": "x"}, "/10.0.0.5"),
    ],
)
def test_a_host_outside_the_allowed_targets_is_refused(
    inject_content: dict[str, Any], field: str
) -> None:
    (finding,) = policy_findings(DATA, with_inject_content(inject_content))

    assert (finding.code, finding.severity, finding.path, finding.field, finding.message) == (
        "POL-003",
        Severity.BLOCKING,
        JSON,
        f"/scenario_injects/0/inject_content{field}",
        MESSAGE,
    )


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "http://www.example.com/a",
        "https://user@host.example.org:8443/x",
        "http://[2001:db8::1]:80/",
        "http://10.42.0.7/",  # the test environment
        "http://#{target}/path",  # a variable the platform fills
        "http://${target}:8080/",
        "http://{{target}}/",
        "file:///etc/hosts",  # no host
        "ping 127.0.0.1 then 192.0.2.4.",
        "version 1.2.3.4.5",  # no address
        "std::string",
        "12:30:00",
        "00:1a:2b:3c:4d:5e",
        "#{user.email}",  # a variable, never a host name
        "",
        "deadbeef",
        "Run the scan.",
        "http://#{x}.example.com/",  # a variable inside an example name
        "http://${target}",
        '<a href="http://www.example.com/">x</a>',
        "see http://www.example.com, then",
        "report.pdf",  # a file name, never a host
        "cmd.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "/usr//lib/x",
        "// a comment",
        "10.0.19041",  # a version
        "user@evil.com",  # an e-mail address, another rule's matter
        "host.example.com:8443/path",
        "http://www.exam" + chr(0x200B) + "ple.com/",  # an invisible character, dropped
        "http://[::1]x]/",  # a bracketed address ends at its first "]"
        "archive.tar.gz",
        "report.pdf.",
        "x fe80",
        "ping 0177.0.0.1",  # octal loopback
        "ping 0x7f000001",  # hexadecimal loopback
        "reg add HKLM\\x /v y /t REG_DWORD /d 0x00000001",  # 0.0.0.1: this network, no host
        "exit 0x1",
        "write to admin@corp.com",  # an e-mail address, another rule's matter
        "mail admin@[2001:db8::1]",  # a domain literal with a documentation address
        "error 0x80070005",  # one part in free text: a number, never an address
        "magic 0xdeadbeef",
        "ping 0x08080808",  # one part in free text: a limit, a number cannot be told apart
        "0x1.0x1000000",  # out of range: no resolver reads it as an address
        "089",  # not octal: no address
        "version 10.1",  # two decimal parts: a version
        "Le 15.01.2024, la crise commence.",  # a date, never an octal address
        "01.02.2024",
        "chmod 0755 run.sh",  # a file mode
        "Pr" + chr(0xE9) + "parer l'exercice de crise.",  # a sentence, never a host
        chr(0xE9) + "a" * 70,  # a label IDNA cannot encode: no host
    ],
)
def test_allowed_or_hostless_values_pass(value: str) -> None:
    assert policy_findings(DATA, with_inject_content({"field": value})) == ()


def test_a_dotted_key_is_no_host_name() -> None:
    assert policy_findings(DATA, with_inject_content({"user.email": "x"})) == ()


def test_a_key_and_its_value_are_reported_once() -> None:
    assert _pol_003(policy_findings(DATA, with_inject_content({"10.0.0.5": "8.8.8.8"}))) == [
        "/scenario_injects/0/inject_content/10.0.0.5"
    ]


def test_one_rule_alone_reads_its_data() -> None:
    failing = with_inject_content({"targets": "10.0.0.5"})

    assert [f.code for f in rule_findings("POL-003", DATA, failing)] == ["POL-003"]


def test_a_value_is_reported_once_whatever_it_names() -> None:
    value = "http://10.0.0.5/ and http://evil.com/ and 8.8.8.8"

    assert _pol_003(policy_findings(DATA, with_inject_content({"x": value}))) == [
        "/scenario_injects/0/inject_content/x"
    ]


@pytest.mark.parametrize(
    ("part", "pointer"),
    [
        ("scenario_articles", "/scenario_articles/0/article_content"),
        ("scenario_channels", "/scenario_channels/0/article_content"),
        ("scenario_challenges", "/scenario_challenges/0/article_content"),
    ],
)
def test_exercise_texts_are_checked(part: str, pointer: str) -> None:
    stored = {"scenario_information": {}, part: [{"article_content": "see http://10.0.0.5/"}]}

    assert _pol_003(policy_findings(DATA, content(stored=stored))) == [pointer]


def test_descriptions_titles_contract_copies_and_senders_are_left_out() -> None:
    stored = {
        "scenario_information": {
            "scenario_description": "see https://10.0.0.5/report",
            "scenario_mail_from": "a@10.0.0.5",
        },
        "scenario_injects": [
            {
                "inject_title": "Scan 10.0.0.5",
                "inject_description": "http://evil.com",
                "inject_injector_contract": {"injector_contract_content": "http://10.0.0.5"},
                "inject_content": {"targets": ""},
            }
        ],
    }

    assert _pol_003(policy_findings(DATA, content(stored=stored))) == []


@pytest.mark.parametrize(
    "stored",
    [
        None,
        [],
        {"scenario_injects": None},
        {"scenario_injects": [None, "x", {"inject_content": None}, {"inject_content": 5}]},
        {"scenario_articles": "x"},
        {"scenario_injects": [{"inject_content": {"n": 10, "b": True, "z": None}}]},
    ],
)
def test_a_stored_scenario_not_shaped_like_one_is_left_to_its_own_check(stored: object) -> None:
    assert _pol_003(policy_findings(DATA, content(stored=stored))) == []


def test_a_whole_value_is_a_host_name_only_up_to_253_characters() -> None:
    long_name = ("a" * 63 + ".") * 4 + "com"

    assert _pol_003(policy_findings(DATA, with_inject_content({"t": long_name}))) == []


def _seconds(value: str) -> float:
    entry = with_inject_content({"x": value})
    runs = []
    for _ in range(3):
        start = time.perf_counter()
        policy_findings(DATA, entry)
        runs.append(time.perf_counter() - start)
    return min(runs)


@pytest.mark.parametrize(
    "unit",
    ["a", "://", "1.", "1:", "http://a", "a" * 63 + "."],
    ids=["letters", "links", "dots", "colons", "schemes", "labels"],
)
def test_a_long_value_is_read_in_linear_time(unit: str) -> None:
    small, large = _seconds(unit * 5_000), _seconds(unit * 20_000)

    assert large < 8 * small + 0.05
