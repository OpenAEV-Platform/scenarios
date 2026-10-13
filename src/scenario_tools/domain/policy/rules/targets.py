"""Allowed targets: what an inject could reach and what a player reads names only example names,
loopback and test addresses, the test environment's ranges and authorised external targets, so
that a shared scenario never points at someone's system.

The content of every inject and the exercise texts (articles, channels, challenges) are read;
descriptions, which hold references, recorded contract copies, which their own check compares,
and e-mail addresses, which a rule of their own reads, are not. A text is first read as a tool
would: compatibility forms folded, invisible characters dropped, and every variable the platform
fills (``#{…}``, ``${…}``, ``{{…}}``) replaced by one label, so that a variable stands for a
host only when it is the whole host. A host is then found where it is unambiguous: after every
``://``, ``//`` or ``\\\\`` that starts a link, in every IP address, also in a form a resolver
accepts (leading zeros, hexadecimal parts), and in a value that is a whole host name, with a
port or a path; a name that is not ASCII is never allowed. Keys are read for links and
addresses. Free text is never searched for bare names, and a whole value that ends with a file
extension is a file. A refused value is never quoted.
"""

import ipaddress
import re
import unicodedata
from collections.abc import Iterator, Mapping
from typing import Any

from scenario_tools.domain.catalogue.structure import INJECTS
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.policy.targets import AllowedTargets
from scenario_tools.domain.shared.finding import Severity

_CONTENT = "inject_content"
_EXERCISE_TEXTS = ("scenario_articles", "scenario_channels", "scenario_challenges")
_DOTS = str.maketrans(dict.fromkeys((chr(0x3002), chr(0xFF61), chr(0xFF0E)), "."))  # full stops
_VARIABLE = re.compile(r"#\{[^}]{0,200}\}|\$\{[^}]{0,200}\}|\{\{[^}]{0,200}\}\}")
_PLACE = "openaev-variable"  # the label a variable becomes
# Where a link starts: "://" anywhere, or "//" and "\\" (with a scheme of two letters or more,
# never a drive) after the start of the text or a separator.
_LINK = re.compile(r"://|(?:^|(?<=[\s\"'=(,<>]))(?:[A-Za-z][A-Za-z0-9+.-]{1,30}:)?[/\\]{2}")
_AUTHORITY = re.compile(r"[^/?#\s<>()\\]*")  # what follows, up to the path
_QUOTES = str.maketrans("", "", "'\"")  # a shell removes them
_NOT_ADDRESS = re.compile(r"[^0-9A-Fa-f:.]+")  # an address holds nothing else
_PORTED = re.compile(r"([^:]*):[0-9]*")  # a host and its port
_SENTENCE_END = re.compile(r"[.:]+\Z")  # the dots and colons that end a sentence or a list
# Four parts a resolver reads as an IPv4 address: decimal, with leading zeros or in hexadecimal.
_IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_PART = r"(?:0[xX][0-9A-Fa-f]{1,8}|0[0-7]{1,3}|[0-9]{1,3})"  # hexadecimal, octal or decimal
_HEX_IPV4 = re.compile(rf"(?<![0-9A-Za-z.]){_PART}(?:\.{_PART}){{3}}(?![0-9A-Za-z.])")
_LABEL = r"[^\W_](?:[\w-]{0,61}[^\W_])?"  # letters and digits of any script
_WHOLE_HOST = re.compile(
    rf"(?P<host>(?:{_LABEL}\.)+[^\W\d_]{{2,63}}\.?)(?P<port>:[0-9]{{1,5}})?(?P<path>[/?#].*)?"
)
_NAME_LIMIT = 254  # the longest DNS name, with its final dot
# The last labels that make a whole value a file name rather than a host.
_FILE_EXTENSIONS = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "vbs",
        "js",
        "jse",
        "hta",
        "msi",
        "lnk",
        "scr",
        "py",
        "sh",
        "pl",
        "rb",
        "php",
        "jar",
        "class",
        "txt",
        "log",
        "csv",
        "json",
        "xml",
        "yaml",
        "yml",
        "ini",
        "conf",
        "cfg",
        "md",
        "html",
        "htm",
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "zip",
        "rar",
        "gz",
        "tar",
        "tgz",
        "bz2",
        "iso",
        "img",
        "bin",
        "dat",
        "tmp",
        "bak",
        "pem",
        "crt",
        "cer",
        "pfx",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "svg",
        "ico",
        "so",
        "deb",
        "rpm",
        "apk",
        "dmg",
    }
)
_MESSAGE = (
    "this value names a host outside the example names, test addresses and authorised targets: "
    "use an example name, such as host.example.com, or a test address"
)


def _texts(value: Any, pointer: str) -> Iterator[tuple[str, str, bool]]:
    """Every text inside ``value``, with its JSON pointer and whether it is a key."""
    if isinstance(value, str):
        yield pointer, value, False
    elif isinstance(value, Mapping):
        for key, child in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            yield f"{pointer}/{escaped}", str(key), True
            yield from _texts(child, f"{pointer}/{escaped}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _texts(child, f"{pointer}/{index}")


def _as_read(text: str) -> str:
    """``text`` as a tool reads it: compatibility forms folded, invisible characters dropped,
    and each variable one label."""
    text = unicodedata.normalize("NFKC", text).translate(_DOTS)
    text = "".join(c for c in text if c != "\0" and unicodedata.category(c) != "Cf")
    return _VARIABLE.sub(_PLACE, text)


def _link_hosts(text: str) -> Iterator[str]:
    """The host of every link of ``text``, without user information or port."""
    for start in _LINK.finditer(text):
        authority = _AUTHORITY.match(text, start.end())[0].translate(_QUOTES)  # type: ignore[index]
        host = authority.rpartition("@")[2].rstrip(",;!")
        if host.startswith("["):
            host = host[1:].partition("]")[0]
        elif ported := _PORTED.fullmatch(host):
            host = ported[1]  # several colons outside brackets: no host, so refused
        if host and host != _PLACE:
            yield host


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _addresses(text: str) -> Iterator[str]:
    """Every IP address written in ``text``: each IPv4 address, a port after it left out, and
    each IPv6 address that holds a digit, so that ``std::string`` is none, as written or
    without the dots or colons that end a sentence (its leading "::" stays)."""
    yield from (match[0] for match in _IPV4.finditer(text))
    for token in _NOT_ADDRESS.split(text):
        if token.count(":") < 2 or not any(c.isdigit() for c in token):
            continue
        for candidate in (token, _SENTENCE_END.sub("", token)):
            if _is_address(candidate):
                yield candidate
                break


def _odd_address(text: str) -> bool:
    """Whether ``text`` writes an IPv4 address with a hexadecimal or a four-digit octal part,
    which ``ipaddress`` refuses but a resolver reads."""
    return any(not _is_address(match[0]) for match in _HEX_IPV4.finditer(text))


def _whole_host(text: str) -> str | None:
    """The host ``text`` is, alone or with a port or a path, or ``None``; letters of any script
    count, and a name that is not ASCII is never allowed."""
    match = _WHOLE_HOST.fullmatch(text.strip())
    if match is None or len(match["host"]) > _NAME_LIMIT:
        return None
    host = match["host"]
    last = host.removesuffix(".").rpartition(".")[2].lower()
    if last in _FILE_EXTENSIONS and not match["port"] and not match["path"]:
        return None  # a file name
    return host


def _names_another_host(text: str, allowed: AllowedTargets, *, key: bool) -> bool:
    text = _as_read(text)
    if any(not allowed.allows(host) for host in _link_hosts(text)):
        return True
    if any(not allowed.allows(address) for address in _addresses(text)) or _odd_address(text):
        return True
    if key:
        return False  # a key is never a whole host name: keys hold dotted names
    host = _whole_host(text)
    return host is not None and not allowed.allows(host)


def _read(stored: object) -> Iterator[tuple[str, object]]:
    """The parts of the stored scenario the rule reads, with their pointers."""
    if not isinstance(stored, Mapping):
        return
    injects = stored.get(INJECTS)
    if isinstance(injects, list):
        for index, inject in enumerate(injects):
            if isinstance(inject, Mapping):
                yield f"/{INJECTS}/{index}/{_CONTENT}", inject.get(_CONTENT)
    for part in _EXERCISE_TEXTS:
        yield f"/{part}", stored.get(part)


def _check(data: PolicyData, content: EntryContent) -> Iterator[Violation]:
    path = f"{content.directory}/scenario.json"
    reported: set[str] = set()
    for pointer, value in _read(content.stored):
        for field, text, key in _texts(value, pointer):
            if field not in reported and _names_another_host(text, data.targets, key=key):
                reported.add(field)
                yield Violation(path, field, _MESSAGE)


RULE = Rule(
    "POL-003",
    Severity.BLOCKING,
    "Injects and exercise texts name only example names, loopback and test addresses, the test "
    "environment's ranges and authorised external targets.",
    _check,
)
