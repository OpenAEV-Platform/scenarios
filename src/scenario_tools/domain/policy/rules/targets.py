"""Allowed targets: what an inject could reach and what a player reads names only example names,
loopback and test addresses, the test environment's ranges and authorised external targets, so
that a shared scenario never points at someone's system.

The content of every inject, the exercise texts (articles, channels, challenges) and the name,
description, key and value of the conditions of a workflow's steps (each item of a list on its own,
never the step a dependency names) are read;
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

from scenario_tools.domain.policy.payloads import (
    COMMAND_LIMIT,
    argument_values,
    commands,
    payloads,
    substituted,
)
from scenario_tools.domain.policy.rule import EntryContent, PolicyData, Rule, Violation
from scenario_tools.domain.policy.targets import AllowedTargets
from scenario_tools.domain.shared.finding import Severity
from scenario_tools.domain.shared.stored import injects
from scenario_tools.domain.shared.workflow import conditions

_CONTENT = "inject_content"
# What a person reads of a condition of a step: its name, its description and the key it reads;
# a filter's value too, below.
_CONDITION_TEXTS = ("condition_name", "condition_description", "condition_key")
_LISTS = frozenset({"IN", "NIN"})  # whose value lists its items between commas
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
# Decimal IPv4 addresses, and the forms of one to four parts a resolver also reads as one
# (inet_aton) when a part is hexadecimal or octal; decimal forms of fewer parts read as versions.
# A sentence may end right after an address: a final dot is no part of it.
# Never inside a longer dotted number (1.2.3.4.5), but after a name and its dot (b.co.8.8.8.8).
_IPV4 = re.compile(r"(?<![0-9])(?<![0-9]\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9]|\.[0-9])")
_PART = r"(?:0[xX]0*[0-9A-Fa-f]{1,8}|0*[0-9]{1,11})"  # leading zeros a resolver ignores
_RESOLVER_IPV4 = re.compile(
    rf"(?<![0-9A-Za-z.]){_PART}(?:\.{_PART}){{0,3}}(?![0-9A-Za-z]|\.[0-9A-Za-z])"
)
_OCTAL = re.compile(r"0[0-9]+")  # a resolver reads it in base 8, and refuses 8 and 9
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")  # a number, such as a flag, never a host
# An e-mail address, another rule's matter: a domain name ending with a top-level name of
# letters, with nothing glued after it. An address after "@" (ssh, scp, a domain literal) is no
# e-mail and stays. Bounded, so that the search stays linear.
_EMAIL = re.compile(r"[\w.+-]{1,64}@(?:[\w-]{1,63}\.){1,8}[^\W\d_]{2,63}(?![\w-]|\.\w)")
_ONE_COLON = re.compile(r"\A:(?!:)")  # "addr:" before an IPv6 address
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
        ended = _SENTENCE_END.sub("", token)
        for candidate in (token, ended, _ONE_COLON.sub("", ended)):
            if _is_address(candidate):
                yield candidate
                break


def _base(part: str) -> int:
    """The base a resolver reads ``part`` in: hexadecimal after "0x", octal after a 0."""
    if part[:2].lower() == "0x":
        return 16
    return 8 if _OCTAL.fullmatch(part) else 10


def _resolved(text: str) -> ipaddress.IPv4Address | None:
    """The IPv4 address a resolver reads in ``text``: one to four parts with a hexadecimal one,
    or one or four parts with an octal one; ``None`` otherwise, decimal forms of fewer parts and
    octal ones of two or three, such as dates, reading as versions or numbers."""
    parts = text.split(".")
    bases = [_base(part) for part in parts]
    if 16 not in bases and not (8 in bases and len(parts) in (1, 4)):
        return None
    try:
        numbers = [int(part, bases[index]) for index, part in enumerate(parts)]
    except ValueError:
        return None  # "08": not octal
    *head, last = numbers
    if any(number > 255 for number in head) or last >= 256 ** (5 - len(numbers)):
        return None
    value = last
    for index, number in enumerate(head):
        value += number << (8 * (3 - index))
    return ipaddress.IPv4Address(value)


def _resolver_addresses(text: str, whole: str) -> Iterator[str]:
    """Every IPv4 address a resolver reads in a hexadecimal or octal form of ``text``, but
    those of this network, which are numbers. A form of one part counts only as the ``whole``
    value: in free text it is a number, such as an error code."""
    for match in _RESOLVER_IPV4.finditer(text):
        if "." not in match[0] and match[0] != whole:
            continue
        address = _resolved(match[0])
        if address is not None and address not in _THIS_NETWORK:
            yield str(address)


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
    whole = text.strip()
    for piece in _EMAIL.split(text):  # the text around e-mail addresses
        found = (*_addresses(piece), *_resolver_addresses(piece, whole))
        if any(not allowed.allows(address) for address in found):
            return True
    if key:
        return False  # a key is never a whole host name: keys hold dotted names
    host = _whole_host(text)
    return host is not None and not allowed.allows(host)


def _read(stored: object) -> Iterator[tuple[str, object]]:
    """The parts of the stored scenario the rule reads, with their pointers."""
    if not isinstance(stored, Mapping):
        return
    for found in injects(stored):
        yield f"{found.pointer}/{_CONTENT}", found.inject.get(_CONTENT)
    for part in _EXERCISE_TEXTS:
        yield f"/{part}", stored.get(part)
    for pointer, condition in conditions(stored):
        for key in _CONDITION_TEXTS:
            yield f"{pointer}/{key}", condition.get(key)
        kind, value = condition.get("condition_type"), condition.get("condition_value")
        if isinstance(kind, str) and kind in _LISTS and isinstance(value, str):  # its items
            for item in value.split(","):
                yield f"{pointer}/condition_value", item.strip()
        elif kind != "DEPEND_ON":  # its value names a step, not a text
            yield f"{pointer}/condition_value", value
    for payload in payloads(stored):
        values = argument_values(payload)
        for field, command, _ in commands(payload):
            resolved = substituted(command, values, COMMAND_LIMIT)  # what the payload runs
            if resolved is not None:  # else too long, which the forbidden actions report
                yield field, resolved


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
    "Injects, exercise texts and the texts of a workflow's conditions name only example names, "
    "loopback and test addresses, the test environment's ranges and authorised external targets.",
    _check,
)
