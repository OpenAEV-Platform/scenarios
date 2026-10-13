"""Linked, never copied: every source is a link to a public page, and an entry holds only its own
files, so that no report or other document is copied into the catalogue.

The schema already requires each source to be an ``https://`` URI marked TLP:CLEAR. What it
cannot see is where the link leads: user information, an IP address, a host with no dot, a
local, internal or reserved name, or anything but a public DNS name, which no reader outside the
author's network could open; nor a credential in its query or fragment, which would let anyone
open a private page. The link is read here, since the schema has checked its form. A refused link
is never quoted, since it may name a private host or carry a credential.
"""

import ipaddress
import re
from collections.abc import Iterator, Mapping
from typing import Any

from scenario_tools.domain.policy.rule import EntryContent, Rule, Violation
from scenario_tools.domain.shared.characters import hidden_in
from scenario_tools.domain.shared.finding import Severity

OWN_FILES = frozenset({"scenario.yaml", "scenario.json", "README.md", "CHANGELOG.md"})
_OWN = ", ".join(sorted(OWN_FILES))
_SCHEME = "https://"
# Names that never lead to a public page: the special-use names of RFC 2606, RFC 6761, RFC 7686
# and RFC 8375 (the whole of .arpa), the top-level name kept for private use, and the names
# local networks commonly use.
_RESERVED = (
    "localhost",
    "local",
    "test",
    "invalid",
    "example",
    "onion",
    "arpa",
    "internal",
    "localdomain",
    "lan",
    "corp",
    "home",
    "intranet",
    "private",
)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_TOP = re.compile(r"[a-z]{2,63}|xn--[a-z0-9-]{1,59}")
# Query and fragment keys that carry a credential: tokens, keys, passwords and the signatures
# of pre-signed links, compared in lower case once percent-decoded.
_CREDENTIAL_KEYS = frozenset(
    {
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "auth",
        "authorization",
        "key",
        "api_key",
        "apikey",
        "sig",
        "signature",
        "password",
        "passwd",
        "pwd",
        "secret",
        "client_secret",
        "x-amz-signature",
        "x-amz-credential",
        "x-amz-security-token",
        "x-goog-signature",
        "x-goog-credential",
    }
)
_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_COPIED = "sources are linked, never copied into an entry"


def _host_problem(authority: str) -> str | None:
    """What keeps the authority of a link from naming a public host, if anything."""
    if "@" in authority:
        return "holds user information"
    if authority.startswith("["):
        return "has an IP address as its host"
    host = authority.rpartition(":")[0] if ":" in authority else authority
    if not host.isascii():  # lower() would map some letters to ASCII ones
        return "has a host that is not a public DNS name"
    host = host.lower().removesuffix(".")
    if not host:
        return "has no host"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return "has an IP address as its host"
    if any(host == name or host.endswith(f".{name}") for name in _RESERVED):
        return "has a local, internal or reserved host"
    if "." not in host:
        return "has a host with no dot, which only a local network resolves"
    labels = host.split(".")
    if not all(map(_LABEL.fullmatch, labels)) or not _TOP.fullmatch(labels[-1]):
        return "has a host that is not a public DNS name"
    return None


def _carries_credential(parameters: str) -> bool:
    """Whether a query or a fragment holds a key that carries a credential."""
    for parameter in re.split(r"[&;]", parameters):
        key = _ESCAPE.sub(lambda escape: chr(int(escape[1], 16)), parameter.partition("=")[0])
        if key.strip().lower() in _CREDENTIAL_KEYS:
            return True
    return False


def _link_problem(url: str) -> str | None:
    """What keeps the ``https://`` link ``url`` from leading to a public page, if anything."""
    rest, _, fragment = url[len(_SCHEME) :].partition("#")
    rest, _, query = rest.partition("?")
    problem = _host_problem(rest.partition("/")[0])
    if problem is None and (_carries_credential(query) or _carries_credential(fragment)):
        problem = "carries a credential in its query or fragment"
    return problem


def _source_violations(declared: Mapping[str, Any] | None, path: str) -> Iterator[Violation]:
    sources = declared.get("sources") if isinstance(declared, Mapping) else None
    if not isinstance(sources, list):
        return
    for index, source in enumerate(sources):
        url = source.get("url") if isinstance(source, Mapping) else None
        if not isinstance(url, str) or not url.startswith(_SCHEME):
            continue  # the schema refuses it
        problem = _link_problem(url)
        if problem is not None:
            yield Violation(
                path,
                f"/sources/{index}/url",
                f"the source link {problem}: link a public page that any reader can open",
            )


def _showable(name: str) -> bool:
    """Whether a file name may be shown in a finding as it is: a name a directory may hold, which
    never changes the finding's path, printable, without blanks around it that a reader cannot
    see, no path separator of another system, and nothing that hides text from a reviewer."""
    return (
        name not in ("", ".", "..")
        and "/" not in name
        and "\\" not in name
        and name.strip() == name
        and name.isprintable()
        and not hidden_in(name)
    )


def _file_violations(directory: str, files: frozenset[str]) -> Iterator[Violation]:
    others = files - OWN_FILES
    hidden = [name for name in others if not _showable(name)]
    if hidden:
        count = f"{len(hidden)} file" + ("s" if len(hidden) > 1 else "")
        yield Violation(
            directory,
            "",
            f"the entry holds {count} whose name cannot be shown safely, besides its own files "
            f"({_OWN}): {_COPIED}",
        )
    for name in sorted(others.difference(hidden)):
        yield Violation(
            f"{directory}/{name}",
            "",
            f"this file is not one of the entry's own ({_OWN}): {_COPIED}",
        )


def _check(content: EntryContent) -> Iterator[Violation]:
    yield from _source_violations(content.declared, f"{content.directory}/scenario.yaml")
    yield from _file_violations(content.directory, content.files)


RULE = Rule(
    "POL-001",
    Severity.BLOCKING,
    "Sources are linked, never copied: each source link leads to a public page and carries no "
    "credential, and an entry holds only its own files.",
    _check,
)
