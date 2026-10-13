"""The security products a shared scenario never names, as one pattern found in a command read
by ``as_command``. A product's name is found anywhere, even fused to other letters
(``CrowdStrikeFalcon``, ``crowdstrike's``), its words joined by a blank, an underscore, a dot,
a hyphen or nothing at all; a short name that other words hold (``eset`` in ``reset``) is found
only as a whole word."""

import re
from collections.abc import Mapping

_NAME = re.compile(r"[a-z0-9]+(?: [a-z0-9]+){0,4}")
_NAME_LIMIT = 100
_KEYS = ("products", "words")


def _names(items: list[object]) -> list[str]:
    names: list[str] = []
    for name in items:
        if not isinstance(name, str) or len(name) > _NAME_LIMIT or not _NAME.fullmatch(name):
            raise ValueError("vendor-names: a product must be a name in lower case")
        names.append(name)
    return names


def _alternatives(names: list[str]) -> str:
    """Each name, its words joined by a blank, an underscore, a dot, a hyphen or nothing."""
    return "|".join(re.escape(name).replace(r"\ ", r"[\s_.-]?") for name in names)


def vendors_from_document(document: object) -> re.Pattern[str]:
    """Read the vendor-names data document: products, found anywhere, and short names, found as
    whole words; distinct names in lower case, at least one product."""
    shape = "vendor-names: the document must be a mapping holding products and words"
    if not isinstance(document, Mapping):
        raise ValueError(shape)
    listed, short = document.get("products"), document.get("words")
    if not isinstance(listed, list) or not isinstance(short, list):
        raise ValueError(shape)
    unknown = sorted(str(key) for key in document if key not in _KEYS)
    if unknown:
        raise ValueError(f"vendor-names: unknown keys {', '.join(unknown)}")
    products, words = _names(listed), _names(short)
    if not products:
        raise ValueError("vendor-names: products must name at least one product")
    if len(set(products + words)) != len(products) + len(words):
        raise ValueError("vendor-names: each product once")
    found = _alternatives(products)
    if words:
        found += rf"|(?<![a-z0-9])(?:{_alternatives(words)})(?![a-z0-9])"
    return re.compile(found)
