"""The hosts and addresses a scenario may name, read from the maintainers' data: example names
with their subdomains, networks (loopback, test ranges and the test environment's), and exact
authorised external targets. A host that cannot be read is never allowed."""

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network

_KEYS = ("domains", "networks", "lab_networks", "external_targets")
_NAME = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)


@dataclass(frozen=True)
class AllowedTargets:
    """What may be named: names with their subdomains, networks, and exact external targets."""

    domains: tuple[str, ...]
    networks: tuple[Network, ...]
    external: frozenset[str]

    @classmethod
    def from_document(cls, document: object) -> "AllowedTargets":
        """Read the allowed-targets data document: four lists of distinct texts, names in lower
        case and networks without host bits, so that a typo never widens what is allowed."""
        if not isinstance(document, Mapping):
            raise ValueError("allowed-targets: the document must be a mapping")
        unknown = sorted(str(key) for key in document if key not in _KEYS)
        if unknown:
            raise ValueError(f"allowed-targets: unknown keys {', '.join(unknown)}")
        lists: dict[str, list[str]] = {}
        for key in _KEYS:
            value = document.get(key)
            if (
                not isinstance(value, list)
                or not all(isinstance(item, str) for item in value)
                or len(set(value)) != len(value)
            ):
                raise ValueError(f"allowed-targets: {key} must be a list of distinct texts")
            lists[key] = value
        for key in ("domains", "external_targets"):
            if not all(_NAME.fullmatch(name) for name in lists[key]):
                raise ValueError(f"allowed-targets: {key} must hold host names in lower case")
        networks: list[Network] = []
        for key in ("networks", "lab_networks"):
            for text in lists[key]:
                try:
                    networks.append(ipaddress.ip_network(text))
                except ValueError:
                    raise ValueError(
                        f"allowed-targets: {key} must hold networks without host bits"
                    ) from None
        return cls(tuple(lists["domains"]), tuple(networks), frozenset(lists["external_targets"]))

    def example_domain(self, host: str) -> bool:
        """Whether ``host`` is an example name, or a subdomain of one: a domain an e-mail
        address may use. An authorised external target is a scan target, never an e-mail
        domain, so it does not count here."""
        host = host.strip().lower().removesuffix(".")
        return any(host == domain or host.endswith(f".{domain}") for domain in self.domains)

    def allows(self, host: str) -> bool:
        """Whether ``host``, a name or an address, may be named."""
        host = host.strip().lower().removesuffix(".")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                address = address.ipv4_mapped  # the IPv4 address it reaches
            return any(address in network for network in self.networks)
        if not _NAME.fullmatch(host):
            return False
        return host in self.external or any(
            host == domain or host.endswith(f".{domain}") for domain in self.domains
        )
