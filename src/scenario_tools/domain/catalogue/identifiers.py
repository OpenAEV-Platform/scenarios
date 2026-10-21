"""Deterministic identifiers, and inject matching across versions.

Every identifier is a UUIDv5, so anyone can recompute it: the root namespace derives from the
repository URL, a scenario's namespace from its external ID, and an object's ID from its type and
a key. A new version keeps the IDs of the previous one, so that installed scenarios can be matched
inject by inject. Injects are matched in this order: the explicit mapping; an ID that is already
one of the previous version, for a document normalised again; the same authoring instance; the
same contract and title, when one candidate is left; and among several candidates, the one whose
parent injects already match. What remains ambiguous is refused. The steps of a workflow are
matched the same way, a step's source identifier being its signature digest: the caller matches
unchanged content first, there is no authoring instance to match, and a new step whose derived
identifier another step kept takes the next free one.
"""

import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

NS_OPENAEV_SCENARIOS = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/OpenAEV-Platform/scenarios"
)


def scenario_namespace(external_id: str) -> uuid.UUID:
    """The namespace of a scenario's identifiers, from its external ID in any UUID spelling."""
    try:
        canonical = uuid.UUID(external_id)
    except ValueError as error:
        raise ValueError(f"external ID {external_id!r} is not a UUID") from error
    return uuid.uuid5(NS_OPENAEV_SCENARIOS, str(canonical))


def stable_id(namespace: uuid.UUID, object_type: str, key: str) -> str:
    """The stable ID of an object, from its type and a key: its external ID, its name, or its ID
    in the source export, depending on the type.

    The type is a fixed name, never empty and without ``:``, so that ``type:key`` splits only one
    way and two objects can never share an ID.
    """
    if not object_type or ":" in object_type:
        raise ValueError(f"object type {object_type!r} must be a non-empty name without ':'")
    return str(uuid.uuid5(namespace, f"{object_type}:{key}"))


@dataclass(frozen=True)
class InjectSignature:
    """What identifies an inject across versions: its ID, contract, title and parents.

    For the new export, ``id`` and ``parents`` are source IDs; for the previous version, they
    are stable IDs.
    """

    id: str
    contract: str
    title: str
    parents: tuple[str, ...]


@dataclass(frozen=True)
class InjectMatching:
    """Stable ID of every inject of the new export, which of them are new, and which injects of
    the previous version were removed."""

    ids: Mapping[str, str]
    new: tuple[str, ...]
    removed: tuple[str, ...]


class InjectMatchingError(ValueError):
    code = ""


class AmbiguousInjectError(InjectMatchingError):
    """An inject matches several injects of the previous version, or several injects compete for
    one; an explicit mapping resolves it."""

    code = "VER-010"

    def __init__(
        self, source_id: str, candidates: Sequence[str], object_type: str = "inject"
    ) -> None:
        super().__init__(
            f"{object_type} {source_id!r} cannot be matched unambiguously with the previous "
            f"version; candidates: {', '.join(candidates)}"
        )
        self.source_id = source_id
        self.candidates = tuple(candidates)


class InvalidInjectMappingError(InjectMatchingError):
    code = "VER-011"


def _index(signatures: Sequence[InjectSignature], label: str) -> dict[str, InjectSignature]:
    index: dict[str, InjectSignature] = {}
    for signature in signatures:
        if signature.id in index:
            raise ValueError(f"duplicate inject ID {signature.id!r} in the {label} version")
        index[signature.id] = signature
    return index


class _Matcher:
    def __init__(
        self,
        namespace: uuid.UUID,
        new: dict[str, InjectSignature],
        previous: dict[str, InjectSignature],
        object_type: str,
        content_sources: bool,
    ) -> None:
        self.namespace = namespace
        self.object_type = object_type
        self.content_sources = content_sources
        self.new = new
        self.previous = previous
        # Sorted once: comparing parents must not cost a sort for every candidate at every pass.
        self.previous_parents = {
            target: tuple(sorted(signature.parents)) for target, signature in previous.items()
        }
        self.ids: dict[str, str] = {}
        self.taken: set[str] = set()

    def assign(self, source: str, target: str) -> None:
        self.ids[source] = target
        self.taken.add(target)

    def apply_mapping(self, mapping: Mapping[str, str]) -> None:
        for source, target in sorted(mapping.items()):
            if source not in self.new:
                raise InvalidInjectMappingError(f"unknown source {self.object_type} {source!r}")
            if target not in self.previous:
                raise InvalidInjectMappingError(
                    f"stable ID {target!r} is not in the previous version"
                )
            if target in self.taken:
                raise InvalidInjectMappingError(f"stable ID {target!r} used twice")
            self.assign(source, target)

    def match_already_normalised(self) -> None:
        for source in sorted(self.new):
            if source not in self.ids and source in self.previous and source not in self.taken:
                self.assign(source, source)

    def match_same_instance(self) -> None:
        if self.content_sources:  # a source is content, not an instance's identifier
            return
        for source in sorted(self.new):
            derived = stable_id(self.namespace, self.object_type, source)
            if source not in self.ids and derived in self.previous and derived not in self.taken:
                self.assign(source, derived)

    def groups(self) -> dict[tuple[str, str], tuple[list[str], list[str]]]:
        """Unmatched injects and free candidates, by contract and title."""
        groups: dict[tuple[str, str], tuple[list[str], list[str]]] = {}
        for source in sorted(self.new):
            if source not in self.ids:
                signature = self.new[source]
                groups.setdefault((signature.contract, signature.title), ([], []))[0].append(source)
        for target in sorted(self.previous):
            if target not in self.taken:
                signature = self.previous[target]
                groups.setdefault((signature.contract, signature.title), ([], []))[1].append(target)
        return groups

    def match_by_signature(self) -> None:
        progress = True
        while progress:
            progress = False
            for sources, candidates in self.groups().values():
                if len(sources) == 1 and len(candidates) == 1:
                    self.assign(sources[0], candidates[0])
                    progress = True
                elif sources and candidates:
                    progress |= self.match_by_parents(sources, candidates)
        for sources, candidates in sorted(self.groups().values()):
            if sources and candidates:
                raise AmbiguousInjectError(sources[0], candidates, self.object_type)

    def match_by_parents(self, sources: list[str], candidates: list[str]) -> bool:
        by_parents: dict[tuple[str, ...], list[str]] = {}
        for target in candidates:
            by_parents.setdefault(self.previous_parents[target], []).append(target)
        options: dict[str, list[str]] = {}
        for source in sources:
            parents = self.new[source].parents
            if all(parent in self.ids for parent in parents):
                wanted = tuple(sorted(self.ids[parent] for parent in parents))
                options[source] = by_parents.get(wanted, [])
        claims = Counter(found[0] for found in options.values() if len(found) == 1)
        matched = False
        for source, found in sorted(options.items()):
            if len(found) == 1 and claims[found[0]] == 1:
                self.assign(source, found[0])
                matched = True
        return matched

    def give_new_ids(self) -> tuple[str, ...]:
        fresh = []
        for source in sorted(self.new):
            if source in self.ids:
                continue
            derived = stable_id(self.namespace, self.object_type, source)
            retry = 0
            while derived in self.taken and self.content_sources:
                retry += 1
                derived = stable_id(self.namespace, self.object_type, f"{source}:{retry}")
            if derived in self.taken:
                raise InvalidInjectMappingError(
                    f"{self.object_type} {source!r} would get {derived!r}, already given to "
                    f"another {self.object_type}"
                )
            self.assign(source, derived)
            fresh.append(source)
        return tuple(fresh)


def match_injects(
    namespace: uuid.UUID,
    new: Sequence[InjectSignature],
    previous: Sequence[InjectSignature],
    mapping: Mapping[str, str] | None = None,
    object_type: str = "inject",
    *,
    content_sources: bool = False,
) -> InjectMatching:
    """Give every inject (or step) of ``new`` a stable ID, reusing those of ``previous``.
    ``content_sources`` says that a source identifier is derived from content, as a step's
    signature digest is, rather than given by an instance."""
    matcher = _Matcher(
        namespace, _index(new, "new"), _index(previous, "previous"), object_type, content_sources
    )
    matcher.apply_mapping(mapping or {})
    matcher.match_already_normalised()
    matcher.match_same_instance()
    matcher.match_by_signature()
    fresh = matcher.give_new_ids()
    removed = tuple(sorted(set(matcher.previous) - matcher.taken))
    return InjectMatching(ids=dict(sorted(matcher.ids.items())), new=fresh, removed=removed)
