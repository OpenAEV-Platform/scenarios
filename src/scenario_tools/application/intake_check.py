"""Intake's check mode: the verdicts intake would give on the payloads an export embeds, and the
findings on the payloads a request would claim, from intake's own functions, writing nothing."""

import json
from collections.abc import Mapping
from typing import Any

from scenario_tools.application.assign_payloads import no_attached_files
from scenario_tools.application.intake_entry import adopting, claim_list, refusal_finding
from scenario_tools.application.prepare_entry import prepare_entry
from scenario_tools.domain.catalogue.characters import hidden_character_findings
from scenario_tools.domain.catalogue.intake import FACETS, completed_facets
from scenario_tools.domain.shared.finding import Finding
from scenario_tools.domain.verification.payload_catalogue import Catalogue
from scenario_tools.domain.verification.payload_references import unhashable_findings
from scenario_tools.ports.data import DataLoader
from scenario_tools.ports.schema import SchemaValidator

# What the check mode needs to normalise an export, and never shows: the entry's external ID
# and the catalogue facets an export may lack. The verdicts judge the payloads alone.
CHECKED_ID = "00000000-0000-4000-8000-000000000000"
_CHECKED_FACETS = dict.fromkeys(FACETS.values(), "check") | {FACETS["severity"]: "low"}
_CHECKED_REQUEST = {
    "mode": "update",
    "external_id": CHECKED_ID,
    "domain": "check",
    "slug": "check",
    "issue": 1,
}


def intake_check(
    export: Any,
    claims: object,
    *,
    export_path: str,
    claims_path: str,
    data: DataLoader,
    schema: SchemaValidator,
    payloads: Catalogue,
    external_id: str,
    previous: object = None,
    previous_path: str | None = None,
) -> tuple[Finding, ...]:
    """The verdicts ``intake`` gives on the payloads ``export`` embeds against the catalogue
    ``payloads``, with the findings on ``claims``, a document holding a request's ``payloads``
    alone (none when it is ``None``): from the same functions, writing nothing. The export is
    normalised as intake normalises it for the entry ``external_id``, and, for an update, with
    the entry's stored scenario, ``previous``, read from ``previous_path``: normalisation derives
    the identifiers it orders injects by, and rewrites in values, from both, so the verdicts
    are intake's only with them. A facet the export lacks is given a value the verdicts never
    read."""
    listed: tuple[Mapping[str, Any], ...] = ()
    if claims is not None:
        refused = _claims_refused(claims, claims_path, schema)
        if refused:
            return refused
        listed = tuple(claims["payloads"]) if isinstance(claims, Mapping) else ()
    export, _ = completed_facets(export, {}, _CHECKED_FACETS, export_path)
    prepared, verdict = adopting(
        export,
        lambda form: prepare_entry(
            form,
            external_id,
            data,
            path=export_path,
            previous=previous,
            previous_path=previous_path,
        ),
        lambda form: prepare_entry(form, external_id, data, path=export_path),
        claim_list(listed),
        (export_path, claims_path),
        payloads,
        data,
        schema,
    )
    if prepared.refusals or verdict is None:
        return prepared.refusals
    # A payload that cannot be hashed has no verdict: intake's reference checks refuse it, and
    # the check says so as they do.
    refused = unhashable_findings(
        json.loads(prepared.scenario_json), no_attached_files, export_path
    )
    return (*refused, *verdict.refusals, *verdict.told)


def _claims_refused(claims: object, path: str, schema: SchemaValidator) -> tuple[Finding, ...]:
    """Why the claims document at ``path`` is refused: it is a mapping of ``payloads`` alone,
    the list a request holds, checked against the request's own definition."""
    hidden = hidden_character_findings(claims, path)
    if hidden:
        return hidden
    if not isinstance(claims, Mapping) or set(claims) != {"payloads"}:
        why = "the claims must be a mapping holding the request's payloads list alone"
        return (refusal_finding("SCH-001", path, "", why),)
    violations = schema.validate("intake-request", {**_CHECKED_REQUEST, **claims})
    return tuple(refusal_finding("SCH-001", path, v.pointer, v.message) for v in violations)
