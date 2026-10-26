"""What intake writes once a request is accepted: the entry's files, the plan of the pull request,
and both written in one go, or nothing kept."""

import contextlib
import json
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from scenario_tools.application.intake_entry import IntakeResult
from scenario_tools.application.render_sheet import SHEET
from scenario_tools.domain.catalogue.intake import intake_plan
from scenario_tools.domain.shared.canonical import ContentHash
from scenario_tools.domain.shared.finding import Finding
from scenario_tools.ports.errors import EnvironmentProblemError
from scenario_tools.ports.plan import PlanSink
from scenario_tools.ports.repository import EntryWriter


def intake_files(
    result: IntakeResult, render: Callable[[dict[str, Any]], bytes]
) -> dict[str, bytes]:
    """The files intake writes in the entry, by name, in the order they are written: its
    ``scenario.yaml`` first when there is one to write, as ``render`` writes it, then its
    ``scenario.json``; none when the request is refused or changes nothing."""
    if result.refusals or not result.changed or result.scenario_json is None:
        return {}
    files = {} if result.metadata is None else {"scenario.yaml": render(result.metadata)}
    if result.changelog is not None:
        files["CHANGELOG.md"] = result.changelog
    if result.sheet is not None:
        files[SHEET] = result.sheet
    files["scenario.json"] = result.scenario_json
    return files


def plan_document(
    result: IntakeResult, files: Mapping[str, bytes], base: str, findings: Iterable[Finding]
) -> dict[str, Any]:
    """The plan of the pull request: the files written with their digests, from the commit
    ``base``, and what is left, from intake and from the checks of the entry written."""
    if result.request is None or result.refusals:
        raise ValueError("a refused request has no plan")
    entry = result.request.entry
    digests = {f"{entry}/{name}": ContentHash.of_bytes(data).hex for name, data in files.items()}
    digests.update(
        {path: ContentHash.of_bytes(data).hex for path, data in result.payload_files.items()}
    )
    return intake_plan(
        result.request,
        base=base,
        changed=result.changed,
        files=digests,
        checklist=(*result.to_complete, *findings),
        changes=result.payload_changes,
    )


def write_intake(
    result: IntakeResult,
    *,
    entries: EntryWriter,
    plan: PlanSink,
    base: str,
    current: Callable[[], str],
    validate: Callable[[str], tuple[Finding, ...]],
    render: Callable[[dict[str, Any]], bytes],
) -> tuple[Finding, ...]:
    """Write the entry ``result`` says and its plan, from the commit ``base``, in one go: the
    plan's place is reserved first, then the entry is written and checked as ``validate``
    checks it, and the plan is published only once the checkout's commit, as ``current`` reads
    it once sure its path still names the checkout held, is still ``base``, then, last, the
    entry is known to be still where and as it was written. The entry is
    kept only with its plan: if anything stops the run before, what was written is taken back
    and the place given back. What is left to complete and the entry's findings are given. The
    caller holds the repository from the catalogue's check that made ``result`` until this
    returns."""
    if result.request is None or result.refusals:
        raise ValueError("a refused request is never written")
    entry = result.request.entry
    with plan.reserving() as reservation, contextlib.ExitStack() as stack:
        files = intake_files(result, render)
        # The new payload versions first: a new payload's in a folder of its own, a new version
        # of a payload in that payload's folder. The entry's check reads them, and they are
        # taken back with it if anything stops the run.
        versions = []
        for path, data in sorted(result.payload_files.items()):
            folder, name = path.rsplit("/", 1)
            held: dict[str, bytes] | None = {} if path in result.payload_changes else None
            versions.append(
                stack.enter_context(entries.writing(folder, {name: data}, previous=held))
            )
        written = stack.enter_context(entries.writing(entry, files, previous=result.previous))
        findings = validate(entry)
        document = plan_document(result, files, base, findings)
        if current() != base:  # the plan must describe what its base gives
            raise EnvironmentProblemError(
                "the checkout's commit changed while the run wrote: nothing is kept"
            )
        for checked in (*versions, written):  # last: what the checkout's check leaves out
            checked.check()
        reservation.publish(json.dumps(document, indent=2).encode() + b"\n")
    return (*result.to_complete, *findings)
