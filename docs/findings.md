# Findings

The tools report what they find as **findings**. Each finding has:

- a **code**, such as `SCH-001`: its family, then a number;
- a **severity**: blocking (it must be fixed before the entry is accepted) or info (worth a look,
  never blocking), written `BLOCKING` or `INFO` in the text output and `"blocking"` or `"info"` in
  the JSON output;
- the **path** of the file it is about, relative to the repository, and the **field** inside it,
  as a JSON pointer such as `/requires/openaev` (empty for the whole file);
- a **message** that says what is wrong and, most of the time, what to do.

With `--format json`, a command prints one JSON document: `{command, ok, findings}`, with an
`error` member as well when the environment stops it. A usage error is printed as text on the
error output whatever the format. A report shows at most 100 findings; when there are more, one
last finding (`IO-016`) counts the rest.

A command exits with `0` when nothing blocks, `1` when a finding blocks, `2` on a usage error,
`3` when the environment stops it (a file it cannot read, a platform it cannot reach), and `4` on
a defect of the tool itself.

## Inputs: `IO`

These protect the tools from files that are too large, malformed or crafted. They apply to every
file the tools read: exports, archives, requests, scenario files.

| Code | What it means | What to do |
|---|---|---|
| `IO-001` | The file is larger than the tools accept. | Make it smaller, or check it is the right file. |
| `IO-002` | The file is not valid JSON or YAML (syntax or encoding). | Fix the syntax; save it as UTF-8. |
| `IO-003` | The YAML uses an anchor, an alias or a merge key. | Write the values out in full. |
| `IO-004` | The data is nested deeper than the tools accept. | Flatten the structure. |
| `IO-005` | A key appears twice in the same object or mapping. | Keep one. |
| `IO-006` | A value JSON cannot represent exactly: `NaN`, `Infinity`, a number out of range, an integer beyond ±(2^53−1), a broken Unicode character, or a YAML type JSON does not have. | Use a plain number, string or boolean. |
| `IO-007` | The archive is not a valid ZIP file, or uses a feature the tools refuse. | Export the scenario again from the platform. |
| `IO-008` | The archive, once decompressed, is too large, or an entry's real size differs from the size it declares. | Export again; do not edit the archive by hand. |
| `IO-009` | The archive holds too many entries. | Export again. |
| `IO-010` | An entry of the archive has an unsafe name: empty, absolute, with `..`, a backslash, a drive letter or a NUL character, or a name an extra field would change. | Export again from the platform. |
| `IO-011` | The archive holds a link. | Export again. |
| `IO-012` | Two entries of the archive have the same name, ignoring case. | Export again. |
| `IO-013` | A path is not what it should be: a symbolic link, a device, a directory where a file is expected, or a file where a directory is expected. Links are never followed, in an archive or in the repository. | Replace it with a regular file or directory, as the message says. |
| `IO-014` | The input is not shaped as the tools expect: an export that is not shaped like an OpenAEV scenario export (a missing or wrong field, an identifier that is not a UUID, a part the tools do not handle yet, an export version they do not read, injects and a workflow together, a workflow with no step or beyond its bounds, a key outside the closed lists of `policy/data/export-keys.yaml`, a workflow setting outside its bounds, a scope or a condition linked to no step (refused, never removed); a step that does not run the inject of a command payload on the platform's implant, holds run state, a non-empty input, targets, assets, teams or documents, or a key outside the classification of its inject; a step identifier given twice, a condition held by two steps or whose copies differ, conditions that do not form one tree per step, a dependency on no step of the scenario, steps that wait for each other, two steps that run the same payload under the same title after the same steps, two identical conditions under one parent, a condition that maps a step's output into another (refused for good), a type of condition not supported (a condition is a dependency, a filter, `AND` or `OR`), a dependency that is not the only condition of its step, a filter that holds a condition, an `AND` or `OR` that holds none, an `IN` or `NIN` list with no value, a filter value that is not text, an `AND` or `OR` with a value, or a filter value that quotes a step or a condition; the finding's field points at the node at fault), a release archive holding what `build` never writes, a stored scenario whose workflow `archive` refuses as normalisation would (its graph, or a condition out of the subset), or an `expected.json` of the release fixtures out of shape. | For an export, export again, and if it persists, open an issue with the platform version; otherwise, build the release or the fixtures again. |
| `IO-015` | Policy data was found at more than one level above the output: an entry may not carry its own rules. | Remove the extra `policy/` directory. |
| `IO-016` | The report holds more findings than it shows; this one counts the rest. | Fix the findings shown, then run the command again. |
| `IO-017` | A text holds an invisible or direction-changing character (such as a right-to-left override), which could make a reviewer read something other than what the platform runs. | Remove the character; the message gives its position. |

## Scenario entries: `SCH`

These check an entry of the catalogue: its place, its `scenario.yaml` and its `scenario.json`.

| Code | What it means | What to do |
|---|---|---|
| `SCH-001` | A document does not follow its schema; the field points at the value. | Fix the value as the message says; the schemas are in `schemas/`. |
| `SCH-002` | The name, severity, category or main focus of `scenario.yaml` differs from the scenario itself. | Make `scenario.yaml` say what `scenario.json` says. |
| `SCH-003` | `requires.injectors` does not list exactly the injectors the injects and steps use. | Add the missing ones and remove the extra ones the message names. |
| `SCH-004` | `platforms` misses a platform that an inject or a step needing an executor targets. | Add the platforms the message names. |
| `SCH-005` | An inject or a step uses a contract the tools do not know: neither a built-in contract they recorded, nor one created from a payload. | Use a built-in contract, or open an issue so that it can be recorded. |
| `SCH-006` | The copy of a built-in contract stored in the scenario differs from the one the tools recorded. | Export the scenario again from a platform at a supported version. |
| `SCH-007` | (Info) Something to complete or review in `scenario.yaml`, `CHANGELOG.md` or `README.md`: for a new entry, a field the export cannot give, a default such as the version (a workflow export starts as `chained` and `EE`), or the starting changelog section to complete; for an update, the version to raise and the changelog section to add, the sheet to render again, and after a rename the name and facets to align. | Complete or confirm it before the pull request. |
| `SCH-008` | The entry is not where an entry belongs (`scenarios/<domain>/<slug>/`, with a known domain and a kebab-case slug), or a required file is missing. A directory name with a backslash, or a path that starts with a drive such as `C:`, is reported at the last directory before it, and none of its files is read, by this check or by those that compare entries. | Move the entry, or add the missing file. |
| `SCH-009` | The description still ends with `…`: it was cut to fit and was not reviewed. | Rewrite the end of the description and remove the mark. |
| `SCH-010` | Another entry has the same `external_id`. | Give this entry its own identifier, or update the existing entry instead. |
| `SCH-011` | (Info) The minimum platform version is older than the one the built-in contracts were checked on. | Raise it, or check the scenario on the older versions. |
| `SCH-012` | Another entry has the same scenario name, as a reader sees it (ignoring case, spacing and invisible characters). | Rename one of them, or update the existing entry instead. |
| `SCH-013` | The type or the edition disagrees with the stored scenario: `type: chained` without a workflow, a workflow with another type, or a workflow with an edition other than `EE`, which alone runs one. One finding per case. | Set `type` and `requires.edition` as the message says, or export the scenario again if the workflow was not meant. |

## Adding or updating an entry: `ITK`

These come from `intake`, which turns a platform export and a request into an entry. Nothing is
written when one of them blocks. See [`intake.md`](intake.md).

| Code | What it means | What to do |
|---|---|---|
| `ITK-001` | A new entry's `external_id` is taken, or several entries have the one an update names. | Choose a new identifier, or fix the duplicates first. |
| `ITK-002` | Something is already where the new entry would go. | Choose another slug, or remove what is there. |
| `ITK-003` | The export's scenario has the name of another entry. | Rename the scenario on the platform, or update the existing entry. |
| `ITK-004` | An update names an `external_id` no entry has. | Check the identifier, or add a new entry instead. |
| `ITK-005` | An update's domain and slug are not those of the entry it names. | Give the entry's own domain and slug. |
| `ITK-006` | An update's export has another scenario name than the entry, without `rewrite: true`. | Add `rewrite: true` if the scenario was really renamed. |
| `ITK-007` | The threat or the sources of the request would make `scenario.yaml` break its schema. | Fix them as the `SCH-001` findings that follow say. |
| `ITK-008` | An entry of the catalogue cannot be read: a link, a hidden name left by an interrupted run, a name with a backslash or a drive, or a `scenario.yaml` that is not a mapping. | Fix or remove that entry first. |

## Versions and identifiers: `VER`

| Code | What it means | What to do |
|---|---|---|
| `VER-001` | The version is not raised as the change needs, against the entry as the base branch holds it, at the same path or, moved, at the path it left: major for the attack chain (an inject removed, its place in the chain or whether it is enabled, its targets, those its content holds included, or its contract changed), the requirements, the targets, the type, or an item such as a team removed; minor for an inject or a payload added or changed, the rest of an inject's content, or an item added or changed; patch for an inject's text, an item's name, description or tags, and descriptive metadata such as the name, the description, the severity, the threat, the sources or the status. A change no rule names needs a major version. The finding gives the reason and the least version. | Raise `version` in `scenario.yaml` to the version the finding gives, or higher, and add its section on top of `CHANGELOG.md`. |
| `VER-002` | The version is lower than the previous one. | A version never decreases: give a higher one. |
| `VER-003` | An inject added has the contract and the title of an inject removed from the previous version, under a new ID. Inject IDs stay from one version to the next. | Prepare the entry again with `normalize --previous` or `intake`, which keep the IDs; a new inject takes another title. |
| `VER-004` | `CHANGELOG.md` is missing, or its level-2 headings are not sections `## <version> — <YYYY-MM-DD>` (a hyphen or an en dash does too), newest first: each version lower than the one above and each date no later, the first being the entry's version. A heading in a fenced code block is not read. | Add the section of this version on top; other headings take `###`. |
| `VER-005` | The entry's external ID changed. | Keep it: a new scenario is a new entry. |
| `VER-006` | The base branch's copy of the entry cannot be compared: its `scenario.yaml` or its `scenario.json` is missing, or it has no valid version. | A maintainer fixes the entry on the base branch first. |
| `VER-010` | Matching the injects or steps of the export with those of the previous version is ambiguous. | Give the match explicitly, in a mapping file for `normalize --map`, from the export's inject or step identifier to the stored one. |
| `VER-011` | A match given with `--map` is invalid: an unknown inject or step identifier, one used twice, or one that would collide. | Fix the mapping file. |
| `VER-012` | (Info) An inject or a step of the previous version is no longer in the export; a retitled step reads as one removed and one added, unless it is mapped. | Check it was removed on purpose, and say so in the changelog. |
| `VER-013` | (Info) A change of the entry since the base branch's copy, from `diff`: where it is (the file and the pointer of what changed, the list for an inject or item removed), the version it needs, and the ID of the inject or item it concerns; never a value. The 30 that need the most are listed; `VER-014` says how many more. | Nothing to do; `validate` judges the version. |
| `VER-014` | (Info) The least version the changes of the entry need, from `diff`, why, and whether the entry's version is enough; or that nothing needs a new version, that the entry is new, or that it cannot be compared. It comes first, on the entry itself. | When it says too low, raise `version` to it at least, as `VER-001` asks. |
| `VER-020` | From `build`: the previous release holds this version of the scenario with another archive, or said otherwise of it (its status, its facets, its requirements). A released version never changes. A change of how archives are built would change every archive. | Raise the version, as `VER-001` asks of the change. |

## Releases: `REL`

`build` reads, for each entry of the catalogue, the pull request that last changed it and those
who approved it, from the approvals file `scenario-tools approvals` writes (see
[`releases.md`](releases.md)). It also refuses, with `VER-002`, a version lower than
the one the previous release holds.

| Code | What it means | What to do |
|---|---|---|
| `REL-001` | The approvals file names no pull request for the entry. | Give an approvals file that lists every entry of the catalogue. |
| `REL-002` | The pull request that last changed the entry has no approval, and is not listed in `policy/data/merged-before-review.yaml` as merged before reviews were required. | Change the entry through a reviewed pull request. |
| `REL-003` | The previous release lists a scenario that no entry has. A released scenario is withdrawn by a new version, never removed. | Bring the entry back, with `status` set to `DEPRECATED` or `REVOKED` in a new version. |

## Verifying a release: `VRF`

`verify` checks a release as its consumers will, before it is published: the manifest, then each
archive it lists. A release fails on any of these findings. A manifest that fails its own checks
(its schema, its approver, a scenario listed twice, a payload ID listed with two contents) is
reported alone: no archive is read. A manifest that cannot be read at all is reported by its `IO`
finding; an archive refused as unsafe, or whose scenario is not one `build` writes, is `VRF-007`,
whose message starts with the `IO` code that refused it. `verify` does not check again what `build`
checks on the commit it builds: the scenario's facts, its normalised form and the policy. `VRF-001`
to `VRF-005` are kept for signed releases, which do not exist yet.

| Code | What it means | What to do |
|---|---|---|
| `VRF-006` | An archive the manifest lists is missing, or its size or its SHA-256 is not the one listed; or a file stands beside the archives that the manifest does not list, and would be published with them, a `manifest.json` other than the one verified included. | Publish the archives `build` wrote, unchanged, beside their manifest, and nothing else. |
| `VRF-007` | An archive is unsafe to extract, or is not what `build` writes: too large, too many entries, an entry name leaving the extraction directory, a link, a layout the checks refuse; any entry but `scenario.json` and `attachments.zip`, an `attachments.zip` that does not open with the shared password, or a `scenario.json` with a part outside the closed list of a stored scenario (which holds the workflow of a scenario in chaining), or not structured as an export. | Build the release again with `build`; never edit an archive. |
| `VRF-008` | A payload an archive embeds, in an inject or a step, sits outside an inject's or a step's contract, is not listed in the manifest, has another content than the canonical hash listed, has no ID or cannot be hashed; or the manifest lists a payload the archive does not embed, lists one twice, or lists one ID with two versions or hashes across the release: a platform holding a payload by its ID does not read it again. | Build the release again with `build`, from entries that pass `validate`. |
| `VRF-009` | The manifest does not meet its schema, lists a scenario twice, or names an archive after another scenario or version than the item's; or an approved manifest does not name its release approver. | Build the manifest with `build`; the release job adds the approver. |

## Release fixtures: `CNF`

`scenario-tools conformance run` runs `verify` on each release fixture of
[`conformance/releases`](../conformance/README.md) and compares what it gives with what
`expected.json` says. A run fails on any of these findings; an `expected.json` that is not shaped
as the fixtures write it is refused input (`IO-014`).

| Code | What it means | What to do |
|---|---|---|
| `CNF-001` | Verifying a fixture gives other findings than `expected.json` lists for it, by code, path, field or the `IO` code of an unsafe archive. | If `verify` or the fixtures changed on purpose, run `make fixtures`; otherwise, the change broke a check. |
| `CNF-002` | A fixture `expected.json` lists has no directory, or a directory beside it is no fixture `expected.json` lists. | Run `make fixtures`; never add or remove a fixture by hand. |

## Other checks

A blocking `POL-004`, `POL-005`, `POL-006` or `POL-009` finding can be excepted when the breach is
legitimate, for one field of an entry's `scenario.json` as it is: the maintainers add the exception,
with the hash of that `scenario.json` and a justification, to `policy/data/exceptions.yaml`, and the
finding is then reported as information, with the justification. No other finding can be
excepted.

| Code | What it means | What to do |
|---|---|---|
| `GEN-001` | The entry's sheet, `README.md`, is missing or is not what `scenario-tools render` writes from `scenario.yaml`, `scenario.json` and the policy exceptions the entry was granted; or the sheet cannot be rendered, `scenario.yaml` or `scenario.json` being missing or not an object. In the sheet, every text of the entry is plain text, never Markdown, a link or an image; the commands of a workflow's steps are shown as code, with the values they run with. | Run `scenario-tools render <entry>`; never edit the sheet by hand. |
| `GEN-002` | The stored `scenario.json` is not what normalisation gives for it. | Run `normalize` or `intake` again instead of editing the file by hand. |
| `PAY-001` | No reference of `scenario.yaml` names a payload embedded in an inject or a step: its `payload_external_id` is missing, or names no reference. | Run `scenario-tools payloads <entry> --assign`. |
| `PAY-002` | A reference's hash is not the hash of the payload it names, its version is not `1.0.0`, or two references give one ID. | Run `scenario-tools payloads <entry> --assign`. |
| `PAY-003` | An embedded payload carries an ID that is not the one its content has: the ID derived from its hash, or the one `policy/data/payload-ids.yaml` agrees for it. Its content changed under the ID, or the ID was taken from another payload: the platform, which trusts the ID, would run another content. Also when the registry agrees the content's ID under another name than the payload's. Also raised by `validate-payloads` on a version file of `payloads/` whose `payload_external_id` is not the ID its content has (`field` is `/payload_external_id`), or whose content the registry agrees under another name than the version's. | Run `scenario-tools payloads <entry> --assign`, which gives the payload the ID its content has; correct the name in the registry. For a version file, write the ID its content has. |
| `PAY-004` | The scenario holds a payload outside the contract of an inject or a step, where no reference can name it. | Remove it: a payload belongs to the contract of the inject or the step that runs it. |
| `PAY-005` | An embedded payload cannot be hashed without guessing: a field the hash does not cover, a field of another payload type, a value of an unexpected type, a set holding an item twice, a detection remediation, a free-form AI object, an attached file (the bytes of attached files are not read yet, so any payload that carries one is refused for now), or a technique of its contract without an external ID. The finding names the field, never its value. | Remove the field or correct its value. A detection remediation or a new kind of field needs the hash to cover it first: open an issue. |
| `PAY-006` | A reference of `scenario.yaml` names no payload the scenario embeds. | Run `scenario-tools payloads <entry> --assign`, which drops it. |
| `PAY-007` | Two payloads of the scenario share a name with different contents. A reviewer reads a payload by its name. | Give each payload its own name. |
| `PAY-009` | The payload catalogue, `payloads/`, or one of its version files is not valid (`validate-payloads`). The layout: an entry other than a payload folder or a version file, a link or a special file, a folder not named by a slug, a file not named `<version>.json`, a payload folder with no version. A version file: out of `schemas/payload.schema.json` (one finding per violation, at its pointer; a type other than `Command` is one), not in the stored form (a byte order mark, CRLF or another layout included) or over 262,144 bytes, a set not sorted as the hash sorts it (techniques, platforms, expectations and the security platforms of an expectation by their text, domains by their name), a name that does not carry its version (a suffix on 1.0.0, no or another suffix on a later version), a content the canonical form cannot hash. Across the catalogue: two base names among the versions of one payload; a base name, an ID or a content used by two payloads or two versions. The message is fixed and never quotes a value. | Correct the file or the folder; give each payload its own slug and base name, and each version its own content and ID. |
| `POL-001` | A source or a file breaks "linked, never copied": a source link holds a user name or password, carries a credential in its query or fragment (a token, a key, a password, the signature of a pre-signed link), or its host is an IP address, a name with no dot, a local, internal or reserved name (such as `localhost`, `.local`, `.internal`, `.test`, `.example`, `.arpa`, `.lan`, `.corp`) or not a public DNS name; or the entry holds a file other than `scenario.yaml`, `scenario.json`, `README.md` and `CHANGELOG.md`. | Link a public page that any reader can open, without a credential; remove the copied file and link its source instead. |
| `POL-002` | A recurrence field has a value: a shared scenario must never schedule itself. | Remove the recurrence. |
| `POL-003` | An inject or a step, an embedded payload's commands, an article, channel or challenge, or the name, description or key of a workflow's condition, names a host that is not allowed: in a link, in an IP address, or as a whole value. Allowed are the example names (`example.com`, `.example`, `.test`, `localhost`…), loopback and the documentation address ranges, as `policy/data/allowed-targets.yaml` lists them. Inject and scenario descriptions are not checked. | Use an example name, such as `host.example.com`, or a documentation address, such as `192.0.2.10`; a real target is set on the platform when the scenario runs. |
| `POL-004` | The command, cleanup, argument or prerequisite of a payload embedded in an inject or a step takes a forbidden action, as `policy/data/forbidden-actions.yaml` lists them: deleting shadow copies or backups, wiping or formatting a disk, deleting a whole drive, clearing event logs, encrypting data, running an encoded command a reviewer cannot read, or removing a protection (an antivirus, a firewall, a security service) without a cleanup command that restores it. A command longer than 65,536 characters is refused as too long to check. | Remove the action; a shared scenario emulates an attack without causing its damage. |
| `POL-005` | A payload embedded in an inject or a step changes the endpoint (it runs or drops a file, or writes, creates or starts something, as `policy/data/side-effects.yaml` lists them) but has no cleanup command, or no executor to run it. | Add a cleanup command that undoes what the payload does, with its executor. |
| `POL-006` | The commands, name or output parsers of a payload embedded in an inject or a step name a security product, as `policy/data/vendor-names.yaml` lists them: a shared scenario stays vendor-neutral. | Describe the behaviour instead of the product, for example "the endpoint's security agent". |
| `POL-007` | (Info) A payload embedded in an inject or a step asks for elevated privileges. | Check why it needs them; nothing blocks. |
| `POL-008` | (Info) A payload this scenario, in an inject or a step, did not run in its previous version; for a new entry, each of its payloads. | Review what it runs; nothing blocks. |
| `POL-009` | In a time-based scenario, two injects that run a payload on the endpoint are less than 60 seconds apart (blocking), or less than 120 seconds before a heavy payload such as an executable or a dropped file (info). The steps of a workflow are exempt: each waits for the steps before it, never for a time (a time-based scenario holding a workflow is refused by `SCH-013`). | Space the injects by at least 60 seconds, or 120 for a heavy payload. |
| `POL-010` | The scenario, its injects and steps included, holds a user, a team member, a variable value or an e-mail address of a real domain. | Export the scenario again with the fixed options and run `normalize`, which removes them; use an example domain such as `example.com`. |
| `POL-011` | An exception of `policy/data/exceptions.yaml` for this entry covers none of its findings: the entry's `scenario.json` changed since the exception was granted (the finding gives its new hash), the breach was fixed, or its field moved. | A maintainer reviews the change, then gives the exception the new hash or field, or removes it. |
| `OAV-001` | The platform skipped an inject at import, because it lacks the injector, contract or payload. | Install what the message names on the platform, then import again. |
| `TTL-001` | The pull request title breaks the convention. | Write it as `type(scope): description (#issue)`, as `CONTRIBUTING.md` says. |
