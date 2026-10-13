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
| `IO-014` | The export is not shaped like an OpenAEV scenario export: a missing or wrong field, an identifier that is not a UUID, a part the tools do not handle yet. | Export again; if it persists, open an issue with the platform version. |
| `IO-015` | Policy data was found at more than one level above the output: an entry may not carry its own rules. | Remove the extra `policy/` directory. |
| `IO-016` | The report holds more findings than it shows; this one counts the rest. | Fix the findings shown, then run the command again. |
| `IO-017` | A text holds an invisible or direction-changing character (such as a right-to-left override), which could make a reviewer read something other than what the platform runs. | Remove the character; the message gives its position. |

## Scenario entries: `SCH`

These check an entry of the catalogue: its place, its `scenario.yaml` and its `scenario.json`.

| Code | What it means | What to do |
|---|---|---|
| `SCH-001` | A document does not follow its schema; the field points at the value. | Fix the value as the message says; the schemas are in `schemas/`. |
| `SCH-002` | The name, severity, category or main focus of `scenario.yaml` differs from the scenario itself. | Make `scenario.yaml` say what `scenario.json` says. |
| `SCH-003` | `requires.injectors` does not list exactly the injectors the injects use. | Add the missing ones and remove the extra ones the message names. |
| `SCH-004` | `platforms` misses a platform that an inject needing an executor targets. | Add the platforms the message names. |
| `SCH-005` | An inject uses a contract the tools do not know: neither a built-in contract they recorded, nor one created from a payload. | Use a built-in contract, or open an issue so that it can be recorded. |
| `SCH-006` | The copy of a built-in contract stored in the scenario differs from the one the tools recorded. | Export the scenario again from a platform at a supported version. |
| `SCH-007` | (Info) Something to complete or review in `scenario.yaml`: for a new entry, a field the export cannot give or a default such as the version; for an update, the version to raise and the changelog section to add, and after a rename the name and facets to align. | Complete or confirm it before the pull request. |
| `SCH-008` | The entry is not where an entry belongs (`scenarios/<domain>/<slug>/`, with a known domain and a kebab-case slug), or a required file is missing. A directory name with a backslash, or a path that starts with a drive such as `C:`, is reported at the last directory before it, and none of its files is read, by this check or by those that compare entries. | Move the entry, or add the missing file. |
| `SCH-009` | The description still ends with `…`: it was cut to fit and was not reviewed. | Rewrite the end of the description and remove the mark. |
| `SCH-010` | Another entry has the same `external_id`. | Give this entry its own identifier, or update the existing entry instead. |
| `SCH-011` | (Info) The minimum platform version is older than the one the built-in contracts were checked on. | Raise it, or check the scenario on the older versions. |
| `SCH-012` | Another entry has the same scenario name, as a reader sees it (ignoring case, spacing and invisible characters). | Rename one of them, or update the existing entry instead. |

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
| `VER-010` | Matching the injects of the export with those of the previous version is ambiguous. | Give the match explicitly, in a mapping file for `normalize --map`. |
| `VER-011` | A match given with `--map` is invalid: an unknown identifier, one used twice, or one that would collide. | Fix the mapping file. |
| `VER-012` | (Info) An inject of the previous version is no longer in the export. | Check it was removed on purpose, and say so in the changelog. |

## Other checks

| Code | What it means | What to do |
|---|---|---|
| `GEN-002` | The stored `scenario.json` is not what normalisation gives for it. | Run `normalize` or `intake` again instead of editing the file by hand. |
| `PAY-004` | The scenario embeds payloads, which the archive cannot carry yet. | Wait for payload support, or use built-in contracts. |
| `POL-001` | A source or a file breaks "linked, never copied": a source link holds a user name or password, carries a credential in its query or fragment (a token, a key, a password, the signature of a pre-signed link), or its host is an IP address, a name with no dot, a local, internal or reserved name (such as `localhost`, `.local`, `.internal`, `.test`, `.example`, `.arpa`, `.lan`, `.corp`) or not a public DNS name; or the entry holds a file other than `scenario.yaml`, `scenario.json`, `README.md` and `CHANGELOG.md`. | Link a public page that any reader can open, without a credential; remove the copied file and link its source instead. |
| `POL-002` | A recurrence field has a value: a shared scenario must never schedule itself. | Remove the recurrence. |
| `POL-003` | An inject, an embedded payload's commands, or an article, channel or challenge, names a host that is not allowed: in a link, in an IP address, or as a whole value. Allowed are the example names (`example.com`, `.example`, `.test`, `localhost`…), loopback and the documentation address ranges, as `policy/data/allowed-targets.yaml` lists them. Descriptions are not checked. | Use an example name, such as `host.example.com`, or a documentation address, such as `192.0.2.10`; a real target is set on the platform when the scenario runs. |
| `POL-004` | An embedded payload's command, cleanup, argument or prerequisite takes a forbidden action, as `policy/data/forbidden-actions.yaml` lists them: deleting shadow copies or backups, wiping or formatting a disk, deleting a whole drive, clearing event logs, encrypting data, running an encoded command a reviewer cannot read, or removing a protection (an antivirus, a firewall, a security service) without a cleanup command that restores it. A command longer than 65,536 characters is refused as too long to check. | Remove the action; a shared scenario emulates an attack without causing its damage. |
| `POL-005` | An embedded payload changes the endpoint (it runs or drops a file, or writes, creates or starts something, as `policy/data/side-effects.yaml` lists them) but has no cleanup command, or no executor to run it. | Add a cleanup command that undoes what the payload does, with its executor. |
| `POL-006` | An embedded payload's commands, name or output parsers name a security product, as `policy/data/vendor-names.yaml` lists them: a shared scenario stays vendor-neutral. | Describe the behaviour instead of the product, for example "the endpoint's security agent". |
| `POL-007` | (Info) An embedded payload asks for elevated privileges. | Check why it needs them; nothing blocks. |
| `POL-009` | In a time-based scenario, two injects that run a payload on the endpoint are less than 60 seconds apart (blocking), or less than 120 seconds before a heavy payload such as an executable or a dropped file (info). | Space the injects by at least 60 seconds, or 120 for a heavy payload. |
| `POL-010` | The scenario holds a user, a team member, a variable value or an e-mail address of a real domain. | Export the scenario again with the fixed options and run `normalize`, which removes them; use an example domain such as `example.com`. |
| `OAV-001` | The platform skipped an inject at import, because it lacks the injector, contract or payload. | Install what the message names on the platform, then import again. |
| `TTL-001` | The pull request title breaks the convention. | Write it as `type(scope): description (#issue)`, as `CONTRIBUTING.md` says. |
