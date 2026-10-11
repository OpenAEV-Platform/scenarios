# Adding or updating an entry from a platform export

`scenario-tools intake` turns an OpenAEV scenario export and a short request into an entry of
this repository, written in place, and writes the plan of the pull request that proposes it.
The export archive itself never enters the repository.

```sh
scenario-tools intake export.zip --request request.yaml --repo . --plan ../plan.json
```

- `export.zip`: the scenario as the platform exports it.
- `--request`: what the export cannot say (below).
- `--repo`: the root of a checkout of this repository, at the commit the change starts from.
- `--plan`: where the plan is written; it may not be inside `scenarios/`, and neither may the
  export nor the request.

## The request

A YAML file of at most 64 KiB, checked against `schemas/intake-request.schema.json`.

A new entry:

```yaml
mode: new
external_id: 5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42   # chosen once, lower case
domain: techniques          # one of policy/data/domains.yaml
slug: easm                  # kebab-case, at most 64 characters
threat:
  ttps: [T1595]             # cves, intrusion_sets or ttps, as in scenario.yaml
sources:
  - url: https://attack.mitre.org/techniques/T1595/
    tlp: "TLP:CLEAR"
generated_by: run 42        # optional
issue: 12                   # the issue the pull request closes
```

An update of an existing entry:

```yaml
mode: update
external_id: 5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42
domain: techniques
slug: easm
issue: 13
rewrite: true               # only when the scenario was renamed on the platform
```

An update rewrites `scenario.json` only. `scenario.yaml` is never rewritten: raise its
`version`, add the section to `CHANGELOG.md`, and, after a rename, align its `name`, `category`
and `main_focus` with the export.

## What is refused

Nothing is written when the request is refused:

| Code | Why |
|---|---|
| `ITK-001` | a new entry whose `external_id` another entry has |
| `ITK-002` | a new entry whose directory already exists |
| `ITK-003` | an export whose scenario name another entry has |
| `ITK-004` | an update whose `external_id` no entry has |
| `ITK-005` | an update whose `domain` and `slug` are not the entry's place |
| `ITK-006` | an update with another scenario name, without `rewrite: true` |
| `ITK-007` | `threat` or `sources` that make `scenario.yaml` break its schema |

Scenario names are compared without case, outer blanks or runs of blanks.

## The plan

`plan.json` gives the commit the change starts from (`base`), whether there is anything to
propose (`changed`), each file written with its SHA-256, the pull request's `title` and `body`
(it closes the issue and lists what is left to complete or review), and the number of
`blocking` findings left. The same inputs always give the same plan.

## Exit codes

- `0`: the entry is written; what is listed in the plan is left to complete.
- `1`: the request is refused, and nothing is written; or the entry is written but a check
  blocks it, for instance a description cut to its length bound and marked with `…`. Fix the
  files in place, then run `scenario-tools validate` on the entry. To start again from the
  export instead, remove the entry's directory first.
- `2`: a usage error, nothing is run.
- `3`: the checkout, its rules, or the plan's place cannot be used; nothing is written.

The findings are printed on standard output, one per line, or as one JSON document with
`--format json` (`{command, ok, findings}`). A script tells the two cases of exit code `1`
apart by the plan: none is written when the request is refused. Remove an earlier
`plan.json` before running, or read its `blocking` count, so that a plan left by another run is
never taken for this one's.

A run stopped before its end may leave a hidden directory `.<slug>.*` beside the entry's
place: it is no entry, and is never read as one; remove it before committing.
