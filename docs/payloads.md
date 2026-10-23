# The payload catalogue

The payloads the catalogue's scenarios run are kept in `payloads/`, one frozen file per version,
so that a scenario can point at the exact version it runs and a fix is always a new version.

## Layout

```txt
payloads/
  process-discovery-ps/        one folder per payload, named by its slug
    1.0.0.json                 one file per version, named by its version
```

The slug is lower-case letters and digits in runs joined by single hyphens, at most 64
characters; it is chosen when the payload is first added and never changes. Nothing else is in
`payloads/`: no index, no README, no link. The list of versions of a payload is the list of its
files. `schemas/payload.schema.json` checks each file; `scenario-tools validate-payloads payloads`
checks the whole catalogue, and its findings are explained in [`findings.md`](findings.md).

## What a version file holds

A version file holds the payload as the platform holds it, under the names the platform
exports, cleaned:

- the payload's fields: its type (`Command` only for now), name, description, platforms,
  architecture, elevation, expectations and the security platforms each expects, arguments,
  prerequisites, cleanup, command and output parsers;
- its techniques by their external IDs (`payload_attack_patterns`) and its domains
  (`payload_domains`, name and colour), both sorted; a platform export holds a payload's domains
  on its contract, so `intake` takes them from the contract's own copy;
- the ID of this version (`payload_external_id`).

A payload exported without a description is given its name as one when the scenario is
normalised, so the scenario's copy and the version file carry the same description and the same
hash. A real description is better: write it in OpenAEV and export again.

The security platforms each expectation expects (`payload_expected_security_platforms`) are kept
as the platform holds them: they are part of the content, so of the hash.

What the cleaning leaves out, and why:

| Left out | Why |
|---|---|
| The payload's identifier on an instance, and those of its output parsers | They belong to one platform; the version's ID is `payload_external_id` |
| Source, status, collector type | What the platform records of where a payload came from; whoever installs the catalogue sets them |
| Tags | Labels of one platform; whoever installs the catalogue sets its own |
| Authors, creation and update dates | They describe one platform's copy, not the content |
| The full records of the techniques | The external IDs name them; the platform holds the records |
| Every null or empty value | An absent value and an empty one are the same content (`false` and `0` are kept) |

The hash of a version is the canonical payload hash of its fields, its techniques passed as a
contract's. It leaves out the ID and the domains, so it is the hash the platform computes for the
same payload embedded in a scenario. The ID of a version is the one its content has: the ID
`policy/data/payload-ids.yaml` agrees for that hash, otherwise the one derived from it.

## Names and versions

The first version, 1.0.0, carries the payload's plain name, its base name. Every other version
carries the base name followed by ` (<version>)`, so that a platform shows two versions a person
can tell apart; the version is part of the name, so of the hash. Every version of a payload has
one base name, and no two payloads share a base name or a slug. The identifiers the repository
derives from a payload's name are derived from its base name, so a scenario that moves to another
version of a payload keeps them.

## A published version is never edited

A version file, once merged, is frozen: a change of any field, the domains included, is a new
version with a higher number, in a file of its own. A version is never removed. The checks of
every pull request hold this rule against the base branch, with
`scenario-tools validate-payloads payloads --previous-root <base checkout>`: a version the base
holds that is edited or removed is `VER-022`, a new version that is not higher than the base's
highest is `VER-023`. A pull request is compared with the base branch as it is when the check
runs: one that is behind it reads a version merged since as removed, until it is brought up to
date. A release also refuses a version it published before with another content or file, or
that is gone (`VER-021`).
