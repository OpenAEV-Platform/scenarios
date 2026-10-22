# Consuming a release

This page is for those who build what consumes the catalogue: a collector that installs
scenarios on a platform, a marketplace, an offline import. It says what a release holds, what to
check before any of its content is used, and how to test those checks.

Releases are not published yet. Where they are published will be said here with the first one.

## What a release holds

A release is a `manifest.json` and, beside it, one import archive per scenario, named
`<external_id>-<version>.zip`. The manifest follows
[`schemas/manifest.schema.json`](../schemas/manifest.schema.json). It names its `repository`, its
`channel` (`edge` for every release, `stable` for those recommended to everyone), its name
`release` (`YYYY.MM.DD.N`), `issued_at` (the time of the commit it is built from) and, once the
release is approved, its `release_approver`. For each scenario it gives:

- its `external_id`, which never changes from one version to the next, its `version` and its
  `status`;
- its archive: `name`, `size` and `sha256`;
- every payload its archive embeds, as `id`, `version` and `sha256`; the hash is the canonical
  hash of the payload's content, and is what identifies it;
- what a platform needs to run it, in `requires`: the OpenAEV versions (`openaev`), the edition
  (`CE` or `EE`), the injectors and the executors;
- the facets a catalogue shows, and who approved its change, in which pull request.

A scenario's `type` says how its injects run: at set times (`time-based`), or in chaining
(`chained`), where each step runs once the steps it depends on have run. A scenario in chaining
needs the Enterprise edition; its `scenario.json` holds a `scenario_workflow`, whose steps each
carry their inject, and its manifest item lists the payloads of its steps as it lists those of
injects.

The repository builds every release against the channel's previous one, and guarantees that:

- a released version never changes: neither its archive nor what the manifest says of it, but
  for its approvals and its test report; a correction is a new version;
- a version never decreases;
- a released scenario stays in every later release: it is withdrawn by a new version, never
  removed.

## What to check before using a release

A release with any finding below is not used at all.

1. **Source.** Download releases over HTTPS, from the repository's release location by default.
   Make changing that location an administrator's action, and log it.
2. **Manifest.** Read it as strict JSON, as every JSON document of a release is read: UTF-8, at
   most 20 MiB and 64 levels deep, no key twice in an object, no `NaN` nor infinite number, no
   integer beyond ±(2^53 − 1), no unpaired surrogate. Then check it against the manifest schema,
   which cannot see a key a parser already dropped. Its `repository` and `channel` are the ones
   you follow, and it names its `release_approver`: a manifest without one was built, never
   approved. A scenario listed twice, or an archive named after another scenario or version than
   its item's, refuses the release.
3. **Versions.** If a version you already installed comes with another archive hash, or with
   anything else the manifest says of it but its approvals and its test report, the release
   breaks the repository's guarantee: refuse it. So with a version lower than one you installed,
   or a scenario you installed that the release no longer lists.
4. **Integrity, before opening.** The size and the SHA-256 of every archive match the manifest.
   Nothing beside the archives goes unlisted.
5. **Safe extraction.** Before extracting anything, refuse an archive over 20 MiB, whose entries
   declare over 100 MiB in total, of more than 1,000 entries, or whose encrypted entries take
   over 10 MiB as stored. Refuse an entry whose stream inflates beyond the size it declares; an
   entry name that is empty, absolute or on a drive, or holds a `..` component, a backslash or a
   null character; two entry names that differ only by their case or their Unicode form; any
   link. The archive itself is checked whole: only stored and deflate entries, no unsupported
   flag, entries lying end to end with no byte that belongs to none, each local header agreeing
   with the central directory, each CRC right.
6. **Content.** An archive holds `scenario.json`, the entry whose comment is `Scenario`, and
   possibly `attachments.zip`, with no comment: itself an archive, under the same rules, whose
   entries open with the shared password `infected` (an entry that is not encrypted is read as
   it is). Nothing else. `scenario.json` is read as strict JSON, as the manifest is, is
   structured as an export and holds only the parts of a stored scenario, `scenario_workflow`
   among them.
7. **Payloads.** Every payload the scenario embeds sits in the contract of an inject or of a
   step, carries its ID, can be hashed, and is listed once by that ID with the canonical hash of
   its content; every listed payload is embedded; one payload ID has one version and one hash
   across the release.
   When an import would reuse a payload the platform already holds under an ID the manifest
   lists, the content it holds must have the hash the manifest lists: otherwise do not use it,
   and report the conflict.
8. **Status and requirements.** A `REVOKED` scenario must no longer run; a `DEPRECATED` one is
   replaced or no longer maintained. Install only scenarios whose `requires` the platform meets.
9. **Scenarios in chaining.** Import one only where the import does both of these:
   - once it has created the steps, and before any run, it rewrites the value of every
     `DEPEND_ON` condition, which is the `step_id` the archive gives the awaited step, to the
     identifier the platform gave that step. The repository refuses a dependency on a step the
     scenario does not have, so every such value names a step of the archive. Without this, a
     step that waits for another never starts;
   - when it would reuse an injector contract, or a payload, that the platform already holds
     under the identifier the archive gives it, it compares what it holds with what the archive
     embeds: the contract with its payload, and each payload by its canonical hash. When they
     differ, it refuses the import and creates nothing. The identifiers of a release can be
     computed in advance, so a contract placed first under one of them would otherwise run
     something other than what was reviewed. Checking the payloads against the manifest
     (check 7) is not enough: the contract decides what a step runs.

   A consumer that lacks either of these must not import an archive whose scenario is in
   chaining. The repository also refuses a condition that copies a step's output into the next
   step's inject (a mapper): it would run on the platform data read from a targeted host, which
   no review saw. Do not add that behaviour on your side.

The canonical hash of a payload, with test vectors, is described in
[`conformance/payload-hash.json`](../conformance/payload-hash.json).

## Testing your checks

The repository's own verifier runs checks 2 (but for which repository and channel you follow),
4, 5, 6 and 7 (but for the reuse of a payload a platform holds). Checks 1, 3, 8 and 9 depend on
where you download from, on what is installed and on how it is imported, and are yours alone.

For a scenario in chaining, the verifier proves what it proves for any scenario: the archive is
the one the manifest lists, safe to open, and embeds exactly the payloads the manifest vouches
for, steps included. It does not check again that the workflow's graph and conditions are sound
(no loop, every dependency on a step of the scenario, only the condition types the repository
accepts): `build` checks them before it writes an archive, and the archive's hash then stands for
them. Nor does it run check 9: it cannot see what a platform holds, nor how it imports.

From the repository's root:

```sh
uv run scenario-tools verify <manifest.json> --schemas schemas [--archives <dir>] [--approved]
```

`--approved` requires the `release_approver`; `--archives` gives the archives' directory, the
manifest's by default. The findings are explained in
[`findings.md`](findings.md#verifying-a-release-vrf). The release workflow runs it, without
`--approved`, on every release it builds.

[`conformance/releases`](../conformance/README.md) holds one release that must be accepted, and
one for each way the verifier refuses a release, but for an archive over 20 MiB, with the
findings expected for each. A consumer can run its own checks on them; the archives of the
refused releases are hostile on purpose, and are opened only by a verifier.

## What releases do not give yet

- **No signature.** A release is trusted through its hashes and the location it comes from;
  what stands between an attacker and a platform is the repository's review and release
  rules. Signed releases may come later.
- **No scenario in chaining yet.** As this page is written, none is released, and none will be
  before the platform's import does what check 9 asks.
- **No revocation list.** A scenario is withdrawn by a new version whose `status` is `REVOKED`;
  a platform learns it from the next release it reads.
