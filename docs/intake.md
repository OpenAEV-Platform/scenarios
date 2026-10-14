# Adding or updating an entry from a platform export

`scenario-tools intake` turns an OpenAEV scenario export and a short request into an entry of
this repository, written in place, and writes the plan of the pull request that proposes it.
The command never copies the export into the repository. Keep the export, the request and the
plan outside the checkout, so that a later `git add` cannot take them either.

```sh
scenario-tools intake export.zip --request request.yaml --repo . --plan ../plan.json
scenario-tools --format json intake export.zip --request request.yaml --repo . --plan ../plan.json
```

- `export.zip`: the scenario as the platform exports it: a `.zip`, or else its JSON.
- `--request`: what the export cannot say (below).
- `--repo`: the root of a checkout of this repository, at the commit the change starts from,
  with nothing left to commit under `scenarios/`, `policy/` or `schemas/`, untracked, ignored
  or skipped files and submodules included, and no file there that git converts by
  `.gitattributes`: the plan describes what that commit gives. The rest of the checkout does
  not count.
- `--plan`: where the plan is written. Nothing may be there yet, its directory must exist and
  not be a link, and it may not be inside `scenarios/`, `policy/` or `schemas/`, which stay as
  committed. Neither may the export nor the request, wherever the path they are given by leads.
- `--format json` goes before `intake`, as for every command.

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
issue: 12                   # the issue the pull request closes, a whole number
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

An update gives no `threat`, `sources` or `generated_by`, and a new entry no `rewrite`. The
schema bounds the rest: a new entry needs `threat` and `sources`, `threat` holds at most its
three lists, `sources` at most 50 entries, `generated_by` 1 to 200 characters, and `issue` is
from 1 to 2^53-1. `domain` and `slug` are names,
never a path, whatever the schema says.

A new entry starts its `CHANGELOG.md` with the section of its version and the day of the run,
`## 1.0.0 — <YYYY-MM-DD>`, to complete before the pull request, and gets its sheet, `README.md`,
which `scenario-tools render` writes from `scenario.yaml` and `scenario.json`.

Intake gives each payload the scenario embeds the ID its content has, written in the payload's
`payload_external_id` and in a reference of `scenario.yaml` with its hash, as
`scenario-tools payloads --assign` does. The ID is derived from the hash of the payload's content,
unless `policy/data/payload-ids.yaml` agrees another ID for that very content: an unchanged
payload keeps its ID, a changed one takes a new one.

An update rewrites `scenario.json`, and `scenario.yaml` only when the references of its payloads
change: it is then written in the tools' layout, so a comment added to it by hand is not kept.
Raise its `version`, add the section to `CHANGELOG.md`, and, after a rename, align its `name`,
`category` and `main_focus` with the export; then render the sheet again with
`scenario-tools render`, since it shows what changed. Each inject the export no longer has is
listed (`VER-012`).

## What is refused

Nothing is written when the request is refused:

| Code | Why |
|---|---|
| `SCH-001` | a request outside its schema, a domain not in `policy/data/domains.yaml`, a `domain` or `slug` that is not a kebab-case name, an `issue` that is not a whole number, or an export whose scenario has no name, or a blank one |
| `IO-*` | an export or a request that cannot be read safely: too large, malformed, a link |
| `IO-017` | a hidden character in the request, or in what would be stored |
| `IO-013` | a link on the entry's path inside the checkout, `scenarios/` included |
| `SCH-008` | an update of an entry that has no `scenario.json` |
| `ITK-001` | a new entry whose `external_id` another entry has, or an update of one several entries have |
| `ITK-002` | a new entry whose place is taken: anything already there |
| `ITK-003` | an export whose scenario name another entry has; for an update, only with `rewrite: true` |
| `ITK-004` | an update whose `external_id` no entry has |
| `ITK-005` | an update whose `domain` and `slug` are not the entry's place |
| `ITK-006` | an update with another scenario name, without `rewrite: true` |
| `ITK-007` | `threat` or `sources` that make `scenario.yaml` break its schema |
| `ITK-008` | an entry of the catalogue, or a domain, that is a link, a hidden name a cut run left (`.scenario-tools-<hex>`) or a name a finding cannot show (a backslash, a drive), an entry holding such a name, or an entry whose `scenario.yaml` cannot be read or is not a mapping: what it holds is unknown, so is what is taken, and every request is refused until it is fixed |

The export is also refused as `normalize` refuses it.

Scenario names are compared in their Unicode compatibility form, without case, outer blanks or
runs of blanks, without the hidden characters the checks find and without soft hyphens: names
that look the same to a reader are the same name. A joiner where emoji or a script puts one
changes what is shown, so it stays, and letters of other scripts that merely look alike stay
different. An export without a name takes no other's. `validate` compares the names of all the
entries of the repository the same way (`SCH-012`), so that two branches cannot each bring in the
same name: rename one of the scenarios, or update the existing entry instead.

## The plan

`plan.json` holds:

- `base`: the commit the change starts from.
- `blocking`: how many blocking findings are left, each counted once.
- `body`: the pull request's body. It closes the issue, then lists what is left to complete or
  review, each finding once. An informative one is left out when it asks for nothing, or when a
  blocking one names the same file and field.
- `changed`: whether there is anything to propose.
- `entry`: the entry's directory.
- `files`: each file written, with its SHA-256.
- `mode`: `new` or `update`.
- `title`: the pull request's title.

The same inputs always give the same plan, wherever the export and the request are. An update
whose export gives the stored `scenario.json` again writes nothing, but still has its plan and
its checks, and a blocking finding on the stored entry still gives exit code `1`.

## Opening the pull request

Once the plan is written, complete what its body lists, then propose the entry from the
plan's `base`. Review the entry as any contribution first: what the export holds, commands and
addresses included, becomes public, and the issue the body closes is the one the request
names.

1. create a branch from `base`, and add the files the plan lists under `files`, with what
   completing the list changed: for a new entry, the starting section of its `CHANGELOG.md`, which
   says what the version holds; for an update, `scenario.yaml` with its raised `version` and
   `CHANGELOG.md` with its new section, which the run never writes;
2. render the sheet again with `scenario-tools render`, since completing the entry changes it,
   then run `scenario-tools validate` on the entry, with `--previous-root` pointing at a checkout
   of the base branch for an update: nothing may block;
3. commit them, signed, and push the branch;
4. open the pull request with the plan's `title` and `body`.

The plan names no branch: whoever pushes chooses it. Before the next intake, come back to the
commit it starts from: the entry just proposed is a change of the checkout until then, and the
run refuses it. For instance:

```sh
git switch -c add-easm <base>      # the plan's base
git add scenarios/techniques/easm  # the whole entry: what the run wrote, and what was completed
git commit -S -m "feat(scenarios): add easm (#12)" && git push -u origin add-easm
git switch main                    # back to where the next intake starts
```

To drop an entry rather than propose it, remove its directory (`git clean -fd <entry>`) for a
new one, or restore its file (`git restore <entry>/scenario.json`) for an update, and remove its
plan.

## Exit codes

- `0`: the entry and its plan are written; what the plan lists is left to complete.
- `1`: the request is refused, and nothing is written, no plan included. Or the entry and its
  plan are written but a check blocks the entry, for instance a description cut to its length
  bound and marked with `…`: fix the files in place, then run `scenario-tools validate` on the
  entry. To start again from the export instead, remove the plan, and either the entry's
  directory for a new entry, or the change to `scenario.json` for an update
  (`git checkout -- <entry>/scenario.json`, which also drops any change made to it by hand).
- `2`: a usage error, and nothing is run: the options, a plan already there, or a plan, an export
  or a request inside `scenarios/`, `policy/` or `schemas/`.
- `3`: the environment stops the run. Nothing is kept, except in the last case below, which the
  run names. This covers:
  - the checkout has changes that are not committed under `scenarios/`, `policy/` or
    `schemas/`, untracked, ignored or skipped files and submodules included, files git converts
    there, or a commit that changes while it is checked: commit or remove them first;
  - the export or the request cannot be read, or the paths given cannot be resolved;
  - the checkout, its rules, its commit, or the plan's place cannot be used;
  - another `intake` run holds the checkout;
  - the checkout, the entry, a file written or the plan's place was changed meanwhile;
  - the run was asked to stop before it started writing, or once all was written (then the
    entry and its plan stand, and the run says so).

  What the run wrote is taken back. When that cannot be done, the run says what is left and
  where.
- `4`: a defect of the tool.

The findings are printed on standard output, one per line, or as one JSON document with
`--format json` (`{command, ok, findings}`, with `error` when the code is `3`). A script tells
the two cases of exit code `1` apart by the plan: none is written when the request is refused,
and when one is, its `blocking` count says how many findings are left. The plan must not exist
before the run, so that a plan left by another run is never taken for this one's.

## What a run guarantees

- **Links:** a run never follows a link inside the checkout, nor at the plan's place: the plan
  file and its directory. It writes from the descriptors of the directories it holds, and reads
  the catalogue and a file to update by paths it checks first. The directories above the plan's
  directory are the caller's path, and their links are followed.
- **One run at a time:** a run holds the checkout from the catalogue's check to the plan, so
  that no other `intake` run writes in it meanwhile. Other commands do not take this lock.
- **What is written:**
  - The plan's place is reserved first.
  - The entry is written from the checkout held, never from its path again.
  - A new entry's files are created where nothing is. The directories it needs, when
    missing, are made and set so that all can read them, whatever the umask.
  - An update sets `scenario.json` aside at once, and replaces it only if what was set aside
    still holds what the checks read; a file another puts in its place meanwhile is never
    overwritten, and what the run puts back goes only where nothing is (on a file system
    without hard links, by its name, which leaves a tiny window).
  - The plan is published only if the checkout, the entry and each file written, or read for
    an update that writes nothing, are still what the run wrote or read, nothing else under
    `scenarios/`, `policy/` or `schemas/` differs from the plan's `base`, which is still the
    checkout's commit, and the plan's own place is still the one reserved.
- **All or nothing:** the entry is kept only once its plan is published. A run that fails
  before then takes back what it wrote: a new entry's files, the entry and the directories made
  for it are removed, an updated `scenario.json` gets its previous bytes back, and the plan's
  place is freed. Anything another process put or changed there meanwhile is never removed nor
  overwritten: a file put or changed in a new entry stays, and the entry with it. A file or
  directory the run made, but that it cannot open or whose identity it cannot read, cannot be
  told from another's: it is left, and the run says so; such a directory may be open to its
  owner alone. A directory made for the entry that another has since filled, moved or
  replaced is left too, and said.
- **Asked to stop:** a request to stop (Ctrl-C, SIGTERM as a CI job is cancelled, SIGHUP as a
  terminal closes, or SIGQUIT) while the run writes waits until the writing is done, then is
  dropped, never acted on later: a run never stops half way, and ends as usual. Asked before it
  writes, while it reads
  the commit included, the run stops with nothing written, with exit code `3`. A request the
  caller already ignores, as `nohup` does, stays ignored.
- **What it does not prevent:** another process that moves or replaces files or directories of
  the checkout, or the plan's place, while a run is writing. Such a process could change the
  repository directly anyway. What the run wrote is checked before the plan is published: the
  checkout, the entry, each file written and the plan's place. A change there stops the run,
  which takes back what it wrote. A file another adds to the entry is not looked for. git
  finds the checkout by its path as it starts, then works from the directory it found, as far
  as git 2.43 shows; once git has read it, the run checks that the path still names the
  checkout it holds, before anything is written, and again before the plan is published. A
  checkout swapped for another and back while git starts is not seen.

A run killed outright (SIGKILL), with no chance to take anything back, may leave an incomplete
entry, whose directories may be open to their owner alone, an empty or partly written plan, or
hidden names `.scenario-tools-<hex>` in or next to the entry, or next to the plan. Remove them
before running again; an update cut short may have left `scenario.json` itself under such a
name: restore it from the commit (`git restore <entry>/scenario.json`). Until they are removed,
such a name is a change of the checkout (exit code `3`), and once committed by mistake, it
refuses every request (`ITK-008`). Such a name never belongs in a pull request: `validate`
refuses it as an entry (`SCH-008`), but not as a file inside one, so look for it before adding
the entry to a commit.

The command runs on Linux, and is meant to run on macOS too, which its tests do not cover yet,
with git 2.40 or later: the attributes of the checkout's
commit are read too, so that a change to them outside the three directories cannot hide a
conversion. The git a macOS release ships may be older: install a recent one first.
