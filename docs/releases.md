# Releases

A release of the catalogue is every entry's import archive, the file of every payload version of
`payloads/`, and a manifest that lists them, with the hash of each, so that a platform can check
what it imports. This page is for the
maintainers who build releases; what a platform checks of a release is in
[`consumers.md`](consumers.md). Releases are published as GitHub releases of this repository,
named `YYYY.MM.DD.N`, each channel's pointer on the `channels` branch.

## How a release is built

The **Release** workflow (`.github/workflows/release.yml`) is run by hand, from the Actions
tab, for a channel (`edge` for now; `stable` comes with promotion). It stops unless it runs on
the head of the default branch, whose changes were reviewed. Who starts it approves the release.

0. **The previous release.** The channel's pointer is read on the `channels` branch, and the
   manifest of the release it names is downloaded; `scenario-tools channel previous` checks that
   the pointer names that manifest. With no pointer, it is the first release, only while the
   repository has none; otherwise the workflow stops.

1. **Approvals.** `scenario-tools approvals` finds, for each entry, the pull request merged into
   the default branch as the last commit that changed it, and those who approved what it
   merged: an approval of its last commit, by the repository's owner, a member of the
   organisation or a collaborator, that no later request for changes or dismissal of theirs
   withdrew. Neither a bot nor the pull request's author approves. The approvals name the
   commit they were collected at. It is the only job that reads more than the code: the pull
   requests and their reviews, read only. A role on GitHub is no proof of write access: what
   makes an approval count for a merge is the default branch's rules, which this check stands
   behind, never in place of.
2. **Two builds.** `scenario-tools build` runs on two runners, each from its own checkout of the
   commit, with those approvals; it refuses approvals collected at another commit. It runs the
   checks of `validate-payloads` on the catalogue first, then lists every payload version with
   its file, used by a scenario or not; against the previous release, a payload version it
   published with another content or file, or that the catalogue no longer holds, is `VER-021`.
3. **Comparison.** The two releases must be the same bytes, file for file.
4. **Verification.** `scenario-tools verify <manifest> --schemas schemas` checks the release as its
   consumers will: each archive against the manifest, by its size and its SHA-256; safe extraction,
   and nothing in an archive, or in its scenario's parts, but what `build` writes; each payload an
   archive embeds, inside an inject's contract and listed with the canonical hash its content has;
   one version and one hash for each payload ID across the release; each payload file against
   the manifest, by its bytes, its content hash and its ID, and every reference of a scenario to
   a listed version; and nothing beside the archives and payload files, but the manifest
   verified, that the manifest does not list. `--archives` gives another
   directory for the archives, and `--approved` also requires the release approver, once the
   release is approved.

5. **Publication.** The one job allowed to write approves the release with the login of who
   started the run (`scenario-tools approve`), verifies it again as approved
   (`verify --approved`), writes the channel's next pointer (`scenario-tools channel pointer`,
   refused unless it moves the channel forward), publishes the release, refused when its tag
   exists, reads it back and checks it against that pointer and as its consumers will, and then
   moves the channel to it, refused if the pointer changed since the run read it. The run's summary
   names the release and each scenario whose last change was merged without approval.

The two builds are kept as the run's artifacts for seven days. For now the repository has no
protected environment to approve a release in, published releases are not made immutable by
GitHub, and nothing but the workflow's practice keeps others from writing on `channels`: starting
the run stands for the approval, the workflow never replaces a release, and only it writes the
pointers.

**What it assumes.** A change of the catalogue goes through a pull request that is squash-merged:
the last commit that changed an entry is then the one the pull request was merged as. An entry
last changed by a commit pushed straight to the default branch, or merged another way, stops
the workflow, and no list can admit it: change the entry again through a reviewed pull request.
A pull request or a review whose account was deleted cannot be read as approved: it stops the
workflow, naming the pull request; change the entry again through a reviewed pull request. To
run `approvals` by hand, `GITHUB_TOKEN` must hold a token that can read the pull requests,
and the checkout its whole history.

## What `build` checks

- The checkout has no uncommitted change under `scenarios/`, `policy/` and `schemas/`. The
  release is dated by the commit's time, so two builds of one commit give the same bytes.
- Every directory two levels under `scenarios/` is an entry, and each passes `validate` and the
  archive's checks.
- Each entry's last pull request is named with its approvers. One with no approver is said
  (`REL-002`, information) and still released, with an empty list of approvers, while one
  maintainer merges the catalogue's changes alone; one listed in
  `policy/data/merged-before-review.yaml` is not said. That list holds the pull requests merged
  before reviews were required, each with why; it is reviewed as any change of the rules is.
- Against the previous release of the channel: a released version never changes, neither its
  archive nor what the manifest says of it (`VER-020`); a version never decreases (`VER-002`);
  and a released scenario stays in the catalogue (`REL-003`).

The findings are described in [`findings.md`](findings.md).

## Channels

Every release is published on the `edge` channel; one recommended to everyone is promoted to
`stable`, with the same archives. Each channel will have a pointer, `edge.json` or `stable.json`,
which [`schemas/channel.schema.json`](../schemas/channel.schema.json) describes: the channel's
release, by its name, and the SHA-256 of that release's manifest. A consumer reads the pointer,
then the manifest of the release it names, and checks that it has that hash, that repository,
that channel and that name. The releases themselves never change, and a channel moves to a later
release, never back: publishing the same release again leaves it as it is, and a channel is
never rolled back, a later release is published instead. The release workflow writes the pointers
on the `channels` branch: `scenario-tools channel previous` checks that a pointer names a given
manifest, and `scenario-tools channel pointer` writes the pointer to an approved release, refused
unless it moves the channel forward.

## Release fixtures

[`conformance/releases`](../conformance/README.md) holds one release `verify` accepts, and one for
each way it refuses one, with what verifying each must give. A consumer can run its own verifier
on them. The tests check that they are what `scenario-tools conformance build` writes, and that
each gives what it expects; after a change to `verify` or to the fixtures, `make fixtures` writes
them again.

## Withdrawing a scenario

A released scenario is never removed from the catalogue: a new version sets its `status` to
`DEPRECATED` (replaced, or no longer maintained) or `REVOKED` (must no longer run). The manifest
then tells the platforms.
