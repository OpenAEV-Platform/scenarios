# Releases

A release of the catalogue is every entry's import archive and a manifest that lists them, with
the hash of each archive, so that a platform can check what it imports. This page is for the
maintainers who build releases. Releases are not published yet: the workflow builds one and
checks that it is reproducible.

## How a release is built

The **Release build** workflow (`.github/workflows/release.yml`) is run by hand, from the
Actions tab, for a channel (`edge` or `stable`). It stops unless it runs on the default branch,
whose changes were reviewed.

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
   commit, with those approvals; it refuses approvals collected at another commit.
3. **Comparison.** The two releases must be the same bytes, file for file.
4. **Verification.** `scenario-tools verify <manifest> --schemas schemas` checks the release
   as its consumers will: each archive against the manifest, by its size and its SHA-256; safe
   extraction, and nothing in an archive but what `build` writes; each payload an archive
   embeds, inside an inject's contract and listed with the canonical hash its content has; and
   nothing beside the archives, but the manifest verified, that the manifest does not list.
   `--archives` gives another directory for the archives, and `--approved` also requires the
   release approver, once the release is approved.

A green run means the release builds, is reproducible and passes what its consumers check;
nothing is published. The two builds are kept as the run's artifacts for seven days.

Until releases are published, the workflow builds only the first release of the repository: it
stops when the repository has a release, whatever its channel, as the next one needs the
previous manifest. A draft release is not seen.

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
- Each entry has at least one approver (`REL-002`), unless its pull request is listed in
  `policy/data/merged-before-review.yaml`. The list holds the pull requests merged before
  reviews were required, each with why; it is reviewed as any change of the rules is.
- Against the previous release of the channel: a released version never changes, neither its
  archive nor what the manifest says of it (`VER-020`); a version never decreases (`VER-002`);
  and a released scenario stays in the catalogue (`REL-003`).

The findings are described in [`findings.md`](findings.md).

## Withdrawing a scenario

A released scenario is never removed from the catalogue: a new version sets its `status` to
`DEPRECATED` (replaced, or no longer maintained) or `REVOKED` (must no longer run). The manifest
then tells the platforms.
