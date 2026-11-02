# Runbook

What the maintainers do when something goes wrong. Each section says what to check first, then
what to do. A security problem is reported privately, as [`SECURITY.md`](../SECURITY.md) says.

## A release build fails

The **Release** workflow stops at the first job that fails. Its jobs run in this order: the
previous release and the approvals, the two builds, the comparison and the verification, then
the publication.

- **Previous release.** The channel's pointer does not name the manifest it is read with, or the
  repository has a release while the channel has no pointer: someone wrote on `channels`, or a
  publication stopped between the release and its pointer. Find which release the channel should
  name, the latest the workflow published, and restore its pointer from it with
  `scenario-tools channel pointer` before releasing again. Never delete or replace a release.
- **Approvals.** The job names the entry and its pull request.
  - An entry whose last change was not approved is said (`REL-002`) and does not stop the
    release. Never list a pull request in `policy/data/merged-before-review.yaml` to silence it:
    that list holds only the pull requests merged before reviews were required.
  - An entry last changed by a commit pushed straight to the default branch, or merged otherwise
    than squashed, or a pull request or review whose account was deleted: change the entry again
    through a reviewed pull request.
  - The workflow run on another branch than the default one stops: run it on the default branch.
  - A token or API problem: run the workflow again; if it persists, check GitHub's status.
- **Builds.** The findings are explained in [`findings.md`](findings.md): a released version
  changed without a new version (`VER-020`), a version lower than released (`VER-002`), a
  released scenario removed (`REL-003`), or an entry that fails its checks. Fix the entries
  through a pull request, then run the workflow again.
- **Comparison.** The two builds differ: the release is not reproducible, or a build job was
  tampered with. Keep both builds, which the run keeps as artifacts for seven days, compare
  them, and find the cause before anything else runs; if tampering cannot be ruled out, report
  it privately, as [`SECURITY.md`](../SECURITY.md) says.
- **Verification.** `verify` refuses what was built: a defect of the tools, or a sign of
  tampering. If tampering cannot be ruled out, report it privately, as
  [`SECURITY.md`](../SECURITY.md) says; open a public issue only for a defect known to be no
  security problem.
- **Publication.** The tag of the release exists: a release is never replaced; find why, then
  release again from a later commit. The release is published but the channel did not move:
  write the pointer to it with `scenario-tools channel pointer` and ask an administrator to put
  it on `channels`, which only the release app can update otherwise.
  Until the pointer is restored, a run the same day stops on the existing tag, as it names the
  release again: restore the pointer first. A release tagged on another commit than the run's,
  or one that fails its check once read back, is not pointed at: find why before anything else,
  and if tampering cannot be ruled out, report it privately, as
  [`SECURITY.md`](../SECURITY.md) says.
  A publication stopped while its files were uploaded can leave a draft release: delete the
  draft, which no one could read, before releasing again. The pointer changed while the run
  ran: someone wrote on `channels`; find who, then release again.

## A pull request is refused by mistake

A policy rule or the secret scan refuses what is legitimate. Never work around the check in the
pull request: an ignore file or a `gitleaks:allow` comment in it is never read.

- **The secret scan:** a maintainer adjusts the shared rules, through a reviewed pull request.
- **A blocking `POL-004`, `POL-005`, `POL-006` or `POL-009`:** a maintainer may add an exception
  for that field of that `scenario.json`, with its hash and a justification, as
  [`findings.md`](findings.md#other-checks) describes, and a code owner approves it. The checks
  take an exception only once the default branch names the code owners of the policy data in
  `.github/CODEOWNERS`; until then, none can be granted. No other finding can be excepted.

## A secret reached the default branch

1. Revoke it first, wherever it was issued: it is public from the moment it was pushed.
2. Remove it from the entry through a pull request, with a new version.
3. The history keeps it, and the default branch's history is never rewritten: revoking it is what
   protects.

## An account is compromised

A maintainer's, a reviewer's or an automated account, or a token.

1. Revoke what it holds: its sessions, its tokens and keys, its membership of the maintainers'
   team. Rotate any secret it could read.
2. List what it did since it may have been compromised, in the repository's and the
   organisation's audit logs: its pushes, its approvals, its merges, the workflow runs it
   started, the **Release** runs included, and any change to the branch rules, the
   collaborators, the keys or the workflows.
3. For each merge it made or approved, review the change again. A scenario it touched that may
   be malicious is withdrawn at once, as below.
4. Check any release published since then against what its commit
   builds: build that commit again on the same channel, with the approvals file and the previous
   manifest the release was built from, never approvals collected again, as reviews may have
   changed since. The archives must be the same bytes; so must the manifest, but for its
   `release_approver`, which publication adds, and which is checked on its own.
5. Report it as [`SECURITY.md`](../SECURITY.md) says, so that an advisory can tell the platforms.

## A scenario must be withdrawn

A released scenario is never removed from the catalogue: the next release would refuse it
(`REL-003`), and platforms would never learn it is withdrawn.

1. In its `scenario.yaml`, set `status` to `REVOKED` when it must no longer run, or `DEPRECATED`
   when it is replaced or no longer maintained. Leave `scenario.json` as it is.
2. Raise its `version`: a patch is enough when the status is the only change.
3. Add the version's section on top of its `CHANGELOG.md`, `## <version> — <YYYY-MM-DD>`, saying
   why.
4. Render its sheet again (`scenario-tools render <entry>`): the sheet shows the status.
5. Open the pull request and have it reviewed and merged.

Platforms learn it from the next release they read: there is no revocation list yet. For a dangerous scenario, also report it as [`SECURITY.md`](../SECURITY.md)
says, so that an advisory can tell the platforms that installed it without waiting.
