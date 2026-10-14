# Contributing to the OpenAEV scenarios

Thank you for considering a contribution. This repository is a catalogue of attack scenarios for
[OpenAEV](https://github.com/OpenAEV-Platform/openaev), and the tools that prepare and check them.
The [README](README.md) explains how it works; this page explains how to take part.

## What you can contribute

- **A scenario**: a new one, or a better version of one already in the catalogue.
- **A fix**: a scenario that does not run as described, a mistake in a description, a bug in the
  tools.
- **An idea or a question**: open an issue, even if you do not plan to write the change yourself.

Every contribution starts with an issue, so that the work is discussed before it is done. Pick
the template that fits: bug report, feature request, question or technical improvement.

## Contributing a scenario

1. Build and test the scenario on an OpenAEV platform you are allowed to test, then export it.
2. Open an issue that describes the scenario and the threat it plays.
3. Follow [`docs/intake.md`](docs/intake.md): write a short request, run `scenario-tools intake`,
   and complete what its plan lists.
4. Run `scenario-tools validate` on the entry, then open a pull request with the title and body
   the plan gives.

A scenario holds **public content only**: no customer data, no internal address, no real
credential, nothing you would not show at a conference. Targets are placeholders that each user
fills in on their own platform. Reviewers check this, and the automated checks scan every entry
for secrets.

### When a policy rule blocks a legitimate attack

A new attack may need to breach a rule: run a command a shared scenario avoids, leave something no
cleanup can undo, name a security product, or start two endpoint injects close together
(`POL-004`, `POL-005`, `POL-006`, `POL-009`). Say why in the pull request, quoting the finding. If
the maintainers agree, once the entry is otherwise reviewed, they grant an exception for that field
of the entry's `scenario.json` as it is in `policy/data/exceptions.yaml`, in your pull request, and
a code owner approves it: the finding becomes information. The exception names the sha256 of that
`scenario.json`, so change nothing more in it after it is granted. A later change to what the
scenario runs changes that hash: the checks then block again and give the new hash, and a
maintainer, once the change is reviewed, gives the exception that hash in the same pull request
(from a fork, allow edits from maintainers). A change to `scenario.yaml` alone, such as its
version, keeps the exception. The other rules have no exception, and no exception is taken before
the repository names the code owners who approve them.

### Versions

Each entry has a version, in `scenario.yaml`, and a `CHANGELOG.md` with one section per version,
newest first, such as `## 1.2.0 — 2026-10-14`. A change to an entry raises its version as far as
the change needs, against the entry on the base branch: a major version for its attack chain, its
targets, an inject's contract, its requirements, or anything removed; a minor one for an inject or
a payload added, or an inject's content changed; a patch for text and descriptive metadata. The
finding gives the reason and the least version, and
[`docs/findings.md`](docs/findings.md) the rules. The pull request runs this comparison against
the base branch as it is when the check runs; to run it before, point `--previous-root` at a
checkout of the project's `main`, not your fork's:

```sh
git remote add upstream https://github.com/OpenAEV-Platform/scenarios.git  # once, from a fork
git fetch upstream main
git worktree add --detach ../scenarios-main upstream/main
uv run scenario-tools validate --previous-root ../scenarios-main -- scenarios/<domain>/<entry>
git worktree remove ../scenarios-main
```

If you cloned the project itself, use `origin/main` in place of `upstream/main`. If the pull
request's check disagrees with your run, rebase your branch on the project's `main`.

## Working on the tools

The tools are written in Python 3.12 and managed with [uv](https://docs.astral.sh/uv/):

```sh
uv sync --frozen
uv run scenario-tools --help
make check
```

`make check` runs everything the continuous integration runs: linting, types, architecture
contracts, tests with full coverage of the domain, security checks, the audit of the dependencies
and of the workflows, and the secret scan. It needs [gitleaks](https://github.com/gitleaks/gitleaks)
and [actionlint](https://github.com/rhysd/actionlint) at the versions set in the `Makefile`.

New behaviour comes with its tests, written first. The code keeps its layers apart: the domain
holds the rules and no input or output, the adapters talk to files, git and the platform, and
`make check` refuses an import that crosses them the wrong way.

## Pull requests

- **One issue, one pull request.** The pull request closes its issue.
- **Titles** follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) and end
  with the issue: `type(scope): description (#issue)`, the description in lower case with no
  final period. For example `feat(scenarios): add easm (#72)` or
  `fix(tooling): read a link as a link (#123)`.
- **Signed commits.** See the
  [GitHub documentation on signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).
- **Checks.** Three checks must pass before a merge: the tools pipeline, the title, and the
  checks of the entries the pull request adds or changes. The title and entry checks run as the
  target branch has them, so that a pull request cannot change them; the tools pipeline runs the
  pull request's own version, which the review covers.
- **Review.** Every change is reviewed by a maintainer before it is merged.

## Code of conduct

This project follows the [OpenAEV code of conduct](CODE_OF_CONDUCT.md). By taking part, you agree
to respect it.

## Security

Do not report a security problem in a public issue: see [`SECURITY.md`](SECURITY.md).

## Getting in touch

For questions about this repository, open an issue. For OpenAEV in general, join the
[Filigran community on Slack](https://community.filigran.io) or read the
[OpenAEV documentation](https://docs.openaev.io).
