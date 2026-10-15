# AGENTS.md

> **Entry point for coding and content agents.** It says what this repository is, which
> commands to run, where the rules live, and what an agent never does. The step-by-step guide to
> proposing a scenario is [`docs/agents.md`](docs/agents.md).

## What this repository is

The catalogue of OpenAEV scenarios, and the tools that prepare, check and release it. A scenario
is an entry under `scenarios/<domain>/<slug>/`: its metadata (`scenario.yaml`), the scenario as
the platform stores it (`scenario.json`), its sheet (`README.md`) and its `CHANGELOG.md`.
Releases are built from the catalogue; platforms install them. Every scenario runs on real
endpoints: what this repository holds must be safe to run and public.

| Path | What it holds |
|---|---|
| `scenarios/` | The entries, by domain |
| `policy/data/` | The data the policy rules read, and the exceptions the maintainers grant |
| `schemas/` | The schemas of an entry, an intake request, a release manifest |
| `src/scenario_tools/` | The tools, in layers: `domain` (rules, no input or output), `application`, `ports`, `adapters`, `interface` (the command line) |
| `tests/` | The tests, organised by those layers, plus architecture, workflow and secret-scan tests |
| `conformance/` | Shared test vectors and release fixtures |
| `docs/` | The documentation, linked below |

## Key commands

```sh
uv sync --frozen                     # install the tools, as locked
uv run scenario-tools --help         # every command
uv run scenario-tools intake ...     # an entry from a platform export (docs/intake.md)
uv run scenario-tools validate <entry>
uv run scenario-tools render <entry> # the entry's sheet, never written by hand
uv run scenario-tools diff <entry> --previous-root <base-checkout>   # what changed, the version needed
make check                           # everything the continuous integration runs
```

## Where the rules live

| Subject | Read |
|---|---|
| Proposing or updating a scenario | [`docs/agents.md`](docs/agents.md), then [`docs/intake.md`](docs/intake.md) |
| What a scenario may hold, versions, pull requests | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
| Every finding the tools report, and what to do | [`docs/findings.md`](docs/findings.md) |
| Releases | [`docs/releases.md`](docs/releases.md), [`docs/consumers.md`](docs/consumers.md) |
| Security | [`SECURITY.md`](SECURITY.md), [`docs/threat-model.md`](docs/threat-model.md), [`docs/runbook.md`](docs/runbook.md) |
| Working on the tools | [`CONTRIBUTING.md`](CONTRIBUTING.md#working-on-the-tools) |

## What an agent never does

- **Never puts anything non-public in an entry:** no customer data, no internal address, no real
  credential or token. Targets are placeholders.
- **Never writes a generated file by hand:** the sheet comes from `scenario-tools render`, the
  stored scenario and the payload references from `scenario-tools intake`.
- **Never works around a check:** no ignore file, no `gitleaks:allow` comment, no change to
  `policy/data/` to make an entry pass. A policy exception is the maintainers' to grant.
- **Never commits** the export, the request or the plan of an intake run: keep them outside
  the checkout.
- **Never approves, merges or publishes.** An automated account opens pull requests; people
  review them. A pull request that proposes a scenario adds or changes only that entry; a policy
  exception in `policy/data/` is added by a maintainer, never by the agent.
- **Never ticks a box** of the pull request template's checklist: its scenario boxes attest a
  human test run, and the human author ticks them.

## Pull requests

- Title in Conventional Commits, ending with the issue it closes: `feat(scenarios): add easm (#72)`.
- For a scenario, the title and the body are the intake plan's. For any other change, the body
  follows [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md). Every pull
  request closes an issue.
- Commits are signed.

## Working on the tools

New behaviour comes with its tests, written first; `make check` passes before a pull request is
opened (it needs the tools [`CONTRIBUTING.md`](CONTRIBUTING.md#working-on-the-tools) lists),
mutation testing of the policy and verification rules included: a surviving mutant fails the
build. It is killed by a test, or the code is rewritten so that it cannot survive: never
silenced. The domain holds no input or output, and the architecture contracts refuse an import
that crosses the layers the wrong way.
