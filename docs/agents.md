# Proposing a scenario as an agent

This page is for an agent, or an automated account, that proposes scenarios to the catalogue: it
turns a scenario built on a platform into a pull request, with the tools of this repository. It
follows the same path as a person, as [`CONTRIBUTING.md`](../CONTRIBUTING.md) and
[`intake.md`](intake.md) describe it, in the order an agent runs it. What an agent never does is
in [`AGENTS.md`](../AGENTS.md).

Run every command from the root of the checkout.

## What it needs

- **An issue**, opened first, that describes the scenario and the threat it plays: every pull
  request closes one, and the request names it.
- **The scenario's export**, from a platform it is allowed to test on, as the platform exports it.
- **A checkout** of this repository at `main`, with nothing left to commit under `scenarios/`,
  `policy/` or `schemas/`, and the tools installed (`uv sync --frozen`).
- **A request**, a short YAML file: `mode: new` with the entry's `external_id` (a lower-case
  UUID, chosen once), `domain`, `slug`, `threat`, `sources` and the `issue`; or `mode: update`
  for a new version of an entry, whose `external_id`, `domain` and `slug` are the entry's, with
  `rewrite: true` only when the scenario was renamed on the platform. For a scenario built
  without a severity, category or main focus, the request gives them (`severity`, `category`,
  `main_focus`), and intake writes them where the platform reads them. For a payload copied
  from a catalogue payload and changed, the request says which one in `payloads`
  (`based_on`), and intake writes it as that payload's next version. Its fields are in
  [`intake.md`](intake.md#the-request).
- **A base checkout**, for an update: a separate worktree of the project's `main`, which
  `--previous-root` points at below, made and removed as
  [`CONTRIBUTING.md`](../CONTRIBUTING.md#versions) shows.

Keep the export, the request and the plan outside the checkout, in a directory that exists; the
plan must not exist yet.

## The steps

1. **Run `intake`**, asking for JSON so that the result can be read:

   ```sh
   uv run scenario-tools --format json intake ../export.zip --request ../request.yaml --repo . --plan ../plan.json
   ```

   Then act on its exit code:

   | Code | What it means | What to do |
   |---|---|---|
   | `0` | The entry and its plan are written; what the plan lists is left to complete | Go on, unless the plan's `changed` is `false`: the export gives the stored scenario again, there is nothing to propose, so stop |
   | `1` | The request is refused (no plan), or a check blocks the entry (a plan) | Read the findings in [`findings.md`](findings.md): fix the request and run again, or fix the entry's files in place |
   | `2` | A usage error, nothing ran: the options, or a plan already there | Fix the command, or remove the old plan |
   | `3` | The environment stopped the run | Read the message. Another `intake` run holding the checkout: wait. A change not committed under `scenarios/`, `policy/` or `schemas/`: if it is an entry this agent left unfinished, complete and commit it on its own branch first; if it is not, stop and report it, never discard another's work. Otherwise stop, and report the message as it is |
   | `4` | A defect of the tools | Stop, and report it |

2. **Complete what the plan's `body` lists:** the fields of `scenario.yaml` it names; the
   starting section of `CHANGELOG.md` for a new entry; for an update, the raised `version` and
   its `CHANGELOG.md` section. In what follows, `<entry>` is the plan's `entry`. For an update,
   `scenario-tools diff --previous-root <base-checkout> -- <entry>` gives the version each change
   needs.
3. **Render and check**, again after any change to the entry:

   ```sh
   uv run scenario-tools render <entry>
   uv run scenario-tools validate <entry>                                   # a new entry
   uv run scenario-tools validate --previous-root <base-checkout> -- <entry>  # an update
   ```

   A blocking finding is fixed in the entry, never worked around. The only finding left may be
   a `POL-004`, `POL-005`, `POL-006` or `POL-009` the attack needs to breach: the pull request
   then asks for an exception, as below, and the maintainers grant it or refuse it before any
   merge. Without `--previous-root`, the version is not compared: for an update, always give it.
4. **Propose the entry:** a branch from the plan's `base`, the whole entry directory added, a
   signed commit with the plan's `title`, then a pull request with the plan's `title` and `body`.
   It adds or changes only that entry.
5. **Go back** to `main` before the next intake, once the entry is committed on its branch:
   switching does not clear what is not committed, and the next run refuses any change left
   under `scenarios/`, `policy/` or `schemas/`.

## When a check refuses the pull request

- **A policy finding** (`POL-*`): change the scenario so that it keeps to the rule. For
  `POL-004`, `POL-005`, `POL-006` and `POL-009` only, when the attack needs to breach the rule,
  say why in the pull request, quoting the finding; the maintainers decide, as
  [`CONTRIBUTING.md`](../CONTRIBUTING.md#when-a-policy-rule-blocks-a-legitimate-attack) describes.
  The other rules have no exception.
- **A secret:** if it is real, report it so that it is revoked, and rewrite the branch without
  it, as [`CONTRIBUTING.md`](../CONTRIBUTING.md#contributing-a-scenario) shows; if it is not, say
  so in the pull request, quoting the rule.
- **The version** (`VER-001`): raise it to the version the finding gives, and add its section to
  `CHANGELOG.md`.
- **Anything else:** the finding says what to do, in [`findings.md`](findings.md). Run
  `validate` again until nothing blocks, then push.

## What it leaves to people

Reviewing the entry, granting an exception, ticking the pull request template's checklist
(its scenario boxes attest a human test run), approving and merging the pull request, and
releasing the catalogue. An agent that cannot complete what the plan lists stops, and says what
is left.
