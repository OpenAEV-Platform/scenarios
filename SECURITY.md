# Security policy

## What to report

- **The tools** of this repository: a way to make them follow a link, read or write outside where
  they should, run code they should not, or accept an entry they should refuse.
- **A scenario** of the catalogue: one that could harm the systems it runs against beyond what it
  describes, or that holds data that should not be public, such as a credential, a customer's
  data or an internal address.
- **The checks and workflows**: a way for a pull request to pass checks it should fail, or to
  reach what it should not.

## How to report

Do not open a public issue. Report the problem privately through
[GitHub's security advisory form for OpenAEV](https://github.com/OpenAEV-Platform/openaev/security/advisories/new),
and say that it concerns the scenarios repository. The
[OpenAEV security policy](https://github.com/OpenAEV-Platform/openaev/security/policy) describes
what to include, how fast you get an answer and how disclosure works; it applies to this
repository too.

## What follows a report

A scenario found dangerous is withdrawn by a new version whose status is `REVOKED`: platforms
learn it from the next release they read, and from the
security advisory, when one is published, sooner. [`docs/runbook.md`](docs/runbook.md) describes how a scenario is withdrawn, and
[`docs/threat-model.md`](docs/threat-model.md) what the repository guards against.

## Supported versions

The tools are supported on the latest commit of the main branch. A scenario is supported in the
latest version the catalogue publishes.
