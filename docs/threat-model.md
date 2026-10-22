# Threat model

The scenarios of this catalogue run on real endpoints, through the agents of every platform that
installs them. Content tampered with on its way is therefore not a bug: it is an attack on every
platform that imports it. This page says who could attack, what they could do, and what stands in
their way, as the repository is today; what is planned is said so. Releases are not published
yet: the release workflow builds and checks the first release, and publishes nothing.

## Who could attack, and what stops them

| Attacker | What they could do | What stops them |
|---|---|---|
| A contributor proposing malicious or careless content | A scenario that harms what it runs against beyond what it says, or that discloses data | The pull request checks: every entry it adds or changes is validated and its policy rules applied (forbidden actions, changes to the endpoint without a cleanup command, security products named, hosts outside the allowed targets, recurrences), and its entries and commits are scanned for secrets. The entry and title checks run as the target branch has them, so that a pull request cannot change them; a change to the tools, rules or workflows themselves is checked by the tools pipeline, which runs the pull request's own version, and by the review. Every change is reviewed by a maintainer before it is merged. |
| A compromised maintainer or reviewer account | Merge malicious content | The contribution rules: a review before every merge, signed commits. The default branch's settings that enforce them live on GitHub, not in the repository. Planned: the maintainers named as code owners of the rules, tools and workflows, and a separate approval to publish a release. |
| A compromised agent or bot account | Propose malicious content | Its pull requests go through every check and a review. An automated account must not be given the right to approve, merge or publish; the release workflow never counts a bot's review as an approval. |
| A compromised build job | Alter the archives of a release | The release is built twice, on two runners, and the two builds must be the same bytes; the jobs that build it can only read the repository. |
| A corrupted or truncated download | Install broken content | Each archive's size and SHA-256 are in the manifest, for a consumer to check before it opens the archive. |
| A malicious archive: path traversal, decompression bomb, oversized file | Compromise or exhaust a consumer | Size limits and safe extraction before anything is extracted: the repository's verifier applies them to every release it builds, and [`consumers.md`](consumers.md) asks every consumer to. |
| A payload put on a platform first, under an ID a release lists | Make a distributed scenario run other content | The payload's content hash is in the manifest; [`consumers.md`](consumers.md) asks a platform that already holds a payload under that ID to check its content against it, and not to use it otherwise. |
| An injector contract put on a platform first, under the identifier a scenario in chaining uses | Make a step run other content than its archive embeds, since the import keeps the contract it finds | [`consumers.md`](consumers.md) asks that a scenario in chaining be imported only where the import compares a contract or payload it would reuse with the one embedded, and refuses the import when they differ. |
| A scenario whose steps pass data to each other | Run, in a later step, what an earlier step read from the targeted host, which no review saw, or carry that data elsewhere | A condition that copies a step's output into the next step's inject (a mapper) is refused at any depth, by the checks of every pull request and again before an archive is built. The conditions accepted today only decide whether a step runs; a condition type is assessed here before it is accepted. |
| A scenario that sets its own scope | Widen or narrow the assets its steps target on the platform that installs it, or fix hosts no review saw | A workflow's scope rules, scope variables and team members must be empty: the checks refuse one that holds any, rather than removing it, so that what is reviewed is what is stored; the targets are set where the scenario is installed. |
| A test report swapped | Mislead reviewers and consumers | Planned: each report's hash in the manifest, beside its scenario's archive. |

How a release is built is in [`releases.md`](releases.md); what `intake` guarantees as it writes,
in [`intake.md`](intake.md).

## Accepted for now

- **Whoever can publish a release can publish anything.** A compromised account or token with the
  right to publish, or a bypass of the branch and release protections, could publish content
  with a matching manifest. Releases are not signed. Signing, with consumers checking the
  signature against a key the attacker does not hold, would show a release replaced after it
  was built; it would not stop malicious content merged through bypassed protections, which
  is signed like any other. It is the first addition if the risk grows.
- **A compromised mirror or a changed download location could do the same.** This is why
  [`consumers.md`](consumers.md) asks consumers to download from the repository's release
  location by default, and to make changing it an administrator's action.
- **An older release replayed is not detected** by the release alone. A consumer is asked to
  refuse a version lower than one it installed, but a platform that installs for the first time
  cannot tell an old release from the latest.
- **There is no revocation list.** A scenario is withdrawn by a new version, which a platform
  learns from the next release it reads.

## Out of scope

The compromise of GitHub itself, and a platform administrator acting against their own platform.
Any other case is assessed when it is reported: see [`SECURITY.md`](../SECURITY.md).
