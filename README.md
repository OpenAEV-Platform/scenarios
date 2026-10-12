# OpenAEV scenarios

A catalogue of shareable attack scenarios for
[OpenAEV](https://github.com/OpenAEV-Platform/openaev), and the tools that prepare and check them.

> **Status: early.** No scenario has been added yet. The first ones will be the three scenarios of
> the platform's starter pack. Releases, and installing a scenario from the catalogue straight into
> a platform, come later.

## What this repository is for

**OpenAEV** is an open-source platform for adversarial exposure validation. It plays realistic
attacks against your own systems, in a controlled way, to check that your defences see them and
stop them.

A **scenario** is the script of such an attack. It is a timeline of steps, called *injects*. An
inject can run a scan against a host, execute a command on a machine, or send an email to a team.
Each inject says what to do, against which target, and what a good defence should show: an alert,
a blocked command, a report from the team.

Anyone can build a scenario on their own platform. This repository is where scenarios are
**shared**. Each one is reviewed, described in the same way, and kept under version control. Any
OpenAEV user will be able to find it, understand what it does before running it, and get the next
version when it improves.

## How a scenario gets here

```mermaid
flowchart LR
    A["Scenario built<br/>on an OpenAEV platform"] -->|export| B["Export archive<br/>(.zip)"]
    B -->|"scenario-tools intake"| C["Entry in this repository<br/>scenario.json + scenario.yaml"]
    C --> D["Pull request<br/>checks and human review"]
    D -->|merge| E["Catalogue"]
    E -.-> F["Release (planned):<br/>archives and their hashes"]
    F -.-> G["OpenAEV platforms (planned):<br/>install and update"]
```

1. Someone builds and tests a scenario on an OpenAEV platform, then **exports** it as an archive.
2. The `intake` command turns the export into an **entry** of this repository. It replaces or
   removes what belongs to that one platform: internal identifiers, dates, users, the sender's
   address. It also writes a short description file next to it.
3. The entry is proposed in a **pull request**. A human review checks that it is complete, safe to
   publish, and does what it says. Automated checks of every entry in a pull request are planned;
   until then, contributors run them themselves.
4. Once merged, the scenario is part of the **catalogue**.
5. *Planned:* the catalogue is published in releases. Each archive comes with its hash (a
   fingerprint of the file), so that a platform can verify what it installs. OpenAEV platforms
   will then install a scenario from the catalogue and be told when a new version exists.

## What an entry looks like

Each scenario is a folder, filed by domain. This is the layout of an entry:

```text
scenarios/
└── techniques/            the domain: vulnerabilities, intrusion-sets, ransomware or techniques
    └── easm/              the entry's short name (its "slug")
        ├── scenario.yaml  the description: what it is, what it needs, which threat it plays
        └── scenario.json  the scenario itself, in a normalised form
```

- **`scenario.yaml`** is written for people and for the catalogue. It holds:
  - the name, a description and the severity;
  - the threat the scenario reproduces (MITRE ATT&CK techniques, CVEs, intrusion sets) and its
    sources;
  - the targets you must provide on your platform;
  - what your platform needs to run it: its version, its edition, and the injectors (the modules
    that run each step);
  - its **version**, and its **`external_id`**: an identifier (a UUID), chosen once, that never
    changes.
- **`scenario.json`** is the scenario as OpenAEV exports it, in a **normalised** form. Every value
  that only makes sense on one platform is replaced or removed, and lists whose order does not
  matter are sorted. Normalising the same export again gives the same file, so a change in this
  file is always a real change of the scenario.

The rules for both files are in [`schemas/`](schemas/). The data the checks use is in
[`policy/`](policy/): the domains, the platform's built-in injector contracts, and the fields
removed from an export.

## The starter pack

OpenAEV installs three scenarios on each new platform, unless this is turned off: *EASM Scenario*
(external attack surface management), *Tabletop Exercise - Akira Ransomware Crisis* and *[SALT
TYPHOON] CVE & TTPs validation*. They will be the catalogue's first entries, at version 1.0.0.
Their identifiers are taken from the platform itself, and listed in
[`docs/starter-pack-ids.md`](docs/starter-pack-ids.md).

## The tools

The repository includes `scenario-tools`, a command-line tool written in Python.

| Command | What it does |
|---|---|
| `intake` | Turns a platform export and a short request into a new entry, or an update of one, and writes the plan of the pull request |
| `normalize` | Writes the normalised `scenario.json` of an export |
| `validate` | Checks entries against the schemas and the repository's rules (some rules are not run yet) |
| `archive` | Builds the archive of an entry that the platform's importer reads |
| `openaev export`, `openaev import` | Exports a scenario from a platform, or imports an archive into one |
| `check-title` | Checks a pull request title against the shared convention |

To run them, install [uv](https://docs.astral.sh/uv/), then, from a clone of this repository:

```sh
uv sync --frozen
uv run scenario-tools --help
```

`openaev export` and `openaev import` read the platform's address and an API token from the
`OPENAEV_URL` and `OPENAEV_TOKEN` environment variables. Until scenarios can be installed from the
catalogue, `archive` then `openaev import` is the way to try an entry on your own platform.

The tools run on Linux, with git 2.40 or later; macOS is not tested yet. They read every file with
strict limits on size and depth, and never follow a symbolic link inside the repository. They
refuse invisible or direction-changing characters in the files they read, so that what a reviewer
reads is what the platform runs.

These checks protect the review, not your systems. A scenario plays real attack techniques:
always read it before you run it, and only run it against systems you are allowed to test.

## Contributing a scenario

1. Build and test your scenario on an OpenAEV platform, then export it.
2. Follow [`docs/intake.md`](docs/intake.md): write a short request (identifier, domain, short
   name, threat, sources), run `intake`, and complete what its plan lists.
3. Run `validate` on your entry, then open a pull request with the title and body the plan gives.

A few rules apply to every pull request:

- **Public content only.** No customer data, no internal addresses, no real credentials. Targets
  are placeholders that each user fills in on their own platform. Reviewers check this.
- **Signed commits.**
- **A title** that follows [Conventional Commits](https://www.conventionalcommits.org/) and ends
  with the issue number, for example `feat(scenarios): add easm (#72)`.
- **A human review** of every change.

## Questions, security and licence

- **Questions and ideas:** open an issue in this repository.
- **Security problems:** do not open a public issue. Report them privately, as the
  [OpenAEV security policy](https://github.com/OpenAEV-Platform/openaev/security/policy) explains.
- **Licence:** the [Apache License 2.0](LICENSE), for the tools and the scenarios alike.

## Repository layout

| Folder | Content |
|---|---|
| `scenarios/` | The catalogue's entries, one folder each |
| [`schemas/`](schemas/) | JSON schemas of an entry's description, an intake request and a release manifest |
| [`policy/`](policy/) | The data the checks rely on |
| [`docs/`](docs/) | Guides: adding an entry, the starter-pack identifiers |
| [`src/`](src/) | The source of `scenario-tools` |
| [`tests/`](tests/) | Its tests, with real platform exports as reference data |
