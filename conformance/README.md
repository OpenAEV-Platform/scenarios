# Conformance material

What a platform, or any consumer of the catalogue, can check its own implementation against.
Nothing here needs a secret.

## `payload-hash.json`

Test vectors of the canonical hash of a payload: each payload, the techniques of its contract and
the hashes of its attached files, with its canonical form and its SHA-256, or the reason it
cannot be hashed. A platform computing the hash must give the same result for each.

## `releases/`

Release fixtures, written by `scenario-tools conformance build`, the same bytes on every build.
Each directory is a release: its `manifest.json`, and the archives beside it.

- `accepted` is an approved release `verify` accepts: two scenarios sharing one payload, one
  with attachments encrypted with the shared password.
- `chaining-accepted` is a release `verify` accepts with a scenario in chaining: two steps, the
  second waiting for the first, both running the payload a time-based scenario also runs, listed
  once. Its steps carry only what `verify` reads, not every field an export carries.
- Every other directory is a release refused for one reason, one fixture for each way `verify`
  refuses a release:
  - an archive whose hash or size is not the one listed, or that is missing; a file the
    manifest does not list;
  - an archive unsafe to extract: an entry name leaving the extraction directory, a scenario
    entry over 100 MiB once inflated, or inflating beyond the size it declares, more than 1,000
    entries, a symbolic link, two entries of one name;
  - an archive that is not what `build` writes: an entry it never writes, attachments
    encrypted with another password, a scenario part outside the closed list, a workflow whose
    steps are not a list or keep their data as text;
  - a payload whose content is not the one listed, not listed, listed but not embedded,
    without its ID, that cannot be hashed, listed twice, outside an inject's contract, or one
    ID with two contents across the release; the `chaining-*` fixtures refuse a step's payload
    that is not listed, not the one listed, or outside its contract;
  - a manifest that does not meet its schema, an approved one without its release approver, a
    scenario listed twice, an archive named after another version.

  An archive over the 20 MiB a verifier reads has no fixture: the repository would carry it.

`releases/expected.json` describes each fixture and lists the findings verifying it must give, by
code, path and field; for an archive refused as unsafe, `cause` is the `IO` code that refused it.
A fixture with `approved` set is verified as an approved release. The codes are explained in
[`docs/findings.md`](../docs/findings.md).

```sh
uv run scenario-tools conformance run conformance/releases --schemas schemas
```

The archives of the refused fixtures are hostile on purpose: open them only with a verifier.
