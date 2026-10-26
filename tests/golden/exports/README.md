# Reference OpenAEV exports

Test inputs only: scenario releases are built from the catalogue and never include them.
These archives are the three starter-pack scenarios shipped with OpenAEV Community
Edition (https://github.com/OpenAEV-Platform/openaev, under
`openaev-api/src/main/resources/starterpack/scenarios/`), exported through the platform
API. `sources.json` records their origin, the platform version, the export options and the
SHA-256 of each archive; the tests fail if an archive changes.

They come from OpenAEV, Copyright (c) 2021-2026 Filigran SAS, licensed under the
Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0).

`tabletop-exercise-akira-ransomware-crisis.zip` is reproduced without modification. In
`easm-scenario.zip` and `salt-typhoon-cve-ttps-validation.zip` the embedded copies of the
built-in **Nuclei** contracts were re-recorded for platform 3.261016.0, where the Nuclei
injector gained a `template_url` field (openaev/injectors#466) and so the canonical copy of
every built-in Nuclei contract changed. The copies are the platform's own, captured from a
3.261016.0 instance; nothing else in the archives is altered. This keeps them consistent with
`policy/data/builtin-contracts.yaml` so `SCH-006` (built-in contract drift) passes.

They are kept raw on purpose, as the input of the normalisation tests: they keep the values
they hold in the OpenAEV sources, such as sender addresses. Their reviewed normalised form is
in `../normalised/`. After a deliberate change to normalisation, regenerate it from the
repository root, then review the diff before committing:

```
for export in tests/golden/exports/*.zip; do
  name=$(basename "$export" .zip)
  mkdir -p "build/normalised/$name"
  uv run scenario-tools normalize "$export" --out "build/normalised/$name" \
    --external-id 5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42
  cp "build/normalised/$name/scenario.json" "tests/golden/normalised/$name.json"
done
```
