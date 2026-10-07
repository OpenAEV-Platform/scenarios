# Reference OpenAEV exports

Test inputs only; they are never part of a release. These archives are the three
starter-pack scenarios shipped with OpenAEV Community Edition
(https://github.com/OpenAEV-Platform/openaev, under
`openaev-api/src/main/resources/starterpack/scenarios/`), exported unchanged through
the platform API. `sources.json` records their origin, the platform version, the export
options and the SHA-256 of each archive; the tests fail if an archive changes.

They come from OpenAEV, Copyright (c) 2021-2026 Filigran SAS, licensed under the
Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0). They are
reproduced without modification.

They are raw exports on purpose: they keep the values they hold in the OpenAEV
sources, such as sender addresses, so that normalisation is tested on real input.
