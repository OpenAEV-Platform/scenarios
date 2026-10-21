# A hand-built export of a scenario in chaining

Test input only: scenario releases are built from the catalogue and never include it.

`two-steps.json` is shaped as the platform's exporter writes a scenario in chaining: two steps
that run the same command payload, the second one after the first. It was written from an export
of a test instance, with these edits, so that it holds nothing of that instance:

- every identifier is replaced by a made-up one (`00000000-0000-4000-8000-…`), except the
  identifier of the platform's implant injector, which is the same on every platform; every
  date is replaced by `2026-01-01T00:00:00Z`;
- the name and description are replaced, and the severity, category and main focus are set;
- the command payload is the "Process Discovery - ps" payload of the public OpenAEV payloads,
  as the instance installed it.

Everything else is as the exporter wrote it, including `step_data`, which the exporter writes as
JSON text.

`two-steps.normalised.json` is its reviewed stored form, as `normalize` writes it. It changes
only with a reviewed change to normalisation.
