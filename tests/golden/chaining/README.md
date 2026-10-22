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

`filters.json` is `two-steps.json` with its second step filtered instead of waiting for the
first: an `AND` holding an `EQ` and an `OR` of an `IN` list and an `IS_NOT_NULL`, as an export
of a test instance holds them. It was written by hand from that export, with these edits:

- the scenario's name and the second step's title are replaced;
- the conditions' identifiers, keys, values and names are made up;
- as the exporter writes them, the conditions are listed with each one's subtree in turn, so
  that the five conditions take eleven entries, every copy identical; filters and groups carry
  `condition_key_types: ["text"]` and a null `condition_step_from_id`, and groups a null key and
  value.

`filters.normalised.json` is its reviewed stored form: each condition once, sorted by its stable
identifier.
