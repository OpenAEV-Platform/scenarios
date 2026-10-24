# Snapshots of the tools

`tests/test_snapshots.py` runs every command of the tools that needs neither GitHub nor a
platform on a frozen reference corpus, and compares, byte for byte, its output, its error output,
its exit code and the files it writes with what `expected/` holds. It runs with every other test,
in `make check` and in CI.

- `corpus/`: a frozen copy of the catalogue's entries (one of them in chaining), `payloads/`, the
  schemas and policy data and the conformance fixtures, and the exports of the starter pack and of
  the entry in chaining. It does not follow the catalogue: a snapshot changes only when the tools
  do.
- `inputs/`: the intake requests the cases give.
- `cases.py`: the cases, and how one runs: in a git checkout of the corpus of its own, committed
  at a fixed time, with the clock, the time zone and the locale fixed. Output or a written file over
  16 KiB is kept as its SHA-256 and size, and an output holding a null character
  in hexadecimal.
- `expected/`: one directory per case.

A difference is a change of behaviour. When a change is meant, regenerate the cases it changes
(each is run twice, and written only when both runs agree), then review every difference before
committing:

```sh
uv run python -m tests.snapshots.regenerate CASE...
```

A refactoring never regenerates them.
