"""Settings every test shares."""

import os

from hypothesis import settings

# A property test judges what holds, never how fast: the default deadline of 200 ms fails a test
# whose property holds when the machine is busy. The tests that bound a running time are marked
# `timing` and run alone (see the Makefile).
settings.register_profile("repository", deadline=None)
# For make check-fast only, never a gate: fewer examples, a quicker loop while working.
settings.register_profile("fast", deadline=None, max_examples=10)
settings.load_profile(os.environ.get("SCENARIOS_HYPOTHESIS_PROFILE", "repository"))
