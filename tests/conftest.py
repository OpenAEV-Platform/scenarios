"""Settings every test shares."""

from hypothesis import settings

# A property test judges what holds, never how fast: the default deadline of 200 ms fails a test
# whose property holds when the machine is busy. The tests that bound a running time are marked
# `timing` and run alone (see the Makefile).
settings.register_profile("repository", deadline=None)
settings.load_profile("repository")
