"""The form of an identifier the platform gives: a UUID in lower case with its hyphens."""

import re

CANONICAL_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
