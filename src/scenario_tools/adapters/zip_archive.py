"""The import archive as a ZIP file, the same bytes for the same entry on every build.

The layout is the one the platform's importer reads: the type of each entry comes from its
comment, so the scenario is the entry whose comment is ``Scenario``; the attachments archive is
read by its name, and opened with the shared password. Every entry has fixed metadata, and is
stored without compression: deflate bytes depend on the zlib build, stored ones on nothing.
"""

import io
import stat
import zipfile

SCENARIO_ENTRY = "scenario.json"
SCENARIO_COMMENT = b"Scenario"
ATTACHMENTS_ENTRY = "attachments.zip"
_UNIX = 3  # whatever the system that builds it: Python marks entries made on Windows as such


def _entry(name: str, comment: bytes = b"") -> zipfile.ZipInfo:
    entry = zipfile.ZipInfo(name)  # dated 1980-01-01 00:00:00, the earliest a ZIP can hold
    entry.create_system = _UNIX
    entry.external_attr = (stat.S_IFREG | 0o644) << 16
    entry.compress_type = zipfile.ZIP_STORED
    entry.comment = comment
    return entry


class ZipArchiveBuilder:
    def build(self, scenario: bytes, attachments: bytes | None) -> bytes:
        entries = [(_entry(SCENARIO_ENTRY, SCENARIO_COMMENT), scenario)]
        if attachments is not None:
            entries.append((_entry(ATTACHMENTS_ENTRY), attachments))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for entry, data in sorted(entries, key=lambda item: item[0].filename):
                archive.writestr(entry, data)
        return buffer.getvalue()
