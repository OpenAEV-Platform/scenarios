"""The hand-built scenario in chaining as an entry: where it sits and its metadata."""

CHAINED = "scenarios/techniques/chained"
CHAINED_METADATA = """\
schema_version: 1
external_id: 5b9a2c84-3a0e-4c55-9a8c-2a6f0d7e1b42
version: 1.0.0
status: VERIFIED
name: Two chained steps
description: Lists the processes of an endpoint, then lists them again once it is done.
severity: low
category: attack-scenario
main_focus: endpoint-protection
type: chained
platforms:
- Linux
- MacOS
threat:
  ttps:
  - T1057
sources:
- url: https://attack.mitre.org/techniques/T1057/
  tlp: TLP:CLEAR
  title: 'MITRE ATT&CK T1057: Process Discovery'
targets: []
requires:
  openaev: '>=3.261024.0'
  edition: EE
  injectors:
  - openaev_implant
  executors:
  - openaev
payloads: []
"""
