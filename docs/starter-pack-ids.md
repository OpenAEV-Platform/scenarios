# Starter-pack identifiers

The OpenAEV platform embeds three scenarios, the starter pack, and installs them once on a new
platform, unless the starter pack is turned off. The catalogue is to publish the same three
scenarios, so that a platform can link an installed copy to its catalogue version and offer the
next one. This page fixes their identifiers, which the entries use.

Their identifiers in the catalogue are taken from the platform's embedded exports: the scenario
ID of each export, and the payload ID of each payload it holds. A scenario's ID is the
`external_id` of its entry; a payload's ID is the one the entry's references to it use. All are
fixed once published: none of them ever changes, whatever later versions hold. The
platform's import does not keep these identifiers on the copies it installs today: linking an
installed copy to the catalogue needs the platform to read them back from its embedded exports.

## Scenarios

Each entry is added at its place as the catalogue is filled.

| Scenario | Entry | `external_id` |
|---|---|---|
| EASM Scenario | `scenarios/techniques/easm/` | `3e2aa79f-9d73-48fd-839e-ccf1525b42e7` |
| Tabletop Exercise - Akira Ransomware Crisis | `scenarios/ransomware/akira-ransomware-crisis/` | `90bf7bde-7f50-4b2b-ac78-a7617960d509` |
| [SALT TYPHOON] CVE & TTPs validation | `scenarios/intrusion-sets/cve-ttps-validation/` | `8c7511d2-9ca9-4236-8cf9-be3b10f8cd8e` |

## Payloads

The payloads of *[SALT TYPHOON] CVE & TTPs validation*, the only scenario of the three that holds
any:

| Payload | ID |
|---|---|
| BAT script execution with WMIC - Salt Typhoon | `11de5aa3-4615-402f-afb7-1459dd5851ef` |
| Cleanup artifacts | `b0ab8632-2ea2-4b44-81e7-04289245de03` |
| Copy beacon cab file to remote target with some masquerading - Salt Typhoon | `e38425d8-fef7-48a2-bf1f-217cdd08642a` |
| Create a New Service "Crowdoor" - Salt Typhoon | `13973155-b166-4bbf-a34a-6b74c0d92957` |
| Create a new Registry Key for Autorun of cmd.exe - Salt Typhoon | `3bb212f8-84ac-4e21-bffe-eaee2afe43b0` |
| Deploy cab file containing beacon to target - Salt Typhoon Style | `f3cf1f92-54dc-497e-8d0e-10c0edacf285` |
| Enumerate Local and Remote System Info - Salt Typhoon | `e66243d7-14ac-41c3-98db-e262169180ce` |
| Execute a remote BAT Script via PSExec - Salt Typhoon | `03874f13-ab7c-4616-b3ec-4274c3205644` |
| Expand cab file to remote target with some masquerading - Salt Typhoon | `abf89316-e585-4863-9458-57c71fcc98dc` |
| Exfiltrate data HTTPS using curl windows | `1f0f9adf-4c16-42ce-bfb6-1ff2134bd8fc` |
| TrillClient’s user credential discovery - Salt Typhoon | `a2a29122-1033-4b4b-8581-b57a3ed0f75f` |

## Where they come from

The platform's source holds the embedded exports, one archive per scenario, under
`openaev-api/src/main/resources/starterpack/scenarios/` of
[OpenAEV-Platform/openaev](https://github.com/OpenAEV-Platform/openaev); these identifiers were
read there at commit `cbbe3ffd68`. In each, the scenario ID is `scenario_information.scenario_id`,
and a payload's ID is the `payload_id` of the injector contract that holds it. Should the platform
replace an export later, the identifiers here stay those recorded. A test of this repository keeps
this page as it is: an identifier, once published, is never changed nor reused.
