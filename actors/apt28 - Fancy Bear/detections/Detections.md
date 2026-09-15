# APT28 — Detections

**Presentation reviewed:** 2026-09-15.

This directory contains defensive detection and threat-hunting content associated with the APT28 procedures documented in this repository.

> **Review / tuning:** queries are investigation starting points. Validate sensor coverage, approved administration and campaign context before production use. A behavioral or artifact match does not establish APT28 attribution.

## Content

- [KQL](KQL.md) — 33 copyable queries.
- [Splunk](Splunk.md) — 28 copyable searches.
- [YARA](APT28-Hunting.yar) — 10 file and artifact triage rules.
- [ATT&CK evidence mapping](../technical/mitre-attack.md).

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| 1. Credential Access | 6 | 4 | Sensor requirements, scope and false positives are stated per query |
| 2. Active Directory and Network Discovery | 1 | 1 | Sensor requirements, scope and false positives are stated per query |
| 3. Persistence and Remote Administration | 11 | 12 | Sensor requirements, scope and false positives are stated per query |
| 4. Tunneling and C2 | 2 | 2 | Sensor requirements, scope and false positives are stated per query |
| 5. Defense Evasion and Impairment | 4 | 3 | Sensor requirements, scope and false positives are stated per query |
| 6. Collection and Exfiltration | 2 |  | Sensor requirements, scope and false positives are stated per query |
| 10. Campaign Artifact Hunts | 7 | 6 | Sensor requirements, scope and false positives are stated per query |

## Query Organization

Both query files use the same investigation families, numbered entries and field order: origin, telemetry, review / tuning, then the copyable query. Only populated families appear. Query counts and coverage depend on the actor and sensor; shared family names do not imply identical detection logic. Bibliographic sources remain in the actor's reference file.

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| APT28_HEADLACE_SHORTCUT | Published | Detects the HEADLACE backdoor shortcut dropper. Rule is meant for threat hunting. | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| APT28_HEADLACE_CREDENTIALDIALOG | Published | Detects scripts used by APT28 to lure user into entering credentials | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| APT28_HEADLACE_CORE | Published | Detects HEADLACE core batch scripts | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| APT28_MASEPIE | Published | Detects MASEPIE python script | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| APT28_GooseEgg_Artifact_Bundle_Triage | Repository-authored | Local heuristic for co-located GooseEgg artifact strings; not a binary-family signature | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| APT28_Outlook_Macro_Configuration_Triage | Repository-authored | Local heuristic for scripts staging Outlook macros and changing startup/security settings | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| APT28_Browser_Secret_Script_Triage | Repository-authored | Local STEELHOOK-related script heuristic; also matches credential auditing tools | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| APT28_Headless_Webhook_Script_Triage | Repository-authored | Local HEADLACE/HOOKEDGE-related service-abuse heuristic; approved automation can match | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| APT28_Neusploit_Staging_Strings_Triage | Repository-authored | Local heuristic for co-located Neusploit staging names; no exploit or family identification | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| APT28_Retained_SHA256_Exact_Match | Repository-authored | Exact file match against 14 retained malicious SHA-256 values; historical corpus | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |

## Review Notes

Reviewed **2026-09-15**. Empty and inapplicable detection sections have been removed. Locally authored content translates documented procedures into testable defensive hypotheses; it is not presented as vendor-published detection logic. Bibliographic provenance is centralized in the actor's reference file.

See [validation](../../../VALIDATION.md) for structural checks, harmless YARA fixtures and the limits of static query review.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
|---|---|
| Document execution and HEADLACE delivery | Process creation and command line. Inspect ancestry and scripts; approved automation can match (H01, H03–H04). |
| Outlook credential exposure | Endpoint network events. Confirm public destination, message context and authentication evidence (H02). |
| GooseEgg persistence and staging | Process, registry and file events. Correlate task, COM handler and copied constraint file (H05–H08). |
| Outlook macro persistence and execution | File, registry and process events. Inspect macro ownership, policy changes and executing process (H09–H12, H14). |
| OneDrive DLL side-loading | Image-load events. Validate loaded DLL path, signature and hash (H13). |
| Browser and prompted credential collection | Process command line; recovered scripts for YARA. Script bodies may be absent from process logs (H15–H16). |
| Registry-hive collection | Process creation. Baseline backup and response activity (H17). |
| Remote service execution | Process creation / parent image. PsExec is also legitimate administration (H18). |
| Neusploit staging | File creation. Names alone have low specificity; correlate exact hashes (H19). |
| Mail-channel hunting | Endpoint network events. Generic script-host hypothesis; mail automation can match (H20). |
| Native discovery | Process creation. Local threshold: three distinct tools in ten minutes (H21). |
| Router-campaign infrastructure | Endpoint network events. 182 historical IPs; no assumption of current hostile control (H22). |
| Sample matching | File/process/image-load hashes, depending on platform. 14 SHA-256 and two SHA-1 values; legitimate OneDrive excluded (H23). |
| Webhook communication | Network hostname visibility or Sysmon DNS. DNS resolution and successful connection are different observations (H24). |

See [validation](../../../VALIDATION.md) for structural checks, YARA fixture results and query-execution limits.
