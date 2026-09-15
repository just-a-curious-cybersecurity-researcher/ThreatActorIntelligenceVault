# APT28 — Detections

This directory contains defensive detection and threat-hunting content associated with the APT28 procedures documented in this repository.

> **Review / tuning:** queries are investigation starting points. Validate sensor coverage, approved administration and campaign context before production use. A behavioral or artifact match does not establish APT28 attribution.

## Content

- [KQL](KQL.md) — 33 copyable queries: nine retained Microsoft hunts and 24 locally authored hunts.
- [Splunk](Splunk.md) — 28 copyable searches: four retained Splunk Security Content searches and 24 locally authored hunts.
- [YARA](APT28-Hunting.yar) — ten rules: four retained published HEADLACE / MASEPIE rules, five local content heuristics and one local exact-hash rule.

## Coverage, Telemetry and Tuning Register

| Procedure / campaign | Local query IDs | Required telemetry | Review / tuning |
|---|---|---|---|
| Document execution and HEADLACE delivery | H01, H03–H04 | Process creation and command line | Inspect ancestry and scripts; approved automation can match |
| Outlook credential exposure | H02 | Endpoint network events | Confirm public destination, message context and authentication evidence |
| GooseEgg persistence and staging | H05–H08 | Process, registry and file events | Correlate task, COM handler and copied constraint file |
| Outlook macro persistence and execution | H09–H12, H14 | File, registry and process events | Inspect macro ownership, policy changes and executing process |
| OneDrive DLL side-loading | H13 | Image-load events | Validate loaded DLL path, signature and hash |
| Browser and prompted credential collection | H15–H16 | Process command line; recovered scripts for YARA | Script bodies may be absent from process logs |
| Registry-hive collection | H17 | Process creation | Baseline backup and response activity |
| Remote service execution | H18 | Process creation / parent image | PsExec is also legitimate administration |
| Neusploit staging | H19 | File creation | Names alone have low specificity; correlate exact hashes |
| Mail-channel hunting | H20 | Endpoint network events | Generic script-host hypothesis; mail automation can match |
| Native discovery | H21 | Process creation | Local threshold: three distinct tools in ten minutes |
| Router-campaign infrastructure | H22 | Endpoint network events | 182 historical IPs; no assumption of current hostile control |
| Sample matching | H23 | File/process/image-load hashes, depending on platform | 14 SHA-256 and two SHA-1 values; legitimate OneDrive excluded |
| Webhook communication | H24 | Network hostname visibility or Sysmon DNS | DNS resolution and successful connection are different observations |

## Query Organization

H01–H24 use the same identifiers in KQL and Splunk. Each entry includes its telemetry, origin and interpretation limits. Sensor differences are explicit: a Sysmon file-creation event does not represent every modification, and DNS telemetry does not prove data transfer.

The retained Microsoft queries also cover cloud sign-ins and Exchange/mailbox investigation. They state required account input or custom Exchange ingestion. The four retained Splunk searches require the publisher's macros and Endpoint CIM mapping; local searches operate on extracted Sysmon fields.

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| APT28_HEADLACE_SHORTCUT | Published | Shortcut dropper content | File triage; inspect target and provenance |
| APT28_HEADLACE_CREDENTIALDIALOG | Published | Credential-prompt script strings | Recovered script content required |
| APT28_HEADLACE_CORE | Published | HEADLACE batch content | Does not establish execution |
| APT28_MASEPIE | Published | Python implant strings | Source-level content; packed forms may not match |
| APT28_GooseEgg_Artifact_Bundle_Triage | Local heuristic | co-located GooseEgg artifact strings; not a binary-family signature | Extracted content below 10 MB; validate matched strings |
| APT28_Outlook_Macro_Configuration_Triage | Local heuristic | scripts staging Outlook macros and changing startup/security settings | Extracted content below 10 MB; validate matched strings |
| APT28_Browser_Secret_Script_Triage | Local heuristic | STEELHOOK-related script heuristic; also matches credential auditing tools | Extracted content below 10 MB; validate matched strings |
| APT28_Headless_Webhook_Script_Triage | Local heuristic | HEADLACE/HOOKEDGE-related service-abuse heuristic; approved automation can match | Extracted content below 10 MB; validate matched strings |
| APT28_Neusploit_Staging_Strings_Triage | Local heuristic | co-located Neusploit staging names; no exploit or family identification | Extracted content below 10 MB; validate matched strings |
| APT28_Retained_SHA256_Exact_Match | Local exact hash | 14 retained SHA-256 values | Whole-file match below 100 MB; requires the YARA hash module |

## September 2026 Review

Reviewed **2026-09-15**. Empty and inapplicable detection sections have been removed. Locally authored content translates documented procedures into testable defensive hypotheses; it is not presented as vendor-published detection logic. Bibliographic provenance is centralized in the actor's reference file.

See [validation](../../../VALIDATION.md) for structural checks, harmless YARA fixtures and the limits of static query review.
