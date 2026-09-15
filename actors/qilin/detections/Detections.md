# Qilin — Detections

**Presentation reviewed:** 2026-09-15.

This directory contains defensive hunting content based on Qilin-associated tradecraft. Queries and rules are starting points requiring local review, sensor configuration and tuning.

> **Review / tuning:** Approved RMM, backup, deployment and security-assessment activity can match. Confidence in detecting a behavior is separate from confidence in attributing it to Qilin.

## Content

- [KQL](KQL.md) — 19 copyable queries.
- [Splunk](Splunk.md) — 19 copyable searches.
- [YARA](Qilin-Hunting.yar) — 4 file and artifact triage rules.
- [ATT&CK evidence mapping](../technical/mitre-attack.md).

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| 1. Credential Access | 2 | 2 | Sensor requirements, scope and false positives are stated per query |
| 2. Active Directory and Network Discovery | 2 | 2 | Sensor requirements, scope and false positives are stated per query |
| 3. Persistence and Remote Administration | 1 | 1 | Sensor requirements, scope and false positives are stated per query |
| 4. Tunneling and C2 | 1 | 1 | Sensor requirements, scope and false positives are stated per query |
| 5. Defense Evasion and Impairment | 1 | 1 | Sensor requirements, scope and false positives are stated per query |
| 6. Collection and Exfiltration | 2 | 2 | Sensor requirements, scope and false positives are stated per query |
| 7. Recovery Inhibition | 1 | 1 | Sensor requirements, scope and false positives are stated per query |
| 8. Deployment and Impact | 3 | 3 | Sensor requirements, scope and false positives are stated per query |
| 9. Multi-Stage Correlation | 1 | 1 | Sensor requirements, scope and false positives are stated per query |
| 10. Campaign Artifact Hunts | 5 | 5 | Sensor requirements, scope and false positives are stated per query |

## Query Organization

Both query files use the same investigation families, numbered entries and field order: origin, telemetry, review / tuning, then the copyable query. Only populated families appear. Query counts and coverage depend on the actor and sensor; shared family names do not imply identical detection logic. Bibliographic sources remain in the actor's reference file.

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| QILIN_AGENDA_Redacted_Note_Triage | Repository-authored | Agenda/Qilin note content triage, not encryptor detection | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| QILIN_SYSVOL_Chrome_Script_Artifact_Triage | Repository-authored | Script/document combining reported logon script and staging artifacts | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| QILIN_Configuration_PE_Heuristic | Repository-authored | PE triage with Talos-reported configuration and restoration clues | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| QILIN_Restoration_Script_Artifact_Triage | Repository-authored | Text artifact combining restoration task and masqueraded TeamViewer launcher | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |

## Review Notes

The query documents use the common numbered investigation families. Existing Q01–Q14 hunts retain their identifiers and logic; Q15–Q19 add discovery, proxy staging, archive creation, PsExec and multi-stage investigation. Telemetry and false-positive limits accompany each hunt.

Coverage is indexed by stable query IDs in the per-platform tuning registers. Credential, discovery, RMM, proxy, impairment, collection, recovery and deployment hunts can be investigated independently or correlated. The campaign section retains GPO collection, restoration persistence, hypervisor changes and the unresolved WSL hypothesis.

YARA scans artifact bytes, not events. The rules recognize note content, scripts or PE configuration clues; they cannot prove execution, credential theft, exfiltration or an operator's identity. Research documents and restored notes can match. No broad tool-name signature is labelled definitive Qilin malware detection. The PE configuration rule is heuristic and requires binary validation before operational use.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
|---|---|
| AiTM/MSP entry | Correlate identity-provider and ScreenConnect sessions, phishing navigation and new instance IDs; endpoint logs alone cannot confirm MFA relay |
| VPN compromise | Normalize appliance account/source/result/MFA fields; investigate successful access and privilege changes |
| Domain policy change | DC Event 5136 with audited DN/attributes and SYSVOL history can corroborate policy changes; a file write is not policy application |
| Central share encryption | File-server auditing, SMB identity, write/rename rates and note creation; one host can damage many shares |
| Hypervisor impact | vCenter tasks, ESXi syslog/SSH, credentials, shutdowns and datastore writes; Windows commands provide partial visibility |
| Exfiltration completion | Archive/session history, SMTP/proxy metadata and provider audit; cloud connections alone do not prove theft |

Rules are UTF-8, source-linked and statically reviewed. The unchanged YARA rules were compiled and checked with harmless positive/negative fixtures on 2026-09-10; these tests do not estimate malware recall or field false-positive rates. KQL/SPL require execution against the deployment's schemas, representative benign periods and approved simulations before promotion to alerts. [Validation report](../../../VALIDATION.md).

Technical references: MDE process schema, MDE registry schema, Sysmon event definitions, PowerShell logging.

See [validation](../../../VALIDATION.md) for structural checks, YARA fixture results and query-execution limits.
