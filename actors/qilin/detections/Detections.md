# Qilin — Detections

This directory contains defensive hunting content based on Qilin-associated tradecraft. Queries and rules are starting points requiring local review, sensor configuration and tuning.

> **Environment-specific tuning is mandatory.** Approved RMM, backup, deployment and security-assessment activity can match. Confidence in detecting a behavior is separate from confidence in attributing it to Qilin.

## Content

- [KQL](KQL.md) — Microsoft Defender XDR / Advanced Hunting.
- [Splunk](Splunk.md) — Windows/Sysmon-oriented searches; adapt indexes and fields.
- [YARA](Qilin-Hunting.yar) — file, script and artifact triage.
- [ATT&CK evidence mapping](../technical/mitre-attack.md).

## September 2026 Review

The query documents use the same ten numbered investigation families as the Akira collection. Existing Q01–Q14 hunts retain their identifiers and logic; Q15–Q19 add discovery, proxy staging, archive creation, PsExec and multi-stage investigation. Sources and false-positive limits accompany each hunt.

Coverage is indexed by stable query IDs in the per-platform tuning registers. Credential, discovery, RMM, proxy, impairment, collection, recovery and deployment hunts can be investigated independently or correlated. The campaign section retains GPO collection, restoration persistence, hypervisor changes and the unresolved WSL hypothesis.

YARA scans artifact bytes, not events. The rules recognize note content, scripts or PE configuration clues; they cannot prove execution, credential theft, exfiltration or an operator's identity. Research documents and restored notes can match. No broad tool-name signature is labelled definitive Qilin malware detection. The PE configuration rule is heuristic and requires binary validation before operational use.


## Additional Telemetry Opportunities

| Opportunity | Evidence | Collection and decision |
|---|---|---|
| AiTM/MSP entry | [Q22](../References.md#q22) | Correlate identity-provider and ScreenConnect sessions, phishing navigation and new instance IDs; endpoint logs alone cannot confirm MFA relay |
| VPN compromise | [Q11](../References.md#q11), [Q15](../References.md#q15) | Normalize appliance account/source/result/MFA fields; investigate successful access and privilege changes |
| Domain policy change | [Q11](../References.md#q11) | DC Event 5136 with audited DN/attributes and SYSVOL history can corroborate policy changes; a file write is not policy application |
| Central share encryption | [Q15](../References.md#q15) | File-server auditing, SMB identity, write/rename rates and note creation; one host can damage many shares |
| Hypervisor impact | [Q15](../References.md#q15), [Q23](../References.md#q23) | vCenter tasks, ESXi syslog/SSH, credentials, shutdowns and datastore writes; Windows commands provide partial visibility |
| Exfiltration completion | [Q15](../References.md#q15), [Q22](../References.md#q22) | Archive/session history, SMTP/proxy metadata and provider audit; cloud connections alone do not prove theft |

Rules are UTF-8, source-linked and statically reviewed. The unchanged YARA rules were compiled and checked with harmless positive/negative fixtures on 2026-09-10; these tests do not estimate malware recall or field false-positive rates. KQL/SPL require execution against the deployment's schemas, representative benign periods and approved simulations before promotion to alerts. [Validation report](../../../VALIDATION.md).

Technical references: [MDE process schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table), [MDE registry schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table), [Sysmon event definitions](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows).
