# SafePay — Detections

**Presentation reviewed:** 2026-09-24.

This directory contains copyable hunting content tied to SafePay intrusion evidence, the Windows locker and the incident-scoped QDoor chain.

> **Review / tuning:** SafePay abuses legitimate remote access, archiving, transfer and Windows components. Tune approved ScreenConnect tenants, administration hosts, backup workflows, red-team activity and service accounts before production use.

## Content

- [KQL](KQL.md) — 31 copyable queries.
- [Splunk](Splunk.md) — 31 paired searches.
- [YARA](SafePay-Hunting.yar) — 2 public GTIG rules and 8 local exact-artifact or contextual rules.
- [ATT&CK evidence mapping](../technical/mitre-attack.md).

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| 1. Credential Access | 3 | 3 | Authentication fields, planned password changes and testing activity require local normalization |
| 2. Active Directory and Network Discovery | 3 | 3 | Share and SMB activity must be baselined for administrators and servers |
| 3. Persistence and Remote Administration | 3 | 3 | Compare signer, service path and RMM tenant with approved inventory |
| 4. Tunneling and C2 | 3 | 3 | Historical IPs and shared Imgur infrastructure need time and process context |
| 5. Defense Evasion and Impairment | 5 | 5 | Maintenance and security administration can overlap individual behaviors |
| 6. Collection and Exfiltration | 2 | 2 | Dual-use archive and transfer tools require destination and volume evidence |
| 7. Recovery Inhibition | 2 | 2 | Verify command outcome and distinguish approved recovery work |
| 8. Deployment and Impact | 2 | 2 | Exact samples and mass file events provide different coverage |
| 9. Multi-Stage Correlation | 1 | 1 | Confirm true ordering and account/process continuity |
| 10. Campaign Artifact Hunts | 7 | 7 | Workstation names, temporary files, QDoor values and Sygnia artifacts are case-scoped |

## Query Organization

KQL and Splunk use paired identifiers SP01–SP31 and the same ten investigation families. Each entry states its origin, required telemetry and tuning boundary before the copyable query. Bibliographic URLs remain in [References](../References.md).

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| G_Ransom_SAFEPAY_1 | Public GTIG | SafePay import-hash and code-byte signature | Preserve GTIG authorship; test performance and sample coverage locally |
| G_Ransom_SAFEPAY_2 | Public GTIG | Decode, AES-check, encryption and encoded-string byte patterns | Vendor rule can miss revised builds and may match related compiler output |
| SAFEPAY_Published_Locker_SHA256 | Repository-authored | Two role-resolved SafePay Windows payload hashes | Exact-artifact coverage only |
| SAFEPAY_Published_Associated_SHA256 | Repository-authored | Fifteen additional vendor-published SafePay-associated hashes | Component role is not public; use as triage evidence |
| SAFEPAY_QDoor_Incident_SHA256 | Repository-authored | Three QDoor chain hashes | One incident; not a universal SafePay component |
| SAFEPAY_Revised_Config_Artifact_Triage | Repository-authored | Mutex, locker arguments, note and extension conjunction | Inspect matched strings and PE provenance |
| SAFEPAY_QDoor_Loader_Artifact_Triage | Repository-authored | Export, hollowing target, filename and protocol marker | Related loaders or research corpora can match |
| SAFEPAY_Ransom_Note_Triage | Repository-authored | Brand/contact/service text in small artifacts | Notes and intelligence documents can match |
| SAFEPAY_Command_Artifact_Triage | Repository-authored | Locker switches plus recovery-inhibition commands | Script/log hunt; a match does not prove execution |
| SAFEPAY_Sygnia_Incident_Artifact_Triage | Repository-authored | Sygnia script, tool and attacker-tenant artifact conjunctions | One incident; require host/timeline corroboration |

## Review Notes

The query set distinguishes exact SafePay payloads, incident-scoped QDoor artifacts and broad dual-use behavior. The C2 search excludes the shared Imgur CDN IP, which is handled separately with its exact path. Locker and QDoor hashes appear together only in a triage query that preserves their roles in the provenance register.

Public GTIG rules are copied with their original rule names and authorship. The eight additional rules were written for this repository and are not presented as vendor detections. YARA scans bytes; it cannot establish that a command executed, a file was encrypted or data left the network.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
|---|---|
| FortiGate policy and MFA evaluation | Retain local/group policy match, source IP, device name, account type and MFA result. NCC's access path depended on policy configuration, not a demonstrated CVE. |
| Defender operational events | Collect 5001 and 5007 with process ancestry to distinguish UI/PowerShell impairment from approved changes. |
| QDoor memory and network evidence | Preserve `regsvr32` module load, `WerFault.exe` memory image, TCP/443 payload prefix and hard-coded destination. Endpoint filenames alone are insufficient. |
| File-server and backup impact | Centralize SMB access, service stops, shadow-copy changes and high-rate extension creation; compromised endpoints may not retain all events. |
| Large outbound transfer | Join archive creation with proxy/firewall byte counts and newly installed FileZilla/Rclone. Tool execution alone does not prove exfiltration. |
| OneDrive/SharePoint staging | Preserve tenant name, account, browser/sync-client lineage, multipart archive names and outbound bytes. Do not alert on Microsoft hosting ranges alone. |
| Veeam and virtualization access | Correlate service-account discovery, console launches and remote logons with an unusual operator identity and subsequent archive or locker activity. |
| Ransom-note and file footer collection | Preserve an original encrypted file, note and locker sample. Footer length and algorithm selector can separate build states and guide recovery assessment. |

See [validation](../../../VALIDATION.md) for structural checks, compiled YARA results and query-execution limits.
