# Akira — Detections

**Presentation reviewed:** 2026-09-15.

This directory contains defensive detection and threat-hunting content based on Akira-associated tradecraft documented in this repository.

> **Review / tuning:** these queries and rules are starting points and must be reviewed and tuned for each environment before production use. Akira frequently abuses legitimate administration, RMM, tunneling, backup, compression and security tools, so expected software, service accounts, jump hosts, red-team activity and normal administrative workflows must be baselined to avoid false positives.

## Content

- [KQL](KQL.md) — 38 copyable queries.
- [Splunk](Splunk.md) — 31 copyable searches.
- [YARA](Akira-Hunting.yar) — 12 file and artifact triage rules.
- [ATT&CK evidence mapping](../technical/mitre-attack.md).

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| 1. Credential Access | 6 | 5 | Sensor requirements, scope and false positives are stated per query |
| 2. Active Directory and Network Discovery | 5 | 3 | Sensor requirements, scope and false positives are stated per query |
| 3. Persistence and Remote Administration | 3 | 2 | Sensor requirements, scope and false positives are stated per query |
| 4. Tunneling and C2 | 3 | 3 | Sensor requirements, scope and false positives are stated per query |
| 5. Defense Evasion and Impairment | 5 | 5 | Sensor requirements, scope and false positives are stated per query |
| 6. Collection and Exfiltration | 3 | 3 | Sensor requirements, scope and false positives are stated per query |
| 7. Recovery Inhibition | 2 | 2 | Sensor requirements, scope and false positives are stated per query |
| 8. Deployment and Impact | 4 | 3 | Sensor requirements, scope and false positives are stated per query |
| 9. Multi-Stage Correlation | 1 |  | Sensor requirements, scope and false positives are stated per query |
| 10. Campaign Artifact Hunts | 6 | 5 | Sensor requirements, scope and false positives are stated per query |

## Query Organization

Both query files use the same investigation families, numbered entries and field order: origin, telemetry, review / tuning, then the copyable query. Only populated families appear. Query counts and coverage depend on the actor and sensor; shared family names do not imply identical detection logic. Bibliographic sources remain in the actor's reference file.

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| AKIRA_Ransomware_Artifact_Cooccurrence_Triage | Repository-authored | Triage for multiple Akira-specific ransomware/leak-site artifacts | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| CTI_Credential_Dumping_Artifact_Triage | Repository-authored | Credential dumping / credential-store access strings observed in ransomware tradecraft | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| CTI_Mimikatz_Like_PE_Triage | Repository-authored | Triage rule for PE files containing multiple Mimikatz-specific strings | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| CTI_AD_Discovery_Script_Artifact_Triage | Repository-authored | AD/network discovery strings associated with Akira-reported tooling | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| CTI_RMM_References_Triage | Repository-authored | Triage for files/scripts containing references to multiple RMM products seen in ransomware intrusions | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| CTI_Tunneling_C2_Artifact_Triage | Repository-authored | Tunneling/C2 utility references useful for artifact triage | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| CTI_Defense_Impairment_Command_Artifact | Repository-authored | Scripts/artifacts containing defense impairment commands | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| CTI_Exfiltration_Artifact_Triage | Repository-authored | Archive/exfiltration utility references observed in Akira-associated tradecraft | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| CTI_Recovery_Inhibition_Artifact_Triage | Repository-authored | Shadow-copy and recovery-inhibition commands in scripts/artifacts | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| CTI_PsExec_Ransomware_Deployment_Artifact_Triage | Repository-authored | PsExec/PSEXESVC references combined with ransomware-impact indicators | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| AKIRA_Multi_Family_Script_Triage | Repository-authored | Higher-context script/config triage based on multiple Akira-associated behavior families | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |
| AKIRA_SafeBoot_S3_Script_Artifact_Triage | Repository-authored | Text artifact containing SafeBoot service registration and S3 transfer clues | Inspect matching strings, file context and rule conditions; a match does not prove execution or attribution |

## Review Notes

The original KQL, Splunk and YARA collection is retained and refined. MiniDump queries accept numeric PIDs, SSH forwarding respects option case, canonical and variant note names are covered, and the YARA multi-family rule now actually requires different string families. New hunts cover AnyDesk SafeBoot registration, S3 transfer, AD exports, WinRM, Veeam credentials, ESX Admins changes and driver/service co-occurrence.

Each query file has a coverage/tuning register and campaign-specific review notes. Generic existing tool-name hunts remain broad ransomware investigation leads. None is an Akira attribution rule. YARA scans bytes in artifacts; it cannot observe a reboot, execution sequence or exfiltration. Research documents containing the same strings can match it.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
| --- | --- |
| VPN spray then successful session | Normalize vendor username, source IP, authentication result and MFA state; count distinct targets before success. Exclude health checks and mistyped saved credentials. No universal VPN field schema is assumed. Context: Huntress. |
| Certificate request, PKINIT, U2U and WinRM | Correlate CA request/issuance audits, DC Kerberos logs and network RPC/WinRM telemetry. This supports a credential-abuse investigation; U2U alone is not UnPAC proof. Context: Darktrace. |
| Offline DC disk mounting | Hypervisor datastore/mount events plus NTDS and SYSTEM access; endpoint-only detection may miss the operation. Authorized recovery is an alternative. |
| ESXi/AHV disruption | Preserve remote hypervisor audit/syslog and backup logs; mass VM shutdown, disk writes and identity changes. A Windows query cannot claim hypervisor coverage. |

See [validation](../../../VALIDATION.md) for compiled YARA checks and the limits of static query review.

See [validation](../../../VALIDATION.md) for structural checks, YARA fixture results and query-execution limits.
