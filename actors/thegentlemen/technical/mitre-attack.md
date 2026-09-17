# The Gentlemen — MITRE ATT&CK Mapping

**Presentation reviewed:** 2026-09-17.

Uses the shared Enterprise ATT&CK profile. Additional techniques were checked against the same official STIX snapshot on 2026-09-17. Confidence refers to the scoped source observation, not attribution from one event.

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1190 — Exploit Public-Facing Application | initial access | Exposed-service exploitation associations; exact 2025 entry assessed | Moderate Confidence in scoped reporting |
| T1078 — Valid Accounts | stealth; persistence; privilege escalation; initial access | Compromised credentials for entry and remote access | Moderate Confidence in scoped reporting |
| T1059.001 — PowerShell | execution | PowerShell discovery, preferences and payload routines | High Confidence in scoped reporting |
| T1059.003 — Windows Command Shell | execution | Batch/cmd orchestration | High Confidence in scoped reporting |
| T1047 — Windows Management Instrumentation | execution | WMI utility use for recovery impairment | High Confidence in scoped reporting |
| T1053.005 — Scheduled Task | execution; persistence; privilege escalation | gentlemen_system and persistence tasks | High Confidence in scoped reporting |
| T1547.001 — Registry Run Keys / Startup Folder | persistence; privilege escalation | Registry autoruns | High Confidence in scoped reporting |
| T1068 — Exploitation for Privilege Escalation | privilege escalation | Supporting vulnerable-driver tool | Moderate Confidence in scoped reporting |
| T1685 — Disable or Modify Tools | defense impairment | Security-tool and Defender impairment | High Confidence in scoped reporting |
| T1112 — Modify Registry | defense impairment; persistence | Authentication and RDP registry changes | High Confidence in scoped reporting |
| T1685.005 — Clear Windows Event Logs | defense impairment | Windows event-log clearing | High Confidence in scoped reporting |
| T1070.004 — File Deletion | stealth | Artifact and executable deletion | High Confidence in scoped reporting |
| T1087.002 — Domain Account | discovery | Domain account enumeration | High Confidence in scoped reporting |
| T1069.002 — Domain Groups | discovery | Privileged domain-group enumeration | High Confidence in scoped reporting |
| T1046 — Network Service Discovery | discovery | Internal network scanning | High Confidence in scoped reporting |
| T1018 — Remote System Discovery | discovery | Host discovery | High Confidence in scoped reporting |
| T1135 — Network Share Discovery | discovery | Share discovery | High Confidence in scoped reporting |
| T1021.002 — SMB/Windows Admin Shares | lateral movement | PsExec and SMB distribution | High Confidence in scoped reporting |
| T1484.001 — Group Policy Modification | defense impairment; privilege escalation | GPO deployment | High Confidence in scoped reporting |
| T1219.002 — Remote Desktop Software | command and control | AnyDesk remote administration | High Confidence in scoped reporting |
| T1090 — Proxy | command and control | SystemBC companion proxy | Moderate Confidence in scoped reporting |
| T1005 — Data from Local System | collection | Local business data collection | Moderate Confidence in scoped reporting |
| T1039 — Data from Network Shared Drive | collection | Shared-resource collection | Moderate Confidence in scoped reporting |
| T1048 — Exfiltration Over Alternative Protocol | exfiltration | Likely encrypted WinSCP transfer | Moderate Confidence in scoped reporting |
| T1489 — Service Stop | impact | Backup/database service-stop attempts | High Confidence in scoped reporting |
| T1490 — Inhibit System Recovery | impact | Shadow-copy deletion attempts | High Confidence in scoped reporting |
| T1486 — Data Encrypted for Impact | impact | File encryption | High Confidence in scoped reporting |
| T1491.001 — Internal Defacement | impact | Wallpaper change | High Confidence in scoped reporting |
| T1053.003 — Cron | execution; persistence; privilege escalation | Reboot cron in ESXi branch | High Confidence in scoped reporting |
| T1037.004 — RC Scripts | persistence; privilege escalation | ESXi boot script | High Confidence in scoped reporting |
| T1543.003 — Windows Service | persistence; privilege escalation | Named remote services and configured payload ImagePath | High Confidence in sample reporting |
| T1021.006 — Windows Remote Management | lateral movement | Invoke-Command propagation route; distinct from WMI | High Confidence in sample reporting |
| T1222.001 — Windows Permissions | defense impairment | takeown/icacls file-access preparation | High Confidence in sample reporting |
| T1070.003 — Clear Command History | stealth | PSReadLine history deletion | High Confidence in sample reporting |
| T1485 — Data Destruction | impact | Optional free-space overwrite routine; success requires storage evidence | High Confidence in sample capability |

## Version Changes and Excluded Mappings

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1562.001 | T1685 | Security-tool impairment moved in the shared profile |
| T1070.001 | T1685.005 | Windows log clearing moved in the shared profile |

Tool inventory alone is not mapped as executed behavior. Password-gated launch is not proof of virtual-machine detection. WinSCP is mapped at the parent exfiltration technique because the exact transfer protocol must be established.

## Defensive Application

Use the [detection register](../detections/Detections.md) to select telemetry. Technique classification, successful execution and actor identity are different findings.
