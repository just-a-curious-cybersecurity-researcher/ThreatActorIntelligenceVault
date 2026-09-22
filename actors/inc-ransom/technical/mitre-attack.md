# INC Ransom — MITRE ATT&CK

**Presentation reviewed:** 2026-09-22.

Technique names and tactics follow the repository snapshot retrieved 2026-09-10. Procedures retain their source scope; this is not a claim that every technique occurred in one incident.

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1078 — Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Obtained accounts used for remote entry and subsequent access; official advisory and Huntress. | High in reported scope |
| T1133 — External Remote Services | persistence, initial-access | Remote-access services used for foothold; Huntress incident reporting. | High in reported scope |
| T1190 — Exploit Public-Facing Application | initial-access | Reported edge exploitation; qualified associations in vulnerabilities.md. | Moderate |
| T1566 — Phishing | initial-access | Phishing association in collected actor reporting; broad technique only. | Moderate |
| T1059.001 — PowerShell | execution | Operator PowerShell and credential scripts; not assumed payload internals. | High in reported scope |
| T1059.003 — Windows Command Shell | execution | Command shells used in hands-on activity. | High in reported scope |
| T1047 — Windows Management Instrumentation | execution | WMIC-related remote execution in early Huntress case. | High in reported scope |
| T1569.002 — Service Execution | execution | PsExec/service execution during deployment. | High in reported scope |
| T1136.001 — Local Account | persistence | Administrative local-account creation in the regional advisory. | High in reported scope |
| T1003.001 — LSASS Memory | credential-access | LSASS-oriented tools in collected research; distinguish tooling from confirmed successful dumping. | Moderate |
| T1003.003 — NTDS | credential-access | Directory-database acquisition tooling in the supplied research. | Moderate |
| T1087.002 — Domain Account | discovery | Domain-account discovery with administrative tools. | High in reported scope |
| T1069.002 — Domain Groups | discovery | Domain-group enumeration. | High in reported scope |
| T1046 — Network Service Discovery | discovery | Network scanners used in incident activity. | High in reported scope |
| T1135 — Network Share Discovery | discovery | Share discovery before collection and encryption. | High in reported scope |
| T1018 — Remote System Discovery | discovery | Host discovery with scanners and domain tools. | High in reported scope |
| T1021.001 — Remote Desktop Protocol | lateral-movement | RDP access with obtained credentials. | High in reported scope |
| T1021.002 — SMB/Windows Admin Shares | lateral-movement | Administrative shares in staging and deployment. | High in reported scope |
| T1219.002 — Remote Desktop Software | command-and-control | AnyDesk/ScreenConnect and other remote desktop software. | High in reported scope |
| T1560.001 — Archive via Utility | collection | 7-Zip/WinRAR archive staging; Rclone itself is not the archiver. | High in reported scope |
| T1567.002 — Exfiltration to Cloud Storage | exfiltration | MEGASync/Rclone/Restic transfer to remote cloud storage. | High in reported scope |
| T1105 — Ingress Tool Transfer | command-and-control | Transfer of intrusion tools into the environment. | High in reported scope |
| T1486 — Data Encrypted for Impact | impact | INC file encryption, scoped to published branches. | High in reported scope |
| T1491.001 — Internal Defacement | impact | Wallpaper and other local extortion presentation. | High in reported scope |
| T1490 — Inhibit System Recovery | impact | Sample-level shadow-copy manipulation and ESXi snapshot-related capability. | High in reported scope |
| T1685 — Disable or Modify Tools | defense-impairment | Separate impairment tooling and Defender changes. | High in reported scope |
| T1053.005 — Scheduled Task | execution, persistence, privilege-escalation | Scheduled execution, including temporary-task activity. | High in reported scope |
| T1036 — Masquerading | stealth | Renamed Restic and other incident binaries; name does not establish functionality. | High in reported scope |
| T1543.003 — Windows Service | persistence, privilege-escalation | Service-based payload execution across the classic Safe Mode path. | High in reported scope |
| T1083 — File and Directory Discovery | discovery | Payload traversal and operator file discovery. | High in reported scope |
| T1489 — Service Stop | impact | Service/application interruption around deployment; qualify by examined routine. | High in reported scope |

## Version Changes and Excluded Mappings

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1562.001 | T1685 | Current repository snapshot separates Disable or Modify Tools under defense-impairment |
| T1219 (broad source mapping) | T1219.002 | Remote Desktop Software is the supported specific procedure |

Generic financial motivation does not automatically establish Financial Theft. Cloud uploads use the supported exfiltration procedure; archive creation is mapped to the actual archive tool. Unverified exploit and credential leads are not expanded into unsupported subtechniques.

## Defensive Application

Use the lifecycle to connect identity, process, network and storage evidence. API capabilities need suitable telemetry; process creation alone cannot show all payload internals. The [detection register](../detections/Detections.md) states collection and tuning requirements.
