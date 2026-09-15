# Qilin — MITRE ATT&CK Evidence Mapping

**Reviewed 2026-09-11.** Each row is a dossier mapping of a documented behavior or sample capability. It is not a claim that every affiliate performs it. High Confidence in a reported observation does not automatically establish actor identity. Software analysis describes capability; incident reports describe observed use.

Names and tactics use the official Enterprise ATT&CK STIX snapshot retrieved 2026-09-10, SHA256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`. MITRE data. The catalog changes; the compact [validation profile](../../../scripts/attack-profile.json) preserves the identifiers used here.

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1190 — Exploit Public-Facing Application | Initial Access | Italian CSIRT reporting links Qilin campaigns to exploitation of exposed Ivanti/Fortinet services; the bulletin does not provide a complete exploit trace for each victim | Moderate Confidence in actor-specific mapping |
| T1133 — External Remote Services | Persistence, Initial Access | VPN entry in July 2024 case | High Confidence in source observation / mapping |
| T1078 — Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Stolen VPN or RMM administrator credentials | High Confidence in source observation / mapping |
| T1566.002 — Spearphishing Link | Initial Access | ScreenConnect alert spear-phishing link targeting MSP administrator | High Confidence in source observation / mapping |
| T1557 — Adversary-in-the-Middle | Credential Access, Collection | AiTM reverse-proxy capture of credentials and MFA input | High Confidence in source observation / mapping |
| T1199 — Trusted Relationship | Initial Access | MSP administrative access used against downstream customers | High Confidence in source observation / mapping |
| T1059.001 — PowerShell | Execution | PowerShell scripts for credential harvest and vCenter deployment | High Confidence in source observation / mapping |
| T1059.003 — Windows Command Shell | Execution | Batch launchers and ransomware commands | High Confidence in source observation / mapping |
| T1059.004 — Unix Shell | Execution | Linux/ESXi shell execution | High Confidence in source observation / mapping |
| T1569.002 — Service Execution | Execution | PsExec remote service execution | High Confidence in source observation / mapping |
| T1047 — Windows Management Instrumentation | Execution | WMI requests in APAC intrusion | High Confidence in source observation / mapping |
| T1555.003 — Credentials from Web Browsers | Credential Access | Chrome credential databases collected using GPO logon script | High Confidence in source observation / mapping |
| T1003.001 — LSASS Memory | Credential Access | Mimikatz/WDigest credential-access script capability; full toolkit execution not independently verified | Moderate Confidence |
| T1484.001 — Group Policy Modification | Defense Impairment, Privilege Escalation | Default Domain Policy logon script altered for credential collection and later deployment | High Confidence in source observation / mapping |
| T1037.001 — Logon Script (Windows) | Persistence, Privilege Escalation | Malicious logon.bat invoked by logon policy | High Confidence in source observation / mapping |
| T1053.005 — Scheduled Task | Execution, Persistence, Privilege Escalation | TVInstallRestore ONLOGON task in Talos sample | High Confidence in source observation / mapping |
| T1547.001 — Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | HKLM Run persistence and restoration path | High Confidence in source observation / mapping |
| T1136.001 — Local Account | Persistence | Supportt administrative backdoor account in reported campaign | Moderate Confidence |
| T1087.002 — Domain Account | Discovery | Domain user/group queries before propagation | High Confidence in source observation / mapping |
| T1069.002 — Domain Groups | Discovery | Domain administrator group collection | High Confidence in source observation / mapping |
| T1018 — Remote System Discovery | Discovery | AD computer and ESXi host enumeration; Group-IB also documents payload-driven computer discovery | High Confidence in source observation / mapping |
| T1135 — Network Share Discovery | Discovery | Network-share discovery | High Confidence in source observation / mapping |
| T1046 — Network Service Discovery | Discovery | Internal scanning and repeated SMB/RDP connections | High Confidence in source observation / mapping |
| T1082 — System Information Discovery | Discovery | OS, CPU and memory discovery in reported tooling chain | Moderate Confidence |
| T1057 — Process Discovery | Discovery | Process discovery for termination | High Confidence in source observation / mapping |
| T1083 — File and Directory Discovery | Discovery | Configurable file/directory traversal | High Confidence in source observation / mapping |
| T1021.001 — Remote Desktop Protocol | Lateral Movement | RDP lateral movement after VPN access | High Confidence in source observation / mapping |
| T1021.002 — SMB/Windows Admin Shares | Lateral Movement | SMB/admin shares and PsExec distribution | High Confidence in source observation / mapping |
| T1021.004 — SSH | Lateral Movement | SSH enabled and used on hypervisors | High Confidence in source observation / mapping |
| T1021.006 — Windows Remote Management | Lateral Movement | WinRM remote commands in MSP incident | High Confidence in source observation / mapping |
| T1219.002 — Remote Desktop Software | Command And Control | ScreenConnect, AnyDesk and other remote desktop software abuse | High Confidence in source observation / mapping |
| T1090 — Proxy | Command And Control | SystemBC proxy capability in observed intrusion tooling | Moderate Confidence |
| T1071.001 — Web Protocols | Command And Control | HTTP(S) C2 and MeshAgent WebSocket channel | High Confidence in source observation / mapping |
| T1105 — Ingress Tool Transfer | Command And Control | Secondary tool and encryptor transfers | High Confidence in source observation / mapping |
| T1685 — Disable or Modify Tools | Defense Impairment | dark-kill driver/process impairment and antivirus-service termination | High Confidence in source observation / mapping |
| T1685.005 — Clear Windows Event Logs | Defense Impairment | Windows event-log clearing | High Confidence in source observation / mapping |
| T1686 — Disable or Modify System Firewall | Defense Impairment | Firewall changes enabling remote access | High Confidence in source observation / mapping |
| T1688 — Safe Mode Boot | Defense Impairment | Safe Mode boot in original Go capability and MSP intrusion | Moderate Confidence |
| T1036 — Masquerading | Stealth | IPScanner.ps1 name conceals browser credential function; renamed tools | High Confidence in source observation / mapping |
| T1055 — Process Injection | Stealth, Privilege Escalation | NETXLOADER-mediated injection in documented chain | High Confidence in source observation / mapping |
| T1689 — Downgrade Attack | Defense Impairment | Downgrade of /User/execInstalledOnly on ESXi in deployment script | High Confidence in source observation / mapping |
| T1005 — Data from Local System | Collection | Collection of local business data and browser databases | High Confidence in source observation / mapping |
| T1039 — Data from Network Shared Drive | Collection | File collection from managed customer network locations | High Confidence in source observation / mapping |
| T1560.001 — Archive via Utility | Collection | WinRAR preparation of stolen data | High Confidence in source observation / mapping |
| T1074.002 — Remote Data Staging | Collection | Per-endpoint LD/temp.log files staged back to SYSVOL | High Confidence in source observation / mapping |
| T1567.002 — Exfiltration to Cloud Storage | Exfiltration | Cyberduck to Backblaze, MEGA and easyupload transfers in separate incidents | High Confidence in source observation / mapping |
| T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | FTP exfiltration to 194.165.16.13 in probable Qilin-related May 2024 intrusion | Moderate Confidence |
| T1486 — Data Encrypted for Impact | Impact | Configurable Go/Rust Windows and Linux/ESXi encryption | High Confidence in source observation / mapping |
| T1490 — Inhibit System Recovery | Impact | Shadow-copy/snapshot removal and backup-job destruction | High Confidence in source observation / mapping |
| T1489 — Service Stop | Impact | Service and VM shutdown before disk encryption | High Confidence in source observation / mapping |
| T1531 — Account Access Removal | Impact | ESXi root password changes impair legitimate access | High Confidence in source observation / mapping |

## Version Changes and Excluded Mappings

Older sources use identifiers that the current catalog has revoked. The changes below are nomenclature maintenance, not evidence of new actor behavior.

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1562.001 | T1685 | Disable or Modify Tools moved under defense impairment |
| T1562.004 | T1686 | System-firewall impairment moved |
| T1070.001 | T1685.005 | Windows event-log clearing moved |
| T1574.002 | T1574.001 | DLL side-loading merged into DLL |

No `T1604` mapping is used: it does not resolve to an Enterprise technique in this snapshot. SharePoint collection, cloud-account-to-cloud-account transfer, automatic exfiltration and private-key theft are not inferred merely from a generic tool name. Safe Mode, local storage discovery and group modification are mapped to their actual semantics. Unsupported original associations remain research questions rather than active mappings.

## Defensive Application

Use [detections](../detections/Detections.md) for sensor requirements and false positives. These queries cover only some procedures in the table; an ATT&CK row does not imply an implemented or tested alert. For exploitation confidence and prerequisites see [vulnerabilities](vulnerabilities.md).
