# Qilin — MITRE ATT&CK Evidence Mapping

**Reviewed 2026-09-11.** Each row is a dossier mapping of a documented behavior or sample capability. It is not a claim that every affiliate performs it. High Confidence in a reported observation does not automatically establish actor identity. Software analysis describes capability; incident reports describe observed use.

Names and tactics use the official Enterprise ATT&CK STIX snapshot retrieved 2026-09-10, SHA256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`. [MITRE data](https://github.com/mitre-attack/attack-stix-data). The catalog changes; the compact [validation profile](../../../scripts/attack-profile.json) preserves the identifiers used here.

| ID / technique | ATT&CK tactics | Evidence and scope | Source | Assessment confidence |
|---|---|---|---|---|
| [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Initial Access | Italian CSIRT reporting links Qilin campaigns to exploitation of exposed Ivanti/Fortinet services; the bulletin does not provide a complete exploit trace for each victim | [Q30](../References.md#q30) | Moderate Confidence in actor-specific mapping |
| [T1133 — External Remote Services](https://attack.mitre.org/techniques/T1133) | Persistence, Initial Access | VPN entry in July 2024 case | [Q11](../References.md#q11) | High Confidence in source observation / mapping |
| [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078) | Stealth, Persistence, Privilege Escalation, Initial Access | Stolen VPN or RMM administrator credentials | [Q11](../References.md#q11), [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) | Initial Access | ScreenConnect alert spear-phishing link targeting MSP administrator | [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1557 — Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) | Credential Access, Collection | AiTM reverse-proxy capture of credentials and MFA input | [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1199 — Trusted Relationship](https://attack.mitre.org/techniques/T1199) | Initial Access | MSP administrative access used against downstream customers | [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001) | Execution | PowerShell scripts for credential harvest and vCenter deployment | [Q11](../References.md#q11), [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) | Execution | Batch launchers and ransomware commands | [Q11](../References.md#q11), [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004) | Execution | Linux/ESXi shell execution | [Q15](../References.md#q15), [Q23](../References.md#q23) | High Confidence in source observation / mapping |
| [T1569.002 — Service Execution](https://attack.mitre.org/techniques/T1569/002) | Execution | PsExec remote service execution | [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) | Execution | WMI requests in APAC intrusion | [Q09](../References.md#q09) | High Confidence in source observation / mapping |
| [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003) | Credential Access | Chrome credential databases collected using GPO logon script | [Q11](../References.md#q11) | High Confidence in source observation / mapping |
| [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001) | Credential Access | Mimikatz/WDigest credential-access script capability; full toolkit execution not independently verified | [Q15](../References.md#q15) | Moderate Confidence |
| [T1484.001 — Group Policy Modification](https://attack.mitre.org/techniques/T1484/001) | Defense Impairment, Privilege Escalation | Default Domain Policy logon script altered for credential collection and later deployment | [Q11](../References.md#q11) | High Confidence in source observation / mapping |
| [T1037.001 — Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001) | Persistence, Privilege Escalation | Malicious logon.bat invoked by logon policy | [Q11](../References.md#q11) | High Confidence in source observation / mapping |
| [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005) | Execution, Persistence, Privilege Escalation | TVInstallRestore ONLOGON task in Talos sample | [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001) | Persistence, Privilege Escalation | HKLM Run persistence and restoration path | [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1136.001 — Local Account](https://attack.mitre.org/techniques/T1136/001) | Persistence | Supportt administrative backdoor account in reported campaign | [Q18](../References.md#q18) | Moderate Confidence |
| [T1087.002 — Domain Account](https://attack.mitre.org/techniques/T1087/002) | Discovery | Domain user/group queries before propagation | [Q18](../References.md#q18) | High Confidence in source observation / mapping |
| [T1069.002 — Domain Groups](https://attack.mitre.org/techniques/T1069/002) | Discovery | Domain administrator group collection | [Q18](../References.md#q18) | High Confidence in source observation / mapping |
| [T1018 — Remote System Discovery](https://attack.mitre.org/techniques/T1018) | Discovery | AD computer and ESXi host enumeration; Group-IB also documents payload-driven computer discovery | [Q15](../References.md#q15), [Q18](../References.md#q18), [Q35](../References.md#q35) | High Confidence in source observation / mapping |
| [T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135) | Discovery | Network-share discovery | [Q09](../References.md#q09), [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046) | Discovery | Internal scanning and repeated SMB/RDP connections | [Q09](../References.md#q09) | High Confidence in source observation / mapping |
| [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082) | Discovery | OS, CPU and memory discovery in reported tooling chain | [Q18](../References.md#q18) | Moderate Confidence |
| [T1057 — Process Discovery](https://attack.mitre.org/techniques/T1057) | Discovery | Process discovery for termination | [Q13](../References.md#q13) | High Confidence in source observation / mapping |
| [T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083) | Discovery | Configurable file/directory traversal | [Q13](../References.md#q13), [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1021.001 — Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) | Lateral Movement | RDP lateral movement after VPN access | [Q09](../References.md#q09) | High Confidence in source observation / mapping |
| [T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) | Lateral Movement | SMB/admin shares and PsExec distribution | [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1021.004 — SSH](https://attack.mitre.org/techniques/T1021/004) | Lateral Movement | SSH enabled and used on hypervisors | [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1021.006 — Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) | Lateral Movement | WinRM remote commands in MSP incident | [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1219.002 — Remote Desktop Software](https://attack.mitre.org/techniques/T1219/002) | Command And Control | ScreenConnect, AnyDesk and other remote desktop software abuse | [Q15](../References.md#q15), [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1090 — Proxy](https://attack.mitre.org/techniques/T1090) | Command And Control | SystemBC proxy capability in observed intrusion tooling | [Q15](../References.md#q15), [Q18](../References.md#q18) | Moderate Confidence |
| [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001) | Command And Control | HTTP(S) C2 and MeshAgent WebSocket channel | [Q09](../References.md#q09), [Q23](../References.md#q23) | High Confidence in source observation / mapping |
| [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) | Command And Control | Secondary tool and encryptor transfers | [Q15](../References.md#q15), [Q23](../References.md#q23) | High Confidence in source observation / mapping |
| [T1685 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1685) | Defense Impairment | dark-kill driver/process impairment and antivirus-service termination | [Q15](../References.md#q15), [Q23](../References.md#q23) | High Confidence in source observation / mapping |
| [T1685.005 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005) | Defense Impairment | Windows event-log clearing | [Q11](../References.md#q11), [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1686 — Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1686) | Defense Impairment | Firewall changes enabling remote access | [Q18](../References.md#q18) | High Confidence in source observation / mapping |
| [T1688 — Safe Mode Boot](https://attack.mitre.org/techniques/T1688) | Defense Impairment | Safe Mode boot in original Go capability and MSP intrusion | [Q12](../References.md#q12), [Q22](../References.md#q22) | Moderate Confidence |
| [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036) | Stealth | IPScanner.ps1 name conceals browser credential function; renamed tools | [Q11](../References.md#q11), [Q23](../References.md#q23) | High Confidence in source observation / mapping |
| [T1055 — Process Injection](https://attack.mitre.org/techniques/T1055) | Stealth, Privilege Escalation | NETXLOADER-mediated injection in documented chain | [Q18](../References.md#q18) | High Confidence in source observation / mapping |
| [T1689 — Downgrade Attack](https://attack.mitre.org/techniques/T1689) | Defense Impairment | Downgrade of /User/execInstalledOnly on ESXi in deployment script | [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1005 — Data from Local System](https://attack.mitre.org/techniques/T1005) | Collection | Collection of local business data and browser databases | [Q11](../References.md#q11), [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1039 — Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039) | Collection | File collection from managed customer network locations | [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1560.001 — Archive via Utility](https://attack.mitre.org/techniques/T1560/001) | Collection | WinRAR preparation of stolen data | [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1074.002 — Remote Data Staging](https://attack.mitre.org/techniques/T1074/002) | Collection | Per-endpoint LD/temp.log files staged back to SYSVOL | [Q11](../References.md#q11) | High Confidence in source observation / mapping |
| [T1567.002 — Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) | Exfiltration | Cyberduck to Backblaze, MEGA and easyupload transfers in separate incidents | [Q15](../References.md#q15), [Q09](../References.md#q09), [Q22](../References.md#q22) | High Confidence in source observation / mapping |
| [T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003) | Exfiltration | FTP exfiltration to 194.165.16.13 in probable Qilin-related May 2024 intrusion | [Q09](../References.md#q09) | Moderate Confidence |
| [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) | Impact | Configurable Go/Rust Windows and Linux/ESXi encryption | [Q13](../References.md#q13), [Q15](../References.md#q15), [Q12](../References.md#q12), [Q23](../References.md#q23) | High Confidence in source observation / mapping |
| [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490) | Impact | Shadow-copy/snapshot removal and backup-job destruction | [Q15](../References.md#q15), [Q22](../References.md#q22), [Q35](../References.md#q35) | High Confidence in source observation / mapping |
| [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489) | Impact | Service and VM shutdown before disk encryption | [Q15](../References.md#q15) | High Confidence in source observation / mapping |
| [T1531 — Account Access Removal](https://attack.mitre.org/techniques/T1531) | Impact | ESXi root password changes impair legitimate access | [Q09](../References.md#q09), [Q15](../References.md#q15) | High Confidence in source observation / mapping |

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
