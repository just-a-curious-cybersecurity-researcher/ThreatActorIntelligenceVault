# Akira — MITRE ATT&CK Evidence Mapping

**Presentation reviewed:** 2026-09-15.

**Reviewed 2026-09-10.** Each row is a dossier mapping of a documented behavior or sample capability. It is not a claim that every affiliate performs it. High Confidence in a reported observation does not automatically establish actor identity. Software analysis describes capability; incident reports describe observed use.

Names and tactics use the official Enterprise ATT&CK STIX snapshot retrieved 2026-09-10, SHA256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`. MITRE data. The catalog changes; the compact [validation profile](../../../scripts/attack-profile.json) preserves the identifiers used here.

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1482 — Domain Trust Discovery | Discovery | nltest /DOMAIN_TRUSTS and domain-trust reconnaissance reported by the joint advisory | High Confidence in source observation / mapping |
| T1059.005 — Visual Basic | Execution | Visual Basic scripts used for command execution in the advisory update | High Confidence in source observation / mapping |
| T1133 — External Remote Services | Persistence, Initial Access | VPN access in multiple affiliate intrusions | High Confidence in source observation / mapping |
| T1078 — Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Compromised VPN/domain credentials; access does not itself prove exploitation | High Confidence in source observation / mapping |
| T1190 — Exploit Public-Facing Application | Initial Access | Reported edge-service exploitation; CVE confidence varies by incident | Moderate Confidence |
| T1110.003 — Password Spraying | Credential Access | Multi-user VPN password spray before successful August 2026 login | High Confidence in source observation / mapping |
| T1059.001 — PowerShell | Execution | PowerShell discovery, credential collection and impairment commands | High Confidence in source observation / mapping |
| T1059.003 — Windows Command Shell | Execution | Windows command-shell execution in observed intrusions and encryptors | High Confidence in source observation / mapping |
| T1059.004 — Unix Shell | Execution | Linux shell commands and ESXCLI execution | High Confidence in source observation / mapping |
| T1047 — Windows Management Instrumentation | Execution | Impacket wmiexec reported in intrusions | Moderate Confidence |
| T1569.002 — Service Execution | Execution | PsExec service execution during deployment | High Confidence in source observation / mapping |
| T1003.001 — LSASS Memory | Credential Access | LSASS dumping; distinguish script references from verified dump output | High Confidence in source observation / mapping |
| T1003.003 — NTDS | Credential Access | NTDS extraction, including offline DC virtual-disk access | High Confidence in source observation / mapping |
| T1555.003 — Credentials from Web Browsers | Credential Access | Browser-store extraction via esentutl | High Confidence in source observation / mapping |
| T1558.003 — Kerberoasting | Credential Access | Kerberoasting in reported tradecraft | Moderate Confidence |
| T1649 — Steal or Forge Authentication Certificates | Credential Access | Certificate request/PKINIT/U2U sequence supports certificate abuse assessment, not proof from U2U alone | Moderate Confidence |
| T1087.002 — Domain Account | Discovery | Domain-user discovery and AdUsers.txt export | High Confidence in source observation / mapping |
| T1018 — Remote System Discovery | Discovery | AD computer enumeration and AdComp.txt export | High Confidence in source observation / mapping |
| T1069.002 — Domain Groups | Discovery | Domain-group reconnaissance | High Confidence in source observation / mapping |
| T1016 — System Network Configuration Discovery | Discovery | Native network-configuration discovery | High Confidence in source observation / mapping |
| T1046 — Network Service Discovery | Discovery | Network/port scanners in intrusions | High Confidence in source observation / mapping |
| T1135 — Network Share Discovery | Discovery | Share discovery and sensitive-file enumeration | High Confidence in source observation / mapping |
| T1083 — File and Directory Discovery | Discovery | File/directory enumeration before encryption | High Confidence in source observation / mapping |
| T1057 — Process Discovery | Discovery | Process enumeration and targeted process termination preparation | High Confidence in source observation / mapping |
| T1680 — Local Storage Discovery | Discovery | Enumerating local volumes for encryption | High Confidence in source observation / mapping |
| T1021.001 — Remote Desktop Protocol | Lateral Movement | RDP lateral access on Windows systems; not native ESXi RDP | High Confidence in source observation / mapping |
| T1021.002 — SMB/Windows Admin Shares | Lateral Movement | SMB/admin-share use and payload staging | High Confidence in source observation / mapping |
| T1021.004 — SSH | Lateral Movement | SSH access to virtualization systems and transfer channels | High Confidence in source observation / mapping |
| T1021.006 — Windows Remote Management | Lateral Movement | Ruby WinRM client observed to /wsman | High Confidence in source observation / mapping |
| T1136.001 — Local Account | Persistence | Local administrative account creation | High Confidence in source observation / mapping |
| T1136.002 — Domain Account | Persistence | Additional domain accounts during intrusions | High Confidence in source observation / mapping |
| T1068 — Exploitation for Privilege Escalation | Privilege Escalation | Post-compromise ESX Admins authorization flaw; domain-joined ESXi precondition | High Confidence in source observation / mapping |
| T1219.002 — Remote Desktop Software | Command And Control | AnyDesk and other legitimate remote desktop software abused by affiliates | High Confidence in source observation / mapping |
| T1090 — Proxy | Command And Control | SystemBC/proxy and tunneling activity; not every instance uses Tor | High Confidence in source observation / mapping |
| T1572 — Protocol Tunneling | Command And Control | SSH/Ngrok tunnel channels in reported operations | Moderate Confidence |
| T1105 — Ingress Tool Transfer | Command And Control | Wget download of vmwaretools from external staging host | High Confidence in source observation / mapping |
| T1685 — Disable or Modify Tools | Defense Impairment | Security-tool removal or termination including POORTRY-related tooling | High Confidence in source observation / mapping |
| T1686 — Disable or Modify System Firewall | Defense Impairment | Firewall disabling/modification in reported intrusion commands | Moderate Confidence |
| T1688 — Safe Mode Boot | Defense Impairment | SafeBoot AnyDesk registration and networked Safe Mode reboot | High Confidence in source observation / mapping |
| T1574.001 — DLL | Stealth, Execution | DLL loading abuse reported in malware/tool staging; sample context required | Moderate Confidence |
| T1036 — Masquerading | Stealth | Ngrok named Sysmon.exe in original advisory | High Confidence in source observation / mapping |
| T1560.001 — Archive via Utility | Collection | RAR/7-Zip archive staging before data transfer | High Confidence in source observation / mapping |
| T1005 — Data from Local System | Collection | Local sensitive-file collection | High Confidence in source observation / mapping |
| T1039 — Data from Network Shared Drive | Collection | Network-share data collection | High Confidence in source observation / mapping |
| T1567.002 — Exfiltration to Cloud Storage | Exfiltration | s5cmd upload to S3; cloud storage is legitimate infrastructure | High Confidence in source observation / mapping |
| T1048 — Exfiltration Over Alternative Protocol | Exfiltration | SSH exfiltration assessment from host/volume evidence; separate from C2 | Moderate Confidence |
| T1486 — Data Encrypted for Impact | Impact | C++ and Rust payloads encrypt Windows/Linux/virtual disks | High Confidence in source observation / mapping |
| T1490 — Inhibit System Recovery | Impact | Shadow-copy deletion and recovery inhibition | High Confidence in source observation / mapping |
| T1489 — Service Stop | Impact | Services and Hyper-V VMs stopped before encryption | High Confidence in source observation / mapping |

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
