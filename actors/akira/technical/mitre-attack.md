# Akira — MITRE ATT&CK Evidence Mapping

**Reviewed 2026-09-10.** Each row is a dossier mapping of a documented behavior or sample capability. It is not a claim that every affiliate performs it. High Confidence in a reported observation does not automatically establish actor identity. Software analysis describes capability; incident reports describe observed use.

Names and tactics use the official Enterprise ATT&CK STIX snapshot retrieved 2026-09-10, SHA256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`. [MITRE data](https://github.com/mitre-attack/attack-stix-data). The catalog changes; the compact [validation profile](../../../scripts/attack-profile.json) preserves the identifiers used here.

| ID / technique | ATT&CK tactics | Evidence and scope | Source | Assessment confidence |
|---|---|---|---|---|
| [T1482 — Domain Trust Discovery](https://attack.mitre.org/techniques/T1482) | Discovery | nltest /DOMAIN_TRUSTS and domain-trust reconnaissance reported by the joint advisory | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1059.005 — Visual Basic](https://attack.mitre.org/techniques/T1059/005) | Execution | Visual Basic scripts used for command execution in the advisory update | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1133 — External Remote Services](https://attack.mitre.org/techniques/T1133) | Persistence, Initial Access | VPN access in multiple affiliate intrusions | [A01](../References.md#a01), [A11](../References.md#a11) | High Confidence in source observation / mapping |
| [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078) | Stealth, Persistence, Privilege Escalation, Initial Access | Compromised VPN/domain credentials; access does not itself prove exploitation | [A01](../References.md#a01), [A11](../References.md#a11) | High Confidence in source observation / mapping |
| [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Initial Access | Reported edge-service exploitation; CVE confidence varies by incident | [A01](../References.md#a01), [A06](../References.md#a06) | Moderate Confidence |
| [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003) | Credential Access | Multi-user VPN password spray before successful August 2026 login | [A11](../References.md#a11) | High Confidence in source observation / mapping |
| [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001) | Execution | PowerShell discovery, credential collection and impairment commands | [A01](../References.md#a01), [A11](../References.md#a11) | High Confidence in source observation / mapping |
| [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) | Execution | Windows command-shell execution in observed intrusions and encryptors | [A01](../References.md#a01), [A21](../References.md#a21) | High Confidence in source observation / mapping |
| [T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004) | Execution | Linux shell commands and ESXCLI execution | [A21](../References.md#a21) | High Confidence in source observation / mapping |
| [T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) | Execution | Impacket wmiexec reported in intrusions | [A01](../References.md#a01) | Moderate Confidence |
| [T1569.002 — Service Execution](https://attack.mitre.org/techniques/T1569/002) | Execution | PsExec service execution during deployment | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001) | Credential Access | LSASS dumping; distinguish script references from verified dump output | [A01](../References.md#a01), [A19](../References.md#a19) | High Confidence in source observation / mapping |
| [T1003.003 — NTDS](https://attack.mitre.org/techniques/T1003/003) | Credential Access | NTDS extraction, including offline DC virtual-disk access | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003) | Credential Access | Browser-store extraction via esentutl | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003) | Credential Access | Kerberoasting in reported tradecraft | [A03](../References.md#a03) | Moderate Confidence |
| [T1649 — Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649) | Credential Access | Certificate request/PKINIT/U2U sequence supports certificate abuse assessment, not proof from U2U alone | [A10](../References.md#a10) | Moderate Confidence |
| [T1087.002 — Domain Account](https://attack.mitre.org/techniques/T1087/002) | Discovery | Domain-user discovery and AdUsers.txt export | [A11](../References.md#a11) | High Confidence in source observation / mapping |
| [T1018 — Remote System Discovery](https://attack.mitre.org/techniques/T1018) | Discovery | AD computer enumeration and AdComp.txt export | [A11](../References.md#a11) | High Confidence in source observation / mapping |
| [T1069.002 — Domain Groups](https://attack.mitre.org/techniques/T1069/002) | Discovery | Domain-group reconnaissance | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1016 — System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) | Discovery | Native network-configuration discovery | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046) | Discovery | Network/port scanners in intrusions | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1135 — Network Share Discovery](https://attack.mitre.org/techniques/T1135) | Discovery | Share discovery and sensitive-file enumeration | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083) | Discovery | File/directory enumeration before encryption | [A16](../References.md#a16) | High Confidence in source observation / mapping |
| [T1057 — Process Discovery](https://attack.mitre.org/techniques/T1057) | Discovery | Process enumeration and targeted process termination preparation | [A21](../References.md#a21) | High Confidence in source observation / mapping |
| [T1680 — Local Storage Discovery](https://attack.mitre.org/techniques/T1680) | Discovery | Enumerating local volumes for encryption | [A16](../References.md#a16) | High Confidence in source observation / mapping |
| [T1021.001 — Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) | Lateral Movement | RDP lateral access on Windows systems; not native ESXi RDP | [A01](../References.md#a01), [A10](../References.md#a10) | High Confidence in source observation / mapping |
| [T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) | Lateral Movement | SMB/admin-share use and payload staging | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1021.004 — SSH](https://attack.mitre.org/techniques/T1021/004) | Lateral Movement | SSH access to virtualization systems and transfer channels | [A10](../References.md#a10), [A21](../References.md#a21) | High Confidence in source observation / mapping |
| [T1021.006 — Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) | Lateral Movement | Ruby WinRM client observed to /wsman | [A10](../References.md#a10) | High Confidence in source observation / mapping |
| [T1136.001 — Local Account](https://attack.mitre.org/techniques/T1136/001) | Persistence | Local administrative account creation | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1136.002 — Domain Account](https://attack.mitre.org/techniques/T1136/002) | Persistence | Additional domain accounts during intrusions | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) | Privilege Escalation | Post-compromise ESX Admins authorization flaw; domain-joined ESXi precondition | [A04](../References.md#a04) | High Confidence in source observation / mapping |
| [T1219.002 — Remote Desktop Software](https://attack.mitre.org/techniques/T1219/002) | Command And Control | AnyDesk and other legitimate remote desktop software abused by affiliates | [A01](../References.md#a01), [A11](../References.md#a11) | High Confidence in source observation / mapping |
| [T1090 — Proxy](https://attack.mitre.org/techniques/T1090) | Command And Control | SystemBC/proxy and tunneling activity; not every instance uses Tor | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572) | Command And Control | SSH/Ngrok tunnel channels in reported operations | [A01](../References.md#a01) | Moderate Confidence |
| [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) | Command And Control | Wget download of vmwaretools from external staging host | [A10](../References.md#a10) | High Confidence in source observation / mapping |
| [T1685 — Disable or Modify Tools](https://attack.mitre.org/techniques/T1685) | Defense Impairment | Security-tool removal or termination including POORTRY-related tooling | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1686 — Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1686) | Defense Impairment | Firewall disabling/modification in reported intrusion commands | [A01](../References.md#a01) | Moderate Confidence |
| [T1688 — Safe Mode Boot](https://attack.mitre.org/techniques/T1688) | Defense Impairment | SafeBoot AnyDesk registration and networked Safe Mode reboot | [A11](../References.md#a11) | High Confidence in source observation / mapping |
| [T1574.001 — DLL](https://attack.mitre.org/techniques/T1574/001) | Stealth, Execution | DLL loading abuse reported in malware/tool staging; sample context required | [A01](../References.md#a01) | Moderate Confidence |
| [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036) | Stealth | Ngrok named Sysmon.exe in original advisory | [A01-ORIGINAL](../References.md#a01-original) | High Confidence in source observation / mapping |
| [T1560.001 — Archive via Utility](https://attack.mitre.org/techniques/T1560/001) | Collection | RAR/7-Zip archive staging before data transfer | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1005 — Data from Local System](https://attack.mitre.org/techniques/T1005) | Collection | Local sensitive-file collection | [A01](../References.md#a01), [A12](../References.md#a12) | High Confidence in source observation / mapping |
| [T1039 — Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039) | Collection | Network-share data collection | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1567.002 — Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) | Exfiltration | s5cmd upload to S3; cloud storage is legitimate infrastructure | [A11](../References.md#a11) | High Confidence in source observation / mapping |
| [T1048 — Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) | Exfiltration | SSH exfiltration assessment from host/volume evidence; separate from C2 | [A10](../References.md#a10) | Moderate Confidence |
| [T1486 — Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486) | Impact | C++ and Rust payloads encrypt Windows/Linux/virtual disks | [A01](../References.md#a01), [A03](../References.md#a03), [A16](../References.md#a16) | High Confidence in source observation / mapping |
| [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490) | Impact | Shadow-copy deletion and recovery inhibition | [A01](../References.md#a01) | High Confidence in source observation / mapping |
| [T1489 — Service Stop](https://attack.mitre.org/techniques/T1489) | Impact | Services and Hyper-V VMs stopped before encryption | [A21](../References.md#a21), [A22](../References.md#a22) | High Confidence in source observation / mapping |

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
