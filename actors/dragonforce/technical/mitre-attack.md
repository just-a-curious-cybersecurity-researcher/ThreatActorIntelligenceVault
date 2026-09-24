# DragonForce — MITRE ATT&CK Mapping

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR  
**Mapping rule:** Every entry requires malware-analysis or incident evidence. Generic ransomware behavior is excluded.

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1078 — Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion | Compromised admin/domain accounts in Trend reporting; identity takeovers in Scattered Spider-linked deployments | High for named cases |
| T1566 — Phishing | Initial Access | SMS and identity phishing in Octo Tempest/Scattered Spider deployment context | High for affiliate; not service-wide |
| T1190 — Exploit Public-Facing Application | Initial Access | Citrix CVE-2025-5777 broker chain; SimpleHelp CVEs; reported Ivanti/Log4j associations | High for Citrix/SimpleHelp route; moderate for other associations |
| T1059.003 — Windows Command Shell | Execution | Native commands, PsExec and post-exploitation execution in IR cases | High |
| T1059.001 — PowerShell | Execution | Post-exploitation and tooling execution in affiliate reporting | Moderate |
| T1574.001 — DLL | Execution, Defense Evasion | Signed VirtualBox/DbgView executables loaded malicious DLLs in Symantec case | High |
| T1053.005 — Scheduled Task | Execution, Persistence, Privilege Escalation | Conti-derived locker optionally creates/replaces a SYSTEM task | High for analyzed sample |
| T1136.001 — Local Account | Persistence | `ctxsvc`, `CtxAppVCOMService` and `test` in Citrix-linked cases; account creation in Symantec case | High, case-scoped |
| T1688 — Safe Mode Boot | Defense Evasion | LockBit-derived `-safe` path configures a Safe Mode reboot before encryption | High for analyzed branch |
| T1003.001 — LSASS Memory | Credential Access | Mimikatz reporting | High for published activity |
| T1003.002 — Security Account Manager | Credential Access | Registry-hive export and PassView-related credential collection | High |
| T1555.003 — Credentials from Web Browsers | Credential Access | LaZagne and Backdoor.Turn browser credential capability | High |
| T1087.002 — Domain Account | Discovery | AdFind/ADExplorer and Backdoor.Turn LDAP discovery | High |
| T1069.002 — Domain Groups | Discovery | AdFind/ADExplorer group enumeration | High |
| T1482 — Domain Trust Discovery | Discovery | AdFind domain-trust discovery in Trend reporting | High |
| T1018 — Remote System Discovery | Discovery | NetScan/Netscanold, AD discovery and locker private-IP probing | High |
| T1016 — System Network Configuration Discovery | Discovery | ARP/private-address collection and connection discovery | High |
| T1135 — Network Share Discovery | Discovery | `NetShareEnum` in Conti-derived locker; SMB share discovery in operations | High |
| T1082 — System Information Discovery | Discovery | RMM/device inventory and native commands | Moderate |
| T1021.001 — Remote Desktop Protocol | Lateral Movement | RDP in incident and affiliate reporting | High |
| T1021.002 — SMB/Windows Admin Shares | Lateral Movement | PsExec, `-psex`, RemCom and network-share encryption | High |
| T1047 — Windows Management Instrumentation | Execution | WMIC/WMI remote execution and shadow-copy actions | High |
| T1219.002 — Remote Desktop Software | Command and Control | SimpleHelp, AnyDesk, ScreenConnect, Zoho Assist, Atera and NetBird in documented activity | High; product use is case-specific |
| T1569.002 — Service Execution | Execution | PsExec/RemCom-style remote service execution in incident reporting | High for cited cases |
| T1484.001 — Group Policy Modification | Privilege Escalation, Defense Evasion | LockBit-derived `-gspd` and `-gdel` modes | High for analyzed branch |
| T1090 — Proxy | Command and Control | SystemBC, ngrok and Chisel in published deployments | High for affiliate cases |
| T1071.001 — Web Protocols | Command and Control | Cobalt Strike/SystemBC web communications and HTTP transfer reporting | Moderate |
| T1105 — Ingress Tool Transfer | Command and Control | RMM/MSI delivery, downloaders and post-exploitation tool transfer | High |
| T1572 — Protocol Tunneling | Command and Control | Backdoor.Turn uses Teams/Skype TURN relay access and QUIC to its real C2 | High for Hackledorb case |
| T1685 — Disable or Modify Tools | Defense Evasion | Process termination, BYOVD, registry/service impairment | High |
| T1686 — Disable or Modify System Firewall | Defense Evasion | Firewall weakening in Symantec case | High, case-scoped |
| T1068 — Exploitation for Privilege Escalation | Privilege Escalation | AppMgmt registry symbolic-link LPE; vulnerable-driver exploitation | High for cited cases |
| T1112 — Modify Registry | Defense Evasion, Persistence | LimitBlankPassword, firewall/policy, encrypted file icon and wallpaper settings | High |
| T1027 — Obfuscated Files or Information | Defense Evasion | Custom string/configuration obfuscation and hashed API resolution | High |
| T1036 — Masquerading | Defense Evasion | Renamed utilities and a malicious driver masquerading as security software | High for cited case |
| T1560.001 — Archive via Utility | Collection | Common archivers in published operations before exfiltration | Moderate |
| T1567.002 — Exfiltration to Cloud Storage | Exfiltration | MEGA use in Trend reporting | High |
| T1048 — Exfiltration Over Alternative Protocol | Exfiltration | FTP/SFTP transfer reporting | Moderate |
| T1489 — Service Stop | Impact | Security, backup and application process/service interruption | High |
| T1490 — Inhibit System Recovery | Impact | Shadow-copy, backup catalog/system-state and boot recovery changes | High |
| T1486 — Data Encrypted for Impact | Impact | Windows and Linux/ESXi encryptors | High |
| T1070.004 — File Deletion | Defense Evasion | Repeated payload rename followed by self-deletion in the LockBit-derived branch | High for analyzed branch |

## Version Changes and Excluded Mappings

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1086 | T1059.001 | PowerShell was moved under Command and Scripting Interpreter |
| T1076 | T1021.001 | RDP is a Remote Services sub-technique |
| T1077 | T1021.002 | Windows admin shares are a Remote Services sub-technique |

The following are deliberately excluded from the confirmed map: use of every CVE in FortiGuard’s actor card; ransomware deployment as proof of Scattered Spider in every case; NAS encryption details; and specific cloud persistence methods not tied to a DragonForce deployment. The service’s DLS announcements do not create ATT&CK evidence.

## Defensive Application

Prioritize technique chains rather than individual events:

1. unusual help-desk/MFA or public-edge access;
2. new RMM or side-loaded signed process;
3. credential and AD discovery;
4. SYSTEM task, remote service or privileged identity action;
5. vulnerable-driver load or security-process termination;
6. shadow-copy/boot recovery change;
7. SMB fan-out, ESXi VM shutdown and note/extension burst.

Keep the affiliate label, service label and payload lineage in separate investigation fields. This prevents a Scattered Spider identity alert from becoming unsupported attribution of every later artifact to DragonForce core.
