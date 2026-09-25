# APT29 — MITRE ATT&CK Evidence Mapping

**Presentation reviewed:** 2026-09-25.

This mapping prioritizes current MITRE G0016 evidence and the 2024–2026 campaigns reviewed here. Technique presence does not mean universal use. ATT&CK version checked: **v19.2 / G0016 v6.2**.

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1566.001 — Spearphishing Attachment | Initial Access | Dukes lures, ISO/VHDX containers and malicious RDP attachments | High |
| T1566.002 — Spearphishing Link | Initial Access | ROOTSAW/WINELOADER and diplomatic credential/delivery links | High |
| T1189 — Drive-by Compromise | Initial Access | AWS-observed watering hole used compromised websites and selective redirects into device-code phishing | High for the 2025 campaign |
| T1204.002 — Malicious File | Execution | ISO/IMG/ZIP/RDP delivery and the GRAPELOADER side-loading bundle require user execution | High |
| T1110.003 — Password Spraying | Credential Access | Microsoft corporate breach and government cloud advisory | High |
| T1621 — Multi-Factor Authentication Request Generation | Credential Access | Government cloud advisory documents repeated MFA prompts until user acceptance | High |
| T1078 — Valid Accounts | Initial Access, Persistence, Privilege Escalation, Stealth | Reused credentials, service accounts and cloud accounts | High |
| T1190 — Exploit Public-Facing Application | Initial Access | Fortinet, Zimbra, Pulse, Citrix and VMware exploitation in 2021 reporting; TeamCity CVE-2023-42793 exploitation from 2023-09 | High |
| T1199 — Trusted Relationship | Initial Access | SolarWinds, cloud solution partners and downstream provider access | High |
| T1195.002 — Compromise Software Supply Chain | Initial Access | SUNSPOT modification of the SolarWinds build process and signed SUNBURST delivery | High |
| T1583 — Acquire Infrastructure | Resource Development | Leased infrastructure obtained through resellers using fake identities, low-reputation email and cryptocurrency | High for the government-described SVR pattern |
| T1584 — Compromise Infrastructure | Resource Development | Compromised websites, tenants and captive-portal infrastructure used for delivery and operations | High |
| T1584.005 — Botnet | Resource Development | Compromised small-business Microsoft tenants supported later Teams-based targeting | High |
| T1665 — Hide Infrastructure | Resource Development | Residential/mobile proxies and Tor obscure actor origin and blend with victim geography | High |
| T1059.001 — PowerShell | Execution | Post-compromise execution, discovery and ChocoShell | High |
| T1059.003 — Windows Command Shell | Execution | Native command execution across multiple campaigns | High |
| T1059.005 — Visual Basic | Execution | Sibot and script-based execution | High |
| T1047 — Windows Management Instrumentation | Execution | Execution and historical Dukes/SolarWinds persistence support | High |
| T1569.002 — Service Execution | Execution | PsExec and CornFlake service operation | High |
| T1218.010 — Regsvr32 | Stealth | Historical signed-binary proxy execution in APT29 corpus | Moderate |
| T1218.005 — Mshta | Stealth | HTML/script execution in phishing and post-compromise chains | High |
| T1218.011 — Rundll32 | Stealth | NativeZone/VaporRage and SolarWinds-era DLL execution | High |
| T1547.001 — Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | Dukes families and CornFlake redundant persistence | High |
| T1053.005 — Scheduled Task | Execution, Persistence, Privilege Escalation | GoldMax, SUNSPOT, remote tasks and CornFlake | High |
| T1543.003 — Windows Service | Persistence, Privilege Escalation | CornFlake `svchost32` service | High |
| T1546.003 — Windows Management Instrumentation Event Subscription | Persistence, Privilege Escalation | RegDuke and SolarWinds-era WMI persistence | High |
| T1098.001 — Additional Cloud Credentials | Persistence, Privilege Escalation | Credentials added to applications/service principals | High |
| T1098.002 — Additional Email Delegate Permissions | Persistence, Privilege Escalation | Application impersonation and mailbox permissions | High |
| T1098.003 — Additional Cloud Roles | Persistence, Privilege Escalation | Privileged service-principal/cloud role assignment | High |
| T1098.005 — Device Registration | Persistence, Privilege Escalation | Actor-controlled devices enrolled after authentication | High |
| T1136.003 — Cloud Account | Persistence | Provider-targeting campaign created cloud users and applications after privileged access | High |
| T1484.002 — Trust Modification | Defense Impairment, Privilege Escalation | Federation trust altered to accept actor-controlled signing material | High |
| T1548.002 — Bypass User Account Control | Privilege Escalation | Historical APT29 and ChocoShell behavior | Moderate–high |
| T1068 — Exploitation for Privilege Escalation | Privilege Escalation | 2024 joint advisory identifies privilege escalation after exploitation and lists exposure priorities separately from confirmed use | High for the documented actor behavior; CVE-specific scope varies |
| T1555.003 — Credentials from Web Browsers | Credential Access | Browser profiles, Chrome cookies, CornFlake and ChocoShell | High |
| T1539 — Steal Web Session Cookie | Credential Access | SolarWinds-era cookie theft and modern browser-token collection | High |
| T1528 — Steal Application Access Token | Credential Access | Stolen tokens used to access cloud accounts without a password | High |
| T1550.001 — Application Access Token | Persistence, Privilege Escalation, Stealth | Compromised service principals and OAuth tokens used in Microsoft 365 | High |
| T1550.004 — Web Session Cookie | Persistence, Privilege Escalation, Stealth | Stolen and forged cookies used to access cloud resources and bypass MFA | High |
| T1558.003 — Kerberoasting | Credential Access | TGS tickets obtained for offline cracking in SolarWinds campaign | High |
| T1649 — Steal or Forge Authentication Certificates | Credential Access | AD CS and AD FS certificate material | High |
| T1003.001 — LSASS Memory | Credential Access | Credential dumping in post-compromise operations | Moderate–high |
| T1087.002 — Domain Account | Discovery | PowerShell/AD enumeration | High |
| T1069.002 — Domain Groups | Discovery | AD group and privilege discovery | High |
| T1482 — Domain Trust Discovery | Discovery | `Get-AcceptedDomain`, AdFind and federation review | High |
| T1082 — System Information Discovery | Discovery | Dukes, SUNBURST, WINELOADER and CornFlake profiling | High |
| T1057 — Process Discovery | Discovery | Malware and operator process enumeration | High |
| T1083 — File and Directory Discovery | Discovery | Local/share targeting and malware profiling | High |
| T1135 — Network Share Discovery | Discovery | Historical Dukes and post-compromise operations | High |
| T1018 — Remote System Discovery | Discovery | Domain/network movement preparation | High |
| T1016 — System Network Configuration Discovery | Discovery | Host networking and GoldFinder proxy-path mapping | High |
| T1021.001 — Remote Desktop Protocol | Lateral Movement | RDP access and malicious RDP-file campaign | High |
| T1021.002 — SMB/Windows Admin Shares | Lateral Movement | Remote execution and Tor tunnel carriage | High |
| T1021.006 — Windows Remote Management | Lateral Movement | Hands-on remote administration | Moderate–high |
| T1574.001 — DLL | Execution, Stealth | WINELOADER and other DLL side-loading chains | High |
| T1036 — Masquerading | Stealth | Ministry impersonation, fake Cloudflare checks, Microsoft-themed domains and service/file names imitate trusted entities | High |
| T1055 — Process Injection | Privilege Escalation, Stealth | WINELOADER module execution and other post-compromise tooling | High |
| T1027 — Obfuscated Files or Information | Stealth | Encrypted strings/configuration, HTML/JS and staged payloads | High |
| T1027.003 — Steganography | Stealth | Operation Ghost communications and historical web-service dead drops | High |
| T1070.004 — File Deletion | Stealth | Cleanup across Dukes and SolarWinds-era operations | High |
| T1685 — Disable or Modify Tools | Defense Impairment | Security/logging suppression, AMSI tampering and GTG-20006 payloads reported to freeze security updates | High |
| T1686 — Disable or Modify System Firewall | Defense Impairment | `netsh` firewall modification in SolarWinds campaign | High |
| T1102 — Web Service | Command and Control | Dropbox, Google Drive, Trello, GitHub and social web services | High |
| T1071.001 — Web Protocols | Command and Control | HTTP/S C2 in multiple malware families | High |
| T1090.002 — External Proxy | Command and Control | Tor, VPNs, residential proxies and redirectors | High |
| T1572 — Protocol Tunneling | Command and Control | Tor/meek remote-service tunnel | High |
| T1105 — Ingress Tool Transfer | Command and Control | Payload retrieval from actor or compromised infrastructure | High |
| T1573 — Encrypted Channel | Command and Control | Multiple encrypted malware protocols; CornFlake ECDH session | High |
| T1114 — Email Collection | Collection | EWS, Graph, mailbox export and application impersonation | High |
| T1005 — Data from Local System | Collection | Files and secrets collected from compromised endpoints | High |
| T1039 — Data from Network Shared Drive | Collection | Historical Dukes and post-compromise file collection | High |
| T1113 — Screen Capture | Collection | CornFlake and historical backdoors | High |
| T1056.001 — Keylogging | Collection, Credential Access | CornFlake and historical implant capability | High |
| T1074.001 — Local Data Staging | Collection | Local packaging and temporary artifacts | High |
| T1074.002 — Remote Data Staging | Collection | Password-protected archives on internal OWA/server systems | High |
| T1048 — Exfiltration Over Alternative Protocol | Exfiltration | Mail, web services and encrypted non-C2 transfer paths | High |
| T1567.002 — Exfiltration to Cloud Storage | Exfiltration | Legitimate storage services in campaign-specific transfers | Moderate–high |

## Version Changes and Excluded Mappings

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1086 | T1059.001 — PowerShell | ATT&CK consolidated command interpreters |
| T1085 | T1218.011 — Rundll32 | ATT&CK system-binary proxy execution sub-technique |
| T1084 | T1546.003 — WMI Event Subscription | ATT&CK persistence taxonomy update |
| T1107 | T1070.004 — File Deletion | ATT&CK indicator-removal taxonomy update |
| T1060 | T1547.001 — Registry Run Keys / Startup Folder | ATT&CK boot/autostart taxonomy update |
| T1035 | T1569.002 — Service Execution | ATT&CK system-services taxonomy update |
| T1486 | Excluded | No evidence of data encryption for impact or ransom |
| T1490 | Excluded | ChocoShell uses a temporary snapshot for collection; no recovery-inhibition objective is documented |

## Defensive Application

Prioritize identity techniques before endpoint-only signatures: password spray, device code, stolen token, device registration, application credentials, roles, permissions, federation and mailbox access. On endpoints, correlate LOLBin execution, side-loading, service/task/Run persistence and collection artifacts.

ATT&CK mappings organize evidence; they are not attribution rules. Use [KQL](../detections/KQL.md), [Splunk](../detections/Splunk.md) and [YARA](../detections/APT29-Hunting.yar) as reviewable hunts tied to the published procedures.
