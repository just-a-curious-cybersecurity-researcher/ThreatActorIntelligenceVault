# APT28 — MITRE ATT&CK Evidence Mapping

**Presentation reviewed:** 2026-09-15.

**Reviewed:** 2026-09-14. Each row maps a source-described behavior or capability, not universal actor practice or independent proof of attribution.

Names and tactics were checked against the official Enterprise ATT&CK data, retrieved 2026-09-14; SHA-256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`. Used identifiers are retained in the [validation profile](../../../scripts/attack-profile.json).

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1566.001 — Spearphishing Attachment | Initial Access | Spearphishing documents in Neusploit delivery | High confidence in source-described behavior; mapping is analytical |
| T1566.002 — Spearphishing Link | Initial Access | Credential-phishing links in dedicated TA422 campaigns | High confidence in source-described behavior; mapping is analytical |
| T1190 — Exploit Public-Facing Application | Initial Access | Exploitation of exposed infrastructure in router campaigns | High confidence in source-described behavior; mapping is analytical |
| T1203 — Exploitation for Client Execution | Execution | Office exploitation in the Neusploit delivery chain | High confidence in source-described behavior; mapping is analytical |
| T1068 — Exploitation for Privilege Escalation | Privilege Escalation | GooseEgg local privilege escalation | High confidence in source-described behavior; mapping is analytical |
| T1078 — Valid Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Stolen credentials used to access victim resources | High confidence in source-described behavior; mapping is analytical |
| T1110.003 — Password Spraying | Credential Access | Distributed password spraying against organizations | High confidence in source-described behavior; mapping is analytical |
| T1557 — Adversary-in-the-Middle | Credential Access, Collection | DNS redirection enabling adversary-in-the-middle interception | High confidence in source-described behavior; mapping is analytical |
| T1187 — Forced Authentication | Credential Access | Outlook-triggered forced NTLM authentication | High confidence in source-described behavior; mapping is analytical |
| T1555.003 — Credentials from Web Browsers | Credential Access | Browser credential extraction with STEELHOOK | High confidence in source-described behavior; mapping is analytical |
| T1059.001 — PowerShell | Execution | PowerShell credential collection scripts | High confidence in source-described behavior; mapping is analytical |
| T1059.003 — Windows Command Shell | Execution | HEADLACE batch execution | High confidence in source-described behavior; mapping is analytical |
| T1059.006 — Python | Execution | MASEPIE Python implementation | High confidence in source-described behavior; mapping is analytical |
| T1053.005 — Scheduled Task | Execution, Persistence, Privilege Escalation | GooseEgg scheduled task persistence | High confidence in source-described behavior; mapping is analytical |
| T1546.015 — Component Object Model Hijacking | Privilege Escalation, Persistence | GooseEgg COM registration | High confidence in source-described behavior; mapping is analytical |
| T1112 — Modify Registry | Defense Impairment, Persistence | Outlook security and macro registry changes | High confidence in source-described behavior; mapping is analytical |
| T1137 — Office Application Startup | Persistence | Outlook macro-based persistence | High confidence in source-described behavior; mapping is analytical |
| T1574.001 — DLL | Stealth, Execution | NotDoor chain DLL loading alongside a legitimate executable | High confidence in source-described behavior; mapping is analytical |
| T1542.001 — System Firmware | Stealth, Persistence | LoJax UEFI firmware persistence | High confidence in source-described behavior; mapping is analytical |
| T1027 — Obfuscated Files or Information | Stealth | Payload concealment in contemporary implant delivery | High confidence in source-described behavior; mapping is analytical |
| T1027.003 — Steganography | Stealth | Payload hidden in a PNG image | High confidence in source-described behavior; mapping is analytical |
| T1105 — Ingress Tool Transfer | Command And Control | Download and staging of payload components | High confidence in source-described behavior; mapping is analytical |
| T1071.001 — Web Protocols | Command And Control | Web-based implant communication | High confidence in source-described behavior; mapping is analytical |
| T1102 — Web Service | Command And Control | Legitimate cloud storage used by implants | High confidence in source-described behavior; mapping is analytical |
| T1090 — Proxy | Command And Control | Compromised routers used as proxy infrastructure | High confidence in source-described behavior; mapping is analytical |
| T1090.002 — External Proxy | Command And Control | External relay infrastructure masks operational origin | High confidence in source-described behavior; mapping is analytical |
| T1584.008 — Network Devices | Resource Development | Compromised network devices used as operational infrastructure | High confidence in source-described behavior; mapping is analytical |
| T1082 — System Information Discovery | Discovery | System information collection in router malware | High confidence in source-described behavior; mapping is analytical |
| T1016 — System Network Configuration Discovery | Discovery | Router network configuration reconnaissance | High confidence in source-described behavior; mapping is analytical |
| T1083 — File and Directory Discovery | Discovery | File discovery by espionage implants | High confidence in source-described behavior; mapping is analytical |
| T1057 — Process Discovery | Discovery | Process discovery in historical Sednit tooling | High confidence in source-described behavior; mapping is analytical |
| T1033 — System Owner/User Discovery | Discovery | User identity collection in HEADLACE scripts | High confidence in source-described behavior; mapping is analytical |
| T1113 — Screen Capture | Collection | Screenshot capability of SlimAgent | High confidence in source-described behavior; mapping is analytical |
| T1056.001 — Keylogging | Collection, Credential Access | Keylogging capability of SlimAgent | High confidence in source-described behavior; mapping is analytical |
| T1114 — Email Collection | Collection | Email collection through Outlook-targeting implants | High confidence in source-described behavior; mapping is analytical |
| T1005 — Data from Local System | Collection | Local file collection by espionage implants | High confidence in source-described behavior; mapping is analytical |
| T1021.002 — SMB/Windows Admin Shares | Lateral Movement | SMB-based lateral movement in logistics targeting | High confidence in source-described behavior; mapping is analytical |
| T1569.002 — Service Execution | Execution | Remote service execution in logistics intrusions | High confidence in source-described behavior; mapping is analytical |
| T1070.004 — File Deletion | Stealth | HEADLACE artifact deletion | High confidence in source-described behavior; mapping is analytical |
| T1485 — Data Destruction | Impact | Destructive file-deletion capability reported for PRISMEX; not ransomware encryption | High confidence in source-described behavior; mapping is analytical |

## Version Changes and Excluded Mappings

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1574.002 | T1574.001 | DLL side-loading merged into DLL in the recorded catalog; nomenclature maintenance, not a new actor behavior |

Revoked and deprecated entries are excluded. Ransomware encryption and recovery inhibition are not inferred from espionage activity. Malware capability does not prove execution at every victim. Parent techniques are retained where the source does not establish a narrower implementation.

## Defensive Application

Prioritize the identity, edge-device and mailbox surfaces described in the [detection register](../detections/Detections.md). Technique matches support a behavioral investigation; they are not actor signatures.
