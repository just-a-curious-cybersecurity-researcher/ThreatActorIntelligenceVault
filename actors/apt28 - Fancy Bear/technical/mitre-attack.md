# APT28 — MITRE ATT&CK Evidence Mapping

**Reviewed:** 2026-09-14. Each row maps a source-described behavior or capability, not universal actor practice or independent proof of attribution.

Names and tactics were checked against the official [Enterprise ATT&CK data](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json), retrieved 2026-09-14; SHA-256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`. Used identifiers are retained in the [validation profile](../../../scripts/attack-profile.json).

| ID / technique | ATT&CK tactics | Evidence and scope | Source | Assessment confidence |
|---|---|---|---|---|
| [T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) | Initial Access | Spearphishing documents in Neusploit delivery | [A29](../References.md#a29) | High confidence in source-described behavior; mapping is analytical |
| [T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) | Initial Access | Credential-phishing links in dedicated TA422 campaigns | [A38](../References.md#a38) | High confidence in source-described behavior; mapping is analytical |
| [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) | Initial Access | Exploitation of exposed infrastructure in router campaigns | [A20](../References.md#a20) | High confidence in source-described behavior; mapping is analytical |
| [T1203 — Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203) | Execution | Office exploitation in the Neusploit delivery chain | [A29](../References.md#a29) | High confidence in source-described behavior; mapping is analytical |
| [T1068 — Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) | Privilege Escalation | GooseEgg local privilege escalation | [A17](../References.md#a17) | High confidence in source-described behavior; mapping is analytical |
| [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078) | Stealth, Persistence, Privilege Escalation, Initial Access | Stolen credentials used to access victim resources | [A21](../References.md#a21) | High confidence in source-described behavior; mapping is analytical |
| [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003) | Credential Access | Distributed password spraying against organizations | [A55](../References.md#a55) | High confidence in source-described behavior; mapping is analytical |
| [T1557 — Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) | Credential Access, Collection | DNS redirection enabling adversary-in-the-middle interception | [A33](../References.md#a33) | High confidence in source-described behavior; mapping is analytical |
| [T1187 — Forced Authentication](https://attack.mitre.org/techniques/T1187) | Credential Access | Outlook-triggered forced NTLM authentication | [A16](../References.md#a16) | High confidence in source-described behavior; mapping is analytical |
| [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003) | Credential Access | Browser credential extraction with STEELHOOK | [A21](../References.md#a21) | High confidence in source-described behavior; mapping is analytical |
| [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001) | Execution | PowerShell credential collection scripts | [A21](../References.md#a21) | High confidence in source-described behavior; mapping is analytical |
| [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) | Execution | HEADLACE batch execution | [A21](../References.md#a21) | High confidence in source-described behavior; mapping is analytical |
| [T1059.006 — Python](https://attack.mitre.org/techniques/T1059/006) | Execution | MASEPIE Python implementation | [A21](../References.md#a21) | High confidence in source-described behavior; mapping is analytical |
| [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005) | Execution, Persistence, Privilege Escalation | GooseEgg scheduled task persistence | [A17](../References.md#a17) | High confidence in source-described behavior; mapping is analytical |
| [T1546.015 — Component Object Model Hijacking](https://attack.mitre.org/techniques/T1546/015) | Privilege Escalation, Persistence | GooseEgg COM registration | [A17](../References.md#a17) | High confidence in source-described behavior; mapping is analytical |
| [T1112 — Modify Registry](https://attack.mitre.org/techniques/T1112) | Defense Impairment, Persistence | Outlook security and macro registry changes | [A25](../References.md#a25) | High confidence in source-described behavior; mapping is analytical |
| [T1137 — Office Application Startup](https://attack.mitre.org/techniques/T1137) | Persistence | Outlook macro-based persistence | [A25](../References.md#a25) | High confidence in source-described behavior; mapping is analytical |
| [T1574.001 — DLL](https://attack.mitre.org/techniques/T1574/001) | Stealth, Execution | NotDoor chain DLL loading alongside a legitimate executable | [A25](../References.md#a25) | High confidence in source-described behavior; mapping is analytical |
| [T1542.001 — System Firmware](https://attack.mitre.org/techniques/T1542/001) | Stealth, Persistence | LoJax UEFI firmware persistence | [A12](../References.md#a12) | High confidence in source-described behavior; mapping is analytical |
| [T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) | Stealth | Payload concealment in contemporary implant delivery | [A29](../References.md#a29) | High confidence in source-described behavior; mapping is analytical |
| [T1027.003 — Steganography](https://attack.mitre.org/techniques/T1027/003) | Stealth | Payload hidden in a PNG image | [A29](../References.md#a29) | High confidence in source-described behavior; mapping is analytical |
| [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) | Command And Control | Download and staging of payload components | [A29](../References.md#a29) | High confidence in source-described behavior; mapping is analytical |
| [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001) | Command And Control | Web-based implant communication | [A28](../References.md#a28) | High confidence in source-described behavior; mapping is analytical |
| [T1102 — Web Service](https://attack.mitre.org/techniques/T1102) | Command And Control | Legitimate cloud storage used by implants | [A28](../References.md#a28) | High confidence in source-described behavior; mapping is analytical |
| [T1090 — Proxy](https://attack.mitre.org/techniques/T1090) | Command And Control | Compromised routers used as proxy infrastructure | [A20](../References.md#a20) | High confidence in source-described behavior; mapping is analytical |
| [T1090.002 — External Proxy](https://attack.mitre.org/techniques/T1090/002) | Command And Control | External relay infrastructure masks operational origin | [A20](../References.md#a20) | High confidence in source-described behavior; mapping is analytical |
| [T1584.008 — Network Devices](https://attack.mitre.org/techniques/T1584/008) | Resource Development | Compromised network devices used as operational infrastructure | [A20](../References.md#a20) | High confidence in source-described behavior; mapping is analytical |
| [T1082 — System Information Discovery](https://attack.mitre.org/techniques/T1082) | Discovery | System information collection in router malware | [A48](../References.md#a48) | High confidence in source-described behavior; mapping is analytical |
| [T1016 — System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) | Discovery | Router network configuration reconnaissance | [A48](../References.md#a48) | High confidence in source-described behavior; mapping is analytical |
| [T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083) | Discovery | File discovery by espionage implants | [A28](../References.md#a28) | High confidence in source-described behavior; mapping is analytical |
| [T1057 — Process Discovery](https://attack.mitre.org/techniques/T1057) | Discovery | Process discovery in historical Sednit tooling | [A03](../References.md#a03) | High confidence in source-described behavior; mapping is analytical |
| [T1033 — System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) | Discovery | User identity collection in HEADLACE scripts | [A21](../References.md#a21) | High confidence in source-described behavior; mapping is analytical |
| [T1113 — Screen Capture](https://attack.mitre.org/techniques/T1113) | Collection | Screenshot capability of SlimAgent | [A28](../References.md#a28) | High confidence in source-described behavior; mapping is analytical |
| [T1056.001 — Keylogging](https://attack.mitre.org/techniques/T1056/001) | Collection, Credential Access | Keylogging capability of SlimAgent | [A28](../References.md#a28) | High confidence in source-described behavior; mapping is analytical |
| [T1114 — Email Collection](https://attack.mitre.org/techniques/T1114) | Collection | Email collection through Outlook-targeting implants | [A25](../References.md#a25) | High confidence in source-described behavior; mapping is analytical |
| [T1005 — Data from Local System](https://attack.mitre.org/techniques/T1005) | Collection | Local file collection by espionage implants | [A28](../References.md#a28) | High confidence in source-described behavior; mapping is analytical |
| [T1021.002 — SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) | Lateral Movement | SMB-based lateral movement in logistics targeting | [A21](../References.md#a21) | High confidence in source-described behavior; mapping is analytical |
| [T1569.002 — Service Execution](https://attack.mitre.org/techniques/T1569/002) | Execution | Remote service execution in logistics intrusions | [A21](../References.md#a21) | High confidence in source-described behavior; mapping is analytical |
| [T1070.004 — File Deletion](https://attack.mitre.org/techniques/T1070/004) | Stealth | HEADLACE artifact deletion | [A21](../References.md#a21) | High confidence in source-described behavior; mapping is analytical |
| [T1485 — Data Destruction](https://attack.mitre.org/techniques/T1485) | Impact | Destructive file-deletion capability reported for PRISMEX; not ransomware encryption | [A31](../References.md#a31) | High confidence in source-described behavior; mapping is analytical |

## Version Changes and Excluded Mappings

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1574.002 | T1574.001 | DLL side-loading merged into DLL in the recorded catalog; nomenclature maintenance, not a new actor behavior |

Revoked and deprecated entries are excluded. Ransomware encryption and recovery inhibition are not inferred from espionage activity. Malware capability does not prove execution at every victim. Parent techniques are retained where the source does not establish a narrower implementation.

## Defensive Application

Prioritize the identity, edge-device and mailbox surfaces described in the [detection register](../detections/Detections.md). Technique matches support a behavioral investigation; they are not actor signatures.
