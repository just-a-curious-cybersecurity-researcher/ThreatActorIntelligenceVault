# SafePay — MITRE ATT&CK Mapping

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR  
**ATT&CK object status:** No dedicated SafePay group or software object was located at cutoff; this is a local evidence-based Enterprise mapping.

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1110.003 — Password Spraying | Credential Access | DCSO observed VPN password spraying | High, one case |
| T1078 — Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion | VPN/RDP access and domain-admin use in Huntress/NCC cases | High |
| T1133 — External Remote Services | Persistence, Initial Access | VPN, RDP and ScreenConnect access | High |
| T1190 — Exploit Public-Facing Application | Initial Access | NCC’s FortiGate policy flaw is mapped operationally but was a misconfiguration, not a demonstrated CVE exploit; vendor CVE associations remain qualified | Moderate for exposed-service abuse; low for specific CVEs |
| T1059.001 — PowerShell | Execution | ShareFinder, Defender changes and wallpaper retrieval | High |
| T1059.003 — Windows Command Shell | Execution | Batch execution and locker distribution | High |
| T1218.010 — Regsvr32 | Defense Evasion | `soc.dll` and `locker.dll` execution | High |
| T1548.002 — Bypass User Account Control | Privilege Escalation, Defense Evasion | CMSTPLUA/DllHost behavior and `-uac` option | High for early sample |
| T1543.003 — Windows Service | Persistence, Privilege Escalation | ScreenConnect Client service under LocalSystem | High, one case |
| T1547.001 — Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | Optional HKLM Run persistence in Microsoft telemetry | Moderate |
| T1112 — Modify Registry | Defense Evasion | Sygnia confirmed HKCU Run-value deployment of the locker; Microsoft reports optional Run persistence | High, one case |
| T1021.001 — Remote Desktop Protocol | Lateral Movement | Interactive access across Huntress/NCC cases | High |
| T1021.002 — SMB/Windows Admin Shares | Lateral Movement | Batch and locker distribution to shares/servers | High |
| T1135 — Network Share Discovery | Discovery | ShareFinder/SharpShares and locker-native enumeration | High |
| T1046 — Network Service Discovery | Discovery | Advanced IP Scanner, NetScan and route/host scripts in Sygnia IR | High, one case |
| T1016 — System Network Configuration Discovery | Discovery | `RouteCIDR.py`, `ping`, `nslookup` and supporting outputs | High, one case |
| T1087.002 — Domain Account | Discovery | Sygnia observed Active Directory enumeration with PowerShell helpers and `dsa.msc` | High, one case |
| T1082 — System Information Discovery | Discovery | Batch/QDoor host information and environment checks | High |
| T1083 — File and Directory Discovery | Discovery | Targeted collection and recursive target traversal | High |
| T1003.001 — LSASS Memory | Credential Access | Mimikatz is listed in multiple SafePay profiles; direct LSASS access was not exposed in the reviewed cases | Moderate |
| T1003.002 — Security Account Manager | Credential Access | NCC recorded a RemoteRegDump-like temporary artifact consistent with registry credential extraction | Moderate-high, one case |
| T1552.001 — Credentials In Files | Credential Access | Snaffler was executed while SafePay sought exposed credentials and Veeam service material | Moderate-high, one case |
| T1134.001 — Token Impersonation/Theft | Defense Evasion, Privilege Escalation | Locker duplicates a token and assigns it to a suspended network-enumeration thread | High, sample-level |
| T1560.001 — Archive via Utility | Collection | WinRAR and 7-Zip associations; WinRAR directly observed | High for WinRAR |
| T1005 — Data from Local System | Collection | Sygnia documented targeted collection from compromised systems | High, one case |
| T1039 — Data from Network Shared Drive | Collection | Remote user/share data was archived in Huntress and Sygnia cases | High |
| T1074.001 — Local Data Staging | Collection | Split RAR archives were built in a central staging location before transfer | High |
| T1219.002 — Remote Desktop Software | Command and Control | ScreenConnect and AnyDesk were observed as remote-access tooling | High, case-scoped |
| T1071.001 — Web Protocols | Command and Control | HTTPS retrieval and trusted web/cloud traffic; QDoor itself used a separate custom protocol | Moderate-high |
| T1095 — Non-Application Layer Protocol | Command and Control | QDoor custom unencrypted protocol over TCP/443 | High, one case |
| T1572 — Protocol Tunneling | Command and Control | QDoor tunnel command | High, one case |
| T1567.002 — Exfiltration to Cloud Storage | Exfiltration | Sygnia confirmed transfer to an attacker-controlled OneDrive for Business tenant | High, one case |
| T1027 — Obfuscated Files or Information | Stealth | Modified UPX, embedded stages, stack-built strings and encoded configuration | High |
| T1055 — Process Injection | Stealth, Privilege Escalation | RunPE-style process hollowing of suspended `WerFault.exe` | High |
| T1622 — Debugger Evasion | Defense Evasion | Locker applies `ThreadHideFromDebugger` to a suspended worker before resuming it | High, sample-level |
| T1140 — Deobfuscate/Decode Files or Information | Defense Evasion | Runtime stack-string and configuration decryption | High |
| T1106 — Native API | Execution | Native thread/token/process APIs and async I/O | High, sample-level |
| T1614.001 — System Language Discovery | Discovery | Early builds inspect system language before continuing; later DCSO build omitted the exit | High, build-scoped |
| T1685 — Disable or Modify Tools | Defense Evasion | Defender protection changes and security-product/service interruption | High |
| T1489 — Service Stop | Impact | VSS, database, mail, backup and security service stops | High |
| T1047 — Windows Management Instrumentation | Execution | `wmic shadowcopy delete` | High |
| T1070.004 — File Deletion | Defense Evasion | Self-delete and rapid FileZilla removal | Moderate-high |
| T1048 — Exfiltration Over Alternative Protocol | Exfiltration | FileZilla/SFTP, RDP clipboard and direct VPN transfer are case-scoped options; Huntress lacked packet proof but Triskele observed completed transfers through other channels | Moderate-high |
| T1490 — Inhibit System Recovery | Impact | VSS deletion and BCD recovery changes | High |
| T1531 — Account Access Removal | Impact | Administrative passwords changed after compromise | High, NCC case |
| T1486 — Data Encrypted for Impact | Impact | `.safepay` encryption across endpoints and shares | High |
| T1491.001 — Internal Defacement | Impact | Optional hostile desktop wallpaper | Moderate |

## Version Changes and Excluded Mappings

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1202 (Indirect Command Execution) | T1218.010 (Regsvr32) for this behavior | Older Huntress mapping used T1202; the observed signed-binary proxy is specifically Regsvr32 |
| T1562.001 (Impair Defenses) | T1685 (Disable or Modify Tools) for direct product impairment | Current mapping makes the Defender/security-tool action more explicit; T1562.001 may remain valid in older platforms |
| T1048 (Exfiltration Over Alternative Protocol) | Retained with moderate confidence | FileZilla execution suggests transfer, but Huntress did not collect network evidence proving completion |
| T1190 (Exploit Public-Facing Application) | Not used as proof of a named CVE | The confirmed NCC route was policy misconfiguration plus weak credentials |

No mapping is added solely because FortiGuard lists a CVE or tool. No Linux/ESXi techniques are added without a native SafePay sample or documented platform action.

## Defensive Application

Use the mapping to connect remote identity activity, process execution, service changes, file writes and network events. The highest-value correlations join a new VPN/RDP source with share discovery, first-seen RMM or QDoor, archive creation, recovery commands and a `.safepay` rename burst. Technique presence alone is not actor attribution.
