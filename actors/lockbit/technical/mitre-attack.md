# LockBit — MITRE ATT&CK Mapping

**Presentation reviewed:** 2026-09-17.

Mappings use the repository's official Enterprise ATT&CK snapshot, with the additional identifiers checked against the same STIX checksum on 2026-09-17. They describe supported procedures across branches and affiliate cases, not a mandatory attack sequence or an alert-coverage guarantee.

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1078 — Valid Accounts | stealth, persistence, privilege-escalation, initial-access | Affiliate use of compromised credentials; access and lateral movement | High in published procedure; actor attribution remains contextual |
| T1133 — External Remote Services | persistence, initial-access | Exposed VPN/RDP entry routes in the joint advisory | High in published procedure; actor attribution remains contextual |
| T1190 — Exploit Public-Facing Application | initial-access | Public-facing appliance/application exploitation; campaign-specific | High in published procedure; actor attribution remains contextual |
| T1566 — Phishing | initial-access | Affiliate phishing route; no universal lure attributed | High in published procedure; actor attribution remains contextual |
| T1539 — Steal Web Session Cookie | credential-access | Citrix Bleed session theft in AA23-325A | High in published procedure; actor attribution remains contextual |
| T1059.001 — PowerShell | execution | PowerShell staging and recovery-inhibition child processes | High in published procedure; actor attribution remains contextual |
| T1059.003 — Windows Command Shell | execution | Batch and cmd orchestration in affiliate cases | High in published procedure; actor attribution remains contextual |
| T1059.006 — Python | execution | CISA a.py WinRM client | High in published procedure; actor attribution remains contextual |
| T1047 — Windows Management Instrumentation | execution | WMI execution and shadow-copy management | High in published procedure; actor attribution remains contextual |
| T1053.005 — Scheduled Task | execution, persistence, privilege-escalation | GPO-deployed tasks and UpdateAdobeTask campaign persistence | High in published procedure; actor attribution remains contextual |
| T1569.002 — Service Execution | execution | PsExec/service-based execution | High in published procedure; actor attribution remains contextual |
| T1003.001 — LSASS Memory | credential-access | ProcDump and CISA DLL LSASS dump paths | High in published procedure; actor attribution remains contextual |
| T1003.002 — Security Account Manager | credential-access | SAM hive export in a.bat | High in published procedure; actor attribution remains contextual |
| T1555.003 — Credentials from Web Browsers | credential-access | PasswordFox in the affiliate tool inventory | High in published procedure; actor attribution remains contextual |
| T1087.002 — Domain Account | discovery | AD account discovery with directory/native utilities | High in published procedure; actor attribution remains contextual |
| T1069.002 — Domain Groups | discovery | Domain group discovery for privileged access | High in published procedure; actor attribution remains contextual |
| T1018 — Remote System Discovery | discovery | Host discovery before remote deployment | High in published procedure; actor attribution remains contextual |
| T1046 — Network Service Discovery | discovery | Port scanning and scanner utilities | High in published procedure; actor attribution remains contextual |
| T1082 — System Information Discovery | discovery | Host configuration discovery / Seatbelt | High in published procedure; actor attribution remains contextual |
| T1083 — File and Directory Discovery | discovery | Encryptor file and directory traversal | High in published procedure; actor attribution remains contextual |
| T1135 — Network Share Discovery | discovery | Share discovery before remote file access | High in published procedure; actor attribution remains contextual |
| T1482 — Domain Trust Discovery | discovery | BloodHound/domain relationship discovery | High in published procedure; actor attribution remains contextual |
| T1548.002 — Bypass User Account Control | privilege-escalation | COM-related elevation in analyzed Windows branches | High in published procedure; actor attribution remains contextual |
| T1068 — Exploitation for Privilege Escalation | privilege-escalation | Netlogon escalation association in joint advisory | High in published procedure; actor attribution remains contextual |
| T1484.001 — Group Policy Modification | defense-impairment, privilege-escalation | Red domain-deployment Group Policy changes | High in published procedure; actor attribution remains contextual |
| T1021.001 — Remote Desktop Protocol | lateral-movement | Affiliate RDP movement | High in published procedure; actor attribution remains contextual |
| T1021.002 — SMB/Windows Admin Shares | lateral-movement | SMB shares and administrative deployment | High in published procedure; actor attribution remains contextual |
| T1021.006 — Windows Remote Management | lateral-movement | CISA WinRM script | High in published procedure; actor attribution remains contextual |
| T1219.002 — Remote Desktop Software | command-and-control | Affiliate RMM access; legitimate software may be abused | High in published procedure; actor attribution remains contextual |
| T1572 — Protocol Tunneling | command-and-control | Plink, Ligolo and Ngrok tunneling | High in published procedure; actor attribution remains contextual |
| T1071.001 — Web Protocols | command-and-control | HTTP-based remote tooling in the joint tool register | High in published procedure; actor attribution remains contextual |
| T1027 — Obfuscated Files or Information | stealth | Packed payloads, encoded configuration and API hashing | High in published procedure; actor attribution remains contextual |
| T1620 — Reflective Code Loading | stealth | Reflectively loaded 5.0 Windows payload | High in published procedure; actor attribution remains contextual |
| T1614.001 — System Language Discovery | discovery | Language checks in analyzed encryptors | High in published procedure; actor attribution remains contextual |
| T1685 — Disable or Modify Tools | defense-impairment | Security-tool impairment and in-process telemetry interference | High in published procedure; actor attribution remains contextual |
| T1685.005 — Clear Windows Event Logs | defense-impairment | Direct EvtClearLog and command-based event-log clearing | High in published procedure; actor attribution remains contextual |
| T1688 — Safe Mode Boot | defense-impairment | Configurable Black Safe Mode behavior | High in published procedure; actor attribution remains contextual |
| T1112 — Modify Registry | defense-impairment, persistence | Settings, service configuration and registry artifacts | High in published procedure; actor attribution remains contextual |
| T1543.003 — Windows Service | persistence, privilege-escalation | Auto-start remote-access service in Citrix campaign | High in published procedure; actor attribution remains contextual |
| T1005 — Data from Local System | collection | Collection of endpoint files before extortion | High in published procedure; actor attribution remains contextual |
| T1039 — Data from Network Shared Drive | collection | Collection from network shares | High in published procedure; actor attribution remains contextual |
| T1560.001 — Archive via Utility | collection | 7-Zip and cabinet archive staging | High in published procedure; actor attribution remains contextual |
| T1567.002 — Exfiltration to Cloud Storage | exfiltration | Rclone/MEGA cloud transfer activity | High in published procedure; actor attribution remains contextual |
| T1048 — Exfiltration Over Alternative Protocol | exfiltration | FTP/SSH-based transfer tools in affiliate cases | High in published procedure; actor attribution remains contextual |
| T1490 — Inhibit System Recovery | impact | Shadow-copy and backup removal routines | High in published procedure; actor attribution remains contextual |
| T1489 — Service Stop | impact | Service stops before file processing | High in published procedure; actor attribution remains contextual |
| T1486 — Data Encrypted for Impact | impact | Version-specific encryption of local, remote and virtual-machine files | High in published procedure; actor attribution remains contextual |
| T1491.001 — Internal Defacement | impact | Wallpaper/note-related local presentation changes | High in published procedure; actor attribution remains contextual |
| T1070.004 — File Deletion | stealth | Payload self-removal in documented builds | High in published procedure; actor attribution remains contextual |

## Version Changes and Excluded Mappings

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1562.001 | T1685 — Disable or Modify Tools | Use the active identifier from the repository's current STIX snapshot |
| T1070.001 | T1685.005 — Clear Windows Event Logs | Historical advisory identifier superseded |
| T1562.009 | T1688 — Safe Mode Boot | Current active technique replaces the old sub-technique |
| T1219 generic remote access | T1219.002 — Remote Desktop Software | Product-specific RMM behavior is mapped at the supported level |
| T1485 for ordinary event-log clearing | T1685.005 | Log clearing should not automatically be described as general data destruction |

An available tool's entire feature set is not mapped unless the reporting supports the procedure. Experimental macOS samples and an advertised command-line option do not establish all-platform operational use.

## Defensive Application

Use the mapping to plan collection across identity, process, memory, task/service, backup, network and virtualization telemetry. The [query register](../detections/Detections.md) states what each local hunt actually observes; command-line queries cannot directly prove internal API calls or encryption success.

