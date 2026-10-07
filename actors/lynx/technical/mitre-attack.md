# Lynx — MITRE ATT&CK Evidence Mapping

**Presentation reviewed:** 2026-10-07.

| ID / technique | ATT&CK tactics | Evidence and scope | Assessment confidence |
|---|---|---|---|
| T1078 — Valid Accounts | Initial Access; Persistence; Privilege Escalation; Defense Evasion | Valid credentials used for exposed RDP in the documented 2025 intrusion. | High |
| T1133 — External Remote Services | Initial Access; Persistence | Internet-facing RDP supplied the initial interactive path. | High |
| T1021.001 — Remote Desktop Protocol | Lateral Movement | RDP was the principal movement method to internal, backup and file servers. | High |
| T1059.003 — Windows Command Shell | Execution | `cmd.exe` launched discovery and `w.exe`. | High |
| T1059.001 — PowerShell | Execution | PowerShell appeared in interactive execution; exact scripts are not generalized. | High in case; Moderate in function scope |
| T1053.005 — Scheduled Task | Execution; Persistence; Privilege Escalation | A malicious GPO created a scheduled task to launch the locker from `NETLOGON`. | High in 2026 PacketWatch case |
| T1484.001 — Group Policy Modification | Defense Evasion; Privilege Escalation | `gpscript.exe` was used to create the deployment GPO. | High in 2026 PacketWatch case |
| T1136.002 — Domain Account | Persistence | Lookalike domain accounts were created with `dsa.msc`. | High |
| T1543.003 — Windows Service | Persistence; Privilege Escalation | AnyDesk was installed as a service. | High in case |
| T1219.002 — Remote Desktop Software | Command and Control | AnyDesk was installed; RDP remained dominant. | High in installation; low in subsequent use |
| T1046 — Network Service Discovery | Discovery | NetScan and NetExec enumerated hosts and services. | High |
| T1135 — Network Share Discovery | Discovery | NetScan and interactive browsing identified network shares. | High |
| T1018 — Remote System Discovery | Discovery | NetScan, ping and native tools enumerated remote systems. | High |
| T1082 — System Information Discovery | Discovery | `systeminfo` and NetScan collected host/OS properties. | High |
| T1016 — System Network Configuration Discovery | Discovery | `ipconfig`, `route print`, `nslookup` and `nbtstat` were observed. | High |
| T1083 — File and Directory Discovery | Discovery | Network shares and candidate files were browsed before staging and encryption. | High |
| T1057 — Process Discovery | Discovery | Task Manager and the encryptor's process enumeration expose process state. | High |
| T1560.001 — Archive via Utility | Collection | `7zG.exe` created archives from selected share data. | High |
| T1048 — Exfiltration Over Alternative Protocol | Exfiltration | Browser uploads to `temp[.]sh` transferred archives; precise protocol is ordinary web traffic. | High in transfer; mapping Moderate |
| T1567.002 — Exfiltration to Cloud Storage | Exfiltration | Rclone and RMM file-transfer functions moved collected data in 2026 cases. | High in cases; destination varies |
| T1105 — Ingress Tool Transfer | Command and Control | NetExec was downloaded through Edge and the locker was staged to servers. | High |
| T1003.001 — LSASS Memory | Credential Access | Mimikatz was observed in direct Lynx incident response. | High in 2026 cases; affiliate behavior |
| T1685 — Disable or Modify Tools | Defense Impairment | Affiliates disabled Defender and added exclusions; the locker also terminates backup and security-adjacent software. | High in cases and capability |
| T1489 — Service Stop | Impact | The encryptor recursively stops matching services. | High capability |
| T1222.001 — Windows Permissions | Defense Impairment | Lynx takes ownership and replaces DACLs to gain file write access. | High capability |
| T1112 — Modify Registry | Defense Impairment; Persistence | Wallpaper setting and service installation can modify registry-backed configuration. | Moderate; implementation-specific |
| T1490 — Inhibit System Recovery | Impact | Manual Veeam job deletion, volume shadow-copy suppression and ESXi snapshot removal. | High |
| T1486 — Data Encrypted for Impact | Impact | AES-CTR transforms eligible content and appends `.LYNX`. | High |
| T1005 — Data from Local System | Collection | Files were selected from local and network storage for staging; encryptor also enumerates local data. | High in case; behavior scope separated |

## Version Changes and Excluded Mappings

| Historical ID | Current equivalent | Reason |
|---|---|---|
| T1219 | T1219.002 — Remote Desktop Software | Current sub-technique used for AnyDesk rather than the former parent-only mapping. |
| T1562.001 | T1685 — Disable or Modify Tools | Repository ATT&CK profile uses the current defense-impairment mapping for tool disabling. |

No dedicated MITRE ATT&CK Lynx group/software object was located. G1032 and S1139 describe INC Ransom and are lineage comparators, not Lynx identifiers. Exact exploit CVEs and Cobalt Strike remain excluded because the reviewed Lynx-specific cases do not establish them at the same level. PacketWatch supports phishing and credential dumping at affiliate-case scope, while Triskele supports configuration-led VPN/RMM access.

## Defensive Application

Use mappings to connect identity, endpoint, network, backup and file telemetry. Highest-value correlations join T1078/T1133 with T1136.002, discovery, archive creation, outbound transfer, T1490 and T1486. Technique coverage supports hunting; it does not attribute ordinary administrative use to Lynx.
