# Lynx — Detections

**Presentation reviewed:** 2026-10-07.

## Content

- [KQL queries](KQL.md): 28 executable Microsoft Defender XDR hunts.
- [Splunk searches](Splunk.md): 28 corresponding searches with stated sensor assumptions.
- [YARA rules](Lynx-Hunting.yar): one published family rule plus four scoped repository rules.

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| 1. Credential Access | 2 | 2 | Baseline remote access and approved password-audit activity |
| 2. Active Directory and Network Discovery | 4 | 4 | Inventory scanners and administrators can match |
| 3. Persistence and Remote Administration | 3 | 3 | Validate account requester, service signer and change ticket |
| 4. Tunneling and C2 | 2 | 2 | Historical IPs and legitimate AnyDesk require context |
| 5. Defense Evasion and Impairment | 3 | 3 | Built-in API behavior can evade command-only collection |
| 6. Collection and Exfiltration | 2 | 2 | Distinguish ordinary archives and approved file sharing |
| 7. Recovery Inhibition | 2 | 2 | Confirm command result, Veeam audit and ESXi task outcome |
| 8. Deployment and Impact | 3 | 3 | Exact hashes are narrow; file-fan-out thresholds need tuning |
| 9. Multi-Stage Correlation | 1 | 1 | Sequence logic depends on retention and device normalization |
| 10. Campaign Artifact Hunts | 6 | 6 | Tool hashes, RMM, credential, exfiltration and deployment artifacts are incident-scoped |

## Query Organization

LNX01–LNX28 use matching identifiers in KQL and SPL. The hunts prioritize documented affiliate cases and reverse-engineered locker behaviors. They do not assume that every Lynx affiliate uses the same tools.

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| MAL_RANSOM_INC_Aug24 | Published by Nextron/X__Junior | INC/Lynx PE strings and opcode combinations | Upstream lineage rule; can match related INC variants |
| LYNX_Published_Locker_SHA256 | Repository-authored | Exact ten published Lynx locker samples | Exact bytes only; excludes dual-use tool hashes |
| LYNX_Note_Text_Triage | Repository-authored | Ransom-note text conjunction | Text archives and research reports can match |
| LYNX_Windows_Artifact_Bundle_Triage | Repository-authored | PE with multiple Lynx execution/artifact strings | Changed/stripped builds can evade it |
| LYNX_Encrypted_Output_Trailer_Triage | Repository-authored | Published 116-byte trailer fields at EOF | Intended for encrypted-file triage, not executable identity |

## Review Notes

The published YARA rule retains its original name and metadata. Local exact-hash logic contains only locker samples. NetScan and NetExec are detected through context queries because their case-specific hashes identify legitimate or dual-use binaries.

Command-line hunts detect optional flags, not API-only execution. Service stops, Restart Manager termination and volume device controls require EDR, Windows service events, Veeam telemetry or storage snapshots to confirm outcome.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
|---|---|
| Restart Manager process termination | ETW/EDR API or process-handle telemetry tied to a process later modifying many files |
| Shadow-copy device control | Kernel/EDR capture of `0x53C028`, plus before/after VSS inventory |
| Print-based ransom impact | PrintService Operational events and spool content associated with the locker process |
| File-footer validation | Inspect a forensic copy for marker placement and per-file ephemeral key; avoid altering evidence |
| Veeam impairment | Job-deletion audit, console session, user and source workstation correlation |
| ESXi impact | Shell audit, VM task history, snapshot inventory and hashes of generated `kill`/`delete` scripts |
