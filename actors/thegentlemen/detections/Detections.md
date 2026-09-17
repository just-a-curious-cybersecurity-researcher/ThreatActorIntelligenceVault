# The Gentlemen — Detections

**Presentation reviewed:** 2026-09-17.

## Content

- [KQL queries](KQL.md): 54 executable hunt queries.
- [Splunk searches](Splunk.md): 54 corresponding searches with sensor differences documented.
- [YARA rules](TheGentlemen-Hunting.yar): 11 repository-authored rules for artifacts, encrypted-output triage and exact sample identity.

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| 1. Credential Access | 3 | 3 | Sensor and false-positive scope stated per entry |
| 2. Active Directory and Network Discovery | 9 | 9 | Sensor and false-positive scope stated per entry |
| 3. Persistence and Remote Administration | 14 | 14 | Sensor and false-positive scope stated per entry |
| 4. Tunneling and C2 | 4 | 4 | Sensor and false-positive scope stated per entry |
| 5. Defense Evasion and Impairment | 9 | 9 | Sensor and false-positive scope stated per entry |
| 6. Collection and Exfiltration | 3 | 3 | Sensor and false-positive scope stated per entry |
| 7. Recovery Inhibition | 3 | 3 | Sensor and false-positive scope stated per entry |
| 8. Deployment and Impact | 5 | 5 | Sensor and false-positive scope stated per entry |
| 9. Multi-Stage Correlation | 2 | 2 | Sensor and false-positive scope stated per entry |
| 10. Campaign Artifact Hunts | 2 | 2 | Sensor and false-positive scope stated per entry |

## Query Organization

H01–H54 use matching identifiers in KQL and SPL. Exact behavior and collection differences are stated within each entry. Tool-inventory hypotheses are identified per entry. H47–H48 use forwarded ESXi records and require Sentinel/Azure Monitor or Splunk syslog. All other pairs use Windows endpoint telemetry; event coverage is not identical across platforms.

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| GENTLEMEN_Note_Text_Triage | Repository-authored | Note resemblance | Archived research and simulations match |
| GENTLEMEN_Windows_Artifact_Bundle_Triage | Repository-authored | PE artifact-name combination | Not a validated universal family signature |
| GENTLEMEN_Task_Command_Artifact_Triage | Repository-authored | Script/text task pattern | Match does not prove command execution |
| GENTLEMEN_Encrypted_Output_Footer_Triage | Repository-authored | Published footer fields near EOF; encrypted-output triage, not executable attribution | Reports or test files embedding the footer; inspect original file and trailer |
| GENTLEMEN_Background_Worker_PE_Triage | Repository-authored | Windows worker artifact combination in a PE-like file | Compiled research fixtures or security software embedding artifact strings |
| GENTLEMEN_Propagation_Strings_PE_Triage | Repository-authored | Multiple published propagation names plus distribution context | Research binaries; changed or obfuscated builds can evade matching |
| GENTLEMEN_Remote_Preparation_Script_Triage | Repository-authored | Text conjunction of remote preparation behaviors; not actor-specific | Threat reports, configuration scripts and simulations; verify values and context |
| GENTLEMEN_ESXi_Artifact_Bundle_Triage | Repository-authored | ELF artifact bundle from the dedicated ESXi analysis | Research ELF files; not proof that every Linux variant shares these strings |
| GENTLEMEN_ESXi_Boot_Text_Triage | Repository-authored | Boot/cron text referencing the reported hidden payload path | Archived incident evidence and analyst notes; validate actual installed path and scheduler |
| GENTLEMEN_Self_Delete_Batch_Triage | Repository-authored | Generic executable/self-deleting batch pattern seen in the supplied analysis | Legitimate installer/uninstaller cleanup; generic behavior, not family identification |
| GENTLEMEN_Published_Locker_Hash_Match | Repository-authored | Exact published Windows/Linux locker identity; no generic tool hashes | Copies of the identified bytes; does not establish execution or actor presence |

## Review Notes

The supplied brand-only YARA is replaced with scoped conjunctions. Its placeholder thegentlemen.onion is not retained as real infrastructure. Published behavior is the basis for a local hunt, not a claim that the publisher authored these queries.

YARA can miss obfuscated or changed builds. Process names, historical IPs and generic maintenance commands require contextual validation. Synthetic fixtures test condition logic, not malware coverage. The footer rule has a 100 MB limit and tests marker proximity; larger disk images require extraction of a forensic tail copy or another scanning workflow. The exact-hash rule covers identified samples below 50 MB, not all variants.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
|---|---|
| Driver-based impairment | Driver loads, signer/hash, service creation and EDR health; a filename alone is insufficient |
| GPO/NETLOGON deployment | Directory-service auditing and SYSVOL writes linked to administrative sessions |
| ESXi boot persistence | Host startup files, cron changes and associated executable identity |
| Transfer completion | WinSCP/rclone job history, destinations and bytes; distinguish attempts from successful theft |
| Shadow-copy impact | Snapshot inventory and command results; a process event is only an attempt |
