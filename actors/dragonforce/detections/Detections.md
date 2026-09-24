# DragonForce — Detection and Hunting Index

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Content

- [Microsoft Sentinel / Defender XDR KQL](KQL.md)
- [Splunk SPL](Splunk.md)
- [Repository-authored YARA hunts](DragonForce-Hunting.yar)
- [IOC registers](../iocs/IOCs.md)
- [Operational lifecycle](../intelligence/operations.md)

## Coverage, Telemetry and Tuning Register

| Query family | KQL queries | Splunk searches | Review / tuning |
|---|---|---|---|
| Credential access | DF01–DF02 | DF01–DF02 | Utilities and hive export can be administrative; validate signer, account and destination |
| AD/network discovery | DF03–DF05 | DF03–DF05 | Baseline scanners and management subnets; TCP/445 fan-out is behavior, not attribution |
| Persistence/RMM | DF06–DF08 | DF06–DF08 | Validate approved RMM tenant, installer and task/account creator |
| Tunneling/C2 | DF09–DF11 | DF09–DF11 | Shared services and compromised domains require case correlation |
| Defense impairment | DF12–DF15 | DF12–DF15 | Driver/file creation is not proof of loading; side-loaded names are case-scoped |
| Collection/exfiltration | DF16 | DF16 | Confirm archive creation and destination; command execution does not prove transfer |
| Recovery inhibition | DF17 | DF17 | Backup administration can match; verify parent and change outcome |
| Deployment/impact | DF18–DF21 | DF18–DF21 | Exact hashes are narrow; extensions and commands can be customized |
| Multi-stage | DF22 | DF22 | Ordered same-host correlation prioritizes investigation; it does not prove causality |
| Campaign artifacts | DF23–DF25 | DF23–DF25 | Huntress and Symantec values are incident-specific |

## Query Organization

KQL and SPL use matching DF identifiers. Each query states its telemetry and tuning assumptions. Queries are repository-authored defensive hunts derived from published behavior; they are not vendor rules or exclusive attribution logic.

## YARA Coverage

| Rule | Origin / type | Coverage | Review / tuning |
|---|---|---|---|
| `DRAGONFORCE_Published_Encryptors_SHA256` | Local exact-hash rule | Eight published Windows encryptors | Exact artifacts only |
| `DRAGONFORCE_BackdoorTurn_Campaign_SHA256` | Local exact-hash rule | Backdoor, loader, side-loaded DLL, drivers and utilities from one Symantec case | Incident-scoped; role comes from provenance register |
| `DRAGONFORCE_Conti_Derived_Windows_Hunt` | Local behavior/string conjunction | Mutex, log, Base32 and visual artifacts | Related Conti-derived code can match |
| `DRAGONFORCE_LockBit_Derived_CLI_Hunt` | Local behavior/string conjunction | LockBit-derived DragonForce switches | Other leaked-builder derivatives can match |
| `DRAGONFORCE_Linux_ESXi_Hunt` | Local behavior/string conjunction | ELF VMware path/command/config strings | Admin scripts may contain commands; requires ELF |
| `DRAGONFORCE_Ransom_Note_Hunt` | Local text-artifact rule | Archived negotiation onion/Tox/brand | Notes can be copied into research collections |

## Review Notes

Exact network indicators are scoped to the Huntress and Symantec campaigns. The two Windows lineages require different behavioral logic. Scattered Spider identity and cloud detections are used only where official reporting connects that affiliate to DragonForce deployment. Ransom notes and suffixes are corroboration, not sole proof.

## Additional Telemetry Opportunities

| Opportunity | Collection and decision |
|---|---|
| Citrix ADC authentication | Retain `AAA_LOGIN_FAILED` details, raw username bytes, session ID and source IP; alert on high-volume malformed failures followed by session use |
| Driver load | Collect Sysmon 6 or EDR kernel-driver telemetry with hash, signer, service and initiating process |
| Citrix session continuity | Retain session/cookie identifiers and alert when one authenticated session moves from a known employee address to unrelated infrastructure within minutes |
| Task/account changes | Audit Security 4698/4720/4732 and Task Scheduler operational logs |
| VMware | Forward ESXi shell, Hostd/vCenter tasks and datastore file events |
| SMB | Retain process-attributed TCP/445 and share access to expose locker-native fan-out |
| File footer | Preserve representative encrypted files so branch-specific metadata can be parsed |
| Identity | Retain help-desk reset, MFA method, session-token and privileged-role changes |
