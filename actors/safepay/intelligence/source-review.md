# SafePay — Source Review

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| ransomware.live SafePay and hot pages | Requested tracker sources; direct rendering failed during collection, so no current metric was inferred from them | References, notes |
| RansomLook SafePay | 574 all-time posts, 21/30d, 66/90d by dated-row count, last post 2026-09-15; degraded parser, infrastructure, emails and two notes retained | Overview, infrastructure, notes |
| RansomLook crypto | Returned no public SafePay wallet | Blockchain, blockchain-addresses |
| BreachSense | 578 total, 22/30d, 245/12m, 2026-09-16 most recent; country/sector subsets retain their denominators | Overview, victimology |
| Invaders | 245 claims since its 2025-11-12 coverage start; useful for scope differences, not all-time totals | This file |
| Halcyon | Closed-group assessment, rebound, possible former LockBit/ALPHV links, tools, hashes and IPs | Attribution, operations, IOCs |
| FortiGuard ID 6331 | Narrative supports closed operation but metadata says RaaS; its broad CVE list is retained as catalog association only | Attribution, vulnerabilities |
| Huntress | Primary source for two early incidents, command lines, process/service targets, UAC behavior and locker hash | Operations, encryptor, detections, IOCs |
| DCSO reverse engineering | Primary source for revised build, 80-byte footer, AES/ChaCha selection, config extraction, code comparison and one IR timeline | Encryptor, operations, attribution |
| DCSO GitHub | Exact mutex, exclusions, killed processes/services and analysis tooling; scripts were reviewed, not executed | Encryptor, tooling, detections |
| NCC Group | Primary IR for FortiGate policy error, ScreenConnect, QDoor, RDP/SMB, arguments, early 65-byte footer and IOCs | Operations, tooling, IOCs |
| Microsoft Defender | Family synthesis, algorithm behavior, optional persistence, note variants and network artifacts | Encryptor, operations, IOCs |
| Google Threat Intelligence Group | Two public SafePay YARA rules and 2025 ransomware context | Detections, References |
| Bitdefender / Acronis | Corroborating family hashes and DLL behavior | IOCs, encryptor |
| Blackpoint / Quorum / KPMG | Secondary/advisory cross-checks; retained where they preserve original incident IOCs or source links | References, IOC provenance |
| MITRE ATT&CK | No dedicated SafePay group or software object located; local mapping remains evidence based | MITRE mapping |
| TRM Labs | 452 claims by 2025 year-end and unnamed shared VASP cash-out overlap | Blockchain, overview |
| OFAC / Chainalysis | No public SafePay designation or actor-specific address set located | Blockchain |
| Ingram Micro | Confirms ransomware, containment and restoration; does not name SafePay or initial access in its initial statement | Timeline, cases |
| Conduent SEC filings | Confirms unauthorized access, exfiltration, response costs and notifications; does not name SafePay or confirm 8.5 TB | Timeline, cases |
| California AG / Children’s Council notice | Confirms the incident and affected population; actor attribution remains the DLS claim | Timeline, cases |
| SOCRadar / current September 2026 trackers | Ryomo, ARA Lyss and `gob.pe` retained as claims, not verified incidents | Timeline |
| MalwareBazaar, ThreatFox, OTX and URLhaus | Reviewed as discovery sources; no bulk community-tag import without original provenance | IOC registers |
| Sygnia | Primary 2025 IR case: FortiGate/VPN entry, domain-admin escalation, discovery bundle, Veeam credential access, Run-key deployment, OneDrive exfiltration and case-scoped IOCs | Operations, tooling, ATT&CK, IOCs, detections |
| Triskele Labs | Direct SafePay-related response evidence: VPN/RDG exposure, RDP, AnyDesk, Proton VPN/Mullvad, RDP clipboard and transfer over the original VPN | Operations, tooling, ATT&CK |
| Check Point | Targeting and activity context retained; expected VPN exploitation is not treated as incident proof | Overview, attribution |
| Xcitium | Technical synthesis used to corroborate API, process and service behavior where it agrees with primary reversing | Encryptor, tooling |
| UK OFSI / EU cyber lists | Current sanctions context reviewed; no SafePay-named designation located | Blockchain, sanctions assessment |

## Analytical Decisions

### Closed group versus RaaS

The DLS says SafePay does not provide RaaS. Huntress, DCSO, Microsoft, Halcyon and TRM describe centralized or non-affiliate operation. FortiGuard’s metadata and some market reports use RaaS. The dossier records a closed operation with possible brokers or external services; no public affiliate panel, recruitment post or split was located.

### LockBit code versus LockBit organization

Huntress describes extensive overlap with leaked LockBit Black. DCSO identifies architectural similarities but materially different ECC, KDF, CRC and configuration design and assesses independent development. The strongest conclusion is technical influence or selective reuse. Personnel continuity remains unproven.

### Tracker totals and last seen

RansomLook’s 574 and BreachSense’s 578 were captured within one day of each other. Their 21 versus 22 30-day totals and 2026-09-15 versus 2026-09-16 last-seen dates are compatible with parser, timezone and collection differences. Invaders begins in November 2025 and cannot be compared as an all-time total.

### Conduent figures

SafePay claimed 8.5 TB. Corporate filings confirm exfiltration but not that volume. Public affected-person totals progressed through roughly 10.5 million and 25.9 million before an HHS-derived figure of 62,224,658 appeared. These figures reflect evolving notifications and overlapping client datasets; they are not three separately compromised networks.

### CVE handling

NCC’s case is a policy misconfiguration plus weak credentials, not a demonstrated FortiGate exploit. FortiGuard’s CVE list is a vendor association catalog. Unless an IR source ties exploitation to a SafePay chain, entries remain qualified and are not presented as confirmed initial-access methods.

Sygnia later described a FortiGate flaw together with a misconfigured, weak, non-MFA administrative account but did not identify a CVE. This independently reinforces the edge-control failure pattern; it still does not justify assigning a named Fortinet vulnerability.

### Exfiltration channels

Sygnia directly observed SafePay switch from blocked FileZilla traffic to an attacker-controlled OneDrive for Business tenant. Triskele observed FileZilla in one case and transfer through the same VPN channel in another. Huntress saw FileZilla execution without packet proof, while DCSO measured 450 GB leaving through an unidentified channel. These are separate case outcomes. OneDrive, FTP/SFTP, Rclone, RDP clipboard and direct VPN transfer are documented options rather than mandatory stages.

### Expanded hash sets

ThreatLocker, TEHTRIS and KPMG publish larger SafePay-associated digest sets. The advisory lists do not assign every value to a locker, loader or supporting component. Named incident artifacts retain high-confidence roles; all other values remain vendor-published associated samples with moderate confidence and must not be used alone for actor attribution.

### IOC handling

Exact samples and incident infrastructure retain source and scope. RMM names, workstations and filenames are not global indicators. Onion status is an observation at cutoff. No wallet is inserted without a published address and attribution basis.

## Prioritized Intelligence Gaps

| Gap | Why it matters | Evidence needed |
|---|---|---|
| Operator identity and location | Tests Eastern Europe and rebrand hypotheses | Legal records, seized panel, authenticated communications or infrastructure ownership |
| Closed-team boundaries | Distinguishes core operators from brokers and contractors | Panel records, affiliate rules, payment splits or repeated access-provider mapping |
| Build chronology | Determines footer, language guard and algorithm behavior | Dated samples with hashes, configs and victim IDs |
| Linux/ESXi capability | Prevents assuming a platform branch from VM impact | Native sample and reverse-engineering report |
| Payment cluster | Enables flow tracing and sanctions screening | Victim address, transaction ID and authoritative attribution |
| CVE-to-case mapping | Improves patch prioritization | IR logs showing exploit requests and downstream SafePay deployment |
| Claim verification | Measures real impact | Victim/regulator confirmation and matched incident dates |

## Additional Findings After Original-Source Review

- The revised DCSO sample removed the early language guard and expanded the footer from 65 to 80 bytes.
- DCSO’s exact configuration output resolves NCC’s apparent “targeted extensions” list as ignored extensions; treating it as an encryption target list would invert the behavior.
- NCC’s statement that hypervisors were encrypted does not demonstrate an ESXi-native locker. DCSO separately observed encryption inside guest VMs despite hypervisor privileges.
- Microsoft’s actor page aggregates optional Run-key persistence, wallpaper behavior and multiple infrastructure observations. Those elements are retained as observed variants rather than mandatory family behavior.
- GTIG published two SafePay YARA rules in March 2026, providing a public vendor baseline beyond string-only local hunts.
- TRM’s shared VASP endpoint is meaningful financial overlap, but the missing public address prevents independent reproduction and IOC publication.
- Sygnia’s incident establishes OneDrive/SharePoint Online as a completed exfiltration path and adds ten case-scoped network indicators, named discovery artifacts and Run-key execution evidence.
- Triskele’s direct response expands the access and egress picture to RDG, AnyDesk, Proton VPN, Mullvad, RDP clipboard and transfer over the original VPN session.
