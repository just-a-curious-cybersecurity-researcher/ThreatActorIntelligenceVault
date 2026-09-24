# DragonForce — Source Review

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| ransomware.live DragonForce | 652 claimed victims, first confirmed capture 2023-12-13 and last discovery 2026-09-20; retained as tracker observation | Overview, References |
| RansomLook DragonForce | 652 all-time posts, 7/30d, 1/7d, 70/90d by dated-row count, last post 2026-09-21; two notes and infrastructure inventory | Overview, notes, infrastructure |
| BreachSense DragonForce | 670 total, 11/30d and 380/12 months through 2026-09-14; sector/country subsets retained with denominators | Overview |
| RansomLook crypto | Returned no public wallet; used to define the financial gap | Blockchain, blockchain-addresses |
| SOCRadar | Current public card exposed a count near 390 but limited methodology; retained only for discrepancy analysis | This file |
| FortiGuard actor card | Useful actor summary and large CVE catalog; Malaysia/hacktivism fields can conflate the ransomware service with DragonForce Malaysia | Attribution, vulnerabilities |
| MITRE ATT&CK search | No dedicated DragonForce group or software object located; local mapping is evidence based | MITRE mapping |
| Trend Micro / TrendAI spotlight | Detailed tools, arguments, Linux/ESXi behavior and reported exploit associations; used with sample/case boundaries | Operations, encryptors, tooling |
| CrowdStrike searches | Public Scattered Spider reporting informs the affiliate relationship; no distinct public DragonForce-core name confirmed | Attribution |
| Microsoft Octo Tempest | Officially documents Octo Tempest deployment of DragonForce and VMware ESXi targeting | Attribution, operations |
| Mandiant UNC3944 | At 2025-05-06 GTIG had not independently confirmed the UK retail attribution; date-scoped caveat retained | Attribution |
| CISA Scattered Spider advisory | Later update explicitly includes possible DragonForce deployment and ESXi encryption | Attribution, operations |
| Unit 42 Slippery Scorpius | Separates ransomware operator from Malaysian hacktivist; describes white-label/service model | Attribution, overview |
| Unit 42 Muddled Libra | Provides affiliate intrusion and exfiltration evidence | Operations |
| Secureworks/Sophos cartel analysis | Supports GOLD HARVEST deployment reporting and challenges the “cartel” framing | Attribution |
| Sophos SimpleHelp IR | Medium-confidence exploitation of three SimpleHelp CVEs and downstream DragonForce deployment | Operations, vulnerabilities |
| Huntress CitrixBleed 2 IR | High-confidence broker exploitation of CVE-2025-5777; one chain ended in DragonForce; detailed artifacts retained | Operations, IOCs, detections |
| Symantec Backdoor.Turn | Detailed Hackledorb-associated campaign, drivers, side-loading, TURN/QUIC backdoor and campaign IOCs | Operations, tooling, IOCs |
| S2W Conti-derived analysis | Primary reverse-engineering basis for Windows code, algorithms, footer, decryptor and hashes | Encryptor, IOCs |
| S2W 2026 ecosystem/panel analysis | Separates the revised RansomBay builder, `encryption_rules`, 537-byte footer, removal of LockBit output and confirmed Linux/NAS/RHEL/ESXi roles | Encryptors, overview, operations |
| Group-IB panel infiltration | Establishes the 80/20 split, team permissions, client/build/publication workflow and earlier dual-builder configuration | Attribution, overview, encryptors |
| Cyble LockBit comparison | Binary-diff evidence and public hash/YARA for LockBit-derived branch | Encryptor, IOCs, detections |
| SentinelOne DragonForce profile | Useful timeline, hashes and public claims; Malaysia linkage treated as disputed | Attribution, IOCs |
| Check Point quarterly reports | Victim trend and cartel-size assessment; not used as proof of individual compromises | Timeline |
| ZeroFox Backdoor.Turn flash report | Corroborates the Teams/TURN assessment and dates the June 2026 disclosure; original Symantec analysis remains authoritative for artifacts | Operations, References |
| Decryption Digest Teams C2 article | Secondary synthesis reviewed; unsupported claims such as a universal service name and “confirmed” victim totals were not promoted | References, this file |
| CrowdStrike Scattered Spider material | Confirms CrowdStrike naming, financial motive and affiliate tradecraft; does not provide a separate DragonForce-core label | Attribution, References |
| NCA UK retail arrests | Confirms linked investigation and arrests, not service-core membership | Timeline, attribution |
| M&S corporate disclosures | Establishes incident date and £300m operating-profit impact estimate before mitigation | Timeline |
| NCSC annual review | Confirms UK disruption and Co-op data theft at national level | Timeline |
| TRM crypto crime report | Confirms inclusion in ransomware ecosystem and geographic clue; no public wallet tracing | Blockchain |
| MalwareBazaar, ThreatFox, OTX, URLhaus | Used only where a value could be tied to an original report or sample; bulk community tags were not imported | IOC registers |

## Analytical Decisions

### Tracker totals

The values `633`, `673` and `390` appeared in earlier snapshots or summaries. At the 2026-09-24 cutoff the accessible pages did not reproduce those values exactly: RansomLook and ransomware.live showed 652, BreachSense showed 670 through 2026-09-14, SOCRadar showed approximately 390 and Invaders showed 392 since 2025-10-08. RansomLook’s rolling 30-day value decreased from 11 on 2026-09-23 to 7 on 2026-09-24 without a change in the all-time total. The differences reflect snapshot date, window boundaries, collection start, parser health, partner-brand treatment and deduplication. No total is labeled the number of confirmed intrusions.

### Ransomware versus hacktivism

FortiGuard lists both financial gain and hacktivism and identifies Malaysia as suspected geography. Unit 42 explicitly says Slippery Scorpius should not be confused with the Malaysian hacktivist group. The dossier treats the ransomware service as financially motivated and preserves the shared-name problem as an attribution discrepancy.

### Affiliate versus operator

Scattered Spider-related names remain an affiliate layer. CISA, Microsoft and Unit 42 support deployment of DragonForce, but none makes UNC3944, Octo Tempest, Muddled Libra or Scattered Spider a core-service alias. Tools seen only in those cases are labeled accordingly.

### Code lineage versus organization

LockBit-builder and Conti-source reuse are confirmed technical lineages. They do not establish joint ownership or staff continuity. Alliance announcements with LockBit and Qilin remain claims unless a source demonstrates shared control or infrastructure.

### CVE handling

CitrixBleed 2 and SimpleHelp CVEs have incident-level evidence. Trend Micro’s smaller list is retained as reported DragonForce association. FortiGuard’s broader list is a catalog-only section; it is not mapped into the operational chain as observed exploitation.

### IOC handling

Hashes are split into encryptor, backdoor and supporting-tool roles. Campaign domains from Symantec and Huntress are not promoted to global service infrastructure. Scattered Spider IOCs are omitted unless the source connects them to a DragonForce-ending case.

## Prioritized Intelligence Gaps

| Gap | Why it matters | Evidence needed |
|---|---|---|
| Operator identities and location | Resolves Malaysia/CIS/Northern Asia disagreement | Legal records, seized panel data or independently authenticated communications |
| Affiliate-to-victim mapping | Prevents assigning one affiliate’s tools to all intrusions | IR timelines, panel records and negotiation identifiers |
| Public payment cluster | Enables sanctions screening and flow analysis | Victim payment address, transaction ID and authoritative tracing |
| NAS implementation | Confirms advertised platform support | Recoverable sample and reverse-engineering report |
| 2026 cartel membership | Distinguishes marketing from shared operations | Shared backend records, infrastructure control or corroborated partner communications |
| Tracker deduplication | Establishes a defensible publication count | Exported records with stable IDs and cross-tracker entity matching |

## Additional Findings After Original-Source Review

- The current 90-day RansomLook count is 70, derived from the 70 dated rows between 2026-06-27 and 2026-09-21. The site itself exposes 7-day and 30-day values but no 90-day summary.
- RansomLook marked its parser degraded because of a captcha and showed only 10% average infrastructure uptime over 30 days. A low recent count may contain collection loss.
- The two archived ransom notes reuse the same negotiation onion and Tox identity, but the second adopts explicit “Ransomware Cartel” language and income/insurance-based pricing.
- S2W’s earlier Windows encryptor appends 534 bytes because the encryption ratio occupies one byte. Its 2026 panel beta expands that field to four bytes, producing a 537-byte footer; the victim-specific `.RNP` Windows decryptor also reads 537 bytes. The ESXi recovery branch checks a separate eight-byte build key and reads 512 bytes of protected metadata. These are versioned layouts, not an unresolved source discrepancy.
- The S2W/Group-IB panel comparison shows that removal of the LockBit builder and driver selector from the interface did not remove BYOVD process termination from generated binaries. Panel options and payload capability are tracked separately.
- The S2W report supports Linux, NAS and RHEL as related builder outputs and isolates VM shutdown/environment collection to ESXi. It does not publish enough per-platform artifacts to invent NAS/RHEL hashes or paths.
- Symantec’s original IOC appendix exposes two Backdoor.Turn samples, two side-loaded DLLs, drivers, AV killers, discovery tools and archives. They are retained as one incident set rather than global DragonForce infrastructure.
- Symantec observed Backdoor.Turn after the ransomware event. Recovery validation must therefore look for continuing access rather than assuming encryption marks actor exit.
- Huntress’s 2026 Citrix cases show an access-broker boundary. Only one of the investigated chains culminated in DragonForce, so CVE-2025-5777 is a supported route but not a family-exclusive indicator.
