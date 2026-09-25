# APT29 — Source Review

**Presentation reviewed:** 2026-09-25.

Last updated: **2026-09-25**. This file records source scope, disagreements, exclusions and collection gaps. Bibliographic URLs are centralized in [References](../References.md).

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| MITRE ATT&CK G0016 | Version 6.2, modified 2026-07-31; current aliases, campaigns, software and technique evidence. T1486 is absent. | Overview; ATT&CK; tooling |
| NCSC / Five Eyes cloud advisory | Almost-certain SVR assessment; service accounts, stolen tokens, device registration and residential proxies. | Attribution; operations; detections |
| CISA / NSA / FBI SVR advisories | Public-facing CVEs, SolarWinds follow-on TTPs, Microsoft cloud identity evidence and WellMess/WellMail context. | Operations; vulnerabilities; detections |
| CISA / FBI / NSA / SKW / CERT.PL / NCSC TeamCity advisory | CVE-2023-42793 exploitation since 2023-09 and observed follow-on access. Supply-chain exposure is separated from demonstrated downstream compromise. | Overview; operations; vulnerabilities; detections |
| Microsoft CaptiveCrunch | 2026-07-31; Storm-2945 relationship, captive portals, CornFlake, ChocoShell, FruitStone, public KQL and IoCs. | Overview; operations; tooling; IOCs; detections |
| Anthropic GTG-20006 | 2026-09-10; provider-observed AI-assisted Russian espionage, qualified Midnight Blizzard linkage, targeting, tools and public IoCs. | Attribution; overview; operations; tooling; IOCs; detections |
| Check Point GRAPELOADER | 2025-04-15; APT29-attributed European diplomatic phishing, reverse engineering, exact hashes/domains and a revised WINELOADER. | Overview; operations; tooling; IOCs; detections |
| AWS watering hole | 2025-08-29; selective compromised-site redirects and device-code authorization. AWS systems were not compromised. | Overview; operations; IOCs; detections |
| Microsoft delegated administration | 2021 provider campaign; DAP, RoadTools/AADInternals and Azure Run Command establish cloud-to-on-premises and cross-tenant paths without a product vulnerability. | Operations; tooling; detections |
| Google UNC6293 / UNC7005 | 2025 report began with low-confidence APT29/ICECAP linkage; 2026 report upgraded the relation to moderate confidence with an ICE RELIC initial-access subcluster. IoCs remain qualified. | Attribution; overview; operations; tooling; IOCs; detections |
| Google UNC5976 | Google assesses this Russian cluster as distinct from UNC6293/UNC7005 and potentially aligned to other requirements. HEADRUSH and its infrastructure are excluded. | Attribution exclusion; source boundaries |
| CERT.PL / SKW diplomatic campaign | Partial-to-full overlap with NOBELIUM/APT29, not universal equivalence; adds SNOWYAMBER, HALFRIG and QUARTERRIG. | Overview; tooling; attribution caveat |
| 2024 joint SVR advisory | Confirms CVE-2022-27924 and CVE-2023-42793 exploitation; the larger table states capability and interest only. Also documents crypto-funded infrastructure leasing without wallet data. | Operations; vulnerabilities; ATT&CK; financial negative finding |
| Microsoft Storm-2372 | Original 2025 report updated 2026-07-31 to describe a Midnight Blizzard initial-access subcluster. | Operations; detections; source boundaries |
| Microsoft corporate intrusion | Late-2023 access; 2024 disclosure and response guidance. OAuth and mailbox abuse followed password spray. | Overview; operations; detections |
| Microsoft malicious RDP files | One-day 2024-10-22 campaign against thousands of users at 100+ organizations; recipient count is not compromise count. | Overview; operations; detections |
| Microsoft GoldMax / GoldFinder / Sibot | 2020 deployment, 2021 publication; malware behavior, hashes and carefully scoped domains. | Tooling; IOCs; YARA exact hash inventory |
| Microsoft FoggyWeb / MAGICWEB | Post-compromise AD FS persistence; requires prior privileged access. | Operations; tooling; detections |
| Mandiant UNC2452 merge | Firsthand evidence used to merge UNC2452 into APT29 in 2022; retained cluster label for historical precision. | Attribution; source-review |
| Mandiant SolarWinds | SUNBURST supply-chain and selective follow-on activity; distribution and hands-on victim counts kept distinct. | Overview; operations; tooling |
| Mandiant WINELOADER | 2024 German political-party campaign; ROOTSAW, compromised WordPress, certutil/tar and DLL side-loading. | Overview; tooling; IOCs; detections |
| Mandiant Tor domain fronting | Tor plus meek carried remote services through a fronted TLS path. No `.onion` hostname was published. | Operations; tooling; IOC exclusion |
| CrowdStrike COZY BEAR | Likely SVR nexus; contractor-versus-department question remains open. StellarParticle adds TrailBlazer and cloud identity evidence. | Attribution; tooling |
| ESET Operation Ghost | High-confidence Dukes attribution from code, targeting and tradecraft; historical IoCs retained as such. | Overview; tooling; IOCs |
| NCSC vaccine advisory | WellMess/WellMail, public IoCs and public YARA. | Tooling; IOCs; detections |
| Unit 42 Cloaked Ursa | Legitimate storage delivery and NATO/diplomatic targeting; source date and campaign date separated. | Operations; tooling |
| Proofpoint TA421 | Secondary cloud-app analysis using APT29/Midnight Blizzard equivalence; primary Microsoft evidence preferred for the Microsoft incident. | Source corroboration |
| Volexity device-code clusters | CozyLarch overlaps APT29 only at medium confidence; UTA0304 and UTA0307 remain separate. | Attribution exclusions; detections |
| Treasury / UK attribution | SolarWinds attributed to SVR; technology supporters sanctioned. No actor wallet list. | Attribution; financial negative finding |
| Ransomware trackers | No supported APT29 RaaS group, DLS or victim ledger located. Trackers are not used to prove state-actor identity. | Overview; source limitations |

## Analytical Decisions

- `APT29`, `Midnight Blizzard`, `NOBELIUM` and `UNC2452` are connected only through explicit government or vendor statements. Historical labels remain visible where they identify a narrower corpus.
- `Storm-2372` and `Storm-2945` are Microsoft operational subclusters. Their techniques are not assigned to every APT29 operator.
- `GTG-20006` remains an Anthropic cluster. Shared CaptiveCrunch methods and IoCs corroborate overlap, while Anthropic's wording—consistent with public reporting linking the actor to Midnight Blizzard—does not establish complete equivalence with APT29.
- `UNC6293` and `UNC7005` remain Google clusters. Google's 2026 moderate-confidence relationship is limited to an ICE RELIC initial-access subcluster; their indicators are not promoted to universal APT29 infrastructure.
- `UNC5976` is excluded. Similar OAuth abuse and Russian targeting do not override Google's explicit distinct-cluster assessment.
- Volexity's `CozyLarch` is retained as medium-confidence overlap; UTA0304 and UTA0307 indicators are excluded from the APT29 IOC corpus.
- `NikoWiper` and other publicly GRU/Sandworm-attributed wipers are excluded. No reviewed APT29 implant encrypts victim data for payment or destructive impact.
- ChocoShell's VSS behavior is recorded under credential collection and cleanup, not recovery inhibition.
- Tor domain fronting is documented in operations. No `onion-infrastructure.md` is created because no source provided an APT29-controlled onion hostname.
- No `blockchain-addresses.md` or blockchain chapter is created. Treasury sanctions and provider searches did not establish an APT29-attributed wallet, transaction graph, mixer route or payment cluster.
- Shared services such as Dropbox, Google Drive, GitHub, Trello and Microsoft Graph are not treated as malicious domains.
- TeamCity exploitation is included as actor-specific government reporting. Its access to build assets is not restated as a completed software supply-chain compromise because AA23-347A explicitly stopped short of that conclusion for the known victims.
- The 2024 advisory's capability-and-interest CVE table is not a list of confirmed APT29 exploitation. Only entries independently described as exploited are promoted into the supported table.
- Government reporting supports cryptocurrency use to lease infrastructure, but no public address, exchange account or transaction graph was supplied. No blockchain-address file is created from that procurement statement.

## Prioritized Intelligence Gaps

| Gap | Why it matters | Evidence needed |
|---|---|---|
| Storm-2945 upstream captive-portal compromise | Determines exposure and remediation beyond endpoint cleanup | Vendor/appliance forensics, management-plane logs and provider records |
| Storm-2372 and Storm-2945 operator boundary | Affects campaign attribution and identity-control prioritization | Cross-campaign infrastructure, tooling and victim-level chronology |
| Current ICE RELIC taxonomy scope | Prevents silent expansion of older APT29 claims under a new vendor name | Google taxonomy mapping with included/excluded clusters |
| UNC6293 / UNC7005 handoff boundary | Determines whether initial-access clusters transfer sessions to a separate post-compromise team | Victim-level token chronology, shared tasking infrastructure and explicit vendor mapping |
| GTG-20006 organizational boundary | Determines whether every reported tool and operation belongs to a Midnight Blizzard subcluster or a partially overlapping provider-observed actor | Independent victim telemetry, cross-campaign infrastructure and explicit vendor/government cluster mapping |
| Direct SVR staff versus contractors | Changes organizational assessment, but not immediate defensive action | Official evidence, court records or corroborated insider documentation |
| Live status of historical infrastructure | Prevents stale blocking from becoming attribution evidence | Passive DNS, certificate, hosting and sinkhole observations with dates |
| Tenant persistence after credential reset | Determines whether applications, roles, devices or federation preserve access | Entra audit, service-principal credential inventory, consent and federation history |
| Victim-specific SolarWinds follow-on scope | Separates exposed Orion customers from selected espionage victims | Verified incident reports and telemetry from each environment |
| Public financial infrastructure | Tests whether crypto was used to buy infrastructure without inventing a revenue model | Court/provider records tying an address and transaction to an APT29 operation |

## Additional Findings After Original-Source Review

Microsoft's 2026 CaptiveCrunch publication provides a rare modern endpoint-plus-identity chain and public KQL. It also supplies exclusion evidence: Microsoft distinguished this campaign from Forest Blizzard's separate 2026 DNS hijacking despite surface similarities.

Anthropic's September 2026 report extends the public record through activity observed between December 2025 and August 2026. Its GTG-20006 case overlaps CaptiveCrunch in hospitality-provider compromise, DNS manipulation, ClickFix delivery, device-code abuse and several exact indicators. The provider also reports AI-assisted malware rebuilding, cross-platform tooling, scheduled token renewal, mailbox and cloud collection, and more than 20 organizations in planning, reconnaissance or live operations. These are retained as campaign-scoped findings because Anthropic used qualified attribution language.

Current MITRE includes UNC3524 as an APT29 alias and reflects cloud-native procedures such as additional application credentials, roles, device registration, application tokens and remote email collection. These mappings support cloud-first hunts but do not prove that an event belongs to APT29.

Google’s 2026 use of `ICE RELIC (formerly known as APT29)` is treated as a naming update. The source discussed supply-chain defense and cited SolarWinds; it did not announce a new 2026 APT29 supply-chain compromise.

Google's August 2026 report adds a more precise boundary than the earlier naming reference. It relates UNC6293 and UNC7005 to an ICE RELIC initial-access subcluster with moderate confidence, notes distinct infrastructure and operational-security practices, and excludes UNC5976. This supersedes the low-confidence APT29/ICECAP wording in Google's June 2025 UNC6293 report without turning either cluster into a full alias.

The 2025 Check Point campaign closes a technical gap between 2024 WINELOADER reporting and cloud-centric 2026 operations. The publication exposes the complete three-file side-loading bundle, Run-key persistence, host profiling, shellcode execution sequence, RC4-based WINELOADER internals, anomalous user agent and seven exact SHA-256 values.

AWS's watering-hole reporting and Microsoft's CaptiveCrunch reporting describe two different campaign windows and access paths. AWS observed opportunistic compromised-site redirects in 2025; Microsoft observed hospitality captive-portal traffic manipulation by Storm-2945 in 2026. Shared device-code objectives do not make the upstream compromises identical.

No reviewed source supports an APT29 encryptor, ransomware extension, ransom note, wallet or actor-operated onion service. Those files are omitted rather than populated with generic placeholders or unrelated Russian activity.
