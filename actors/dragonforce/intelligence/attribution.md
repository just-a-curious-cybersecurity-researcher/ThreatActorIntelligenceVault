# DragonForce — Attribution

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Evidence Classes and Confidence

- **Government advisory or court/law-enforcement notice:** used for named affiliate deployment, incident linkage, arrests and public defensive guidance. Confidence is high for what the authority states and is not expanded to unnamed incidents.
- **Incident response and malware reverse engineering:** used for intrusion chains, tools, algorithms, configuration and artifacts. Confidence is high for the analyzed case/sample and moderate when generalized.
- **DLS and actor statements:** used to establish recruitment, alliance, victim and policy claims. They do not independently validate the claim.
- **Tracker observation:** high confidence for the date/content observed, low confidence for victim verification.
- **Secondary aggregation:** retained as a discovery lead and cross-check, never used alone for high-confidence attribution.

## Names and Scope

| Label | Source and scope | Limitation |
|---|---|---|
| DragonForce | RaaS/service brand, encryptor branding and DLS identity | May represent core service, affiliate or white-label customer |
| Slippery Scorpius | Unit 42 tracking for the group behind DragonForce ransomware | Unit 42 explicitly distinguishes it from the Malaysian hacktivist group |
| Water Tambanakua | Trend Micro tracking for DragonForce ransomware activity | Vendor-scoped cluster; not necessarily every affiliate |
| Hackledorb | Symantec tracking for the DragonForce developer/operator associated with Backdoor.Turn | Applied to Symantec’s observed cluster and tooling |
| Ransom:Win32/DragonForce!rfn | Microsoft Defender malware detection name | Malware classification, not an actor name |
| Muddled Libra / UNC3944 / Octo Tempest / Scattered Spider / GOLD HARVEST | Vendor names for an affiliate ecosystem reported deploying DragonForce | Must not be treated as DragonForce aliases |
| DragonForce Malaysia | Separate hacktivist identity in older public reporting | Shared branding does not prove common operators |

CrowdStrike public material uses SCATTERED SPIDER for the affiliate cluster. Mandiant uses UNC3944, Microsoft uses Octo Tempest and Unit 42 uses Muddled Libra. No distinct public CrowdStrike or Mandiant name for the DragonForce core service was confirmed. MITRE did not expose a dedicated DragonForce group/software object at the cutoff.

## Geographic Nexus

The geographic attribution is unresolved. FortiGuard and some early vendor profiles list Malaysia, apparently influenced by DragonForce Malaysia branding. Unit 42 rejects conflation of the ransomware operator with that hacktivist group, and the hacktivist identity publicly denied the association. Belgium’s CCB notes exclusions affecting CIS/Russian organizations as a possible Russia/CIS signal. TRM reports that leaked audio was assessed as consistent with Northern or Central Asia.

None of those data points identifies an operator location with high confidence. Language, victim exclusions and branding can be selected operationally. The defensible assessment is a transnational cybercrime service with disputed operator geography.

## Relationships and Alternative Hypotheses

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| Scattered Spider ecosystem | CISA says recent Scattered Spider incidents may deploy DragonForce; Microsoft documented Octo Tempest use against ESXi; Unit 42 links Muddled Libra to Slippery Scorpius | Verified affiliate/deployer relationship. The affiliate and RaaS operators remain separate |
| LockBit | Early locker built from leaked LockBit 3.0 builder; high binary similarity; later public alliance claim | Confirmed code lineage, actor-level alliance only partly corroborated |
| Conti | Later Windows branch reuses Conti-derived design and code | Technical inheritance from leaked source; no proof that Conti personnel operate DragonForce |
| RansomHub | DragonForce claimed partnership/transfer; DLS/infrastructure changes followed disruption | Transfer is plausible; reporting disagrees between voluntary partnership and hostile seizure |
| Qilin | Public alliance announcement in September 2025 | Marketing claim; no public evidence of a merged operator set |
| BlackLock / Mamona | DLS compromise and note/code similarities were reported | Rivalry and reuse are stronger explanations than ordinary collaboration |
| Devman | Affiliate/partner separation and competing service activity in 2025 | Supported organizational fracture; exact access to infrastructure and code remains unclear |
| ShinyHunters / Coinbase Cartel | DragonForce initially presented the name as a subbrand; later research linked activity to ShinyHunters | Branding claim does not establish control by DragonForce |
| State or intelligence service | No public operational or legal evidence | Assessed financially motivated crime |

Group-IB’s access to the affiliate panel supports a commercial separation between service and intrusion team. Each partner receives an individual onion entry point, a chief administrator can create lower-privileged team accounts, and the client record ties the build creator to ransom and publication state. S2W later observed eight panel areas covering client/build management, team coordination, publication and support. Those controls support a managed RaaS platform; they do not reveal legal identities or prove that the core operator directed each intrusion.

Mandiant stated on 2025-05-06 that public reporting resembled Scattered Spider activity in the UK retail cases but GTIG had not then independently confirmed it. Later Microsoft and CISA reporting supports the broader deployment relationship. The date difference explains the apparent disagreement.

## Decision Use

Analysts should attribute at the narrowest defensible layer. A DragonForce note, extension or locker hash supports malware/service identification. Help-desk social engineering, SIM-related access or cloud identity abuse supports a Scattered Spider-style hypothesis only when case evidence also links the cluster. LockBit-like code supports builder lineage, not LockBit operator ownership.

Containment should therefore use behavior and case artifacts first. Public actor names are useful for enrichment and prioritization after technical scope is established.

## Official Organizational Evidence and Limits

No indictment, sanctions notice or government statement publicly names a DragonForce operator hierarchy. The UK arrests relate to three retail intrusions and remain allegations. CISA describes Scattered Spider deployment behavior, not membership in DragonForce core. The service’s RAMP posts, interviews and DLS announcements reveal commercial positioning but are self-authored.

The best-supported organizational model is a service/operator layer running RansomBay, builders, victim records and publication/negotiation infrastructure for changing affiliates and white-label customers. “Cartel” is retained as the service’s term and as a market model; it is not treated as proof of centralized control over Qilin, LockBit, RansomHub or Scattered Spider.
