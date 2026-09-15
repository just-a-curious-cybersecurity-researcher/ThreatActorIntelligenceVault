# APT28 / Fancy Bear

**Presentation reviewed:** 2026-09-15.

APT28 is a cyberespionage intrusion set associated in public government assessments with Russia's military intelligence service. The NCSC assesses that it is almost certainly GRU Military Unit 26165, the 85th Main Special Service Centre (GTsSS). Vendor clusters overlap but are not guaranteed to describe identical operator populations.

The dossier follows the Akira/Qilin file and section conventions. Espionage, credential theft, hack-and-leak activity and destructive capability are distinguished. Detection files include populated procedures only, with copyable queries and rules. Intelligence review cutoff: **2026-09-14**; detection expansion: **2026-09-15**.

## Quick Profile

| Field | Assessment |
|---|---|
| Name | APT28 / Fancy Bear |
| Vendor alias | Forest Blizzard / STRONTIUM; Sofacy; Sednit; Pawn Storm; Tsar Team; Fighting Ursa; FROZENLAKE. CERT-UA: UAC-0001. Unit attribution: 26165 / 85th GTsSS. See [scope table](intelligence/attribution.md#names-and-scope). |
| First observed | At least 2004 in ESET/NCSC retrospective reporting; FireEye's 2014 analysis documented activity since at least 2007. These are visibility bounds. |
| Motivation | Military, political and diplomatic intelligence; selected influence/disruption operations. |
| Model | State-directed operations in official attribution; no evidenced RaaS affiliate marketplace. |
| Primary platforms | Windows and email/cloud identities; documented Linux, network-device and historical firmware tooling. |
| Primary regions in collected reporting | Ukraine; European/NATO countries; North America; additional diplomatic/government targets worldwide. |
| Common target sectors | Government, military, diplomacy, defense suppliers, logistics, technology, energy, media and anti-doping organizations. |
| Suspected nexus | Russia / GRU Unit 26165, according to named government sources; unit identity is not independently verified internal knowledge. |
| Status | Active in 2026 reporting, including Office exploitation, paired cloud implants, DNS hijacking and HOOKEDGE revisions. |

## Key Intelligence Judgments

**KJ-01 — High Confidence.** APT28 remains a significant espionage threat to organizations supporting Ukraine and to diplomatic and defense networks. This assessment combines official targeting warnings with distinct vendor investigations; it is not a numerical likelihood for every organization.

**KJ-02 — High Confidence.** Email and identity collection are recurring objectives. Outlook exploitation, malicious Outlook components and router-mediated interception require endpoint, identity and network evidence together.

**KJ-03 — High Confidence.** The intrusion set combines custom implants with ordinary scripts and legitimate services. A familiar executable or cloud domain alone cannot establish attribution.

**KJ-04 — Moderate Confidence.** Parallel cloud implants and selective follow-on tasking favor continued collection after initial compromise. This is an assessment of published cases, not a universal deployment pattern.

**KJ-05 — High Confidence.** Cryptocurrency-funded infrastructure has public judicial and provider evidence. It does not establish ransom income, an affiliate split or a relationship with Qilin/LockBit.

**KJ-06 — High Confidence.** Unit 26165 and Unit 74455 have documented cooperation in charging allegations, but they are not interchangeable. The 2018 Winter Olympics destructive attack belongs to the Unit 74455 case.

**KJ-07 — Moderate Confidence.** APT28's 2026 threat includes possible destructive consequences alongside espionage: Trend reports a destructive command in its campaign analysis. That does not demonstrate ransomware deployment or justify assigning Sandworm's wipers to APT28.

## Navigation

### Intelligence

- [Overview, dated evolution and victimology](intelligence/overview.md)
- [Operations and attack lifecycle](intelligence/operations.md)
- [Attribution and relationships](intelligence/attribution.md)
- [Blockchain and financial intelligence](intelligence/blockchain.md)
- [Source review, assessment and gaps](intelligence/source-review.md)

### Technical

- [Tooling and malware](technical/tooling-malware.md)
- [Vulnerabilities and exposed infrastructure](technical/vulnerabilities.md)
- [MITRE ATT&CK evidence mapping](technical/mitre-attack.md)

### Defensive Reference

- [Indicators of compromise](iocs/IOCs.md)
- [Published detections and hunting](detections/Detections.md)
- [Ransom notes — applicability](ransom-notes/Ransom-Notes.md)
- [References](References.md)

## Analytical Caveat

Incident dates, report dates and source updates are different fields. A public indicator is a historical observation unless its current use is demonstrated. Attribution confidence, source confidence and detection specificity are separate judgments. Source disagreements remain visible.

## Evidence Currency

Last updated: **2026-09-14**. Public-source dossier; no access to private vendor telemetry, victim systems or actor infrastructure. Public reporting is not an exhaustive census. Source-native TLP markings are preserved; the repository does not relabel third-party restricted material. The [source review](intelligence/source-review.md) records unavailable sources and bounded negative findings.

## Structure

<!-- tree:start -->
```text
apt28 - Fancy Bear/
├── detections/
│   ├── APT28-Hunting.yar
│   ├── Detections.md
│   ├── KQL.md
│   └── Splunk.md
├── intelligence/
│   ├── attribution.md
│   ├── blockchain.md
│   ├── operations.md
│   ├── overview.md
│   └── source-review.md
├── iocs/
│   ├── blockchain-addresses.md
│   ├── domains.md
│   ├── extensions.md
│   ├── file-artifacts.md
│   ├── file-patterns.md
│   ├── hash-provenance.md
│   ├── hashes.md
│   ├── IOCs.md
│   ├── ip-addresses.md
│   └── onion-infrastructure.md
├── ransom-notes/
│   └── Ransom-Notes.md
├── technical/
│   ├── mitre-attack.md
│   ├── tooling-malware.md
│   └── vulnerabilities.md
├── README.md
└── References.md
```
<!-- tree:end -->
