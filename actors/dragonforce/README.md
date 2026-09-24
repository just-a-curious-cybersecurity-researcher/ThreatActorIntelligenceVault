# DragonForce — Threat Actor Intelligence Dossier

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR  
**Confidence:** High for the existence of the RaaS and its published malware lineages; moderate for operator geography and individual intrusion ownership.

## Quick Profile

| Field | Assessment |
|---|---|
| Primary name | DragonForce |
| Vendor tracking | Slippery Scorpius (Unit 42, service/operator); Water Tambanakua (Trend Micro); Hackledorb (Symantec developer/operator tracking) |
| Affiliate labels that must remain separate | Muddled Libra (Unit 42), UNC3944 (Mandiant), Octo Tempest (Microsoft), Scattered Spider (CrowdStrike/public reporting), GOLD HARVEST (Secureworks) |
| First observed | Late 2023; public tracker first-seen dates vary between 2023-04-06 collection metadata and 2023-12-13 confirmed DLS capture |
| Business model | Financially motivated RaaS that evolved into a white-label and “cartel” service; reported affiliate share 80% in the 2024 recruitment model |
| State affiliation | No public evidence of state direction or sponsorship |
| Reported geography | Disputed. Malaysia appears in some vendor profiles and early hacktivist reporting; other research points toward Russian-speaking/CIS links or Northern/Central Asia |
| Platforms | Windows, Linux, VMware ESXi, NAS and RHEL; NAS/RHEL are confirmed at panel/flow level but lack sample-level hashes and paths |
| Code lineages | Early LockBit 3.0 builder derivative; maintained Conti-derived Windows/Linux core; 2026 RansomBay beta revision |
| Principal impact | Data theft, extortion, endpoint and hypervisor encryption |
| Current tracker snapshot | 652 RansomLook posts; seven in 30 days; 70 entries in the 90-day window; last post 2026-09-21 |
| Financial visibility | BTC is specified in an archived note; no public wallet set or direct DragonForce OFAC designation was located |

## Key Intelligence Judgments

- DragonForce is a service and brand, not a reliable one-to-one identity for every intrusion. An affiliate can use the locker, leak infrastructure and negotiation service while retaining its own access tradecraft.
- Scattered Spider-linked clusters have deployed DragonForce, including against VMware ESXi. That association is supported by CISA, Microsoft and Unit 42; those names are not aliases for the DragonForce operators.
- The LockBit and Conti relationships are technical lineages created by leaked code or builders. They do not prove personnel continuity.
- “Cartel” announcements involving RansomHub, LockBit and Qilin are partly service marketing. Public evidence supports infrastructure pressure, white-label offers and some transfers, but not a stable merged organization.
- Public analysis supports two materially different Windows code bases plus a maintained-builder revision that changes configuration and footer layout. Detection and recovery decisions must identify the branch before applying assumptions about algorithms, footer offsets, command-line syntax or extension.
- Tracker counts are claims observed on leak infrastructure. They are not verified incident counts and can contain reposts, partner-brand entries and later corrections.

## Navigation

- [Operational lifecycle](intelligence/operations.md)
- [Intelligence overview](intelligence/overview.md)
- [Attribution and relationships](intelligence/attribution.md)
- [Encryptor analysis index](intelligence/encryptor/README.md)
- [Blockchain and payment evidence](intelligence/blockchain.md)
- [Source review and discrepancies](intelligence/source-review.md)
- [MITRE ATT&CK mapping](technical/mitre-attack.md)
- [Tooling and malware](technical/tooling-malware.md)
- [Vulnerability review](technical/vulnerabilities.md)
- [Indicators](iocs/IOCs.md)
- [Detection index](detections/Detections.md)
- [Ransom-note archive links](ransom-notes/Ransom-Notes.md)
- [Source register](References.md)

## Analytical Caveat

Three evidence layers are kept separate throughout the dossier: the DragonForce service/operator, generic or unidentified affiliates, and named affiliate clusters such as Scattered Spider. A DLS claim establishes that a brand published a victim; it does not establish initial access, encryptor execution or data-theft success. Actor statements about partnerships, origin and victim counts are treated as claims until independently corroborated.

## Evidence Currency

Tracker figures and infrastructure status were checked on 2026-09-24. RansomLook exposed 652 posts, seven in the previous 30 days and a last post dated 2026-09-21; 70 visible entries fall between 2026-06-27 and 2026-09-21. BreachSense reported 670 victims with data updated through 2026-09-14. Infrastructure state is volatile and the IOC registers preserve observation context rather than labeling every value active.

## Structure

<!-- tree:start -->
```text
dragonforce/
├── detections/
│   ├── Detections.md
│   ├── DragonForce-Hunting.yar
│   ├── KQL.md
│   └── Splunk.md
├── intelligence/
│   ├── encryptor/
│   │   ├── conti-derived.md
│   │   ├── linux-esxi.md
│   │   ├── lockbit-derived.md
│   │   ├── panel-builder-beta.md
│   │   └── README.md
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
