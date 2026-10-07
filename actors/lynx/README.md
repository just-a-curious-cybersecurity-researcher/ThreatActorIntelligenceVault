# Lynx

**Presentation reviewed:** 2026-10-07.

Lynx is a financially motivated ransomware-as-a-service operation first observed in July 2024. Its operators provide affiliates with a victim-management panel, negotiation and leak infrastructure, and Windows plus multi-architecture Linux/ESXi encryptors. Public binary comparisons establish a strong code lineage with INC ransomware; they do not, by themselves, prove that both brands have always been run by the same people.

The most detailed public incident reconstruction shows a human-operated intrusion that began through exposed RDP with valid credentials, continued through account creation, network and share discovery, 7-Zip staging and browser-based exfiltration, and ended with manual backup deletion and Lynx deployment. This is one affiliate playbook, not a universal sequence.

## Quick Profile

| Field | Assessment |
|---|---|
| Name | Lynx |
| Related tracking | Water Lalawag (Trend Micro intrusion set); Storm-2113 (Microsoft affiliate activity, not the core service) |
| First observed | July 2024; affiliate recruitment advertised 2024-08-08 |
| Motivation | Financial extortion |
| Model | Ransomware-as-a-Service; 80/20 affiliate/operator split reported by Group-IB |
| Primary platforms | Windows; Linux, ESXi, NAS and multiple CPU architectures offered to affiliates |
| Encryption | AES-128 in CTR mode with Curve25519-derived key material; configurable partial or full encryption |
| Primary extension / note | `.LYNX` / `README.txt` |
| Targeting | Broad enterprise targeting; manufacturing and construction lead classified tracker data |
| Status at review | Active in 2026 tracker data; latest visible RansomLook post dated 2026-08-29 |

## Key Intelligence Judgments

**KJ-01 — High confidence.** Lynx operates as a RaaS platform. The panel, affiliate recruitment, victim-specific builds, leak scheduling and 80/20 revenue model were directly observed by Group-IB.

**KJ-02 — High confidence.** The encryptor shares substantial implementation with INC ransomware. Similarity percentages differ by sample and platform; this supports code lineage more strongly than uninterrupted organizational identity.

**KJ-03 — High confidence.** Lynx encryptors can stop processes and services, take ownership of inaccessible files, close file owners through Restart Manager, reduce shadow-copy storage, enumerate shares, mount hidden volumes, encrypt selected portions of files, change wallpaper and print notes.

**KJ-04 — Moderate confidence.** Affiliates commonly obtain access through valid credentials, exposed remote services or vulnerable edge software. Exact entry mechanics vary, and no single published CVE is established as a universal Lynx vector.

**KJ-05 — High confidence.** Leak-site posts are extortion claims, not independently verified incident totals. RansomLook and BreachSense report different counts because their snapshots, parsing and deduplication differ.

**KJ-06 — Moderate confidence.** INC, Lynx and Sinobi form a technical and infrastructure lineage. Public evidence leaves open whether Sinobi is a successor, an offshoot or another tenant using related code and infrastructure.

**KJ-07 — High confidence.** No public Lynx-specific wallet or OFAC designation was validated during this review. Chainalysis reports shared on-chain behavior with INC without publishing the underlying addresses.

## Navigation

### Intelligence

- [Overview](intelligence/overview.md)
- [Operations / Attack Lifecycle](intelligence/operations.md)
- [Ransomware executable internals](intelligence/encryptor.md)
- [Attribution & Relationships](intelligence/attribution.md)
- [Blockchain & Financial Intelligence](intelligence/blockchain.md)

### Technical

- [Tooling & Malware](technical/tooling-malware.md)
- [Known Vulnerabilities](technical/vulnerabilities.md)
- [MITRE ATT&CK Mapping](technical/mitre-attack.md)

### Defensive Reference

- [Indicators of Compromise](iocs/IOCs.md)
- [Detection Opportunities](detections/Detections.md)
- [Ransom Notes](ransom-notes/Ransom-Notes.md)
- [Source Review and Intelligence Gaps](intelligence/source-review.md)
- [References](References.md)

## Analytical Caveat

RaaS attribution must distinguish the Lynx service, a specific affiliate, a Lynx encryptor and adjacent INC/Sinobi activity. A valid Lynx sample proves payload identity; it does not automatically identify the access broker, operator or every preceding action.

## Evidence Currency

Reviewed **2026-10-07**. Tracker values are dated snapshots. Historical infrastructure and IP addresses require current enrichment before operational use.

## Structure

<!-- tree:start -->
```text
lynx/
├── detections/
│   ├── Detections.md
│   ├── KQL.md
│   ├── Lynx-Hunting.yar
│   └── Splunk.md
├── intelligence/
│   ├── attribution.md
│   ├── blockchain.md
│   ├── encryptor.md
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
