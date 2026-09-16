# Qilin / Agenda

**Presentation reviewed:** 2026-09-15.

Qilin is a financially motivated ransomware-as-a-service program associated with the earlier Agenda name. Its Go/Rust encryptors and supporting infrastructure serve affiliates whose intrusion methods differ. This dossier traces the program's evolution while separating core operators, malware families and deployment clusters. Reviewed **2026-09-11**.

## Quick Profile

| Field | Assessment |
|---|---|
| Name | Qilin / Agenda |
| Vendor alias | REVENANT SPIDER (CrowdStrike); Water Galura (TrendAI); boundaries qualified in attribution |
| First observed | Mid-2022; operator, probable incident, public analysis and branding dates differ |
| Motivation | Financial |
| Model | Ransomware-as-a-Service with configurable builders and extortion support |
| Primary platforms | Windows and separate Linux/ESXi payloads; newer Nutanix checks are capability evidence |
| Primary regions in collected reporting | Global; United States, Canada, UK, France and Germany prominent in reviewed populations |
| Common target sectors | Manufacturing, professional services, healthcare, education and others; SMEs/cloud providers in Italian reporting |
| Suspected nexus | Moderate Confidence Russian-speaking criminal ecosystem; nationality, location and state control unestablished |
| Status | Active in the collected reporting; source-bounded rather than live monitoring |

## Key Intelligence Judgments

**KJ-01 — High Confidence.** Valid accounts, exposed infrastructure and targeted phishing are documented access paths. [Operations](intelligence/operations.md#2-initial-access)

**KJ-02 — High Confidence.** Credential collection, AD discovery, lateral movement, recovery impairment and ransomware deployment recur, with different order and scope across affiliates. [Attack lifecycle](intelligence/operations.md)

**KJ-03 — High Confidence.** Legitimate RMM, administration and transfer tools are extensively abused. Product names alone are weak attribution signals. [Tooling](technical/tooling-malware.md)

**KJ-04 — Moderate Confidence.** State/criminal clusters deploying Qilin and migration between RaaS programs do not establish common program ownership. [Relationships](intelligence/attribution.md)

**KJ-05 — Moderate Confidence.** Russian-language recruitment and related indicators support a criminal-ecosystem nexus, not universal nationality or physical location. [Geographic nexus](intelligence/attribution.md#geographic-nexus)

**KJ-06 — High Confidence.** Qilin combines encryption with disclosure pressure; management-plane and central-share access can amplify impact beyond the executing host. [Operations](intelligence/operations.md#13-ransomware-deployment-and-impact)

**KJ-07 — Moderate Confidence.** AudiA6 and FirstVPN reporting establishes service relationships. [Financial analysis](intelligence/blockchain.md)

## Navigation

### Intelligence

- [Overview and timeline](intelligence/overview.md)
- [Operations / Attack Lifecycle](intelligence/operations.md)
- [Ransomware executable internals](intelligence/encryptor.md)
- [Attribution and relationships](intelligence/attribution.md)
- [Blockchain and financial intelligence](intelligence/blockchain.md)
- [Source review](intelligence/source-review.md)

### Technical

- [Tooling and malware](technical/tooling-malware.md)
- [Vulnerabilities and access conditions](technical/vulnerabilities.md)
- [MITRE ATT&CK mapping](technical/mitre-attack.md)

### Defensive Reference

- [IOCs](iocs/IOCs.md)
- [Detections](detections/Detections.md)
- [Ransom notes](ransom-notes/Ransom-Notes.md)
- [References](References.md)

## Analytical Caveat

This is a public-source dossier, not live monitoring. No actor-controlled service or stolen-data corpus was accessed. Return to [actor index](../README.md).

## Evidence Currency

Presentation and operational evidence reviewed **2026-09-11**. Individual observations keep their original dates; financial screening remains the September 10 snapshot. See [Source Review](intelligence/source-review.md) for added research.

## Structure

<!-- tree:start -->
```text
qilin/
├── detections/
│   ├── Detections.md
│   ├── KQL.md
│   ├── Qilin-Hunting.yar
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
