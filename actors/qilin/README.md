# Qilin / Agenda

Qilin is a financially motivated ransomware-as-a-service program associated with the earlier Agenda name. Its Go/Rust encryptors and supporting infrastructure serve affiliates whose intrusion methods differ. This dossier traces the program's evolution while separating core operators, malware families and deployment clusters. Reviewed **2026-09-10**.

## Quick Profile

| Field | Evidence-based description |
|---|---|
| Names | Qilin / Agenda; REVENANT SPIDER (CrowdStrike), Water Galura (TrendAI); scope qualified in attribution |
| First observed | Mid-2022; June operator/probable-case reporting, August public Go analysis and August–September rebrand assessment |
| Motivation / model | Financial extortion; RaaS with configurable payloads and negotiation/publication support |
| Platforms | Windows; separate Linux/ESXi payloads; newer Nutanix checks are capability evidence |
| Victimology | Global, varying by affiliate; healthcare/education in early samples, manufacturing/services prominent later; SMEs and cloud providers in Italian 2026 reporting |
| Suspected nexus | Moderate Confidence Russian-speaking criminal ecosystem; no universal nationality/location or state-control conclusion |
| Financial visibility | Service relationships to AudiA6 and FirstVPN; no validated direct victim-payment/treasury address in the reviewed public inventory |

## Key Intelligence Judgments

**KJ-01 — High Confidence:** affiliate and sample variability matters. Panel evidence and distinct incident chains show that one universal Qilin playbook would misrepresent the operation. [RaaS and cases](intelligence/operations.md)

**KJ-02 — High Confidence:** identity and management infrastructure can amplify impact. GPO credential collection, MSP RMM access and centralized share/hypervisor deployment create exposure beyond a single endpoint. [Technical analysis](technical/tooling-malware.md)

**KJ-03 — Moderate Confidence:** Russian-language recruitment and related technical evidence support an ecosystem nexus, while named state or criminal groups using Qilin remain separate deployment relationships. [Attribution and alternatives](intelligence/attribution.md)

**KJ-04 — Moderate Confidence:** the public financial evidence supports use of third-party services. Official FirstVPN wallet attribution does not establish Qilin's control of those wallets; the exact purchase address and treasury remain unknown. [Financial analysis](intelligence/blockchain.md)

## Navigation

### Intelligence

- [Overview and timeline](intelligence/overview.md)
- [Operations and campaigns](intelligence/operations.md)
- [Attribution and relationships](intelligence/attribution.md)
- [Blockchain and financial intelligence](intelligence/blockchain.md)
- [Source review and intelligence gaps](intelligence/source-review.md)

### Technical

- [Tooling and malware](technical/tooling-malware.md)
- [Vulnerabilities and access conditions](technical/vulnerabilities.md)
- [MITRE ATT&CK mapping](technical/mitre-attack.md)

### Defensive Reference

- [IOCs](iocs/IOCs.md)
- [Detections](detections/Detections.md)
- [Ransom notes](ransom-notes/Ransom-Notes.md)
- [References](References.md)

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
│   ├── agenda.md
│   ├── linux.md
│   ├── qilin-2025.md
│   ├── qilin-media.md
│   ├── qilin.md
│   └── Ransom-Notes.md
├── technical/
│   ├── mitre-attack.md
│   ├── tooling-malware.md
│   └── vulnerabilities.md
├── README.md
└── References.md
```
<!-- tree:end -->

## Analytical Caveat

This is a public-source dossier, not live monitoring. No actor-controlled service or stolen-data corpus was accessed. Unsupported claim details, precise treasury identities and unobserved WSL execution remain documented gaps. Return to [actor index](../README.md).
