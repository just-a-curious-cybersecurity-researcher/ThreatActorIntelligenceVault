# LockBit

**Presentation reviewed:** 2026-09-21.

LockBit is a financially motivated ransomware operation and malware family first observed as ABCD in 2019. Its Ransomware-as-a-Service model combines affiliate intrusions with centrally supplied encryptors, negotiation and publication infrastructure, and data-transfer tooling. CrowdStrike tracks the operation as **BITWISE SPIDER**.

The dossier separates original LockBit, Red / 2.0, Black / 3.0, Green, NG-Dev, the 2024 possible impostors, native 4.0 and 5.0. Published reverse engineering supports separate analyses of each documented branch. Capabilities vary by sample and configuration; affiliate scripts are distinguished from executable routines.

## Quick Profile

| Field | Assessment |
|---|---|
| Name | LockBit |
| Vendor alias | BITWISE SPIDER (CrowdStrike) |
| First observed | 2019-09 as ABCD; LockBit branding in 2020 |
| Motivation | Financial |
| Model | Ransomware-as-a-Service; encryption and data-theft extortion |
| Primary platforms | Windows; separate Linux and ESXi encryptors |
| Primary regions in collected reporting | Global, with substantial reporting from North America and Europe |
| Common target sectors | Healthcare, manufacturing, finance, education, government and critical infrastructure |
| Suspected nexus | Russian-speaking criminal ecosystem; named individuals attributed by authorities |
| Status | Post-Cronos activity and 5.0 payloads documented in the collected 2025–2026 reporting |

## Key Intelligence Judgments

**KJ-01 — High confidence.** Affiliate intrusions use multiple access routes, including compromised credentials, exposed remote services and exploited edge systems. The service does not have one compulsory intrusion sequence.

**KJ-02 — High confidence.** LockBit's development history contains overlapping branches. Version names alone cannot establish cryptography, persistence, output format or deployment features; these require sample-specific evidence.

**KJ-03 — High confidence.** The Black builder leak materially weakens the link between a LockBit-family payload and membership of the LockBit service. An exact file match identifies bytes, not the operator who deployed them.

**KJ-04 — High confidence.** Operation Cronos disrupted infrastructure in 2024. Subsequent releases and extortion claims demonstrate continued activity in public reporting, without establishing continuity of every affiliate, server or business arrangement.

**KJ-05 — Moderate confidence.** Financial reporting supports a developer/affiliate revenue model and named sanctioned actors. An exchange relationship, a downstream transfer or a wallet embedded in a possible impostor note does not establish control by the core service.

**KJ-06 — High confidence.** Defensive triage benefits from combining file-impact evidence with process, policy, service and transfer telemetry. Generic administration tools, note branding and hexadecimal extensions are insufficient on their own for attribution.

## Navigation

### Intelligence

- [Overview](intelligence/overview.md)
- [Operations / Attack Lifecycle](intelligence/operations.md)
- [Ransomware executable internals by version](intelligence/encryptor/README.md)
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

LockBit malware, affiliates and the service organization are distinct attribution objects. Published binary analyses support capabilities of particular samples; advisories support particular intrusion observations. Neither establishes that every affiliate follows every documented step. Criminal allegations retain the legal status stated by their source.

## Evidence Currency

The initial source collection was reviewed **2026-09-17**, with executable and intrusion-lifecycle research expanded **2026-09-21**. Presentation and local validation were completed **2026-09-21**. This dossier synthesizes the supplied bibliography and additional public research, including 2025–2026 reporting. It is not live infrastructure monitoring. Confidence applies to each proposition. The [source review](intelligence/source-review.md) records material corrections, discrepancies and source-access limits.

## Structure

<!-- tree:start -->
```text
lockbit/
├── detections/
│   ├── Detections.md
│   ├── KQL.md
│   ├── LockBit-Hunting.yar
│   └── Splunk.md
├── intelligence/
│   ├── encryptor/
│   │   ├── lockbit-1.md
│   │   ├── lockbit-2.md
│   │   ├── lockbit-3.md
│   │   ├── lockbit-4-impostors.md
│   │   ├── lockbit-4.md
│   │   ├── lockbit-5.md
│   │   ├── lockbit-green.md
│   │   ├── lockbit-ng-dev.md
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
