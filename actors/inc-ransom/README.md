# INC Ransom — Actor Profile

**Presentation reviewed:** 2026-09-22.

## Quick Profile

| Field | Assessment |
|---|---|
| Primary name | INC Ransom / Incransom |
| Type / motivation | Financially motivated ransomware and data extortion; current RaaS model |
| Emergence | Mid-2023; incident, sample and leak-post dates differ |
| Tracking | MITRE G1032; software S1139; GOLD IONIC, Tarnished Scorpion, Water Anito in their respective source scopes |
| Target environment | Windows networks and Linux/ESXi infrastructure |
| Targeting | Healthcare, education, industry, public bodies and professional services |
| Main effect | Data theft, encryption, recovery disruption and disclosure pressure |
| Technical focus | Classic versus Rust implementations, partial encryption and recovery metadata |
| Review cutoff | 2026-09-22; publication and incident dates preserved separately |

## Key Intelligence Judgments

INC is an intrusion-and-extortion ecosystem, not just an executable. Affiliate tools, cloud exfiltration and payload-internal actions must remain distinct.

Classic and Rust payloads require separate cryptographic and file-format descriptions. Footer analysis can help evaluate recovery; it does not provide a universal decryption key.

INC/Lynx/Sinobi relationships have technical and financial evidence, but do not justify merging their operators, wallet ownership or IOC sets.

## Navigation

- [Overview and timeline](intelligence/overview.md), [attribution](intelligence/attribution.md) and [source review](intelligence/source-review.md).
- [Operational lifecycle](intelligence/operations.md).
- [Detailed encryptor analysis](intelligence/encryptor.md).
- [Blockchain and financial intelligence](intelligence/blockchain.md).
- [MITRE ATT&CK](technical/mitre-attack.md), [tools and malware](technical/tooling-malware.md), [vulnerabilities](technical/vulnerabilities.md).
- [IOC index](iocs/IOCs.md).
- [Detection index](detections/Detections.md): 30 KQL hunts, 30 Splunk searches and five YARA rules.
- [Ransom-note archive](ransom-notes/Ransom-Notes.md).
- [References and implementation provenance](References.md).

## Analytical Caveat

Published sample capabilities, observed incident actions and actor claims are different evidence classes. Related-family code or a legitimate tool cannot independently attribute a new incident. Payment clusters likewise do not identify every address's owner.

## Evidence Currency

Research was reviewed through 2026-09-22, including the Huntress publication of 2026-09-21. Historical artifacts retain their date context; none are asserted to be currently active by collection date alone. Detections require local data validation and are not credited to vendors that did not write them.

## Structure

<!-- tree:start -->
```text
inc-ransom/
├── detections/
│   ├── Detections.md
│   ├── INC-Hunting.yar
│   ├── KQL.md
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
