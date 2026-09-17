# The Gentlemen / Storm-2697

**Presentation reviewed:** 2026-09-17.

The Gentlemen is a financially motivated ransomware-as-a-service operation documented from 2025. Microsoft tracks its operators as Storm-2697. This dossier separates affiliate intrusion activity, Windows encryptor internals, Linux/ESXi observations and claims made in leaked conversations. Reviewed **2026-09-17**.

## Quick Profile

| Field | Assessment |
|---|---|
| Name | The Gentlemen |
| Vendor alias | Storm-2697 (Microsoft); operator tracking label |
| First observed | 2025; early activity and later public reporting have different dates |
| Motivation | Financial |
| Model | Ransomware-as-a-Service; encryption and data-disclosure pressure |
| Primary platforms | Windows Go encryptor; separately documented Linux/ESXi payloads |
| Primary regions in collected reporting | International victim population; tracker claims require individual corroboration |
| Common target sectors | Cross-sector enterprise environments, including organizations dependent on shared storage and virtualization |
| Suspected nexus | Russian-speaking criminal ecosystem in reviewed reporting; language does not establish nationality or state control |
| Status | Active in collected 2026 reporting; source-bounded rather than live monitoring |

## Key Intelligence Judgments

**KJ-01 — High Confidence.** The Windows encryptor contains task creation, user-context handling and network-share encryption routines. These binary capabilities are distinct from the preceding affiliate intrusion. [Executable internals](intelligence/encryptor.md)

**KJ-02 — High Confidence.** Published investigations document credential abuse, lateral movement, exfiltration and defense impairment. Their sequence and tool selection vary between cases. [Operations](intelligence/operations.md)

**KJ-03 — High Confidence.** The August 2025 case used a customized security-disabling utility with a vulnerable driver. Its CVE concerns local defense impairment, not the initial Fortinet access path. [Vulnerabilities](technical/vulnerabilities.md)

**KJ-04 — Moderate Confidence.** Leaked conversations provide evidence of affiliate support and business arrangements, but advertised capabilities and discussions are not equivalent to observed execution. [Attribution](intelligence/attribution.md)

**KJ-05 — High Confidence in published attribution.** TRM reports a Gentlemen-associated transfer relationship with AudiA6. The reported amount is not an estimate of total ransom revenue or proof of ownership of every downstream wallet. [Financial analysis](intelligence/blockchain.md)

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

This is a public-source dossier, not live monitoring. Sample-specific behavior, affiliate tradecraft and tracker claims retain separate evidential roles. No actor-controlled service or stolen-data corpus was accessed. Return to [actor index](../README.md).

The detection package now includes 54 KQL hunts, 54 paired Splunk searches and 11 YARA rules. Two pairs require forwarded ESXi logs; the Windows hunts use endpoint telemetry. Local rules and tool-inventory hypotheses are identified explicitly.

## Evidence Currency

Evidence and presentation reviewed **2026-09-17**. Indicators retain source publication context; this review date does not establish current infrastructure control. The [source review](intelligence/source-review.md) records corrections to the supplied research and access limits.

## Structure

<!-- tree:start -->
```text
thegentlemen/
├── detections/
│   ├── Detections.md
│   ├── KQL.md
│   ├── Splunk.md
│   └── TheGentlemen-Hunting.yar
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
