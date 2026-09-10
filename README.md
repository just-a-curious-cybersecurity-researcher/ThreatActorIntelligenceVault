# Threat Actor Intelligence

This repository is a personal Cyber Threat Intelligence (CTI) knowledge base built from publicly available reporting and technical research.

The objective is to consolidate information about threat actors, ransomware operations and related cybercriminal activity into a consistent structure that combines:

- analytical assessments and actor profiling;
- operational lifecycle and observed tradecraft;
- MITRE ATT&CK mapping;
- malware, tooling and exploited vulnerabilities;
- indicators of compromise;
- detection opportunities;
- financial and blockchain intelligence where publicly available.

The repository is intended as a research and defensive reference. Attribution in cyber threat intelligence is inherently probabilistic: vendor naming, actor clustering and relationships between groups may change as new evidence emerges. Claims that remain uncertain are therefore presented as assessments rather than facts.

## Threat Actors

| Actor | Type | Motivation | First observed | Status |
|---|---|---|---|---|
| [Akira](actors/akira/) | Ransomware / RaaS | Financial | March-April 2023 | Active in collected reporting |

## Repository Structure

Each actor is organized into a small set of analytical and technical documents:

```text
actor/
├── README.md
├── intelligence/
│   ├── overview.md
│   ├── operations.md
│   ├── attribution.md
│   └── blockchain.md
├── technical/
│   ├── tooling-malware.md
│   ├── vulnerabilities.md
│   └── mitre-attack.md
├── IOCs.md
├── Detections.md
└── References.md
```

## Analytical Note

The presence of a single tool, IOC or ATT&CK technique is not sufficient to attribute activity to a specific threat actor. Greater analytical weight should be placed on combinations of behavior, infrastructure, malware artifacts, temporal context and corroborating reporting.
