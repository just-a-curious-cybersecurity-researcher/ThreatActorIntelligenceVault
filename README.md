# Threat Actor Intelligence

This repository is a personal Cyber Threat Intelligence (CTI) knowledge base built from publicly available reporting and technical research.

The objective is to consolidate information about threat actors, ransomware operations and related cybercriminal activity into a consistent structure that combines:

- analytical assessments and actor profiling;
- operational lifecycle and observed tradecraft;
- MITRE ATT&CK mapping;
- malware, tooling and exploited vulnerabilities;
- indicators of compromise;
- detection opportunities;
- financial and blockchain intelligence where publicly available;
- source-backed ransom-note variants and negotiation context.

The repository is intended as a research and defensive reference. Attribution in cyber threat intelligence is inherently probabilistic: vendor naming, actor clustering and relationships between groups may change as new evidence emerges. Claims that remain uncertain are therefore presented as assessments rather than facts.

## Threat Actors

| Actor | Type | Motivation | First-observation context | Evidence reviewed |
|---|---|---|---|---|
| [Akira](actors/akira/README.md) | Ransomware / RaaS | Financial | March–April 2023 emergence | 2026-09-10 |
| [Qilin / Agenda](actors/qilin/README.md) | Ransomware / RaaS | Financial | Mid-2022; operator, sample and branding dates differ | 2026-09-10 |

See the [actor index](actors/README.md), [financial-source review](actors/financial-source-review.md) and [validation report](VALIDATION.md).

## Repository Structure

The tree below shows the general organization of the knowledge base. Each threat actor has its own folder following this structure; individual documents vary with the available evidence.

```text
ThreatActorIntelligenceVault/
├── actors/
│   ├── <actor>/
│   │   ├── intelligence/
│   │   ├── technical/
│   │   ├── iocs/
│   │   ├── detections/
│   │   ├── ransom-notes/
│   │   ├── README.md
│   │   └── References.md
│   ├── financial-source-review.md
│   └── README.md
├── scripts/
├── README.md
└── VALIDATION.md
```

## Analytical Note

The presence of a single tool, IOC or ATT&CK technique is not sufficient to attribute activity to a specific threat actor. Greater analytical weight should be placed on combinations of behavior, infrastructure, malware artifacts, temporal context and corroborating reporting.


## Intelligence Workflow and Confidence

**Collection → Processing → Analysis → Dissemination:** source registers identify publisher, dates and access limits; IOC registers normalize values and roles while preserving unresolved leads; intelligence documents evaluate competing explanations; actor summaries and detections translate findings into defensive use. Source-review documents record the disposition and substantive use of references.

- **High Confidence:** direct or strongly corroborated evidence supports the specific proposition. “High confidence in published reporting” still does not mean independently verified private-key ownership or actor identity.
- **Moderate Confidence:** credible evidence supports an assessment, but incomplete visibility or plausible alternatives remain.
- **Low Confidence:** a tentative lead, indirect relationship or uncorroborated claim; unsuitable as a sole attribution or blocking basis.

Separate observed events, sample capabilities, third-party reporting, vendor attribution, analyst assessments and attacker claims. Multiple articles repeating one underlying report are one evidence chain. Publication date, incident date, collection date and current service availability are different fields. When evidence is insufficient to populate a category, omit that content or section. Do not insert placeholder statements about uncertainty, missing information or intelligence gaps, and do not borrow another actor's facts to fill it. Use the same presentation for supported content; empty categories do not need to be reproduced. Retain source attribution and qualifications needed to represent the evidence that is actually included accurately.

## Defensive and Financial Use

Legitimate administration tools acquire meaning through account, host, tenant, timing and surrounding behavior. ATT&CK mappings describe supported procedures, not guaranteed coverage by an alert. Queries require local schema/tuning and production validation; YARA scans artifacts, not behavior over time.

Blockchain roles are explicit: Victim Payment Address, Affiliate Address, Intermediary Address, Peel Chain Address, Consolidation Address, Suspected Operator Address, Suspected Treasury Address, Exchange Deposit, VASP, Mixer, Bridge, Service Infrastructure, OFAC-Sanctioned Address, Law-Enforcement Seizure Address or Unknown Downstream Address. Only evidence-backed categories are populated. An official attribution to a service and an analyst-assessed relationship to a ransomware group have separate confidence levels. No downstream address inherits organizational ownership automatically.

The [validation script](scripts/validate_repository.py) checks internal links/anchors, index coverage, README trees, indicator syntax/checksums and active ATT&CK entries. Optional [harmless detection-fixture tests](scripts/test_detection_artifacts.py) compile YARA and exercise selected regex boundaries. See [validation](VALIDATION.md) for commands and practical limits.
