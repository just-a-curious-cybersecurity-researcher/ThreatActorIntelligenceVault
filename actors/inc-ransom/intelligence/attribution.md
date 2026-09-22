# INC Ransom — Attribution

**Presentation reviewed:** 2026-09-22.

## Evidence Classes and Confidence

High confidence applies to a directly reported sample or observed incident artifact. Vendor cluster equivalence and cross-brand organizational relationships require separate assessment. A tool match, shared host or copied note is not sufficient to identify an operator.

## Names and Scope

| Label | Source and scope | Limitation |
|---|---|---|
| INC Ransom / Incransom | Extortion brand used in incident and tracker reporting | Actor claim is distinct from confirmed compromise |
| G1032 | MITRE group entry | Different object from the malware entry |
| S1139 / INC Ransomware | MITRE software entry | Capabilities are not proof of use in every case |
| GOLD IONIC | Secureworks tracking of INC-related operations | Preserve the report's observation period |
| Tarnished Scorpion | Official regional advisory tracking | Advisory-specific organizational scope |
| Water Anito | Trend Micro operational label | Vendor cluster naming |

## Geographic Nexus

Reporting places INC in the Russian-speaking criminal ecosystem and discusses victimology consistent with that environment. Victim distribution is not proof of citizenship, physical residence or state direction.

Financial and infrastructure observations can concern affiliates or service providers in other jurisdictions. They should not be transformed into a single geographic identity for the core.

## Relationships and Alternative Hypotheses

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| INC–Lynx | Unit 42 code comparison and Chainalysis financial observations | Technical/financial relationship supported; Unit 42 uses rebranding language, while continued separate branding requires retaining separate records |
| INC–Sinobi | Supplied research and later reporting describe related code and infrastructure | Code propagation, shared services and affiliate movement can coexist; do not merge all operators |
| Nemty / Karma / Nokoyawa | Tradecraft overlap discussed in the official advisory | Shared tooling is weaker evidence than identified personnel |
| Vanilla Tempest–INC | Microsoft's healthcare reporting identifies use of INC through RaaS | Intrusion operator/deployer relationship; not an alias for the core |
| Fox Tempest–INC affiliates | Microsoft identifies a financial relationship with its malware-signing service | Supporting supplier, not evidence of INC ownership or development |
| Earlier closed group versus current RaaS | Secureworks 2024 versus official 2026 account | Date the assessments; organizational evolution and visibility differences are plausible |
| Infrastructure provider versus operator | Official Tonga incident attribution | A named infrastructure role does not establish control over the full brand |

## Decision Use

Use INC attribution to guide evidence collection and response priorities. For a specific incident, preserve note identifiers, executable hash, deployment chain, extortion infrastructure and time-bounded network artifacts.

Financial clustering and malware similarity are independent evidence types. Their agreement strengthens a relationship assessment without proving that every wallet and executable has the same owner.

## Official Organizational Evidence and Limits

The joint regional advisory provides an explicit affiliate/core distinction. Its named infrastructure attribution remains attached to the Tonga case. This dossier does not extend that statement into leadership, developer or treasury ownership claims.
