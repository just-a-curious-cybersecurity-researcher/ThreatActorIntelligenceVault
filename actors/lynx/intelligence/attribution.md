# Lynx — Attribution and Relationships

**Presentation reviewed:** 2026-10-07.

## Evidence Classes and Confidence

**High Confidence** requires direct panel access, sample analysis or incident telemetry. **Moderate Confidence** covers vendor cluster assessments and code/infrastructure relationships. Dark-web marketing and tracker labels are recorded as claims, not verified identities.

## Names and Scope

| Label | Source and scope | Limitation |
|---|---|---|
| Lynx | RaaS, encryptor and extortion-site brand | Does not identify a specific affiliate or operator. |
| `silencer` | RAMP recruiter/representative observed by Group-IB | Pseudonym; legal identity and exclusive control are unknown. |
| Water Lalawag | Trend Micro intrusion-set label applied to Lynx activity | Vendor-scoped cluster, not proof of one person or team. |
| Storm-2113 | Microsoft tracking for multiple affiliates deploying Lynx in Q3 2024 | Affiliate activity cluster; must not be used as a synonym for the core RaaS. |
| INC Ransom | Predecessor code lineage and possible organizational relationship | Similar code is stronger evidence for reuse than for identical membership. |
| Sinobi | Later ransomware brand with reported Lynx/INC code and infrastructure overlap | Successor, offshoot and shared-code hypotheses remain open. |

## Geographic Nexus

Russian-language recruitment on RAMP and the claimed prohibition on targeting the CIS support placement in a Russian-speaking cybercrime ecosystem. They do not establish operator nationality, residence or state direction. No public evidence reviewed here supports a state-sponsored mission.

## Relationships and Alternative Hypotheses

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| Lynx ↔ INC Ransom | Windows BinDiff similarity; Linux/ESXi comparison with more than 91% overlapping non-library functions; INC source reportedly offered for sale in 2024 | High Confidence in code lineage. Purchase, fork, personnel continuity and shared developer remain competing organizational explanations. |
| Lynx ↔ Sinobi | Code similarity, copied site structure and reported acquisition of Lynx/INC leak-site domains by a common actor | Moderate Confidence in ecosystem continuity; insufficient to call every Sinobi incident a Lynx rebrand. |
| Lynx ↔ Hunters International | Group-IB identified infrastructure similarities among brands | Low-to-Moderate Confidence relationship lead; infrastructure design can be reused or sold. |
| Affiliates ↔ core | Panel access, 80/20 split, affiliate-controlled negotiation and wallets | High Confidence in separation of roles; a payload hash does not identify the affiliate. |

## Decision Use

Attribute at the narrowest supported layer. Use file structure and hashes for malware-family identification; use negotiation infrastructure for campaign linkage; use account, access and network evidence for affiliate activity. Do not project tools seen in an INC case into a Lynx case without direct linkage.

## Official Organizational Evidence and Limits

DNSC's Electrica attribution is official defensive reporting about one incident. No reviewed indictment names Lynx administrators or establishes a legal organizational chart. RaaS panel observations expose service design, but pseudonyms and self-asserted rules are not verified civil identities or enforceable policy.
