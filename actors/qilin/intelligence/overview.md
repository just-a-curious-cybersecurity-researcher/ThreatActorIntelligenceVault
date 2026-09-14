# Qilin — Intelligence Overview

## Background

Qilin is a financially motivated ransomware-as-a-service ecosystem associated with the earlier Agenda name. Operators provide payload builders and extortion infrastructure; affiliates obtain access and conduct intrusions. Program, encryptor and deployment cluster are related but distinct entities. [Q10](../References.md#q10), [Q15](../References.md#q15)

CrowdStrike tracks REVENANT SPIDER and TrendAI uses Water Galura. Operator/probable-case reporting reaches June 2022; public Go analysis appeared in August. Different first-observation definitions should not be forced into one release date. [Q05](../References.md#q05), [Q12](../References.md#q12)

## Targeting and Victimology

Early Go samples targeted healthcare and education organizations in Indonesia, Saudi Arabia, South Africa and Thailand. The broader 2023 leak snapshot already spanned the Americas, Europe and Asia-Pacific. Later Talos reporting places manufacturing ahead of professional/scientific services and wholesale trade, with the United States most represented, followed by Canada, the UK, France and Germany. These are **source populations**, not a permanent global targeting rule. [Q12](../References.md#q12), [Q10](../References.md#q10), [Q15](../References.md#q15)

The Italian 2026 bulletin includes SMEs and cloud providers. Consequently, Qilin cannot be reduced to large healthcare victims. **Moderate Confidence assessment:** available access, affiliate specialization and the leverage created by business interruption explain the observed mix better than a single sector mandate. Provider compromise can multiply downstream effects. [Q30](../References.md#q30), [Q22](../References.md#q22)

Synnovis illustrates systemic consequences: the June 2024 ransomware incident disrupted pathology services used by London hospitals. Attribution to Qilin is reported by security sources here; it must be distinguished from independently confirmed disruption. The dossier does not adopt a reported USD 50 million demand as a payment, or a claimed stolen volume as verified patient-record exposure. [Q09](../References.md#q09), [Q03](../References.md#q03)


## Operational Model

Reported Qilin operations can involve:

1. exposed services, valid accounts or targeted phishing for access;
2. execution through scripts and remote management;
3. credential collection and AD/network discovery;
4. privileged account use and lateral movement;
5. persistent control channels and defense impairment;
6. staging and exfiltration of business information;
7. backup/snapshot destruction and ransomware deployment;
8. negotiation and threatened disclosure.

The [operations dossier](operations.md) details each phase and its incident evidence. These stages organize analysis rather than prescribing a universal affiliate sequence. A successful upstream MSP compromise can expose multiple downstream organizations. [Q22](../References.md#q22)

## Ransomware Development

Early Agenda Go samples, Windows Rust branches, Qilin.B and Linux/ESXi payloads have different capabilities and configuration formats. Intermittent encryption, password gating and selectable propagation affect impact and visibility. A single binary is not automatically portable across Windows and Linux. [Q12](../References.md#q12), [Q13](../References.md#q13), [Q24](../References.md#q24)

Build-specific crypto, exclusions and supporting tools are in [Tooling and Malware](../technical/tooling-malware.md). Later Nutanix checks establish awareness, not a verified AHV exploit or a successful deployment in every reported incident. [Q23](../References.md#q23)

## Data Leak Site

Qilin uses publication infrastructure to pressure victims and separate credentialed negotiation portals to handle chats. Archived notes and incident reporting also reference media-branded publication threats. These are adversary claims, not verified cooperation with the genuine WikiLeaks organization or independent confirmation of every listed breach. [Q31](../References.md#q31), [Q22](../References.md#q22)

See [Onion Infrastructure](../iocs/onion-infrastructure.md) for roles and [Ransom Notes](../ransom-notes/Ransom-Notes.md) for variant evidence.

## Current Evolution in the Collected Research

The reviewed cases document GPO-based browser theft, MSP administration abuse, redundant RMM channels, driver-based impairment and central-share/hypervisor impact. These are complementary case observations, not one combined attack. [Q11](../References.md#q11), [Q22](../References.md#q22), [Q15](../References.md#q15), [Q23](../References.md#q23)

Group-IB's July 2026 review reports **1,062** Qilin leak-site incidents during 2025, whereas TrendAI's March 2026 spotlight describes **almost 1,400** disclosed victims for that year. Do not average or merge these figures: collection coverage, duplicates, brand assignment and observation cutoffs differ and were not reconciled. Tracker totals are dynamic claims; nonpaying/publicized cases, reposts, subsidiaries and reporting gaps bias measurement. [Q17](../References.md#q17), [Q18](../References.md#q18), [Q01](../References.md#q01), [Q02](../References.md#q02)

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| June–August 2022 | **Early activity and Go Windows Agenda binaries.** CrowdStrike dates the operator to at least June; Trend Micro published binary analysis August 25. Darktrace retrospectively identifies a **probable** June case. Different first-seen definitions explain part of the variation. [Q05](../References.md#q05), [Q12](../References.md#q12), [Q09](../References.md#q09) |
| August–September 2022 | **Likely Agenda-to-Qilin branding change.** CrowdStrike assessment; do not treat a renamed service as proof every sample was rewritten at once. [Q05](../References.md#q05) |
| December 2022 | **Rust Windows samples with intermittent encryption.** Direct analysis; early Rust CLI differs from Go and later Rust builds. [Q13](../References.md#q13) |
| March–May 2023 | **Affiliate panel examined and revenue-share terms reported.** Group-IB infiltration in March; 12 DLS entries in July 2022–May 2023 snapshot. [Q10](../References.md#q10) |
| June–July 2024 | **Synnovis disruption and separate GPO-based Chrome theft case.** Distinct incidents; browser-harvest case is not the Synnovis intrusion. [Q09](../References.md#q09), [Q11](../References.md#q11) |
| October 2024 | **Qilin.B variant documented.** Hardware-aware cipher selection and revised key protection/impairment. [Q24](../References.md#q24) |
| January 2025 | **MSP ScreenConnect administrator phished; customers attacked downstream.** STAC4365 affiliate case, not exploitation of a ScreenConnect product flaw. [Q22](../References.md#q22) |
| March 2025 | **Moonstone Sleet starts deploying Qilin.** Microsoft-reported deployment relationship, not RaaS ownership. [Q25](../References.md#q25) |
| 2025 | **Broader affiliate ecosystem; cloud exfiltration and dual encryptors.** Talos observed credential toolkit and Cyberduck/Backblaze; Trend Micro documents drivers, Linux payload and new Nutanix checks. [Q15](../References.md#q15), [Q23](../References.md#q23) |
| May 2026 | **Italian bulletin covers SME/cloud-provider attacks and Ivanti/Fortinet exploitation.** National incident reporting republished by CSIRT Toscana. [Q30](../References.md#q30) |
| June–July 2026 | **AudiA6 disruption and FirstVPN sanctions expose service relationships.** Financial-service evidence, not Qilin takedown. [F03](../References.md#f03), [F04](../References.md#f04), [F01](../References.md#f01) |

## Law-Enforcement Development

The June–July 2026 AudiA6 disruption and FirstVPN sanctions concern services used by ransomware actors. Official service-level findings and vendor Qilin linkage have different scopes; neither establishes a complete Qilin takedown or identifies all core operators. [F04](../References.md#f04), [F01](../References.md#f01), [F03](../References.md#f03), [F02](../References.md#f02)

Reviewed **2026-09-11**. The underlying official financial screening remains dated **2026-09-10**; a formatting review is not a new sanctions-list download.
