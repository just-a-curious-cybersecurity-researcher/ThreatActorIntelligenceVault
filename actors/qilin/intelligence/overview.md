# Qilin — Overview and Evolution

Qilin is a financially motivated ransomware-as-a-service ecosystem associated with the earlier **Agenda** name. Operators maintain builders, negotiation/leak infrastructure and affiliate services; intrusion teams choose access paths and deploy the payload. This dossier distinguishes the program, the encryptor and individual affiliate clusters. **High Confidence** in the RaaS model, supported by Group-IB's panel access and multiple IR reports. [Q10](../References.md#q10), [Q15](../References.md#q15)

## Timeline

| Period | Development | Evidence / interpretation |
|---|---|---|
| June–August 2022 | Early activity and Go Windows Agenda binaries | CrowdStrike dates the operator to at least June; Trend Micro published binary analysis August 25. Darktrace retrospectively identifies a **probable** June case. Different first-seen definitions explain part of the variation. [Q05](../References.md#q05), [Q12](../References.md#q12), [Q09](../References.md#q09) |
| August–September 2022 | Likely Agenda-to-Qilin branding change | CrowdStrike assessment; do not treat a renamed service as proof every sample was rewritten at once. [Q05](../References.md#q05) |
| December 2022 | Rust Windows samples with intermittent encryption | Direct analysis; early Rust CLI differs from Go and later Rust builds. [Q13](../References.md#q13) |
| March–May 2023 | Affiliate panel examined and revenue-share terms reported | Group-IB infiltration in March; 12 DLS entries in July 2022–May 2023 snapshot. [Q10](../References.md#q10) |
| June–July 2024 | Synnovis disruption and separate GPO-based Chrome theft case | Distinct incidents; browser-harvest case is not the Synnovis intrusion. [Q09](../References.md#q09), [Q11](../References.md#q11) |
| October 2024 | Qilin.B variant documented | Hardware-aware cipher selection and revised key protection/impairment. [Q24](../References.md#q24) |
| January 2025 | MSP ScreenConnect administrator phished; customers attacked downstream | STAC4365 affiliate case, not exploitation of a ScreenConnect product flaw. [Q22](../References.md#q22) |
| March 2025 | Moonstone Sleet starts deploying Qilin | Microsoft-reported deployment relationship, not RaaS ownership. [Q25](../References.md#q25) |
| 2025 | Broader affiliate ecosystem; cloud exfiltration and dual encryptors | Talos observed credential toolkit and Cyberduck/Backblaze; Trend Micro documents drivers, Linux payload and new Nutanix checks. [Q15](../References.md#q15), [Q23](../References.md#q23) |
| May 2026 | Italian bulletin covers SME/cloud-provider attacks and Ivanti/Fortinet exploitation | National incident reporting republished by CSIRT Toscana. [Q30](../References.md#q30) |
| June–July 2026 | AudiA6 disruption and FirstVPN sanctions expose service relationships | Financial-service evidence, not Qilin takedown. [F03](../References.md#f03), [F04](../References.md#f04), [F01](../References.md#f01) |

## Victimology and Selection

Early Go samples targeted healthcare and education organizations in Indonesia, Saudi Arabia, South Africa and Thailand. The broader 2023 leak snapshot already spanned the Americas, Europe and Asia-Pacific. Later Talos reporting places manufacturing ahead of professional/scientific services and wholesale trade, with the United States most represented, followed by Canada, the UK, France and Germany. These are **source populations**, not a permanent global targeting rule. [Q12](../References.md#q12), [Q10](../References.md#q10), [Q15](../References.md#q15)

The Italian 2026 bulletin includes SMEs and cloud providers. Consequently, Qilin cannot be reduced to large healthcare victims. **Moderate Confidence assessment:** available access, affiliate specialization and the leverage created by business interruption explain the observed mix better than a single sector mandate. Provider compromise can multiply downstream effects. [Q30](../References.md#q30), [Q22](../References.md#q22)

Synnovis illustrates systemic consequences: the June 2024 ransomware incident disrupted pathology services used by London hospitals. Attribution to Qilin is reported by security sources here; it must be distinguished from independently confirmed disruption. The dossier does not adopt a reported USD 50 million demand as a payment, or a claimed stolen volume as verified patient-record exposure. [Q09](../References.md#q09), [Q03](../References.md#q03)

## Measurement Conflicts

Group-IB's July 2026 review reports **1,062** Qilin leak-site incidents during 2025, whereas TrendAI's March 2026 spotlight describes **almost 1,400** disclosed victims for that year. Do not average or merge these figures: collection coverage, duplicates, brand assignment and observation cutoffs differ and were not reconciled. Tracker totals are dynamic claims; nonpaying/publicized cases, reposts, subsidiaries and reporting gaps bias measurement. [Q17](../References.md#q17), [Q18](../References.md#q18), [Q01](../References.md#q01), [Q02](../References.md#q02)

**Intelligence Gaps:** current core membership, actual affiliate count, independently verified payment rate, unique victim denominators and exact conversion of reported capabilities into operations. See [attribution](attribution.md), [operations](operations.md) and [financial intelligence](blockchain.md).
