# Qilin — Attribution and Relationships

## Names and Scope

| Name | Meaning / source | Confidence and limitation |
|---|---|---|
| Qilin / Agenda | Related ransomware/program names; Agenda appears in early notes | High Confidence; version and branding dates differ across sources. [Q12](../References.md#q12), [Q05](../References.md#q05) |
| REVENANT SPIDER | CrowdStrike financially motivated RaaS operator cluster | Vendor attribution, High Confidence in published equivalence; the public excerpt does not expose its full evidence. [Q05](../References.md#q05) |
| Water Galura | TrendAI tracking name for Agenda/Qilin | High Confidence in vendor's stated mapping, not independent identity proof. [Q18](../References.md#q18) |
| Stinkbug | CrowdStrike-listed community identifier | Moderate Confidence in scope; no separately verified cluster boundary in public excerpt. [Q05](../References.md#q05) |
| Haise / Lucifer44 | Reported spokesperson/operator handle relationship | Group-IB directly observed Haise in recruitment context; CSIRT publication associates Lucifer44. Pseudonyms are not verified civil identities or proof of sole leadership. [Q10](../References.md#q10), [Q30](../References.md#q30) |

## Geographic Nexus

Group-IB preserved Russian-language recruitment material stating that CIS targets were excluded. Talos observed Windows-1251 encoding in a credential-exfiltration script and explicitly allowed a false-flag explanation. CrowdStrike assigns a Russian/Eastern European location label. These support a **Moderate Confidence Russian-speaking criminal-ecosystem nexus**, not the nationality or physical location of every operator. Neither Chinese mythological branding nor an Eastern European code page establishes state sponsorship. [Q10](../References.md#q10), [Q15](../References.md#q15), [Q05](../References.md#q05)

Advertised geographic exclusions may reflect affiliate rules, operational convenience or reputation management. Absence from a leak tracker is weak negative evidence. A universal Russian-language binary kill switch is not established by the technical sources reviewed. This is why categorical country-of-origin labels in secondary profiles are qualified here. [Q06](../References.md#q06), [Q08](../References.md#q08)

## Cross-Actor Relationships

| Relationship | Supporting evidence | Assessment / alternative |
|---|---|---|
| STAC4365 → Qilin | Sophos attributes the January 2025 MSP intrusion to that phishing affiliate with high confidence and analyzes the deployed payload | High Confidence in vendor-attributed deployment; STAC4365 is not an alias for all Qilin operations. [Q22](../References.md#q22) |
| Pistachio Tempest → Qilin | Darktrace links some case IOCs to Microsoft's distribution cluster and notes experimentation with Qilin | Moderate Confidence in reported affiliate overlap; retrospective network evidence and shared tools leave uncertainty. [Q09](../References.md#q09) |
| Moonstone Sleet → Qilin | Microsoft reports use from March 2025 | High Confidence in published deployment attribution; a North Korean actor using a criminal service does not make Qilin a North Korean organization. [Q25](../References.md#q25) |
| RansomHub → Qilin affiliates | Vendor assessments of migration after RansomHub disruption | Moderate Confidence in ecosystem movement; timing and TTP overlap do not prove a merger or transfer of all operators. [Q17](../References.md#q17), [Q18](../References.md#q18) |
| DragonForce / LockBit / Qilin | September 15, 2025 alliance announcement reported by TrendAI | High Confidence in reported **claim**, Low Confidence in operational integration. Advertising is not evidence of a common treasury or development team. [Q18](../References.md#q18) |
| Qilin → The Gentlemen / Devman | Group-IB describes operations founded by former Qilin affiliates | Vendor assessment, Moderate Confidence; breakaway teams can retain access and methods without sharing current ownership. [Q17](../References.md#q17) |
| Akira ↔ Qilin | Some driver-tool overlap and both use AudiA6 | Common tooling/service supply is a strong alternative to shared command. No actor equivalence inferred. [Q23](../References.md#q23), [F03](../References.md#f03) |
| Black Basta / BlackMatter / REvil similarities | Early Agenda analysis compares portal verification and Safe Mode/password behavior | Low Confidence in organizational connection; implementation imitation or common requirements suffice. [Q12](../References.md#q12) |

## Financial Evidence and Limits

FirstVPN is officially sanctioned infrastructure; TRM reports a Qilin-linked service purchase. Attribution of FirstVPN's addresses is strong, but no exact Qilin transaction is exposed for each address. AudiA6 is a shared laundering service. Neither relationship establishes the ransomware group's control of every service wallet. See [financial intelligence](blockchain.md).

**Intelligence Gaps:** independently identified core leaders, precise boundaries between builder operators and negotiators, per-affiliate payment splits and evidence confirming claimed alliance operations. Reviewed 2026-09-10.
