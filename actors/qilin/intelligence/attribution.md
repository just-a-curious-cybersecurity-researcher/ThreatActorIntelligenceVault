# Qilin — Attribution and Relationships

## Evidence Classes and Confidence

**Observed** means observed by the named publisher, not independently observed on victim systems by this repository. **High Confidence** requires strong direct or convergent support; **Moderate Confidence** denotes credible but incomplete evidence or alternatives; **Low Confidence** denotes tentative or uncorroborated support. Confidence in a published vendor label is separate from confidence in organizational identity.

## Names and Scope

| Label | Source and scope | Limitation |
|---|---|---|
| Qilin / Agenda | Related ransomware/program names; Agenda appears in early notes | High Confidence; version and branding dates differ across sources. |
| REVENANT SPIDER | CrowdStrike financially motivated RaaS operator cluster | Vendor attribution, High Confidence in published equivalence; the public excerpt does not expose its full evidence. |
| Water Galura | TrendAI tracking name for Agenda/Qilin | High Confidence in vendor's stated mapping, not independent identity proof. |
| Stinkbug | Symantec tracking label; also listed by CrowdStrike | High Confidence in the published mapping, not identical membership across vendor clusters. |
| Haise / Lucifer44 | Reported spokesperson/operator handle relationship | Group-IB directly observed Haise in recruitment context; CSIRT publication associates Lucifer44. Pseudonyms are not verified civil identities or proof of sole leadership. |

## Geographic Nexus

Group-IB preserved Russian-language recruitment material stating that CIS targets were excluded. Talos observed Windows-1251 encoding in a credential-exfiltration script and explicitly allowed a false-flag explanation. CrowdStrike assigns a Russian/Eastern European location label. These support a **Moderate Confidence Russian-speaking criminal-ecosystem nexus**, not the nationality or physical location of every operator. Neither Chinese mythological branding nor an Eastern European code page establishes state sponsorship. 

Advertised geographic exclusions may reflect affiliate rules, operational convenience or reputation management. Absence from a leak tracker is weak negative evidence. A universal Russian-language binary kill switch is not established by the technical sources reviewed. This is why categorical country-of-origin labels in secondary profiles are qualified here. 

## Relationships and Alternative Hypotheses

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| STAC4365 → Qilin | Sophos attributes the January 2025 MSP intrusion to that phishing affiliate with high confidence and analyzes the deployed payload | High Confidence in vendor-attributed deployment; STAC4365 is not an alias for all Qilin operations. |
| Pistachio Tempest → Qilin | Darktrace links some case IOCs to Microsoft's distribution cluster and notes experimentation with Qilin | Moderate Confidence in reported affiliate overlap; retrospective network evidence and shared tools leave uncertainty. |
| Moonstone Sleet → Qilin | Microsoft reports use from March 2025 | High Confidence in published deployment attribution; a North Korean actor using a criminal service does not make Qilin a North Korean organization. |
| RansomHub → Qilin affiliates | Vendor assessments of migration after RansomHub disruption | Moderate Confidence in ecosystem movement; timing and TTP overlap do not prove a merger or transfer of all operators. |
| DragonForce / LockBit / Qilin | September 15, 2025 alliance announcement reported by TrendAI | High Confidence in reported **claim**, Low Confidence in operational integration. Advertising is not evidence of a common treasury or development team. |
| Qilin → The Gentlemen / Devman | Group-IB describes operations founded by former Qilin affiliates | Vendor assessment, Moderate Confidence; breakaway teams can retain access and methods without sharing current ownership. |
| Akira ↔ Qilin | Some driver-tool overlap and both use AudiA6 | Common tooling/service supply is a strong alternative to shared command. No actor equivalence inferred. |
| Black Basta / BlackMatter / REvil similarities | Early Agenda analysis compares portal verification and Safe Mode/password behavior | Low Confidence in organizational connection; implementation imitation or common requirements suffice. |

## Decision Use

Use convergent malware/configuration, incident timelines, negotiation evidence and independently corroborated infrastructure to assess attribution. An RMM product, country, driver, language or downstream financial transfer is insufficient on its own. Preserve the identity of the observing vendor and the boundary of the cluster it describes.

## Official Organizational Evidence and Limits

FirstVPN is officially sanctioned infrastructure; TRM reports a Qilin-linked service purchase. Attribution of FirstVPN's addresses is strong, but no exact Qilin transaction is exposed for each address. AudiA6 is a shared laundering service. Neither relationship establishes the ransomware group's control of every service wallet. See [financial intelligence](blockchain.md).
