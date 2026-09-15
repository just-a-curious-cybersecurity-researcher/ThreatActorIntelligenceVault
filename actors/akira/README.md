# Akira

Akira is a financially motivated ransomware operation first observed around March-April 2023. The collected reporting describes it as a Ransomware-as-a-Service (RaaS) operation with a relatively closed enterprise model. CrowdStrike tracks the actor as **PUNK SPIDER**.

Akira has primarily targeted organizations in North America and Europe, with additional activity reported in other regions. Frequently affected sectors include industrial and manufacturing organizations, professional services, technology, education, finance and critical infrastructure. The operation initially focused mainly on Windows environments and expanded to Linux systems during 2023.

Its intrusions commonly combine compromised credentials or exploitation of exposed remote-access infrastructure with credential theft, Active Directory and network discovery, lateral movement, defense evasion, data exfiltration and ransomware deployment. In some cases, stolen data has reportedly been used for extortion even when encryption was not completed.

## Quick Profile

| Field | Assessment |
|---|---|
| Name | Akira |
| Vendor alias | PUNK SPIDER (CrowdStrike) |
| First observed | March-April 2023 |
| Motivation | Financial |
| Model | Ransomware-as-a-Service / closed enterprise model |
| Primary platforms | Windows, later Linux |
| Primary regions in collected reporting | United States, Canada, Germany, Italy and broader North America / Europe; additional activity elsewhere |
| Common target sectors | Industrial, manufacturing, professional services, technology, education, finance, critical infrastructure |
| Suspected nexus | Possible Russian / post-Soviet or broader Russian-speaking cybercriminal ecosystem |
| Status | Active in the collected reporting |

## Key Intelligence Judgments

**KJ-01 — High confidence.** Akira affiliates rely heavily on valid credentials and exposed remote-access infrastructure for initial access. VPN and RDP access, password spraying, exploitation of public-facing systems and phishing have all been reported.

**KJ-02 — High confidence.** Post-compromise activity commonly progresses through credential access, Active Directory and network reconnaissance, lateral movement, defense impairment, data staging/exfiltration and finally ransomware deployment or extortion.

**KJ-03 — High confidence.** Akira affiliates make extensive use of legitimate administration software, offensive-security tools and LOLBins. Individual tools such as AnyDesk, Rclone, Mimikatz, PsExec or Ngrok are therefore weak attribution signals when observed in isolation.

**KJ-04 — Moderate Confidence.** Code/financial overlap and the May 2026 DOJ account support a historical Conti relationship. The official account includes Akira among a multi-brand organization’s names during a bounded period; it does not establish that every current affiliate belongs to one unchanged organization. 

**KJ-05 — Moderate Confidence.** A Russian-speaking ecosystem nexus is supported by vendor reporting; nationality, physical location and state direction remain unestablished. See the evidence and alternatives in [Attribution](intelligence/attribution.md).

**KJ-06 — High confidence.** Akira follows a double-extortion model and may monetize stolen data even when encryption is absent or unsuccessful.

**KJ-07 — Moderate confidence.** The progressively standardized post-payment laundering process described in blockchain reporting may indicate increasing centralization of treasury/cash-out operations, although the exact admin/affiliate split is obscured once funds reach shared off-ramp infrastructure.

## Navigation

### Intelligence

- [Overview](intelligence/overview.md)
- [Operations / Attack Lifecycle](intelligence/operations.md)
- [Attribution & Relationships](intelligence/attribution.md)
- [Blockchain & Financial Intelligence](intelligence/blockchain.md)

### Technical

- [Tooling & Malware](technical/tooling-malware.md)
- [Known Vulnerabilities](technical/vulnerabilities.md)
- [MITRE ATT&CK Mapping](technical/mitre-attack.md)

### Defensive Reference

- [Indicators of Compromise](iocs/IOCs.md)
- [Detection Opportunities](detections/Detections.md)
- [Ransom Notes](ransom-notes/Ransom-Notes.md)
- [Source Review and Intelligence Gaps](intelligence/source-review.md)
- [References](References.md)

## Analytical Caveat

Akira operates as a RaaS ecosystem and observed tradecraft may differ between affiliates and campaigns. This profile therefore describes reported Akira-associated activity rather than a guaranteed step-by-step playbook for every intrusion.

## Evidence Currency

Reviewed **2026-09-10**. This is a source-bounded dossier, not live monitoring. Key judgments above are synthesized from the documented [operations](intelligence/operations.md), [attribution](intelligence/attribution.md) and [financial analysis](intelligence/blockchain.md). Confidence applies to each proposition, not to every member of a RaaS ecosystem. The [source review](intelligence/source-review.md) records contradictions and unresolved leads.

## Structure

<!-- tree:start -->
```text
akira/
├── detections/
│   ├── Akira-Hunting.yar
│   ├── Detections.md
│   ├── KQL.md
│   └── Splunk.md
├── intelligence/
│   ├── attribution.md
│   ├── blockchain.md
│   ├── operations.md
│   ├── overview.md
│   └── source-review.md
├── iocs/
│   ├── blockchain-addresses.md
│   ├── extensions.md
│   ├── file-artifacts.md
│   ├── file-patterns.md
│   ├── hash-provenance.md
│   ├── hashes.md
│   ├── IOCs.md
│   ├── ip-addresses.md
│   └── onion-infrastructure.md
├── ransom-notes/
│   ├── akira-contact-warning.md
│   ├── akira-v2.md
│   ├── akira-warning.md
│   ├── akira.md
│   ├── megazord-messaging.md
│   ├── megazord.md
│   ├── other-filenames.md
│   └── Ransom-Notes.md
├── technical/
│   ├── mitre-attack.md
│   ├── tooling-malware.md
│   └── vulnerabilities.md
├── README.md
└── References.md
```
<!-- tree:end -->
