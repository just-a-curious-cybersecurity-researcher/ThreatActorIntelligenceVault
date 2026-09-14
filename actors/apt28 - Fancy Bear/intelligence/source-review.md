# APT28 — Source Review and Intelligence Gaps

Review date: **2026-09-14**. This register separates collection from the resulting analysis. A source being reachable is not evidence that all its claims are reliable. The [reference register](../References.md) resolves publisher, URL, date and limitations for the original and additional sources. The review is bounded to the retained public material; retrieval limitations do not imply full-text validation.

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| [A01](../References.md#a01) MITRE ATT&CK | 2026-09-14 (retrieved). Curated group record; technique mappings require campaign evidence. | Overview; attribution |
| [A02](../References.md#a02) FireEye / Mandiant | 2014-10-27. Canonical attribution assessment, development and targeting since at least 2007. | Overview; attribution |
| [A03](../References.md#a03) ESET | 2016. Historical implant, platform and operational analysis; not a current infrastructure list. | Operations; tooling; ATT&CK |
| [A04](../References.md#a04) CrowdStrike | 2016; subsequently updated. Incident responder distinguishes separate FANCY BEAR and COZY BEAR intrusions. | Overview; attribution |
| [A05](../References.md#a05) US DOJ | 2018-07-13. Charging allegations; cooperation between Units 26165 and 74455 and bitcoin-funded infrastructure. | Attribution; blockchain |
| [A06](../References.md#a06) US DOJ | 2018. Seven defendants; anti-doping targeting, close-access teams and publication support. Allegations, not convictions. | Overview; attribution |
| [A07](../References.md#a07) Council of the EU | 2020-10-22. Historical restrictive-measures decision; do not infer all present designations from this notice. | Attribution; blockchain |
| [A08](../References.md#a08) UK FCDO | 2020-10-22. Explicit Unit 26165 attribution, Bundestag/WADA context; distinguishes Unit 74455 Olympic attacks. | Overview; attribution |
| [A09](../References.md#a09) US Treasury | 2018-12-19. Named officers and unit roles; sanctions statement, not a wallet-clustering dataset. | Attribution; blockchain |
| [A10](../References.md#a10) US DOJ | 2018-05-23. Historical label conflation includes Sandworm; retained as an attribution discrepancy. | Operations; infrastructure; IOCs |
| [A11](../References.md#a11) US DOJ | 2020-10-19. Exclusion evidence: Olympic Destroyer and other destructive operations assigned to Unit 74455. | Overview; attribution |
| [A12](../References.md#a12) ESET | 2018-09-27. Firmware persistence observed in a bounded Sednit campaign. | Operations; tooling; ATT&CK |
| [A13](../References.md#a13) ESET | 2019-05-22. Historical Sednit-associated tooling; preserve cluster/date boundaries. | Operations; tooling; ATT&CK |
| [A14](../References.md#a14) Kaspersky GReAT | 2018-02-20. Sofacy/SOURFACE and Zebrocy history; earlier inferred overlaps are not organizational proof. | Operations; tooling; ATT&CK |
| [A15](../References.md#a15) FireEye / Mandiant | 2017-08-11. Moderate-confidence campaign, GAMEFISH and Responder; separates observed hotel intrusion from inferred guest credential theft. | Operations; tooling; ATT&CK |
| [A16](../References.md#a16) Microsoft | 2023-03-24; updated 2024-02-15. NTLM leakage, Exchange follow-on activity, public investigation queries. | Operations; vulnerabilities; detections |
| [A17](../References.md#a17) Microsoft | 2024-04-22. Post-compromise escalation, file hashes and published KQL; not an initial-access exploit. | Operations; vulnerabilities; detections |
| [A18](../References.md#a18) Volexity | 2024-11-22. Investigation of February 2022 activity; publication year is not incident year. | Operations; tooling; ATT&CK |
| [A19](../References.md#a19) US DOJ | 2024-02-15. January 2024 operation; APT28 repurposed criminally compromised MooBot routers. | Operations; infrastructure; IOCs |
| [A20](../References.md#a20) FBI / NSA / partners | 2024-02-27. EdgeRouter investigation, credential/proxy roles and remediation. | Operations; vulnerabilities; detections |
| [A21](../References.md#a21) NSA / FBI / CISA / international partners | 2025-05-21. AA25-141A / U/OO/157019-25 / PP-25-2107; public YARA on printed pages 18–22; TLP:CLEAR. FBI copy read; CISA landing page returned 403. | Operations; vulnerabilities; detections |
| [A22](../References.md#a22) ANSSI / CERT-FR | 2025-04-29. 2021–2024 investigations; alias footnote uses UAC-0028, whereas CERT-UA campaign labels use UAC-0001. | Overview; attribution |
| [A23](../References.md#a23) NCSC | 2025-05-06 (report version). Observed in 2023; technical report deliberately separates malware analysis from attribution. | Tooling; attribution |
| [A24](../References.md#a24) NCSC | 2025-07-18. APT28 attribution and UK sanctions announcement. Use dedicated 2018/2020 sources for OPCW unit identity. | Overview; attribution |
| [A25](../References.md#a25) S2 Grupo / LAB52 | 2025-09-03. Sample analysis, hashes and exfiltration email; signed OneDrive hash is explicitly legitimate. | Operations; infrastructure; IOCs |
| [A26](../References.md#a26) CERT-UA | 2025-06-21. Primary endpoint opened but rendered no text; details corroborated by ESET and Sekoia, not represented as independently readable here. | Tooling; attribution |
| [A27](../References.md#a27) Sekoia | 2025. BeardShell/Covenant sample analysis and infrastructure. Publicly displayed YARA includes a TLP:GREEN-labelled rule; not redistributed. | Operations; infrastructure; IOCs |
| [A28](../References.md#a28) ESET | 2026-03-10. 2024–2026 paired implants and code lineage; authors' technical attribution. | Operations; tooling; ATT&CK |
| [A29](../References.md#a29) Zscaler ThreatLabz | 2026-02-02. Observed exploitation 2026-01-29; high-confidence attribution; MiniDoor and PixyNetLoader naming. | Operations; vulnerabilities; detections |
| [A30](../References.md#a30) CERT-UA | 2026. Endpoint opened without rendered text; citation supplied by ESET. Exact incident claims rely on readable corroboration. | Tooling; attribution |
| [A31](../References.md#a31) Trend Micro / TrendAI | 2026-03-26. PRISMEX, defense supply chains and reported destructive command; shared-infrastructure CVE chain is explicitly not independently confirmed. | Operations; vulnerabilities; detections |
| [A32](../References.md#a32) NCSC | 2026-04-07. Two infrastructure clusters, public IP list, router models and mitigations. | Operations; infrastructure; IOCs |
| [A33](../References.md#a33) Microsoft | 2026-04-07. TLS warning precondition, selective interception and government targeting in Africa. | Operations; infrastructure; IOCs |
| [A34](../References.md#a34) Lumen Black Lotus Labs | 2026. Independent network visibility and coordinated disruption; report's AUTHENTIC ANTICS date differs from NCSC's dated attribution. | Operations; infrastructure; IOCs |
| [A35](../References.md#a35) US DOJ | 2026-04-07. US portion of router network disrupted; not evidence of permanent worldwide eradication. | Operations; infrastructure; IOCs |
| [A36](../References.md#a36) Recorded Future Insikt Group | 2026 (page includes July activity). Body extends beyond executive summary's April cutoff; medium-confidence targeting assessment. | Operations; infrastructure; IOCs |
| [A37](../References.md#a37) Unit 42 | 2024. Medium-to-high attribution; public services and diplomatic targeting. | Operations; tooling; ATT&CK |
| [A38](../References.md#a38) Proofpoint | 2023. Repeated exploitation of patched vulnerabilities; high message volume is not victim count. | Operations; vulnerabilities; detections |
| [A39](../References.md#a39) Google TAG | 2023-10-18. FROZENLAKE / CVE-2023-38831; other groups in the same report remain separate. | Operations; vulnerabilities; detections |
| [A40](../References.md#a40) Google Threat Intelligence Group | 2025. PROMPTSTEAL = LAMEHUG, observed June 2025; runtime command generation, not proof of autonomous operations. | Operations; tooling; ATT&CK |
| [A41](../References.md#a41) Elliptic | 2018-07-24. Provider assessment of infrastructure funding; amount-based transaction identification is not an official wallet designation. | Attribution; blockchain |
| [A42](../References.md#a42) TRM Labs | 2026-08-17. Mentions APT28/PROMPTSTEAL; does not establish APT28 ransom revenue. | Attribution; blockchain |
| [A43](../References.md#a43) Secureworks CTU (now hosted by Sophos) | 2016-06-16. Primary phishing-link analysis; vendor-host migration does not create independent corroboration. | Overview; attribution |
| [A44](../References.md#a44) ESET | 2026. Sednit activity and separate Sandworm section; no transfer of wiper attribution between sections. | Operations; tooling; ATT&CK |
| [A45](../References.md#a45) Proofpoint | 2026. Tracks TA458 separately from TA422 and Roundish; limits broad APT28 assignment of new webmail zero-days. | Tooling; attribution |
| [A46](../References.md#a46) Microsoft | 2026-07-31. Exclusion evidence: captive-portal campaign is not Forest Blizzard. | Overview; attribution |
| [A47](../References.md#a47) Unit 42 | 2024. Generic post-exploitation tool analysis; not accepted as an APT28-specific family. | Tooling; attribution |
| [A48](../References.md#a48) NCSC / NSA / CISA / FBI | 2023-04-18. 2021 activity; CVE-2017-6742 and Jaguar Tooth. | Operations; vulnerabilities; detections |
| [A49](../References.md#a49) NCSC | 2026-09-14 (retrieved). Official YARA/Snort downloads and OGL v3.0 terms. Binary-download MIME blocked rendering of some YARA files. | Detections; KQL; Splunk |
| [A50](../References.md#a50) Splunk | 2026-05-13 (updated). Four public SPL detections; product dependencies and tuning remain applicable. | Detections; KQL; Splunk |
| [A51](../References.md#a51) Splunk | 2026-05-13 (updated). Public SPL; displayed query references time fields it does not aggregate. | Detections; KQL; Splunk |
| [A52](../References.md#a52) Splunk | 2026-05-13 (updated). Public SPL; query finds file creation and does not itself exclude Outlook ancestry. | Detections; KQL; Splunk |
| [A53](../References.md#a53) Splunk | 2026-05-13 (updated). Public registry analytic. | Detections; KQL; Splunk |
| [A54](../References.md#a54) Splunk | 2026-05-13 (updated). Public registry analytic. | Detections; KQL; Splunk |
| [A55](../References.md#a55) NSA / CISA / FBI / NCSC | 2021-07-01. AA21-181A; Kubernetes-backed guessing against enterprise/cloud; 2019–2021 context. | Operations; vulnerabilities; detections |
| [A56](../References.md#a56) ransomware.live | 2026-09-14 (attempted review). Page retrieval failed; indexed alias searches did not establish an APT28 RaaS listing. Not a complete negative census. | Source caveats; overview |
| [A57](../References.md#a57) Europol | 2016. Strategic discussion of Sofacy targeting European institutions; not an APT28 arrest announcement. | Overview; attribution |
| [A58](../References.md#a58) FBI | 2026-09-14 (retrieved). Public allegations and officer identity; no reward amount inferred. | Overview; attribution |
| [A59](../References.md#a59) FBI / NSA | 2020-08-13. Linux espionage malware attributed to Unit 26165. | Tooling; attribution |
| [A60](../References.md#a60) ESET | 2025. Medium-confidence Sednit assessment; retain together with Proofpoint's later distinct-cluster treatment. | Tooling; attribution |
| [A61](../References.md#a61) Council of the EU | 2024-05-03. Official attribution of SPD and Czech institution targeting. | Overview; attribution |
| [A62](../References.md#a62) Unit 42 | 2025-08-01 (updated). Fighting Ursa and unit mapping; catalogue includes UAC-0028. | Overview; attribution |
| [A63](../References.md#a63) CrowdStrike | 2026. Public annual-report finding on FANCY BEAR / LAMEHUG; not full access to OverWatch telemetry. | Operations; tooling; ATT&CK |
| [A64](../References.md#a64) CERT Polska | 2024-05-08. Campaign-level public investigation. | Operations; tooling; ATT&CK |
| [A65](../References.md#a65) Recorded Future | 2025 (analysis cutoff 2025-03-24). UAC-0063 overlap linked to APT28 only with medium confidence; not merged into core inventory. | Overview; attribution |
| [A66](../References.md#a66) Google / Mandiant | 2026-09-14 (retrieved). Tsar Team, CHOPSTICK, SOURFACE and EVILTOSS historical scope. | Overview; attribution |
| [A67](../References.md#a67) Cisco Talos | 2020. Attribution-methodology context; no inferred organizational identity from a shared indicator. | Overview; attribution |
| [A68](../References.md#a68) Huntress | 2026-09-14 (retrieved). Reviewed as secondary context; visible placeholder prose limits suitability for detailed TTP evidence. | Source caveats; overview |
| [A69](../References.md#a69) WithSecure | 2023-12. Secondary cross-check of Outlook exploitation; originating Microsoft analysis preferred. | Source caveats; overview |
| [A70](../References.md#a70) CSIRT.SK | 2024-03. Regional corroboration; avoid treating upload/crawl date as event date. | Source caveats; overview |
| [A71](../References.md#a71) Check Point Research | 2024-05-06. Secondary chronology check; official Germany/Czechia statement preferred. | Source caveats; overview |
| [A72](../References.md#a72) FireEye / Mandiant | 2015. Probable APT28 association; CVE-2015-3043 delivery and CVE-2015-1701 local escalation. | Operations; vulnerabilities; detections |
| [A73](../References.md#a73) Trellix | 2022 (2021 activity). Graphite/OneDrive and PowerShell Empire; original investigation. | Operations; tooling; ATT&CK |
| [A74](../References.md#a74) Trend Micro | 2014. Canonical multistage phishing and website-compromise research. | Operations; tooling; ATT&CK |
| [A75](../References.md#a75) SigmaHQ | 2021-04-05; modified 2023-02-08. Status test; generic Outlook-created macro detection, not a NotDoor-specific attribution rule. | Detections; KQL; Splunk |

## Analytical Decisions

- Name the assessing government; indictment allegations are not convictions. [A05](../References.md#a05), [A32](../References.md#a32)
- Overlapping labels need not denote identical operator populations. [Attribution](attribution.md)
- Preserve ESET's medium-confidence assessment and Proofpoint's distinction from TA422. [A60](../References.md#a60), [A45](../References.md#a45)
- Exclude from confirmed APT28 tooling. [A47](../References.md#a47)
- Separate Unit 74455 / Sandworm from anti-doping espionage. [A06](../References.md#a06), [A11](../References.md#a11)
- Do not transfer Midnight Blizzard's 2026 campaign into APT28. [A46](../References.md#a46)
- Cryptocurrency infrastructure funding is not RaaS revenue. [A05](../References.md#a05), [A41](../References.md#a41)
- Retain published logic and disclose upstream limitations. [Detection register](../detections/Detections.md)
- Publication does not establish present control; absent observation bounds remain empty. [IOC provenance](../iocs/IOCs.md#publication-provenance)

## Prioritized Intelligence Gaps

| Gap | Why it matters | Evidence needed |
|---|---|---|
| Operator identities, contractors and cluster boundaries | Shared tooling and overlapping aliases do not establish an identical operator population or criminal partnership | Corroborated legal records, operator-level evidence and dated cluster comparisons |
| RoundPress / TA458 attribution | ESET and Proofpoint apply different confidence and cluster boundaries | Campaign-level payload, infrastructure and victim overlap with explicit attribution reasoning |
| Current infrastructure control | Router relays, hosting and cloud accounts change control; published indicators are not a live blocklist | Passive DNS, certificate fingerprints, tenancy dates and incident timestamps |
| Token theft and Outlook persistence at a victim | An implant capability does not prove successful collection or continued access | Identity/token audit records, mailbox access, macro/DLL provenance and endpoint execution telemetry |
| Operational cryptocurrency funding | Historical infrastructure payments do not establish current wallets, balances or RaaS revenue | Public transaction identifiers and independently corroborated actor-controlled addresses |
| Ransomware-specific applicability | No verified ransom-note family or affiliate panel is established in the retained material | Direct attributable evidence before assigning a ransomware operating model |
| Collection and retrieval coverage | Unreadable endpoints and negative searches cannot establish absence of reporting | Readable primary reports and further source-specific collection; no inference from search absence |

See [References](../References.md), [Attribution](attribution.md), [Blockchain](blockchain.md) and [IOC index](../iocs/IOCs.md).

## Additional Findings After Original-Source Review

Government and criminal-case publications provide the principal attribution anchors. CERT Polska's May 2024 investigation retains qualified actor association and a legitimate-service caveat. CERT-UA endpoints did not expose readable article text in this review; named vendor/government corroboration supports the retained details. ESET annual reporting and public CrowdStrike material provide context, not actor-specific conclusions from industry-wide totals. [A21](../References.md#a21), [A26](../References.md#a26), [A30](../References.md#a30), [A44](../References.md#a44), [A63](../References.md#a63), [A64](../References.md#a64)

DOJ, Elliptic and public TRM material support the financial discussion without establishing a verified wallet inventory or RaaS payment flow. Targeted Chainalysis, GovCERT and Eurojust APT28 searches yielded no usable direct result. Incomplete ransomware.live retrieval and indexed checks are not a complete census or proof of absence. No paid reporting, private victim telemetry, live router probing or actor contact was used. [A05](../References.md#a05), [A41](../References.md#a41), [A42](../References.md#a42), [A56](../References.md#a56)

Visible Huntress and derivative profile material was insufficient for detailed tactical claims, so original reporting takes precedence. Published government YARA and vendor query bodies retain their original logic; some NCSC catalog downloads remain link-only. Local compilation covers copied rule files, not every linked signature. [A49](../References.md#a49), [A68](../References.md#a68), [detection register](../detections/Detections.md)

**Assessment as of 2026-09-14:** high threat to exposed government, defense, diplomatic and logistics organizations connected to Russian strategic priorities. This judgment follows recent reported campaigns and is not a universal severity score. Prioritize identity and token theft, vulnerable edge devices, mailbox access and cloud traffic from unusual endpoint processes. Neither a shared tool nor an observed capability alone establishes APT28 attribution or execution at a particular victim. [A21](../References.md#a21), [A28](../References.md#a28), [A32](../References.md#a32)
