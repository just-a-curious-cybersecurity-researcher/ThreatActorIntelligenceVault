# APT28 — Intelligence Overview

Last updated: **2026-09-14**. Confidence applies to the specific judgment or incident, not to every activity grouped under an alias.

## Background

FireEye's 2014 report assessed a Russian-government sponsor from targeting, development patterns and language/time-zone evidence. Later government statements identify GRU Unit 26165. The stronger later attribution must not be projected backwards as something the 2014 researchers independently proved. 

ESET uses an at-least-2004 activity boundary. Its historical corpus includes Xagent, Sedreco, Xtunnel and USBStealer; the 2026 research connects portions of the modern arsenal to earlier code. This supports continuity of tooling, without proving an unchanged staff roster over two decades. 

## Targeting and Victimology

**Ukrainian government and armed forces.** Intelligence value / reported targeting: Operational information, communications and personnel surveillance Evidence / confidence: ESET and official reporting; high confidence in reported targeting. 

**Aid logistics, defense suppliers and IT providers.** Intelligence value / reported targeting: Shipment planning and trusted relationships supporting Ukraine Evidence / confidence: Joint advisory since 2022; high. 

**European diplomatic and political institutions.** Intelligence value / reported targeting: Foreign policy, defense and political decision-making Evidence / confidence: ANSSI, EU and HOOKEDGE reporting; high for established cases, moderate for inferred collection priorities. 

**US political organizations.** Intelligence value / reported targeting: Email theft and subsequent publication in 2016 Evidence / confidence: DOJ allegations and incident-response evidence; high attribution confidence, legal allegations retained. 

**Anti-doping bodies and sports officials.** Intelligence value / reported targeting: Retaliatory theft and selective disclosure following doping investigations Evidence / confidence: DOJ anti-doping case; high confidence in the existence and scope of the charges. 

**Hotels, neighboring organizations and routers.** Intelligence value / reported targeting: Access paths to people or networks of intelligence interest Evidence / confidence: Case-dependent; these intermediaries are not necessarily the final intelligence target. 

Victim country is not operator location. A document impersonating a ministry does not prove that ministry was compromised. Counts of phishing messages, routers, accounts and organizations cannot be added into one victim total.

## Operational Model

The applicable model is intelligence collection, with specialized development, remote operations and historically documented close-access teams. The 2018 anti-doping case alleges that traveling teams transferred access to operators in Russia. It does not describe open affiliate recruitment. 

MooBot provides a concrete criminal-infrastructure overlap: APT28 used routers previously compromised by non-GRU criminal actors. That supports appropriation of access, not proof of an affiliate contract, a revenue-sharing arrangement or a joint ransomware enterprise. 

## Ransomware Development

**No aplica / Not applicable:** the reviewed evidence does not establish an APT28 ransomware product, builder market or RaaS program. The corresponding technical inventory documents espionage implants in [Tooling and Malware](../technical/tooling-malware.md). Trend's destructive-command observation is retained separately from encryption-for-payment. 

## Data Leak Site

**No aplica / Not applicable to a ransomware leak site.** DCLeaks, Guccifer 2.0 and the Fancy Bears' Hack Team persona belong to documented hack-and-leak allegations. They are not evidence of a ransom-payment portal or affiliate panel. Publication support involved Unit 74455 in the DOJ cases. 

The ransomware.live check is recorded as a bounded search, with retrieval limitations, in [Source Review](source-review.md). Absence from a ransomware tracker is not a classification test for a state actor.

## Current Evolution in the Collected Research

The recent evidence covers several independent campaigns:

- **Office exploitation:** Zscaler observed CVE-2026-21509 exploitation on 2026-01-29, after the 2026-01-26 emergency update. This establishes rapid use after disclosure in that visibility window. 
- **Long-term implants:** ESET reports paired BeardShell/Covenant deployments during 2025–2026. 
- **Router-mediated collection:** NCSC, Microsoft, Lumen and DOJ describe compromised-router DNS redirection and selective interception. 
- **Lightweight scripts:** Recorded Future's HOOKEDGE page includes 2026-06-29 and July revisions, although its executive summary retains an April endpoint. 

These findings do not imply one combined intrusion or one implant replacing every previous family.

## Intelligence Gaps

See the final [assessment and collection gaps](source-review.md#prioritized-intelligence-gaps): current operator roster, victim-level outcomes, live infrastructure status, unresolved subcluster boundaries and the unverified public wallet dataset are not filled by analogy to another actor.

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| 2004–2014 | Retrospective activity bounds and the first canonical FireEye assessment; different starting dates reflect different datasets. |
| 2015–2018 | Political and anti-doping compromises, hack-and-leak support, hotel access and firmware persistence. |
| 2019–2023 | Large-scale credential attacks, Linux/router tooling and renewed exploitation of mail clients and archives. |
| 2024–2026 | Continued credential operations coexist with modern custom implants, cloud-service abuse and router DNS collection. |
| 2015-04–2015-05 | **Victim / sector / country:** Bundestag / parliament / Germany **Technique and outcome:** Intrusion, email compromise and theft; later official attribution **Malware / tooling:** No sample assumed from the sanctions notice **Publication / source:** 2020-10-22;  **Confidence:** High; official attribution |
| 2016 | **Victim / sector / country:** DNC, DCCC and campaign personnel / US **Technique and outcome:** Phishing, credential theft, internal collection and coordinated releases **Malware / tooling:** Xagent / Xtunnel in historical technical evidence **Publication / source:** 2016 responder record and 2018-07-13 charges;  **Confidence:** High; charges remain allegations |
| 2016–2018 | **Victim / sector / country:** WADA / anti-doping and sports / multinational **Technique and outcome:** Remote and close-access collection; selective publication **Malware / tooling:** Credential/phishing infrastructure **Publication / source:** 2018 case;  **Confidence:** High for documented allegations |
| 2017-07 | **Victim / sector / country:** Hotels / Europe and Middle East **Technique and outcome:** Phishing, internal movement and credential interception; no demonstrated theft of hotel guests' credentials in that campaign **Malware / tooling:** GAMEFISH, Responder, EternalBlue **Publication / source:** 2017-08-11;  **Confidence:** Moderate, vendor assessment |
| 2018-04 | **Victim / sector / country:** OPCW / international organization / Netherlands **Technique and outcome:** Attempted close-access Wi-Fi operation; distinguish attempt from successful exfiltration **Malware / tooling:** Close-access equipment **Publication / source:** UK attribution and DOJ context;  **Confidence:** High, official attribution |
| By 2018-09 | **Victim / sector / country:** Government-related Sednit targets / Europe **Technique and outcome:** Firmware implant found on a victim system **Malware / tooling:** LoJax **Publication / source:** 2018-09-27;  **Confidence:** High, ESET technical observation |
| 2019–2021 | **Victim / sector / country:** Enterprise and cloud accounts / multinational **Technique and outcome:** Distributed password attacks with follow-on access **Malware / tooling:** Kubernetes infrastructure **Publication / source:** 2021-07-01;  **Confidence:** High, joint advisory |
| 2021 | **Victim / sector / country:** Network infrastructure / US and Europe **Technique and outcome:** Cisco router reconnaissance and malware deployment **Malware / tooling:** Jaguar Tooth **Publication / source:** 2023-04-18;  **Confidence:** High, joint advisory |
| 2022-02 | **Victim / sector / country:** Organization with Ukraine expertise / US **Technique and outcome:** Neighboring compromised systems provided Wi-Fi proximity after credential guessing **Malware / tooling:** Native administration; remote dual-homed systems **Publication / source:** 2024-11-22;  **Confidence:** High, Volexity attribution |
| 2022–2023; disclosed 2024 | **Victim / sector / country:** SPD and Czech institutions / politics, government / Germany, Czechia **Technique and outcome:** Email account targeting; public governmental attribution **Malware / tooling:** Outlook exploitation context in technical sources **Publication / source:** 2024-05-03;  **Confidence:** High; do not invent victim-specific payload |
| 2023 | **Victim / sector / country:** Ukraine / government and other targets **Technique and outcome:** WinRAR exploitation for delivery **Malware / tooling:** Campaign-specific payloads **Publication / source:** 2023-10-18;  **Confidence:** High, Google observation |
| 2023-12 | **Victim / sector / country:** Ukraine / government; related European targeting **Technique and outcome:** Phishing, scripted foothold and credential collection **Malware / tooling:** MASEPIE, STEELHOOK, OCEANMAP **Publication / source:** CERT-UA case corroborated in,  **Confidence:** High for documented chain |
| 2024-01 | **Victim / sector / country:** Compromised Ubiquiti routers / worldwide **Technique and outcome:** Court-authorized disruption of reused criminal botnet **Malware / tooling:** MooBot plus APT28 tooling **Publication / source:** 2024-02-15 and 2024-02-27;  **Confidence:** High |
| Reported 2024-04 | **Victim / sector / country:** Government and other strategic targets / US, Europe, Ukraine **Technique and outcome:** Local privilege escalation after access; not a new April-only campaign **Malware / tooling:** GooseEgg **Publication / source:** 2024-04-22;  **Confidence:** High, Microsoft |
| 2024-03 onward; 2024-05 Poland notice | **Victim / sector / country:** Diplomatic/government targets / Europe, Poland **Technique and outcome:** Car-sale and other lures, staged scripts and service abuse **Malware / tooling:** HEADLACE-related chains **Publication / source:**,  **Confidence:** Medium–high; separate campaigns |
| 2024 | **Victim / sector / country:** Government and defense email / multiple countries **Technique and outcome:** Webmail XSS collection **Malware / tooling:** SpyPress / RoundPress **Publication / source:** 2025 ESET report;  **Confidence:** Moderate; later clustering disagreement |
| 2024-04; 2025–2026 follow-on | **Victim / sector / country:** Government and military personnel / Ukraine **Technique and outcome:** Surveillance and redundant cloud channels **Malware / tooling:** SlimAgent, BeardShell, modified Covenant **Publication / source:** 2025 CERT-UA/Sekoia; 2026-03-10 ESET;  **Confidence:** High for ESET lineage assessment |
| Since 2022; disclosed 2025-05 | **Victim / sector / country:** Logistics and technology / NATO and Ukraine aid routes **Technique and outcome:** Credential attacks, trusted-relationship access and mailbox collection; related camera targeting **Malware / tooling:** HEADLACE, MASEPIE and native tools **Publication / source:** 2025-05-21;  **Confidence:** High; camera linkage qualified by authors |
| 2023 observation; 2025 attribution | **Victim / sector / country:** Microsoft cloud-account users / victim details withheld **Technique and outcome:** Credential/token interception inside Outlook **Malware / tooling:** AUTHENTIC ANTICS **Publication / source:** Report version 2025-05-06; attribution 2025-07-18;  **Confidence:** High; different dates denote different events |
| 2025-06 | **Victim / sector / country:** Ukraine / espionage targets **Technique and outcome:** Runtime LLM-assisted discovery and document collection **Malware / tooling:** PROMPTSTEAL / LAMEHUG **Publication / source:** GTIG 2025;  **Confidence:** High for GTIG observation |
| Published 2025-09-03 | **Victim / sector / country:** Multiple sectors / NATO countries **Technique and outcome:** Outlook macro backdoor, email tasking and exfiltration **Malware / tooling:** NotDoor **Publication / source:**  **Confidence:** Vendor attribution; sample capabilities distinct from confirmed victim outcomes |
| 2025-09–2026-07 | **Victim / sector / country:** Diplomatic / defense-related targets / Romania, Spain, Türkiye **Technique and outcome:** Macro documents, staged tasking and webhook service abuse **Malware / tooling:** HOOKEDGE **Publication / source:** Rolling 2026 page;  **Confidence:** Moderate for targeting; publication metadata incomplete |
| 2026-01-29 | **Victim / sector / country:** Ukraine, Slovakia, Romania / targeted users **Technique and outcome:** Exploitation of CVE-2026-21509 following disclosure **Malware / tooling:** MiniDoor, PixyNetLoader, Covenant **Publication / source:** 2026-02-02;  **Confidence:** High, Zscaler |
| Since 2025-09; escalated 2026-01 | **Victim / sector / country:** Defense supply chain, transport and aid / Central and Eastern Europe **Technique and outcome:** Office delivery, COM persistence and cloud channels; destructive command reported in 2025 branch **Malware / tooling:** PRISMEX components, Covenant **Publication / source:** 2026-03-26;  **Confidence:** High for reported components; qualify exploit-chain inference |
| 2024–2026 | **Victim / sector / country:** Routers and selected downstream identities / global; African government targets in Microsoft visibility **Technique and outcome:** DHCP/DNS changes, selected redirection and credential interception **Malware / tooling:** DNS infrastructure; no endpoint implant required for this path **Publication / source:** 2026-04-07;  **Confidence:** High; ongoing validity of each IP not established |
| 2026-04-07 | **Victim / sector / country:** US part of router network **Technique and outcome:** Operation Masquerade disrupts malicious DNS configuration **Malware / tooling:** Court-authorized remediation **Publication / source:**  **Confidence:** High; disruption is geographically bounded |

**Excluded from the APT28 incident total:** Olympic Destroyer / PyeongChang 2018 (Unit 74455), CaptiveCrunch 2026 (Midnight Blizzard), and TA458's new 2026 webmail exploits as unqualified APT28 events. 

## Law-Enforcement Development

The 2018 election and anti-doping cases describe named officers, organizations and alleged roles. The 2020 EU/UK sanctions, 2024 botnet disruption and 2026 Operation Masquerade represent different interventions. Neither an indictment nor infrastructure seizure establishes that the intrusion set ceased operating. 

See [Attribution](attribution.md) for organizational distinctions and [Blockchain](blockchain.md) for funding, sanctions and provider evidence.
