# APT29 — Intelligence Overview

**Presentation reviewed:** 2026-09-25.

Last updated: **2026-09-25**. Confidence applies to each campaign or judgment, not to every activity grouped under an alias.

## Background

APT29 is a strategic cyberespionage actor active since at least 2008 in government reporting. Historical Dukes malware, the SolarWinds supply-chain compromise, post-SolarWinds cloud operations and modern Midnight Blizzard identity campaigns form a linked but evolving body of activity. Mandiant's 2022 merge of UNC2452 into APT29 materially expanded the umbrella; it did not erase the value of campaign-specific labels.

The current MITRE G0016 record is version 6.2, modified 2026-07-31. It lists two campaigns—Operation Ghost and the SolarWinds Compromise—and a broad set of cloud, identity, endpoint and supply-chain techniques. The dossier supplements that curated history with Microsoft’s 2025–2026 operational subclusters.

## Targeting and Victimology

**Government and diplomacy.** Foreign-policy correspondence, negotiating positions and institutional relationships remain core collection objectives. European ministries and diplomatic entities recur from Operation Ghost through later phishing.

**Defense, military and intelligence-adjacent organizations.** Government warnings include military organizations and trusted suppliers. Targeting a provider can enable access to downstream public-sector customers.

**Technology and IT services.** SolarWinds, cloud solution providers and Microsoft demonstrate the value of source code, authentication material and privileged trusted relationships.

**Think tanks, NGOs and political organizations.** These targets hold policy analysis, contacts and forward-looking political information. The 2024 WINELOADER campaign expanded one APT29 phishing cluster's visible focus to German political parties.

**Healthcare and research.** The 2020 WellMess/WellMail campaign targeted COVID-19 vaccine research in Canada, the United Kingdom and United States for intelligence and intellectual property.

**Aviation, education, law enforcement, local government, government finance, energy and telecommunications.** The 2024 Five Eyes advisory records expansion across these sectors. It does not mean every organization in those sectors is equally targeted.

**Travelers and hospitality infrastructure.** CaptiveCrunch compromised hospitality-related captive-portal networks to reach corporate travelers. The hospitality operator can be an access path rather than the final intelligence target.

## Operational Model

APT29 operates as an espionage program, not a commercial affiliate service. Campaigns combine tailored malware, credential operations, cloud-native APIs, legitimate services, compromised infrastructure and careful per-victim compartmentation. Operators may abandon weak targets, keep access through identities after endpoint remediation, or deploy multiple persistence layers in high-value environments.

Public sources do not document open recruitment, a negotiator team, affiliate revenue splits or a leak-site business. Vendor uncertainty over direct SVR staffing versus contractors remains an organizational gap, not evidence of criminal franchising.

## Ransomware Development

The reviewed Microsoft, Mandiant, CISA, NCSC, ESET, CrowdStrike and MITRE sources do not establish an APT29 ransomware family, builder or encryption-for-payment workflow. Malware described here supports access, credential theft, persistence, collection, command execution and exfiltration.

ChocoShell can create a volume snapshot to read locked browser databases and then remove that temporary snapshot. The objective and surrounding behavior are credential collection and cleanup; this is not shadow-copy destruction for recovery denial. T1486 is therefore excluded.

## Data Leak Site

No reviewed source identifies an APT29 ransom leak site, affiliate panel or victim-negotiation portal. Ransomware trackers are not authoritative actor registries; their lack of a supported APT29 group entry is consistent with, but does not independently prove, the espionage classification.

## Current Evolution in the Collected Research

- **2024:** password spraying against a legacy Microsoft test tenant led to OAuth application abuse, Exchange Online mailbox access and later attempts against source-code repositories. In parallel, a ROOTSAW/WINELOADER phishing cluster targeted German political parties.
- **2025-01 onward:** Check Point linked a European diplomatic phishing wave to APT29. Fake ministry invitations delivered GRAPELOADER through PowerPoint DLL side-loading, with a revised WINELOADER assessed as a likely later stage.
- **2025-04 onward:** Google tracked UNC6293 using long rapport-building, Google application-specific passwords, Microsoft device-code and OAuth flows against academics, journalists and critics of Russia. Google later assessed UNC6293 and UNC7005 with moderate confidence as related to an ICE RELIC initial-access subcluster.
- **2025-08:** AWS disrupted an opportunistic watering-hole campaign that compromised legitimate sites, redirected a randomized subset of visitors and imitated Cloudflare verification before Microsoft device-code authorization.
- **2024–2025:** Storm-2372 used device-code phishing, messaging applications and Microsoft Teams engagement to obtain tokens, register devices and collect Microsoft 365 email through Graph.
- **2024-10-22:** a large spear-phishing wave sent malicious RDP configuration files to thousands of users in more than 100 organizations, exposing mapped local resources to actor-controlled servers.
- **2026:** Storm-2945 combined device/OAuth phishing with compromised captive portals, traffic manipulation, ClickFix-style execution, CornFlake and ChocoShell. Microsoft explicitly distinguished CaptiveCrunch from Forest Blizzard's separate 2026 DNS-hijacking activity.
- **2025-12–2026-08:** Anthropic observed GTG-20006 automate infrastructure acquisition, device-code phishing, malware rebuilding, persistence, collection and exfiltration. Anthropic described its attribution as consistent with public Midnight Blizzard reporting; this dossier preserves that qualification.
- **2026 taxonomy:** Google Threat Intelligence refers to the actor formerly known as APT29 as ICE RELIC. The naming change does not widen attribution beyond the cited operation.
- **2026 subcluster boundary:** Google assesses UNC6293 and UNC7005 as related to an ICE RELIC initial-access subcluster with moderate confidence. It assesses UNC5976 as a distinct Russian cluster, so UNC5976 and HEADRUSH are excluded from this actor's IOC corpus.

## Intelligence Gaps

See [Source Review](source-review.md#prioritized-intelligence-gaps) for subcluster boundaries, live infrastructure, victim outcomes, contractor questions and telemetry needed to validate cloud persistence.

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| 2008–2012 | Government/MITRE lower bound for SVR cyber operations; exact public visibility varies. |
| 2013–2019 | Operation Ghost uses PolyglotDuke, RegDuke and FatDuke against European foreign ministries and an EU-country embassy; ESET links code and tradecraft to The Dukes with high confidence. |
| 2015 | US government networks and the Democratic National Committee were compromised in activity publicly associated with COZY BEAR/APT29; keep separate from APT28's later DNC operation. |
| 2017 | Mandiant documents APT29 using Tor plus meek domain fronting to tunnel remote services while traffic appeared to reach legitimate Google infrastructure. |
| 2018–2020 | SVR actors exploited internet-facing appliances and used WellMess/WellMail; 2020 vaccine research targeting sought scientific intelligence. |
| 2019-08–2020-12 | SolarWinds build-environment compromise inserted SUNBURST into signed Orion updates; selected victims received follow-on access and identity/cloud operations. |
| 2020–2021 | GoldMax, GoldFinder, Sibot, SUNSPOT, TEARDROP/RAINDROP, BOOMBOX, NativeZone and VaporRage supported layered persistence, delivery and post-compromise operations. |
| 2021–2022 | Large diplomatic phishing waves, trusted-provider access, cloud service-principal abuse and targeted email collection continued after SolarWinds exposure. |
| 2022 | APT29 phished a European diplomatic entity and abused Windows Credential Roaming; Mandiant formally merged UNC2452 into APT29. |
| 2023 | Diplomatic phishing used adaptive payloads and legitimate storage services; cloud identity and mailbox access remained central. |
| 2023 | CERT.PL and Poland's Military Counterintelligence Service documented parallel SNOWYAMBER, HALFRIG and QUARTERRIG delivery chains using diplomatic lures, compromised sites, ISO/IMG files, DLL side-loading, Cobalt Strike and Brute Ratel. The agencies described partial-to-full overlap with NOBELIUM/APT29 rather than a blanket identity assertion. |
| 2023-09 onward | Joint government reporting attributes large-scale exploitation of JetBrains TeamCity CVE-2023-42793 to SVR actors. Observed follow-on activity included privilege escalation, lateral movement, backdoor deployment and long-term access; the advisory did not establish a SolarWinds-style supply-chain operation through the compromised servers. |
| 2023-11–2024-03 | Microsoft corporate intrusion began with password spraying against a legacy non-production tenant account, then OAuth application and mailbox abuse; exfiltrated secrets were used in later repository-access attempts. |
| 2024-02 | WINELOADER campaign targeted German political parties with a compromised WordPress site, ROOTSAW, certutil/tar staging and DLL side-loading. |
| 2024-10-22 | RDP-file phishing reached thousands of users in more than 100 organizations; resource redirection exposed local data and devices to actor infrastructure. |
| 2024-08–2025 | Storm-2372 device-code phishing targeted government, NGO, defense, IT, telecom, healthcare, education and energy organizations across multiple regions. |
| 2025-01–2025-04 | European diplomatic targets received ministry-themed wine-event lures. The chain used `wine.zip`, a legitimate PowerPoint executable, two hidden DLLs, GRAPELOADER persistence and a likely WINELOADER follow-on. |
| 2025-04–2026-08 | UNC6293 and UNC7005 used application-specific passwords, device/OAuth flows, residential proxies, messaging-device linking and selected malware delivery. Google connects them to an ICE RELIC initial-access subcluster with moderate confidence and keeps their infrastructure distinct. |
| 2025-08 | AWS disrupted an APT29 watering hole that injected obfuscated JavaScript into legitimate sites, redirected about 10% of visitors and moved to server-side redirects after disruption; fake Cloudflare pages led to Microsoft device authorization. |
| 2026-02–2026-07 | CaptiveCrunch used OAuth/device-code phishing and, from May, traffic manipulation on compromised hospitality captive portals; CornFlake and ChocoShell supported credential and intelligence collection. |
| 2025-12–2026-08 | Anthropic's GTG-20006 case observed more than 20 organizations in operational planning, reconnaissance or live activity, concentrated on Ukrainian and European government, defense, intelligence, diplomacy, think-tank and drone-technology targets. Device-code phishing, compromised hospitality Wi-Fi, ClickFix delivery, mailbox export, actor-device registration and rapidly rebuilt malware overlap the modern Midnight Blizzard corpus; attribution remains source-qualified. |

## Law-Enforcement Development

Public APT29 disruption is dominated by coordinated attribution, sanctions, advisories, tenant remediation and infrastructure or account takedown rather than a named-officer criminal case equivalent to the 2018 APT28 indictment. US and UK governments attributed SolarWinds to the SVR in 2021. Treasury sanctioned Russian technology entities supporting intelligence services under Executive Order 14024 authorities.

No reviewed source identifies an APT29-specific ransom seizure, decryptor release or cryptocurrency forfeiture. Those absences follow the documented intelligence mission and must not be replaced with financial-crime material about unrelated Russian actors.
