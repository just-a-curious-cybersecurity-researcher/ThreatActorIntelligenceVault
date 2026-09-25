# APT29 — References

**Presentation reviewed:** 2026-09-25.

Public-source review cutoff: **2026-09-25**. Publication, incident, update and retrieval dates are distinguished. Source limitations and alias decisions are recorded in [Source Review](intelligence/source-review.md).

## Source Register

### M01

**MITRE ATT&CK — APT29 — G0016** — retrieved 2026-09-25; G0016 v6.2 modified 2026-07-31.
[MITRE ATT&CK — APT29 — G0016](https://attack.mitre.org/groups/G0016/)
Current aliases, campaigns, software and technique evidence.

### M02

**NCSC and international partners — SVR cyber actors adapt tactics for initial cloud access** — 2024-02-26.
[NCSC advisory](https://www.ncsc.gov.uk/files/Advisory-SVR-cyber-actors-adapt-tactics-for-initial-cloud-access.pdf)
Almost-certain SVR assessment and cloud identity TTPs.

### M03

**NSA, CISA and FBI — Russian SVR Targeting U.S. and Allied Networks** — 2021-04-15.
[CISA alert and joint advisory](https://www.cisa.gov/news-events/alerts/2021/04/15/nsa-cisa-fbi-joint-advisory-russian-svr-targeting-us-and-allied)
Five public-facing CVEs and SVR attribution context.

### M04

**CISA, FBI, NSA and partners — Further TTPs Associated with SVR Cyber Actors — AA21-116A** — 2021-04-26.
[CISA AA21-116A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-116a)
SolarWinds follow-on, cloud, credential and malware behavior.

### M05

**NCSC, CSE, NSA and CISA — APT29 targets COVID-19 vaccine development** — 2020-07-16.
[NCSC full advisory](https://www.ncsc.gov.uk/files/Advisory-APT29-targets-COVID-19-vaccine-development.pdf)
WellMess/WellMail analysis, public IoCs and YARA.

### M06

**Microsoft — CaptiveCrunch: Midnight Blizzard targets travelers worldwide** — 2026-07-31.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/)
Storm-2945 attribution, CornFlake, ChocoShell, FruitStone, public KQL and IoCs.

### M07

**Microsoft — Storm-2372 conducts device code phishing campaign** — 2025-02-13; updated 2026-07-31.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
Device-code flow, messaging-platform social engineering and Graph email collection.

### M08

**Microsoft — Midnight Blizzard conducts large-scale spear-phishing campaign using RDP files** — 2024-10-29.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/)
October 2024 campaign scope, resource redirection and defensive guidance.

### M09

**Microsoft Security Response Center — Actions following attack by nation-state actor Midnight Blizzard** — 2024-01-19.
[MSRC incident disclosure](https://www.microsoft.com/en-us/msrc/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard)
Legacy tenant account, password spray and targeted email exfiltration.

### M10

**Microsoft Security Response Center — Update on actions following Midnight Blizzard attack** — 2024-03-08.
[MSRC incident update](https://www.microsoft.com/en-us/msrc/blog/2024/03/update-on-microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard)
Use of exfiltrated secrets and source-code repository access attempts.

### M11

**Microsoft — Guidance for responders on nation-state attack** — 2024-01-25.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
OAuth application, application role and Exchange Online collection details.

### M12

**Microsoft — GoldMax, GoldFinder, and Sibot: Analyzing NOBELIUM's layered persistence** — 2021-03-04; IoCs updated 2021-04-15.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/)
Malware internals, infrastructure caveats and exact hashes.

### M13

**Microsoft — Breaking down NOBELIUM's latest early-stage toolset** — 2021-05-28.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/)
EnvyScout, BOOMBOX, NativeZone and VaporRage chain.

### M14

**Microsoft — FoggyWeb: Targeted NOBELIUM malware leads to persistent backdoor** — 2021-09-27.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/09/27/foggyweb-targeted-nobelium-malware-leads-to-persistent-backdoor/)
AD FS component paths, credential/certificate collection and detection guidance.

### M15

**Microsoft — MAGICWEB: NOBELIUM's post-compromise trick to authenticate as anyone** — 2022-08-24.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/08/24/magicweb-nobeliums-post-compromise-trick-to-authenticate-as-anyone/)
AD FS post-compromise authentication manipulation.

### M16

**Mandiant — UNC2452 Merged into APT29** — 2022-04-27.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/unc2452-merged-into-apt29/)
Firsthand cluster merge, operational scope, victimology and cloud/email objectives.

### M17

**Mandiant — SolarWinds supply-chain compromise using SUNBURST** — 2020-12-13; APT29 merge note added 2022.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor/)
SUNBURST technical analysis and selective follow-on framing.

### M18

**Mandiant — Microsoft 365 remediation and hardening for UNC2452** — 2021-01-19; merge update 2022.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452/)
Service principals, application impersonation, provider relationships and tenant remediation.

### M19

**Mandiant — APT29 uses WINELOADER to target German political parties** — 2024-03-22.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/apt29-wineloader-german-political-parties)
ROOTSAW delivery, WINELOADER internals, MD5s, domain and staging sequence.

### M20

**Mandiant — APT29 Domain Fronting With TOR** — 2017-03-27.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/apt29-domain-frontin)
Tor/meek encrypted tunnel and remote-service carriage; no actor onion hostname.

### M21

**Mandiant — They See Me Roaming: APT29 and Windows Credential Roaming** — 2022-11-08.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/apt29-windows-credential-roaming/)
Diplomatic phishing, LDAP behavior and credential-roaming abuse.

### M22

**Mandiant — Tracking APT29 phishing campaigns** — 2022.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/tracking-apt29-phishing-campaigns)
BEATDROP, BOOMMIC, Trello and campaign compartmentation.

### M23

**Mandiant — APT29 continues targeting Microsoft** — 2022.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/apt29-continues-targeting-microsoft)
Microsoft 365 and identity-oriented operations.

### M24

**Mandiant — APT29's evolving diplomatic phishing** — 2023.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/apt29-evolving-diplomatic-phishing)
Parallel initial-access tooling and diplomatic targeting.

### M25

**CrowdStrike — COZY BEAR adversary profile** — retrieved 2026-09-25.
[CrowdStrike Adversary Universe](https://www.crowdstrike.com/en-us/adversaries/cozy-bear/)
Likely SVR nexus, community aliases, objective and contractor uncertainty.

### M26

**CrowdStrike — Observations from the StellarParticle campaign** — 2022-01-27.
[CrowdStrike blog](https://www.crowdstrike.com/en-us/blog/observations-from-the-stellarparticle-campaign/)
Browser cookies, service principals, Linux GoldMax and TrailBlazer.

### M27

**CrowdStrike — Work with the DNC: setting the record straight** — 2020 update of historical incident.
[CrowdStrike blog](https://www.crowdstrike.com/en-us/blog/bears-midst-intrusion-democratic-national-committee/)
Separates COZY BEAR from FANCY BEAR in the DNC environment.

### M28

**ESET — Operation Ghost: The Dukes aren't back — they never left** — 2019-10-17.
[WeLiveSecurity](https://www.welivesecurity.com/2019/10/17/operation-ghost-dukes-never-left/)
PolyglotDuke, RegDuke, FatDuke, code-lineage hashes and victimology.

### M29

**Unit 42 — Cloaked Ursa uses online storage services in campaigns** — 2022-07-19.
[Unit 42 research](https://unit42.paloaltonetworks.com/cloaked-ursa-online-storage-services-campaigns/)
Dropbox/Google Drive delivery and NATO/diplomatic targeting.

### M30

**Proofpoint — Revisiting MACT: malicious applications in credible cloud tenants** — 2024-04-11.
[Proofpoint research](https://www.proofpoint.com/us/blog/cloud-security/revisiting-mact-malicious-applications-credible-cloud-tenants)
Secondary analysis of application abuse; Microsoft remains primary for its incident.

### M31

**Volexity — Multiple Russian threat actors targeting device-code authentication** — 2025-02-13.
[Volexity research](https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/)
Medium-confidence CozyLarch overlap and explicit separation of UTA0304/UTA0307.

### M32

**US Treasury — Sanctions Russia with sweeping new sanctions authority** — 2021-04-15.
[US Treasury](https://home.treasury.gov/news/press-releases/jy0127)
SVR SolarWinds attribution and sanctions against intelligence-supporting technology companies.

### M33

**UK Government — Russia: UK exposes Russian involvement in SolarWinds compromise** — 2021-04-15.
[GOV.UK](https://www.gov.uk/government/news/russia-uk-exposes-russian-involvement-in-solarwinds-cyber-compromise)
High-likelihood SVR assessment and historical pattern.

### M34

**Microsoft and CrowdStrike — Strategic collaboration on threat actor naming** — 2025-06-02.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2025/06/02/announcing-a-new-strategic-collaboration-to-bring-clarity-to-threat-actor-naming/)
Confirms APT29 / Midnight Blizzard / Cozy Bear cross-vendor naming alignment without claiming perfect equivalence.

### M35

**Google Threat Intelligence Group — Supply-chain compromise mitigation guidance** — 2026-07-30.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/mitigation-guidance-for-supply-chain-compromise)
Uses ICE RELIC as the current Google name for the actor formerly known as APT29 and cites SolarWinds.

### M36

**Microsoft — Midnight Blizzard threat actor profile** — retrieved 2026-09-25.
[Microsoft Security Insider](https://www.microsoft.com/en-us/security/security-insider/midnight-blizzard)
Current Microsoft alias, origin, sector and objective overview.

### M37

**NCSC, CISA, FBI and NSA — Further TTPs associated with SVR cyber actors** — 2021-05-07.
[NCSC joint advisory page](https://www.ncsc.gov.uk/news/joint-advisory-further-ttps-associated-with-svr-cyber-actors)
Official SolarWinds follow-on detection and mitigation context.

### M38

**Ransomware.live — ransomware group tracker** — reviewed 2026-09-25.
[Ransomware.live groups](https://www.ransomware.live/groups)
Bounded negative review: no supported APT29 RaaS group or leak-site dossier was used.

### M39

**RansomLook — ransomware group tracker** — reviewed 2026-09-25.
[RansomLook](https://www.ransomlook.io/)
Bounded negative review; not an attribution authority for state espionage.

### M40

**Breachsense — ransomware group directory** — reviewed 2026-09-25.
[Breachsense ransomware groups](https://www.breachsense.com/ransomware-groups/)
Bounded negative review; no APT29 victim ledger imported.

### M41

**FBI, CISA, NSA, SKW, CERT.PL and NCSC — Russian SVR exploiting JetBrains TeamCity CVE globally — AA23-347A** — 2023-12-13.
[CISA joint advisory PDF](https://www.cisa.gov/sites/default/files/2023-12/aa23-347a-russian-foreign-intelligence-service-svr-exploiting-jetbrains-teamcity-cve-globally_0.pdf)
Actor-specific CVE-2023-42793 exploitation, follow-on access and bounded supply-chain-risk assessment.

### M42

**CISA — Detecting post-compromise threat activity in Microsoft cloud environments — AA21-008A** — 2021-01-08; revised 2021-05-28.
[CISA AA21-008A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a)
SolarWinds-era identity, mailbox, service-principal and cloud-remediation evidence; read with the later government attribution record.

### M43

**Anthropic — Detecting and countering misuse of AI: September 2026** — 2026-09-10; activity window 2025-12 through 2026-08.
[Anthropic Threat Intelligence report](https://www.anthropic.com/threat-intelligence-report-september-2026)
Provider-observed GTG-20006 campaign, qualified Midnight Blizzard linkage, targeting, AI-assisted operations, malware names and public indicators.

### M44

**Check Point Research — Renewed APT29 phishing campaign against European diplomats** — 2025-04-15.
[Check Point Research](https://research.checkpoint.com/2025/apt29-phishing-campaign/)
GRAPELOADER and revised WINELOADER reverse engineering, delivery chain, persistence, anti-analysis behavior and exact indicators.

### M45

**AWS Security — Amazon disrupts watering-hole campaign by Russia's APT29** — 2025-08-29.
[AWS Security Blog](https://aws.amazon.com/blogs/security/amazon-disrupts-watering-hole-campaign-by-russias-apt29/)
Compromised-site redirects, fake Cloudflare verification, device-code abuse, disruption boundaries and two exact domains.

### M46

**AWS Security — Amazon identified internet domains abused by APT29** — 2024-10-24.
[AWS Security Blog](https://aws.amazon.com/blogs/security/amazon-identified-internet-domains-abused-by-apt29/)
Independent provider account of AWS-themed infrastructure and malicious RDP delivery; explicitly excludes compromise of AWS systems.

### M47

**Microsoft — NOBELIUM targeting delegated administrative privileges** — 2021-10-25.
[Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/)
Service-provider trust abuse, cross-tenant administration, RoadTools/AADInternals, Azure Run Command and public hunting guidance.

### M48

**Google Threat Intelligence — Creative phishing against academics and critics of Russia** — 2025-06-18; updated 2025-07-10.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/creative-phishing-academics-critics-of-russia)
UNC6293 application-specific-password theft, device-code/OAuth evolution, residential proxy and lure hash; original APT29/ICECAP link was low confidence.

### M49

**Google Threat Intelligence — Distinct clusters target individuals of interest to Russia** — 2026-08-20.
[Google Cloud Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia)
Moderate-confidence UNC6293/UNC7005 relationship to an ICE RELIC initial-access subcluster, explicit UNC5976 separation and public IoCs.

### M50

**Polish Military Counterintelligence Service and CERT.PL — Espionage campaign linked to Russian intelligence services** — 2023-04-13.
[GOV.PL technical campaign page](https://www.gov.pl/web/baza-wiedzy/espionage-campaign-linked-to-russian-intelligence-services)
Partial-to-full NOBELIUM/APT29 overlap, SNOWYAMBER, HALFRIG, QUARTERRIG, DLL side-loading and commercial post-exploitation tooling.

### M51

**FBI, NSA, CNMF and NCSC — Update on SVR cyber operations and vulnerability exploitation — JCSA-20241010-001** — 2024-10-10.
[FBI joint advisory](https://www.fbi.gov/file-repository/cyber-alerts/update-on-svr-cyber-operations-and-vulnerability-exploitation.pdf)
Confirmed Zimbra and TeamCity exploitation, separately scoped capability-and-interest CVE list, infrastructure acquisition and current government ATT&CK mapping.

## Review Coverage

Reviewed **2026-09-25**. The [source review](intelligence/source-review.md) records how the source families were used, which cluster claims remain qualified and why ransomware, wallet and onion inventories are absent. Primary government, vendor and incident-response reporting takes precedence over aggregator summaries.

## Detection Implementation Provenance

`H01`–`H28` are paired across KQL and Splunk. Microsoft-published predicates are identified in each entry; the remaining searches are repository translations of documented procedures. Thresholds, joins and local field mappings are implementation choices and have not been runtime-validated against a tenant.

| Local query | Documented basis |
|---|---|
| H01 — Distributed password spray with successful follow-on | M02, M09, M11 |
| H02 — Device-code authentication followed by Microsoft 365 access | M06, M07, M31 |
| H03 — New device registration after unusual sign-in | M02, M06, M07 |
| H04 — Credential added to application or service principal | M11, M16, M18, M26 |
| H05 — OAuth consent or high-value application permission grant | M11, M18, M30 |
| H06 — Mailbox delegation or application-impersonation change | M11, M16, M18 |
| H07 — AD, federation and Exchange discovery burst | M16, M21, M26 |
| H08 — Suspicious RDP attachment or RDP client launch | M08 |
| H09 — CornFlake executable path | M06 |
| H10 — CornFlake service registration bundle | M06 |
| H11 — Unexpected FoggyWeb files on AD FS servers | M14 |
| H12 — MAGICWEB DLL or AD FS configuration change | M15 |
| H13 — WINELOADER certutil and tar staging sequence | M19 |
| H14 — WINELOADER DLL loaded by SqlDumper | M19 |
| H15 — CaptiveCrunch network indicators | M06 |
| H16 — Audit policy or PowerShell logging impairment | M04, M16, M42 |
| H17 — Unusual high-volume mailbox access by an application | M11, M16, M18, M42 |
| H18 — Device-code sign-in followed by cloud persistence | M02, M06, M07, M11 |
| H19 — Retained APT29 sample hashes | M05, M06, M12 |
| H20 — ChocoShell-style VSS access for locked browser data | M06 |
| H21 — Suspicious process launched by a Windows TeamCity server | M41 |
| H22 — Anthropic GTG-20006 published indicators | M43 |
| H23 — AWS watering-hole indicators | M45 |
| H24 — GRAPELOADER persistence bundle | M44 |
| H25 — Cross-tenant delegated administration | M47 |
| H26 — Azure Run Command after cloud sign-in | M47 |
| H27 — Qualified UNC6293/UNC7005 indicators | M48, M49 |
| H28 — WINELOADER Windows 7 / Edge 119 user agent | M44 |

| Local YARA rule | Documented basis |
|---|---|
| `wellmess_certificate_base64_snippets` | M05; public NCSC rule |
| `wellmess_regex_used_for_parsing_beacons` | M05; public NCSC rule |
| `APT29_CornFlake_Artifact_Bundle_Triage` | M06; local multi-string heuristic |
| `APT29_GoldMax_Artifact_Bundle_Triage` | M12; local multi-string heuristic |
| `APT29_WINELOADER_Staging_Script_Triage` | M19; local script-chain heuristic |
| `APT29_Retained_SHA256_Exact_Match` | M05, M06, M12, M44; directly attributed/core exact-hash tier in this dossier |
| `APT29_Qualified_Cluster_SHA256_Exact_Match` | M48, M49; exact qualified-cluster hash inventory in this dossier |

## Executable Analysis Provenance

No `encryptor.md` is present because the reviewed corpus provides no APT29 encryptor. Executable behavior in [Tooling and Malware](technical/tooling-malware.md) comes from the original technical analyses: NCSC for WellMess/WellMail (M05), Microsoft for CornFlake/ChocoShell and GoldMax-era tooling (M06, M12–M15), Mandiant for SUNBURST and WINELOADER (M17, M19, M24), CrowdStrike for StellarParticle components (M26), ESET for Operation Ghost (M28), Check Point for GRAPELOADER and WINELOADER 2025 (M44), Polish government researchers for SNOWYAMBER/HALFRIG/QUARTERRIG (M50), Google for qualified UNC6293/UNC7005 tooling (M48–M49), and Anthropic for the campaign-scoped GTG-20006 toolkit (M43).
