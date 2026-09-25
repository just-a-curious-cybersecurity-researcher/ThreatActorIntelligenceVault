# APT29 / Midnight Blizzard

**Presentation reviewed:** 2026-09-25.

APT29 is a long-running Russian cyberespionage intrusion set. The United Kingdom and partner governments assess that it is almost certainly part of the Russian Foreign Intelligence Service (SVR). Vendor labels describe overlapping analytical clusters and campaigns; they are not interchangeable operator rosters.

This dossier follows the APT28 file and section conventions while preserving the different service attribution and mission. Intelligence review cutoff: **2026-09-25**.

## Quick Profile

| Field | Assessment |
|---|---|
| Name | APT29 / Midnight Blizzard |
| Principal aliases | Cozy Bear, CozyDuke, The Dukes, NOBELIUM, UNC2452, Dark Halo, YTTRIUM, SolarStorm, Blue Kitsune, IRON HEMLOCK, IRON RITUAL, NobleBaron, UNC3524; CrowdStrike: COZY BEAR; Google Threat Intelligence in 2026: ICE RELIC. |
| First observed | Government and MITRE reporting place SVR cyber operations from at least 2008; vendor visibility bounds vary by corpus. |
| Motivation | Strategic foreign intelligence collection. |
| Model | State-linked espionage operations; no evidenced RaaS, affiliate market or proprietary ransomware locker. |
| Primary platforms | Microsoft 365 / Entra ID, Windows, Active Directory and AD FS; documented Linux tooling and compromised network or cloud infrastructure. |
| Primary targeting | Governments, diplomacy, military, think tanks, NGOs, political organizations, technology and IT providers, healthcare research, education, energy and telecommunications. |
| Suspected nexus | Russia / SVR, according to named government assessments. |
| Status | Active. Public reporting through 2026-09 covers Storm-2945 / CaptiveCrunch, ICE RELIC-linked initial-access clusters and Anthropic's GTG-20006. The latter two remain source-qualified rather than automatic aliases for the full actor. |

## Key Intelligence Judgments

**KJ-01 — High Confidence.** APT29 is an intelligence-collection actor associated by multiple governments with the SVR. This is distinct from APT28 / Forest Blizzard, which is associated with the GRU, and from Sandworm / APT44.

**KJ-02 — High Confidence.** Identity is a primary operating surface. Password spraying, stolen tokens, device registration, OAuth application abuse, federation trust manipulation and mailbox access can preserve access without a persistent endpoint implant.

**KJ-03 — High Confidence.** Supply-chain compromise is a demonstrated access method, but SolarWinds does not make every later APT29 intrusion a supply-chain operation.

**KJ-04 — High Confidence.** The actor uses compartmented infrastructure and victim-specific tooling. Historical IoCs have strong retrospective value and weak standalone value for current attribution.

**KJ-05 — Moderate Confidence.** Microsoft assesses Storm-2372 and Storm-2945 as Midnight Blizzard operational subclusters. That vendor assessment does not make every device-code campaign or captive-portal compromise an APT29 operation.

**KJ-06 — High Confidence.** No reviewed source establishes an APT29 ransomware product, ransom-payment program, attributed wallet set or actor-operated onion service. Tor transport is documented; that is not evidence of a published onion hostname.

**KJ-07 — High Confidence.** ChocoShell's temporary shadow-copy use in 2026 supported access to locked browser data and cleanup. It is not evidence of recovery inhibition, disk encryption or T1486.

**KJ-08 — Moderate Confidence.** Anthropic states that its attribution of GTG-20006 is consistent with public reporting linking the activity to Midnight Blizzard. Strong overlap with CaptiveCrunch, device-code abuse, victimology and shared indicators supports inclusion, but GTG-20006 is retained as a source-specific cluster rather than treated as a proven alias for every APT29 operation.

**KJ-09 — Moderate Confidence.** Google Threat Intelligence assesses UNC6293 and UNC7005 with moderate confidence as related to an ICE RELIC initial-access subcluster. Their indicators and procedures are retained in a separate qualified tier. Google's UNC5976 remains excluded because Google assesses it as distinct.

**KJ-10 — High Confidence.** The 2024 joint SVR advisory confirms exploitation of Zimbra CVE-2022-27924 and TeamCity CVE-2023-42793. Its separate list of vulnerabilities reflects assessed capability and interest, not confirmed exploitation; this dossier preserves that distinction.

**KJ-11 — High Confidence.** Government reporting says SVR operators have used cryptocurrency to lease infrastructure, but it supplies no wallet, transaction or service attribution. This supports a procurement method, not a payment program or blockchain-address inventory.

## Navigation

### Intelligence

- [Overview, campaigns and victimology](intelligence/overview.md)
- [Operations and attack lifecycle](intelligence/operations.md)
- [Attribution and relationships](intelligence/attribution.md)
- [Source review, assessment and gaps](intelligence/source-review.md)

### Technical

- [Tooling and malware](technical/tooling-malware.md)
- [Vulnerabilities and exposed infrastructure](technical/vulnerabilities.md)
- [MITRE ATT&CK evidence mapping](technical/mitre-attack.md)

### Defensive Reference

- [Indicators of compromise](iocs/IOCs.md)
- [Detections and threat hunting](detections/Detections.md)
- [References](References.md)

## Analytical Caveat

APT29 is an umbrella analytical label. Core historical Dukes activity, UNC2452, NOBELIUM, Midnight Blizzard operational subclusters and campaign-specific clusters are linked only to the extent stated by each source. Shared victimology, a legitimate cloud service or a common tool cannot establish attribution alone.

## Evidence Currency

Last updated: **2026-09-25**. Public-source dossier; no access to private vendor telemetry, victim systems or live actor infrastructure. Publication date, incident date and indicator observation date are separate fields. Source-native confidence language is retained.

## Structure

<!-- tree:start -->
```text
apt29-midnight-blizzard/
├── detections/
│   ├── APT29-Hunting.yar
│   ├── Detections.md
│   ├── KQL.md
│   └── Splunk.md
├── intelligence/
│   ├── attribution.md
│   ├── operations.md
│   ├── overview.md
│   └── source-review.md
├── iocs/
│   ├── domains.md
│   ├── extensions.md
│   ├── file-artifacts.md
│   ├── file-patterns.md
│   ├── hash-provenance.md
│   ├── hashes.md
│   ├── IOCs.md
│   └── ip-addresses.md
├── technical/
│   ├── mitre-attack.md
│   ├── tooling-malware.md
│   └── vulnerabilities.md
├── README.md
└── References.md
```
<!-- tree:end -->
