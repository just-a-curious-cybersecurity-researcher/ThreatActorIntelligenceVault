# Akira — Attribution and Relationships

## Evidence Classes and Confidence

**Observed** here means observed by the named publisher. This repository has not independently accessed victim networks or private attribution telemetry. **High Confidence** means strong direct or convergent evidence for the specific claim; **Moderate Confidence** means credible but incomplete evidence or plausible alternatives; **Low Confidence** marks weak, indirect or uncorroborated support.

## Names and Scope

| Label | Source and scope | Limitation |
|---|---|---|
| Akira | Ransomware brand, operation and malware family | Context must specify which entity is meant; excludes 2017 namesake |
| PUNK SPIDER | CrowdStrike developer/maintainer cluster; community identifiers include Storm-1567, REDBIKE and Darter [A20](../References.md#a20) | Public excerpt does not establish identical membership across all vendor clusters |
| Howling Scorpius | Unit 42 designation for the operation [A21](../References.md#a21) | Vendor attribution |
| GOLD SAHARA; Storm-1567 | Listed as associated names in the joint advisory [A01](../References.md#a01) | Not proof that every affiliate belongs to the core group |
| STAC5881 | Sophos intrusion cluster deploying Akira, Fog or Frag [A05](../References.md#a05) | Affiliate/activity relationship, **not an Akira alias** |
| Megazord; Akira_v2 | Encryptor names | Software variants, not proven separate organizations |

## Geographic Nexus

TRM reports Russian-language forum communications and non-VPN Russian IP observations, assessing a possible Russian/post-Soviet base. GLIMPS mentions Slavic communications and avoidance of Russian victims without exposing its underlying evidence. These are **vendor reports**, not independently inspected communications. [A02](../References.md#a02), [A08](../References.md#a08)

**Assessment — Moderate Confidence:** a Russian-speaking criminal-ecosystem nexus is plausible. Confidence in a specific country of operation or nationality is **Low Confidence**. Language, hosting and victim selection can reflect affiliates, service providers, incomplete collection, deliberate avoidance or deception. No state sponsorship is established.

TRM also reports absence of a Russian-keyboard execution safeguard. That weakens any claim that malware behavior proves universal regional avoidance. Lack of known Russian victims is not proof of operator location. [A02](../References.md#a02)

## Relationships and Alternative Hypotheses

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| Conti | Avast found file-footer, exclusion and cryptographic implementation similarities. Arctic Wolf traced three payments totaling over $600,000 to Conti-affiliated addresses and assigns high confidence to participant overlap. [A16](../References.md#a16), [A17](../References.md#a17) | **Moderate Confidence** in personnel/affiliate overlap; **not** proof of a rebrand. Leaked code, shared developers or common cash-out intermediaries remain alternatives. Vendor high confidence is recorded separately from this dossier's judgment. |
| Snatch | Stairwell identified a target also reportedly attacked by Snatch in an exposed operator dataset. [A12](../References.md#a12) | **Low Confidence** in shared affiliate identity; multi-affiliation is plausible, separate compromise also possible. No verified named member. |
| Fog | Arctic Wolf observed shared intrusion infrastructure; Sophos tracks a cluster deploying both payloads. [A05](../References.md#a05), [A06](../References.md#a06) | **Moderate Confidence** in activity/service overlap, not organizational identity. Financial evidence is evaluated separately in [Blockchain](blockchain.md). |
| Frag | TRM proposes an Akira extension based on shared financial infrastructure; Sophos reports a common deployment cluster. [A02](../References.md#a02), [A05](../References.md#a05) | **Moderate Confidence** in a relationship; shared affiliate or laundering provider remains viable. These sources observe different layers and do not prove common administrators. |
| BlackCat / LockBit | GLIMPS reports technical similarities; underlying comparative evidence is not provided. [A08](../References.md#a08) | **Low Confidence** organizational hypothesis only. Retained as an intelligence gap, not an equivalence. |
| Anubis / Lumos / INC | Similar cash-out timing in TRM reporting. [A02](../References.md#a02) | Timing alone has weak attribution value; operational convenience or shared services can explain it. |

## Decision Use

Attribute an incident using convergent malware, note/configuration, negotiation, timeline and intrusion evidence. Do not infer Akira from an RMM product, a VPN CVE or a shared exchange. Financial links cannot establish the identity of whoever operated a victim endpoint. See [Source Review](source-review.md) for outstanding evidence needs.

## Official Historical Organizational Evidence — May 2026

DOJ reports that Deniss Zolotarjovs, a Latvian national based in Moscow, received a 102-month sentence after pleading guilty to money-laundering and wire-fraud conspiracy. It places his participation around June 2021–August 2023 in an organization led by former Conti leaders, and includes **Akira** among that organization's ransom-note brands. DOJ describes a hierarchical organization operating for a time from St. Petersburg. **High Confidence in this being the official account**, supported by the prosecution; it is stronger evidence for a historical connection than code similarity alone. [A24](../References.md#a24)

**Scope assessment — Moderate Confidence:** this strengthens the historical Conti/Akira relationship. The release does not establish that Zolotarjovs administered Akira's current RaaS, identify which Akira incidents he negotiated, or determine every affiliate's nationality. Brand-level totals in this prosecution must not become Akira-only victim or revenue figures. Royal, Karakurt, TommyLeaks and SchoolBoys are related brands in this official account, not interchangeable contemporary Akira aliases.
