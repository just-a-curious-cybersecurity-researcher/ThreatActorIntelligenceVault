# LockBit — Overview

**Presentation reviewed:** 2026-09-17.

## Background

LockBit is a financially motivated ransomware operation and malware family. ABCD activity dates to 2019-09; LockBit branding appeared on Russian-language criminal forums in 2020-01. The affiliate service subsequently combined encryptors, a control panel, negotiation infrastructure, data publication and the StealBit transfer utility.

A malware version identifies code and capabilities. An affiliate identifies an intrusion operator. The LockBit service identifies the organization supplying infrastructure and managing the commercial relationship. These entities overlap, but are not interchangeable, particularly after the 2022-09 leak of the Black builder.

## Targeting and Victimology

The joint international advisory describes victims across healthcare, manufacturing, finance, education, government, energy, food and agriculture, transport and emergency services. The opportunity to compromise remote access and the victim's capacity to pay are more useful targeting indicators than a single industry profile.

Public incident counts have different denominators. ANSSI described 69 confirmed incidents alongside a wider alert set in the 2023 advisory; some alerts originated only from leak-site claims. A public posting is an extortion claim, not independent confirmation of a fresh compromise, successful encryption or payment.

## Operational Model

Core developers maintain the encryptor and affiliate platform. Affiliates acquire access, operate inside victims' networks, steal data, deploy a chosen payload and negotiate. Initial-access brokers and hosting providers can support that chain without becoming members of the development team.

The 2024 Khoroshev indictment alleges a 20 percent developer share. Other reporting describes varying commercial arrangements; a single historical split should not be applied to every campaign. StealBit is a separate exfiltration tool distributed within the service. The presence of a LockBit encryptor does not prove StealBit executed on that endpoint.

## Ransomware Development

The [encryptor directory](encryptor/README.md) separates original Windows LockBit, Red / 2.0, Black / 3.0 and its builder, Conti-derived Green, NG-Dev, the 2024 possible impostors, the 2025 4.0 samples and 5.0.

The branches overlap. The service offered multiple encryptors concurrently, and leaked Black tooling continued to be usable after later releases. A higher version number is not proof that all earlier variants stopped operating. Experimental macOS samples reported in 2023 establish development activity; they do not establish the same deployment prevalence as Windows or ESXi.

## Data Leak Site

The service uses Tor-hosted publication and negotiation infrastructure. These roles are distinct from payload delivery, command and control and exfiltration ingestion. Operation Cronos changed control of infrastructure in 2024; names subsequently reused or replaced require dates and roles.

The dossier retains defanged historical endpoints in [onion infrastructure](../iocs/onion-infrastructure.md) and uses public archives for [ransom notes](../ransom-notes/Ransom-Notes.md). Archived notes can contain actor claims and links to infrastructure whose ownership later changed.

## Current Evolution in the Collected Research

Trend Micro and Check Point documented Windows, Linux and ESXi 5.0 samples and renewed operational activity during 2025-09. The new family includes randomized 16-character hexadecimal suffixes and an invisible mode that suppresses visible changes. Neither the absence of a note nor the absence of a `.lockbit` extension excludes impact.

Check Point counted 163 LockBit leak-site postings in Q1 2026. This is a dated observation of published claims, not 163 independently validated infections or an estimate of the actor's complete victim population. The supplied September tracker totals are not treated as interchangeable with that quarter's measurement.

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| 2019-09 to 2020 | ABCD emergence followed by LockBit branding; original Windows branch develops privilege, encryption and recovery-inhibition routines |
| 2021-06 | Red / 2.0 adds service features including StealBit and automated domain deployment capabilities |
| 2021-10 | Linux-ESXi Locker becomes available; hypervisor impact requires its separate platform-specific payload |
| 2022 | Black / 3.0 appears; sources distinguish earlier emergence from the broad June public launch |
| 2022-09 | Builder leak makes Black-family payload generation available outside the affiliate program |
| 2023-01 to 2023-02 | Green is reported as a Conti-derived alternative; it coexists with Black |
| 2023-11 | Joint Citrix Bleed advisory documents affiliate use of stolen NetScaler sessions and subsequent Windows intrusion tooling |
| 2024-02 | Operation Cronos disrupts the service; NG-Dev analysis and possible 4.0 impostor reporting describe different artifacts |
| 2024-05 | Authorities publicly identify and sanction the alleged administrator, Dmitry Khoroshev |
| 2025-02 to 2025-04 | Post-Cronos 4.0 release and technical analyses; Check Point's sample observations extend through April |
| 2025-05 | Separate affiliate-panel database leak; not another name for the February 2024 seizure |
| 2025-09 | 5.0 Windows, Linux and ESXi variants documented; shared code routines link analyzed 4.0 and 5.0 samples |
| 2026-Q1 | Check Point records 163 DLS postings; renewed claims do not erase the builder-based attribution problem |

## Law-Enforcement Development

The NCA-led Cronos operation, publicly announced on 2024-02-20, seized infrastructure and provided intelligence and decryption assistance. It disrupted a service, not every distributed binary or affiliate foothold.

The 2024-05-07 U.S. indictment alleges that Khoroshev administered and developed LockBit. DOJ announced Rostislav Panev's extradition on 2025-03-13 in a separate alleged developer case. Criminal allegations, sanctions designations and findings after conviction must retain their respective legal status.

