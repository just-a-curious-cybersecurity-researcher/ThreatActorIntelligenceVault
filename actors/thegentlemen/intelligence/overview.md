# The Gentlemen — Overview

**Presentation reviewed:** 2026-09-17.

## Background

The Gentlemen is a financially motivated ransomware operation documented from mid-2025. It combines data theft and encryption with a public leak site. Microsoft tracks the platform's operators as Storm-2697; affiliates conduct intrusions using the service.

SOCRadar's profile contains an early-2023 origin that conflicts with the 2025 emergence in primary reporting; that date is not adopted. The initial campaign, first public listing and opening of the affiliate program are different milestones. Branding references Guy Ritchie's films; it is not evidence of operator identity or technical capability.

## Targeting and Victimology

The supplied material and 2025 reporting describe manufacturing, construction, healthcare and insurance victims, with Thailand and the United States prominent in the early sample. Later reporting spans additional regions and financial, education and transportation organizations.

A leak-site listing is an extortion claim. The supplied “320 victims across 17 countries” combines undated totals with an early geographic snapshot and is not presented as a current population.

## Operational Model

Affiliates obtain access, map the environment, weaken protection, collect data and deploy the locker. The platform supplies ransomware and negotiation infrastructure. Tailoring a process killer to a victim's installed security software is observed behavior; it does not make every campaign equally capable.

## Ransomware Development

The documented Windows implementation is Go-based. Its password gate, local/share modes, recovery impairment and cleanup are described in [executable internals](encryptor.md). Linux and ESXi are treated as separate payload branches; platform marketing does not make a Windows command applicable on BSD or NAS appliances.

## Data Leak Site

The group uses onion infrastructure for publication and negotiation. See [infrastructure](../iocs/onion-infrastructure.md) for defanged addresses and [notes](../ransom-notes/Ransom-Notes.md) for externally hosted note text. Site availability is a time-dependent tracker observation.

## Current Evolution in the Collected Research

The collected research moves from an August 2025 incident through 2026 executable, affiliate-program and financial analyses. Unit 42's July 10 publication records 580 claimed victims across 77 countries as of July 7. This is a dated claim population, not independently confirmed encryption incidents. SOCRadar's smaller profile total and the earlier 17-country snapshot use different periods/coverage; they are not combined into one statistic. The practical threat is the combination of privileged access, adaptable defense impairment and coordinated encryption. Financial-service evidence is recorded separately in [blockchain intelligence](blockchain.md).

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| Mid-2025 | Emergence supported by vendor reporting; separate from affiliate recruitment. |
| August 2025 | Trend Micro investigated the campaign behind its September publication. |
| 2025-09-09 | Trend Micro published the adaptive tooling and deployment case. |
| September 2025 | Public recruitment/RaaS expansion described by Microsoft and Cybereason. |
| 2026-03-19 | Group-IB published intrusion and underground-source TTP research. |
| 2026-03-26 | ESET published a synthesis of the tailored intrusion model. |
| 2026-05-04 | Administrator acknowledgement of the internal leak, according to Check Point's later analysis. |
| 2026-05-13 | Check Point published analysis of internal program discussions. |
| 2026-05-28 | Microsoft published its Windows executable analysis. |
| 2026-06-29 | Kaspersky described a Windows C locker and a separate Go backdoor. |
| 2026-07-10 | Unit 42 published a program update with dated leak-site counts and newer tooling names. |
| 2026-07-19 | COLCERT issued its public campaign advisory. |
| 2026-09-17 | Expanded source, executable and detection review; not an incident date. |

## Law-Enforcement Development

The AudiA6 service disruption is relevant financial context, not evidence that The Gentlemen's locker or entire affiliate program was dismantled. See the [financial review](blockchain.md#regulatory-and-judicial-review).
