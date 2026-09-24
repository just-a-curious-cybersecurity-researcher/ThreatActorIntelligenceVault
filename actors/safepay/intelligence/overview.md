# SafePay — Intelligence Overview

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Background

SafePay is a financially motivated ransomware and data-extortion operation first observed in September–October 2024. Huntress documented two unrelated October 2024 deployments before the family had an established public profile. The operation uses the names SafePay, Safepay and SafePay Ransomware Group; the note identifies the intruders as the “SafePay team.”

The public DLS states that SafePay has never provided RaaS. Incident-response reporting and the absence of public affiliate recruitment support a closed or tightly controlled operating model. Some vendor metadata nevertheless classifies the actor as RaaS or private RaaS. This dossier uses “closed operation” unless evidence specifically concerns service or affiliate behavior.

## Targeting and Victimology

SafePay targets organizations across manufacturing, construction, healthcare, education, professional services, logistics, finance, government and nonprofit sectors. BreachSense’s classified subsets place Germany and the United States first, followed by the United Kingdom, Canada, Italy, Spain, Australia and Japan. Current DLS claims also include Peru, Mexico and Switzerland.

The victim set spans small and medium organizations and large service providers. High-volume compromise of a business-process provider can expose records belonging to many client organizations; Conduent illustrates why affected-person totals and the number of directly compromised networks are different measures.

The group combines encryption and threatened publication. DCSO directly observed post-encryption telephone calls intended to accelerate negotiation. The archived note emphasizes financial, personnel, customer, legal and banking data, gives a ten-day contact window, and threatens a further three-day publication timer.

## Operational Model

The best-supported model is a centralized team that retains access, deployment, negotiation and proceeds. SafePay’s own anti-RaaS statement, low forum visibility, recurring workstation names and consistent intrusion sequence support this assessment. It does not prove that the operators never buy access or contract external services: DCSO considered an initial-access broker one plausible explanation for a long quiet period, and FortiGuard lists purchased access as a known vector.

Reported operations begin with weak or stolen credentials, password spraying or remote-access misconfiguration. The operators use RDP, SMB and legitimate remote-management software; enumerate shares; acquire domain-level access; archive selected business data; remove recovery paths; and deploy a password-gated DLL or executable across endpoints and shares. The dwell time is variable rather than universally 24 hours.

Sygnia's 2025 case adds a detailed cloud-enabled sequence: the actor reached domain-admin access within hours, enumerated identity, network, backup and virtualization systems, sought Veeam service credentials, staged split RAR volumes and pivoted from blocked FTP to an attacker-controlled OneDrive tenant. Triskele's response work adds AnyDesk, Proton VPN, Mullvad, RDP clipboard and direct transfer over the access VPN. These observations broaden the playbook without implying that every SafePay intrusion uses every tool.

## Ransomware Development

The Windows locker is written in C and uses asynchronous Overlapped I/O with a processor-scaled worker pool. It requires a victim-specific `-pass` value to unlock embedded configuration. Published arguments cover local paths, network shares, mapped drives, self-deletion, UAC handling, logging and encryption depth.

The family resembles LockBit Black in state-machine structure, command-line concepts, import resolution and asynchronous file handling. DCSO found material differences: Curve25519 rather than LockBit’s RSA design, SHA-512-based derivation, a distinct CRC32 setup and an encrypted configuration in a `.debug` section. Its assessment is independent development influenced by existing ransomware. Huntress described more extensive leaked LockBit overlap. The disagreement is retained as code-lineage uncertainty, not resolved as operator attribution.

No public Linux or VMware ESXi SafePay encryptor sample was located. DCSO observed encryption inside guest virtual machines despite hypervisor privileges, while NCC reported encrypted hypervisors without publishing a platform-specific SafePay binary. That evidence supports virtual-infrastructure impact, not an ESXi-native variant.

## Data Leak Site

SafePay maintains Tor leak, negotiation/chat and file-server infrastructure and has also advertised a TON address. RansomLook recorded five service URLs, nine file servers and two chat servers at cutoff; most were down, while one primary service and one file server remained reachable during portions of the preceding 30 days.

Tracker totals are publication telemetry. They can differ because of parser degradation, discovery timestamps, duplicates, removals and coverage windows. DLS publication must remain labeled as a claim until a victim, regulator, court record or incident-response provider independently confirms the event.

## Current Evolution in the Collected Research

SafePay became one of the highest-volume DLS brands by May 2025, then slowed before recovering in the second quarter of 2026. TRM counted 452 claims by the end of 2025 and used SafePay as an example of high victim volume without proportionate public payment visibility. September 2026 postings show continued geographic breadth and include healthcare, government, technology, manufacturing and Swiss public-service targets.

BreachSense's 2026-09-23 snapshot classified sectors for 376 of 578 claims: manufacturing led with 90, followed by construction (50), healthcare (46), education (40), financial services and logistics (26 each). Countries were identified for 396 claims: Germany (108) and the United States (102) led. Its finding that 114 of 578 victim domains had employee credentials exposed during the preceding year is useful exposure context, but it does not establish those credentials as SafePay's entry route.

Newer Windows analysis reports AES-CBC when AES-NI is available and ChaCha20 otherwise; an earlier analyzed build used ChaCha20 and a shorter footer. DCSO also found that its later sample no longer contained the Cyrillic-language guard described by Huntress and NCC. This is evidence of build evolution, not a reliable indication that regional targeting policy changed.

## Intelligence Gaps

- Operator identities, residence and organizational continuity with LockBit or ALPHV personnel.
- A verified victim-to-payment address set and complete laundering path.
- Incident-level proof for most CVEs listed in aggregate actor profiles.
- Public Linux/ESXi samples, if such a branch exists.
- Stable mapping between locker builds, victim identifiers, negotiations and DLS posts.
- Independent confirmation for many current DLS claims.

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| 2024-09 to 2024-10 | Emergence window. Huntress observed two unrelated October deployments using `.safepay` and `readme_safepay.txt`. |
| 2024-10 to 2024-11 | Early build showed LockBit-like arguments, a CIS-language guard, RDP access and network-share encryption. |
| 2025-Q1 | DCSO incident began with VPN password spraying; a 25-day quiet period preceded a two-day privilege, collection, exfiltration and encryption burst. |
| 2025-05 | SafePay reached the top tier of public DLS activity. DCSO published revised-build internals and assessed independent, influenced development. |
| 2025-07 | Ingram Micro confirmed ransomware and global service disruption; SafePay attribution and 3.5 TB claim came from incident reporting and the later DLS post, not the company’s initial statement. |
| 2025-08 | Children’s Council of San Francisco experienced unauthorized access and later notified 12,655 individuals; SafePay claimed the incident separately. |
| 2025-10 to 2026 | Conduent notifications expanded as client datasets were reviewed. SafePay claimed 8.5 TB, while corporate filings confirmed exfiltration without naming the actor. |
| 2025 year-end | TRM recorded 452 SafePay claims and described the operation as rejecting an affiliate model. |
| 2025 incident / 2026-03 publication | Sygnia documented a seven-day chain from VPN access to OneDrive exfiltration and encryption of more than 60 servers, including Run-key deployment and Veeam/virtualization targeting. |
| 2026-Q2 | Halcyon reported a rebound after a lull and more than double the prior-quarter claim total. |
| 2026-06 publication | Triskele added direct-response evidence from Australian/APAC intrusions: VPN/RDG, valid accounts, RDP, AnyDesk, anonymizing VPNs, clipboard/direct-VPN transfer and common archive tools. |
| 2026-09 | RansomLook showed 574 posts, 21/30d, 66/90d and a 2026-09-15 last post; BreachSense showed 578, 22/30d, 245/12m and 2026-09-16. Invaders, whose collection begins in 2025-11, showed 245 claims and a 2026-09-20 discovery date. These are collection timestamps and scopes, not a single reconciled incident count. |

## Law-Enforcement Development

No public indictment, takedown or direct OFAC designation naming SafePay or identified SafePay operators was located by the cutoff. Victim notifications, corporate filings and law-enforcement notifications confirm individual incidents without establishing the people behind the operation. Sanctions screening must therefore use the payment address supplied in each negotiation and current official lists rather than assuming SafePay is itself designated.
