# DragonForce — Intelligence Overview

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Background

DragonForce is a financially motivated ransomware service first consistently observed under that name in late 2023. It supplies affiliates with encryptors, a victim-management and negotiation workflow, leak infrastructure and, increasingly, white-label branding. Public reporting describes a conventional RaaS launch in 2024 followed by a “cartel” model announced in March 2025. The practical change was greater branding flexibility: affiliates could retain their own identity while using DragonForce infrastructure and code.

The name is overloaded. An earlier Malaysian hacktivist identity used DragonForce branding, while the ransomware service presents itself as apolitical and financially motivated. Unit 42 explicitly separates Slippery Scorpius, its name for the ransomware operator, from the Malaysian hacktivist group. The shared name and vendor shorthand explain contradictory origin labels; they do not establish continuity.

No dedicated MITRE ATT&CK group or software object was located for DragonForce at the cutoff. This dossier therefore maps only techniques supported by incident or malware evidence.

## Targeting and Victimology

DragonForce is globally opportunistic. BreachSense classified 470 country records through 2026-09-14: the United States led with 213, followed by the United Kingdom with 41, Germany with 27, Canada with 22, Italy with 15 and Australia with 14. Its sector sample emphasized manufacturing, construction, finance, healthcare, technology, legal services, logistics and education. These totals describe the tracker’s classified subset, not the entire claimed population.

The service’s 2025 data-analysis offer reportedly focused on datasets above roughly 300 GB and organizations with at least USD 15 million in annual revenue. That reflects a monetization preference rather than a hard victim exclusion. The DLS contains smaller organizations and a broad set of countries.

The April 2025 incidents involving Marks & Spencer, Co-op and Harrods are reference cases for a Scattered Spider-style affiliate using DragonForce-associated extortion. M&S disclosed the incident on 2025-04-22; Co-op disclosed disruption on 2025-04-30; Harrods reported an attempted intrusion on 2025-05-01. The NCA later arrested four suspects in relation to the three attacks. DragonForce’s role is supported by the service’s claim and later reporting; the official arrest notice connects the incidents but does not itself assign every technical action to DragonForce core.

## Operational Model

The operator maintains shared infrastructure and malware while affiliates obtain access and conduct intrusions. A 2024 recruitment post offered affiliates 80% of payments. Group-IB’s panel review showed client records, configurable builders, test-decrypt controls, publication scheduling, team accounts and access permissions; affiliates were expected to arrive with proven access and exfiltrated data. The 2025 white-label/cartel model allowed a partner to operate a distinct brand on DragonForce’s backend. The separation matters:

- **Service/operator layer:** evidence can support builder lineage, affiliate panel, DLS, chat, negotiation and shared policies. It cannot identify which person gained access to a victim.
- **Generic affiliate layer:** IR evidence can support the tools and procedures of a case that ended in DragonForce. It does not establish a stable procedure for every affiliate.
- **Named affiliate layer:** sources can establish Scattered Spider/UNC3944/Octo Tempest/Muddled Libra tradecraft in a linked case. The affiliate name does not become a DragonForce alias.

The advertised “cartel” should be read as a service and market arrangement. Public announcements involving RansomHub, LockBit and Qilin exceed the evidence for a durable combined organization. Rival DLS compromises, infrastructure takeovers and partner departures show competition as well as cooperation.

## Ransomware Development

The early Windows branch was constructed from the leaked LockBit 3.0 builder. Binary comparison published by Cyble found strong function and branch similarity, consistent with a rebrand rather than independent source development. Its command-line options and broad endpoint behavior inherit LockBit characteristics.

A later Windows branch uses Conti-derived code and a distinct design: ChaCha8 file encryption, victim-specific RSA-4096 key protection, an encrypted configuration, three file modes, a fixed mutex in the analyzed build, local/network thread pools, optional vulnerable-driver process termination and a structured footer. The code-lineage change invalidates assumptions that every DragonForce sample is “LockBit with a new name.”

Linux/ESXi builds enumerate and stop virtual machines, then encrypt configured filesystem roots. S2W’s 2026 panel review also confirmed NAS and RHEL outputs sharing the Linux cryptographic core, while isolating VM shutdown and ESXi environment collection to the ESXi build.

The 2026 RansomBay beta builder adds per-extension encryption-mode rules and expands the footer’s encryption-ratio field from one byte to four bytes. This changes the Windows footer from 534 to 537 bytes without changing the ChaCha8/RSA-4096 core. The same panel no longer offered the LockBit-derived builder or a visible driver selector, although generated binaries retained BYOVD process termination. Each branch is documented separately under the encryptor index.

## Data Leak Site

At the cutoff RansomLook listed two main DLS addresses, 16 file servers, one negotiation/chat server and two admin endpoints. Thirty-day uptime was poor: the tracker reported a 10% average and marked its parser degraded because of a RaaS captcha. One main DLS was down with 67% uptime and the other was up with 58%; most file servers were down during the snapshot.

RansomLook reported 652 posts, seven in the preceding 30 days and one in the preceding seven days. The last visible post was `arsrenacer.com` at 2026-09-21 00:41. Manual counting of the dated rows produced 70 entries in the 90-day window from 2026-06-27 through 2026-09-21. These are publications, not validated compromises. The drop from 11 to seven in one day reflects the rolling window and possible parser loss, not removal from the all-time total.

## Current Evolution in the Collected Research

The late-2025/2026 evidence shows continued affiliate diversity. A CitrixBleed 2 access chain observed by Huntress ended in DragonForce deployment in one case, but the responder could not determine whether the initial access broker and affiliate were the same entity. A separate Symantec incident began in December 2025 and exposed a longer intrusion involving signed-binary sideloading, several vulnerable or malicious drivers, persistence changes and Backdoor.Turn. The Go backdoor used Microsoft Teams/Skype visitor credentials to acquire TURN relay access and then used QUIC toward its real C2.

The service remained active in September 2026 despite organizational fractures. Devman split from the ecosystem in 2025, competing brands appeared, and Check Point observed a steep quarterly fluctuation. These changes weaken claims of one cohesive cartel but do not remove the service’s operational capacity.

## Intelligence Gaps

Public evidence does not identify a verified operator roster, stable headquarters or a complete affiliate list. No authoritative wallet cluster is public. The current relationship among the service, Devman and advertised cartel members remains partly based on actor statements. NAS/RHEL support is confirmed at the panel/flow level but lacks the hashes, paths and recovery detail available for Windows and ESXi. Tracker posts do not reveal how many entries represent encryption, theft-only extortion, reposts or white-label partners.

## Dated Evolution and Victimology

| Period | Evidence and interpretation |
|---|---|
| 2023-08 to 2023-12 | Vendor emergence dates cluster in late 2023. ransomware.live’s first confirmed DLS capture is 2023-12-13; BreachSense’s 2023-04-06 first-recorded value is collection metadata and should not be treated as a confirmed launch date. |
| 2024-01 | An archived note sets a 2024-01-21 deadline, confirms BTC payment language and uses the original DragonForce chat/blog infrastructure. |
| 2024-06 | The service advertised affiliate recruitment on RAMP with an 80/20 affiliate/operator split. |
| 2024-11 | Linux/ESXi tooling was publicly analyzed; the branch targeted `/vmfs/volumes` and stopped VMs before encryption. |
| 2025-03 | DragonForce announced a cartel/white-label model. This supports service expansion, not a verified merger of named gangs. |
| 2025-04 to 2025-05 | M&S, Co-op and Harrods were attacked. Public attribution connects Scattered Spider-style access and DragonForce extortion; UK authorities later arrested four suspects. |
| 2025-05 | DragonForce interfered with RansomHub and BlackLock infrastructure and advertised partner transfers. Reporting disagrees on voluntary partnership versus hostile takeover. |
| 2025-07 | Microsoft and CISA documented Scattered Spider deployment of DragonForce, including VMware ESXi impact. Devman’s separation exposed organizational instability. |
| 2025-08 | The service advertised data analysis/auditing for large stolen datasets and revenue-based pricing support. |
| 2025-09 | A public alliance with Qilin and LockBit was announced. It remains an actor claim with incomplete operational corroboration. |
| 2025-12 to 2026-02 | Symantec’s U.S. services case used side-loading, BYOVD and Backdoor.Turn over Teams-associated TURN relays. |
| 2026-02 | S2W’s panel review found the LockBit builder and visible driver selector removed, BYOVD still embedded, and a beta builder adding extension-specific modes plus a 537-byte footer. |
| 2026-01 to 2026-06 | Huntress investigated multiple CitrixBleed 2 chains; one culminated in DragonForce encryption. |
| 2026-Q1 | Check Point counted 101 DragonForce-branded victims and described continued growth, while also assessing the cartel as smaller than advertised. |
| 2026-09 | RansomLook showed 652 all-time posts, seven in 30 days, 70 in 90 days and a last post on 2026-09-21. BreachSense showed 670 through 2026-09-14. |

## Law-Enforcement Development

On 2025-07-10 the UK National Crime Agency announced the arrest of four people aged 17–20 in connection with the M&S, Co-op and Harrods attacks. The notice describes suspected Computer Misuse Act, blackmail, money-laundering and organized-crime offenses. It is an investigation milestone, not a conviction or proof that the suspects operated the DragonForce service.

No OFAC SDN entry directly designating DragonForce or a named DragonForce operator was located at the cutoff. Sanctions against other ransomware services and the reuse of LockBit or Conti code do not transfer to DragonForce.
