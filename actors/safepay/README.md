# SafePay — Threat Actor Intelligence Dossier

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR  
**Confidence:** High for the Windows ransomware family and the documented intrusion procedures; moderate for the closed-group model; low for operator geography and personnel continuity with older ransomware services.

## Quick Profile

| Field | Assessment |
|---|---|
| Primary name | SafePay |
| Aliases | Safepay; SafePay Ransomware Group; “SafePay team” in ransom notes |
| Vendor tracking | FortiGuard actor ID 6331; Halcyon SafePay; Microsoft `Ransom:Win32/Safepay.A`; no dedicated public CrowdStrike, Mandiant UNC or Microsoft Storm actor name located |
| First observed | September–October 2024; Huntress observed two deployments in October 2024 |
| Business model | Financially motivated, centrally controlled extortion operation; public evidence supports a closed team more strongly than a conventional public RaaS |
| State affiliation | None established |
| Reported geography | Likely Eastern Europe or a Russian-speaking nexus, inferred from language exclusions and victim selection; no operator identity or location is confirmed |
| Platforms | Confirmed Windows; no public Linux or ESXi SafePay encryptor sample located at cutoff |
| Code lineage | Independent Windows implementation influenced by LockBit Black and other ransomware designs; similarity does not establish LockBit operator continuity |
| Principal impact | Targeted data theft, endpoint/share encryption and double extortion, including direct telephone pressure |
| Current tracker snapshot | RansomLook: 574 posts, 21/30d, 66 visible posts in the 90-day window, last post 2026-09-15; BreachSense: 578 total, 22/30d, 245/12m, most recent 2026-09-16; Invaders: 245 since its 2025-11 coverage start, latest discovery 2026-09-20 |
| Financial visibility | Bitcoin payment context is reported, but no public SafePay wallet register or direct SafePay OFAC designation was located |

## Key Intelligence Judgments

- SafePay presents itself as a closed operation and explicitly rejects public RaaS. Microsoft, Huntress, DCSO and Halcyon support centralized control; the FortiGuard “RaaS” metadata label and some industry summaries are insufficient to demonstrate an affiliate program.
- The locker borrows architectural ideas and command-line conventions from LockBit Black, yet DCSO found different cryptographic and hashing choices and assessed independent development. Binary lineage must not be converted into attribution to LockBitSupp or former LockBit personnel.
- Confirmed incident-response evidence supports compromised remote access, weak or stolen credentials, password spraying, RDP/SMB movement, ShareFinder or SharpShares, WinRAR, FileZilla, ScreenConnect, QDoor and rapid network-share encryption.
- Sygnia adds completed OneDrive/SharePoint Online exfiltration, Run-key locker execution, Snaffler, network scanners, Veeam credential access and virtualization-console activity. Triskele adds AnyDesk, Proton VPN/Mullvad, RDP clipboard and direct VPN exfiltration. These remain case-scoped behaviors.
- Speed varies by intrusion. Halcyon describes approximately 24-hour operations, NCC observed encryption after two days, and DCSO observed a 25-day quiet period followed by privilege escalation, theft and encryption within two days.
- SafePay remained active after its 2025 peak. Current trackers disagree by collection time and scope; their totals represent DLS posts or claims, not independently verified compromises.
- Public reverse engineering supports at least two Windows build states. Footer length, algorithm selection and the CIS-language guard differ, so recovery and detection assumptions must remain sample-scoped.

## Navigation

- [Operational lifecycle](intelligence/operations.md)
- [Intelligence overview](intelligence/overview.md)
- [Attribution and relationships](intelligence/attribution.md)
- [Encryptor analysis index](intelligence/encryptor/README.md)
- [Blockchain and payment evidence](intelligence/blockchain.md)
- [Source review and discrepancies](intelligence/source-review.md)
- [MITRE ATT&CK mapping](technical/mitre-attack.md)
- [Tooling and malware](technical/tooling-malware.md)
- [Vulnerability review](technical/vulnerabilities.md)
- [Indicators](iocs/IOCs.md)
- [Detection index](detections/Detections.md)
- [Ransom-note archive links](ransom-notes/Ransom-Notes.md)
- [Source register](References.md)

## Analytical Caveat

The dossier keeps four evidence layers separate: SafePay operators, the SafePay locker, supporting tools used in one or more intrusions, and victim names published on the DLS. A DLS listing proves a SafePay claim, not initial-access ownership, malware execution, successful exfiltration or the accuracy of the claimed volume. Shared code and shared cash-out services establish technical or financial overlap, not common control.

## Evidence Currency

Tracker figures and infrastructure status were checked on 2026-09-24. RansomLook showed 574 all-time posts, 21 in 30 days, 66 dated entries between 2026-06-27 and 2026-09-15, and a degraded 2/16 parser state. BreachSense showed 578 total, 22 in 30 days and 245 in 12 months through 2026-09-23, with a most-recent date of 2026-09-16. Invaders displayed later 2026-09-20 discoveries but covers only claims since 2025-11-12. Dates and totals remain tracker-specific.

## Structure

<!-- tree:start -->
```text
safepay/
├── detections/
│   ├── Detections.md
│   ├── KQL.md
│   ├── SafePay-Hunting.yar
│   └── Splunk.md
├── intelligence/
│   ├── encryptor/
│   │   ├── README.md
│   │   ├── windows-early-build.md
│   │   └── windows-revised-build.md
│   ├── attribution.md
│   ├── blockchain.md
│   ├── operations.md
│   ├── overview.md
│   └── source-review.md
├── iocs/
│   ├── blockchain-addresses.md
│   ├── domains.md
│   ├── extensions.md
│   ├── file-artifacts.md
│   ├── file-patterns.md
│   ├── hash-provenance.md
│   ├── hashes.md
│   ├── IOCs.md
│   ├── ip-addresses.md
│   └── onion-infrastructure.md
├── ransom-notes/
│   ├── Ransom-Notes.md
│   ├── readme-safepay-ascii.md
│   └── readme-safepay.md
├── technical/
│   ├── mitre-attack.md
│   ├── tooling-malware.md
│   └── vulnerabilities.md
├── README.md
└── References.md
```
<!-- tree:end -->
