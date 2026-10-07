# Lynx — Source Review

**Presentation reviewed:** 2026-10-07.

Review date: **2026-10-07**. This file records what each source can and cannot establish. Full URLs are centralized in [References.md](../References.md).

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| Group-IB RaaS analysis | Direct panel evidence: recruitment, 80/20 split, affiliate roles, platform builds, CLI, Linux/ESXi functions and infrastructure. Panel availability was not treated as observed deployment. | Overview; attribution; encryptor; infrastructure; blockchain |
| Unit 42 INC/Lynx comparison | Retained code similarity, Windows samples and note contacts. “Rebranding” in the title is treated as an assessment rather than proven organizational identity. | Attribution; encryptor; hashes |
| Nextron reverse engineering | Used for API-level Windows behavior, key derivation, 116-byte trailer and asynchronous file processing. | Encryptor; detections; IOCs |
| FortiGuard roundup | Confirmed early Windows options, exclusions, process/service strings and 2025 visibility. Later Linux availability updates this snapshot. | Encryptor; tooling |
| Rapid7 early analysis | Preserved early victim count, note infrastructure and lower BinDiff result. Difference from later Group-IB percentages reflects sample/platform scope. | Overview; source caveats |
| The DFIR Report | Used as the primary end-to-end affiliate case: RDP, accounts, NetScan, NetExec, 7-Zip, `temp[.]sh`, Veeam deletion and `w.exe`. | Operations; detections; IOCs |
| CERT Polska | Used for mixed INC/Lynx cases, vulnerable software and remote administration. Cross-brand observations remain scoped. | Operations; attribution; vulnerabilities |
| Microsoft Threat Intelligence | Storm-2113 retained as multiple affiliates deploying Lynx, not the service's universal alias. “Exploits” retained without inventing CVEs. | Attribution; vulnerabilities |
| RansomLook | Used for current tracker snapshot, note links, infrastructure roles and absence of published wallets. Claims are not confirmed breaches. | Overview; notes; infrastructure; blockchain |
| BreachSense | Used for dated victim/sector/country and credential-exposure statistics. Its Akira/Pear-looking onion rows were excluded as probable aggregation contamination. | Overview; source caveats |
| Chainalysis | Retained the public INC/Lynx on-chain-behavior relationship; no address inferred from undisclosed analysis. | Blockchain |
| DNSC / Electrica reporting | Retained official incident attribution and separation of affected enterprise IT from unaffected critical operational systems. | Overview; operations |
| Sinobi research | Retained code/site/infrastructure overlap as a qualified successor or offshoot hypothesis. | Attribution; current evolution |
| PacketWatch | Added multi-case 2026 IR evidence for VPN/phishing access, RMM, credentials, GPO deployment, Rclone, two IPs, a locker hash and ESXi `.vmdk` encryption. Case infrastructure remains affiliate-scoped. | Operations; encryptor; tooling; IOCs; detections |
| Triskele Labs | Added two direct cases involving permissive SSL-VPN LDAP authentication and absent MFA. This is a configuration finding, not an invented CVE. | Operations; vulnerabilities |
| CybaVerse / MSP Corner | Added one Windows sample and its host artifacts. Office/OneNote process-tree observations remain case-specific rather than core Lynx behavior. | Encryptor; IOCs |
| TRM Labs | Added undisclosed shared cash-out points and likely shared-affiliate assessment across Lynx, INC, Qilin, SafePay and Kairos. No wallet was inferred. | Blockchain |

## Analytical Decisions

- A leak post, a confirmed incident, an encrypted endpoint and a paid ransom are different events.
- The Lynx service, affiliates, payload and INC/Sinobi code lineage are kept separate.
- Capabilities exposed by command-line options are not described as executed unless case telemetry supports them.
- No CVE is promoted from a generic ransomware profile into the supported table without Lynx-specific incident evidence.
- Hashes of NetScan and NetExec are context artifacts from one case, not Lynx malware signatures.
- Source links stay in `References.md`; operational files use source names without repetitive inline URLs.

## Prioritized Intelligence Gaps

| Gap | Why it matters | Evidence needed |
|---|---|---|
| Core operator identities and location | Separates ecosystem inference from legal attribution | Indictment, seized infrastructure or independently corroborated identities |
| Exact CVE-led cases | Improves exposure-based hunting | IR timeline linking exploit telemetry, vulnerable build and Lynx deployment |
| Linux/ESXi sample identity | Real-world `.vmdk` encryption is now reported, but exact build matching remains unavailable | ELF hash, invocation and victim chronology |
| Wallet and split flows | Enables sanctions and laundering analysis | Negotiation records, transaction IDs and cluster methodology |
| Sinobi continuity | Resolves rebrand versus shared-code hypotheses | Panel, infrastructure ownership, developer or treasury evidence |
| Current infrastructure ownership | Historical onions and domains age quickly | Dated passive DNS, certificates, service fingerprints and seizure records |

## Additional Findings After Original-Source Review

RansomLook showed 418 all-time posts and no posts in the previous 30 days, while BreachSense's earlier snapshot showed 391 victims and one in its previous 30 days. Snapshot date, source ingestion, post counting and deduplication explain why these should not be reconciled into one definitive figure.

Group-IB's later multi-platform archive updates FortiGuard's February 2025 statement that only Windows had been found. Group-IB still said Linux had not been reported in the wild at its publication date, so binary availability and incident deployment remain separate.

The absence of Lynx wallets from the tracker and public OFAC material is reported plainly. TRM adds a real downstream cash-out overlap but withholds the addresses, so no placeholder address, INC/Qilin/SafePay/Kairos wallet or generic laundering path was inserted. Addresses belonging to the unrelated Lynx cryptocurrency project and an older homonymous malware page were explicitly excluded.

PacketWatch closes two earlier evidence gaps: ESXi `.vmdk` encryption is now documented in direct incident response, and a new Windows locker hash is tied to `pushprinterconnections.exe`. The public record still lacks the exact Linux/ESXi sample hash.
