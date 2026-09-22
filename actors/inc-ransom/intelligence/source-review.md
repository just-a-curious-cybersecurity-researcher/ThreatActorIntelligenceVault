# INC Ransom — Source Review

**Presentation reviewed:** 2026-09-22.

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| Supplied INC dossier | Used as the collection baseline; separated assertions, artifacts and pointers to sources | Entire dossier |
| MITRE G1032 / S1139 | Group and software treated as different objects; current mappings checked against repository profile | Attribution, ATT&CK, encryptor |
| Picus article | Reviewed as a synthesis; hypothetical example commands are not incident observations | Operations, source provenance |
| ACSC / CERT Tonga / NCSC | Retained current affiliate model, regional incident scope and narrowly attributed infrastructure role | Overview, attribution, operations |
| Secureworks GOLD IONIC | Retained its older closed-group assessment and conditional wording for Citrix Bleed | Attribution, vulnerabilities |
| Huntress 2023, 2024 and 2026 | Separated deployment, pre-encryption tools, exfiltration and payload activity | Operations, IOCs, detections |
| Cybereason / SentinelOne / Trend Micro | Used for classic behavior and historical variant context; sample-dependent flags remain scoped | Encryptor, tooling |
| GuidePoint and newly supplied Dark Reading | Original recovery analysis retained; news headline is not evidence of a universal decryption key | Encryptor |
| Newly supplied CyPro | Reviewed as a secondary Rust summary; traced technical detail to original reverse engineering | Encryptor, references |
| Acronis / HivePro / press summaries | Original Acronis register used for sample hashes; Veeam extraction separated from encryptor; conflicting packing statements qualified | Encryptor, IOCs |
| Unit 42 / INC–Lynx–Sinobi leads | Technical relationship retained; related-family samples excluded from INC hash detections | Attribution |
| TRM / Chainalysis | Added direct financial research; differentiated multi-brand findings from INC address attribution | Blockchain |
| ransomware.live / RansomLook | Tracker totals remain separate collection claims; five ransomware.live note pages retrieved and checked for rendered content on 2026-09-22 | Notes, references |
| Morado / SC3 / unnamed hash lists | Values without independently inspected original artifact provenance are not promoted into actionable sample lists | IOC scope |
| Fortra, ProvenData, Halcyon, FortiGuard, Check Point, SocPrime, Vectra, UnderDefense, SOSRansomware, LeMagIT and remaining publisher-only pointers | Supplied leads, not a claim that every unnamed article was retrieved; overlapping content checked through cited originals | Review coverage |
| Treasury / OFAC and unrelated CISA advisories | No transfer of another group's designation, wallets or attack procedures into INC | Financial scope |

## Analytical Decisions

The note's AES-256-CBC claim is not a universal description: an independently examined classic sample uses CTR. Mode thresholds remain attached to examined formats. --kill is separated from --safe-mode.

The Veeam credential extractor is a separate pre-encryption tool. The Linux Rust analysis places ephemeral-key initialization at worker-thread level. The Windows packing description in the original report contradicts itself, so a universal VMProtect claim is excluded.

CVE-2023-35082 is not SimpleHelp. Broad vulnerability lists are not automatically incident-confirmed exploit chains. Tracker totals with different observation dates or collection methods are not added together.

The malformed short onion name in the supplied note is excluded. Related-family hashes, incident passwords and corrupted digest strings are not converted into INC indicators.

## Additional Findings After Original-Source Review

The second review retrieved SonicWall's migrated Linux article and inspected its script screenshot. The delete helper removes snapshots; the article's broader “delete virtual machines” prose is not repeated as a technical finding. A failed helper invocation outside ESXi is separated from successful hypervisor execution.

Microsoft adds a healthcare affiliate/deployer relationship and financial evidence concerning a malware-signing supplier. Neither relationship is promoted to a new INC alias or treasury attribution.

Cyber Centaurs' repository recovery is separated from decrypting victim originals. Its SHA-1 and MD5 values are preserved as published, without inventing SHA-256 equivalents. Tooling present on a host is not treated as proof that the tool completed exfiltration.

The note archive was successfully revisited: its group label is incransom, but its five individual note endpoints use the inc archive path. All five returned rendered note content without storing local copies.

The ESXi query now consumes forwarded hypervisor logs. Additional service-registry and cloud-endpoint hunts cover actions missed by process-name-only searches.


Public financial research provides substantive cross-brand flow evidence without justifying a list of almost 200 INC-owned addresses. The source scope is preserved in the financial chapter.

Recovery analysis distinguishes metadata-assisted triage, possible extraction of untouched data and cryptographic decryption with a matching key. Rust branding alone establishes none of those recovery outcomes.

All copyable hunts and local YARA rules are identified as repository-authored. Vendor reports supply the documented behavior and artifacts; they are not credited with queries they did not publish.
