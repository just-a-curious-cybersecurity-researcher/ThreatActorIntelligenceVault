# Akira — Source Review

**Presentation reviewed:** 2026-09-15.

Review date: **2026-09-10**. This register separates collection from the resulting analysis. A source being reachable is not evidence that all its claims are reliable. The reference register resolves publisher, URL, date and limitations for the original and additional sources.

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| 1 CISA | Read 31-page November 2025 revision through DC3 mirror. Added AHV scope, aliases, additional note names and CVEs. Corrected technique semantics rather than copying its table blindly. | Overview; tooling; vulnerabilities; ATT&CK; IOCs |
| 2 TRM | Read full March 2026 profile. Bounded “present” to that publication; retained all four phases, HTX and exceptions, while keeping Frag as vendor assessment. | Blockchain; attribution |
| 3 Cisco/Talos, previously no URL | Resolved October 2024 and Q1 IR reports. Distinguish Rust Windows Megazord from Linux Akira_v2; note names and return to C++. Found incorrect Cisco CVE/product association. | Tooling; vulnerabilities; notes |
| 4 Microsoft, previously no URL | Resolved July 2024 ESXi investigation. Domain-joined hypervisor group abuse is post-compromise escalation. | Vulnerabilities; ATT&CK; detections |
| 5 Sophos, previously no URL | Resolved STAC5881/Frag investigation; browser text available. Shared affiliate activity is more defensible than brand equivalence. | Attribution; vulnerabilities |
| 6 Arctic Wolf, previously no URL | Resolved October 2024 incident analysis and September 2025 follow-up. Affected firmware does not prove exploitation; stolen credentials can outlast patching. | Operations; vulnerabilities |
| 7 Check Point | Read full overview. Retained general context; excluded uncorroborated demand-size assertion and unsupported large-enterprise-only characterization. | Overview; source caveats |
| 8 GLIMPS | Retrieved and read both PDF pages directly after browser failure. Qualified language, ClickFix/SectopRAT and generic IP claims; conflicting chart denominators prevent quantitative reuse. | Attribution; IOC caveats; tooling |
| 9 Ransomware.live | Retrieved full actor HTML; reviewed profile, infrastructure, notes and indicator sections. Victim entries remain actor claims; not imported as confirmed breaches. | Notes; infrastructure review |
| 10 Darktrace | Read incident analysis, not just general TTP table. Added certificate/PKINIT/U2U evidence, WinRM and two incident IP roles. Corrected any implication that native ESXi accepts RDP. | Operations; IPs; ATT&CK |
| 11 Huntress | Read complete case and IOCs. Added s5cmd, AD export files, AnyDesk SafeBoot registration and observed payload hash. | Operations; detections; IOCs |
| 12 Stairwell, previously no URL | Resolved original June 2023 exposure analysis. Added Fortinet script hashes and separated installed/tested reconnaissance from demonstrated use. | Attribution; tooling; vulnerabilities; hashes |
| 13 Qualys, previously no URL | Resolved overview and its IOC table. CVE-2021-21972 remains reporting with limited incident provenance; chart/date inconsistencies not generalized. | Vulnerabilities; hashes |
| 14 RansomLook | Reviewed all 15 address records and displayed transaction dates. Compared against KELA; the shared source ransomwhe.re is one attribution chain. | Blockchain addresses |
| 15 KELA | Read full report, separating Akira pages from Black Basta. Added negotiation observations; checked appendix addresses. A 64-hex appendix item remains unresolved rather than becoming a wallet. | Operations; blockchain addresses; notes |

## Analytical Decisions

- A malware capability, an observed operator command and a tool merely found on a server are separate evidence classes.
- Older headings and source tables sometimes confuse credential theft with escalation, Tor negotiation with C2, or archiving with exfiltration. The updated mapping uses the demonstrated action.
- Leak-site totals, confirmed victims, incident-response cases, demands and received payments have different denominators. No combined total is calculated.
- Retained legacy hashes have valid syntax; a valid hash length does not verify attribution. Source associations are enriched where exact-value matches can be made.

## Prioritized Intelligence Gaps

| Gap | Why it matters | Evidence needed |
|---|---|---|
| Operator vs affiliate identities and location | A Russian-language service ecosystem does not locate every participant | Independently corroborated identities, legal records, device-level evidence |
| ClickFix/SectopRAT chain | Avoid expanding every affiliate playbook from one unattributed summary | Dated IR timeline, payload/configuration and source link |
| Exfiltration-only prevalence | Failed encryption and deliberate data-only extortion differ | Incident-level outcomes and sampling denominator |
| Current financial flows | TRM phase IV is not continuous September 2026 observation | Public transaction IDs, bridge event identifiers, destination labels |
| Treasury and ultimate beneficiaries | Service deposits obscure internal balances | Exchange records, judicial attribution or independently reproducible clustering |
| Infrastructure control intervals | Cloud IPs and relay services change ownership | Passive DNS/certificates, tenancy dates and incident timestamps |

See References, [Attribution](attribution.md), [Blockchain](blockchain.md) and [IOC index](../iocs/IOCs.md).

## Additional Findings After Original-Source Review

Reviewed 2026-09-16: the [executable internals](encryptor.md) document adds sample-scoped execution flows, variant comparisons and explicit separation of payload, launcher and operator activity. The bibliography records the supporting analyses and a section-to-source map; no malware was executed.

DOJ's May 2026 sentencing record adds historical organizational evidence beyond code/transaction overlap. Chainalysis independently supports Akira/Fog cash-out overlap, while TRM's AudiA6 analysis exposes another shared service. ThreatLabz's three archived note texts establish real wording changes and `.arika` mentions; they do not prove actual extension-emission behavior. The official September SDN snapshot enables reproducible, narrowly scoped screening. [financial review](../../financial-source-review.md)
