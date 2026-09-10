# Qilin — Source Review and Intelligence Gaps

## Nine Requested Starting Sources

| Source | Review disposition and substantive use |
|---|---|
| RansomLook [Q01](../References.md#q01) | Reviewed profile, note names and infrastructure metadata. Treats postings as actor claims; raw leak content excluded. Financial page separately checked: no wallet found. |
| Ransomware.live [Q02](../References.md#q02) | Reviewed actor profile/artifact sections. Generic wallet icon legend is not a Qilin address. Dynamic totals not converted into independently confirmed victims. |
| Check Point [Q03](../References.md#q03) | Used as a comparison checklist. Corrected late-2023 affiliate recruitment chronology with March 2023 infiltration, separated Chrome post-compromise theft from entry and management bypass from SSL-VPN RCE. |
| Cyberzaintza [Q04](../References.md#q04) | Read three-page PDF via browser after direct timeouts. Retained history/platform context; did not adopt undated annual victim counts or definitive geography. |
| CrowdStrike [Q05](../References.md#q05) | Used public operator-cluster definition, community identifiers and likely August–September 2022 rebrand. Public profile is truncated, so no hidden details inferred. |
| Vectra [Q06](../References.md#q06) | Compared RaaS and technical overview against sample/IR reports. Universal localization kill switch and unverified DDoS/automation assertions not promoted to facts. |
| NordLayer [Q07](../References.md#q07) | Reviewed general access, impact and incident-response framing. Not counted as independent telemetry or financial attribution. |
| Huntress library [Q08](../References.md#q08) | General profile and incident leads. Asahi remains an actor claim in this source; no claim that current lack of a full takedown means no service-level disruption. |
| Darktrace [Q09](../References.md#q09) | Reviewed each 2022/2023/2024 probable case, sensor limitations and IOC table. Imported context-specific infrastructure, avoiding universal affiliate attribution. |

## Additional Research That Changes the Assessment

Group-IB supplies panel and recruitment evidence; Trend Micro documents the Go/Rust transition and variant-specific behavior; Sophos supplies two distinct credential/MSP case studies; Talos adds the credential toolkit, Backblaze exfiltration and dual deployment; Halcyon defines Qilin.B; the Italian CSIRT bulletin adds 2026 vulnerabilities and victim context. ThreatLabz provides three redacted note texts rather than reconstructed screenshots. All are resolved in [References](../References.md).

Financial investigation found evidence beyond victim wallets: official FirstVPN sanctions and five multichain service identifiers, TRM's Qilin-linked purchase, and the AudiA6 disruption with a provider-estimated Qilin flow. These remain service relationships. The [shared financial review](../../financial-source-review.md) records exact SDN screening and the limits of negative search results.

## Conflicts, Uncertainty and Collection Priorities

| Issue | Treatment / next evidence needed |
|---|---|
| June/July/August 2022 first-seen and September rebrand vs February 2023 RaaS relaunch | Distinguish operator activity, public malware observation, branding and program promotion; no single definitive launch day. |
| 2025 victim counts differ materially | Keep source/time/denominator separate; reconcile unique organizations and reposts before trends are calculated. |
| WSL used to run Linux payload on Windows | Vendor hypothesis; obtain actual WSL/host execution telemetry. |
| Fake CAPTCHA led to Qilin entry | Temporal/credential evidence supports a hypothesis; obtain full delivery/token chain. |
| Legal department, seven-language calling, alliance | Attacker service claims reported by vendors; seek independent operational evidence. |
| Qilin payment/treasury addresses | No validated victim address in reviewed inventory. Obtain redacted negotiation evidence and transaction identifier; never substitute all FirstVPN wallets. |
| Hash-level role in Talos companion | Eleven hashes published without individual labels; preserve as case artifacts until mapped to sample roles. |
| HHS June 2024 profile | Original PDF access failed and mirror retrieval was unavailable; retained as an unresolved lead, not an independent corroborating source. |

Reviewed 2026-09-10. Collection is bounded to public sources and the stated search coverage; absence from the inventory is not proof of absence of activity.
