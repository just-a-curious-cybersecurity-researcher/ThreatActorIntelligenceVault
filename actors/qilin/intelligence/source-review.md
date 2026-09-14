# Qilin — Source Review

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| RansomLook [Q01](../References.md#q01) | Reviewed profile, note names and infrastructure metadata. Treats postings as actor claims; raw leak content excluded. Financial page separately checked: no wallet found. | Overview; notes; infrastructure |
| Ransomware.live [Q02](../References.md#q02) | Reviewed actor profile/artifact sections. Generic wallet icon legend is not a Qilin address. Dynamic totals not converted into independently confirmed victims. | Overview; IOCs; financial evidence |
| Check Point [Q03](../References.md#q03) | Used as a comparison checklist. Corrected late-2023 affiliate recruitment chronology with March 2023 infiltration, separated Chrome post-compromise theft from entry and management bypass from SSL-VPN RCE. | Overview; operations; vulnerabilities |
| Cyberzaintza [Q04](../References.md#q04) | Read three-page PDF via browser after direct timeouts. Retained history/platform context; did not adopt undated annual victim counts or definitive geography. | Overview; attribution |
| CrowdStrike [Q05](../References.md#q05) | Used public operator-cluster definition, community identifiers and likely August–September 2022 rebrand. Public profile is truncated, so no hidden details inferred. | Attribution; names |
| Vectra [Q06](../References.md#q06) | Compared RaaS and technical overview against sample/IR reports. Universal localization kill switch and unverified DDoS/automation assertions not promoted to facts. | Tooling; source caveats |
| NordLayer [Q07](../References.md#q07) | Reviewed general access, impact and incident-response framing. Not counted as independent telemetry or financial attribution. | Overview; operations |
| Huntress library [Q08](../References.md#q08) | General profile and incident leads. Asahi remains an actor claim in this source; no claim that current lack of a full takedown means no service-level disruption. | Overview; source caveats |
| Darktrace [Q09](../References.md#q09) | Reviewed each 2022/2023/2024 probable case, sensor limitations and IOC table. Imported context-specific infrastructure, avoiding universal affiliate attribution. | Operations; IOCs; ATT&CK |

## Analytical Decisions

Group-IB supplies panel and recruitment evidence; Trend Micro documents the Go/Rust transition and variant-specific behavior; Sophos supplies two distinct credential/MSP case studies; Talos adds the credential toolkit, Backblaze exfiltration and dual deployment; Halcyon defines Qilin.B; the Italian CSIRT bulletin adds 2026 vulnerabilities and victim context. ThreatLabz provides three redacted note texts rather than reconstructed screenshots. All are resolved in [References](../References.md).

Financial investigation found evidence beyond victim wallets: official FirstVPN sanctions and five multichain service identifiers, TRM's Qilin-linked purchase, and the AudiA6 disruption with a provider-estimated Qilin flow. These remain service relationships. The [shared financial review](../../financial-source-review.md) records exact SDN screening and the limits of negative search results.

## Additional Findings After Original-Source Review

- [Q35](../References.md#q35): primary discovery, propagation and backup evidence added to the lifecycle and tool categories; source ATT&CK labels are not copied uncritically.
- [Q36](../References.md#q36): incident-tool inventory and selected sample exclusions; no universal whitelist inferred.
- [Q37](../References.md#q37): a bounded negotiation example, with offers separated from outcomes.
- [Q38](../References.md#q38): October 2024 Qilin case, read separately from adjacent ransomware case studies; uncertain exploit claims remain qualified.

The presentation now follows the Akira dossier's section order and table schemas. Actor-specific variants, relationships and dated evidence remain specific to Qilin. Query identifiers and indicator provenance are retained through the restructuring.
