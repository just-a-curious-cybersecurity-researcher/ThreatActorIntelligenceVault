# Qilin — Source Review

**Presentation reviewed:** 2026-09-15.

## Original Reference-by-Reference Disposition

| Original entry | Review and information added / corrected | Destination |
|---|---|---|
| RansomLook | Reviewed profile, note names and infrastructure metadata. Treats postings as actor claims; raw leak content excluded. Financial page separately checked: no wallet found. | Overview; notes; infrastructure |
| Ransomware.live | Reviewed actor profile/artifact sections. Generic wallet icon legend is not a Qilin address. Dynamic totals not converted into independently confirmed victims. | Overview; IOCs; financial evidence |
| Check Point | Used as a comparison checklist. Corrected late-2023 affiliate recruitment chronology with March 2023 infiltration, separated Chrome post-compromise theft from entry and management bypass from SSL-VPN RCE. | Overview; operations; vulnerabilities |
| Cyberzaintza | Read three-page PDF via browser after direct timeouts. Retained history/platform context; did not adopt undated annual victim counts or definitive geography. | Overview; attribution |
| CrowdStrike | Used public operator-cluster definition, community identifiers and likely August–September 2022 rebrand. Public profile is truncated, so no hidden details inferred. | Attribution; names |
| Vectra | Compared RaaS and technical overview against sample/IR reports. Universal localization kill switch and unverified DDoS/automation assertions not promoted to facts. | Tooling; source caveats |
| NordLayer | Reviewed general access, impact and incident-response framing. Not counted as independent telemetry or financial attribution. | Overview; operations |
| Huntress library | General profile and incident leads. Asahi remains an actor claim in this source; no claim that current lack of a full takedown means no service-level disruption. | Overview; source caveats |
| Darktrace | Reviewed each 2022/2023/2024 probable case, sensor limitations and IOC table. Imported context-specific infrastructure, avoiding universal affiliate attribution. | Operations; IOCs; ATT&CK |

## Analytical Decisions

Group-IB supplies panel and recruitment evidence; Trend Micro documents the Go/Rust transition and variant-specific behavior; Sophos supplies two distinct credential/MSP case studies; Talos adds the credential toolkit, Backblaze exfiltration and dual deployment; Halcyon defines Qilin.B; the Italian CSIRT bulletin adds 2026 vulnerabilities and victim context. ThreatLabz provides three redacted note texts rather than reconstructed screenshots. All are resolved in References.

Financial investigation found evidence beyond victim wallets: official FirstVPN sanctions and five multichain service identifiers, TRM's Qilin-linked purchase, and the AudiA6 disruption with a provider-estimated Qilin flow. These remain service relationships. The [shared financial review](../../financial-source-review.md) records exact SDN screening and the limits of negative search results.

## Additional Findings After Original-Source Review

-: primary discovery, propagation and backup evidence added to the lifecycle and tool categories; source ATT&CK labels are not copied uncritically.
-: incident-tool inventory and selected sample exclusions; no universal whitelist inferred.
-: a bounded negotiation example, with offers separated from outcomes.
-: October 2024 Qilin case, read separately from adjacent ransomware case studies; uncertain exploit claims remain qualified.

The presentation now follows the Akira dossier's section order and table schemas. Actor-specific variants, relationships and dated evidence remain specific to Qilin. Query identifiers and indicator provenance are retained through the restructuring.
