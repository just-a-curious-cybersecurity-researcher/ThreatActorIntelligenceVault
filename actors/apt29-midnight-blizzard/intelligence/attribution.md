# APT29 — Attribution and Relationships

**Presentation reviewed:** 2026-09-25.

Last updated: **2026-09-25**. Government attribution language is preserved as an assessment; vendor cluster equivalence is scoped to the source that makes it.

## Evidence Classes and Confidence

| Label | Source and scope | Limitation |
|---|---|---|
| Joint government assessments | NCSC and international partners assess APT29 is almost certainly part of the SVR; US and UK governments attribute SolarWinds to the SVR | Does not disclose internal evidence, personnel roster or organizational chart |
| Firsthand incident response | Mandiant merged UNC2452 into APT29 after comparing firsthand data; CrowdStrike links StellarParticle to COZY BEAR | Visibility is limited to investigated environments and vendor taxonomy |
| Malware and operational continuity | Dukes code lineage, victimology, infrastructure discipline and recurring cloud/email objectives | Shared code or tools alone cannot prove organizational identity |
| Campaign-specific assessment | Microsoft links Storm-2372 and Storm-2945 to Midnight Blizzard using technical and operational overlaps | A subcluster is not automatically coextensive with every historical APT29 operation |
| Provider-observed campaign assessment | Anthropic says its GTG-20006 attribution is consistent with public reporting linking the actor to Midnight Blizzard | The wording supports a qualified overlap, not automatic equivalence with the full APT29 umbrella |
| Google subcluster assessment | Google assesses with moderate confidence that UNC6293 and UNC7005 relate to an ICE RELIC initial-access subcluster | Google keeps both infrastructures distinct and explicitly separates UNC5976; the relationship is narrower than full alias equivalence |
| Sanctions and public policy | Treasury attributes SolarWinds to the SVR and sanctioned companies supporting Russian intelligence services | Sanctions are not a cryptocurrency attribution dataset or a criminal conviction |

## Names and Scope

| Label | Source and scope | Limitation |
|---|---|---|
| APT29 | Mandiant and MITRE umbrella for long-running Russia-linked espionage | Boundaries have expanded as clusters were merged |
| Midnight Blizzard | Microsoft name for the Russia-based actor it says US/UK governments attribute to the SVR | Microsoft-specific taxonomy; includes named operational subclusters only when Microsoft states the link |
| NOBELIUM | Earlier Microsoft name for the SolarWinds actor and later related activity | Renamed Midnight Blizzard in Microsoft's 2023 taxonomy |
| UNC2452 | Mandiant temporary cluster for SolarWinds and post-compromise activity | Merged into APT29 in 2022; still useful for source-era precision |
| Dark Halo | Volexity name for SolarWinds-related activity | Campaign/cluster label, not proof of a separate service unit |
| COZY BEAR | CrowdStrike adversary label | CrowdStrike says direct SVR department versus contractor status is unknown publicly |
| The Dukes / CozyDuke | Historical family and operator label used by ESET and other vendors | Historical scope should not be projected automatically onto every modern subcluster |
| IRON HEMLOCK / IRON RITUAL | Secureworks labels listed as aliases by MITRE | Vendor scope can differ by dataset and period |
| NobleBaron | Vendor/community label for assessed APT29-related activity | Some reports retain explicit uncertainty around the relationship |
| UNC3524 | Mandiant cluster included by current MITRE as an alias | Preserve source-level scoping when discussing campaign details |
| ICE RELIC | Google Threat Intelligence's 2026 replacement name for the actor formerly called APT29 | Naming change does not create a new actor or establish continuity for every historical claim |
| Storm-2372 | Microsoft initial-access operational subcluster using device-code phishing | Do not assign unrelated device-code campaigns solely from technique similarity |
| Storm-2945 | Microsoft operational subcluster behind CaptiveCrunch | Microsoft assesses the relationship; initial compromise of captive-portal infrastructure remained under investigation at publication |
| GTG-20006 | Anthropic cluster for Russian espionage activity observed abusing its AI services between 2025-12 and 2026-08 | Anthropic says the attribution is consistent with public Midnight Blizzard reporting; retain this source-qualified boundary |
| UNC6293 | Google cluster using application-specific-password, device-code and OAuth phishing | Google upgraded the link from low confidence in 2025 to moderate confidence with an ICE RELIC initial-access subcluster in 2026 |
| UNC7005 / Storm-2945 | Google and Microsoft labels connected through CaptiveCrunch-era identity and malware operations | Google assesses an ICE RELIC relationship with moderate confidence; Microsoft assesses Storm-2945 as a Midnight Blizzard operational subcluster |
| UNC5976 | Separate Google-tracked Russian authentication-focused cluster | Google explicitly assesses it as distinct; its HEADRUSH malware and IoCs are excluded from the APT29 corpus |

## Geographic Nexus

Government partners attribute APT29 activity to Russia's Foreign Intelligence Service. The operational mission and victimology are consistent with foreign-policy intelligence collection. Hosting geography, residential proxy exit country and lure language identify infrastructure or targeting, not operator location.

## Relationships and Alternative Hypotheses

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| SVR | Joint NCSC/NSA/CISA/FBI and allied assessments; US/UK SolarWinds attribution | High confidence in the public attribution; exact internal SVR structure is not public |
| UNC2452 → APT29 | Mandiant's 2022 merge based on firsthand comparison; government attribution alignment | High confidence for the merged analytical cluster; keep UNC2452 for historical source precision |
| Storm-2372 / Storm-2945 → Midnight Blizzard | Microsoft technical, operational and victimology overlaps | Moderate-to-high confidence within Microsoft taxonomy; not independently proven operator identity |
| UNC6293 / UNC7005 → ICE RELIC initial access | Google target, lure, proxy and methodology overlaps with 2021–2024 ICE RELIC phishing | Moderate confidence; separate infrastructure and differing operational security suggest distinct teams or access cells |
| UNC5976 | Russian nexus and some authentication-focused overlap | Explicit exclusion: Google assesses a distinct cluster that may align with different Russian intelligence requirements |
| APT28 / Forest Blizzard | Both serve Russian state intelligence requirements but APT28 is associated with GRU Unit 26165 | Same country, different service and mission structure; do not merge IoCs, malware or campaigns |
| Sandworm / APT44 | Associated with GRU Unit 74455 and destructive operations | NikoWiper and GRU wipers are excluded from APT29 absent campaign-specific evidence |
| FSB-linked actors | Russian state cyber ecosystem | Separate service; common targets or Russian origin are insufficient for overlap |
| Criminal actors | Public reports emphasize state espionage and may show use of commodity tools or compromised infrastructure | No evidence in the reviewed corpus of an APT29 RaaS affiliate program or revenue-sharing cartel |

### Same country, distinct mission

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| APT29 / Midnight Blizzard | SVR; strategic foreign intelligence, cloud/email collection and long-term access | Subject of this dossier |
| APT28 / Forest Blizzard | GRU Unit 26165; military/political intelligence and selected influence operations | Separate dossier and IoC corpus |
| Sandworm / APT44 | GRU Unit 74455; military disruption and destructive operations alongside espionage | Wipers and destructive GRU campaigns are not assigned here |
| Turla | FSB-linked in public government reporting; long-duration espionage | Co-residence on a victim does not prove cooperation |

## Decision Use

Use the attribution to set collection priorities around identity, email, trusted providers, federation and long-lived access. Escalate an incident to APT29 only when behavior, victimology, infrastructure, malware and timing form a campaign-consistent body of evidence. A single hash can identify a sample; a single OAuth event can identify abuse; neither alone identifies the operator.

## Official Organizational Evidence and Limits

The NCSC and partner agencies assess APT29 is almost certainly part of the SVR. Treasury attributes the 2020 SolarWinds compromise to the SVR and identifies Russian technology companies that supported Russian intelligence services. The UK describes the SolarWinds attribution as highly likely.

The public record does not expose a verified APT29 personnel roster comparable to the public indictments naming GRU officers for APT28. No reviewed OFAC action identifies an APT29-specific cryptocurrency wallet. Sanctions against the SVR or supporting entities establish legal exposure and government attribution; they do not prove that a given blockchain address or intrusion belongs to APT29.
