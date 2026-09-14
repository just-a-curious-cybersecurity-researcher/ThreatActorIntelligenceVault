# APT28 — Attribution and Relationships

Last updated: **2026-09-14**.

## Evidence Classes and Confidence

**Government attribution.** Meaning in this dossier: Named agency attributes or assesses an operation/unit Limitation: Confidence belongs to the source; classified supporting material is not independently available.

**Judicial allegation.** Meaning in this dossier: Named defendants, actions and roles alleged in a charging document Limitation: An indictment is not a conviction.

**Technical observation.** Meaning in this dossier: Responder or original researcher documents artifacts and activity Limitation: Visibility is bounded to observed cases and samples.

**Analytical association.** Meaning in this dossier: Code, infrastructure, targeting or timing supports a relationship Limitation: Shared hosting or a similar lure alone does not establish common control.

**Actor claim.** Meaning in this dossier: Persona publishes a claim or stolen material Limitation: Not independent proof of intrusion, identity or completeness.

**High Confidence** means several compatible evidence elements or strong primary case evidence support the specified judgment. **Moderate Confidence** indicates a credible but bounded association or unresolved alternative. Confidence in unit attribution does not automatically confer confidence on every campaign attached to an alias.

## Names and Scope

| Label | Source and scope | Limitation |
|---|---|---|
| APT28 | FireEye/Mandiant; MITRE G0007 | Intrusion-set label, not an audited staffing list. [A01](../References.md#a01), [A02](../References.md#a02) |
| Fancy Bear / FANCY BEAR | CrowdStrike | Separate from COZY BEAR, including at the DNC. [A04](../References.md#a04) |
| Forest Blizzard | Microsoft | Current naming of activity previously tracked as STRONTIUM. [A16](../References.md#a16) |
| STRONTIUM | Microsoft historical label | Naming change, not evidence of a criminal rebrand or organizational merger. [A16](../References.md#a16) |
| Sofacy | Historical vendor group label; also a malware name in some reporting | Identify whether a source means the group or SOURFACE/Sofacy downloader. [A14](../References.md#a14) |
| Sednit / Sednit Gang | ESET | Includes historical and modern technical corpora; campaign scope remains relevant. [A03](../References.md#a03), [A28](../References.md#a28) |
| Pawn Storm | Trend Micro / TrendAI | Campaign umbrella including the PRISMEX report. [A31](../References.md#a31) |
| Tsar Team | Mandiant / Google | Historical actor alias; not a separate unit established here. [A66](../References.md#a66) |
| Fighting Ursa | Palo Alto Networks Unit 42 | Vendor cluster; do not confuse with Trident Ursa or Cloaked Ursa. [A62](../References.md#a62) |
| FROZENLAKE | Google TAG / GTIG | Used in WinRAR and AI-malware reporting. [A39](../References.md#a39), [A40](../References.md#a40) |
| UAC-0001 | CERT-UA campaign tracking | ESET links CERT-UA's recent campaign reports; not an alias for every Russia-linked UAC identifier. [A26](../References.md#a26), [A30](../References.md#a30), [A28](../References.md#a28) |
| Unit 26165 / 85th Main Special Service Center (GTsSS) | US and UK official attribution | NCSC: almost certainly the GRU unit. Transliteration and Centre/Center vary. [A21](../References.md#a21), [A32](../References.md#a32) |
| BlueDelta / Blue Delta | Recorded Future | Overlaps APT28; HOOKEDGE targeting assessments retain their stated confidence. [A36](../References.md#a36) |
| TA422 | Proofpoint | Distinct from TA458 in the 2026 RoundPress analysis. [A38](../References.md#a38), [A45](../References.md#a45) |
| GruesomeLarch | Volexity | Nearest-neighbor incident attribution. [A18](../References.md#a18) |
| TG-4127 / IRON TWILIGHT | Secureworks CTU | Historical primary research now hosted by Sophos; not an extra independent source. [A43](../References.md#a43) |

**Alias discrepancy:** ANSSI's 2025 English report and Unit 42's catalogue list **UAC-0028**. Recent CERT-UA references use **UAC-0001**. Both strings are recorded with their sources; this dossier does not silently normalize all UAC identifiers into one operational cluster. [A22](../References.md#a22), [A62](../References.md#a62), [A26](../References.md#a26)

## Geographic Nexus

FireEye originally assessed Russian sponsorship from intelligence priorities and development evidence. US charging allegations and UK attribution later identified unit-level relationships. Russian-language resources, Moscow working hours or Russian hosting would be insufficient alone; the assessment here rests on the broader source record. [A02](../References.md#a02), [A05](../References.md#a05), [A08](../References.md#a08)

The 2025 joint advisory includes NSA, FBI, CISA, NCSC, ANSSI and German BSI/BND/BfV among its authors/co-sealers. A jointly signed document is one coordinated assessment, not multiple independent incident datasets. [A21](../References.md#a21)

## Relationships and Alternative Hypotheses

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| Unit 26165 ↔ Unit 74455 | DOJ alleges coordination of theft/publication in 2016 and anti-doping releases. [A05](../References.md#a05), [A06](../References.md#a06) | Documented alleged cooperation; not one interchangeable intrusion set. |
| APT28 ↔ criminal MooBot infrastructure | DOJ/FBI describes reuse of criminally compromised Ubiquiti routers. [A19](../References.md#a19), [A20](../References.md#a20) | Operational appropriation supported; recruitment, payment and profit-sharing not established. |
| APT28 ↔ UAC-0063 / TAG-110 | Recorded Future reports a medium-confidence CERT-UA link. [A65](../References.md#a65) | Keep separate; HATVIBE/CHERRYSPY not automatically core APT28 tooling. |
| APT28 ↔ RoundPress / TA458 | ESET assesses Sednit with medium confidence; Proofpoint distinguishes TA458 from TA422. [A60](../References.md#a60), [A45](../References.md#a45) | Unresolved cluster boundary. Do not promote TA458's 2026 zero-days into confirmed APT28 CVEs. |
| APT28 ↔ Qilin / LockBit / Akira | No case-specific operational or financial link established in the reviewed record | Not included as affiliations; shared providers, country or techniques are insufficient. |
| APT28 ↔ VPNFilter | DOJ's 2018 release includes both APT28 and Sandworm in an alias list. [A10](../References.md#a10) | Historical attribution wording is internally broad; retain context but exclude VPNFilter from the unqualified APT28 malware inventory. |
| APT28 ↔ Splinter | Unit 42 describes a general post-exploitation tool. [A47](../References.md#a47) | No supported APT28-specific association established; not counted as an APT28 family. |

### Same country, different mission — do not confuse

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| APT28 / Forest Blizzard | GRU Unit 26165; espionage, selected hack-and-leak operations | This dossier's subject. [A21](../References.md#a21) |
| APT29 / Midnight Blizzard / Cozy Bear | SVR attribution; separate espionage operations | CaptiveCrunch 2026 and the separate COZY BEAR DNC intrusion are excluded. [A46](../References.md#a46), [A04](../References.md#a04) |
| Sandworm / APT44 / Unit 74455 | GRU; destructive and influence-related operations in official cases | Olympic Destroyer, NotPetya and Sandworm campaign payloads are not imported. [A11](../References.md#a11) |
| Turla | Separate Russia-linked espionage cluster | Shared geography or victims do not establish an APT28 relationship. [A01](../References.md#a01), [A67](../References.md#a67) |
| NoName057, KillNet, CARR | Separate public labels and claim channels | No equivalence or APT28 command relationship established here. Claims alone are excluded. |

This table does not claim that missions never overlap. It prevents overlapping interests from being treated as organizational identity.

## Decision Use

Use the cluster name in the originating report, the associated date and the exact evidentiary basis. A new detection of the same behavior may justify investigation without justifying attribution. Conflicting public labels should remain separate in case management until supporting telemetry connects them.

## Official Organizational Evidence and Limits

**2018 election indictment.** Organizational evidence: Names personnel assigned to Units 26165 and 74455 and alleges distinct roles Confidence / limit: Strong public legal attribution; allegations retained. [A05](../References.md#a05)

**2018 anti-doping case.** Organizational evidence: Alleges remote operators and traveling close-access teams, with publication support Confidence / limit: Does not establish current personnel or contractor arrangements. [A06](../References.md#a06)

**2020 EU/UK sanctions.** Organizational evidence: Unit 26165 and individuals linked to Bundestag operation Confidence / limit: Sanction decision is distinct from conviction. [A07](../References.md#a07), [A08](../References.md#a08)

**2025–2026 UK/US attribution.** Organizational evidence: AUTHENTIC ANTICS and router operations tied to Unit 26165 Confidence / limit: Source assessment, not independent access to GRU records. [A24](../References.md#a24), [A32](../References.md#a32), [A35](../References.md#a35)

The NCSC's 2025 AUTHENTIC ANTICS news page also mentions Unit 74455 alongside the OPCW attempt. Dedicated earlier UK material and the 2026 APT28 advisory place the attempted 2018 close-access OPCW operation in APT28 context. This inconsistency is preserved; it is not used to merge the units. [A24](../References.md#a24), [A08](../References.md#a08), [A32](../References.md#a32)
