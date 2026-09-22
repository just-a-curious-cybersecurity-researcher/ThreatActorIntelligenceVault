# LockBit — Attribution

**Presentation reviewed:** 2026-09-17.

## Evidence Classes and Confidence

**High confidence in official publication:** DOJ, Treasury and the NCA identify Dmitry Yuryevich Khoroshev as the alleged administrator behind LockBitSupp. The indictment is an allegation; a sanctions designation is an administrative action.

**High confidence in family identification:** a hash matching a published reverse-engineered sample identifies that artifact. **Moderate confidence in organizational linkage:** code continuity, branding or a matching note supports a relationship but needs campaign and infrastructure context. A leaked-builder payload alone does not identify the person operating it.

## Names and Scope

| Label | Source and scope | Limitation |
|---|---|---|
| LockBit / ABCD | Early malware and later RaaS brand | Original filename extension and brand dates differ |
| LockBit Red / 2.0 | 2021 service and encryptor generation | Windows and Linux-ESXi payloads are separate builds |
| LockBit Black / 3.0 | BlackMatter-related code features; June 2022 public launch context | Public builder has enabled independent use since 2022-09 |
| LockBit Green | Conti-derived branch reported in early 2023 | Not a reliable synonym for every artifact called 4.0 |
| LockBit-NG-Dev | Trend Micro's 2024 .NET development sample | Proposed future-version label does not prove identity with 2025 4.0 |
| LockBit 4.0 | 2025 release branding and analyzed native Windows samples | Unit 42 separately flagged possible impostors using this name in 2024 |
| LockBit 5.0 | 2025 Windows/Linux/ESXi family and renewed service activity | Per-sample technical linkage does not establish who compiled or deployed it |
| LockBitSupp / LockBit / putinkrab | DOJ aliases attributed to Khoroshev | Identity claims should retain the date and authority |

## Geographic Nexus

Russian-language criminal recruitment, official attribution of key participants and language avoidance in analyzed binaries support a Russian-speaking ecosystem nexus. Language checks do not geolocate every affiliate or prove state direction. The published allegations describe a financial criminal enterprise.

## Relationships and Alternative Hypotheses

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| Black and BlackMatter | Reverse engineering identifies shared implementation features | Code reuse supports technical lineage; it does not establish identical personnel |
| Green and Conti | Vendor analysis identifies substantial Conti-derived code | Branch-level relationship; not proof the entire Conti organization became LockBit |
| Leaked Black builder and independent operators | Kaspersky incident analysis and public builder analysis document third-party generation | Family detection must be separated from membership in the RaaS |
| NG-Dev and later 4.0 | Contemporary reporting anticipated a future release | Keep distinct until sample-level lineage is demonstrated; chronology alone is insufficient |
| 2025 4.0 and 5.0 | Trend Micro compares string hashing and API resolution routines | Technical continuity in the compared samples; no blanket identity claim for all “4.0” artifacts |
| RMM vendors and cloud providers | Affiliate intrusions abuse legitimate services | Infrastructure use does not establish vendor complicity |
| LockBit and Qilin / other successor services | Affiliates can migrate or work with multiple brands | Shared operators, tools or victims do not establish a merger |

### The Black builder attribution boundary

The supplied notes describe a leaked package containing `builder.exe`, `keygen.exe`, `config.json` and `Build.bat`. Public analysis confirms that generated encryptors and decryptors can carry different keys, notes and settings. The leak therefore permits operators outside the service to produce recognizable Black-family binaries.

The account that the leak came from a disgruntled developer was reported through criminal and researcher statements; it is not an independently established forensic conclusion about the leak mechanism. Even before the leak, a binary alone was not proof of organizational control.

Correlate the recovered payload with dated negotiation infrastructure, campaign identifiers, operator communications obtained during incident response and separately attributed payment evidence. None of these signals should automatically inherit ownership from a familiar brand.

## Decision Use

Record the narrowest supported conclusion: exact artifact, malware branch, intrusion cluster, affiliate relationship or alleged individual. For the five Unit 42 possible-impostor hashes, retain that source label and keep them out of confirmed service indicators. For decryptors and builder resources, preserve their actual role rather than calling every hash an encryptor.

## Official Organizational Evidence and Limits

The 2024-05-07 indictment alleges that Khoroshev created, developed and administered the service and received a developer share. OFAC simultaneously published a Bitcoin address associated with him. The NCA described access to a network of 194 affiliates during Cronos; affiliate counts are investigative findings at that time, not current membership.

DOJ's consolidated LockBit case page records separate proceedings involving Artur Sungatov, Ivan Gennadievich Kondratiev, Mikhail Vasiliev, Ruslan Astamirov and Rostislav Panev. Panev's 2025 extradition concerns an alleged developer role. These records should not be flattened into a single list of convicted operators.

Publicly documented enforcement against supporting hosting services concerns facilitation infrastructure. It does not make every customer of a host a LockBit participant.

