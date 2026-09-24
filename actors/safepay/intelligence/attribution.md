# SafePay — Attribution

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Evidence Classes and Confidence

- **High confidence:** the SafePay Windows family, note format, DLS brand and specific procedures documented by Huntress, DCSO and NCC.
- **Moderate confidence:** a centralized operating model. Multiple sources and the DLS statement align, but internal membership and external access suppliers are unknown.
- **Low to moderate confidence:** Eastern European or Russian-speaking nexus inferred from language exclusions and victim policy.
- **Low confidence:** continuity with former LockBit or ALPHV personnel. No public identity, shared backend or legal evidence establishes it.

## Names and Scope

| Label | Source and scope | Limitation |
|---|---|---|
| SafePay / Safepay | Actor brand, DLS and ransomware family | Can refer to operator, locker or a DLS claim depending on context |
| SafePay Ransomware Group | FortiGuard and industry profile name | Descriptive name, not a separate cluster |
| SafePay team | Self-identification in ransom note | Actor-controlled claim |
| FortiGuard ID 6331 | FortiGuard actor card | Metadata says RaaS while narrative evidence describes a closed team |
| `Ransom:Win32/Safepay.A` | Microsoft Defender malware detection | Malware label, not an actor alias |
| CrowdStrike / Mandiant / Microsoft actor label | No dedicated public FANCY/UNC/Storm-style name located | Absence of a public label does not mean those vendors lack private tracking |

## Geographic Nexus

Early samples terminate on Russian, Ukrainian, Belarusian, Azerbaijani-Cyrillic, Armenian, Georgian and Kazakh system languages. Microsoft, Halcyon and FortiGuard interpret this as a possible Eastern European or Russian-speaking nexus. Language exclusions are common risk controls in financially motivated malware and do not identify citizenship, location or state direction.

DCSO’s later sample lacked the Cyrillic guard. That difference may reflect a build-specific configuration, development change or victim customization. It does not invalidate the earlier artifact and cannot establish a geographic relocation.

## Relationships and Alternative Hypotheses

| Relationship | Supporting evidence | Assessment and alternatives |
|---|---|---|
| LockBit Black | Shared asynchronous I/O architecture, state-machine concepts, arguments and file-management structures | Strong technical influence. DCSO found independent cryptographic/import/configuration choices; no proof of LockBitSupp control or personnel continuity |
| Former LockBit/ALPHV operators | Halcyon describes possible connections after disruption of major brands | Unconfirmed hypothesis; public evidence does not expose people, panel records or shared infrastructure |
| INC Ransom | Some Defender-disabling commands overlap with an INC deployment; SHA-512 use is uncommon and shared by several families | Procedure or design overlap. Commodity commands and a shared primitive do not establish affiliation |
| BlackSuit | QDoor recovered in one SafePay intrusion resembles a backdoor reported with BlackSuit | Tooling association is incident-scoped; NCC found very low locker-code overlap and no high-confidence actor attribution |
| Initial-access brokers | Purchased access appears in FortiGuard; DCSO considered an IAB plausible for one long delay | Plausible supporting ecosystem, not proof of a public affiliate program |
| INC / Qilin shared cash-out | TRM reports an unpublished global VASP deposit address used in flows attributed to SafePay, INC and Qilin | Financial-service or affiliate overlap; the missing address and transaction graph prevent an operator-level attribution |
| Sygnia / Triskele operational consistency | Separate IR reporting repeats valid remote access, RDP, common archivers/transfer tools and centralized deployment | Supports a repeatable SafePay playbook, but dual-use tools do not identify shared personnel |
| State sponsor | No operational, legal or strategic evidence | Financially motivated crime is the supported assessment |

## Decision Use

Use “SafePay” when a note, extension, exact locker hash, reverse-engineered sample or DLS publication supports the label. Use “SafePay-associated intrusion” when incident-response evidence connects the full operation. Use “SafePay claim” for tracker or DLS-only victims. Do not identify LockBit, ALPHV, BlackSuit or INC operators without separate actor-level evidence.

## Official Organizational Evidence and Limits

No indictment, seized panel, sanctions notice or authenticated internal roster describes SafePay’s organization. The closed-group assessment rests on its own anti-RaaS statement, the absence of public recruitment, vendor observations and recurring operational artifacts. A closed core can still purchase credentials, use brokers, rent infrastructure and deploy public tools. Those dependencies do not by themselves turn the brand into a conventional RaaS.
