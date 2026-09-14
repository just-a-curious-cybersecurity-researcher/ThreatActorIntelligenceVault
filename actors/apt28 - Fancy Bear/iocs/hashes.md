# APT28 — Hash Indicators

> Bulk hash indicators support retrospective scanning and triage but have limited durability. Use contextual artifacts and behavioral evidence to interpret matches.

## Windows APT28 Ransomware Samples — SHA-256

Not applicable: the retained samples belong to espionage and credential-access chains.

## Linux / Unix APT28 Ransomware Samples — SHA-256

Not applicable: no APT28 ransomware sample is assigned to this platform category.

## All SHA-256 Values Collected

Unique SHA-256 values: **14**

```text
0bb0d54033767f081cae775e3cf9ede7ae6bea75f35fbfb748ccba9325e28e5e
1ed863a32372160b3a25549aad25d48d5352d9b4f58d4339408c4eea69807f50
2822c72a59b58c00fc088aa551cdeeb92ca10fd23e23745610ff207f53118db9
3f446d316efe2514efd70c975d0c87e12357db9fca54a25834d60b28192c6a69
5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705
6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f
7d51e5cc51c43da5deae5fbc2dce9b85c0656c465bb25ab6bd063a503c1806a9
8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901
9f4672c1374034ac4556264f0d4bf96ee242c0b5a9edaa4715b5e61fe8d55cc8
a876f648991711e44a8dcf888a271880c6c930e5138f284cd6ca6128eca56ba1
a944a09783023a2c6c62d3601cbd5392a03d808a6a51728e07a3270861c2a8ee
b2ba51b4491da8604ff9410d6e004971e3cd9a321390d0258e294ac42010b546
bb23545380fde9f48ad070f88fe0afd695da5fcae8c5274814858c5a681d8c4e
c60ead92cd376b689d1b4450f2578b36ea0bf64f3963cfa5546279fa4424c2a5
```

## SHA-1

Unique SHA-1 values: **2**

```text
5603e99151f8803c13d48d83b8a64d071542f01b
6d39f49aa11ce0574d581f10db0f9bae423ce3d5
```

## MD5

No MD5 values are retained in this collection.

## Provenance and Newly Sourced Artifacts

Reviewed 2026-09-14. Publication dates and campaign windows are not per-sample observation bounds. A29 was published 2026-02-02 for activity observed from 2026-01-29; A25 was published 2025-09-03; A17 was published 2024-04-22. Individual first_seen / last_seen bounds remain empty in the [provenance register](hash-provenance.md).

| SHA256 | Observed role | Source |
|---|---|---|
| `b2ba51b4491da8604ff9410d6e004971e3cd9a321390d0258e294ac42010b546` | Consultation_Topics_Ukraine(Final).doc: RTF delivery | [A29](../References.md#a29) |
| `1ed863a32372160b3a25549aad25d48d5352d9b4f58d4339408c4eea69807f50` | Courses.doc: RTF delivery | [A29](../References.md#a29) |
| `a944a09783023a2c6c62d3601cbd5392a03d808a6a51728e07a3270861c2a8ee` | 2_2.d: MiniDoor dropper | [A29](../References.md#a29) |
| `bb23545380fde9f48ad070f88fe0afd695da5fcae8c5274814858c5a681d8c4e` | VbaProject.OTM: MiniDoor | [A29](../References.md#a29) |
| `0bb0d54033767f081cae775e3cf9ede7ae6bea75f35fbfb748ccba9325e28e5e` | table.d: PixyNetLoader dropper | [A29](../References.md#a29) |
| `a876f648991711e44a8dcf888a271880c6c930e5138f284cd6ca6128eca56ba1` | EhStoreShell.dll: Payload loader | [A29](../References.md#a29) |
| `2822c72a59b58c00fc088aa551cdeeb92ca10fd23e23745610ff207f53118db9` | SplashScreen.png: Embedded payload image | [A29](../References.md#a29) |
| `9f4672c1374034ac4556264f0d4bf96ee242c0b5a9edaa4715b5e61fe8d55cc8` | office.xml: Scheduled-task configuration | [A29](../References.md#a29) |
| `3f446d316efe2514efd70c975d0c87e12357db9fca54a25834d60b28192c6a69` | Covenant Grunt / Filen | [A29](../References.md#a29) |
| `5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705` | SSPICLI.dll: NotDoor delivery chain | [A25](../References.md#a25) |
| `8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901` | testtemp.ini: NotDoor delivery chain | [A25](../References.md#a25) |
| `6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f` | justice.exe: GooseEgg | [A17](../References.md#a17) |
| `c60ead92cd376b689d1b4450f2578b36ea0bf64f3963cfa5546279fa4424c2a5` | DefragmentSrv.exe: GooseEgg | [A17](../References.md#a17) |
| `7d51e5cc51c43da5deae5fbc2dce9b85c0656c465bb25ab6bd063a503c1806a9` | execute.bat / doit.bat / servtask.bat: GooseEgg script | [A17](../References.md#a17) |

SHA-1 filenames and classifications are preserved in [file artifacts](file-artifacts.md) and [hash provenance](hash-provenance.md). The legitimate OneDrive executable is excluded from this malicious sample corpus.
