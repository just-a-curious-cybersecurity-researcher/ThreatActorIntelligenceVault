# APT29 — Hash Indicators

**Presentation reviewed:** 2026-09-25.

> Hashes are selected public examples for retrospective triage. APT29 frequently uses victim-specific or short-lived artifacts, so absence of a match has little exclusion value.

## Windows Samples — SHA-256

| SHA256 | Observed role |
|---|---|
| `918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593` | CornFlake RAT; first_seen 2026-07-03 |
| `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c` | ChocoShell; first_seen 2026-07-10 |
| `2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41` | WellMess .NET sample in NCSC rule metadata |
| `70d93035b0693b0e4ef65eb7f8529e6385d698759cc5b8666a394b2136cc06eb` | GoldMax |
| `0e1f9d4d0884c68ec25dec355140ea1bab434f5ea0f86f2aade34178ff3a7d91` | GoldMax |
| `247a733048b6d5361162957f53910ad6653cdef128eb5c87c46f14e7e3e46983` | GoldMax |
| `0affab34d950321e3031864ec2b6c00e4edafb54f4b327717cb5b042c38a33c9` | GoldFinder |
| `7e05ff08e32a64da75ec48b5e738181afb3e24a9f1da7f5514c5a11bb067cbfb` | Sibot |
| `acc74c920d19ea0a5e6007f929ef30b079eb2836b5b28e5ffcc20e68fa707e66` | Sibot |
| `653db3b63bb0e8c2db675cd047b737cefebb1c955bd99e7a93899e2144d34358` | 2025 GRAPELOADER initial-access archive `wine.zip` |
| `420d20cddfaada4e96824a9184ac695800764961bad7654a6a6c3fe9b1b74b9a` | Legitimate PowerPoint executable `wine.exe` retained as an exact campaign artifact |
| `85484716a369b0bc2391b5f20cf11e4bd65497a34e7a275532b729573d6ef15e` | `AppvIsvSubsystems64.dll` campaign dependency / junk-code sample |
| `78a810e47e288a6aff7ffbaf1f20144d2b317a1618bba840d42405cddc4cff41` | `AppvIsvSubsystems64.dll` campaign variant |
| `d931078b63d94726d4be5dc1a00324275b53b935b77d3eed1712461f0c180164` | GRAPELOADER `ppcore.dll` |
| `24c079b24851a5cc8f61565176bbf1157b9d5559c642e31139ab8d76bbb320f8` | GRAPELOADER `ppcore.dll` variant |
| `adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8` | WINELOADER 2025 `vmtools.dll` |

## Linux / Unix Samples — SHA-256

| SHA256 | Observed role |
|---|---|
| `8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8` | WellMess Go sample; NCSC rule covers PE or ELF |
| `83014ab5b3f63b0253cdab6d715f5988ac9014570fa4ab2b267c7cf9ba237d18` | WellMail UPX-packed sample; Golang implant |
| `0c5ad1e8fe43583e279201cdb1046aea742bae59685e6da24e963a41df987494` | WellMail unpacked sample |

### Qualified ICE RELIC Initial-Access Cluster — SHA-256

These values come from Google's 2026 UNC6293/UNC7005 reporting. Google assesses the ICE RELIC relationship with moderate confidence. Landing-page hashes and commodity stealers identify campaign association; they do not prove proprietary APT29 development. The ChocoShell value also appears in Microsoft's direct Storm-2945 corpus.

| SHA256 | Observed role |
|---|---|
| `329fda9939930e504f47d30834d769b30ebeaced7d73f3c1aadd0e48320d6b39` | Benign UNC6293 State Department-themed lure PDF; campaign association only |
| `5b8d50c2e8cc3038b7c6e6dbf1219f6e814930a1e3c0053143a1191ae67f8ffc` | UNC7005 GLOBSEC phishing page |
| `a06a8fd1b6fa1924199a4540cf16d089217ce8f78c617739946f145fd1fc88c1` | UNC7005 Finnish Operations Center OAuth landing page |
| `1d9299799a7b8da67c44ebec064d64542c27645f8e84de4a22ca3f6cbc843e3c` | VIDAR used by UNC7005 |
| `c5826032207d623a7f6caec8465af7364eccc355f9a48897da2a54f3e4420265` | ATOMIC used by UNC7005 |
| `125752ad7c20d715920a3b2fb0fdde660f07b3f2b053665cf38c2d6d9de86e1e` | ENGINELIGHT |
| `403b624e35777cbc07dbe66398b21bba70396a20b859c880732338ce1dd1f41f` | CHERRYPIE |
| `28f622028e690c943f7fa9aca426c07cab52b5aaba757ef8a3328609c0b3bec3` | CHERRYPIE |
| `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c` | CHERRYPIE / ChocoShell; independently present in Microsoft Storm-2945 reporting |
| `1e3ee845fde739fcd3ca9ce62c7f142a7c501d11db4c4fb294d4939f12d0f916` | CHERRYPIE |
| `6f7090895c1c3dee30de6b3f098ca3a788dc198646e5293a8b1210430b0add97` | CHERRYPIE |
| `20e20b074967ed6f6e04d609ccec5ff7492665ef25f894c90c2ddc92fa47ac38` | CHERRYPIE |
| `ca3be5885afb3eb3bb19341e2653212200c568f3f900e0b2f04de9ba209aed25` | CHERRYPIE |

## All SHA-256 Values Collected

Unique SHA-256 values: **31**

```text
0affab34d950321e3031864ec2b6c00e4edafb54f4b327717cb5b042c38a33c9
0c5ad1e8fe43583e279201cdb1046aea742bae59685e6da24e963a41df987494
0e1f9d4d0884c68ec25dec355140ea1bab434f5ea0f86f2aade34178ff3a7d91
125752ad7c20d715920a3b2fb0fdde660f07b3f2b053665cf38c2d6d9de86e1e
1d9299799a7b8da67c44ebec064d64542c27645f8e84de4a22ca3f6cbc843e3c
1e3ee845fde739fcd3ca9ce62c7f142a7c501d11db4c4fb294d4939f12d0f916
20e20b074967ed6f6e04d609ccec5ff7492665ef25f894c90c2ddc92fa47ac38
2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41
24c079b24851a5cc8f61565176bbf1157b9d5559c642e31139ab8d76bbb320f8
247a733048b6d5361162957f53910ad6653cdef128eb5c87c46f14e7e3e46983
28f622028e690c943f7fa9aca426c07cab52b5aaba757ef8a3328609c0b3bec3
329fda9939930e504f47d30834d769b30ebeaced7d73f3c1aadd0e48320d6b39
403b624e35777cbc07dbe66398b21bba70396a20b859c880732338ce1dd1f41f
420d20cddfaada4e96824a9184ac695800764961bad7654a6a6c3fe9b1b74b9a
5b8d50c2e8cc3038b7c6e6dbf1219f6e814930a1e3c0053143a1191ae67f8ffc
653db3b63bb0e8c2db675cd047b737cefebb1c955bd99e7a93899e2144d34358
6f7090895c1c3dee30de6b3f098ca3a788dc198646e5293a8b1210430b0add97
70d93035b0693b0e4ef65eb7f8529e6385d698759cc5b8666a394b2136cc06eb
78a810e47e288a6aff7ffbaf1f20144d2b317a1618bba840d42405cddc4cff41
7e05ff08e32a64da75ec48b5e738181afb3e24a9f1da7f5514c5a11bb067cbfb
83014ab5b3f63b0253cdab6d715f5988ac9014570fa4ab2b267c7cf9ba237d18
85484716a369b0bc2391b5f20cf11e4bd65497a34e7a275532b729573d6ef15e
8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8
918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593
a06a8fd1b6fa1924199a4540cf16d089217ce8f78c617739946f145fd1fc88c1
adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8
acc74c920d19ea0a5e6007f929ef30b079eb2836b5b28e5ffcc20e68fa707e66
be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c
c5826032207d623a7f6caec8465af7364eccc355f9a48897da2a54f3e4420265
ca3be5885afb3eb3bb19341e2653212200c568f3f900e0b2f04de9ba209aed25
d931078b63d94726d4be5dc1a00324275b53b935b77d3eed1712461f0c180164
```

## SHA-1

```text
a75995f94854dea8799650a2f4a97980b71199d2
b05caba461000c6ebd8b237f318577e9bccd6047
d09c4e7b641f8cb7cc86190fd9a778c6955fea28
86ec70c27e5346700714dbae2f10e168a08210e4
```

These four historical Operation Ghost values identify OnionDuke, MiniDuke and PolyglotDuke code-comparison samples in ESET reporting.

## MD5

```text
8bd528d2b828c9289d9063eba2dc6aa0
e017bfc36e387e8c3e7a338782805dde
efafcd00b9157b4146506bd381326f39
```

The MD5 values identify two WINELOADER DLLs and the ROOTSAW `invite.hta` from the 2024 campaign.

## Provenance and Newly Sourced Artifacts

Every value is paired to publisher and campaign context in [hash provenance](hash-provenance.md). Core samples and qualified ICE RELIC initial-access-cluster artifacts remain separable in detections; the corpus favors exact primary-source indicators over an unverified bulk feed.
