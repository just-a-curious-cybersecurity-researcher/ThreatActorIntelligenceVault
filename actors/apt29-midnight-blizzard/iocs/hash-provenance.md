# APT29 — Hash Provenance

**Presentation reviewed:** 2026-09-25.

| Hash | Algorithm | Publication provenance | Context / observation | Confidence |
|---|---|---|---|---|
| `918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593` | SHA-256 | Microsoft CaptiveCrunch and Anthropic GTG-20006, 2026 | CornFlake; Microsoft first_seen 2026-07-03 | High for the overlapping campaign corpus |
| `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c` | SHA-256 | Microsoft CaptiveCrunch, Anthropic GTG-20006 and Google UNC7005 reporting, 2026 | ChocoShell / CHERRYPIE; Microsoft first_seen 2026-07-10 | High for the exact artifact; Google's ICE RELIC relationship remains moderate confidence |
| `2285a264ffab59ab5a1eb4e2b9bcab9baf26750b6c551ee3094af56a4442ac41` | SHA-256 | NCSC vaccine advisory, 2020 | WellMess .NET rule metadata | High |
| `8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8` | SHA-256 | NCSC vaccine advisory, 2020 | WellMess Go / PE-or-ELF rule metadata | High |
| `83014ab5b3f63b0253cdab6d715f5988ac9014570fa4ab2b267c7cf9ba237d18` | SHA-256 | NCSC vaccine advisory, 2020 | WellMail UPX-packed | High |
| `0c5ad1e8fe43583e279201cdb1046aea742bae59685e6da24e963a41df987494` | SHA-256 | NCSC vaccine advisory, 2020 | WellMail unpacked | High |
| `70d93035b0693b0e4ef65eb7f8529e6385d698759cc5b8666a394b2136cc06eb` | SHA-256 | Microsoft GoldMax analysis, 2021 | GoldMax | High |
| `0e1f9d4d0884c68ec25dec355140ea1bab434f5ea0f86f2aade34178ff3a7d91` | SHA-256 | Microsoft GoldMax analysis, 2021 | GoldMax | High |
| `247a733048b6d5361162957f53910ad6653cdef128eb5c87c46f14e7e3e46983` | SHA-256 | Microsoft GoldMax analysis, 2021 | GoldMax | High |
| `0affab34d950321e3031864ec2b6c00e4edafb54f4b327717cb5b042c38a33c9` | SHA-256 | Microsoft GoldMax analysis, 2021 | GoldFinder | High |
| `7e05ff08e32a64da75ec48b5e738181afb3e24a9f1da7f5514c5a11bb067cbfb` | SHA-256 | Microsoft GoldMax analysis, 2021 | Sibot | High |
| `acc74c920d19ea0a5e6007f929ef30b079eb2836b5b28e5ffcc20e68fa707e66` | SHA-256 | Microsoft GoldMax analysis, 2021 | Sibot | High |
| `653db3b63bb0e8c2db675cd047b737cefebb1c955bd99e7a93899e2144d34358` | SHA-256 | Check Point GRAPELOADER analysis, 2025 | `wine.zip` campaign archive | High for campaign association |
| `420d20cddfaada4e96824a9184ac695800764961bad7654a6a6c3fe9b1b74b9a` | SHA-256 | Check Point GRAPELOADER analysis, 2025 | Legitimate `wine.exe` in malicious side-loading bundle | High for bundle association; file is not malicious in isolation |
| `85484716a369b0bc2391b5f20cf11e4bd65497a34e7a275532b729573d6ef15e` | SHA-256 | Check Point GRAPELOADER analysis, 2025 | Dependency / junk-code DLL | High for campaign association |
| `78a810e47e288a6aff7ffbaf1f20144d2b317a1618bba840d42405cddc4cff41` | SHA-256 | Check Point GRAPELOADER analysis, 2025 | Dependency DLL variant | High for campaign association |
| `d931078b63d94726d4be5dc1a00324275b53b935b77d3eed1712461f0c180164` | SHA-256 | Check Point GRAPELOADER analysis, 2025 | GRAPELOADER `ppcore.dll` | High |
| `24c079b24851a5cc8f61565176bbf1157b9d5559c642e31139ab8d76bbb320f8` | SHA-256 | Check Point GRAPELOADER analysis, 2025 | GRAPELOADER variant | High |
| `adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8` | SHA-256 | Check Point GRAPELOADER analysis, 2025 | WINELOADER `vmtools.dll` | High |
| `329fda9939930e504f47d30834d769b30ebeaced7d73f3c1aadd0e48320d6b39` | SHA-256 | Google UNC6293 ASP-phishing analysis, 2025 | Benign State Department-themed lure PDF | High for campaign association; low-confidence APT29 link at publication, later moderate-confidence subcluster relationship |
| `5b8d50c2e8cc3038b7c6e6dbf1219f6e814930a1e3c0053143a1191ae67f8ffc` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | UNC7005 GLOBSEC phishing page | Moderate for ICE RELIC relationship; high for source campaign association |
| `a06a8fd1b6fa1924199a4540cf16d089217ce8f78c617739946f145fd1fc88c1` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | UNC7005 OAuth phishing page | Moderate for ICE RELIC relationship; high for source campaign association |
| `1d9299799a7b8da67c44ebec064d64542c27645f8e84de4a22ca3f6cbc843e3c` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | Commodity VIDAR used by UNC7005 | Moderate for ICE RELIC relationship; not proprietary tooling |
| `c5826032207d623a7f6caec8465af7364eccc355f9a48897da2a54f3e4420265` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | Commodity ATOMIC used by UNC7005 | Moderate for ICE RELIC relationship; not proprietary tooling |
| `125752ad7c20d715920a3b2fb0fdde660f07b3f2b053665cf38c2d6d9de86e1e` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | ENGINELIGHT | Moderate for ICE RELIC relationship |
| `403b624e35777cbc07dbe66398b21bba70396a20b859c880732338ce1dd1f41f` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | CHERRYPIE | Moderate for ICE RELIC relationship |
| `28f622028e690c943f7fa9aca426c07cab52b5aaba757ef8a3328609c0b3bec3` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | CHERRYPIE | Moderate for ICE RELIC relationship |
| `1e3ee845fde739fcd3ca9ce62c7f142a7c501d11db4c4fb294d4939f12d0f916` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | CHERRYPIE | Moderate for ICE RELIC relationship |
| `6f7090895c1c3dee30de6b3f098ca3a788dc198646e5293a8b1210430b0add97` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | CHERRYPIE | Moderate for ICE RELIC relationship |
| `20e20b074967ed6f6e04d609ccec5ff7492665ef25f894c90c2ddc92fa47ac38` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | CHERRYPIE | Moderate for ICE RELIC relationship |
| `ca3be5885afb3eb3bb19341e2653212200c568f3f900e0b2f04de9ba209aed25` | SHA-256 | Google ICE RELIC-linked clusters, 2026 | CHERRYPIE | Moderate for ICE RELIC relationship |
| `d09c4e7b641f8cb7cc86190fd9a778c6955fea28` | SHA-1 | ESET Operation Ghost, 2019 | PolyglotDuke comparison sample | High for ESET code comparison |
| `a75995f94854dea8799650a2f4a97980b71199d2` | SHA-1 | ESET Operation Ghost, 2019 | OnionDuke comparison sample | High for ESET code comparison |
| `86ec70c27e5346700714dbae2f10e168a08210e4` | SHA-1 | ESET Operation Ghost, 2019 | Historical MiniDuke comparison sample | High for ESET code comparison |
| `b05caba461000c6ebd8b237f318577e9bccd6047` | SHA-1 | ESET Operation Ghost, 2019 | 2018 MiniDuke comparison sample | High for ESET code comparison |
| `efafcd00b9157b4146506bd381326f39` | MD5 | Mandiant WINELOADER, 2024 | ROOTSAW `invite.hta` | High |
| `8bd528d2b828c9289d9063eba2dc6aa0` | MD5 | Mandiant WINELOADER, 2024 | WINELOADER DLL | High |
| `e017bfc36e387e8c3e7a338782805dde` | MD5 | Mandiant WINELOADER, 2024 | WINELOADER DLL | High |

Historical values are not marked active. `wine.exe`, the UNC6293 PDF and landing-page hashes are campaign artifacts rather than malware; commodity VIDAR/ATOMIC samples are not presented as actor-developed. No sample is classified as ransomware or an encryptor.
