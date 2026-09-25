# APT29 — Contextualized File Artifacts

**Presentation reviewed:** 2026-09-25.

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| `svchost32.exe` | SHA256 | `918fa52ae45ed60ba7cc8bdc99c3cbe9ab92e0375ec31fc05d0d4513be11c593` | CornFlake RAT under `%APPDATA%\svchost32\` |
| ChocoShell sample | SHA256 | `be99857449d2856dd5a84e21c8a3d5e0e01456adb44062ddec5a6b4970d8d42c` | PowerShell collector / credential stealer |
| `invite.hta` | MD5 | `efafcd00b9157b4146506bd381326f39` | ROOTSAW first-stage downloader |
| `vcruntime140.dll` | MD5 | `8bd528d2b828c9289d9063eba2dc6aa0` | WINELOADER DLL side-loaded by `SqlDumper.exe` |
| `Vcruntime140.dll` | MD5 | `e017bfc36e387e8c3e7a338782805dde` | WINELOADER campaign variant |
| GoldFinder | SHA256 | `0affab34d950321e3031864ec2b6c00e4edafb54f4b327717cb5b042c38a33c9` | HTTP redirect/proxy tracing utility |
| `wine.zip` | SHA256 | `653db3b63bb0e8c2db675cd047b737cefebb1c955bd99e7a93899e2144d34358` | GRAPELOADER delivery archive |
| `wine.exe` | SHA256 | `420d20cddfaada4e96824a9184ac695800764961bad7654a6a6c3fe9b1b74b9a` | Legitimate PowerPoint executable in the campaign side-loading bundle |
| `AppvIsvSubsystems64.dll` | SHA256 | `85484716a369b0bc2391b5f20cf11e4bd65497a34e7a275532b729573d6ef15e` | Hidden, code-bloated dependency in GRAPELOADER bundle |
| `AppvIsvSubsystems64.dll` | SHA256 | `78a810e47e288a6aff7ffbaf1f20144d2b317a1618bba840d42405cddc4cff41` | Campaign variant |
| `ppcore.dll` | SHA256 | `d931078b63d94726d4be5dc1a00324275b53b935b77d3eed1712461f0c180164` | GRAPELOADER |
| `ppcore.dll` | SHA256 | `24c079b24851a5cc8f61565176bbf1157b9d5559c642e31139ab8d76bbb320f8` | GRAPELOADER variant |
| `vmtools.dll` | SHA256 | `adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8` | WINELOADER 2025 variant |
| State Department-themed lure PDF | SHA256 | `329fda9939930e504f47d30834d769b30ebeaced7d73f3c1aadd0e48320d6b39` | Benign UNC6293 instructions for creating and sharing an application-specific password; campaign artifact, not malware |

## Additional Named Artifacts Without Hashes in the Supplied Notes

| Additional artifact | Incident role | Date / source |
|---|---|---|
| `%APPDATA%\svchost32\svchost32.exe` | CornFlake copied path; correlate signer/hash, service, task and Run key | 2026 Microsoft |
| `sync.dat` | CornFlake hot-reload configuration for C2 and collection | 2026 Microsoft |
| service `svchost32` / display `Cloud Sync Service` | CornFlake persistence masquerading as cloud synchronization | 2026 Microsoft |
| `features.dat.tmp` | GoldMax encrypted configuration; keys derived per environment | 2021 Microsoft |
| `loglog.txt` | GoldFinder plaintext HTTP route log | 2021 Microsoft |
| `%APPDATA%\Microsoft\NativeCache\NativeCacheSvc.dll` | NativeZone loader location | 2021 Microsoft |
| `%APPDATA%\SystemCertificates\Lib\CertPKIProvider.dll` | VaporRage component loaded by NativeZone | 2021 Microsoft |
| `%WinDir%\ADFS\version.dll` | FoggyWeb loader path | 2021 Microsoft |
| `Microsoft.IdentityServer.Diagnostics.dll` | MAGICWEB malicious AD FS DLL name | 2022 Microsoft |
| `C:\Windows\Tasks\invite.txt` / `invite.zip` | ROOTSAW encoded intermediate and extracted WINELOADER archive | 2024 Mandiant |
| `SqlDumper.exe` plus adjacent `vcruntime140.dll` | Legitimate loader and malicious side-loaded DLL combination | 2024 Mandiant |
| `msedgeupdate_v3.exe` / `msedgeupdate.exe` | GTG-20006 published filenames; validate signer, hash and delivery chain | 2026 Anthropic; campaign period 2025-12–2026-08 |
| `WUEngine.exe` / `DiagHost.exe` | GTG-20006 published Windows artifact names | 2026 Anthropic; no public hash in the report |
| `client_20260507093021_4286d211_x64.exe` | GTG-20006 published Windows artifact name | 2026 Anthropic |
| `fix_network.apk` | GTG-20006 Android delivery artifact | 2026 Anthropic; correlate mobile signer/package and landing infrastructure |
| `version.dll` | Published GTG-20006 filename; also independently used in FoggyWeb context | 2026 Anthropic; filename collision requires path/hash context |
| `%LOCALAPPDATA%\POWERPNT\wine.exe` | GRAPELOADER persistence target | 2025 Check Point; correlate the three-file bundle and exact hashes |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\POWERPNT` | GRAPELOADER Run-key persistence | 2025 Check Point; value points to the copied `wine.exe` |
| campaign tag `e55c854d77279ed516579b91315783edd776ac0ff81ea4cc5b2b0811cf40aa63` | Hard-coded GRAPELOADER campaign/version tag sent with host profile | 2025 Check Point; contextual artifact, not a file hash |
| OAuth client `fc45d3d0-d870-4c83-b3f7-08ebca61d3a0` | UNC6293 attacker-controlled application in meeting-invite lure | 2025 Google; qualified cluster relationship |

## Source and Classification Review

Several names deliberately resemble Windows or Microsoft components. A filename or path alone is insufficient; validate content hash, signer, parent process, creation event and identity activity. `SqlDumper.exe` and the published `wine.exe` are legitimate and must not be classified as malware solely because they appear in a side-loading chain.
