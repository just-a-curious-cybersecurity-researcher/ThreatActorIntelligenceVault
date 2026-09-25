# APT29 — File and Note Patterns

**Presentation reviewed:** 2026-09-25.

| Pattern | Context / period | Source / confidence |
|---|---|---|
| `%APPDATA%\svchost32\svchost32.exe` plus service `svchost32` | CornFlake redundant persistence; 2026 | Microsoft; high for campaign |
| `sync.dat` adjacent to CornFlake | Runtime C2 and collection configuration | Microsoft; contextual artifact |
| `SqlDumper.exe` loading adjacent `vcruntime140.dll` from `C:\Windows\Tasks` | WINELOADER DLL side-loading chain; 2024 | Mandiant; high |
| `invite.txt` → `invite.zip` using `certutil` then `tar` | ROOTSAW staging sequence; 2024 | Mandiant; sequence more specific than filename |
| `features.dat.tmp` under management-software-like ProgramData directory | GoldMax encrypted configuration; 2020–2021 | Microsoft; legitimate names can collide |
| `NativeCacheSvc.dll` → `rundll32 ... CertPKIProvider.dll,eglGetConfigs` | NativeZone/VaporRage chain; 2021 | Microsoft; arguments and paths required |
| `%WinDir%\ADFS\version.dll` with encrypted `.pri` payload | FoggyWeb AD FS persistence | Microsoft; requires AD FS host context |
| `.rdp` attachment with drive, clipboard, device or authentication redirection | October 2024 phishing | Microsoft; legitimate RDP administration can match |
| `msedgeupdate*.exe`, `WUEngine.exe`, `DiagHost.exe` or `client_20260507093021_4286d211_x64.exe` | GTG-20006 Windows delivery corpus; 2025-12–2026-08 | Anthropic; exact names require signer, hash, origin and network context |
| `fix_network.apk` delivered from campaign landing infrastructure | GTG-20006 Android delivery | Anthropic; preserve package certificate and installation source |
| `wine.exe` + hidden `AppvIsvSubsystems64.dll` + hidden `ppcore.dll` in one archive/directory | GRAPELOADER delayed-import DLL side-loading; 2025 | Check Point; exact bundle and hashes are stronger than any one filename |
| `%LOCALAPPDATA%\POWERPNT\wine.exe` plus Run value `POWERPNT` | GRAPELOADER persistence; 2025 | Check Point; validate value data and adjacent DLLs |
| `vmtools.dll` with 964 export names / 482 RVAs and RWX `.text` | WINELOADER 2025 variant | Check Point; static triage characteristics require hash/code confirmation |

APT29 has no ransom-note or encrypted-file naming pattern in the reviewed corpus.
