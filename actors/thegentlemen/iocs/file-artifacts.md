# The Gentlemen — File Artifacts

**Presentation reviewed:** 2026-09-17.

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| Initial KILLAV tool | SHA1 | `c0979ec20b87084317d1bfa50405f7149c3b5c5f` | Trend Micro classification; filename and role should not be inferred from hash order. |
| Windows ransomware | SHA1 | `c12c4d58541cc4f75ae19b65295a52c559570054` | Trend Micro classification; filename and role should not be inferred from hash order. |
| Patched KILLAV tool | SHA1 | `df249727c12741ca176d5f1ccba3ce188a546d28` | Trend Micro classification; filename and role should not be inferred from hash order. |
| PowerRun dual-use tool | SHA1 | `e00293ce0eb534874efd615ae590cf6aa3858ba4` | Trend Micro classification; filename and role should not be inferred from hash order. |

## Additional Named Artifacts Without Hashes in the Supplied Notes

| Additional artifact | Incident role | Date / source |
|---|---|---|
| `All.exe`, `ThrottleBlood.sys` | Initial process-killing chain | August 2025 case |
| `Allpatch2.exe` | Adapted process killer | August 2025 case |
| `PowerRun.exe` | Privileged execution utility | August 2025 case; modification not established |
| `1.bat` | Account/group enumeration script | Supplied incident notes; generic name |
| `gentlemen_system` | SYSTEM worker task | Microsoft 2026 sample |
| `%TEMP%\gentlemen.bmp` | Wallpaper | Supplied notes / sample reporting |
| `grand.exe`, `C:\ProgramData\r.exe` | Internal staging/download and renamed locker | Check Point DFIR case, published 2026-04-20 |
| `C:\ProgramData\data` | Possible document consolidation | Trend Micro August 2025 case; qualified collection assessment |
| `C:\Temp\psexec.exe` | Embedded or downloaded legitimate remote administration tool | Microsoft May 2026 sample |
| `ConsoleHost_history.txt` | PSReadLine history targeted for deletion | Microsoft May 2026 sample |
| `wipefile.tmp` | Optional volume free-space processing | Microsoft May 2026 sample |
| `/bin/.vmware-authd` | Hidden payload copy | Check Point ESXi analysis; not the legitimate daemon |

## Source and Classification Review

The four SHA-1 roles above are directly published by Trend Micro. Other hashes retain their source classification in [hash provenance](hash-provenance.md). A driver filename does not by itself identify its vulnerable version. The [binary narrative](../intelligence/encryptor.md) distinguishes payload artifacts from supporting tools.
