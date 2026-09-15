# Qilin — Contextualized File Artifacts

**Presentation reviewed:** 2026-09-15.

Named artifacts retain their function and source context separately from the bulk hash inventory. Unknown filename/hash relationships are not inferred from an IOC list.

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| Analyzed Agenda Windows Rust sample; filename not established here | SHA256 | `e90bdaaf5f9ca900133b699f18e4062562148169b29cb4eb37a0577388c22527` | High Confidence in the December 2022 analyzed sample. |

## Additional Named Artifacts Without Hashes in the Supplied Notes

The names below are supported by source reporting. This register does not assign a hash unless the publisher establishes that exact relationship. For all published values, see [Hashes](hashes.md).

## Source and Classification Review

| Additional artifact | Incident role | Date / source |
|---|---|---|
| `IPScanner.ps1`, `logon.bat` | Malicious Chrome credential collection through GPO; High Confidence in case; names are mutable | July 2024 |
| `LD`, `temp.log` under host-specific SYSVOL directories | Staged credential database and text output; High Confidence with path/producer; generic filenames alone weak | July 2024 |
| `ru.msi` | Additional attacker-managed ScreenConnect installation; High Confidence in incident; legitimate agent software with unauthorized control | January 2025 |
| `veeam.exe` | Credential-extraction exploit tool; Reported role; not Veeam's genuine executable based on name alone | January 2025 |
| `!light.bat`, `pars.vbs`, `result.txt` | Credential-tool orchestration, formatting and SMTP output; High Confidence in published script evidence; not every toolkit component independently executed | 2025 |
| `encryptor_1.exe`, `encryptor_2.exe` | Talos identifiers for distributed versus central-share deployment; Functional sample labels; do not rely on filename stability | 2025 |
| `%TEMP%\QLOG\ThreadId({Number}).LOG` | Encryptor worker logs; High Confidence in analyzed samples; `{Number}` is a pattern placeholder | 2025 |
| `TVInstallRestore` | ONLOGON restoration task; High Confidence with executable and `/RESTORE`; do not classify all TeamViewer installers as ransomware | 2025 |
| `dark.sys`, dark-kill | Driver/process termination chain; Driver bytes, signer and service evidence required | 2025 |
| `socks64.dll` under ProgramData enterprise-product directories | COROXY/proxy artifact; Generic name; corroborate export/load behavior | 2025 |
| `2stX.exe`, `Or2.exe`, `eskle.sys` | Confirmed driver-based anti-AV components in vendor analysis; High Confidence in source analysis; signer identity is not actor identity | October 2025 |
| `msimg32.dll`, `rwdrv.sys`, `hlpdrv.sys` | DLL dropper and resulting driver artifacts; Dropping/compatible Foxit loader demonstrated in laboratory; victim loader not established | October 2025 |
| `cg6.exe`, `44a.exe`, `aa.exe`, `fnarw.sys` | Suspected alternate anti-AV chain; Low Confidence in `fnarw.sys` relationship; source could not complete driver analysis | October 2025 |
| `mmh_linux_x86-64`, `.filepart` staging suffix | Linux payload transferred through WinSCP / RMM context; Payload existence reported; WSL execution mechanism remains hypothesis | October 2025 |
| `pwndll.dll` in Public directory | Patched C DLL injected into svchost by early Go Agenda; High Confidence in analyzed capability; distinct language from Go parent | August 2022 |

Reviewed **2026-09-11**. Supporting tools, legitimate RMM and encryptors have different roles; a filename does not resolve them. See [Tool Classification](../technical/tooling-malware.md#tool-classification-and-provenance) and [File Patterns](file-patterns.md). No credential values or victim-specific paths are reproduced.
