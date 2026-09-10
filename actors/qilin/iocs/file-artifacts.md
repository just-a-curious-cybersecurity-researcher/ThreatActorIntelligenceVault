# Qilin — Contextualized File Artifacts

| Artifact | Role / evidence state | Observation / source | Confidence / limits |
|---|---|---|---|
| `IPScanner.ps1`, `logon.bat` | Malicious Chrome credential collection through GPO | July 2024 [Q11](../References.md#q11) | High Confidence in case; names are mutable |
| `LD`, `temp.log` under host-specific SYSVOL directories | Staged credential database and text output | July 2024 [Q11](../References.md#q11) | High Confidence with path/producer; generic filenames alone weak |
| `ru.msi` | Additional attacker-managed ScreenConnect installation | January 2025 [Q22](../References.md#q22) | High Confidence in incident; legitimate agent software with unauthorized control |
| `veeam.exe` | Credential-extraction exploit tool | January 2025 [Q22](../References.md#q22) | Reported role; not Veeam's genuine executable based on name alone |
| `!light.bat`, `pars.vbs`, `result.txt` | Credential-tool orchestration, formatting and SMTP output | 2025 [Q15](../References.md#q15) | High Confidence in published script evidence; not every toolkit component independently executed |
| `encryptor_1.exe`, `encryptor_2.exe` | Talos identifiers for distributed versus central-share deployment | 2025 [Q15](../References.md#q15) | Functional sample labels; do not rely on filename stability |
| `%TEMP%\QLOG\ThreadId({Number}).LOG` | Encryptor worker logs | 2025 [Q15](../References.md#q15) | High Confidence in analyzed samples; `{Number}` is a pattern placeholder |
| `TVInstallRestore` | ONLOGON restoration task | 2025 [Q15](../References.md#q15) | High Confidence with executable and `/RESTORE`; do not classify all TeamViewer installers as ransomware |
| `dark.sys`, dark-kill | Driver/process termination chain | 2025 [Q15](../References.md#q15) | Driver bytes, signer and service evidence required |
| `socks64.dll` under ProgramData enterprise-product directories | COROXY/proxy artifact | 2025 [Q23](../References.md#q23) | Generic name; corroborate export/load behavior |
| `2stX.exe`, `Or2.exe`, `eskle.sys` | Confirmed driver-based anti-AV components in vendor analysis | October 2025 [Q23](../References.md#q23) | High Confidence in source analysis; signer identity is not actor identity |
| `msimg32.dll`, `rwdrv.sys`, `hlpdrv.sys` | DLL dropper and resulting driver artifacts | October 2025 [Q23](../References.md#q23) | Dropping/compatible Foxit loader demonstrated in laboratory; victim loader not established |
| `cg6.exe`, `44a.exe`, `aa.exe`, `fnarw.sys` | Suspected alternate anti-AV chain | October 2025 [Q23](../References.md#q23) | Low Confidence in `fnarw.sys` relationship; source could not complete driver analysis |
| `mmh_linux_x86-64`, `.filepart` staging suffix | Linux payload transferred through WinSCP / RMM context | October 2025 [Q23](../References.md#q23) | Payload existence reported; WSL execution mechanism remains hypothesis |
| `pwndll.dll` in Public directory | Patched C DLL injected into svchost by early Go Agenda | August 2022 [Q12](../References.md#q12) | High Confidence in analyzed capability; distinct language from Go parent |

Reviewed 2026-09-10. See [tool classification](../technical/tooling-malware.md). Note-specific filenames are listed separately in [file patterns](file-patterns.md). No credential values or victim-specific paths are reproduced.
