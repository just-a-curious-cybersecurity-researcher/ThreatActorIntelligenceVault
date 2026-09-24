# SafePay — Contextualized File Artifacts

**Presentation reviewed:** 2026-09-24.

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| SafePay locker/DLL | SHA256 | `a0dc80a37eb7e2716c02a94adc8df9baedec192a77bde31669faed228d9ff526` | Principal reverse-engineered Windows sample |
| SafePay Windows sample | SHA256 | `327b8b61eb446cc4f710771e44484f62b804ae3d262b57a56575053e2df67917` | Published by Bitdefender and KPMG |
| SafePay Windows sample | SHA256 | `0f23a313f79d54ae2102f193d3de1a6a98791c27921f28a4fab1092bcb43e5ee` | KPMG advisory; exact role not exposed |
| `soc.dll` | SHA256 | `921df888aaabcd828a3723f4c9f5fe8b8379c6b7067d16b2ea10152300417eae` | QDoor loader in NCC incident |
| QDoor embedded DLL | SHA256 | `6c1d36df94ebe367823e73ba33cfb4f40756a5e8ee1e30e8f0ae55d47e220a6a` | Embedded second stage |
| QDoor injected PE | SHA256 | `e79608cf1d6b51324c14bef8883054c1238ed5f080222cc464810e6e14adc346` | Stage injected into `WerFault.exe` |
| `1.exe` | SHA1 | `07353237350c35d6dc2c8f143b649cd07c71f62b` | NCC deployment artifact; role remains case-scoped |

## Additional Named Artifacts Without Hashes in the Supplied Notes

- `readme_safepay.txt` and `readme_safepay_ascii.txt` — archived ransom-note names.
- `Decryption Instructions.txt` — alternate note name reported by Microsoft.
- `1.bat` — batch coordinator found under `C:\ProgramData`.
- `Vgod.exe` — Microsoft-observed SafePay-related filename.
- `C:\Windows\Temp\RRZqKUbG.tmp` — temporary RemoteRegDump-like artifact.
- `fzsftp.exe` — FileZilla component observed during collection/staging.
- `SystemSettingsAdminFlows.exe` — trusted binary involved in Defender changes.
- `WerFault.exe` — legitimate process used as the QDoor hollowing target.
- `WIN-SBOE3CPNALE` and `WIN-3IUUOFVTQAR` — source workstation names recurring in separate published cases.
- `C:\Users\<user>\Documents\SWG.ps1`, `p.bat_S.bat`, `p.bat_W.bat`, `search.ps1`, `sorted.ps1` and `check.ps1` — Sygnia discovery bundle.
- `C:\Users\<user>\Desktop\RouteCIDR.py` — Sygnia network-enumeration script.
- `C:\ProgramData\Snaffler.exe` — discovery and credential-hunting tool in Sygnia IR.
- `C:\ProgramData\sh.txt`, `domains_S.txt` and `pingS.txt` — Sygnia discovery outputs.
- `C:\Users\<user>\OneDrive – jjvq\` — local sync root for the attacker-controlled OneDrive tenant.

## Source and Classification Review

Locker, QDoor and legitimate-tool artifacts are kept separate because they answer different investigative questions. A `WerFault.exe`, FileZilla or ScreenConnect artifact is not a SafePay signature without parent process, timing, command-line, signer and network context.

| Additional artifact | Incident role | Date / source |
|---|---|---|
| `C:\ProgramData\<single digit>.bat` | Batch staging and remote deployment pattern | NCC Group, 2025 publication |
| `Global\DB1D-19B4-5094-D570-9841-E4BC-8ABD-29AA-03BB-84AD-C61B-1355-4FF2-194B-96BD-7E49` | Mutex extracted from revised locker configuration | DCSO, 2025 |
| `i[.]imgur[.]com/zhCjntO[.]png` | Wallpaper resource retrieved through PowerShell | Microsoft family behavior |
| CMSTPLUA CLSID `{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` | Auto-elevation evidence associated with locker execution | Huntress, 2024 incidents |
| `Global\347F-7B6B-6AFB-3C55-2602-369D-65B9-58A0-16F1-0F42-35DA-0B37-52C3-293C-8975-CAB4` | Victim/build-specific mutex | ThreatLocker, 2025 |
| `Global\622D-BA6A-4BE9-5D15-5C84-898C-1760-4BAF-2BB1-D7D1-389D-6C01-AAFC-1645-BB6E-DC88` | Victim/build-specific mutex | ThreatLocker, 2025 |
| `Global\A8D1-50A2-679B-3D55-D639-9810-8679-7409-02EC-EF50-EA87-5641-0086-74B7-A14E-EE4C` | Victim/build-specific mutex | ThreatLocker, 2025 |
