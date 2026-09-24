# SafePay — File and Note Patterns

**Presentation reviewed:** 2026-09-24.

| Pattern | Context / period | Source / confidence |
|---|---|---|
| `*.safepay` | Files renamed after encryption | Multiple technical sources; high |
| `readme_safepay.txt` | Canonical note filename in samples and public archive | Multiple technical sources; high |
| `readme_safepay_ascii.txt` | ASCII-form archive variant | ransomware.live/RansomLook; high for archived note, original deployment scope unknown |
| `Decryption Instructions.txt` | Alternate note name | Microsoft; moderate |
| `C:\ProgramData\[0-9].bat` | Single-digit batch staging/deployment | NCC incident; high, case-scoped |
| `C:\Windows\Temp\RRZqKUbG.tmp` | RemoteRegDump-like temporary artifact | NCC incident; high, case-scoped |
| `C:\Users\*\Documents\{SWG,search,sorted,check}.ps1` | Script bundle used for discovery and output processing | Sygnia incident; high, case-scoped |
| `C:\Users\*\Documents\p.bat_{S,W}.bat` | Batch discovery scripts | Sygnia incident; high, case-scoped |
| `C:\Users\*\Desktop\RouteCIDR.py` | Route/network enumeration script | Sygnia incident; high, case-scoped |
| `C:\ProgramData\{Snaffler.exe,sh.txt}` | Discovery/credential tool and output | Sygnia incident; high, case-scoped |
| `C:\Users\*\OneDrive – jjvq\*` | Attacker OneDrive sync path used during exfiltration | Sygnia incident; high, case-scoped |
| `$Orphan` entries for multipart `Data*.rar`, `SQL*.rar`, `Accounting*.rar` or IP-named archives | Deleted OneDrive staging residue in the NTFS MFT | Sygnia incident; moderate without tenant/timeline correlation |
| `soc.dll` | QDoor registration and loader artifact | NCC incident; high, case-scoped |
| `WerFault.exe` with anomalous memory image or `regsvr32.exe` ancestry | QDoor process-hollowing target | NCC incident; high, case-scoped |
| `-pass=* -enc=*` with `-path=\\*` | Victim-specific locker command-line cluster | Huntress/NCC reverse engineering; high |
| `WIN-SBOE3CPNALE` / `WIN-3IUUOFVTQAR` | Published operator-side workstation names | Huntress/DCSO; moderate, campaign-scoped |
| `ColinSolomon@protonmail[.]com` | Contact address in the NCC incident note | NCC Group; high, incident-scoped |
| `DepaolaKristabelle@protonmail[.]com` | Contact address in the NCC incident note | NCC Group; high, incident-scoped |
| `VanessaCooke94@protonmail[.]com` | Address currently indexed for SafePay | RansomLook; high for tracker capture, deployment scope unknown |
