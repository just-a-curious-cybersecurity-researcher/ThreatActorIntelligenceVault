# The Gentlemen — File Patterns

**Presentation reviewed:** 2026-09-17.

| Pattern | Context / period | Source / confidence |
|---|---|---|
| `README-GENTLEMEN.txt` | Ransom-note filename | High; supplied notes and executable analysis |
| `README-GENTLEMEN_2.txt`, `README-GENTLEMEN_3.txt` | Archive filenames | High in archive; suffixes do not establish on-disk names |
| `%TEMP%\gentlemen.bmp` | Wallpaper artifact | High in analyzed Windows behavior |
| `<filename>.exe.bat` | Cleanup batch naming | High in supplied executable account; placeholder is not a literal filename |
| `gentlemen_system` | Privileged worker task | High in analyzed sample |
| `UpdateSystem`, `UpdateUser`; `GupdateS`, `GupdateU` | Tasks and autorun value names | High in 2026 sample analysis; generic names need context |
| `DefU`, `DefS`, `UpdateGU`, `UpdateGU2`, `UpdateGS`, `UpdateGS2` | Remote task artifacts | High in Windows sample analysis; exact actions/targets required |
| `DefSvc`, `UpdateSvc`, `UpdateSvc2` | Remote service artifacts | High in Windows sample analysis |
| `share$`, `C:\Temp\psexec.exe` | Distribution share and dual-use tool staging | High in sample reporting; not malicious on name alone |
| `wipefile.tmp` | Optional free-space routine | High in Microsoft sample analysis; filename alone is weak |
| `--eph--`, `--marker--GENTLEMEN` | File trailer fields | Encrypted-output triage; not executable identification |
| `LOCKER_BACKGROUND` | Worker environment flag | Runtime/sample clue; not generally present in process-event schema |
| `/bin/.vmware-authd`, `/etc/rc.local.d/local.sh` | ESXi persistence artifacts | Check Point dedicated ESXi analysis |
| `eztDisk` | Temporary ESXi datastore preparation artifact | Contextual clue; inspect vmkfstools activity |

Read the [notes](../ransom-notes/Ransom-Notes.md) externally; [executable internals](../intelligence/encryptor.md) explains their producers.
