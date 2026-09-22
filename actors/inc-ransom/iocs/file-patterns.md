# INC Ransom — File Patterns

**Presentation reviewed:** 2026-09-22.

| Pattern | Context / period | Source / confidence |
|---|---|---|
| INC-README.txt / INC-README.html | Ransom note output in published INC analyses | Huntress/Cybereason/Acronis; high |
| *.INC / *.inc | Renamed encrypted-file candidates | Multiple primary analyses; verify actual content |
| DATALEAK_PRESS_RELEASE.txt | Later extortion message; August incident | Huntress 2026-09-21; high in case |
| win.exe / windows.exe | Reported payload basenames | Generic names; require hash/lineage |
| lin / lin.exe | Linux payload naming in collected research | Name alone is weak evidence |
| kill / delete | Generated helper script names in historical Linux sample | SonicWall; inspect content, not name alone |
| Inc_readme.html | Underscore-form note filename shown in historical Linux report | SonicWall 2024-06-04; sample-scoped |
| dmksvc | Classic service/Safe Mode artifact | Independent analysis and Trend Micro; sample-scoped |
| winupd | PsExec-related service | Huntress early incident; not a universal service name |
| Recovery Diagnostics | Scheduled task associated with 2026 exfiltration case | Huntress; incident-specific |
| HWAuidoOs2Ec.sys / HwAudio | Driver and service artifacts | Huntress August case; preserve exact published spelling |

RECOVER-style notes and INC_Update from unverified leads are not used as family-wide signatures. Archive naming and original endpoint filenames are different fields.
