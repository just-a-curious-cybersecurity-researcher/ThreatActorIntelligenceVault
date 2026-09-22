# INC Ransom — File Artifacts

**Presentation reviewed:** 2026-09-22.

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| Victim-specific payload name | SHA-256 | `accd8bc0d0c2675c15c169688b882ded17e78aed0d914793098337afc57c289c` | Windows encryptor; Huntress 2023-08-11 |
| Analyzed win.exe | SHA-256 | `e17c601551dfded76ab99a233957c5c4acf0229b46cd7fc2175ead7fe1e3d261` | Windows classic encryptor; Alien177 2024-07-11 |
| 2026-02 incident | SHA-256 | `e034a4c00f168134900bfe235ff2f78daf8bfcfa8b594cd2dd563d43f5de1b13` | Windows encryptor; Huntress 2026 exfiltration report |
| edr.exe | SHA-256 | `1d15b57db62c079fc6274f8ea02ce7ec3d6b158834b142f5345db14f16134f0d` | HRSword / auxiliary tool; Huntress 2026 exfiltration report |
| av.exe | SHA-256 | `36eb4290aa11a950e60d12ab18a8e139d25464355ce761f98891e1ea94f39445` | Security-impairment artifact; Huntress 2024-05-01 |
| kaz.exe | SHA-256 | `fc39cca5d71b1a9ed3c71cca6f1b86cfe03466624ad78cdb57580dba90847851` | Incident artifact; Huntress 2024-05-01 |

## Additional Named Artifacts Without Hashes in the Supplied Notes

| Additional artifact | Incident role | Date / source |
|---|---|---|
| C:\ProgramData\Vendettister\jocularities.ps1 | Script artifact; external communication | Huntress 2026-09-21 |
| hwau.exe / HWAuidoOs2Ec.sys | Loader/driver pair | Huntress August 2026 case |
| HealthUpdater.exe | Renamed Vicarius vRx product; do not classify as encryptor by name | Huntress 2026-09-21 |
| winupdate.exe | Renamed Restic exfiltration utility | Huntress February 2026 incidents |
| filwfp.sys / filnk.sys / fildds.sys | Drivers in a separate termination toolchain | Acronis 2026-06-17 |
| Veeam-Get-Creds-derived PowerShell | Credential extraction before deployment | Acronis 2026-06-17 |
| kill / delete | Generated Linux helper scripts; sample-specific, generic names | SonicWall 2024-06-04, displayed Figure 4 |
| new.ps1 / new.txt | Restic execution script and input-file list | Cyber Centaurs 2026-01-22 / Huntress February case |
| ababcab28dcdb35c | Rogue ScreenConnect instance identifier | Huntress 2024-05-01 |

## Source and Classification Review

Executable names are mutable and can identify legitimate products. The [complete hash register](hashes.md) keeps encryptors, HRSword and other incident artifacts distinct. File names without hashes support a contextual hunt, not an automatic malware verdict.
