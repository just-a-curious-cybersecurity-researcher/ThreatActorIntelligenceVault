# LockBit — File Artifacts

**Presentation reviewed:** 2026-09-17.

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| builder.exe | SHA-256 | `a736269f5f3a9f2e11dd776e352e1801bc28bb699e47876784b8ef761e0062db` | Leaked Black builder; not a victim-side encryptor |
| LB3Decryptor.exe | SHA-256 | `8f0a2d5b47441fbcf1882aa41cae22fd0db057ccc38abad87ccc28813df3a83c` | Calif decryptor sample; retain role |
| NG-Dev specimen | SHA-256 | `f56cba51a4e86f3be5208dfce598d0d6a86cbbc820b214d5d5df7d327e580b82` | Date-gated development sample |
| a.bat | SHA-256 | `98e79f95cf8de8ace88bf223421db5dce303b112152d66ffdf27ebdfcdf967e9` | CISA Citrix campaign credential-collection wrapper |
| SmokeLoader specimen | SHA-256 | `1da6525ae1ef83b6f1dc02396ef0933732f9ffdfca0fda9b2478d32a54e3069b` | Acronis infrastructure overlap; not LockBit 5.0 executable |

## Additional Named Artifacts Without Hashes in the Supplied Notes

| Additional artifact | Incident role | Date / source |
|---|---|---|
| Restore-My-Files.txt | Note in several historical branches | NHS / Red / native 4.0 analyses |
| Generated ID.README.txt | Black ransom note | Black-era reporting and public archive |
| ReadMeForDecrypt.txt | 5.0 ransom note | Trend Micro 2025 |
| Build.bat, config.json, pub.key, priv.key | Builder package artifacts | Cyber Geeks 2022; names are not intrinsically malicious |
| C:\Windows\servicehost.exe and sysconf.bat | Renamed Plink and launching script | CISA Citrix Bleed campaign, 2023 |
| C:\Users\Public\a.png | Dump output disguised with an image extension | CISA sample analysis, 2023 |
| UpdateAdobeTask | Scheduled-task persistence artifact | CISA campaign evidence, 2023 |

## Source and Classification Review

The [hash inventory](hashes.md) provides the complete retained set. Tools, resources, decryptors and payloads are classified separately. Parent process and file content determine whether a generic artifact name is suspicious; a restored ransom note does not establish fresh encryption.

