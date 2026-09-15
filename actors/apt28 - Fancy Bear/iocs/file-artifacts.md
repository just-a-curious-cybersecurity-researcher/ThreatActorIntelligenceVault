# APT28 — Contextualized File Artifacts

**Presentation reviewed:** 2026-09-15.

Named artifacts retain their hash and functional context separately from the bulk corpus.

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| Consultation_Topics_Ukraine(Final).doc | SHA256 | `b2ba51b4491da8604ff9410d6e004971e3cd9a321390d0258e294ac42010b546` | RTF delivery. |
| Courses.doc | SHA256 | `1ed863a32372160b3a25549aad25d48d5352d9b4f58d4339408c4eea69807f50` | RTF delivery. |
| 2_2.d | SHA256 | `a944a09783023a2c6c62d3601cbd5392a03d808a6a51728e07a3270861c2a8ee` | MiniDoor dropper. |
| VbaProject.OTM | SHA256 | `bb23545380fde9f48ad070f88fe0afd695da5fcae8c5274814858c5a681d8c4e` | MiniDoor. |
| table.d | SHA256 | `0bb0d54033767f081cae775e3cf9ede7ae6bea75f35fbfb748ccba9325e28e5e` | PixyNetLoader dropper. |
| EhStoreShell.dll | SHA256 | `a876f648991711e44a8dcf888a271880c6c930e5138f284cd6ca6128eca56ba1` | Payload loader. |
| SplashScreen.png | SHA256 | `2822c72a59b58c00fc088aa551cdeeb92ca10fd23e23745610ff207f53118db9` | Embedded payload image. |
| office.xml | SHA256 | `9f4672c1374034ac4556264f0d4bf96ee242c0b5a9edaa4715b5e61fe8d55cc8` | Scheduled-task configuration. |
| SSPICLI.dll | SHA256 | `5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705` | NotDoor delivery chain. |
| testtemp.ini | SHA256 | `8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901` | NotDoor delivery chain. |
| justice.exe | SHA256 | `6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f` | GooseEgg. |
| DefragmentSrv.exe | SHA256 | `c60ead92cd376b689d1b4450f2578b36ea0bf64f3963cfa5546279fa4424c2a5` | GooseEgg. |
| execute.bat / doit.bat / servtask.bat | SHA256 | `7d51e5cc51c43da5deae5fbc2dce9b85c0656c465bb25ab6bd063a503c1806a9` | GooseEgg script. |
| eapphost.dll | SHA1 | `5603e99151f8803c13d48d83b8a64d071542f01b` | SlimAgent; historical sample revisited in 2026. |
| tcpiphlpsvc.dll | SHA1 | `6d39f49aa11ce0574d581f10db0f9bae423ce3d5` | BeardShell. |
| `onedrive.exe` | SHA256 | `fcb6dc17f96af2568d7fa97a6087e4539285141206185aec5c85fa9cf73c9193` | Legitimate signed executable used in the NotDoor chain; not a malicious-hash verdict. |

## Additional Named Artifacts Without Hashes in the Supplied Notes

| Additional artifact | Incident role | Date / source |
|---|---|---|
| `%APPDATA%\Microsoft\Outlook\VbaProject.OTM` | NotDoor macro persistence. Legitimate Outlook filename; inspect content and provenance |  |
| `C:\ProgramData\testtemp.ini` | NotDoor staging. Name alone is insufficient |  |
| `MPDW-constraints.js` | GooseEgg print-driver modification. Compare signed package baseline and process history |  |
| `wayzgoose*.dll` | GooseEgg payload naming. Campaign artifact, not a universal family signature |  |

## Source and Classification Review

LAB52 includes a legitimate `onedrive.exe` with SHA-256 `fcb6dc17f96af2568d7fa97a6087e4539285141206185aec5c85fa9cf73c9193`. It is chain context, not a malicious-hash verdict. The article's prose and artifact table differ on `%TEMP%\Temp` versus `%TEMP%\Test`; retain both as a source discrepancy rather than inventing a canonical path. 
