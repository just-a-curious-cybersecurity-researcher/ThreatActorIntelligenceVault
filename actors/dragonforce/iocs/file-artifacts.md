# DragonForce — File Artifacts

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| LockBit-derived encryptor | SHA-256 | `1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b` | Cyble binary comparison |
| Conti-derived encryptor | SHA-256 | `451a42db9c514514ab71218033967554507b59a60ee1fc3d88cbeb39eec99f20` | S2W principal sample |
| API-resolving encryptor | SHA-256 | `410db536a57c511b0ccac2639e0eb3320f303fc5c90242379ab43364c51ef321` | S2W variant |
| `1.exe` | SHA-256 | `c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d` | Huntress Citrix-linked case |
| DragonForce payload | SHA-256 | `e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22` | Symantec Backdoor.Turn case |
| Victim decryptor | SHA-256 | `dc7e706587d4897789cc4a5f7cccbb539646b58aa9c86272728c8c1e6ec2a529` | S2W; defensive recovery artifact |

**Backdoor.Turn campaign artifacts**

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| Downloader | SHA-256 | `82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b` | Symantec Hackledorb case |
| Backdoor.Turn | SHA-256 | `821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6` | Go backdoor using Teams TURN relays |
| Backdoor.Turn | SHA-256 | `048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c` | Second published backdoor sample |
| Backdoor.Turn shellcode | SHA-256 | `ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0` | Shellcode containing the backdoor |
| VirtualBox-mimicking side-loaded DLL | SHA-256 | `f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b` | Signed-binary side-loading chain |
| VirtualBox-mimicking side-loaded DLL | SHA-256 | `d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e` | Second published DLL sample |
| ADExplorer | SHA-256 | `142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219` | Active Directory discovery |
| ADExplorer | SHA-256 | `8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3` | Active Directory discovery |
| NetScan | SHA-256 | `d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e` | Network discovery |
| NetScan | SHA-256 | `aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5` | Network discovery |
| Malicious ZIP archive | SHA-256 | `9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759` | Tool staging archive |
| Malicious ZIP archive | SHA-256 | `cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a` | Tool staging archive |
| `GameDriverx64.sys` | SHA-256 | `b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383` | Vulnerable driver |
| K7 vulnerable driver | SHA-256 | `b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877` | Security-process termination |
| Abyss Worker driver | SHA-256 | `8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2` | Custom malicious driver |
| Abyss Worker driver | SHA-256 | `65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951` | Custom malicious driver |
| Topaz Antifraud driver | SHA-256 | `252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab` | Vulnerable driver |
| Havoc Process Terminator | SHA-256 | `8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531` | Huawei-driver exploitation chain |
| Tower of Fantasy driver | SHA-256 | `087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2` | Vulnerable driver |
| AV killer | SHA-256 | `6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4` | Security impairment utility |
| AV killer | SHA-256 | `6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e` | Security impairment utility |

## Additional Named Artifacts Without Hashes in the Supplied Notes

| Additional artifact | Incident role | Date / source |
|---|---|---|
| `HWAuidoOs2Ec.sys` | Huawei driver used by Havoc Process Terminator; hash-to-filename mapping not separately exposed | 2025–2026 Symantec |
| `wsftprm.sys` | Vulnerable Topaz driver; role/hash published separately | 2025–2026 Symantec |
| `GameDriverx64.sys` | Vulnerable driver; exact hash above | 2025–2026 Symantec |
| `K7RKScan.sys` | Vulnerable K7 driver; role/hash published separately | 2025–2026 Symantec |
| Abyss Worker driver | Custom malicious process-termination driver; two hashes above | 2025–2026 Symantec |
| `truesight.sys` / `rentdrv2.sys` | Optional locker BYOVD drivers | S2W |
| `eng.exe`, `legal.exe`, `exsym.exe`, `as.exe`, `exp6.exe` | AppMgmt LPE artifacts | 2026 Huntress |
| `TechSupV18Fix3.zip` | Tool archive downloaded from published IP | 2026 Symantec |
| `ADExplorer.exe`-style artifacts | AD discovery | 2026 Symantec |

## Source and Classification Review

Encryptor hashes, victim decryptor and campaign tooling are classified separately. Symantec’s tools are high-confidence for that Hackledorb-associated incident; their presence does not prove use by every DragonForce affiliate. Generic names such as `1.exe` and `test` require the published context. No PDB path was located in the reviewed original analysis; none is invented.
