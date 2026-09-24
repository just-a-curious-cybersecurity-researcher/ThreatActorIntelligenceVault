# DragonForce — Hashes

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24

## Windows Samples — SHA-256

| SHA256 | Observed role |
|---|---|
| `1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b` | LockBit-derived DragonForce sample; Cyble comparison |
| `451a42db9c514514ab71218033967554507b59a60ee1fc3d88cbeb39eec99f20` | Conti-derived DragonForce Windows sample; S2W |
| `410db536a57c511b0ccac2639e0eb3320f303fc5c90242379ab43364c51ef321` | DragonForce API-resolving variant; S2W |
| `c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d` | DragonForce locker `1.exe` in Citrix-linked Huntress case |
| `e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22` | DragonForce ransomware in Hackledorb/Backdoor.Turn case |
| `df903c620508011ca8eb2aaaf9712a526b31a12c800b856cd524ebb3fde854b2` | DragonForce sample in Halcyon profile |
| `55befb5de5d9bc45978efd1a960ae21ed81e4be9c6521aaeebf8d5884444e3c9` | DragonForce sample in Halcyon profile |
| `572d88c419c6ae75aeb784ceab327d040cb589903d6285bbffa77338111af14b` | DragonForce sample in Halcyon profile |
| `dc7e706587d4897789cc4a5f7cccbb539646b58aa9c86272728c8c1e6ec2a529` | Victim-specific DragonForce decryptor; recovery tool, not locker |

### Campaign Tools — SHA-256

| SHA256 | Observed role |
|---|---|
| `82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b` | Downloader in Symantec Backdoor.Turn case |
| `821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6` | Backdoor.Turn |
| `048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c` | Backdoor.Turn |
| `ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0` | Shellcode containing Backdoor.Turn |
| `f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b` | Side-loaded DLL mimicking VirtualBox |
| `d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e` | Side-loaded DLL mimicking VirtualBox |
| `142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219` | ADExplorer |
| `8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3` | ADExplorer |
| `d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e` | NetScan |
| `aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5` | NetScan |
| `9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759` | Malicious ZIP archive |
| `cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a` | Malicious ZIP archive |
| `b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383` | `GameDriverx64.sys` vulnerable driver |
| `b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877` | K7 vulnerable driver |
| `8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2` | Abyss Worker driver |
| `65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951` | Abyss Worker driver |
| `252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab` | Topaz Antifraud vulnerable driver |
| `8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531` | Havoc Process Terminator |
| `087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2` | Tower of Fantasy vulnerable driver |
| `6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4` | AV-killer utility |
| `6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e` | AV-killer utility |

## Linux / Unix Samples — SHA-256

No full SHA-256 for the reverse-engineered Linux/ESXi sample was exposed in the reviewed public report. No Windows hash is relabeled as Linux to fill the table.

## All SHA-256 Values Collected

Unique SHA-256 values: **30**

```text
048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c
087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2
1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b
142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219
252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab
410db536a57c511b0ccac2639e0eb3320f303fc5c90242379ab43364c51ef321
451a42db9c514514ab71218033967554507b59a60ee1fc3d88cbeb39eec99f20
55befb5de5d9bc45978efd1a960ae21ed81e4be9c6521aaeebf8d5884444e3c9
572d88c419c6ae75aeb784ceab327d040cb589903d6285bbffa77338111af14b
65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951
6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4
6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e
821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6
8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2
82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b
8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3
8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531
9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759
aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5
b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877
b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383
c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d
cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a
ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0
d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e
d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e
dc7e706587d4897789cc4a5f7cccbb539646b58aa9c86272728c8c1e6ec2a529
df903c620508011ca8eb2aaaf9712a526b31a12c800b856cd524ebb3fde854b2
e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22
f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b
```

## SHA-1

SentinelOne published the following SHA-1 values as DragonForce ransom-note artifacts:

```text
343220b0e37841dc002407860057eb10dbeea94d
ae2967d021890a6a2a8c403a569b9e6d56e03abd
c98e394a3e33c616d251d426fc986229ede57b0f
f710573c1d18355ecdf3131aa69a6dfe8e674758
```

SentinelOne published these SHA-1 values as ransomware payloads without branch labels:

```text
011894f40bab6963133d46a1976fa587a4b66378
0b22b6e5269ec241b82450a7e65009685a3010fb
196c08fbab4119d75afb209a05999ce269ffe3cf
1f5ae3b51b2dbf9419f4b7d51725a49023abc81c
229e073dbcbb72bdfee2c244e5d066ad949d2582
29baab2551064fa30fb18955ccc8f332bd68ddd4
577b110a8bfa6526b21bb728e14bd6494dc67f71
7db52047c72529d27a39f2e1a9ffb8f1f0ddc774
81185dd73f2e042a947a1bf77f429de08778b6e9
a4bdd6cef0ed43a4d08f373edc8e146bb15ca0f9
b3e0785dbe60369634ac6a6b5d241849c1f929de
b571e60a6d2d9ab78da1c14327c0d26f34117daa
bcfac98117d9a52a3196a7bd041b49d5ff0cfb8c
e164bbaf848fa5d46fa42f62402a1c55330ef562
e1c0482b43fe57c93535119d085596cd2d90560a
eada05f4bfd4876c57c24cd4b41f7a40ea97274c
fc75a3800d8c2fa49b27b632dc9d7fb611b65201
```

## MD5

S2W published the first value for its principal Conti-derived encryptor and the second for the victim-specific Windows decryptor. Their SHA-256 identities are retained above and in the provenance register.

```text
ada4e228e982a7e309bb6a3308e4872d
a368564c74d7f288fa01e4c7241082fe
```

## Provenance and Newly Sourced Artifacts

The S2W and Cyble values map to specific reverse-engineered branches. Huntress and Symantec values map to incident payloads. Symantec campaign tools remain distinct from ransomware payloads and do not become service-wide IOCs. Halcyon values are retained as vendor-profile samples with lower branch specificity. SentinelOne’s SHA-1 set is preserved without inventing SHA-256 equivalents or version assignments.
