# Lynx — Hash Indicators

**Presentation reviewed:** 2026-10-07.

Exact hashes identify published bytes only. They do not cover rebuilt or victim-specific samples.

## Windows Samples — SHA-256

| SHA256 | Observed role |
|---|---|
| `eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc` | Early Lynx Windows encryptor; Nextron and Unit 42. |
| `571f5de9dd0d509ed7e5242b9b7473c2b2cbb36ba64d38b32122a0a337d6cf8b` | Lynx Windows encryptor; Nextron and Unit 42. |
| `82eb1910488657c78bef6879908526a2a2c6c31ab2f0517fcc5f3f6aa588b513` | Lynx Windows encryptor; Unit 42. |
| `b378b7ef0f906358eec595777a50f9bb5cc7bb6635e0f031d65b818a26bdc4ee` | Lynx Windows encryptor; Nextron. |
| `ecbfea3e7869166dd418f15387bc33ce46f2c72168f571071916b5054d7f6e49` | Lynx Windows encryptor; Nextron. |
| `85699c7180ad77f2ede0b15862bb7b51ad9df0478ed394866ac7fa9362bf5683` | Lynx Windows encryptor; Nextron. |
| `09c5ff735d3d7b8c47b4df7de35e1c72b530b2c2566628bc29aaa54feb4d89f4` | Lynx sample published by CIS. |
| `07b36c1660deb223749a8ac151676d8924bc13aa59e6712a3c14a2df5237264a` | `w.exe` deployed in the 2025 DFIR case. |
| `c3b57cd2c04ffd6dd173edfd975d2b05b7f6f502062a56b8585bda8776824a18` | `pushprinterconnections.exe` deployed as the Lynx encryptor in 2026 PacketWatch IR. |
| `6e65483764d7c25523a5bbef5be99eb42349eef39d5517c46b3a4af262a80ceb` | `1.exe` Lynx Windows sample in a 2025 incident analysis. |

## All SHA-256 Values Collected

```text
eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc
571f5de9dd0d509ed7e5242b9b7473c2b2cbb36ba64d38b32122a0a337d6cf8b
82eb1910488657c78bef6879908526a2a2c6c31ab2f0517fcc5f3f6aa588b513
b378b7ef0f906358eec595777a50f9bb5cc7bb6635e0f031d65b818a26bdc4ee
ecbfea3e7869166dd418f15387bc33ce46f2c72168f571071916b5054d7f6e49
85699c7180ad77f2ede0b15862bb7b51ad9df0478ed394866ac7fa9362bf5683
09c5ff735d3d7b8c47b4df7de35e1c72b530b2c2566628bc29aaa54feb4d89f4
07b36c1660deb223749a8ac151676d8924bc13aa59e6712a3c14a2df5237264a
c3b57cd2c04ffd6dd173edfd975d2b05b7f6f502062a56b8585bda8776824a18
6e65483764d7c25523a5bbef5be99eb42349eef39d5517c46b3a4af262a80ceb
517288e12c05a92e483e6d80b9136c19bc58c46851720680bb6d1b7016034c37
6285d32a9491a0084da85a384a11e15e203badf67b1deed54155f02b7338b108
```

## SHA-1

- `3e01df0155a539fe6d802ee9e9226d8c77fd96c9` — `w.exe`, same DFIR case sample as SHA-256 `07b36c...`.
- `efe8b9ff7ff93780c9162959a4c1e5ecf6e840a4` — SoftPerfect NetScan 7.2.7 in the DFIR case; legitimate tool.
- `2b4b11d3ecffd82ed44db652cdd65733224f8e34` — NetExec in the DFIR case; dual-use tool.

## MD5

- `e2179046b86deca297ebf7398b95e438` — `w.exe`, same DFIR case sample.
- `3073af95dfc18361caebccd69d0021a2` — SoftPerfect NetScan 7.2.7 in the DFIR case.
- `7532ff90145b8c59dc9440bf43dc87a5` — NetExec in the DFIR case.

## Provenance and Newly Sourced Artifacts

The two tool SHA-256 values in the all-values block are `517288...` for NetScan and `6285d3...` for NetExec. They must remain excluded from exact Lynx locker rules. The additional IR review raised the exact Windows locker inventory from eight to ten. No public Linux/ESXi Lynx SHA-256 was promoted from an INC comparison sample.
