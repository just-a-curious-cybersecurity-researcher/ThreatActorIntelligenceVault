# SafePay — Revised Windows Encryptor

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope

This file covers the Windows generation reverse engineered by DCSO in 2025 and later summarized by Microsoft. It preserves differences from the early Huntress/NCC build instead of treating all SafePay samples as one immutable implementation.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| DCSO revised build, 2025 | C Windows PE using Overlapped I/O | Encrypted `.debug` config, CPU-dependent AES-CBC/ChaCha20, 80-byte footer, no Cyrillic guard in analyzed sample | Strong reverse engineering for one build; exact sample hash was not exposed in the article |
| Microsoft `Ransom:Win32/Safepay.A`, updated 2026 | Defender family classification | Corroborates algorithm choice, Curve25519, partial mode, plaintext metadata and optional persistence/wallpaper behaviors | Product telemetry aggregates multiple observations; optional behavior is not mandatory |

## Executable Analysis

### 1. Entry, API resolution and obfuscated strings

The program is a native Windows implementation. More than one hundred strings are built on the stack and decoded at runtime. Each byte is combined with its array index, the first byte of the in-memory `kernel32.dll` image (`M`) and a per-string constant. DCSO resolved 116 of 117 identified strings.

Imports are looked up through a CRC32 construction using polynomial `0x04C11DB7` and an initial value of `0xFF`. The choice resembles primitives used elsewhere but is not identical to the LockBit Black resolver.

The reconstructed module set includes `advapi32.dll`, `rstrtmgr.dll`, `kernel32.dll`, `ole32.dll`, `shell32.dll`, `ntdll.dll`, `mpr.dll` and `user32.dll`. Together they expose service control, Restart Manager/file-lock handling, file and completion-port I/O, COM elevation, native token/thread functions and network-resource enumeration without leaving a normal plaintext import profile.

### 2. Password-derived configuration

The encrypted configuration resides in a PE section named `.debug`. Its layout is a four-byte MurmurHash checksum, a four-byte payload length and encrypted data. The program hashes the supplied `-pass` value with SHA-512, uses the first 32 bytes as a ChaCha20 key and the next 24 bytes as the nonce, decrypts the configuration and validates its MurmurHash.

The resulting configuration contains the mutex, extension and note name, path/file/extension exclusions, process and service kill lists and ransom-note text. A wrong `-pass` fails validation rather than merely selecting a different victim identity.

The `.debug` placement matters for triage: it is configuration data, not ordinary compiler debug information. DCSO's extractor locates the section, derives the ChaCha20 key and 24-byte nonce from the SHA-512 result, decrypts the declared payload length and compares the stored four-byte MurmurHash before parsing fields. Preserve the exact binary and command-line password together; using a password from another victim/build will not yield a valid configuration.

### 3. Single-instance and environment preparation

The default mutex exposed by DCSO is the long `Global\DB1D-…-7E49` value documented in the IOC register. The revised sample did not contain the early Cyrillic-language exit. Analysts must therefore test for the behavior per sample and must not use locale safety as a sandbox control.

ThreatLocker published three additional long `Global\...` mutexes, supporting victim/build customization rather than one immutable family value. A mutex hit should be joined with the PE hash, execution arguments and impact artifacts.

### 4. Process and service interruption

The decrypted configuration drives termination. The process set focuses on databases, Office and mail applications, browsers, editors and synchronization clients. The service set includes VSS, SQL, Exchange, Sophos, Veeam, backup services and Commvault components. This frees files and removes immediate recovery defenses before write-heavy encryption begins.

### 5. Target construction and protected paths

Runtime flags choose a specific path, mapped drive, network share enumeration or broader local traversal. The configuration excludes Windows and application directories, boot and restore areas, executable/system extensions, the note and the `.safepay` suffix. These exclusions preserve system execution long enough for encryption and negotiation.

DCSO's extracted build explicitly protected `Windows`, `Windows.old`, `Program Files`, `Program Files (x86)`, `ProgramData`, `AppData`, `System Volume Information`, `$Recycle.Bin`, Windows Defender/Security/PowerShell paths, browser directories and boot-related locations. It also skipped `readme_safepay.txt`, `autorun.inf`, boot files, `desktop.ini`, `iconcache.db`, `ntuser.dat` variants, `thumbs.db`, already encrypted files and a long set of executable/system extensions. This explains why the host can remain bootable while business data, shares and virtualized workloads become unusable.

### 6. Asynchronous pipeline

SafePay uses Windows Overlapped I/O and multiple threads scaled to processor count. File states and work queues closely resemble LockBit Black’s architecture. This similarity is meaningful for hunting and code genealogy, but the cryptographic and configuration implementations differ.

The pipeline creates an I/O completion port, walks eligible paths, posts file work and lets several workers issue asynchronous reads and writes. The state machine tracks the original size, next region, selected cipher and completion status. Cleanup closes handles, releases the crypto context and tears down the worker pool after outstanding operations finish.

### 7. Encryption-depth scheduling

The `-enc` value ranges from 1 through 10 and controls how many alternating 1 MiB chunks are encrypted or skipped. Lower values accelerate the operation by touching less data. The exact stride for each level should be recovered from the analyzed build; only the published `-enc=1` 1/10 behavior is treated as confirmed here.

### 8. Per-file cipher selection and key handling

For every file, `RtlGenRandom`/`SystemFunction036` produces independent random material. Curve25519 protects the per-file key relationship to the actor’s master key. The symmetric cipher is selected at runtime:

- **AES-NI present:** AES-CBC.
- **AES-NI absent:** ChaCha20.

SHA-512 participates in key derivation. This design is not LockBit Black’s RSA-based key wrapping and supports DCSO’s assessment of influenced rather than directly copied development.

### 9. Revised 80-byte footer

The locker appends plaintext recovery metadata:

```text
 8 bytes  original file size
32 bytes  actor/master ECC public key
32 bytes  per-file ECC public key
 1 byte   encryption level
 1 byte   ChaCha-selection flag
 6 bytes  unused/reserved
```

The 80-byte structure lets a decryptor recover parameters and derive the shared secret when the actor’s private key is available. It is structurally incompatible with the early 65-byte footer.

### 10. Rename, note and optional visual changes

The configured suffix is `.safepay` and the standard note is `readme_safepay.txt`. Microsoft has also observed `Decryption Instructions.txt`, an incident-specific `Vgod.exe`, temporary C# compilation through `csc.exe`, a PowerShell-fetched Imgur wallpaper and optional Run-key persistence. These are observed deployment variations, not required elements of the DCSO binary.

### 11. Decryption implications

DCSO produced research tools by replacing the master ECC key with a controlled test key. That validates the cryptographic interpretation but is not a victim decryptor. Without the corresponding actor private key, public analysis found no practical weakness that recovers arbitrary files.

## Linking Host Activity to the Executable

- A PE with the GTIG code patterns, SafePay import hash, stack-string decoder and encrypted `.debug` configuration is stronger evidence than `.safepay` alone.
- AES feature checks followed by either AES-CBC or ChaCha20 explain different telemetry or performance on otherwise similar hosts.
- The 80-byte tail, original-size field and two ECC public keys provide a version discriminator for forensic samples.
- A missing CIS-language guard is expected in the DCSO revision and must not be treated as an unpacking failure.
- Preserve the exact `-pass` value, binary and representative encrypted files; configuration and footer parsing depend on matching artifacts.
