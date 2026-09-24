# SafePay — Encryptor Analysis Index

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope

This directory describes public reverse engineering of SafePay’s Windows encryptor. It separates observed build behavior from operator actions performed before deployment. No malware was downloaded or executed for this dossier.

No public Linux or ESXi-native SafePay sample was located. Reports of encrypted virtual infrastructure are retained as Windows guest/share impact unless a platform-specific binary is published.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| [Early Windows build](windows-early-build.md), observed 2024 and in NCC case | PE32 DLL or executable deployed through `regsvr32.exe`/batch workflow | ChaCha20, X25519, 65-byte footer in NCC sample, CIS-language exit, LockBit-like arguments | Values describe analyzed samples; a filename or `.safepay` alone is insufficient |
| [Revised Windows build](windows-revised-build.md), analyzed 2025 onward | C Windows locker using Overlapped I/O and encrypted `.debug` configuration | AES-CBC with AES-NI or ChaCha20 fallback, Curve25519, 80-byte footer, no language guard in DCSO sample | DCSO sample shows evolution; it does not prove every later victim received this build |

## Executable Analysis

Across both public analyses, execution requires a victim-specific `-pass` value. The program resolves or decodes its APIs and strings, loads a configuration containing the mutex, extension, exclusions, kill lists and note, obtains elevated capabilities, interrupts applications and recovery services, discovers selected storage, and feeds files into a multithreaded asynchronous encryption queue.

The `-enc` level controls intermittent encryption. An early `-enc=1` case encrypted 1 MiB per 10 MiB region. Per-file random key material is combined with the actor’s public key through X25519/Curve25519-derived exchange. The actor’s private key is required to recreate the decryption secret; no public cryptographic bypass was identified.

## Linking Host Activity to the Executable

The following sequence is consistent with the binary rather than a separate operator utility when it descends from the locker process:

1. `regsvr32.exe` or an incident-specific executable starts with `-pass`, `-enc`, `-path`, `-network`, `-netdrive`, `-selfdelete`, `-log` or UAC arguments.
2. Service-control and process-termination events affect databases, productivity applications, backup products and VSS.
3. `vssadmin`, `wmic` and `bcdedit` children remove restore paths.
4. SMB/network-drive enumeration and a high-volume file-open/write/rename burst follow.
5. Files receive `.safepay`, recovery metadata is appended and a note appears in multiple directories.

The same actions under an unrelated parent can be operator scripts or a different ransomware family. Parent/child lineage, hash, command line and the resulting file state are required for attribution.

