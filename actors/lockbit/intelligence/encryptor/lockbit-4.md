# LockBit — LockBit 4.0, 2025 Native Samples

**Presentation reviewed:** 2026-09-22.

## Scope

This page covers the release announced for 2025-02-03 and the native Windows samples analyzed in March. Deep Instinct and Chuong Dong examine different sample sets; their option names and output details must remain sample-specific.

This is a synthesis of published reverse engineering, not a claim that malware was executed or independently disassembled for this repository. Destructive mockups describe events and are deliberately non-executable. Bibliographic provenance is centralized in [References](../../References.md#executable-analysis-provenance).

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Native 4.0 / 2025 | Windows PE / unpacked payload; dynamic API resolution | Quiet operation, hashed API/service names, partial encryption and direct log clearing | Not the 2024 possible impostors; NG-Dev is a separate development specimen |

## Executable Analysis

### Sample preparation and API resolution

#### 1. Packed launcher and payload

Deep Instinct describes a customized UPX-packed sample without Black's password-gated unpacking requirement. Its three published hashes are retained separately from Chuong Dong's packed/unpacked pair.

After unpacking, much of the payload resolves APIs by name hashes and caches the results. Encoded API references explain why an import-table-only review can miss functionality. They do not demonstrate that the payload has no operating-system dependencies.

#### 2. Resolving functions and recovering strings

The 0x0d4y examination follows DLL-name hashing, export resolution and cached function references through several routines. Calls can consequently look indirect in a decompiler even when they ultimately invoke standard Windows functions. Resolving the import table alone does not expose the complete service, file and logging paths.

The same study separates XOR-obfuscated strings from RC4-protected embedded material. These operations recover the program's own text and data. They do not establish the cipher applied to victims' files, which belongs to a different routine discussed below.

Packing terminology also differs between reports. Deep Instinct describes customized UPX, while 0x0d4y explicitly cautions that UPX-like section names do not establish ordinary UPX packing for its sample. The shared observation is a runtime transition from an on-disk wrapper to recovered executable code; the wrapper must remain associated with its sample.

#### 3. Execution gates and telemetry impairment

Dong identifies `GetKeyboardLayoutList` and an abort when an installed layout matches `0x419`. This tests a Windows keyboard setting, not the host's physical country, IP location or current user nationality. The advertised mutex-related argument is unused in that specimen.

The analyses describe changes to in-process ETW code and remapping of DLL code. Deep Instinct identifies `RtlQueueWorkItem`, `NtOpenSection`, `NtMapViewOfSection` and `WriteProcessMemory` in the investigated loading/unhooking path.

An affected function in the ransomware's address space does not erase all externally collected telemetry. EDR memory events and service logs can still supply evidence. The dossier does not include patch bytes or a procedure to reproduce the bypass.

### Work scheduling and file access

#### 4. Volume and network selection

The independent native-sample analysis enumerates volumes and logical drives, resolves mount points and collects network targets. Directory workers feed file-processing workers. Concurrent producer/consumer work means note creation, service changes and file writes may interleave in event timelines.

File exclusions preserve selected operating-system paths and already processed artifacts. They are a sample's selection policy, not a guarantee that every excluded file is safe from other tools in the intrusion.

The native sample's directory workers use a breadth-first list rather than relying only on recursive function calls. Candidate files move to a separate encryption queue. Discovery can consequently run ahead of file transformation: seeing a path enumerated does not establish that its contents were already changed. The analyzed implementation also excludes very small files and treats directory/reparse-point objects separately from regular files.

The examined volume path uses `FindFirstVolumeW`/`FindNextVolumeW`, resolves names through `GetVolumePathNamesForVolumeNameW`, and can assign a mount point with `SetVolumeMountPointW`. Network discovery uses `WNetOpenEnumW`/`WNetEnumResourceW`. A newly accessible volume path is thus a possible preparation artifact, distinct from the later writes to its contents.

#### 5. Producer and consumer worker pools

Dong reports traversal workers numbering twice the logical processor count and file workers numbering three times that count. Circular queues and semaphores coordinate pending work, including `ReleaseSemaphore` and `WaitForSingleObject`. These are sample-specific allocation rules, not a benchmark of actual simultaneous disk operations.

The directory pool produces candidate paths. The file pool consumes them and performs the more expensive read/transform/write work. Storage latency and unavailable files can keep workers waiting even when many threads exist. Thread count therefore does not translate directly into an encryption rate or an estimate of completed damage.

```text
MOCK QUEUE TRACE — descriptive, not executable
directory worker -> selected path -> pending file queue
file worker -> awakened for available work -> open candidate
successful open -> content processing -> output finalization
other workers -> continue discovery or wait for work/completion
```

#### 6. Handling locked files and services

The code can identify processes holding a file through `NtQueryInformationFile` and evaluate whether a process is critical before attempting termination. Separately, the service path uses the Service Control Manager, enumerates services and compares hashed names with a target list. Matched services can be stopped and their start configuration disabled.

```text
MOCK API TRACE — descriptive, not executable
encryptor-A -> OpenSCManager -> enumerate services
encryptor-A -> hash <service name> -> compare with embedded target list
encryptor-A -> ControlService [stop request]
encryptor-A -> ChangeServiceConfig [disabled start state]
```

This sequence can occur without `sc.exe`, `net.exe` or PowerShell. The resulting service events must be correlated with process and EDR telemetry instead of requiring one shell command.

### Cryptography, output and cleanup

#### 7. File processing

Chuong Dong's identified sample uses XChaCha20 with Curve25519-based key agreement. It protects per-file key material and appends a footer required for interpretation. Deep Instinct separately describes selective file processing and full encryption for small files in its sample set.

The exact cryptographic implementation is therefore associated with a concrete analysis, rather than a generic AES/RSA description copied from another generation.

The independently examined sample generates a 32-byte file key and a 24-byte XChaCha20 nonce, plus an ephemeral Curve25519 key pair. The shared secret feeds a SHA-512-based derivation for an outer layer that protects the file key. XChaCha20 transforms data; Curve25519 supports key agreement; SHA-512 participates in derivation. Listing all three as interchangeable “encryption algorithms” would obscure their different jobs.

The appended `0x5C`-byte footer includes protected file-key material, an ephemeral public key, hash material and an encoded marker. The marker and reversible suffix encoding support already-processed checks. These dimensions belong to the documented sample, not a general LockBit file standard.

```text
MOCK KEY RELATIONSHIPS — conceptual, not executable
file content <-> symmetric file key
symmetric file key -> protected by a derived wrapping layer
wrapping layer <- per-file key agreement with embedded public material
file tail -> protected key material + public recovery metadata + marker
```

Public recovery metadata is not the matching private key. Its presence lets a compatible decryptor interpret the file, but does not make the protected file key publicly recoverable. Preserve the tail even if most of the document remains readable.

#### 8. Partial processing and file-layout differences

EQST describes full processing below 1 MiB and three 9% regions for larger native Green 4.0 files. Its report places protected key material at the front; Dong documents the appended footer above. These are retained as report/sample differences rather than one universal layout.

A region map and a key-container location answer different questions. The first identifies which original bytes were transformed; the second identifies additional information used to interpret an output. A file can retain readable interior regions while also containing a new recovery structure. Comparing only its suffix or overall length cannot reconstruct those two changes.

#### 9. Quiet operation and note differences

Deep Instinct's quiet option suppresses the usual extension, timestamp and note changes. Other examined samples use different option names. Chuong Dong's specimen generates a hexadecimal suffix and writes `Restore-My-Files.txt`.

A 16-hex suffix is consequently useful for hunting but is not exclusive to 5.0. The supplied blanket description of 4.0 output as only `.lockbit` is too narrow.

The collected Deep Instinct analysis describes size-dependent processing alongside configurable exclusion and visibility behavior. This is a second sample set, so its processing policy is not silently applied to Dong's specimen. The practical consequence is that neither the version label nor an unchanged suffix provides a complete map of altered bytes.

Quiet operation also separates filesystem timestamps from sensor timestamps. Preserving an original modification time does not erase the time at which an EDR or remote storage system observed a write. Correlate those independent records instead of treating the file's displayed date as its last real access.

#### 10. Event logs and self-removal

The native analysis describes enumeration of Windows event channels followed by `EvtClearLog`. This is distinct from a child `wevtutil.exe` process and from the earlier in-memory ETW modification. Logs already forwarded to another system can preserve evidence.

Cleanup can remove the launcher after processing. Analyze USN/MFT evidence, process lifetime and recovered memory together; absence of the original PE from disk is not absence of execution.

## Linking Host Activity to the Executable

Prioritize the sample hash and branch-specific output, then correlate service stops, configuration changes, event clearing and file I/O. The [5.0 analysis](lockbit-5.md) explains the later code comparisons without treating every 4.0 behavior as new in 5.0.

Return to the [encryptor index](README.md).
