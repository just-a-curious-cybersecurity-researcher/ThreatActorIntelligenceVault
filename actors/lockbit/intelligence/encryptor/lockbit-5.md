# LockBit — LockBit 5.0 Windows, Linux and ESXi Executables

**Presentation reviewed:** 2026-09-22.

## Scope

Trend Micro's September 2025 investigation covers separate Windows and Linux/ESXi artifacts. LevelBlue's January–February 2026 series adds a larger cross-platform sample set. Version branding does not mean every platform uses byte-identical loaders, options or cryptographic wrappers.

This is a synthesis of published reverse engineering, not a claim that malware was executed or independently disassembled for this repository. Destructive mockups describe events and are deliberately non-executable. Bibliographic provenance is centralized in [References](../../References.md#executable-analysis-provenance).

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| 5.0 / 2025–2026 | Windows PE and Linux/ESXi ELF builds | In-memory Windows payload, randomized suffixes, configurable visibility and virtualization targeting | Compare each build with its published hash and platform; branding alone is insufficient |

## Executable Analysis

### Windows branch

#### 1. Loader and in-memory payload

The examined Windows launcher contains a protected PE payload that is recovered in memory and loaded reflectively. Disk-only scanning may see the wrapper, while memory acquisition exposes the code implementing file impact. A memory image and the original executable therefore need separate evidence identifiers.

The analysis finds continuity with native 4.0 string-hashing and API-resolution routines. That establishes a technical relationship between the compared samples, not the identity of their compiler or operator.

LevelBlue's Windows sample uses a different observable loading path: execution under a hollowed `defrag.exe` process. The file on disk bearing Microsoft's name can be legitimate while the running process contains injected ransomware code. This is a reason to preserve both executable provenance and memory evidence; checking only the host executable's signature would answer the wrong question.

#### 2. Configuration and target visibility

The interface separates directory selection, exclusions, output visibility, note placement, file scope and delayed execution. Invisible operation can suppress note creation, suffix changes and modification-time changes. Those switches are described as observed features; no launch recipe is provided.

A help menu describes intended controls, but implementation must still be checked. Earlier native 4.0 research found an advertised option that was unused. Do not assume a matching flag has identical behavior across all later builds.

#### 3. Security services and event telemetry

The Windows analysis describes an in-process ETW modification, a list of 63 service-name hashes and post-encryption log clearing through `EvtClearLog`. The hashes are comparison values, not 63 publicly identified service names; this dossier does not invent names by reversing that count.

LevelBlue resolves a subset of service targets in its later Windows analysis, including `VeeamTransportSvc`, `VeeamDeploymentService`, `GxVss`, `QBCFMonitorService` and `vmms`. These cover backup, database/accounting and virtualization dependencies. The published resolution is partial and sample-specific. Stopping a guest-management or backup service can disrupt an application independently of whether its files have yet been encrypted.

```text
MOCK API/EVENT TRACE — descriptive, not executable
loader-A -> executable payload appears in private memory
payload-A -> ETW routine modified in its own address space
payload-A -> enumerate services -> compare name hashes -> request matched stops
payload-A -> process selected files
payload-A -> EvtClearLog [enumerated channels]
```

The mockup summarizes the reported routines. It is not a captured trace proving an invariant order or a command for reproducing them.

#### 4. Direct snapshot removal and file-owner handling

S2W's Windows analysis identifies VSS service checks followed by COM-based snapshot deletion through `CreateVssBackupComponentsInternal` and `IVssBackupComponents::DeleteSnapshots`. This route can operate without a `vssadmin.exe` child. Its locked-file path queries file-owning processes before attempting termination and reopening.

The VSS object is an interface to snapshot management; creating it is not itself proof of deletion. A process trace may show the caller while VSS and storage records establish the outcome. Similarly, identifying a file owner does not prove that termination succeeded or that the retry obtained write access.

```text
MOCK API TRACE — descriptive, not executable
payload -> VSS service state -> backup-components interface
payload -> DeleteSnapshots request -> provider outcome
file worker -> blocked open -> query owning process -> retry path
```

These internal calls explain why an investigation restricted to destructive command-line strings can miss relevant preparation activity.

#### 5. File encryption and visible artifacts

The supplied reports describe ChaCha-family encryption with asymmetric key agreement in 5.0 samples. More specific claims about SHAKE256, BLAKE2b or a particular ChaCha variant must remain attached to their respective sample analysis; they are not combined into one universal algorithm.

For the x64 specimen covered by RansomLook's 2026-06-21 analysis, the reported primitives are X25519, SHAKE256 and ChaCha20. The publisher identifies them from constants and structure, explicitly describing the complete key relationships as inferred rather than traced and validated with test vectors. Its key material is described as runtime material. These findings do not establish an identical footer or derivation routine across Windows, Linux and ESXi builds.

The architectural point is that a payload can use public key material without holding the corresponding private recovery secret. Possession of a public key therefore does not by itself decrypt victims' files. Once the required material has been initialized, network isolation alone does not reverse cryptographic transformations already made to the files.

The common visible pattern is a randomized 16-hex suffix and `ReadMeForDecrypt.txt`. A footer preserves information including original size in the examined Windows files, but the absence of a fixed textual family marker complicates simple string identification.

A filename-only hunt misses invisible operation. File-write volume, content changes and storage/backup telemetry are required to investigate encryption without renaming. Defender file-event tables are not guaranteed to record every write or provide an entropy measurement.

#### 6. File secrets, wrapping material and write order

S2W describes random seed material, SHA-512-derived file material, Curve25519-based wrapping and Poly1305-related protection. It reports a 24-byte file nonce while naming the content cipher ChaCha20; this description is not treated as a validated, byte-complete cryptographic specification. It also places recovery-metadata writing before content encryption.

That order affects how an interrupted file should be read. Recovery metadata may already exist when only some selected content regions have been transformed. Its presence is not a completion marker. Conversely, a complete transform with missing or damaged recovery material creates a different recovery problem. Both must be assessed against the concrete build's layout.

There are several distinct secrets and public values in this architecture. The file secret drives bulk processing; ephemeral agreement material helps protect that secret; public values stored with the output allow a compatible recovery implementation to identify the wrapping context. An appended public value is not equivalent to the private recovery capability. Hash functions used for derivation likewise do not directly explain which file ranges were selected.

The S2W and RansomLook descriptions remain separate. SHA-512 in one specimen and inferred SHAKE256 in another cannot be silently substituted into one version-wide key schedule.

#### 7. Finalization and optional free-space wiping

Note placement depends on configuration, and optional free-space wiping has different forensic implications from deleting selected file contents. Do not equate a wiping option with proof that it ran. The source's command-help description of executable retention is not used as a complete specification of every cleanup path.

The later Windows study documents alternate-stream-based self-removal, RC4 decoding of the embedded note and omission of a forced wallpaper change. RC4 in that routine protects the note inside the executable; it is not the file-encryption cipher. A remaining note, a deleted launcher and an unchanged wallpaper are therefore compatible observations in the analyzed build.

S2W also documents `%TEMP%` cleanup, rename/disposition-based payload removal, and an optional helper writing `1.tmp`/`2.tmp` until space runs out, then removing them. Its event-log routine enumerates channels before clearing them.

Free-space filling acts on available allocation space rather than locating and encrypting every existing document. It can interfere with recovery of deleted material and generate a large additional write workload. A full-volume alert must therefore be placed alongside the file-encryption timeline: it may concern an optional cleanup phase rather than a new set of encrypted files. The temporary names alone are common and need process context.

### Linux branch

#### 8. Native file traversal and filtering

The Linux program exposes comparable selection and exclusion controls, reports files being processed and can summarize the processed volume. It runs against paths and permissions available on the host. Linux telemetry should track `execve`, file access and storage behavior, rather than expecting Windows service or registry events.

The newer sample set described by LevelBlue includes stripped ELF files, runtime-decoded strings and architecture-specific differences. A generic Linux file server and an ESXi host are different execution environments even when their payloads share code.

The Linux x64 analysis describes `ptrace`-based debugger checking, self-removal, argument handling, background execution and threaded file work. Related builds inspect `/proc/self/status` and `TracerPid`. These checks concern local execution conditions, not remote exploitation of the host.

In the reported run, the default target was `/home`, including hidden directories such as `.config` and `.local`. System and pseudo-filesystem exclusions reduce the chance of interrupting the locker itself. They do not imply that all hidden content is skipped. The sample exposes both `LINUX Locker v1.06` and a v1.08 note label, demonstrating why internal banners should remain attached to the specimen rather than treated as a clean release sequence.

The source also describes cross-architecture builds. Shared behavior does not remove runtime dependencies: an ELF needs a compatible architecture and loader. The mere presence of a Linux-labelled sample on a host does not establish successful execution there.

#### 9. Linux startup, background execution and output

LevelBlue's Linux x64 flow places debugger checking and self-removal before argument initialization, forking/background execution and threaded encryption. The dynamically linked specimen uses libc and libpthread and lacks ELF section headers. Runtime-decoded data exposes paths and messages that a basic plaintext string scan misses.

Deleting the pathname of a running Linux executable does not necessarily terminate the process or remove its mapped code. This explains how file impact can continue after the launcher disappears. Background execution also changes parent/terminal relationships without establishing a reboot-start service or cron entry.

The reported note controls allow placement in affected folders, only the root, or suppression. Note distribution and file selection are consequently separate measurements. A sparse note count is not a count of processed directories, and hidden directories can still contain affected user data.

```text
MOCK LINUX TRACE — descriptive, not executable
ELF process -> local debugger check -> remove launcher pathname
process -> initialize scope -> background worker activity
worker -> selected user path -> changed content and configured output
note writer -> placement according to settings
```

### ESXi branch

#### 10. Virtual-machine handling and datastore impact

The dedicated locker targets VM-related files and paths under datastores. LevelBlue documents VMware management-tool interaction, VM enumeration and power-state handling in analyzed samples. Guest shutdown releases files and increases the impact of access to a single hypervisor.

The ESXi study describes environment checks, guest inventory, power-state handling and datastore traversal under `/vmfs/volumes`. Its x64 workflow includes a fast partial pass followed by fuller processing; `.vmdk.fastpass` is a reported intermediate artifact. A VM exclusion list and file-percentage controls change the scope of a run. These observations do not establish that every guest on the host was selected or that both passes finished.

The first pass and final pass can therefore leave different snapshots of damage during containment. A disk that was only partly processed may already be unusable. An intermediate suffix is a stage marker, not evidence of a second actor or a separate initial-access event.

```text
MOCK HYPERVISOR TRACE — descriptive, not executable
locker-A -> query VM inventory through VMware management tooling
locker-A -> request power-state changes for selected guests
locker-A -> traverse <datastore>/<VM directory>
locker-A -> write selected virtual-disk/configuration files
```

Review shell, hostd/vpxa and datastore logs together. Virtual-machine power changes alone are routine administration; the suspicious sequence combines an unusual ELF process, broad guest disruption and file impact.

Forensics should preserve the disk descriptor, data extents, snapshot relationships and VM configuration as a set. Encryption of a virtual disk can remove access to many files inside the guest even when guest telemetry records no ransomware process. The source of execution is then the hypervisor; the guest's outage is the downstream effect.

#### 11. VMware control flow and two-stage disk processing

LevelBlue follows an environment check, VM inventory and a power-state loop that requests shutdown and checks the result. Its sample targets virtual disks and VM configuration/state artifacts, including `.vmdk`, `.vmx`, `.vmsn` and `.nvram`. Fast-pass messages describe an initial 1% pass before fuller processing, with `/var/log/encrypt.log` present as a potential optional logging artifact.

The power-state loop and file workers perform different jobs. The first attempts to stop guest use of the backing files; the second transforms selected storage objects. A successful shutdown is therefore not proof of encryption, while an unavailable guest can be an early effect even before the disk worker reaches it.

The virtual-disk format also changes the unit of impact. One selected host file can contain an entire guest filesystem. The apparent percentage of the container changed is not the percentage of guest documents guaranteed recoverable, because filesystem structures and application metadata can be concentrated in selected regions.

The published ESXi x64 study identifies a ChaCha20 implementation; that finding does not establish Windows's exact key container for this ELF. A common cipher family can coexist with different metadata, file traversal and cleanup code.

#### 12. Cross-platform differences

Windows reflective loading, ETW APIs and Service Control Manager actions are not Linux features. Likewise, VMware management commands are not evidence that a Windows workstation independently encrypted a hypervisor. The platform-specific binary and access path determine the interpretation.

## Linking Host Activity to the Executable

Correlate an exact published hash with output, process ancestry and affected platform. The 16-hex suffix and note are useful generic pivots, but not exclusive organizational signatures. Prioritize immutable off-host logs and backups because local visibility can be impaired before or after encryption.

Return to the [encryptor index](README.md).
