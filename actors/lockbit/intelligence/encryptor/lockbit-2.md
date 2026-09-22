# LockBit — LockBit Red / 2.0 Executables

**Presentation reviewed:** 2026-09-22.

## Scope

Red became available in 2021-06; a distinct Linux-ESXi Locker followed in 2021-10. Cybereason's case evidence includes operator scripts and domain deployment, so the analysis keeps those actions separate from the encryption routine.

This is a synthesis of published reverse engineering, not a claim that malware was executed or independently disassembled for this repository. Destructive mockups describe events and are deliberately non-executable. Bibliographic provenance is centralized in [References](../../References.md#executable-analysis-provenance).

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Red / 2021–2022 | Windows PE; separate Linux-ESXi payload | Automated deployment options, concurrent encryption and StealBit service integration | StealBit is a separate transfer program; domain propagation depends on permissions |

## Executable Analysis

### Windows branch

#### 1. Configuration, execution context and target scope

Chuong Dong's 2022-03-19 analysis of the Windows sample beginning `9feed0` describes a check of the PEB's `NtGlobalFlag`, runtime decoding of stack strings and an XOR-encoded configuration. Flags control network traversal, cleanup, presentation and domain deployment. The executable loads libraries and resolves APIs as it needs them. These settings explain why two Red samples can behave differently on the same host: a compiled capability can be disabled.

The binary needs appropriate access to each file or remote resource. Privileged execution can enable wider impact, but the encryptor's presence does not establish that it originally obtained domain credentials.

#### 2. Domain deployment and remote execution

Cybereason observed three deployment routes: manual RDP, semi-automated PsExec initiated through the ransomware and a dedicated Group Policy object. The GPO scheduled tasks stopped processes/services and launched the payload on configured targets. GPO use is not unrestricted autonomous domain compromise: the operator needs the rights and connectivity to change policy and deliver the file.

Dong's binary analysis also identifies generated policy files, including `Registry.pol`, and policy settings that impair Defender. This is a binary-supported deployment path in that sample, distinct from an affiliate independently typing a PowerShell command. Artifacts can include SYSVOL/NETLOGON writes, policy modifications, scheduled-task registration, remote service execution and the same executable hash appearing across machines.

#### 3. Preparing files for encryption

The published incidents contain process termination, service stops and recovery impairment. Database processes may hold files open; backup and security services may interfere with impact. Attribute the concrete action using its parent process: a GPO task running a batch file is different from a service-control API call made inside the encryptor.

In Dong's sample, a failed attempt to open a target file leads to `NtQueryInformationFile` with `FileProcessIdsUsingFileInformation`. The binary enumerates processes, checks their names against a hashed exclusion list and can call `NtTerminateProcess` on a file owner before retrying the open. This path can produce a process exit without a `taskkill.exe` child or a PowerShell command. The exclusions limit which processes this routine terminates.

Before encryption, the executable uses `RegCreateKeyExA`, `RegQueryValueExW` and `RegSetValueExW` to establish a public-key-derived value under `Software\Microsoft\Windows\CurrentVersion\Run`, pointing to its executable. The analysis describes removal of this restart value after encryption. A separate Run entry for the displayed HTA note has a different purpose; it should not be conflated with restarting the encryptor.

#### 4. Traversal, encryption and output

The analyzed Windows sample selects `BCryptGenRandom`, falling back to `CryptGenRandom`, for random input. Its cryptography combines **AES-128-CBC** file processing with the libsodium construction identified by the researcher as **XSalsa20-Poly1305-BLAKE2b-Curve25519** for protecting key material. This is sample-specific evidence; a generic AES/RSA description from another branch would be inaccurate here.

The binary stores or retrieves the victim public key and an encrypted session-key structure in `Public` and `Private` values under a public-key-derived `Software` subkey. The value named `Private` contains protected material; its name does not establish the availability of a usable plaintext decryption key.

`NtCreateIoCompletion` and worker threads coordinate file processing. `GetLogicalDrives` and `GetDriveTypeW` select local volumes; `FindFirstFileExW` and `FindNextFileW` enumerate their contents. Directory, filename and extension exclusions skip operating-system material and already processed outputs. A per-drive `.lock` marker and an in-memory list limit duplicate traversal. Read-only attributes can be cleared before a file is opened.

Workers pass chunks through read, AES-CBC processing and write states, then finalize the file and its recovery metadata. The published sample uses filesystem-sector information when setting up chunks. Do not substitute Black's stream cipher or NG-Dev's extension-specific modes for this implementation.

In this construction, AES handles the data volume and libsodium protects the much smaller key structures. Curve25519 supplies the public-key component; the accompanying symmetric and authentication functions protect the key container. These are separate layers, not a claim that each file is successively encrypted in full with every named primitive. The registry-held session material and the per-file material consequently have different recovery roles.

The file work has an observable lifecycle: selection, opening, optional release of a lock, queued reads/writes, metadata finalization and handle closure. An interruption can leave mixed outcomes in one directory: untouched files, renamed files, partially processed data and completed outputs. A single extension count cannot distinguish these states. Preserve the tail of each file rather than trimming it during triage, because the key container and processing metadata belong to the output format.

Processed files commonly receive `.lockbit`, and `Restore-My-Files.txt` provides the extortion message. Dong also documents icon and wallpaper changes, an HTA note, and a file association that invokes `mshta.exe` to show that note when an encrypted file is opened. A later `mshta.exe` event can therefore be a presentation artifact rather than initial access. The service's advertised printing features are distinct from proof that a specific host printed a note.

```text
MOCK HOST EVENTS — descriptive, not executable
encryptor-A -> query processes holding <target file>
encryptor-A -> request termination of <non-excluded file owner>
encryptor-A -> Run value <key-derived name> = <encryptor path>
encryptor-A -> Software/<key-derived subkey>/Private = <protected session data>
encryptor-A -> file write + rename to <original name>.lockbit
user opens encrypted file -> file association -> mshta.exe -> <local note HTA>
```

#### 5. Completion states and per-file recovery containers

Dong labels four worker states. State 1 transforms and writes a chunk; state 2 handles final renaming and resource cleanup; state 3 completes note-related work; state 4 coordinates completion of larger, multi-chunk files before finalization. These are work-item states, not four successive encryption algorithms.

The distinction explains an interleaved trace: one file can be awaiting a write while another is being renamed and a third work item concerns a note. A note operation must not be counted as another encrypted user file. Likewise, a scheduled write is not evidence of its successful completion.

The per-file container protects the AES key/IV and processing metadata, including original size, block size and chunk count. A separate session container holds protected victim/session material. Red's libsodium containers are not interchangeable with the original generation's fixed RSA footer.

```text
MOCK WORK-ITEM TRACE — descriptive, not executable
file-A -> chunk transform/write -> outstanding completion
file-B -> final metadata -> rename -> close and release context
note-C -> note completion -> release note context
file-A -> remaining chunks complete -> finalization
```

Keeping original-size and chunk information has a practical consequence: an affected file is a container with both damaged content and instructions for interpreting that damage. Renaming it back does not reverse its byte transformations.

#### 6. Network discovery versus domain deployment

Dong's network path uses `GetAdaptersInfo`, probes ports 135/445 and enumerates shares through `NetShareEnum`. That expands the set of accessible file targets. The GPO path instead checks domain-related conditions and generates policy artifacts; it is a distinct execution mechanism.

For example, a workstation can write an encrypted document through an existing SMB session while the file server never launches the PE. A policy-delivered copy creates a second executing process on its destination. These lead to different process counts and containment scopes despite similar encrypted filenames.

#### 7. Operator scripts surrounding the executable

Cybereason observed scripts altering Defender settings, boot/recovery behavior and event logs. These are source-backed campaign actions, but assigning every one to the ransomware's internal code would produce a misleading binary analysis.

```text
MOCK EVENT SEQUENCE — descriptive, not executable
GPO task -> script-A -> request stop of <database service>
GPO task -> script-A -> request change to <security setting>
GPO task -> encryptor-A -> write/rename target files
transfer-tool-B -> outbound upload from a separate staging host
```

### Linux and ESXi branch

The dedicated locker targets files on Linux or VMware storage. ESXi impact concentrates on VM disk and configuration artifacts: stopping guest workloads or releasing file locks precedes datastore encryption where the particular build implements those actions.

Windows COM, Defender and registry routines do not run on ESXi. Review hypervisor shell and management logs, datastore writes and VM power events. One compromised hypervisor can produce effects across multiple guests.

#### 8. VMware-aware startup and file enumeration

The independent Hack & Cheese analysis examines a historical locker previously covered in 2022. It checks for VMware management utilities before its default VM-oriented workflow, resolves VM directories and applies VM and extension exclusions. Its stopping option affects which running guests proceed to encryption. This is access to the VM's host-side files, not an exploit injected into each guest.

The analyzed code uses libc directory matching and threaded file processing. Optional daemonization detaches execution from its terminal; `/tmp/locker.pid` and `/tmp/locklog` are documented artifacts. A detached process is not automatically reboot persistence: no startup service or cron entry follows merely from calling `daemon`.

#### 9. Cryptography and optional free-space handling

The same independent analysis identifies AES file processing, libsodium randomness and `crypto_box_seal` protecting per-file random material. Its prose incorrectly equates 32 bytes with 128 bits, so that sentence is not used to establish the AES key size. Key/IV layout must be distinguished from the total size of an input buffer.

The optional wiping routine fills available space through temporary-file writes. That is distinct from the encryption pass and can affect recovery of previously deleted data. Its presence does not prove it ran during a particular incident.

```text
MOCK STORAGE TRACE — descriptive, not executable
locker-A -> discover VM directories and current power state
locker-A -> apply VM/file exclusions -> obtain writable file handles
worker-B -> transform selected file content -> attach protected key material
optional cleanup worker -> sustained temporary-file writes in free space
```

For a VMDK, the affected object is a virtual disk container. It can contain an operating system, application and many user files, which explains how a relatively small set of host-side writes can disable a much larger guest estate. Snapshot chains and split disk extents also matter: an intact descriptor alone does not establish an intact virtual disk.

### StealBit component

StealBit supports data theft in the Red-era service. It is not the encryption algorithm and should be represented as a distinct process and network flow. Its execution before or alongside encryption explains why recovery from backup does not reverse the confidentiality impact.

## Linking Host Activity to the Executable

Use GPO/task/service logs to identify how the payload arrived, then use process-linked file events to identify what it encrypted. Keep exfiltration clients and operator batch files as separate nodes. A common filename alone does not show whether a command came from a binary, remote shell or policy script.

Return to the [encryptor index](README.md).
