# LockBit — Original LockBit / ABCD Executable

**Presentation reviewed:** 2026-09-22.

## Scope

The original Windows branch spans ABCD in 2019 and LockBit-branded samples in 2020. The name 1.0 is used here to distinguish this generation from Red; it does not imply every 2019 and 2020 binary has identical code.

This is a synthesis of published reverse engineering, not a claim that malware was executed or independently disassembled for this repository. Destructive mockups describe events and are deliberately non-executable. Bibliographic provenance is centralized in [References](../../References.md#executable-analysis-provenance).

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Original / 2019–2020 | Native Windows PE | Early ABCD suffix; later LockBit branding, privilege checks and concurrent I/O | Sophos's 2020 sample is not evidence that all original ABCD builds used the same routines |

## Executable Analysis

### Windows branch

#### 1. Process initialization and privilege checks

The 2020 Sophos analysis describes token inspection through `OpenProcessToken`, creation of an administrator SID with `CreateWellKnownSid`, and comparison through `CheckTokenMembership`. The decision determines whether elevation-related code is needed. It is therefore incorrect to describe all original LockBit as having no UAC-related logic.

That sample uses COM-related elevation and process masquerading. A `dllhost.exe` activation can be visible even when the original executable has an unrelated name. Its process tree must distinguish the caller from the elevated host.

McAfee ATR and Northwave's April 2020 case, now hosted by Trellix, separately describes a .NET launcher carrying an AES-protected ransomware executable. That AES use protects the delivery wrapper; it must not be mistaken for proof of the file cipher used by the recovered payload. The study compares early `.abcd` and later `.lockbit` output, changing mutex behavior and registry-based relaunch mechanisms. Even within this first generation, one specimen's visible strings are not a complete family definition.

#### 2. Unpacking, API recovery and execution gates

Acronis describes two unpacking layers, with TEA protecting an intermediate shellcode layer. The recovered program locates modules through the PEB, resolves functions and decodes strings at runtime. This preparation exposes the actual ransomware routines; TEA here is not the cipher applied to documents.

That analysis also identifies debugger and Windows UI-language checks. These run before destructive work and can explain a payload that starts but never reaches file processing. Sophos's examined 2020 build additionally exits when supplied command-line arguments. This differs from Black's later argument-dependent unlocking: adding an arbitrary argument is not a consistent way to exercise this family.

#### 3. Instance control and file selection

The analyzed branch uses a global mutex to limit duplicate execution. It traverses directories through `FindFirstFileExW` and `FindNextFileW`, comparing names against exclusion lists. Skipped paths are configuration or implementation behavior, not evidence that an endpoint was never accessed.

Sophos also describes runtime decoding of service and process names, rather than keeping every target as a readable disk string. The binary carries both termination targets and file exclusions. Those lists serve different purposes: one releases resources or interferes with protection; the other avoids damaging components needed to keep Windows running. A stopped database can be affected before its data files are processed.

#### 4. Service and process handling

Lexfo identifies `OpenSCManagerA`, `EnumDependentServicesA` and `ControlService` in the service-stop path. Process handling instead traverses a Toolhelp snapshot and uses `OpenProcess`/`TerminateProcess` against selected names. A stopped service and a terminated application can therefore originate from separate routines inside the same PE, without a shell child.

The distinction matters for database files: service preparation changes the application state, while later file I/O changes stored data. An application outage can begin before its first encrypted document appears.

#### 5. Parallel file processing

The implementation uses I/O completion ports to coordinate file work. Enumeration supplies pending file operations to workers; completion notifications let them continue processing without creating a separate operating-system thread for every file. Several writes can therefore occur concurrently rather than in an orderly one-directory-at-a-time sequence.

The 2020 sample selects `BCryptGenRandom` with a CryptoAPI fallback. Sophos relates a registry-held value to material at the end of encrypted files, including a marker with run-related bytes. These are useful connections between the executable, registry and output. A marker identifies a structure; it is not itself a decryption key.

Lexfo resolves the queue calls as `NtCreateIoCompletion`, `NtSetInformationFile` with `FileCompletionInformation`, and `NtRemoveIoCompletion`. File handles are associated with the port; completed asynchronous operations supply subsequent worker activity.

#### 6. AES content processing and the RSA key hierarchy

Lexfo's sample generates a fresh AES-128 key per file. It selects AES-NI or an mbedTLS software implementation. A victim-generated RSA session pair protects those file keys; an embedded actor RSA public key protects the session material. The registry retains protected session data in `SOFTWARE\LockBit\full` and its public counterpart in `SOFTWARE\LockBit\Public`.

Acronis separately identifies AES-128-CBC, with a 16-byte key and IV. Hardware acceleration changes the implementation path, not the meaning of the key hierarchy. A CPU without AES-NI does not thereby prevent the software path from transforming files.

```text
KEY ROLES — conceptual, not executable
document bytes -> AES file key
file key -> protected using victim/session RSA public key
session recovery material -> protected using embedded actor RSA public key
```

The recovery dependency runs in the opposite direction. Possession of the file's wrapped key or the registry's public value does not supply the missing private secret. This is why extracting a recognizable key container is different from obtaining a working decryptor.

#### 7. Appended recovery structure

Lexfo documents a `0x610`-byte footer: `0x100` bytes of protected AES key, `0x500` bytes of protected session material and a `0x10`-byte actor-public-key fragment. These dimensions describe that specimen, not all ABCD output.

The footer is additional recovery data, not another encrypted document. When comparing pre-incident and affected copies, distinguish changes within the original content from bytes appended after its original end. Removing that tail can discard information needed by a compatible recovery tool.

Partial encryption can destroy a file's usability without replacing most of its bytes. For example, damage to a document container's metadata or a database header can prevent normal opening while much of its body remains readable in a forensic viewer. Conversely, readable fragments do not establish that an application can safely recover the complete file. Compare an affected copy with a known-good counterpart at several offsets and preserve the appended metadata.

#### 8. Relaunch, impact and cleanup

Acronis records a Run value named `XO1XADpO01` referencing the payload, removed after completion, and a separate note-related Run entry. A Run value requests execution at user logon; it does not establish a SYSTEM service or an unconditional boot-time launch. The cleanup helper delays, overwrites the payload and removes it. These are separate effects from creating the HTA extortion display.

ABCD-era and later LockBit-era suffixes must be separated. Notes threaten publication as the service evolves. A note's claim that information was downloaded does not itself demonstrate exfiltration by the encryptor.

The 2020 study also documents cleanup behavior. For event interpretation, process lifetime, deletion of the payload and ransom-note creation should be placed on the same timeline; payload disappearance is not evidence that its work failed.

Cynet's June 2020 analysis describes child processes associated with event-log clearing, shadow-copy removal and recovery-configuration changes, alongside a Run-key artifact. This provides a command-based route in the early branch, whereas later samples also use direct management APIs. Correlate each request with its parent process and result: a created child does not prove the target log was cleared or that a recoverable snapshot was removed.

The distinction between local and remote file access is operationally important. A Windows encryptor with access to an SMB share can alter data on a server while executing only on the client. The server may consequently show network file access and changed documents without a local LockBit process. A remote service launch is a different event: it creates execution on the destination and should have corresponding service, authentication or process evidence.

The resulting impact spans file availability, application availability and recovery. These should be recorded separately. File renaming demonstrates a filesystem change; a failed application demonstrates disruption; content comparison demonstrates the actual transformation. None of these observations alone establishes that data was uploaded outside the organization.

```text
MOCK EVENT SEQUENCE — descriptive, not executable
sample-A -> inspect current token -> request elevated context
sample-A -> enumerate directory -> skip configured names
sample-A -> submit concurrent file I/O -> rename processed files
sample-A -> create note -> remove its on-disk launcher
```

## Linking Host Activity to the Executable

Correlate the exact sample hash, early suffix, note, COM activation and file activity. A Defender-setting change or remote-management installation elsewhere in the incident should remain affiliate activity unless the process tree connects it to this executable.

Return to the [encryptor index](README.md).
