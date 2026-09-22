# LockBit — LockBit Black / 3.0 and the Leaked Builder

**Presentation reviewed:** 2026-09-21.

## Scope

Black's broad public launch was in 2022-06; some summaries use an earlier emergence date. The 2022-09 builder leak is a major attribution boundary. The generated payload, builder, key generator and decryptor are different artifacts.

This is a synthesis of published reverse engineering, not a claim that malware was executed or independently disassembled for this repository. Destructive mockups describe events and are deliberately non-executable. Bibliographic provenance is centralized in [References](../../References.md#executable-analysis-provenance).

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Black / 2022 onward | Windows EXE, loader-oriented DLL and reflective DLL forms; related platform builds | Password gating, configurable suppression/impact and BlackMatter-related implementation | A generated Black payload can be deployed outside the LockBit affiliate service |

## Executable Analysis

### Builder artifacts and generated payloads

#### 1. Configuration and key material

Public builder analysis identifies `builder.exe`, `keygen.exe`, `config.json`, `pub.key` and `priv.key`. The configuration selects exclusions, process/service targets, note content and optional behaviors. An independently generated key pair breaks any assumption that a service-provided decryptor will open every Black-family incident.

The builder embeds resources for a decryptor, executable encryptor, multi-export DLL and reflective DLL. Resource 100 is associated with decryptor generation in Cyber Geeks' analysis; it must not be catalogued as an encryptor merely because it belongs to the package.

The resource identifiers distinguish those templates: 100 is the decryptor, 101 the EXE encryptor, 103 the conventional DLL and 106 the reflective DLL. The builder reads the selected template, inserts the prepared configuration and appropriate key material, and produces a separate PE. Finding all four resources indicates the construction tool; an endpoint receiving one generated payload need not contain the builder or private key.

#### 2. Binary preparation

The builder transforms configuration values and embeds key material into its output. File and directory exclusion names are represented through hashes in the examined implementation. The builder's artifact strings are useful for laboratory or incident triage, but finding `config.json` alone says nothing about ransomware.

Payload packaging and execution form should be distinguished. An EXE has a normal executable entry point. A DLL needs a loader to invoke its code. A reflective form can be mapped in memory without appearing as a normally loaded DLL on disk. These packaging choices change what process and image-load telemetry contains; they do not, by themselves, establish different file-encryption algorithms.

No builder invocation or key-generation procedure is reproduced here.

#### 3. Recovering the embedded configuration at startup

The generated binary carries its settings internally; it does not need the operator's original `config.json` beside it. Kaspersky locates this data in `.pdata`. Startup decoding and decompression recover the configuration before its individual fields are interpreted. Consequently, searching the packed file for a plaintext service name can miss a configured target.

Northwave separates this into blob decoding, apLib decompression, a variable block and a string block. The latter uses offsets to encoded entries, with additional protection for credentials and note text. Its variable data includes an RSA-1024 public key and behavior flags. Hashed exclusions cover directories, filenames and extensions; separate lists select processes and services. In its sample, host exclusions suppress selected actions rather than proving that every action against that host is excluded.

Trellix identifies 24 behavior flags and legacy fields inherited from BlackMatter. In particular, a field labelled `AES_KEY` is unused in the examined Black sample. Its presence in a reconstructed structure is therefore not evidence that the active file routine uses AES. A configuration parser describes stored fields; a call path establishes which fields actually influence execution.

```text
MOCK CONFIGURATION FLOW — descriptive, not executable
embedded protected settings -> decoded and decompressed configuration
behavior flags -> select enabled routines
exclusion lists -> reject particular file/path candidates
process/service lists -> select interference targets
public key + note template -> prepare recovery metadata and presentation
```

### Windows encryptor

#### 4. Entry gates and anti-analysis

Some generated payloads require the correct launch password before decrypting the protected body. Packed code, encoded strings and dynamic API resolution make disk strings incomplete. A specimen that exits without file impact may have encountered a configuration gate; it is not thereby harmless.

Language checks and instance-control logic further restrict execution. These are per-build properties, not proof of the operator's location.

The public Trend Micro analysis identifies shared API-resolution and thread-hiding behavior with BlackMatter, including `NtSetInformationThread`. Such similarities concern implementation. They neither make the organizations identical nor prove that every sample executes every available branch. The relevant host question is which code reached the file-processing stage under the recovered configuration.

SentinelOne describes runtime decoding of the executable body, followed by indirect API calls through small heap-resident trampolines. The stored destination pointers are obfuscated. The binary also examines heap debugging flags and the `0xABABABAB` guard pattern and invokes the thread-hiding operation. These checks explain why a protected sample can terminate under observation before its ordinary impact routines become visible.

The unpacking password is an execution gate, not the private recovery key. Recovering it from process telemetry can explain why a captured sample ran on the victim while a passwordless examination did not. It does not supply the secret required to recover encrypted documents.

#### 5. Language and duplicate-instance decisions

When the language gate is enabled, Trellix's specimen queries installation and default UI language through `ZwQueryInstallUILanguage` and `ZwQueryDefaultUILanguage`. The result selects an exit path for configured language values. This checks Windows settings, not the victim's nationality or a verified geographic location.

The single-instance check is optional. Thinkbox derives its sample's global mutex from embedded RSA public material through hashing and further transformation. This differs from the machine-GUID derivation described in the supplied advisory material. A universal `Global\<machine GUID hash>` formula would therefore miss the documented variation. The mutex prevents another matching instance from entering the protected work; disabling it changes concurrency, not the cryptographic family.

#### 6. Privilege, account impersonation and boot-state handling

The supplied analysis identifies CMSTPLUA/ICMLuaUtil-related COM elevation, token duplication and configurable Safe Mode behavior. An elevated `dllhost.exe` can be part of the COM path; token manipulation changes the security context used for later work. The relevant forensic distinction is between boot configuration, a registered relaunch mechanism and the eventual encryptor process. A Safe Mode reboot does not demonstrate that encryption completed there.

Do not generalize the supplied claim that Black “barely encrypts” in Safe Mode. The behavior must be tied to the configuration and execution path of the actual build.

Account impersonation is a separate route. Thinkbox documents configured username/password entries passed to `LogonUserW`; the resulting token is retained for later use. It also identifies requests to enable token privileges through `RtlAdjustPrivilege`. These calls use supplied authority. They do not turn a recovered username into a valid password, nor grant a privilege that the security context cannot obtain.

Local elevation determines what the process can change on one machine. Authenticated access to a share determines which remote files it can reach. Domain policy modification requires another scope of permission. Those distinctions explain why the same binary can damage user documents on one endpoint but fail to stop protected services or deploy to other machines.

The supplied boot-related artifacts include Safe Mode selection and relaunch/automatic-logon settings. The defensible sequence is a requested boot change, a mechanism to resume execution, and a later process in the changed environment. It is not a mandatory opening stage of every Black execution.

#### 7. Process termination and service removal

Black can terminate configured processes and stop services that obstruct access or provide protection. WMI-based shadow-copy deletion can occur through COM/API activity without a standalone `wmic.exe` command. Preserve WMI operations, service transitions and backup events when process-command-line evidence is absent.

Thinkbox identifies process discovery through `NtQuerySystemInformation` and service discovery through `EnumServicesStatusExW`. The returned names are compared with the configured targets. Opening and terminating a matched process is different from cancelling a Windows service through the Service Control Manager.

SentinelOne's observed targets include service strings such as `GxVss`, `veeam`, `sql` and `vss`, and process names including `oracle`, `sql`-related applications, `winword`, `excel`, `outlook`, `notepad` and `wordpad`. These are sample target strings, not a complete current product inventory. Terminating an editor can close the very application a user opened to read the newly dropped note.

Service stopping interrupts the current instance; service deletion changes the registration used for subsequent starts. Trellix documents configurable stop/removal behavior. A stopped database or backup component can therefore become unavailable before encryption touches its data. The action also releases handles that would otherwise obstruct writes.

#### 8. Shadow copies and recovery artifacts

Sophos traces the native WMI route through `IWbemLocator::ConnectServer` into `ROOT\CIMV2`, followed by `IWbemServices::ExecQuery`. The supplied advisory describes selecting `Win32_ShadowCopy` objects and deleting the identified instances. The encryptor is acting as a WMI client; no separate shell command is required for that route.

Deleting a shadow-copy object removes a recovery source; it is not the operation that encrypts the live document. An environment can therefore suffer recovery inhibition even where later file writes fail. Conversely, an intact offline backup is outside the reach of this local deletion routine.

```text
MOCK API TRACE — descriptive, not executable
encryptor-A -> enumerate configured process/service targets
encryptor-A -> request stop of <matched service>
encryptor-A -> query Win32_ShadowCopy -> request deletion of <shadow object>
encryptor-A -> enumerate target files -> submit encryption work
```

#### 9. Event-log impairment

Ranjit Patil's examination of the `80e8defa...` specimen records event-channel registry changes and `ClearEventLogW`. Channel enablement/access changes and deletion of existing records have different effects: one alters logging or access, while the other removes an accumulated history. This is separate from the ETW modifications documented for later LockBit generations.

An API-originated clear does not require `wevtutil.exe` in a process tree. It can coincide with service interference, making the local sequence incomplete while forwarded records still retain earlier events. A request to change a protected setting must still succeed before that setting is treated as disabled.

#### 10. Local targets, shares and deployment routines

Local-volume processing, network-share processing and deployment to another host are separate controls. Northwave documents directory/file/extension filtering and a large-file decision that treats database formats such as `.MDF`, `.NDF`, `.EDB`, `.MDB` and `.ACCDB` differently from other large objects. Hidden-path handling and filename randomization add further branches. A skipped document need not indicate a failed cipher; it may never have entered the work queue.

Kaspersky's examination of 396 samples found PsExec and GPO deployment enabled in 90% and 72%, respectively. These are configuration frequencies within that corpus, not measured success rates in victim networks. The same study found reporting to C2 rarely enabled. A configured deployment function still needs usable accounts, reachable destinations and permission to create its remote execution mechanism.

For example, an encryptor running on host A may modify a document on host B through an SMB handle. That is remote data impact. A copied payload subsequently starting on B is remote execution. Both can occur during the same deployment, but the file server does not need to execute ransomware for its shared files to be affected.

#### 11. Enumeration and concurrent workers

The executable separates finding work from performing it. Published sample analysis shows traversal and encryption workers communicating through I/O completion ports; Ranjit Patil also records parallel threads for discovery, note creation, service operations and file processing. These routines can overlap in time rather than form a perfectly serial checklist.

A queued file is an intention to process an object. An opened handle establishes access; subsequent writes establish modification; final recovery metadata establishes completion of that output structure. These are different milestones. A note in a directory can precede completion of its files, and the last process event need not correspond to the last filesystem event flushed to storage.

#### 12. File selection and cryptographic processing

Calif's sample-specific analysis describes modified Salsa20, a 64-byte per-file key, a separate key-encryption layer and RSA-1024 without padding. It also documents defects affecting the examined implementation. These findings should not be converted into a general claim that all Black files are recoverable.

The supplied dossier contrasts that analysis with AES/RSA descriptions in summaries. A disagreement is not resolved by asserting that a builder option switches between both schemes. Match the hash, configuration and cryptographic routines before choosing a description.

In Calif's examined sample, the extra key-encryption layer is reused across a batch of 1,000 files, reducing RSA operations. The 64-byte value initializes the modified Salsa20 state; it should not be described as standard Salsa20 with a conventional 512-bit key. The implementation processes 128-KiB chunks, with file-size-dependent encrypted and skipped regions.

Its appended footer contains protected file-key material, the original filename and processing information. This explains why preserving the whole output matters: the original data length and the final on-disk length need not be identical. The documented key-reuse defect is sample-specific; Calif observed newer variants in which its recovery opportunity no longer applied.

The two symmetric layers have different purposes. One transforms file contents; the other protects the material needed to undo that transformation. RSA protects the second layer's secret rather than processing the whole document. This is why an embedded public key and a footer are sufficient to produce an encrypted output without including the corresponding private recovery secret in the encryptor.

```text
MOCK FILE LAYOUT — conceptual, not executable
Original:  [application data .....................................]
Processed: [encrypted region][untouched region][encrypted region]
           [protected file metadata and key container]

The region boundaries and footer belong to the particular build.
The diagram is not a complete binary-format specification.
```

Forensic comparison should therefore distinguish untouched regions from decrypted regions. A string recovered from an untouched area was never necessarily processed by the cipher. An interrupted file can also lack a completed footer, producing a different recovery problem from a completed file whose private key is unavailable.

Black commonly generates a nine-character alphanumeric suffix and a related `<id>.README.txt` note. Treating `.lockbit` and `Restore-My-Files.txt` as the exclusive 3.0 artifacts loses this branch's characteristic output.

#### 13. Footer contents and interrupted encryption

Calif reconstructs a variable-length encrypted record containing the apLib-compressed original filename, chunk/skip information and file key. A trailing record contains length/checksum data and the RSA-protected wrapping material. The filename makes the total footer length variable; a fixed string at the end is not a substitute for understanding its structure.

The original name, the selected byte ranges and the appropriate file secret solve different recovery problems. Recovering the name restores identification, but not content. Recovering a key without the corresponding processing layout can still produce incorrectly transformed data. A successful cryptographic operation also does not repair application-level damage that occurred before or during encryption.

#### 14. Open-file handling and the corruption failure mode

Calif identifies `RmStartSession`, `RmRegisterResources` and `RmGetList` in the Restart Manager path used to identify processes holding target files. Termination can then release their handles. With the single-instance guard disabled, one encryptor may terminate another before its recovery footer is written. The missing random key can make that output irrecoverable. Terminating an application during a write can also leave corruption that survives otherwise correct decryption.

This differs from simply applying encryption twice with both sets of recovery metadata intact. A second suffix is a useful clue to repeated processing, but it does not prove that both transformations can be reversed. The missing or incomplete metadata determines the recovery limitation.

#### 15. Notes, presentation and reporting

Configured note text, wallpaper changes and icon changes support extortion. The note can be modified by independent builder users, and optional self-removal can remove the executable after work completes. A decryptor recovered during response must be labelled as a decryptor; it is not evidence of a new ransomware execution.

A note is an output template, whereas the private key belongs to the cryptographic setup. Replacing contact text does not establish that the key hierarchy stayed unchanged. Likewise, two samples using the same note or suffix can use different public keys. Cluster related output using sample hashes, recovered configuration and file structures before treating cosmetic similarity as a shared recovery solution.

Trellix derives its sample's output identifier from an MD5 of public-key material and describes an icon/file-association update followed by `SHChangeNotify`. Ranjit Patil records `SystemParametersInfoW` for wallpaper changes. These calls update the presentation of the impact; they are not the file cipher.

Sophos documents note printing to available printers. Printing, desktop presentation and writing a text note create different artifacts and can be independently visible. A printer job therefore does not imply that the printer itself was encrypted. Similarly, optional execution reporting to a configured destination is not equivalent to uploading the victim's document collection; the service's StealBit client remains a separate component.

### DLL-specific execution and finalization

#### 16. Exported entry points

Cybereason maps `GDLL` to encryption, `SDLL` to Safe Mode restart, `WDLL` to presentation, `GMOD` to policy updating and `DEL` to deletion. These export names identify separate routes within the regular DLL. A `rundll32.exe` host loading the library does not prove that the encryption route was invoked.

Cybereason's reflective template lacks the conventional password/command-line interface. Password protection therefore depends on output form and build. Loading method and payload behavior remain separate questions.

#### 17. Helper processes, named pipes and self-removal

Cybereason describes a temporary ProgramData PE, an injected helper and named-pipe communication. The helper terminates the original process, renames its file 26 times from repeated A characters to repeated Z characters, and calls `DeleteFileW`. A child command process removes the helper file. Configured cleanup can also follow a duplicate-instance exit.

This explains why the process that removes the payload may not be the process that performed encryption. A file-renaming sequence on the launcher is also different from ransomware renaming victim documents. The helper's temporary extension does not make its PE contents a harmless data file.

```text
MOCK CLEANUP TRACE — descriptive, not executable
DLL host -> temporary helper PE under ProgramData
DLL host <-> local named pipe <-> helper
helper -> original process exit -> repeated launcher renames -> file removal
helper -> child cleanup process -> temporary helper removal
```

This models the published DLL routine. It is not an assertion that every EXE, reflective build or independently modified fork uses the same cleanup mechanism.

### Platform scope

The Windows internals above do not establish an equivalent ESXi implementation. The service offered different lockers concurrently, so platform, executable format and artifact provenance are retained in the hash register.

## Linking Host Activity to the Executable

A Black-family hash or YARA match identifies code. Correlate note configuration, dated infrastructure and independently attributed campaign evidence before assigning the operation to the service. Query matches on launch passwords, COM CLSIDs or Safe Mode changes are behavioral leads shared with other software.

Return to the [encryptor index](README.md).
