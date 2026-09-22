# INC Ransom — Encryptor Analysis

**Presentation reviewed:** 2026-09-22.

## Scope

This document follows the execution paths described in published reverse engineering, separating Windows generations and Linux/ESXi. It reconstructs those analyses and the supplied dossier; it does not claim independent execution or disassembly of malware. Sample-to-report provenance is centralized in [References](../References.md).

An intrusion tool and an encryptor are different components. A Veeam credential extractor, an EDR-killing driver loader and a cloud upload client can precede INC encryption without being embedded in INC. Process lineage is therefore essential when assigning an observed action to the ransomware.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Early Windows, 2023 | Native Windows PE; classic implementation | Concurrent partial encryption, Restart Manager, storage discovery, notes and printing | Huntress/Cybereason observations; enabled behavior depends on arguments |
| Updated classic Windows, 2024–2025 | Native Windows | AES-256-CTR and Curve25519 in the independently analyzed 2024 sample; mode and Safe Mode options | Sample beginning e17c6015; “v2” is the researcher's label |
| Windows Rust generation, reported 2026 | Rust and native Windows APIs | Salsa20/AES/Curve25519 artifacts; process/service handling | Acronis Windows set; algorithm strings are not a complete cryptographic specification |
| Historical Linux/ESXi, from December 2023 | Linux executable | Host-level file encryption and virtualization targeting | Historical reporting is distinct from the newer Rust sample |
| Linux/ESXi Rust generation, analyzed 2026 | Rust ELF64 | X25519-derived material, AES-128-CTR and a structured INC footer | Acronis Linux set; do not assume the classic Windows footer layout |

## Executable Analysis

### Classic Windows: initialization and execution choices

#### The argument parser selects the active paths

The program reads its execution arguments before traversing storage. A specific file or directory can constrain the target set. Other options enable share enumeration, hidden-volume handling, application shutdown and diagnostic output. A binary possessing all these routines need not execute all of them in one incident.

The early interface includes --file, --dir, --ens, --lhd and --sup. Later analyses describe --mode, --hide, --kill and --safe-mode. These tokens are useful in captured command lines, but their presence does not establish successful execution.

The supplied notes incorrectly merge --kill with Safe Mode. In the independently analyzed 2024 build, --kill controls process termination, while --safe-mode selects the boot/service path. Running the payload through PsExec as SYSTEM is another separate decision made during deployment; it does not demonstrate an exploit inside INC.

#### Storage enumeration and exclusion checks

The program identifies accessible storage and walks candidate directories. Share enumeration extends the target set to network data reachable with the current token. Hidden-volume handling can expose additional storage. These routines differ from NetScan or AdFind reconnaissance conducted before deployment.

The classic analysis identifies GetDriveTypeW, FindFirstFileW/FindNextFileW and CreateFileW for drive classification, directory iteration and file opening. Forensic evidence is usually a burst of file activity from the payload; ordinary process-creation logs do not expose each API invocation.

Name and path filters omit selected system directories and executable formats. Reported exclusions include Windows, Program Files, AppData, the recycle bin, and .exe, .dll, .msi and .inc extensions. Their purpose is consistent with preserving execution and the extortion interface while damaging valuable data. They do not guarantee bootability or safe handling of every volume.

#### Queueing and worker threads

The classic implementation distributes file work across multiple threads. The analyzed queue path uses CreateIoCompletionPort and GetQueuedCompletionStatus; CreateThread starts workers. Cybereason describes a worker count tied to the processor count, with four workers per processor. Directory traversal and file processing can proceed concurrently through a queue.

This explains rapid impact across unrelated directories. Worker count is not a measure of network connections or affected machines. CPU/disk activity is supporting evidence; repeated INC renames and note creation are more specific.

#### Releasing files through Restart Manager

The --sup path can use Windows Restart Manager to release application-held resources. Restart Manager associates resources with processes and requests shutdown. Related event records can appear even when taskkill.exe or PowerShell never executes.

Other builds implement direct termination. Reported matching targets include database, backup and application processes, with masks varying by build. The independently analyzed 2024 sample targets SQL-name matches through CreateToolhelp32Snapshot-based enumeration followed by OpenProcess and TerminateProcess.

~~~text
[illustrative API/telemetry sequence; not an executable command]
Encryptor: file is held open by an application
Restart Manager: resource associated with a process
Shutdown request or separate termination branch
Encryptor worker: file becomes writable and processing resumes
~~~

A stopped database alone cannot distinguish these paths. Correlate the stopping process, application logs, Restart Manager evidence and the payload's argument set.

#### Recovery inhibition without a command interpreter

Published analysis associates INC with shadow-copy manipulation through DeviceIoControl. The API submits requests to a device driver; its presence alone is not proof of deletion or EDR bypass. The target handle, request, surrounding code and resulting storage activity establish the operation.

A search restricted to vssadmin.exe can therefore miss payload-internal behavior. Conversely, a vssadmin process might belong to a separate operator script. Collect VSS/storage events and endpoint behavioral telemetry together.

Hidden-volume activity can increase the data exposed to traversal, but it is not autonomous exploitation or credential theft. Keep storage access and intrusion-stage privilege acquisition separate.

### Updated classic Windows: encryption and recovery metadata

#### AES mode must remain attached to the sample

Alien177's July 2024 analysis identifies AES-256-CTR with Curve25519 for the sample recorded in the hash register. This corrects the supplied dossier's blanket AES-256-CBC description. The analysis also describes random key preparation for individual files.

The symmetric primitive transforms bulk file data; the asymmetric component protects the material needed for recovery. Embedded public-key material is not an attacker's private decryption key.

CTR generates a keystream from counters and combines it with file bytes. CBC has a different chaining construction. Both may be summarized as AES, but they are not interchangeable when selecting a decryptor or examining file structure. A recovery tool must match the specific format and implementation.

The reported classic file path can be represented as an examination trace:

~~~text
[illustrative API trace; no executable implementation]
CreateFileW / GetFileSizeEx -> obtain target handle and length
CryptGenRandom -> prepare random per-file material
ReadFile -> obtain the selected region
Worker -> transform that region and write resulting bytes
File ending -> append recovery-related metadata
MoveFileExW -> rename the resulting artifact with the INC suffix
~~~

The sequence separates content modification, metadata writing and renaming. An interrupted run can leave these operations at different completion states; a filename alone cannot establish which steps finished.

#### Partial encryption and mode selection

Fast, medium and slow describe work policies, not three separate actor identities. Classic analyses document selected-region encryption and full-file processing. GuidePoint's examined format includes beginning, middle and end regions in fast mode, and an alternating encrypted/skipped-block example for medium mode.

Thresholds must remain sample-specific. A report using 1,000,000 bytes does not justify silently replacing that value with a binary mebibyte. Ambiguous mode tables likewise should not become universal claims that all files above a certain size are ignored.

Partial encryption reduces rewritten data while still damaging structured files. A database, archive or virtual disk can become unusable when only some headers, indexes or internal blocks change. Untouched regions may remain useful for forensic recovery and exposure assessment.

~~~text
[illustrative file map; not a universal offset specification]
Original: [region A][region B][region C][region D][region E]
Result:   [changed ][retained][changed ][retained][changed ][metadata]
Name:     original-name.ext.INC
~~~

#### The classic footer is part of the evidence

GuidePoint describes an 80-byte footer carrying recovery-related material and layout information. A renamed encrypted file is therefore not just the original with different content: its ending is important to the examined decryptor.

In that format, the first 32 bytes are unique to the file/encryption run, followed by a three-byte INC marker. The final 16 bytes describe mode, encrypted-block size, skip multiplier and block count. In the published medium-mode example, a 1,000,000-byte block and a multiplier of five describe 5,000,000-byte skipped regions. These fields describe the examined format, not a universal layout for the Rust branch.

The same investigation discusses repeated encryption and multiple appended footers. Counting filename extensions alone would miss that history. Preserve original artifacts and test recovery only on copies. Failure of one decryptor does not prove that every surviving plaintext region is unrecoverable.

Record sample hash, file length, mode evidence and intact ending together. A different footer can indicate another build, damaged metadata or repeated modification.

Dark Reading's 2024 headline refers to GuidePoint's recovery research, not publication of a universal private key. Metadata can guide triage; untouched portions of partially encrypted files may support forensic extraction. Recovering plaintext is different from decrypting transformed blocks. Application-level consistency still needs checking: a partly recovered virtual disk or database is not necessarily a usable restored system.

#### Service and Safe Mode path

The updated classic sample includes dmksvc and SafeBoot registration in its conditional Safe Mode execution path. Service configuration, boot settings and reboot evidence help reconstruct that branch.

Service-control access requires an appropriately privileged caller. Requesting broad access to the Service Control Manager does not itself grant privilege. Inspect the creating process, service ImagePath, account and execution after reboot.

~~~text
[illustrative telemetry; no deployment commands]
Payload -> Service Control Manager activity
Registry -> SafeBoot service registration
Boot configuration -> reboot
Service -> payload execution under the selected startup context
~~~

This is a conditional path, not a universal persistence mechanism on every INC endpoint.

### Notes, printers and desktop notification

INC writes text/HTML ransom notes and can submit them to printers. Embedded Base64 strings hold note content in analyzed samples; CryptStringToBinaryA performs decoding in the classic Windows analysis. Decoding them recovers text; it is not cryptographic decryption and does not require an online note server.

Printer enumeration and spooler artifacts explain paper demands as well as disk files. Virtual printer drivers can also produce local evidence. A specific spool filename is incidental, not a stable family marker.

Wallpaper changes are another presentation channel. Notes and desktop messages do not prove successful encryption of every intended file: the process can fail or be interrupted after creating them.

The later DATALEAK_PRESS_RELEASE.txt from the September 2026 incident is an additional extortion artifact. Its observed timing does not establish a timer built into every encryptor.

### Rust Windows: newer implementation, familiar host interfaces

Acronis reports Rust dependency artifacts and Salsa20/AES/Curve25519 strings. Its packing description is internally inconsistent: a VMProtect claim is followed by an unpacked/exposed-import description. Neither should be generalized to all INC samples.

The reported code still reads arguments, enumerates storage, handles processes/services and obtains cryptographic randomness through Windows interfaces. Language changes do not eliminate file handles or service-control operations.

Algorithm names alone cannot establish that every file passes through Salsa20 and AES in a particular order. Similarly, a random buffer's size does not identify it as a complete key or IV without tracing its use. The defensible conclusion is a changed implementation, not an invented universal key schedule.

Reported output retains .INC and an INC marker. Those features help identify artifacts but must be combined with provenance because related families reuse code.

### Linux/ESXi: host-level execution

#### Historical Linux sample: generated helper scripts

SonicWall's June 2024 sample creates kill and delete helpers. The former uses esxcli for VM-process termination; Figure 4 shows the latter using vim-cmd for snapshot removal, despite the article's broader VM-deletion wording. These are separate impact mechanisms.

Testing outside ESXi produced a missing-utility error, so the report establishes generated functionality rather than successful hypervisor execution. INC-suffixed output, notes and a changed login message belong to this historical analysis, not only the later Rust branch.

#### Daemon and virtualization paths

Historical Linux reporting starts in 2023; the later Rust ELF analysis should not be projected backwards onto all those binaries. Its options include daemon execution and ESXi-aware actions.

Daemonization detaches execution from a terminal. It is not equivalent to creating a cron job or installing a persistent service. A message-of-the-day modification similarly supplies an extortion notice rather than proving a startup mechanism.

The ESXi path interacts with VMware management utilities to stop VMs and affect snapshots. This can release virtual-disk resources before host-level encryption. Confirm both management actions and file changes: a stopped VM and an encrypted VMDK are separate facts.

#### Runtime choices and scope of impact

A host-level encryptor operates on files accessible to its account. On a hypervisor, virtual disks and associated VM data are ordinary host-visible objects even though they represent complete guest systems. Guest antivirus cannot be assumed to observe a process running outside the guest.

Stopping VM processes reduces concurrent writes, while removing snapshots affects recovery options. File encryption is a third operation. A case timeline should record each result separately: a failed utility call does not prevent another file-processing branch from running.

The daemon and MOTD switches select execution/presentation behavior. They do not establish a cron entry, boot service or self-propagation routine. Keep these distinctions when explaining the binary's persistence and reach.

#### Rust Linux cryptography

The analyzed Linux Rust sample creates ephemeral X25519 material at worker-thread initialization. ECDH with embedded public-key material produces a shared secret, and SHA-256 supplies material for AES-128-CTR. This corrects the unqualified “per-file X25519” wording in the supplied notes.

A 256-bit digest and a 128-bit AES key are different objects. The published description does not justify inventing a digest-slicing or nonce layout. Thread-local initialization must also not be described as a fresh asymmetric keypair for every file without evidence.

The mode controls how much of the file is processed; AES-CTR describes how selected bytes are transformed. These are independent aspects of the implementation.

#### Linux output and recovery boundaries

The Rust Linux format combines .INC with structured end-of-file metadata and an INC marker. Its described mode fields and prefix differ from the classic Windows account. Identify the format before applying an 80-byte-footer assumption.

For hypervisor incidents, preserve executable provenance, launch context, management logs, filenames and intact file endings. One encrypted datastore can affect many guests even when only the host recorded the encryptor process.

## Linking Host Activity to the Executable

Assign an action to INC itself when lineage, an instrumented trace or a matching published code path supports the relationship. Shell history proves a command was run; it does not prove the encryptor implemented it.

Veeam scripts, PsExec/WMIC deployment, EDR terminators and Rclone/Restic exfiltration remain separate components. In particular, renamed Restic winupdate.exe must not be merged with encryptor win.exe.

Record hash, parent/child processes, account, arguments, file/registry/service changes and storage events. API-level observations require appropriate instrumentation; Sysmon process creation alone does not record every Restart Manager or DeviceIoControl call. Continue with the [lifecycle](operations.md), [artifacts](../iocs/file-artifacts.md) and [detections](../detections/Detections.md).
