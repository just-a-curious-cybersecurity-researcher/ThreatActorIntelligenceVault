# The Gentlemen — Ransomware Executable Internals

**Presentation reviewed:** 2026-09-17.

**Research reviewed:** 2026-09-17. Synthesis of published binary analyses and the supplied research; no local malware execution or disassembly.

## Scope

This account follows the encryptor's own routines. Affiliate discovery, WinSCP and Allpatch2.exe remain separate components. Numbered steps describe functional flow, not an invariant runtime trace.

**Mockup convention:** mock commands below are invented, non-executable illustrations. Sample paths, handles and results are fictional; they are not recovered commands or indicators.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| August 2025 case | Windows Go locker | Eight-byte password in analyzed sample; .7mtzhh and README-GENTLEMEN.txt | Trend Micro's campaign/sample view |
| May 2026 executable analysis | Windows Go | Local/share workers, SYSTEM task, partial large-file encryption and cleanup | Microsoft's identified sample; report date is not a release number |
| Go portfolio in 2026 reporting | Windows and reported Linux/NAS/BSD builds | Windows analysis exposes integrated propagation; other Go targets are a portfolio claim, not Windows-compatible commands | Check Point's portfolio description; sample scope must be retained |
| Windows C variant, reported 2026-06-29 | C with statically linked OpenSSL | Different cryptography, TaskSystem and direct event-log API | Kaspersky fin.exe analysis; not the C/ELF ESXi payload |
| ESXi sample analysis, 2026 | Separate C/ELF hypervisor locker | VM/process handling, datastore preparation and boot persistence | Check Point's dedicated ESXi analysis; separate from the Windows Go build |

## Executable Analysis

### 1. Windows — startup and configuration

#### 1. Argument parsing and execution gate

Startup reads the supplied password and compares it with the value embedded in the build. The early analyzed example uses eight bytes. An incorrect value stops the main routine; the password is an execution condition, not the private key needed to recover files.

Optional settings select a path, a delay, local processing, network shares, silent behavior and cleanup. The same executable can therefore produce different observable artifacts across runs.

Read the argument parser as a set of branches. The password gate precedes destructive work; path selection restricts traversal; the delay postpones work; scope selects local or network resources; speed affects large-file processing. A recovered command line therefore explains only the selected path through the program. A password recovered with the executable is not a decryption secret.

The Windows sample is Go code obfuscated with Garble. Its SYSTEM worker uses the environment flag `LOCKER_BACKGROUND=1`. These are static/runtime investigation clues, not evidence that a particular host was encrypted. Check Point additionally documents a `--gpo` option; keep that option tied to its analyzed build rather than assuming every published argument list is identical.

#### 2. Local and network worker separation

The full mode relaunches the executable twice: a local worker under SYSTEM and a worker that can see shares in the user's session. Separating these contexts preserves access to mapped resources that might not exist in a service account's session.

The local path removes an existing gentlemen_system task, registers a replacement and triggers it. This requires prior administrative rights; creating a privileged scheduled task does not manufacture those rights.

**Illustrative mockup — worker dispatch**

```text
mock-worker select --mode FULL
  => local context: SYSTEM; share context: current user
mock-task replace --name gentlemen_system --image "C:\Example\sample.exe"
  => privileged task registered, assuming an authorized administrator
mock-task trigger --name gentlemen_system
  => local worker started
mock-worker start --scope SHARES --context current-user
  => user-visible share worker started
```

These lines explain the two execution contexts. They are not valid task-creation syntax or a launch recipe.

### 2. Windows — preparation and persistence

#### 1. Security and recovery impairment

The binary invokes PowerShell to change Defender preferences and exclude itself and the system drive. It also invokes shadow-copy management utilities and clears selected event logs. These are attempted changes whose success depends on its rights and the endpoint's protections.

The reported preference operations have separate meanings: `Set-MpPreference` changes the real-time protection setting; `Add-MpPreference` adds path/process exclusions. A whole-volume exclusion has a wider scope than excluding the locker image. Preserve the argument value: a command mentioning a setting can enable protection as well as disable it.

The recovery branch invokes both `vssadmin` and `wmic`. Finding both children under one parent is stronger evidence of a shared routine than one administrative command in isolation. Clearing the System, Application and Security channels removes different records; forwarding can leave remote copies even after local deletion.

A literal fragment in the supplied analysis is:

```text
wevtutil cl Security
```

This is a published destructive command for telemetry recognition. It clears the Security log; its appearance alone does not identify the parent executable.

#### 2. Process and service handling

The encryptor terminates selected database, backup, security and productivity processes. The published command-driven routines use `taskkill` for images and service-control operations for services. The goal is both to release open files and interrupt protection or recovery.

Reported image names include `sqlservr`, `sqlwriter`, `mysqld`, `postgres`, `vmms`, `vmwp`, `VeeamNFSSvc` and `VeeamTransportSvc`. Office and mail clients are also targeted. Service entries include `MSSQLSERVER`, `SQLSERVERAGENT`, `vss`, `VeeamDeploymentService`, `BackupExecVSSProvider` and `AcronisAgent`. These are targets of the malware, not malicious files to quarantine by name.

A stop request affects a running service; disabling its start configuration affects future launches. A process termination event does not by itself establish that either service operation succeeded. Generic labels and wildcard-like strings in a target list must not be treated as exact installed service names.

**Illustrative mockup — removing a file-access obstacle**

```text
mock-process find --name example-database.exe
  => PID 4242
mock-process request-termination --pid 4242
  => request issued
mock-service request-stop --name ExampleBackupService
  => STOP_PENDING
```

The mockup represents the reported command-driven behavior, not a claim that the source recovered these function names. A later service-state event is needed to establish a completed stop.

#### 3. Restart mechanisms

The 2026 analysis names UpdateSystem and UpdateUser tasks and GupdateS/GupdateU Run values. A Run value is a logon mechanism; its presence does not itself prove a successful reboot or SYSTEM execution. The scheduled worker and persistent restart entries have different purposes.

For a forensic reconstruction, collect task XML/action paths, registration times, author/principal and the actual trigger. The local SYSTEM worker name differs from the tasks used for remote propagation. Likewise, an HKLM Run value applies at user logon; it is not equivalent to a service starting under SYSTEM. Startup wording in a report should not override the recovered trigger or registry semantics.

### 3. Windows — discovery and file processing

#### 1. Discovering targets

Local mode discovers volumes; share mode checks mapped drives and UNC resources. Network discovery services and the related firewall group are enabled to improve visibility. These changes are separate from operator-created RDP access.

The binary excludes selected system directories, executable formats and its own note. Enumerating a path does not establish that it was selected for encryption.

The Windows traversal includes mounted-volume discovery, Cluster Shared Volume discovery and drive-letter probing. `Get-ClusterSharedVolume` is a useful command-line clue on failover-cluster hosts. For network visibility, the reported service names are `fdrespub`, `fdPHost`, `SSDPSRV` and `upnphost`; the corresponding firewall group is Network Discovery. Enabling discovery is distinct from shutting down firewall protection globally during remote preparation.

Directory exclusions include Windows/system locations and `SYSVOL`/`NETLOGON`; file exclusions protect the ransom note and selected boot/configuration files. A distribution share can be excluded from encryption yet still carry the payload. Do not mistake an exclusion list for a list of safely recoverable files.

#### 2. Ownership and write access

Before content processing, published Windows analysis describes `takeown`, `icacls` and `attrib` activity. They change ownership, permissions and the read-only attribute respectively. The Everyone SID is `S-1-1-0`. These operations explain an access-control change before mass writes; they do not establish an exploit of NTFS.

```text
mock-file examine --path "D:\Example\report.docx"
  => ownership restrictive; read-only attribute present
mock-access request-write --object report.docx
  => ownership/ACL/attribute changes recorded as separate events
mock-file select-for-processing --object report.docx
  => eligible only after path and exclusion checks
```

The mockup is a fictional observation sequence. No real permission-changing command is supplied.

#### 3. Per-file encryption

The documented design combines Curve25519 with XChaCha20. Per-file material separates one file's cryptographic state from another. The attacker-controlled key material and the password used at launch have different functions.

Microsoft describes a fresh ephemeral key pair per file, an ECDH-derived shared secret used as the symmetric key, and a nonce derived from the ephemeral public key. The public part is retained with the encrypted file. Check Point's Windows narrative reverses the key/nonce inputs. Both describe X25519/XChaCha20, but these explanations are not interchangeable. This dossier follows Microsoft's description for its identified sample and records the disagreement; it does not infer a proven version change or provide a decryptor from conflicting prose.

The large-file speed options change the fraction of data processed. The supplied default of 9% is a per-chunk figure, not a statement that exactly 9% of the whole file is affected. Files at or below 0x100000 bytes (1 MiB) are fully processed; larger files use three distributed regions, near the beginning, middle and end. The reported large-file totals are approximately 27% by default, 9% in fast mode, 3% in superfast mode and 0.9% in ultrafast mode. Small files do not acquire these percentages merely because a speed option was supplied.

Microsoft describes 64 KiB processing blocks and a different nonce state for each region. The forensic consequence is a mixture of altered and untouched regions inside one file. An intact header or readable strings elsewhere cannot establish that an archive, database or virtual disk is usable.

**Illustrative mockup — selecting a file-processing policy**

```text
mock-file inspect --path "D:\Example\small.docx"
  => size below threshold; policy: full-content processing
mock-file inspect --path "D:\Example\large.dat"
  => size above threshold; policy: distributed regions
```

The mockup deliberately models selection only. It neither encrypts data nor reconstructs the cryptographic implementation.

#### 4. Footer and visible output

The file trailer contains `--eph--`, a Base64 public-key field and `--marker--`/`GENTLEMEN` identification fields. Large-file mode can add speed metadata. Those are file-format clues; a footer-only YARA match identifies a possible encrypted output, not the ransomware executable. Preserve complete original files and trailers when collecting evidence.

The payload writes README-GENTLEMEN.txt. Trend Micro's early case uses `.7mtzhh`; Microsoft's later analyzed sample uses `.umc16h`. These are sample observations, not fixed family-wide extensions. Silent behavior can suppress renaming, timestamp changes and wallpaper. A lack of a changed suffix is therefore not proof that contents are intact.

The reported bitmap is `%TEMP%\gentlemen.bmp`. Check Point identifies `SystemParametersInfoW` as the wallpaper-setting API. This API is common in legitimate software, so its investigative value comes from the written bitmap and surrounding file impact.

### 4. Windows — propagation and completion

#### 1. Propagation context

The spreading mode accepts configured credentials or reuses the current session. GPO/NETLOGON and remote execution also appear in incident reporting. Identify the actual producer of each remote command rather than assigning all domain activity to the locker.

The module stages the executable in `C:\Temp` and exposes a hidden `share$` distribution share. NullSessionShares, EveryoneIncludesAnonymous and RestrictAnonymous changes support permissive share access. The administrative C$ share and this new distribution share have different roles: one is a remote staging path; the other serves the source copy.

PsExec is embedded and can be dropped as C:\Temp\psexec.exe; Microsoft describes a legitimate Sysinternals Live download fallback. A download from that service identifies acquisition of a dual-use tool, not malicious ownership of the service.

For each discovered target, the module tries independent execution routes through PsExec, WMIC, scheduled tasks, service creation, PowerShell remoting and PowerShell's WMI interface. Failure in one route need not stop later attempts. Blocking wmic.exe alone does not disable all WMI access; an Invoke-Command path depends instead on WinRM. The published count of 21 remote execution operations is an analysis of the program's attempts, not 21 successful host compromises.

User-context tasks are DefU, UpdateGU and UpdateGU2; SYSTEM-context tasks are DefS, UpdateGS and UpdateGS2. Service names are DefSvc, UpdateSvc and UpdateSvc2. The Update variants distinguish network-served and locally staged images. These names support tightly scoped hunts when combined with action paths and the initiating account.

```text
mock-distribution inspect --host SOURCE
  => staged image; hidden share; access-policy modifications
mock-remote-attempt record --target TARGET --route WMI
  => attempted process creation; outcome still requires target telemetry
mock-remote-attempt record --target TARGET --route TASK
  => separate registration attempt despite earlier route failure
mock-evidence correlate --source SOURCE --target TARGET
  => match share access, logon, registration and resulting process
```

This mockup explains evidence correlation. It is not a working lateral-movement sequence. Remote preparation also attempts to disable firewall profiles, enable SMB1 and broaden ACLs; searches must inspect changed values and outcomes, not only command names.

#### 2. Optional free-space processing

The wipe option creates `wipefile.tmp` at a volume root, fills free space and removes the temporary file. Microsoft's implementation description uses 64 MiB writes. A short-lived file plus falling free space is more informative than a filename alone. Filling free space is different from encrypting allocated files, and success cannot be inferred for every storage technology from the command-line flag.

#### 3. Cleanup

The supplied analysis describes removal of Recycle Bin content, Prefetch and selected RDP/Defender support files. A batch file named after the executable delays, deletes the executable and then removes itself. The Windows analysis additionally describes removal of PSReadLine's `ConsoleHost_history.txt` across profiles. This is intended artifact removal; it does not demonstrate that every trace was erased.

```text
mock-cleanup inventory --scope execution-artifacts
  => Prefetch, RDP logs, Defender support logs, console-history files
mock-cleanup record --artifact sample.exe.bat
  => delay stage; image-removal stage; helper-removal stage
mock-evidence compare --sources endpoint,forwarded-logs,filesystem
  => surviving records can remain after local deletion
```

The payload's keep option suppresses its self-deletion path. A retained image can therefore reflect selected configuration rather than an interrupted run.

### 5. ESXi — separate C/ELF branch

#### 1. Startup and VM handling

The examined platform branch takes a password and target paths, with delay and VM-exclusion controls. The Go Linux/NAS/BSD portfolio and this C/ELF branch should not be collapsed into one Windows-like executable.

The recovered routine uses `popen` to enumerate VMs and running VM processes, and `system` for individual commands. `vim-cmd` identifies registered guests; `esxcli` identifies remaining world processes. The program requests power-off and then escalates to forced process termination after a delay, with the ignore list affecting selection. A VM power-off operation is not proof that the guest OS completed a graceful shutdown. The objective is access to virtual disks, not Windows service control.

#### 2. Boot persistence

Check Point describes a copy at /bin/.vmware-authd, an /etc/rc.local.d/local.sh change and a reboot cron entry. These are host boot artifacts; the Windows scheduled-task model is not transferred to this branch.

#### 3. Datastore preparation and restart control

Check Point reports VMFS buffer-setting changes through `esxcfg-advcfg`, temporary `eztDisk` creation/removal through `vmkfstools`, and changes to the VM autostart manager. These are separate from the boot persistence that restarts the locker: the program can arrange its own restart while suppressing automatic guest recovery.

#### 4. File scope

The branch excludes selected boot and virtualization files while processing eligible storage. Platform-specific controls differ from the Windows arguments. Examples of excluded areas include `/boot/`, `/proc/`, `/sys/`, `/etc/` and `/vmware/lifecycle/`; selected VM metadata and boot files are excluded too. An excluded `.vmx` configuration does not protect the associated virtual disks. ESXi shell/host logs and startup-file evidence are required; Windows process telemetry cannot be assumed to cover the hypervisor.

### 6. Windows C — separately reported development branch

#### 1. Startup and execution context

Kaspersky identifies a Windows C sample named fin.exe. Its password gate remains, but delay is measured in seconds; several advertised options are unimplemented. The SYSTEM route replaces and runs TaskSystem. The flag list therefore cannot be treated as a capability checklist copied from the Go branch.

#### 2. File processing

This branch uses statically linked OpenSSL with AES-256-GCM and RSA, replacing the Go branch's reported scheme. Its exclusions are smaller. It writes a differently named ransom note with email contact. Preserve the sample and original file layout; a Go-footer signature is not a universal detector for this branch.

#### 3. Event-log cleanup

The program calls EvtClearLog directly and includes an invalid channel name in the analyzed routine. A hunt limited to wevtutil child processes misses this API path; check channel-clear events and surviving forwarded records.

## Linking Host Activity to the Executable

Correlate commands with executable hashes, process ancestry, account and time. A worker created through Task Scheduler can have a scheduler-related parent; link it through task registration and action fields. Record attempted versus successful operations separately.

Registry values, tasks, note writes and file modifications can connect behavior even when the binary self-deletes. Commands, mockups and strings embedded in a sample are different evidence classes. A mockup is explanatory material and must never become a detection indicator.
