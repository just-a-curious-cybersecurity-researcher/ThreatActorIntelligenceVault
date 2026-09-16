# Akira — Ransomware Executable Internals

**Presentation reviewed:** 2026-09-16.

**Research reviewed:** 2026-09-16. This is a synthesis of published binary analyses, not a local disassembly. The bibliography records the publications supporting each variant.

## Scope

The sections below follow the executable's routines: initialization, preparation, file selection, encryption and output. Optional branches are identified where they occur. Numbering organizes the functional flow; concurrent workers do not necessarily finish in that order.

**Mockup convention:** blocks labelled “Illustrative mockup” use a fictional `mock-api` command to explain inputs, actions and results. They are not executable commands, native API signatures, recovered source code or recorded telemetry. Paths, handles, PIDs and output values in these blocks are invented examples. Published command lines remain separately labelled.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Early Akira, 2023 | Windows x64, C++ | Partial encryption, RSA-protected keys, .akira | Early analyzed samples |
| Early Linux Akira, June 2023 | Linux x64, C++ | Crypto++ implementation | Separate Linux executable |
| Megazord, August 2023 onward | Windows, Rust | Build-ID gate and service termination | Later builds expose additional controls |
| Akira_v2, early 2024 | Linux/ESXi, Rust | Worker-based encryption, .akiranew | Cipher description depends on the analyzed sample |
| Renewed C++ builds, September 2024 | Windows and Linux | ChaCha8 and .akira | Separate platform builds |

## Executable Analysis

### 1. Windows C++ — early Akira

The early cryptographic implementation and the Windows execution analysis describe different samples within the C++ lineage. The execution details below are tied to those sample views.

#### 1. Initialization and execution settings

In the Windows sample examined by Qualys, MD5 `e57340a208ac9d95a1f015a5d6d98b94`, startup processes settings for target paths, shares, exclusions and encryption percentage. These settings determine which content reaches the file-processing routines. It also creates a timestamped execution log, separate from the ransom note.

#### 2. Shadow-copy deletion and file unlocking

The same sample launches PowerShell and uses WMI to request deletion of shadow copies. This is a child-process operation performed as part of the payload's execution.

The published command line is:

```text
powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"
```

This is an observed destructive command, reproduced for matching against collected telemetry. Hunt & Hackett identifies the launch mechanism as WMI's `Win32_Process.Create`, with a 15-second wait. Consequently, the visible PowerShell parent can be a WMI provider process; direct parentage from the encryptor is not required. WMI activity and execution timing are needed to connect that mediated launch to the binary.

Its file-access logic also uses Windows Restart Manager to close applications holding files open. The purpose is to make those files available for modification. Shadow-copy deletion affects recovery; closing a file owner affects access to the live file. They are separate routines.

The recovered API sequence is:

```text
RmStartSession → RmRegisterResources → RmGetList → RmShutdown
```

The program starts a session, registers a target file, obtains its owning processes/services, then requests shutdown. This happens inside the executable: there need not be a `taskkill.exe` command. K7 also identifies `WTSEnumerateProcesses` for process enumeration and comparison against exempt process IDs.

**Illustrative mockup — releasing a file held by another process**

```text
mock-api RmStartSession
  => session: SESSION_A
mock-api RmRegisterResources --session SESSION_A --file "C:\Example\report.docx"
  => file registered with the session
mock-api RmGetList --session SESSION_A
  => file owner: example-editor.exe, PID 4242
mock-api RmShutdown --session SESSION_A
  => shutdown requested for the registered resource's owner
```

The file is the starting point: the routine asks which application holds it and requests that application's shutdown. It does not need to know the editor's name beforehand. The final line represents a request, not confirmation that the process exited or the file became accessible.

Hunt & Hackett's samples leave sessions under `HKCU\SOFTWARE\Microsoft\RestartManager` because they omit `RmEndSession`. That volatile registry data includes the owning PID and process creation time and disappears at shutdown. K7 describes a session-ending branch, so the omission is sample-specific. RestartManager events 10000, 10002 and 10006 respectively record session creation, shutdown activity and shutdown failure.

#### 3. Directory traversal and exclusions

The early samples use Boost for asynchronous processing. During traversal, they omit selected system directories and file types, including executable and library extensions. The ransom note is also excluded. Eligible files proceed to encryption rather than every object encountered being rewritten.

K7 identifies `GetLogicalDriveStringsA` for drive discovery and `FindFirstFileW` / `FindNextFileW` for directory traversal. These are API calls, not shell commands. Their effects appear as file activity; ordinary process-creation logs do not provide an API trace.

**Illustrative mockup — discovering drives and walking a directory**

```text
mock-api GetLogicalDriveStringsA
  => drives: C:\, D:\
mock-api FindFirstFileW --pattern "D:\Example\*"
  => search: SEARCH_A; first entry: report.docx
mock-api FindNextFileW --search SEARCH_A
  => next entry: accounts.xlsx
mock-api FindNextFileW --search SEARCH_A
  => no more entries
```

The search handle keeps the enumeration state between calls. Receiving a filename does not mean it was encrypted: the program still applies its filtering and file-processing logic.

#### 4. Per-file cryptography

The early Windows implementation obtains random key material through `CryptGenRandom`. A ChaCha-family implementation, identified as ChaCha2008 in the original analysis, transforms file content. An embedded RSA-4096 public key protects the symmetric key material.

The file worker performs partial encryption. For files up to 2,000,000 bytes, it processes the first half; larger files have four regions encrypted. Consequently, a transformed file can retain readable areas while essential data is damaged.

#### 5. File completion

Protected key material is appended to the file tail. The executable adds `.akira` to the filename and creates `akira_readme.txt` in affected directories. The RSA public key varies between binaries; the early file layout belongs to that analyzed generation.

### 2. Linux C++ — June 2023 branch

#### 1. Native Linux implementation

This branch is a Linux x64 C++ executable. It retains Boost and the related file-processing design, while Crypto++ supplies cryptographic functionality implemented partly through Windows CryptoAPI in the Windows branch.

#### 2. File transformation and output

The examined Linux branch produces the related encrypted-file format and `.akira` output. This is a platform port of the early lineage; its native execution does not contain Windows registry or PowerShell routines.

### 3. Megazord — Windows Rust branch

#### 1. Build-ID validation

The Rust executable parses its startup arguments and checks a build identifier before proceeding in the protected samples. Cynet's dynamic analysis observed that the sample did not begin its normal operation without the expected identifier.

#### 2. Service and process termination

Once execution proceeds, the binary launches child processes to stop services. The observed targets include SQL services, Windows Defender's service and ShadowProtect. These are termination attempts: a protected service can reject the request.

The shutdown phase precedes file encryption in the observed run. Stopping databases releases active data files; stopping backup and security services interferes with recovery and protection.

Unit 42's Megazord appendix provides these literal examples:

```text
cmd.exe /c net stop SQLWriter
cmd.exe /c net stop ShadowProtectSvc
cmd.exe /c taskkill /f /im sql*
```

Each line is a separately documented command, not a script to run. The first two ask the Service Control Manager to stop a service; the third terminates matching processes. Stopping a service does not delete its registration. A corresponding execution tree can contain the encryptor, `cmd.exe`, and then `net.exe` or `taskkill.exe`; confirm the actual ancestry in process telemetry.

The same appendix contains PowerShell VM-stop activity. The combination of `Get-VM` and `Stop-VM` identifies that script's purpose, but this Windows behavior must not be assigned to the Linux/ESXi binary.

#### 3. Encryption and ransom artifacts

The binary processes eligible files and writes its ransom note. Unit 42 reports the suffix `.powerranges` and note `powerranges.txt`. Cynet renders these names with “powerrangers”; the spelling difference in the publications is retained here rather than treated as evidence of another cryptographic version.

#### 4. Changes in March 2024 samples

Later samples examined by Unit 42 expose additional controls over process/service termination and directory exclusions. Preparation is therefore configurable: a run can reach file encryption without performing the same shutdown operations as another build or invocation. Changes in contact text do not alter this execution distinction.

### 4. Akira_v2 — Linux / ESXi Rust branch

This function-level sequence follows SHA-256 `3298d203c2acb68c474e5fdad8379181890b4403d6491c523c13730129be3f75`.

#### 1. Main and argument parsing

The entry routine collects command-line arguments and constructs a `seahorse` parser. The parser dispatches to `default_action`, the application handler identified in the published reverse engineering.

#### 2. Policy and target collection

`default_action` applies the selected behavior and collects target files. Related v2 analysis documents a default target of `/vmfs/volumes`, VM-file selection, exclusions, background execution and an optional VM-stopping branch. These controls determine the workload before file workers process it.

#### 3. Worker dispatch

The routine identified as `lock` starts worker threads. Their `lock_closure` performs the file operation, separating workload dispatch from the cryptographic transform.

#### 4. Key preparation and encryption

The recovered worker generates per-file random material through Rust's `thread_rng`. Check Point identifies SOSEMANUK for content encryption and Curve25519-related key protection using the dalek implementation and embedded public material.

Talos describes v2 as using ChaCha20 and lists the same sample among its indicators. That is a disagreement between analyses; the SOSEMANUK description here follows the function-level examination of this specific hash.

#### 5. Output

The branch uses `.akiranew` and `akiranew.txt`. These artifacts accompany the Rust/ESXi execution path.

### 5. Renewed C++ builds — September 2024

#### 1. Platform-specific startup

The Windows build adds local-only targeting and exclusions; the Linux build retains background execution and adds exclusions. Those choices constrain file discovery before encryption.

#### 2. Revised cipher and familiar output

The analyzed builds use ChaCha8 and return to `.akira` and `akira_readme.txt`. The implementation language and cipher differ from the Rust branch even though the output names match earlier Akira samples.

## Linking Host Activity to the Executable

A command match identifies a behavior, not its author. Associate the command with the recovered binary's hash, process identity, start time, account and parent/child chain. For WMI-mediated execution, include the initiating WMI activity. PID alone is insufficient because it can be reused.

Direct API actions require different evidence: an EDR/API trace, the associated registry or file changes, or component-specific events. PowerShell content may be visible in script-block logging when enabled, including inline code that never existed as a .ps1 file. Process-creation telemetry records external commands when command-line capture is enabled.

The scheduled tasks and service creation described in K7's intrusion narrative belong to attacker activity before encryption. They are not demonstrated as routines of the analyzed encryptor. Likewise, a service-stop request establishes an attempt; service-state events establish whether it succeeded.
