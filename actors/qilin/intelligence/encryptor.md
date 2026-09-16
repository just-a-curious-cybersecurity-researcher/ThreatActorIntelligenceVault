# Qilin — Ransomware Executable Internals

**Presentation reviewed:** 2026-09-16.

**Research reviewed:** 2026-09-16. This is a synthesis of published binary analyses, not a local disassembly. The bibliography records the publications supporting each variant.

## Scope

The sections below follow the executable's routines: initialization, preparation, file selection, encryption and output. Optional branches are identified where they occur. Numbering organizes the functional flow; concurrent workers do not necessarily finish in that order.

**Mockup convention:** blocks labelled “Illustrative mockup” use a fictional `mock-api` command to explain inputs, actions and results. They are not executable commands, native API signatures, recovered source code or recorded telemetry. Paths, handles, PIDs and output values in these blocks are invented examples. Published command lines remain separately labelled.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Agenda Go, August 2022 | Windows x64, Go | Embedded configuration and optional reboot workflow | Original analyzed branch |
| Agenda Rust, December 2022 | Windows, Rust | Intermittent encryption and changed startup interface | Early Rust samples |
| Qilin Windows, July 2024 | Windows | Password hash validation and token handling | Group-IB's reported sample behavior |
| Qilin.B, October 2024 | Windows, Rust | Hardware-dependent cipher selection | Halcyon's analyzed variant |
| Windows case builds, 2025 | Windows with hypervisor deployment logic | Distributed execution or central-share encryption | Talos's compared samples |
| Linux / ESXi, October 2025 comparison | Separate hypervisor executable | Platform checks and configurable file processing | Includes newer Nutanix recognition |
| Windows, August 2026 analysis | Rust | Extensive selectable modes and per-thread logs | Report date, not a new version number |

## Executable Analysis

### 1. Agenda Go — original Windows branch

#### 1. Embedded configuration

The Go executable carries a victim-specific configuration containing an identifier, ransom text, RSA public key, accounts and process/service and file-filtering lists. These values determine its target selection and output naming.

#### 2. Startup and reboot branches

It inspects the boot state and includes an optional Safe Mode workflow. That workflow prepares a copy named `enc.exe` under the Public profile and a RunOnce entry named `*aster`. It can modify automatic-logon settings and reboot, with subsequent restoration of normal boot configuration.

The initial boot-state check and the optional reboot path are separate conditions in the published analysis, not an unconditional reboot at every start.

The registry artifact is an entry under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, with the value name `*aster`. A registry write can establish this behavior without a `reg.exe` process. The executable copy and registry writer must be correlated; the path by itself does not identify the process that created it.

#### 3. Account and share access

The executable can impersonate accounts supplied in its configuration. It also changes mapped-drive visibility and restarts LanmanWorkstation, making network resources available within its execution context.

The published implementation calls `LogonUserW` with the configured account and `CreateProcessAsUserW` to launch under that account. The latter can produce a new process event; the former is an API operation associated with authentication. The mapped-drive setting is `EnableLinkedConnections`. These details connect account, process and registry evidence without assuming that a shell performed each action.

**Illustrative mockup — authenticating an account and using its context**

```text
mock-api LogonUserW --account "EXAMPLE\sample-user" --credentials "[OMITTED]"
  => authentication succeeded; token: TOKEN_A
mock-api CreateProcessAsUserW --token TOKEN_A --image "C:\Example\sample.exe"
  => process: PID 4242; account: EXAMPLE\sample-user
```

The first operation obtains an authenticated security context; the second uses it for process creation. This example assumes successful calls and omits API prerequisites. It does not imply that any supplied credentials work or that the resulting account is SYSTEM.

#### 4. File encryption and completion

The file routine generates random key and IV material, encrypts content with AES-256 and protects the symmetric key with RSA-2048. It appends the configured company identifier and writes `{company_id}-RECOVER-README.txt`.

#### 5. Companion DLL

The analyzed package also drops `pwndll.dll`, a C component, and injects it into `svchost.exe`. This companion execution is separate from the Go file-encryption routine.

### 2. Agenda Rust — December 2022 branch

#### 1. Startup interface and configuration

The early Rust branch exposes password, IP-target and path inputs, reducing the argument surface of the Go version. Embedded settings supply the extension and encryption policy. The reported extension `MmXReVIxLV` is a sample value.

The password behavior differs from later Qilin: Trend Micro's test accepted a supplied value that also appeared in the support-login context. That test does not establish the hash-validated gate found in later builds.

#### 2. Process and service handling

The executable stops selected processes and services before file processing. The examined list includes AppInfo, the Windows service involved in elevated application launches. Stopping it disrupts that functionality; it is not an elevation routine.

#### 3. Intermittent encryption

The worker supports processing an initial region or alternating encrypted and skipped regions. This reduces the amount of file content rewritten while leaving selected portions unusable. The configuration controls the pattern rather than requiring complete encryption of every file.

#### 4. Output and execution reporting

During processing, the binary reports files and elapsed time. It renames affected files and writes notes in their directories. This branch changes both the implementation and the partial-encryption controls relative to Go.

### 3. Qilin Windows — July 2024 sample behavior

#### 1. Password comparison

The executable hashes the supplied password with SHA-256 and compares it with the value embedded in its configuration. Optional settings select additional execution branches after this gate.

#### 2. Security-context change

Group-IB describes an embedded Mimikatz component that acquires a token from a privileged process and starts another process under that security context. This reported token-handling path belongs to the examined Qilin implementation; it is distinct from merely launching an encryptor with an already privileged account.

#### 3. Filesystem preparation and log clearing

The reported code changes symbolic-link handling for remote resources. It clears Windows event logs before encryption and includes a separate thread that repeatedly clears logs after other work. These routines affect access and trace retention alongside the file-encryption workload.

### 4. Qilin.B — October 2024 Windows branch

#### 1. Initialization and environment checks

The binary checks its execution password, administrative context, virtualization and AES-NI availability. It loads configuration and creates a mutex for instance control. An autorun entry supports execution at a later logon.

#### 2. Preparation and discovery

It changes execution priority, stops configured processes and services, deletes shadow copies and clears event logs. Drive and network-resource enumeration covers local volumes, shares and network shortcuts.

#### 3. Hardware-dependent cryptography

With AES-NI available, the analyzed variant selects AES-256-CTR; otherwise it uses ChaCha20. RSA-4096 with OAEP protects the symmetric key material. Hardware inspection therefore affects the encryption routine used on a particular host.

#### 4. Finalization

The binary appends its company identifier, creates `README-RECOVER-[company_id].txt` and supports self-deletion.

#### 5. Additional Windows routine detail

AhnLab's separate examination describes service matching by name, followed by stop and disable operations. Process monitoring continues during encryption, allowing newly encountered matching processes to be terminated.

Its published matching list includes `veeamtransportsvc`, `backupexecjobengine`, `acronisagent` and `vmms`. Process targets include `sql`, `outlook` and `winword`. These are configuration/matching values, not evidence that every named application was present or successfully terminated.

TXOne's separately analyzed Qilin sample exposes the service-control API path:

```text
OpenSCManager → OpenService → QueryServiceStatusEx
ChangeServiceConfig → EnumDependentServices → ControlService
```

The routine opens the service database and target service, checks its state, changes configuration, examines dependencies and requests a stop for a running service. This can occur without `sc.exe` or `net.exe`. Service state and startup-type changes are the resulting host evidence; an API trace identifies the calling process. The sequence documents TXOne's sample and does not establish identical internals for every Qilin.B build.

**Illustrative mockup — changing a service and requesting its stop**

```text
mock-api OpenSCManager --computer local
  => manager: SCM_A
mock-api OpenService --manager SCM_A --name "ExampleService"
  => service: SERVICE_A
mock-api QueryServiceStatusEx --service SERVICE_A
  => state: RUNNING
mock-api ChangeServiceConfig --service SERVICE_A --startup DISABLED
  => startup configuration changed
mock-api EnumDependentServices --service SERVICE_A
  => no dependent services in this example
mock-api ControlService --service SERVICE_A --control STOP
  => stop request accepted; state: STOP_PENDING
```

Changing startup configuration affects subsequent starts; it does not stop a currently running service. The stop request is a separate operation, and STOP_PENDING is not STOPPED. This is conceptually comparable to service-management commands, but the actual implementation calls APIs inside the process. “ExampleService” is a fictional target, not a Qilin indicator.

AhnLab also identifies `CreateMutexW` during initialization. A mutex is a named synchronization object, not a scheduled task or command-line action.

**Illustrative mockup — creating or finding a named mutex**

```text
mock-api CreateMutexW --name "EXAMPLE_MUTEX"
  => handle: MUTEX_A; already existed: no

mock-api CreateMutexW --name "EXAMPLE_MUTEX"
  => handle: MUTEX_B; already existed: yes
```

The second call illustrates another caller finding the existing named object. Program logic can use that outcome to avoid duplicate execution; the API itself does not terminate either process. The mutex name above is invented and must not be used as an IOC.

Its analyzed sample also creates an asterisk-prefixed autorun value. Self-deletion can leave that value pointing to a missing executable, so registry registration does not guarantee a working restart. These observations describe AhnLab's sample rather than an additional named Qilin.B release.

### 5. Windows case builds — 2025

#### 1. Configuration-driven target selection

The compared payloads contain victim accounts and filtering settings for directories, extensions, processes and services. A symbolic-link allowance for ClusterStorage affects traversal into clustered storage.

#### 2. Two execution paths

One sample distributes execution to other systems through PsExec. Another performs encryption of remote shares from a central host. In the latter path, file writes cross the network without requiring an encryptor process on every file server.

#### 3. Hypervisor deployment branch

The analyzed code also includes PowerShell orchestration for vCenter. This branch prepares deployment to the virtualization environment; the Windows executable and the hypervisor payload remain separate components.

#### 4. Recovery impairment and output

The payload changes VSS service state and requests snapshot deletion. Diagnostic output goes to `%TEMP%\QLOG\ThreadId(N).LOG`. It also writes a temporary JPEG and changes the user's wallpaper through the registry, adding a desktop artifact to file renaming and ransom-note creation.

Published command examples for recovery impairment include:

```text
wmic service where name='vss' call ChangeStartMode Manual
vssadmin.exe delete shadows /all /quiet
net stop vss
```

These are separate destructive command examples from AhnLab's analysis, shown for log matching rather than as a complete execution script. They change VSS startup configuration, request snapshot deletion and stop VSS, respectively. Talos also reports a `cmd /C` wrapper in its case builds. Neither stopping VSS nor deleting snapshots is the same as deleting the service registration.

For event-log clearing, the published inline PowerShell contains `Get-WinEvent -ListLog *` and invokes `[System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($l)`. Those fragments distinguish enumeration and .NET-based clearing from a `wevtutil.exe` launch. The script is passed to PowerShell; the report does not require a corresponding script file on disk.

The wallpaper write targets `HKCU\Control Panel\Desktop\Wallpaper`. QLOG paths, wallpaper changes and the surrounding encryption activity provide additional correlation beyond a generic VSS command.

#### 5. Scheduled task recorded in the incident

Talos records `schtasks` creating a task named `TVInstallRestore`, with `/SC ONLOGON` and `/RU SYSTEM`. Its action references a ransomware executable disguised as a TeamViewer installer and the argument `/RESTORE`. These task fields are useful recognition artifacts.

The report attributes this persistence to the attacker after ransomware execution. It does not establish that the encryptor itself issued the task-creation request. The task creator and the task's configured execution account are different facts; SYSTEM in the task definition does not prove self-elevation by the binary.

### 6. Linux / ESXi — October 2025 comparison

#### 1. Startup and platform selection

The Linux executable checks its execution password and reads runtime settings. The compared code recognizes Linux, VMkernel and FreeBSD; newer logic adds Nutanix AHV recognition. Platform detection selects environment-dependent behavior rather than turning the program into a Windows payload.

#### 2. Target and processing configuration

Path and process filters, execution timing and encryption controls shape the workload. The program supports explicit paths and unattended operation. These are conditional modes within the binary.

#### 3. Diagnostic handling

The newer comparison includes expanded logging and error/fallback handling. Verbose output exposes the selected configuration and processing state. The platform checks and diagnostics are the documented differences; the Windows registry and VSS routines do not belong to this native branch.

### 7. Windows Rust — August 2026 sample analysis

#### 1. Configuration and dispatch

The binary loads `company_id`, accounts, note text, password hash and exclusion lists. Password validation and mutex creation precede normal processing. Separate dispatch paths handle Windows spreading, vCenter deployment or encryption; the spreading modes can leave the local machine unencrypted.

#### 2. File enumeration and transformation

It discovers drives and enumerates files with `FindFirstFileW` and `FindNextFileW`. The examined encryption path generates random AES keys, protects them with an RSA public key and places the protected material at the file end.

#### 3. Optional completion routines

Settings control renaming, note creation, wallpaper changes, autostart and self-deletion. Further modes cover free-space wiping and printing the extortion message. Per-thread diagnostic files are stored under QLOG.

These options extend the execution surface documented in the 2026 analysis; the publication date does not establish a separately numbered ransomware release.

## Linking Host Activity to the Executable

A command match identifies a behavior, not its author. Associate the command with the recovered binary's hash, process identity, start time, account and parent/child chain. PID alone is insufficient because it can be reused. A deployment process can launch the encryptor while separate operator tooling issues similar commands.

Direct API actions require an EDR/API trace or correlated service, registry and file evidence; they do not necessarily create another process. Inline PowerShell can be captured by script-block logging when enabled without leaving a .ps1 file. A script string embedded in a binary establishes capability; execution telemetry establishes that it ran.

For scheduled tasks, correlate registration events and the stored task definition with the creating process. For services, distinguish installation, configuration changes, stop requests and successful stops. This keeps a generic service-management command from being attributed to Qilin solely because encryption happened nearby.
