# SafePay — Early Windows Encryptor

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope

This file covers the Windows branch observed by Huntress in October 2024 and the related build analyzed by NCC. The two reports expose compatible command-line and encryption behavior, but they do not publish enough sample identity to prove every detail belongs to one identical binary.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Huntress incident-1 DLL | PE32 DLL, `locker.dll`, SHA-256 `a0dc80a…ff526` | `regsvr32.exe` launch, victim password, network path, UAC and encryption-level arguments; early CIS-language guard | Exact hash is high confidence; behavior is sample/case scoped |
| NCC `1.exe` build | Windows executable, SHA-1 `07353237…f62b` | `-enc=1` intermittent ChaCha20, X25519 and 65-byte footer | SHA-1 identifies the reported sample; SHA-256 was not published by NCC |

## Executable Analysis

### 1. Argument gate and configuration access

The program expects `-pass=[victim value]`. The value protects embedded actor key/configuration material and also appears as the victim’s portal identifier. Without the correct value the ransomware cannot follow its ordinary configured path. Additional switches select a local or UNC target, mapped drives, network enumeration, self-deletion, logging, UAC handling and encryption percentage.

```text
[locker] -pass=[victim-key] -path=\\[host]\[share] -enc=1
[loader] /n "/i:-pass=[victim-key] -enc=[level] -network -selfdelete" [locker.dll]
```

These are redacted event mockups derived from published syntax.

### 2. Language execution guard

The early build calls the Windows default-language interface and exits for Russian, Ukrainian, Belarusian, Azerbaijani in Cyrillic, Armenian, Georgian and Kazakh settings. This guard reduces operator risk; it does not prove nationality. A later DCSO build omitted it.

### 3. UAC and privilege preparation

The program enables `SeDebugPrivilege` using token and privilege APIs. Huntress found behavior consistent with CMSTPLUA auto-elevation: `DllHost.exe` can appear with the CMSTPLUA process CLSID and then launch an elevated child. Thread hiding and native APIs reduce visibility to simplistic user-mode monitoring.

The privilege sequence is visible as `ZwOpenProcessToken` → `LookupPrivilegeValueA` → `PrivilegeCheck` → `AdjustTokenPrivileges`. The program then calls `DuplicateToken`, stores the impersonation token and creates the network-enumeration thread suspended. `ZwSetThreadInformation` applies the token, `ThreadHideFromDebugger` hides the thread from ordinary debugger tracing, and `NtResumeThread` starts it. This is locker-internal behavior; seeing only one API in isolation is not enough for attribution.

### 4. Single-run and process control

The family uses a global mutex to avoid duplicate execution. DCSO extracted the following default from its later revised build; the value is included as a family pivot and is **not established for the Huntress/NCC early samples**:

```text
Global\DB1D-19B4-5094-D570-9841-E4BC-8ABD-29AA-03BB-84AD-C61B-1355-4FF2-194B-96BD-7E49
```

The early samples terminate configured database, productivity, browser, email and synchronization processes so open files can be modified. Huntress recovered the following case-insensitive stems from the analyzed build:

```text
sql oracle ocssd dbsnmp synctime agntsvc isqlplussvc xfssvccon
mydesktopservice ocautoupds encsvc firefox tbirdconfig mydesktopqos
ocomm dbeng50 sqbcoreservice excel infopath msaccess mspub far
onenote outlook powerpnt steam thebat thunderbird visio winword
wordpad notepad wuauclt onedrive sqlmangr
```

The binary enumerates processes and invokes the native termination path reported as `ZwTerminateProcess` after acquiring sufficient rights. The list mixes processes that lock business data with backup, synchronization and user applications; its immediate purpose is to release files and reduce interference during encryption.

### 5. Service interruption and recovery removal

The service list includes VSS, SQL-related services, Exchange, Sophos, Veeam, generic backup services and Commvault-style `Gx*` services:

```text
vss sql svc$ memtas mepocs msexchange sophos veeam backup
GxVss GxBlr GxFWD GxCVD GxCIMgr
```

The binary opens the Service Control Manager, resolves each configured service and sends `SERVICE_CONTROL_STOP` through `ControlService`; implementations can stop dependent services first. The program or its deployment chain also invokes `vssadmin`, `wmic shadowcopy` and `bcdedit` to remove shadow copies and suppress automatic recovery.

### 6. Target enumeration and exclusions

Local paths, mapped network drives and UNC shares can be selected separately. The published configuration protects the operating system and the encryptor’s own artifacts by ignoring executable/system formats, Windows and Program Files paths, ProgramData, browser/system directories, the ransom note and already encrypted files.

NCC labels its long extension list as targeted files, while the DCSO configuration extractor identifies the matching list as ignored extensions. The extracted configuration and system-survival logic support the latter interpretation.

### 7. Worker model

The locker uses a worker pool and asynchronous file handling similar to LockBit Black. Huntress observed token impersonation and a suspended worker for network-drive parsing. Files are opened, sections are selected according to `-enc`, encrypted and queued through completion handling rather than processed serially.

Local recursion uses Win32 file-enumeration APIs, while mapped and reachable network resources are fed into the same work queue. Completion-port workers allow discovery, read, encryption and write operations to overlap. This explains why endpoint telemetry can show simultaneous access to many paths and why a partial-encryption level can produce rapid environment-wide impact.

### 8. Key creation and ChaCha20

NCC’s sample generates a fresh private value for every file with `CryptGenRandom`, derives a corresponding X25519 public key, and combines the private value with the embedded actor public key to obtain shared secret material. The resulting key protects the file with ChaCha20.

In the documented `-enc=1` mode, the locker handles 10 MiB regions and encrypts 1 MiB from each region. The remainder stays plaintext, accelerating impact while leaving the file unusable.

### 9. Footer and rename

NCC’s encrypted output appends an unencrypted 65-byte structure:

```text
32 bytes  per-file public key
32 bytes  validation/KDF hash
 1 byte   encryption level
```

The original filename is retained and `.safepay` is appended. Recovery tooling must first identify the footer generation; applying this 65-byte layout to a revised 80-byte file would parse the wrong offsets.

### 10. Note and cleanup

The program drops `readme_safepay.txt` across reachable locations. Optional `-selfdelete` removes the running artifact after work completes. The note supplies the victim ID and Tor chat addresses but no reusable public payment wallet.

## Linking Host Activity to the Executable

- `regsvr32.exe` plus `/i:` containing `-pass`, `-enc` and `-path` is a high-value chain.
- The CMSTPLUA `DllHost.exe` parent, privilege adjustment and locker execution strengthen the link.
- Process/service interruption followed by VSS/BCD children and rapid `.safepay` renames is consistent with locker-native behavior.
- A 65-byte appended tail containing two 32-byte fields and one mode byte identifies the NCC generation; preserve samples before restoration.
- The language exit can create false-negative dynamic-analysis results on lab hosts configured with excluded locales.
