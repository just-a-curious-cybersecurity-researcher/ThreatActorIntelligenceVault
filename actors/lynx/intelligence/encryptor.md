# Lynx — Ransomware Executable Internals

**Presentation reviewed:** 2026-10-07.

**Research reviewed:** 2026-10-07. This is a synthesis of published reverse engineering and panel observations, not a local disassembly.

## Scope

The analysis follows the code path from argument parsing through environment preparation, file access, key generation, asynchronous encryption and final artifacts. Optional branches are labelled because the presence of a command-line capability does not prove use in every intrusion.

**Mockup convention:** blocks labelled “Illustrative mockup” describe recovered API flow with invented handles and paths. They are not runnable commands or recovered source code. Published operator commands are labelled separately.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Early Windows Lynx, July 2024 onward | Windows x64, C++ | `.LYNX`, partial encryption, wallpaper and printer output | Directly analyzed samples and public hashes |
| Configurable Windows builds | Windows, C++ | fast/medium/slow/entire modes; network, hidden-drive and silent options | Panel/build evolution; flags vary by build |
| Linux / ESXi bundle, documented 2025 | ELF builds for x86/x64, ARM, MIPS, PPC64LE, RISC-V, s390x and ESXi | simpler CLI, 2× CPU worker count, optional delay/fork/MOTD, VM stop and snapshot deletion | Affiliate archive availability plus 2026 IR observation of encrypted ESXi `.vmdk` files; no public ELF hash in the reviewed reporting |
| INC-derived lineage | Windows and Linux/ESXi | extensive function-level overlap | Code provenance; not an automatic organizational identity |

## Executable Analysis

### 1. Windows C++ branch

#### 1. Argument parsing and execution policy

Startup maps command-line options into global behavior. `--file` and `--dir` constrain scope. `--mode fast|medium|slow|entire` selects approximately 5%, 15%, 25% or 100% processing. Medium is the documented default in later analysis. Other flags control process shutdown, network-share enumeration, hidden-volume mounting, wallpaper, printing, console visibility and safe-mode behavior.

The payload does not need every option. In the 2025 case, the operator selected one volume, fast mode, verbose output and no printing. This explains why incident telemetry may show only a subset of published features.

#### 2. Process and service interruption

With the kill behavior enabled, the binary calls `CreateToolhelp32Snapshot`, walks processes using `Process32FirstW`/`Process32NextW`, performs case-insensitive substring matching and opens matching processes with `PROCESS_TERMINATE`. The list contains SQL, Veeam, backup, Exchange, Java and Notepad strings.

It opens the Service Control Manager, enumerates services, recursively stops dependents and sends a stop control when service or display names contain SQL, Veeam, backup or Exchange. The routine queries status with `QueryServiceStatusEx`, waits and retries until the service stops or its timeout expires, then closes the handles it opened. These are direct API operations, so absence of `taskkill.exe` or `net.exe` does not exclude the behavior.

**Illustrative mockup — process and service shutdown**

```text
mock-api CreateToolhelp32Snapshot --processes all
  => process-set P1
mock-api Process32NextW --set P1
  => "example-backup-agent.exe", PID 4242
mock-api OpenProcess --pid 4242 --rights PROCESS_TERMINATE
mock-api TerminateProcess --handle PROCESS_4242

mock-api OpenSCManagerW --rights enumerate,connect
mock-api EnumServicesStatusExW
  => "ExampleBackupService"
mock-api ControlService --service ExampleBackupService --control STOP
```

#### 3. Worker pool and ransom-note preparation

The embedded note is Base64-decoded and `%id%` is replaced with a victim identifier. The program obtains processor information and prepares an I/O Completion Port. Published analysis describes four worker threads per logical processor for Windows, with asynchronous file operations coordinated through completion packets.

#### 4. Traversal, scope and exclusions

The program recursively enumerates directories with `FindFirstFileW` and `FindNextFileW`, skipping `.`/`..`, reparse points, system files and its own artifacts. It excludes `.exe`, `.msi`, `.dll` and `.lynx`, plus `README.txt` and an internal `LYNX` name. Windows, Program Files, Program Files (x86), `$RECYCLE.BIN` and AppData are generally skipped; Microsoft SQL Server content under Program Files receives special handling so database data can still be reached.

When `--encrypt-network` is active, `WNetOpenEnumW` and `WNetEnumResourceW` recursively enumerate network resources and shares. When `--load-drives` is active, `FindFirstVolumeW`/`FindNextVolumeW` identify volumes and `SetVolumeMountPointW` assigns unused drive letters. Group-IB warns that this branch can damage bootability.

#### 5. Write-access test and ownership branch

Before encryption, Lynx appends 36 bytes containing the character `2`, verifies the write count, returns the pointer and truncates the probe. If the test fails and process stopping is enabled, the binary first invokes Restart Manager against the locked file and retries access. Only a continuing failure reaches the privilege branch: it opens the current process token, resolves and enables `SeTakeOwnershipPrivilege`, builds a full-control ACL, changes owner and DACL with `SetNamedSecurityInfoW`, then disables the privilege.

**Illustrative mockup — file access preparation**

```text
mock-api WriteProbe --file "D:\Example\ledger.dat" --bytes 36
  => ACCESS_DENIED
mock-api AdjustTokenPrivileges --enable SeTakeOwnershipPrivilege
mock-api SetNamedSecurityInfoW --file "D:\Example\ledger.dat" --owner CURRENT_GROUP
mock-api SetNamedSecurityInfoW --file "D:\Example\ledger.dat" --dacl FULL_CONTROL
mock-api AdjustTokenPrivileges --disable SeTakeOwnershipPrivilege
```

This does not create a SYSTEM process or bypass domain controls; it uses a privilege already present in the process token.

#### 6. Unlocking an open file

If `--stop-processes` is enabled, the payload starts a Restart Manager session, registers the file, retrieves processes holding it and terminates eligible owners. It avoids Explorer, critical processes, itself and processes it cannot open. It waits for termination before retrying access.

```text
RmStartSession → RmRegisterResources → RmGetList → OpenProcess → TerminateProcess → WaitForSingleObject
```

#### 7. Per-file key generation

The sample decodes an embedded Curve25519 public key and creates an ephemeral key pair for the file. X25519/Curve25519 produces a shared secret, which is hashed with SHA-512. The resulting material feeds AES key expansion for AES-128 CTR processing. The private key needed for recovery is outside the victim file; panel operators reportedly handle test decryptions because private keys are not stored in the affiliate panel.

#### 8. Marker and partial-encryption layout

The binary appends a 116-byte trailer:

```text
32 bytes  ephemeral Curve25519 public key
64 bytes  SHA-512 of that public key
4 bytes   ASCII "LYNX"
4 bytes   zero / unresolved field
4 bytes   0x000F4240 = 1,000,000-byte encryption block
4 bytes   5 = step / skipped-block parameter
4 bytes   1 = documented skipped-block count field
```

The analyzed default path encrypts 1,000,000 bytes from offset zero, advances to about 6,000,000 and repeats, leaving roughly 5 MB between encrypted regions. Boundary logic subtracts the 116-byte marker from a final read so the trailer is not encrypted.

AES-CTR generates a keystream that is XORed with file bytes; the nonce advances for each block. I/O Completion Port state transitions schedule read, transform, write and completion. On success the file is renamed with `.LYNX`.

#### 9. Recovery inhibition

For drive letters A through Z, the program checks fixed, removable and remote volumes, opens the root and calls `DeviceIoControl` with `IOCTL_VOLSNAP_SET_MAX_DIFF_AREA_SIZE` (`0x53C028`). It supplies a one-byte maximum differential area. This can eliminate practical access to shadow copies without launching `vssadmin.exe` or PowerShell.

#### 10. User-facing impact

The executable writes `README.txt` in traversed directories. Unless disabled, it creates `%TEMP%\background-image.jpg` and sets it as wallpaper. It enumerates printers, excludes Microsoft Print to PDF and Microsoft XPS Document Writer, and sends the note using `StartDocPrinterW`, `StartPagePrinter` and `WritePrinter`.

#### 11. Additional 2025 incident sample

A separate incident-response analysis published a Windows sample named `1.exe` with SHA-256 `6e65483764d7c25523a5bbef5be99eb42349eef39d5517c46b3a4af262a80ceb`. The case observed `.lynx` output, near-maximum entropy, ransom notes under Desktop, ProgramData and PerfLogs, and the wallpaper value `HKCU\Control Panel\Desktop\Wallpaper` pointing to `background-image.jpg`. It also recovered `folder.ico` and `pictures.ico` below `C:\ProgramData\Microsoft\Device Stage\Task\{07deb856-fc6e-4fb9-8add-d8f2cf8722c9}`.

The process tree included `FXSSVC.exe`, `ONENOTE.EXE`, `OfficeC2RClient.exe` and `onenoteim.exe`, including an XPS insertion command. The reporting does not establish that this Office activity is a universal Lynx component, a delivery exploit or command-and-control. It is retained as case telemetry for correlation, not added to the core execution sequence.

### 2. Linux and ESXi branch

#### 1. Platform bundle and startup

The affiliate archive includes `linux-arm64`, `linux-armv5-musl`, `linux-armv7`, `linux-esxi`, `linux-ppc64le`, `linux-x64`, `linux-arm64-musl`, `linux-armv6`, `linux-armv7a`, `linux-mips`, `linux-riscv64`, `linux-x86`, `linux-armv5`, `linux-armv6-musl`, `linux-armv7l-musl`, `linux-mipsel-lts`, `linux-s390x` and `windows`. The musl-linked builds improve portability on minimal or embedded environments.

Linux requires `--file` or `--dir`; optional `--delay`, `--fork`, `--motd` and `--esxi` branches adjust execution. It uses approximately twice the CPU-core count for workers and retains the same AES/Curve25519 scheme and percentage modes.

#### 2. File processing and output

The Linux executable traverses the selected target, filters files, processes the configured fraction and drops notes in directories. `--silent` is Windows-only in the documented table. `--motd` places the ransom message in the system message of the day.

#### 3. ESXi VM and snapshot handling

With the ESXi option, the program writes and executes a `kill` script that obtains World IDs and force-stops VMs:

```text
for i in $(esxcli vm process list | grep 'World' | grep -Eo '[0-9]{1,8}'); do esxcli vm process kill -t=force -w=$i; done
```

It also writes and executes `delete` to enumerate VM IDs and remove snapshots:

```text
for i in $(vim-cmd vmsvc/getallvms | awk '{print $1}' | grep -Eo '[0-9]{1,8}'); do vim-cmd vmsvc/snapshot.removeall $i; done
```

These are destructive published artifacts reproduced for defensive matching. The presence of `esxcli` or `vim-cmd` alone is normal on ESXi; the loop, output filename and timing near mass file changes provide context.

PacketWatch subsequently reported Lynx incidents in which `.vmdk` files on ESXi hosts were encrypted after access to older, unpatched hosts with exposed SSH. That closes the earlier evidence gap between availability of the ESXi build and real-world virtual-disk impact, while still leaving the exact ELF sample hash and invocation unavailable publicly.

### 3. Lineage and version interpretation

Rapid7 measured about 48% overall and 70.8% function similarity in an early Windows comparison and considered that insufficient to prove source derivation alone. Unit 42 documented substantial Windows similarity. Group-IB later compared Linux/ESXi builds and found 147 non-library matches, more than 91% overlapping functions, 87% overall similarity and 98% comparison confidence. These results are compatible because they compare different samples, platforms and dates.

The defensible conclusion is that Lynx uses INC-derived code. The stronger claim that every Lynx operator is a renamed INC member remains unproven.

## Linking Host Activity to the Executable

- A command containing `--mode fast` and `--noprint` shows that the operator selected partial encryption and suppressed printer output; it does not prove that other optional branches ran.
- Direct service-control API calls followed by application termination are consistent with the built-in kill routine. API/EDR telemetry is required because no child command is necessary.
- File owner and DACL changes by the payload are consistent with the write-access recovery branch; distinguish them from administrator remediation.
- Device control `0x53C028` to volume handles is a strong built-in shadow-copy inhibition signal when the sensor captures device I/O.
- Repeated 1 MB modifications separated by about 5 MB and followed by the 116-byte `LYNX` trailer match the analyzed medium/default layout; other modes change the ratio.
- `.LYNX`, `README.txt`, wallpaper and printer jobs are impact artifacts. An extension or generic note alone is insufficient attribution.
