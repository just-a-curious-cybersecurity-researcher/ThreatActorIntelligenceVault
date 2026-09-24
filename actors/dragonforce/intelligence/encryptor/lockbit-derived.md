# DragonForce — LockBit-Derived Windows Encryptor

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope

This file covers the early Windows branch produced from the leaked LockBit 3.0/Black builder. Cyble’s BinDiff comparison reported 93.7% matched functions and approximately 99% similarity in branches/commands. That supports a builder derivative. It does not establish shared operators, and it should not be used to transfer LockBit wallets, infrastructure or sanctions.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Early DragonForce / LockBit Black derivative, 2023–2024 | 64-bit Windows PE; leaked LockBit 3.0 builder lineage | `-safe`, `-wall`, `-path`, `-gspd`, `-psex`, `-gdel` and `-del` options; `.locked` observed | Public analysis is sample-specific; other LockBit-builder rebrands can share most code |
| Microsoft detection set | Windows payloads detected as `Ransom:Win32/DragonForce!rfn` | `.dragonforce_encrypted` and `readme.txt` in Microsoft’s description | Detection name can cover a later or customized build and does not resolve code lineage alone |

## Executable Analysis

### 1. Argument parsing and execution mode

The executable parses LockBit-like switches before touching files. Trend Micro documented:

- `-safe` configures a Safe Mode reboot and then encrypts.
- `-wall` changes the wallpaper, prints the note and self-deletes after repeated renaming.
- `-path <file-or-directory>` restricts encryption to one target.
- `-gspd` modifies Group Policy to support lateral deployment.
- `-psex` uses administrative shares for remote deployment.
- `-gdel` removes Group Policy changes.
- `-del` self-deletes after renaming itself 26 times.

These switches expose two operating styles. An affiliate can execute one binary locally against all enumerated volumes, or use GPO/admin-share orchestration to reach multiple hosts. The presence of `-path` in process telemetry is especially useful because it binds the payload to a selected location.

### 2. Privileged and Safe Mode execution

The `-safe` path changes boot state so the payload can run with fewer active security and application services. An analyst should expect a boot-configuration change, a restart and subsequent payload execution under the reduced Safe Mode service set. The branch can also use token impersonation to operate under SYSTEM context.

Defensive event representation:

```text
[locker.exe -safe]
  -> boot configuration changed to Safe Mode
  -> host restart
  -> same payload or configured launch point executes after boot
  -> encryption begins while normal controls may be absent
```

The exact persistence mechanism used to survive the reboot is build/configuration dependent; a generic SafeBoot registry persistence should not be asserted without telemetry.

### 3. Recovery inhibition

The binary launches native Windows mechanisms to remove shadow copies, Windows Backup catalogs/system-state versions and recovery options. Public command rendering sometimes truncates the program name to `exe`; the behavior corresponds to `wmic`/`vssadmin`, `wbadmin` and `bcdedit` families.

Safe event mockups preserve what an analyst should find without treating placeholder paths as commands to run:

```text
[locker parent] -> [WMIC/VSS tool] shadowcopy delete
[locker parent] -> [BCD tool] /set {default} recoveryenabled No
[locker parent] -> [BCD tool] /set {default} bootstatuspolicy ignoreallfailures
[locker parent] -> [Windows Backup tool] delete catalog -quiet
[locker parent] -> [Windows Backup tool] delete systemstatebackup
```

Process creation, boot-configuration auditing, VSS operational logs and backup-service events can connect these actions to the parent payload.

### 4. Target discovery

The branch enumerates fixed, removable and network drives. Network impact therefore does not require a separate encryptor. When an affiliate also uses `-psex` or GPO, hosts may show both remote execution and share encryption.

The analyzed build avoids system directories such as Windows, Program Files, ProgramData, System Volume Information, boot areas, Tor Browser and debugger-related paths. It also excludes executable/system formats including `.exe`, `.dll`, `.sys`, `.msi`, `.cmd`, `.bat` and `.ps1`. The objective is operational: leave the OS functional enough to display the note and permit negotiation.

### 5. File encryption and naming

SentinelOne describes the early lineage as using AES for file content and RSA to protect key material. The implementation is inherited from the builder and should not be merged with the later branch’s documented ChaCha8/RSA-4096 footer. Trend Micro’s analyzed build appended `.locked` while Microsoft documents `.dragonforce_encrypted` for its DragonForce detection set.

The file loop can be represented as:

```text
for each eligible volume
  for each non-excluded file
    generate/use file-encryption state
    encrypt according to builder configuration
    preserve wrapped recovery material
    rename with configured suffix
    ensure ransom note is visible
```

### 6. User-visible impact and cleanup

The `-wall` option changes the desktop wallpaper and sends the ransom note to available printers. `-del` and the cleanup part of `-wall` repeatedly rename the binary before deletion. Repeated rename/delete activity for one executable after recovery commands and a file-encryption burst is more specific than the filename itself.

### 7. Sample identification

Cyble’s published SHA-256 for the compared branch is `1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b`. Exact-hash matching is high confidence for that artifact but cannot cover rebuilt payloads.

## Linking Host Activity to the Executable

Use the following sequence to attribute host events to this branch:

1. Process creation shows a non-shell PE with one or more documented switches.
2. The same parent starts recovery/boot utilities or precedes a Safe Mode restart.
3. GPO/admin-share activity appears only when the relevant switch was supplied.
4. File events show a dense burst on local/removable/network volumes, respecting system exclusions.
5. `.locked` or `.dragonforce_encrypted` files, note/wallpaper artifacts and printer activity appear during the same window.
6. The binary renames itself repeatedly and deletes itself.

Absence of child command processes does not exclude the family: builder settings can disable functions, and some operations may be performed through APIs. A binary that instead creates the documented mutex, decrypts a ChaCha8 configuration and appends a 534-byte footer belongs to the Conti-derived branch.
