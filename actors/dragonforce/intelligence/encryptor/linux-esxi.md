# DragonForce — Linux and ESXi Encryptor

**Presentation reviewed:** 2026-09-24.
**Last updated:** 2026-09-24  
**TLP:** CLEAR

## Scope

This file covers the ELF branch first publicly analyzed in November 2024 and victim-specific ESXi recovery research. The binary is designed to stop virtual machines and encrypt datastore content. It should be separated from the affiliate’s method for obtaining ESXi credentials or management access.

## Variant Register

| Branch / period | Platform and implementation | Distinguishing behavior | Identification boundary |
|---|---|---|---|
| Trend Micro Linux/ESXi build, 2024 | ELF executable with embedded text configuration | `/vmfs/volumes` target, `vim-cmd` VM control, delay/thread/log flags, `.dragonforce_encrypted` | Several flags were present but unused in the analyzed build |
| RNP ESXi victim build | ELF/victim-specific recovery format | `.RNP_esxi`, victim build key and 512-byte recovery-data handling | Recovery observations belong to that build and do not define the earlier suffix |
| Panel-generated NAS/RHEL build, observed 2026 | Linux ELF sharing the panel cryptographic core | Daemon/log/delay/system-information flow, filename encoding and MOTD change | S2W confirmed functional parity at a high level; unique sample hashes and paths were not published |

## Executable Analysis

### 1. Argument parsing

Trend Micro documented the following switches:

- `-paths` sets a value with no confirmed active purpose in the analyzed build.
- `-vmsvc` sets a value, possibly reserved for a later feature.
- `-e` ignores other configuration.
- `-n` sets the dry-run count; `-d` detaches.
- `-h`, `-m` and `-s` set delay in hours, minutes or seconds.
- `-j` sets worker-thread count; `-l` selects the log path.
- `-p` specifies an encryption path.
- `-q` selects quiet mode; `-v` enables verbose/trace logging.
- `-wvi` and `-wvn` whitelist a VM by ID or name.

The default extracted configuration used a 20-second delay, four threads, no detachment and `encryption.log`. An operator can override the path, log and timing at execution.

### 2. VM inventory and shutdown

The program invokes VMware’s native management utility twice:

```text
[ELF locker] -> vim-cmd vmsvc/getallvms
for each non-whitelisted VM ID
  [ELF locker] -> vim-cmd vmsvc/power.off <VM-ID>
```

VMs can be excluded by numeric ID or displayed name. Shutting them down releases locks on virtual disks and configuration files. Defenders should correlate shell/process telemetry with vCenter/host task events, because command execution alone does not prove each VM reached the powered-off state.

### 3. Configuration and target selection

The analyzed configuration selected `/vmfs/volumes`, which contains ESXi datastores. It enabled renaming and configured `.dragonforce_encrypted`. It excluded boot banks and operational paths such as `BOOTBANK1`, `BOOTBANK2`, `log` and `devices`.

VMware/system file exclusions included `.b00`, `.v00` through `.v07`, `.t00`, `.sf` and filenames such as `boot.cfg`, `state.tgz`, `onetime.tgz`, `imgdb.tgz`, `useropts.gz` and `features.gz`. The exclusions preserve enough host functionality for the encryption process and note to remain accessible.

### 4. Delayed and threaded execution

After applying the requested delay, the binary builds a queue under the configured root and assigns eligible files to worker threads. Four threads were configured in the published sample. The operator can change this with `-j`, so thread count is not a stable IOC.

The dry-run and verbose modes can produce discovery/log activity without encryption. An `encryption.log` file containing target decisions can therefore be valuable even when the impact phase was interrupted.

### 5. Encryption and rename

The published configuration contains encryption parameters `16 52428800 0` and two embedded key-like values. The report does not provide enough implementation detail to assign each numeric field a universal algorithmic meaning. The defensible behavior is that eligible datastore files are processed according to embedded configuration, renamed and marked with the selected suffix.

For the RNP ESXi build, recovery analysis identifies `.RNP_esxi`, a victim-specific build key and recovery metadata read from the end of the file. The decryptor checks the last eight bytes against that build key and then reads a 512-byte protected metadata region. The key is represented as 16 hexadecimal characters and is unique to the encrypted system. These values should not be substituted for the Windows branch’s 534/537-byte layouts.

### 6. Note and host impact

The stopped VMs remain unavailable while virtual disks and adjacent files are encrypted. The note and extension depend on the affiliate build. CISA and Microsoft document DragonForce use against VMware ESXi in Scattered Spider-linked activity, but their reporting does not imply that every ESXi build uses one suffix or note name.

S2W’s 2026 panel analysis adds a broader Linux flow: the generated binary can daemonize with `-d`, perform configured logging and delay, collect host information, encrypt, encode filenames and modify the MOTD. The ESXi output additionally collects ESXi environment/user information and stops VMs; NAS and RHEL outputs omit those virtualization steps.

### 7. Recovery implications

Recovery requires clean control of the hypervisor, verified backups and the victim-specific key where decryption is attempted. Restoring only a VM configuration file while its disk remains encrypted does not recover the workload. Continuing access through stolen vCenter/ESXi credentials or an RMM channel must be removed before restoring datastores.

S2W obtained three ESXi decryptors whose functions were identical apart from filenames and victim-specific build material. During traversal the decryptor removes `readme.txt`, restores the original filename after decryption and uses the embedded RSA private key to recover ChaCha8 session data. This confirms per-victim recovery packaging rather than a universal decryptor.

## Linking Host Activity to the Executable

High-confidence branch evidence combines:

1. A non-standard ELF appears on an ESXi host.
2. The same process ancestry launches `vim-cmd vmsvc/getallvms` followed by repeated `power.off` actions.
3. `encryption.log` or an operator-selected log records the configured path.
4. File operations fan out beneath `/vmfs/volumes` while boot/system exclusions remain untouched.
5. `.dragonforce_encrypted` or `.RNP_esxi` appears on datastore files.
6. A DragonForce note or exact sample hash confirms branding.

VM shutdown commands alone are normal administrative behavior. The detection value comes from unusual initiating binary, non-maintenance timing, concurrent datastore writes and extension/note creation.
