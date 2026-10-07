# Lynx — Contextualized File Artifacts

**Presentation reviewed:** 2026-10-07.

| File / Artifact | Hash Type | Hash | Context |
|---|---|---|---|
| `w.exe` | SHA256 | `07b36c1660deb223749a8ac151676d8924bc13aa59e6712a3c14a2df5237264a` | Lynx encryptor deployed to backup/file servers. |
| `netscan.exe` | SHA256 | `517288e12c05a92e483e6d80b9136c19bc58c46851720680bb6d1b7016034c37` | SoftPerfect NetScan 7.2.7; legitimate scanner used by the affiliate. |
| `nxc.exe` | SHA256 | `6285d32a9491a0084da85a384a11e15e203badf67b1deed54155f02b7338b108` | NetExec; dual-use credential/discovery tool. |
| `pushprinterconnections.exe` | SHA256 | `c3b57cd2c04ffd6dd173edfd975d2b05b7f6f502062a56b8585bda8776824a18` | Lynx encryptor masquerading as a Windows printing component in PacketWatch IR. |
| `1.exe` | SHA256 | `6e65483764d7c25523a5bbef5be99eb42349eef39d5517c46b3a4af262a80ceb` | Lynx Windows sample in a 2025 incident analysis. |

## Additional Named Artifacts Without Hashes in the Supplied Notes

- `README.txt`, `.LYNX`, `%TEMP%\background-image.jpg`.
- `netscan.xml`, `netscan.lic`, `ss.xml`, `delete.me`.
- `.nxc\workspaces\smb.db`, `.nxc\nxc.conf`, `nxc.txt`.
- `secpol.cfg`, desktop archives, ESXi `kill` and `delete` scripts.
- `C:\temp\PsExec.exe`, `PSEXESVC.exe`, `C:\temp\PSTools.zip`, `C:\temp\SessionGopher.ps1`.
- `Rclone.exe`, `rcl.bat`, `nocmd.vbs`, `domain_ips.txt` and `hosts.txt`.
- `%ProgramData%\AnyDesk\connection_trace.txt`, `%ProgramData%\AnyDesk\file_transfer_trace.txt` and `%ProgramData%\Splashtop\Temp\log\FTCLog.txt`.
- `folder.ico` and `pictures.ico` under `C:\ProgramData\Microsoft\Device Stage\Task\{07deb856-fc6e-4fb9-8add-d8f2cf8722c9}`.

## Source and Classification Review

NetScan, NetExec, 7-Zip, Edge and AnyDesk are legitimate or dual-use. Exact file identity and the surrounding account, path, command line and chronology determine relevance.

| Additional artifact | Incident role | Date / source |
|---|---|---|
| Lookalike domain accounts | Persistence and privilege expansion | March 2025 case, published 2025-12-17 |
| AnyDesk service | Alternate remote access installed but not later observed in use | March 2025 case |
| Veeam job-deletion audit | Manual recovery inhibition before encryption | March 2025 case |
| Browser `/upload` history | Evidence of archive transfer to `temp[.]sh` | March 2025 case |
| RMM transfer logs | Evidence of AnyDesk/Splashtop file movement | 2026 PacketWatch cases |
| GPO, scheduled task and `NETLOGON` payload | Domain-wide locker deployment | 2026 PacketWatch case |
| `.vmdk` encryption | ESXi impact after access to exposed hosts | 2026 PacketWatch cases |
