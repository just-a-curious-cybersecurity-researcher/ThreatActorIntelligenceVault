/*
    Presentation reviewed: 2026-09-15.
    Defensive file and artifact triage; review each rule's scope and conditions.
    Rule provenance remains in the actor bibliography and existing metadata.
*/

/*
    Akira Threat Hunting / Artifact Triage Rules

    IMPORTANT
    ---------
    These rules are defensive triage starting points, not universal malware signatures.
    Many strings below occur in legitimate administration, penetration testing, RMM,
    backup, incident-response and forensic tooling. Every rule must be reviewed and
    tuned for the organization where it is deployed.

    YARA scans file/memory content. It does NOT observe process execution, network
    events or user behavior in the way that EDR/KQL/Splunk does. Behavioral commands
    such as `net localgroup Administrators` are therefore represented here only as
    script/artifact strings. Use telemetry-based analytics for actual execution.
*/

rule AKIRA_Ransomware_Artifact_Cooccurrence_Triage
{
    meta:
        description = "Triage for multiple Akira-specific ransomware/leak-site artifacts"
        author = "ThreatActorIntelligenceVault"
        confidence = "artifact association only; no execution or operator attribution"
        false_positives = "Research documents, note archives, test fixtures and restored files"

    strings:
        $ext1 = ".akira" ascii wide
        $ext2 = ".powerranges" ascii wide
        $note = "akira_readme.txt" ascii wide nocase
        $onion1 = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad" ascii wide nocase
        $onion2 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id" ascii wide nocase

    condition:
        2 of them
}

rule CTI_Credential_Dumping_Artifact_Triage
{
    meta:
        description = "Credential dumping / credential-store access strings observed in ransomware tradecraft"
        author = "ThreatActorIntelligenceVault"
        false_positives = "DFIR tooling, pentest scripts, training material, admin scripts"

    strings:
        $mini1 = "comsvcs.dll" ascii wide nocase
        $mini2 = "MiniDump" ascii wide nocase
        $lsass = "lsass.dmp" ascii wide nocase
        $mimi1 = "sekurlsa::logonpasswords" ascii wide nocase
        $mimi2 = "lsadump::sam" ascii wide nocase
        $sam1 = "HKLM\\SAM" ascii wide nocase
        $sam2 = "HKLM\\SECURITY" ascii wide nocase
        $ntds = "ntds.dit" ascii wide nocase
        $browser1 = "key4.db" ascii wide nocase
        $browser2 = "Login Data" ascii wide
        $veeam = "Veeam-Get-Creds" ascii wide nocase

    condition:
        filesize < 20MB and 2 of them
}

rule CTI_Mimikatz_Like_PE_Triage
{
    meta:
        description = "Triage rule for PE files containing multiple Mimikatz-specific strings"
        author = "ThreatActorIntelligenceVault"
        false_positives = "Security products, samples, training binaries"

    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa::" ascii wide nocase
        $s3 = "lsadump::" ascii wide nocase
        $s4 = "privilege::debug" ascii wide nocase
        $s5 = "kerberos::" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and 2 of ($s*)
}

rule CTI_AD_Discovery_Script_Artifact_Triage
{
    meta:
        description = "AD/network discovery strings associated with Akira-reported tooling"
        author = "ThreatActorIntelligenceVault"
        false_positives = "Legitimate AD administration, red-team, inventory and audit scripts"

    strings:
        $sh1 = "SharpHound" ascii wide nocase
        $bh1 = "BloodHound" ascii wide nocase
        $adf = "AdFind" ascii wide nocase
        $ldap = "ldapdomaindump" ascii wide nocase
        $share = "Invoke-ShareFinder" ascii wide nocase
        $sharp = "SharpShares" ascii wide nocase
        $snaff = "Snaffler" ascii wide nocase
        $nl1 = "nltest /dclist" ascii wide nocase
        $nl2 = "nltest /DOMAIN_TRUSTS" ascii wide nocase
        $net1 = "net group \"Domain admins\"" ascii wide nocase
        $net2 = "net localgroup \"Administrators\"" ascii wide nocase

    condition:
        filesize < 30MB and 2 of them
}

rule CTI_RMM_References_Triage
{
    meta:
        description = "Triage for files/scripts containing references to multiple RMM products seen in ransomware intrusions"
        author = "ThreatActorIntelligenceVault"
        false_positives = "Legitimate IT support software, software inventories, deployment scripts"

    strings:
        $r1 = "AnyDesk" ascii wide nocase
        $r2 = "RustDesk" ascii wide nocase
        $r3 = "Radmin" ascii wide nocase
        $r4 = "TeamViewer" ascii wide nocase
        $r5 = "LogMeIn" ascii wide nocase
        $r6 = "ScreenConnect" ascii wide nocase
        $r7 = "MeshAgent" ascii wide nocase
        $r8 = "Level.io" ascii wide nocase

    condition:
        filesize < 40MB and 2 of ($r*)
}

rule CTI_Tunneling_C2_Artifact_Triage
{
    meta:
        description = "Tunneling/C2 utility references useful for artifact triage"
        author = "ThreatActorIntelligenceVault"
        false_positives = "Legitimate tunnels, developers, remote administration"

    strings:
        $n1 = "ngrok tcp" ascii wide nocase
        $n2 = "ngrok http" ascii wide nocase
        $c1 = "cloudflared tunnel" ascii wide nocase
        $c2 = "trycloudflare.com" ascii wide nocase
        $ssh1 = "ssh -R" ascii wide nocase
        $ssh2 = "ssh -L" ascii wide nocase
        $ssh3 = "ssh -D" ascii wide nocase
        $sysbc = "SystemBC" ascii wide nocase
        $cs = "Cobalt Strike" ascii wide nocase

    condition:
        filesize < 30MB and 2 of them
}

rule CTI_Defense_Impairment_Command_Artifact
{
    meta:
        description = "Scripts/artifacts containing defense impairment commands"
        author = "ThreatActorIntelligenceVault"
        false_positives = "IT troubleshooting, lab scripts, red-team exercises"

    strings:
        $mp1 = "Set-MpPreference" ascii wide nocase
        $mp2 = "DisableRealtimeMonitoring" ascii wide nocase
        $mp3 = "DisableBehaviorMonitoring" ascii wide nocase
        $fw1 = "netsh advfirewall" ascii wide nocase
        $fw2 = "state off" ascii wide nocase
        $boot1 = "bcdedit" ascii wide nocase
        $boot2 = "safeboot" ascii wide nocase
        $boot3 = "network" ascii wide nocase
        $tool1 = "PowerTool" ascii wide nocase
        $tool2 = "POORTRY" ascii wide nocase
        $tool3 = "STONESTOP" ascii wide nocase
        $tool4 = "KillAV" ascii wide nocase

    condition:
        filesize < 20MB and 2 of them
}

rule CTI_Exfiltration_Artifact_Triage
{
    meta:
        description = "Archive/exfiltration utility references observed in Akira-associated tradecraft"
        author = "ThreatActorIntelligenceVault"
        false_positives = "Backup jobs, admin scripts, user file-transfer utilities"

    strings:
        $r1 = "rclone copy" ascii wide nocase
        $r2 = "rclone sync" ascii wide nocase
        $w1 = "winscp.com" ascii wide nocase
        $f1 = "FileZilla" ascii wide nocase
        $p1 = "pscp.exe" ascii wide nocase
        $m1 = "mega.nz" ascii wide nocase
        $t1 = "temp.sh" ascii wide nocase
        $a1 = "WinRAR" ascii wide nocase
        $a2 = "7-Zip" ascii wide nocase

    condition:
        filesize < 30MB and 2 of them
}

rule CTI_Recovery_Inhibition_Artifact_Triage
{
    meta:
        description = "Shadow-copy and recovery-inhibition commands in scripts/artifacts"
        author = "ThreatActorIntelligenceVault"
        false_positives = "Backup/recovery administration, lab and IR scripts"

    strings:
        $v1 = "vssadmin delete shadows" ascii wide nocase
        $v2 = "wmic shadowcopy delete" ascii wide nocase
        $v3 = "Win32_Shadowcopy" ascii wide nocase
        $v4 = "Remove-WmiObject" ascii wide nocase
        $b1 = "recoveryenabled no" ascii wide nocase
        $b2 = "bootstatuspolicy ignoreallfailures" ascii wide nocase

    condition:
        filesize < 20MB and 1 of ($v*) or
        filesize < 20MB and 2 of ($b*)
}

rule CTI_PsExec_Ransomware_Deployment_Artifact_Triage
{
    meta:
        description = "PsExec/PSEXESVC references combined with ransomware-impact indicators"
        author = "ThreatActorIntelligenceVault"
        false_positives = "Legitimate remote administration; requires impact-related co-occurrence"

    strings:
        $p1 = "PSEXESVC" ascii wide nocase
        $p2 = "PsExec" ascii wide nocase
        $i1 = "vssadmin" ascii wide nocase
        $i2 = "delete shadows" ascii wide nocase
        $i3 = ".akira" ascii wide nocase
        $i4 = ".powerranges" ascii wide nocase
        $i5 = "akira.readme.txt" ascii wide nocase

    condition:
        filesize < 40MB and 1 of ($p*) and 1 of ($i*)
}

rule AKIRA_Multi_Family_Script_Triage
{
    meta:
        description = "Higher-context script/config triage based on multiple Akira-associated behavior families"
        author = "ThreatActorIntelligenceVault"
        confidence = "generic script triage; no event sequencing or Akira attribution"
        false_positives = "Red-team/IR automation or threat-research collections"

    strings:
        $cred1 = "comsvcs.dll" ascii wide nocase
        $cred2 = "sekurlsa::" ascii wide nocase
        $disc1 = "SharpHound" ascii wide nocase
        $disc2 = "nltest /DOMAIN_TRUSTS" ascii wide nocase
        $def1 = "DisableRealtimeMonitoring" ascii wide nocase
        $def2 = "safeboot" ascii wide nocase
        $ex1 = "rclone" ascii wide nocase
        $ex2 = "WinSCP" ascii wide nocase
        $rec1 = "delete shadows" ascii wide nocase
        $imp1 = "PSEXESVC" ascii wide nocase
        $imp2 = ".akira" ascii wide nocase

    condition:
        filesize < 30MB and 1 of ($cred*) and 1 of ($disc*) and
        (1 of ($def*) or 1 of ($rec*)) and (1 of ($ex*) or 1 of ($imp*))
}

rule AKIRA_SafeBoot_S3_Script_Artifact_Triage
{
    meta:
        description = "Text artifact containing SafeBoot service registration and S3 transfer clues"
        observed = "2026-08-04"
        confidence = "generic workflow triage; not a malware signature"
        false_positives = "Incident reports, administration scripts, lab fixtures"
    strings:
        $boot = "SafeBoot" ascii wide nocase
        $rmm = "AnyDesk" ascii wide nocase
        $s3 = "s3://" ascii wide nocase
        $tool = "s5cmd" ascii wide nocase
    condition:
        filesize < 5MB and all of them
}
