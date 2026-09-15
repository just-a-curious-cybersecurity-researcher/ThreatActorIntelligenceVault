/* Defensive artifact triage. No execution, actor-identity or event-order claims.
   Notes and research archives are expected matches. All rules require tuning. */
rule QILIN_AGENDA_Redacted_Note_Triage
{
    meta:
        description = "Agenda/Qilin note content triage, not encryptor detection"
        confidence = "high for template resemblance; no operator attribution"
        false_positives = "Archived notes, threat reports, simulations, restored files"
    strings:
        $brand1 = "-- Qilin" ascii wide nocase
        $brand2 = "-- Agenda" ascii wide nocase
        $claim = "Your network/system was encrypted." ascii wide
        $field = "-- Credentials" ascii wide
    condition:
        filesize < 256KB and 1 of ($brand*) and $claim and $field
}

rule QILIN_SYSVOL_Chrome_Script_Artifact_Triage
{
    meta:
        description = "Script/document combining reported logon script and staging artifacts"
        observed = "July 2024 case"
        confidence = "generic artifact triage, not proof of GPO execution"
        false_positives = "IR scripts, report text, training and policy maintenance"
    strings:
        $script = "IPScanner.ps1" ascii wide nocase
        $launcher = "logon.bat" ascii wide nocase
        $share = "SYSVOL" ascii wide nocase
        $out = "temp.log" ascii wide nocase
    condition:
        filesize < 2MB and all of them
}

rule QILIN_Configuration_PE_Heuristic
{
    meta:
        description = "PE triage with Talos-reported configuration and restoration clues"
        observed = "2025 samples"
        confidence = "heuristic, sample corpus validation required"
        false_positives = "Other software with similar configs, packed research fixtures, copied code"
    strings:
        $cfg1 = "white_symlink_subdirs" ascii wide
        $cfg2 = "win_services_black_list" ascii wide
        $task = "TVInstallRestore" ascii wide
        $logs = "QLOG" ascii wide
    condition:
        filesize > 1KB and filesize < 30MB and uint16(0) == 0x5A4D
        and all of ($cfg*) and ($task or $logs)
}

rule QILIN_Restoration_Script_Artifact_Triage
{
    meta:
        description = "Text artifact combining restoration task and masqueraded TeamViewer launcher"
        confidence = "workflow resemblance only; not a malware family signature"
        false_positives = "Legitimate deployment documentation, threat reports and test scripts"
    strings:
        $task = "TVInstallRestore" ascii wide
        $restore = "/RESTORE" ascii wide nocase
        $brand = "TeamViewer_Host_Setup" ascii wide nocase
    condition:
        filesize < 2MB and all of them
}
