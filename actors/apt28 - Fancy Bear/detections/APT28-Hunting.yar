/*
    Presentation reviewed: 2026-09-15.
    Defensive file and artifact triage; review each rule's scope and conditions.
    Rule provenance remains in the actor bibliography and existing metadata.
*/

import "hash"

/*
Published by the FBI / NSA / CISA and international partners, 2025-05-21.
Retrieved: 2026-09-14. PDF line wraps normalized; identifiers and logic preserved.
Hunting rules: a match does not establish actor attribution.
*/
rule APT28_HEADLACE_SHORTCUT
{
    meta:
        description = "Detects the HEADLACE backdoor shortcut dropper. Rule is meant for threat hunting."
    strings:
        $type = "[InternetShortcut]" ascii nocase
        $url = "file://"
        $edge = "msedge.exe"
        $icon = "IconFile"
    condition:
        all of them
}
rule APT28_HEADLACE_CREDENTIALDIALOG
{
    meta:
        description = "Detects scripts used by APT28 to lure user into entering credentials"
    strings:
        $command_1 = "while($true)"
        $command_2 = "Get-Credential $(whoami)"
        $command_3 = "Add-Content"
        $command_4 = ".UserName"
        $command_5 = ".GetNetworkCredential().Password"
        $command_6 = "GetNetworkCredential().Password.Length -ne 0"
    condition:
        5 of them
}
rule APT28_HEADLACE_CORE
{
    meta:
        description = "Detects HEADLACE core batch scripts"
    strings:
        $chcp = "chcp 65001" ascii
        $headless = "start \"\" msedge --headless=new --disable-gpu" ascii
        $command_1 = "taskkill /im msedge.exe /f" ascii
        $command_2 = "whoami>\"%programdata%" ascii
        $command_3 = "timeout" ascii
        $command_4 = "copy \"%programdata%\\" ascii
        $non_generic_del_1 = "del /q /f \"%programdata%" ascii
        $non_generic_del_3 = "del /q /f \"%userprofile%\\Downloads\\" ascii
        $generic_del = "del /q /f" ascii
    condition:
        ($chcp and $headless) and
        (1 of ($non_generic_del_*) or ($generic_del) or 3 of ($command_*))
}
rule APT28_MASEPIE
{
    meta:
        description = "Detects MASEPIE python script"
    strings:
        $masepie_unique_1 = "os.popen('whoami').read()"
        $masepie_unique_2 = "elif message == 'check'"
        $masepie_unique_3 = "elif message == 'send_file':"
        $masepie_unique_4 = "elif message == 'get_file'"
        $masepie_unique_5 = "enc_mes('ok'"
        $masepie_unique_6 = "Bad command!'.encode('ascii'"
        $masepie_unique_7 = "{user}{SEPARATOR}{k}"
        $masepie_unique_8 = "raise Exception(\"Reconnect"
    condition:
        3 of ($masepie_unique_*)
}

/* Locally authored defensive heuristics, reviewed 2026-09-15.
Scan extracted/decompressed script or configuration content, including UTF-16LE.
A match indicates a string bundle for triage, not execution or APT28 attribution.
Generic service names, filenames and script APIs can appear in legitimate tools.
Bibliographic provenance and local-rule scope are recorded in References.md.
*/

rule APT28_GooseEgg_Artifact_Bundle_Triage : apt28 local heuristic
{
    meta:
        description = "Local heuristic for co-located GooseEgg artifact strings; not a binary-family signature"
        author = "ThreatActorIntelligenceVault"
        created = "2026-09-15"
        scope = "extracted file content; heuristic; not actor attribution"
    strings:
        $a = "{026CC6D7-34B2-33D5-B551-CA31EB6CE345}" ascii wide nocase
        $b = "wayzgoose" ascii wide nocase
        $c = "MPDW-constraints.js" ascii wide nocase
        $d = "servtask.bat" ascii wide nocase
    condition:
        filesize < 10MB and ($a and 2 of ($b, $c, $d))
}

rule APT28_Outlook_Macro_Configuration_Triage : apt28 local heuristic
{
    meta:
        description = "Local heuristic for scripts staging Outlook macros and changing startup/security settings"
        author = "ThreatActorIntelligenceVault"
        created = "2026-09-15"
        scope = "extracted file content; heuristic; not actor attribution"
    strings:
        $a = "VbaProject.OTM" ascii wide nocase
        $b = "LoadMacroProviderOnBoot" ascii wide nocase
        $c = "PONT_STRING" ascii wide nocase
        $d = "\\Outlook\\Security" ascii wide nocase
    condition:
        filesize < 10MB and ($a and $b and 1 of ($c, $d))
}

rule APT28_Browser_Secret_Script_Triage : apt28 local heuristic
{
    meta:
        description = "Local STEELHOOK-related script heuristic; also matches credential auditing tools"
        author = "ThreatActorIntelligenceVault"
        created = "2026-09-15"
        scope = "extracted file content; heuristic; not actor attribution"
    strings:
        $a1 = "Login Data" ascii wide nocase
        $a2 = "Local State" ascii wide nocase
        $b1 = "ProtectedData" ascii wide nocase
        $b2 = "Unprotect" ascii wide nocase
        $c1 = "Invoke-RestMethod" ascii wide nocase
        $c2 = "Invoke-WebRequest" ascii wide nocase
    condition:
        filesize < 10MB and (all of ($a*) and 1 of ($b*) and 1 of ($c*))
}

rule APT28_Headless_Webhook_Script_Triage : apt28 local heuristic
{
    meta:
        description = "Local HEADLACE/HOOKEDGE-related service-abuse heuristic; approved automation can match"
        author = "ThreatActorIntelligenceVault"
        created = "2026-09-15"
        scope = "extracted file content; heuristic; not actor attribution"
    strings:
        $a = "msedge" ascii wide nocase
        $b = "--headless" ascii wide nocase
        $c = "webhook.site" ascii wide nocase
        $d1 = "cmd.exe" ascii wide nocase
        $d2 = "%programdata%" ascii wide nocase
        $d3 = "%userprofile%" ascii wide nocase
    condition:
        filesize < 10MB and ($a and $b and $c and 1 of ($d*))
}

rule APT28_Neusploit_Staging_Strings_Triage : apt28 local heuristic
{
    meta:
        description = "Local heuristic for co-located Neusploit staging names; no exploit or family identification"
        author = "ThreatActorIntelligenceVault"
        created = "2026-09-15"
        scope = "extracted file content; heuristic; not actor attribution"
    strings:
        $a = "EhStoreShell.dll" ascii wide nocase
        $b = "office.xml" ascii wide nocase
        $c = "SplashScreen.png" ascii wide nocase
        $d = "testtemp.ini" ascii wide nocase
    condition:
        filesize < 10MB and ($a and 2 of ($b, $c, $d))
}

rule APT28_Retained_SHA256_Exact_Match : apt28 local hash
{
    meta:
        description = "Exact file match against 14 retained malicious SHA-256 values; historical corpus"
        author = "ThreatActorIntelligenceVault"
        created = "2026-09-15"
        scope = "whole files smaller than 100 MB; requires hash module; excludes legitimate OneDrive"
    condition:
        filesize > 0 and filesize < 100MB and (
        hash.sha256(0, filesize) == "0bb0d54033767f081cae775e3cf9ede7ae6bea75f35fbfb748ccba9325e28e5e" or
        hash.sha256(0, filesize) == "1ed863a32372160b3a25549aad25d48d5352d9b4f58d4339408c4eea69807f50" or
        hash.sha256(0, filesize) == "2822c72a59b58c00fc088aa551cdeeb92ca10fd23e23745610ff207f53118db9" or
        hash.sha256(0, filesize) == "3f446d316efe2514efd70c975d0c87e12357db9fca54a25834d60b28192c6a69" or
        hash.sha256(0, filesize) == "5a88a15a1d764e635462f78a0cd958b17e6d22c716740febc114a408eef66705" or
        hash.sha256(0, filesize) == "6b311c0a977d21e772ac4e99762234da852bbf84293386fbe78622a96c0b052f" or
        hash.sha256(0, filesize) == "7d51e5cc51c43da5deae5fbc2dce9b85c0656c465bb25ab6bd063a503c1806a9" or
        hash.sha256(0, filesize) == "8f4bca3c62268fff0458322d111a511e0bcfba255d5ab78c45973bd293379901" or
        hash.sha256(0, filesize) == "9f4672c1374034ac4556264f0d4bf96ee242c0b5a9edaa4715b5e61fe8d55cc8" or
        hash.sha256(0, filesize) == "a876f648991711e44a8dcf888a271880c6c930e5138f284cd6ca6128eca56ba1" or
        hash.sha256(0, filesize) == "a944a09783023a2c6c62d3601cbd5392a03d808a6a51728e07a3270861c2a8ee" or
        hash.sha256(0, filesize) == "b2ba51b4491da8604ff9410d6e004971e3cd9a321390d0258e294ac42010b546" or
        hash.sha256(0, filesize) == "bb23545380fde9f48ad070f88fe0afd695da5fcae8c5274814858c5a681d8c4e" or
        hash.sha256(0, filesize) == "c60ead92cd376b689d1b4450f2578b36ea0bf64f3963cfa5546279fa4424c2a5"
        )
}
