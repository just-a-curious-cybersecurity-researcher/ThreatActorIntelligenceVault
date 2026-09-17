/*
    Presentation reviewed: 2026-09-17.
    Defensive file and artifact triage; review each rule's scope and conditions.
    Rule provenance remains in the actor bibliography and existing metadata.
*/

import "hash"

rule GENTLEMEN_Note_Text_Triage
{
    meta:
        description = "Text resembling a Gentlemen ransom note; not executable detection"
        author = "Repository-authored"
        date = "2026-09-16"
        confidence = "template resemblance only"
        false_positives = "Research documents, archived notes, simulations"
    strings:
        $brand = "Gentlemen, your" ascii wide nocase
        $impact = "has been encrypted" ascii wide nocase
        $contact = "TOX" ascii wide nocase
        $contact2 = "onion" ascii wide nocase
    condition:
        filesize < 256KB and $brand and $impact and 1 of ($contact*)
}

rule GENTLEMEN_Windows_Artifact_Bundle_Triage
{
    meta:
        description = "PE containing multiple reported locker artifact names"
        author = "Repository-authored"
        date = "2026-09-16"
        confidence = "heuristic; sample-corpus validation required"
        false_positives = "Tools or binaries embedding intelligence text"
    strings:
        $note = "README-GENTLEMEN.txt" ascii wide
        $task = "gentlemen_system" ascii wide
        $wallpaper = "gentlemen.bmp" ascii wide
    condition:
        filesize > 1KB and filesize < 50MB and uint16(0) == 0x5A4D
        and all of them
}

rule GENTLEMEN_Task_Command_Artifact_Triage
{
    meta:
        description = "Script or text containing locker task and launch-context clues"
        author = "Repository-authored"
        date = "2026-09-16"
        confidence = "text artifact only; does not prove execution"
        false_positives = "Threat reports and authorized simulations"
    strings:
        $task = "gentlemen_system" ascii wide nocase
        $scheduler = "schtasks" ascii wide nocase
        $context = "--system" ascii wide
        $context2 = "--full" ascii wide
    condition:
        filesize < 2MB and $task and $scheduler and 1 of ($context*)
}

rule GENTLEMEN_Encrypted_Output_Footer_Triage
{
    meta:
        description = "Published footer fields near EOF; encrypted-output triage, not executable attribution"
        author = "Repository-authored"
        date = "2026-09-17"
        confidence = "heuristic; corpus validation required"
        false_positives = "Reports or test files embedding the footer; inspect original file and trailer"
    strings:
        $eph = "--eph--" ascii
        $marker = "--marker--GENTLEMEN" ascii
        $pub = /[A-Za-z0-9+\/]{43}=/ ascii
    condition:
        filesize >= 64 and filesize < 100MB
        and for any i in (1..#eph) : (
            @eph[i] + 512 >= filesize
            and for any j in (1..#marker) : (
                @marker[j] > @eph[i] and @marker[j] + 256 >= filesize
                and for any k in (1..#pub) : (
                    @pub[k] >= @eph[i] + !eph[i] and @pub[k] + !pub[k] <= @marker[j]
                )
            )
        )
}

rule GENTLEMEN_Background_Worker_PE_Triage
{
    meta:
        description = "Windows worker artifact combination in a PE-like file"
        author = "Repository-authored"
        date = "2026-09-17"
        confidence = "heuristic; corpus validation required"
        false_positives = "Compiled research fixtures or security software embedding artifact strings"
    strings:
        $worker = "LOCKER_BACKGROUND" ascii wide
        $task = "gentlemen_system" ascii wide
        $note = "README-GENTLEMEN.txt" ascii wide
    condition:
        filesize > 1KB and filesize < 50MB and uint16(0) == 0x5A4D
        and all of them
}

rule GENTLEMEN_Propagation_Strings_PE_Triage
{
    meta:
        description = "Multiple published propagation names plus distribution context"
        author = "Repository-authored"
        date = "2026-09-17"
        confidence = "heuristic; corpus validation required"
        false_positives = "Research binaries; changed or obfuscated builds can evade matching"
    strings:
        $task1 = "UpdateGU2" ascii wide
        $task2 = "UpdateGS2" ascii wide
        $svc1 = "DefSvc" ascii wide
        $svc2 = "UpdateSvc2" ascii wide
        $share = "share$" ascii wide
        $context = "gentlemen_system" ascii wide
    condition:
        filesize > 1KB and filesize < 50MB and uint16(0) == 0x5A4D
        and 3 of ($task*, $svc*) and $share and $context
}

rule GENTLEMEN_Remote_Preparation_Script_Triage
{
    meta:
        description = "Text conjunction of remote preparation behaviors; not actor-specific"
        author = "Repository-authored"
        date = "2026-09-17"
        confidence = "heuristic; corpus validation required"
        false_positives = "Threat reports, configuration scripts and simulations; verify values and context"
    strings:
        $def = "Set-MpPreference" ascii wide nocase
        $firewall = "Set-NetFirewallProfile" ascii wide nocase
        $smb = "SMB1Protocol" ascii wide nocase
        $anon = "EveryoneIncludesAnonymous" ascii wide nocase
        $staging = "share$" ascii wide nocase
    condition:
        filesize < 2MB and all of them
}

rule GENTLEMEN_ESXi_Artifact_Bundle_Triage
{
    meta:
        description = "ELF artifact bundle from the dedicated ESXi analysis"
        author = "Repository-authored"
        date = "2026-09-17"
        confidence = "heuristic; corpus validation required"
        false_positives = "Research ELF files; not proof that every Linux variant shares these strings"
    strings:
        $hidden = "/bin/.vmware-authd" ascii
        $boot = "/etc/rc.local.d/local.sh" ascii
        $note = "README-GENTLEMEN.txt" ascii
        $vm = "vim-cmd" ascii
    condition:
        filesize > 1KB and filesize < 50MB and uint32(0) == 0x464C457F
        and all of them
}

rule GENTLEMEN_ESXi_Boot_Text_Triage
{
    meta:
        description = "Boot/cron text referencing the reported hidden payload path"
        author = "Repository-authored"
        date = "2026-09-17"
        confidence = "heuristic; corpus validation required"
        false_positives = "Archived incident evidence and analyst notes; validate actual installed path and scheduler"
    strings:
        $hidden = "/bin/.vmware-authd" ascii
        $boot = "/etc/rc.local.d/local.sh" ascii
        $cron = "@reboot" ascii
        $delay = "sleep " ascii
    condition:
        filesize < 1MB and $hidden and $delay and 1 of ($boot, $cron)
}

rule GENTLEMEN_Self_Delete_Batch_Triage
{
    meta:
        description = "Generic executable/self-deleting batch pattern seen in the supplied analysis"
        author = "Repository-authored"
        date = "2026-09-17"
        confidence = "heuristic; corpus validation required"
        false_positives = "Legitimate installer/uninstaller cleanup; generic behavior, not family identification"
    strings:
        $delay = "ping " ascii wide nocase
        $local1 = "127.0.0.1" ascii wide
        $local2 = "localhost" ascii wide nocase
        $delete = /del[ \t]+\/[fF][ \t]+\/[qQ]/ ascii wide
        $self1 = "%~f0" ascii wide
        $self2 = "%0" ascii wide
        $exe = ".exe" ascii wide nocase
    condition:
        filesize < 512KB and $delay and 1 of ($local*) and $delete
        and 1 of ($self*) and $exe
}

rule GENTLEMEN_Published_Locker_Hash_Match
{
    meta:
        description = "Exact published Windows/Linux locker identity; no generic tool hashes"
        author = "Repository-authored"
        date = "2026-09-17"
        confidence = "exact file identity only"
        false_positives = "Copies of the identified bytes; does not establish execution or actor presence"
    condition:
        filesize > 0 and filesize < 50MB and (
            hash.sha256(0, filesize) == "025fc0976c548fb5a880c83ea3eb21a5f23c5d53c4e51e862bb893c11adf712a"
            or
            hash.sha256(0, filesize) == "1eece1e1ba4b96e6c784729f0608ad2939cfb67bc4236dfababbe1d09268960c"
            or
            hash.sha256(0, filesize) == "22b38dad7da097ea03aa28d0614164cd25fafeb1383dbc15047e34c8050f6f67"
            or
            hash.sha256(0, filesize) == "2ed9494e9b7b68415b4eb151c922c82c0191294d0aa443dd2cb5133e6bfe3d5d"
            or
            hash.sha256(0, filesize) == "3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235"
            or
            hash.sha256(0, filesize) == "48d9b2ce4fcd6854a3164ce395d7140014e0b58b77680623f3e4ca22d3a6e7fd"
            or
            hash.sha256(0, filesize) == "5dc607c8990841139768884b1b43e1403496d5a458788a1937be139594f01dca"
            or
            hash.sha256(0, filesize) == "62c2c24937d67fdeb43f2c9690ab10e8bb90713af46945048db9a94a465ffcb8"
            or
            hash.sha256(0, filesize) == "788ba200f776a188c248d6c2029f00b5d34be45d4444f7cb89ffe838c39b8b19"
            or
            hash.sha256(0, filesize) == "860a6177b055a2f5aa61470d17ec3c69da24f1cdf0a782237055cba431158923"
            or
            hash.sha256(0, filesize) == "87d25d0e5880b3b5cd30106853cbfc6ef1ad38966b30d9bd5b99df46098e546c"
            or
            hash.sha256(0, filesize) == "8c87134c1b45e990e9568f0a3899b0076f94be16d3c40fa824ac1e6c6ee892db"
            or
            hash.sha256(0, filesize) == "91415e0b9fe4e7cbe43ec0558a7adf89423de30d22b00b985c2e4b97e75076b1"
            or
            hash.sha256(0, filesize) == "994d6d1edb57f945f4284cc0163ec998861c7496d85f6d45c08657c9727186e3"
            or
            hash.sha256(0, filesize) == "9f61ff4deb8afced8b1ecdc8787a134c63bde632b18293fbfc94a91749e3e454"
            or
            hash.sha256(0, filesize) == "a7a19cab7aab606f833fa8225bc94ec9570a6666660b02cc41a63fe39ea8b0ad"
            or
            hash.sha256(0, filesize) == "b67958afc982cafbe1c3f114b444d7f4c91a88a3e7a86f89ab8795ac2110d1e6"
            or
            hash.sha256(0, filesize) == "c46b5a18ab3fb5fd1c5c8288a41c75bf0170c10b5e829af89370a12c86dd10f8"
            or
            hash.sha256(0, filesize) == "c7f7b5a6e7d93221344e6368c7ab4abf93e162f7567e1a7bcb8786cb8a183a73"
            or
            hash.sha256(0, filesize) == "ec368ae0b4369b6ef0da244774995c819c63cffb7fd2132379963b9c1640ccd2"
            or
            hash.sha256(0, filesize) == "efaf8e7422ffd09c7f03f1a5b4e5c2cc32b05334c18d1ccb9673667f8f43108f"
            or
            hash.sha256(0, filesize) == "f736be55193c77af346dbe905e25f6a1dee3ec1aedca8989ad2088e4f6576b12"
            or
            hash.sha256(0, filesize) == "fc75ed2159e0c8274076e46a37671cfb8d677af9f586224da1713df89490a958"
            or hash.sha256(0, filesize) == "f918535f974591ef031bd0f30a8171e3da27a6754e6426a8ba095f83195661c8"
            or hash.md5(0, filesize) == "b9986a0f1f1f1a798dc3f0c59a80a1a3"
            or hash.sha1(0, filesize) == "c12c4d58541cc4f75ae19b65295a52c559570054"
        )
}
