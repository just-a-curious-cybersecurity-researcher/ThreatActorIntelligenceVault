/*
    Presentation reviewed: 2026-09-22.
    Repository-authored artifact hunts based on published INC research.
    Not vendor rules; not exclusive actor attribution.
    Source and sample provenance: ../References.md and ../iocs/hash-provenance.md.
    Scan research corpora separately: embedded notes/strings can match documentation.
*/

import "hash"

rule INC_Classic_Windows_Hunt
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-22"
        description = "Classic INC-like PE strings; related codebases may also match"
        source = "INC005, INC006, INC007; supplied dossier"
        confidence = "hunting"
    strings:
        $cli1 = "--lhd" ascii wide
        $cli2 = "--ens" ascii wide
        $cli3 = "--sup" ascii wide
        $pdb = "INC Encryptor.pdb" ascii wide
        $brand = "fn5+fiBJTkMgUmFuc29tIH5+fn4" ascii wide
    condition:
        filesize > 128 and filesize < 10MB
        and uint16(0) == 0x5a4d
        and uint32(0x3c) < filesize - 4
        and uint32(uint32(0x3c)) == 0x00004550
        and all of ($cli*)
        and ($pdb or $brand)
}

rule INC_Rust_Windows_Hunt
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-22"
        description = "INC-related Rust/cryptographic string conjunction in PE"
        source = "INC010; local conjunction, not the Acronis rule"
        confidence = "hunting"
    strings:
        $note = "INC-README.txt" ascii wide
        $rust = "curve25519-dalek" ascii
        $header = "EncryptionHeader" ascii
        $algo = "SALSA20" ascii
    condition:
        filesize > 128 and filesize < 30MB
        and uint16(0) == 0x5a4d
        and uint32(0x3c) < filesize - 4
        and uint32(uint32(0x3c)) == 0x00004550
        and all of them
}

rule INC_Rust_Linux_Hunt
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-22"
        description = "INC-related ELF note and virtualization-operation strings"
        source = "INC010; local conjunction, not the Acronis rule"
        confidence = "hunting"
    strings:
        $note = "INC-README.txt" ascii
        $brand = "fn5+fiBJTkMgUmFuc29tIH5+fn4" ascii
        $esxi1 = "while stopping ESXi machines" ascii
        $esxi2 = "while removing ESXi snapshots" ascii
    condition:
        filesize > 128 and filesize < 30MB
        and uint32(0) == 0x464c457f
        and $note and $brand and 1 of ($esxi*)
}

rule INC_Ransom_Note_Hunt
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-22"
        description = "Text artifact hunt; a note is not proof of encryption"
        source = "INC003, INC005; supplied note observations"
        confidence = "artifact"
    strings:
        $brand = "INC Ransom" ascii wide nocase
        $tor = ".onion" ascii wide
        $pay = "incpay" ascii wide
    condition:
        filesize < 128KB and all of them
}

rule INC_Published_Encryptor_SHA256
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-22"
        description = "Exact published encryptor artifacts; excludes auxiliary tools"
        source = "INC003, INC007, INC010, INC011"
        confidence = "exact artifact; no variant-wide coverage"
    condition:
        filesize > 0 and filesize < 50MB and
        (
            hash.sha256(0, filesize) == "accd8bc0d0c2675c15c169688b882ded17e78aed0d914793098337afc57c289c" or
            hash.sha256(0, filesize) == "e17c601551dfded76ab99a233957c5c4acf0229b46cd7fc2175ead7fe1e3d261" or
            hash.sha256(0, filesize) == "e034a4c00f168134900bfe235ff2f78daf8bfcfa8b594cd2dd563d43f5de1b13" or
            hash.sha256(0, filesize) == "31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502" or
            hash.sha256(0, filesize) == "ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22" or
            hash.sha256(0, filesize) == "8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4" or
            hash.sha256(0, filesize) == "bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc" or
            hash.sha256(0, filesize) == "6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f" or
            hash.sha256(0, filesize) == "1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449" or
            hash.sha256(0, filesize) == "24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7" or
            hash.sha256(0, filesize) == "dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da" or
            hash.sha256(0, filesize) == "acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4" or
            hash.sha256(0, filesize) == "90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c" or
            hash.sha256(0, filesize) == "ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b" or
            hash.sha256(0, filesize) == "97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2" or
            hash.sha256(0, filesize) == "1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11" or
            hash.sha256(0, filesize) == "f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347" or
            hash.sha256(0, filesize) == "d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb" or
            hash.sha256(0, filesize) == "765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a" or
            hash.sha256(0, filesize) == "d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570" or
            hash.sha256(0, filesize) == "589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880" or
            hash.sha256(0, filesize) == "7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245" or
            hash.sha256(0, filesize) == "5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241" or
            hash.sha256(0, filesize) == "60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6" or
            hash.sha256(0, filesize) == "6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141"
        )
}
