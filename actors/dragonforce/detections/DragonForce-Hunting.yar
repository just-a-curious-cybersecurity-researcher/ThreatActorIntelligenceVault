/*
    Presentation reviewed: 2026-09-24.
    Repository-authored artifact hunts based on published DragonForce research.
    Not vendor rules; not exclusive actor attribution.
    Source and sample provenance: ../References.md and ../iocs/hash-provenance.md.
    Scan research corpora separately: embedded notes/strings can match documentation.
*/

import "hash"

rule DRAGONFORCE_Published_Encryptors_SHA256
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "Exact published DragonForce Windows encryptors"
        source = "DF018, DF019, DF020, DF021, DF022"
        confidence = "exact artifact; no variant-wide coverage"
    condition:
        filesize > 0 and filesize < 50MB and
        (
            hash.sha256(0, filesize) == "1250ba6f25fd60077f698a2617c15f89d58c1867339bfd9ee8ab19ce9943304b" or
            hash.sha256(0, filesize) == "451a42db9c514514ab71218033967554507b59a60ee1fc3d88cbeb39eec99f20" or
            hash.sha256(0, filesize) == "410db536a57c511b0ccac2639e0eb3320f303fc5c90242379ab43364c51ef321" or
            hash.sha256(0, filesize) == "c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d" or
            hash.sha256(0, filesize) == "e45b18c93d187aac5c4486f57483bc87580e15def82a312bfb377ff16eb96b22" or
            hash.sha256(0, filesize) == "df903c620508011ca8eb2aaaf9712a526b31a12c800b856cd524ebb3fde854b2" or
            hash.sha256(0, filesize) == "55befb5de5d9bc45978efd1a960ae21ed81e4be9c6521aaeebf8d5884444e3c9" or
            hash.sha256(0, filesize) == "572d88c419c6ae75aeb784ceab327d040cb589903d6285bbffa77338111af14b"
        )
}

rule DRAGONFORCE_BackdoorTurn_Campaign_SHA256
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "Exact Symantec Backdoor.Turn campaign files, drivers and utilities"
        source = "DF021"
        confidence = "exact incident artifact; not service-wide"
    condition:
        filesize > 0 and filesize < 100MB and
        (
            hash.sha256(0, filesize) == "82b37a92589dfd4d67ca87eb9e52ac8e682e8e60d2211f59074cd5ccc693013b" or
            hash.sha256(0, filesize) == "821da79d727351dd67ce5df7950e9a3de6647a3cf474bb3a093f67507fed92a6" or
            hash.sha256(0, filesize) == "048e18416177de2ead251abdf4d89837f6807c6aba4d5b1debe49adfdecbf05c" or
            hash.sha256(0, filesize) == "ce66b8221446c9b6d83f0ce6382f430e519601641e5daaaf1ca7a8a8806cb0b0" or
            hash.sha256(0, filesize) == "f174c19902523dcf005fa044b6598403a5e5c0a5982398d1bc0dcc5ec1cd351b" or
            hash.sha256(0, filesize) == "d20a3c928761fe00ac522eeb474612b5804cd9108453ea8591106d5d4428428e" or
            hash.sha256(0, filesize) == "142bac0e2148e0d47891b6cd7311195c4acbe33b700fad54a201c52a2bc46219" or
            hash.sha256(0, filesize) == "8395b621bb4415090f232c59fc41d24ea41a519b58eabe512f3ae7d2fdf049a3" or
            hash.sha256(0, filesize) == "d0da2832ae1e13a98f7ce7e33a66c1b0d9797b81f69ece134e4462ea55ac923e" or
            hash.sha256(0, filesize) == "aea26980059ef2ad11e99556a4edfa1f8ec769fa9f06aa573b81bedf319954b5" or
            hash.sha256(0, filesize) == "9335f61f8ad276d94455c5b6876fea48152c3cea759f2598c8108ee461fa5759" or
            hash.sha256(0, filesize) == "cd078957167e1af4de39aecdb981cd14156fa81d5a9c6ac51e74ae5b6199a12a" or
            hash.sha256(0, filesize) == "b6628d201c2a68d2a3de2a87de7a5acfe21b101a97928e1c8d5c82102d967383" or
            hash.sha256(0, filesize) == "b16e217cdca19e00c1b68bdfb28ead53b20adeabd6edcd91542f9fbf48942877" or
            hash.sha256(0, filesize) == "8284c8676cc22c4b2e66826ac16986da7ddecba1f2776b16771be17bfdc45dc2" or
            hash.sha256(0, filesize) == "65ab49119c845801f29a57e8aa177146b2ffbd289d4278109b146f933380f951" or
            hash.sha256(0, filesize) == "252a8bb2eb9c96c5e6cc7cab822e2ed0d508032f9350351221781684e86c03ab" or
            hash.sha256(0, filesize) == "8a4033425d36cd99fe23e6faef9764fbf555f362ebdb5b72379342fbbe4c5531" or
            hash.sha256(0, filesize) == "087f002df0a02c8c74f3ba5cd99cf29fb9efff38bf57b3d808e34a5dd4200dd2" or
            hash.sha256(0, filesize) == "6bbf10bcbef7ac5102b54c81137859891a3802dbacd888be90f990d50e18b0b4" or
            hash.sha256(0, filesize) == "6f9fbe29f8cc2788e2bc9d631e0eea2a8e9837076837b55838005a0e654f0a9e"
        )
}

rule DRAGONFORCE_Conti_Derived_Windows_Hunt
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "Conti-derived DragonForce configuration and artifact conjunction"
        source = "DF018"
        confidence = "hunting; related code can match"
    strings:
        $mutex = "hsfjuukjzloqu28oajh727190" ascii wide
        $base32 = "gwfn6l3bk45o2zecvi7xtyqrpsudmahj" ascii wide
        $log = "C:\\Users\\Public\\log.log" ascii wide
        $wall = "wallpaper_white.png" ascii wide
        $ext = ".dragonforce_encrypted" ascii wide
    condition:
        filesize > 128 and filesize < 50MB
        and uint16(0) == 0x5a4d
        and uint32(0x3c) < filesize - 4
        and uint32(uint32(0x3c)) == 0x00004550
        and $mutex and $base32 and 2 of ($log,$wall,$ext)
}

rule DRAGONFORCE_LockBit_Derived_CLI_Hunt
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "LockBit-derived DragonForce runtime switch conjunction"
        source = "DF017, DF019"
        confidence = "hunting; leaked-builder derivatives can match"
    strings:
        $safe = "-safe" ascii wide
        $wall = "-wall" ascii wide
        $gspd = "-gspd" ascii wide
        $psex = "-psex" ascii wide
        $gdel = "-gdel" ascii wide
        $del = "-del" ascii wide
    condition:
        filesize > 128 and filesize < 30MB
        and uint16(0) == 0x5a4d
        and uint32(0x3c) < filesize - 4
        and uint32(uint32(0x3c)) == 0x00004550
        and 5 of them
}

rule DRAGONFORCE_Linux_ESXi_Hunt
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "DragonForce ELF VMware operation and configuration strings"
        source = "DF017"
        confidence = "hunting"
    strings:
        $path = "/vmfs/volumes" ascii
        $enum = "vim-cmd vmsvc/getallvms" ascii
        $off = "vim-cmd vmsvc/power.off" ascii
        $log = "encryption.log" ascii
        $ext = ".dragonforce_encrypted" ascii
    condition:
        filesize > 128 and filesize < 50MB
        and uint32(0) == 0x464c457f
        and $path and all of ($enum,$off) and 1 of ($log,$ext)
}

rule DRAGONFORCE_Ransom_Note_Hunt
{
    meta:
        author = "ThreatActorIntelligenceVault"
        date = "2026-09-24"
        description = "DragonForce archived note infrastructure and brand conjunction"
        source = "DF001, DF002"
        confidence = "artifact"
    strings:
        $brand = "DragonForce Ransomware Cartel" ascii wide nocase
        $chat = "3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd.onion" ascii wide
        $tox = "1C054B722BCBF41A918EF3C485712742088F5C3E81B2FDD91ADEA6BA55F4A856D90A65E99D20" ascii wide
    condition:
        filesize > 32 and filesize < 256KB and 2 of them
}
