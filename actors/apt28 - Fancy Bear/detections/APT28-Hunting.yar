/*
Published by the FBI / NSA / CISA and international partners, 2025-05-21.
Source: https://www.fbi.gov/file-repository/cyber-alerts/russian-gru-targeting-western-logistics-entities-and-technology-companies-052125.pdf
Retrieved: 2026-09-14. PDF line wraps normalized; identifiers and logic preserved.
Hunting rules: a match does not establish actor attribution.
*/
rule APT28_HEADLACE_SHORTCUT {
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
rule APT28_HEADLACE_CREDENTIALDIALOG {
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
rule APT28_HEADLACE_CORE {
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
rule APT28_MASEPIE {
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
