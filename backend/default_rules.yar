rule Suspect_Strings {
    meta:
        description = "Detects common suspicious strings in malware"
        author = "Glamdring"
        date = "2023-12-01"
    
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell.exe" nocase
        $s3 = "VirtualAlloc"
        $s4 = "WriteProcessMemory"
        $s5 = "CreateRemoteThread"
        $s6 = "URLDownloadToFile"
        $s7 = "ReflectiveLoader"
        
    condition:
        2 of them
}

rule Mimikatz_Keywords {
    meta:
        description = "Detects Mimikatz related keywords"
    strings:
        $s1 = "gentilkiwi" wide ascii nocase
        $s2 = "sekurlsa" wide ascii nocase
        $s3 = "mimikatz" wide ascii nocase
    condition:
        any of them
}
