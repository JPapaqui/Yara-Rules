rule T1087.003 - Email Account - Email Account Discovery {
     meta:

      description = "Email Account Discovery"
      author = "Julio Papaqui"
      reference = "https://attack.mitre.org/techniques/T1087/003/"

    strings:
        $pscmd1 = "Get-GlobalAddressList" ascii wide nocase
        
    condition:
        any of ($pscmd*)
}
