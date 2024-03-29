rule GENERIC_EncodedTextInScript_Base64Decode{
    strings:
        $str1 = "base64" wide ascii nocase
        $str2 = "b64" wide ascii nocase
        $alphabet = /[a-zA-Z0-9\/\+]{40,}={0,3}/
    condition:
        any of ($str*) and $alphabet
}

rule GENERIC_POWERSHELL_EncodedCommandOption{
    strings:
        $pwsh = "powershell" wide ascii nocase
        $enc1 = "-EncodedCommand" wide ascii nocase
        $enc2 = /-e[codeman]{0,13}\s/ wide ascii nocase
    condition:
        $pwsh and any of ($enc*)
}
