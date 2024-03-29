rule T1518_Software_Discovery {
    strings:
        $wmi1 = "Win32_Product" ascii wide nocase

        $reg1 = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" ascii wide nocase
        $reg2 = "\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" ascii wide nocase

    condition:
        any of ($wmi*) or any of ($reg*)
}
