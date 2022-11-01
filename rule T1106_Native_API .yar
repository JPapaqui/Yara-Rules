rule T1106_Native_API {

     meta:

      description = "Native_API"
      author = "Julio Papaqui"
      reference = "https://attack.mitre.org/techniques/T1106/"

    strings:
        $lib1 = "[Kernel32]::" ascii wide nocase
        $lib2 = "[User32]::" ascii wide nocase
        $lib3 = "[gdi32.dll]::" ascii wide nocase
        $lib4 = "[ntdll.dll]::" ascii wide nocase
        $lib5 = "[shell32.dll]::" ascii wide nocase
        $lib6 = "[Wininet.dll]::" ascii wide nocase
        $lib7 = "[Advapi32.dll]::" ascii wide nocase
        $lib8 = "[NtosKrnl.exe]::" ascii wide nocase

    condition:
        any of ($lib*)
}
