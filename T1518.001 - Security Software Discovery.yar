rule T1518_001_Security_Software_Discovery {
    strings:
        $ps1 = "get-process" ascii wide nocase
        $ps2 = "ps" ascii wide nocase
        $ps3 = "$_.Description" ascii wide nocase
        $ps4 = "-like" ascii wide nocase
        $wmi1 = "AntiVirusProduct" ascii wide nocase
        $str1 = /(Little\sSnitch|CbOsxSensorService|falcond|nessusd|santad|CbDefense|td-agent|packetbeat|filebeat|auditbeat|osqueryd|BlockBlock|LuLu)/ ascii wide nocase        

    condition:
        3 of ($ps*) or any of ($wmi*) or any of ($str*)
}
