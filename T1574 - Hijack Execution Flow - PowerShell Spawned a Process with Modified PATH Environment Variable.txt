rule T1574_007_Env_Path_Modified {
    strings:
        $envStr = /env:Path\s*\+?=/ ascii wide nocase

    condition:
        $envStr
}
