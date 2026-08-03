rule XMRig_Miner_Indicators
{
    meta:
        description = "Contains XMRig cryptominer configuration keys or CLI flags, commonly dropped by cryptojacking payloads"
        severity = "high"

    strings:
        $xmrig = "xmrig" nocase
        $donate_level = "donate-level"
        $cpu_priority = "cpu-priority"
        $rig_id = "rig-id"

    condition:
        2 of them
}

rule Mining_Pool_Connection_String
{
    meta:
        description = "Contains a Stratum mining-pool connection URI, indicating the file configures or launches a coin miner"
        severity = "high"

    strings:
        $stratum_tcp = "stratum+tcp://" nocase
        $stratum_ssl = "stratum+ssl://" nocase
        $pool_monero = /pool\.(minexmr|supportxmr|nanopool|hashvault)\./ nocase

    condition:
        any of them
}

rule Cryptonight_Algorithm_Reference
{
    meta:
        description = "References the CryptoNight/RandomX hashing algorithms used almost exclusively by Monero-style cryptominers, not general-purpose software"
        severity = "medium"

    strings:
        $cryptonight = "cryptonight" nocase
        $randomx = "randomx" nocase

    condition:
        any of them
}
