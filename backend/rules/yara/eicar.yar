rule EICAR_Test_File
{
    meta:
        description = "Matches the EICAR antivirus test string - a safe, standard file used to verify detection is working, not real malware"
        severity = "medium"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
