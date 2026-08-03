rule Ransom_Note_Text
{
    meta:
        description = "Contains phrasing typical of a ransomware ransom note (encrypted-files notice plus a payment/contact demand)"
        severity = "critical"

    strings:
        $encrypted_notice1 = "your files have been encrypted" nocase
        $encrypted_notice2 = "all your files are encrypted" nocase
        $encrypted_notice3 = "your data has been encrypted" nocase
        $decrypt_offer = "decrypt your files" nocase
        $bitcoin_demand = /pay(ment)?\s+(in\s+)?bitcoin/ nocase
        $tor_payment_site = /\.onion\b/

    condition:
        (1 of ($encrypted_notice*)) and (1 of ($decrypt_offer, $bitcoin_demand, $tor_payment_site))
}

rule Shadow_Copy_Deletion_Command
{
    meta:
        description = "Contains a command that deletes Volume Shadow Copies or Windows backup catalogs, used by ransomware to block recovery before encrypting"
        severity = "critical"

    strings:
        $vssadmin = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase
        $wbadmin = /wbadmin(\.exe)?\s+delete\s+catalog/ nocase
        $bcdedit = /bcdedit(\.exe)?\s+\/set.*recoveryenabled\s+no/ nocase

    condition:
        any of them
}

rule Mass_File_Rename_Encrypted_Extension
{
    meta:
        description = "Script logic that walks a directory tree renaming files to a known ransomware payment/encrypted extension"
        severity = "high"

    strings:
        $ext_locked = ".locked" nocase
        $ext_encrypted = ".encrypted" nocase
        $ext_crypt = ".crypt" nocase
        $walk_rename_py = /os\.rename\s*\(/
        $walk_dir_ps = /Get-ChildItem[^\n]{0,60}-Recurse/

    condition:
        (1 of ($ext_locked, $ext_encrypted, $ext_crypt)) and (1 of ($walk_rename_py, $walk_dir_ps))
}
