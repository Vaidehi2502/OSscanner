rule Mimikatz_Command_Strings
{
    meta:
        description = "Contains Mimikatz module/command strings used to dump credentials from LSASS memory"
        severity = "critical"

    strings:
        $sekurlsa = "sekurlsa::" nocase
        $lsadump = "lsadump::" nocase
        $kerberos_ptt = "kerberos::ptt" nocase
        $mimikatz_banner = "mimikatz" nocase

    condition:
        any of them
}

rule Shadow_File_Exfiltration_Pattern
{
    meta:
        description = "Reads or copies /etc/shadow and pipes it out (mail/curl/nc), a common Linux credential-theft pattern"
        severity = "critical"

    strings:
        $cat_shadow_pipe = /cat\s+\/etc\/shadow[^\n]{0,60}(\||>)/
        $cp_shadow = /cp\s+\/etc\/shadow\s+/
        $curl_upload_shadow = /curl[^\n]{0,80}--data[^\n]{0,40}@\/etc\/shadow/

    condition:
        any of them
}

rule SSH_Private_Key_Harvesting
{
    meta:
        description = "Searches the filesystem for SSH private keys and stages/exfiltrates them, a common lateral-movement precursor"
        severity = "high"

    strings:
        $find_id_rsa = /find\s+\/[^\n]{0,80}-name\s+["']?id_rsa["']?/
        $grep_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $grep_rsa_key = "-----BEGIN RSA PRIVATE KEY-----"

    condition:
        any of them
}

rule Browser_Credential_Store_Access
{
    meta:
        description = "Directly reads a browser's local credential/cookie store (Chrome Login Data, Firefox key store), a common infostealer technique"
        severity = "high"

    strings:
        $chrome_login_data = "Login Data" wide ascii
        $chrome_cookies_path = /Local\\Google\\Chrome\\User Data/ nocase
        $firefox_logins = "logins.json"
        $firefox_key4 = "key4.db"

    condition:
        any of them
}
