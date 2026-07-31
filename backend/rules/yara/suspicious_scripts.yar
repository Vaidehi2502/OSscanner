rule Suspicious_Reverse_Shell_Pattern
{
    meta:
        description = "Contains a common reverse-shell one-liner pattern (bash /dev/tcp, nc -e, or a piped curl/wget download)"
        severity = "high"

    strings:
        $bash_tcp = "/dev/tcp/"
        $nc_exec = "nc -e"
        $curl_pipe_sh = /curl[^\n]{0,80}\|\s*(sh|bash)/
        $wget_pipe_sh = /wget[^\n]{0,80}\|\s*(sh|bash)/

    condition:
        any of them
}

rule Suspicious_Base64_Shell_Payload
{
    meta:
        description = "Contains a base64-decode piped into a shell, a common dropper/obfuscation pattern"
        severity = "high"

    strings:
        $b64_decode_sh = /base64\s+-d[^\n]{0,40}\|\s*(sh|bash)/
        $echo_b64_sh = /echo\s+[A-Za-z0-9+\/=]{40,}\s*\|\s*base64\s+-d/

    condition:
        any of them
}
