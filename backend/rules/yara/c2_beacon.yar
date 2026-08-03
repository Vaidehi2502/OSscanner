rule Cobalt_Strike_Beacon_Indicators
{
    meta:
        description = "Contains named-pipe or config strings characteristic of a Cobalt Strike Beacon payload"
        severity = "critical"

    strings:
        $pipe_msagent = /\\\\\.\\pipe\\msagent_/ nocase
        $pipe_status = /\\\\\.\\pipe\\status_/ nocase
        $beacon_str = "%s.%s.beacon" nocase
        $cs_watermark = "ReflectiveLoader" nocase

    condition:
        any of them
}

rule Meterpreter_Payload_Indicators
{
    meta:
        description = "Contains strings characteristic of a Metasploit Meterpreter stager/payload"
        severity = "critical"

    strings:
        $meterpreter = "meterpreter" nocase
        $metsrv = "metsrv.dll" nocase
        $payload_windows_meterp = "windows/meterpreter" nocase
        $payload_linux_meterp = "linux/x86/meterpreter" nocase

    condition:
        any of them
}

rule Suspicious_HTTP_Beacon_User_Agent
{
    meta:
        description = "Contains a hardcoded User-Agent string commonly used by malware C2 frameworks to blend beacon traffic in with normal browsing"
        severity = "medium"

    strings:
        $ua_mozilla_incomplete = "Mozilla/4.0 (compatible; MSIE" nocase
        $ua_header_literal = /User-Agent:\s*Mozilla\/4\.0/ nocase
        $curl_spoofed_ua = /curl[^\n]{0,40}-A\s+["']Mozilla/ nocase

    condition:
        any of them
}

rule Raw_Reverse_Shell_Socket_Code
{
    meta:
        description = "Source code that opens a raw socket and duplicates it onto a spawned shell's stdio - a reverse shell implemented directly rather than via a one-liner"
        severity = "high"

    strings:
        $py_socket_dup2 = /s\.connect\s*\([^\n]{0,60}\)[\s\S]{0,120}dup2\s*\(\s*s\.fileno/
        $py_pty_spawn = "pty.spawn"
        $c_dup2_execve = /dup2\s*\(\s*sockfd/

    condition:
        any of them
}
