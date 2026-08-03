rule UPX_Packed_Binary
{
    meta:
        description = "Contains UPX packer section markers - not malicious by itself, but a common way malware hides its real payload from static analysis"
        severity = "low"

    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx_banner = "This file is packed with the UPX executable packer"

    condition:
        any of them
}

rule Obfuscated_PowerShell_Payload
{
    meta:
        description = "PowerShell using base64/encoded-command execution combined with download-and-run cmdlets, a common fileless-malware delivery pattern"
        severity = "high"

    strings:
        $enc_flag = /-(e|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ nocase
        $from_base64 = "FromBase64String" nocase
        $iex = /IEX\s*\(/ nocase
        $invoke_expression = "Invoke-Expression" nocase
        $downloadstring = "DownloadString" nocase
        $webclient = "Net.WebClient" nocase

    condition:
        ($enc_flag or $from_base64) or (($iex or $invoke_expression) and ($downloadstring or $webclient))
}

rule Obfuscated_Python_Exec_Payload
{
    meta:
        description = "Python code that decodes and executes a base64/hex-encoded blob at runtime, a common dropper obfuscation pattern"
        severity = "high"

    strings:
        $exec_b64 = /exec\s*\(\s*(__import__\(['"]base64['"]\)\.)?b64decode\s*\(/
        $exec_compile = /exec\s*\(\s*compile\s*\(/
        $marshal_loads = "marshal.loads"

    condition:
        any of them
}

rule Hex_Escaped_Shellcode_Blob
{
    meta:
        description = "A long run of \\x-escaped bytes, typical of embedded shellcode in a dropper or exploit payload"
        severity = "medium"

    strings:
        $hex_shellcode = /(\\x[0-9a-fA-F]{2}){30,}/

    condition:
        $hex_shellcode
}
