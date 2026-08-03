rule PHP_Webshell_Command_Exec
{
    meta:
        description = "PHP code that executes attacker-controlled input via system/exec/shell_exec/passthru - the core of most PHP webshells"
        severity = "critical"

    strings:
        $sys_post = /system\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $exec_post = /exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $shell_exec_post = /shell_exec\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $passthru_post = /passthru\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $eval_post = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $assert_post = /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/

    condition:
        any of them
}

rule PHP_Webshell_Obfuscated_Eval
{
    meta:
        description = "PHP eval() fed by a decoded string, a common obfuscation wrapper for webshell payloads"
        severity = "high"

    strings:
        $eval_base64 = /eval\s*\(\s*base64_decode\s*\(/
        $eval_gzinflate = /eval\s*\(\s*gzinflate\s*\(/
        $eval_str_rot13 = /eval\s*\(\s*str_rot13\s*\(/
        $create_func = "create_function"

    condition:
        any of them
}

rule Known_Webshell_Signature_Markers
{
    meta:
        description = "Contains a signature banner/marker string used by widely circulated webshell kits"
        severity = "critical"

    strings:
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $wso = "WSO Shell" nocase
        $b374k = "b374k" nocase
        $weevely = "weevely" nocase
        $china_chopper = /eval\s*\(\s*\$_POST\s*\[\s*['"][a-z]{1,3}['"]\s*\]\s*\)\s*;\s*\?>/

    condition:
        any of them
}

rule JSP_ASPX_Webshell_Command_Exec
{
    meta:
        description = "JSP/ASPX code that hands request parameters to a runtime process/command execution API"
        severity = "critical"

    strings:
        $jsp_runtime = /Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter/
        $jsp_processbuilder = "new ProcessBuilder" nocase
        $aspx_cmd = /Process(StartInfo)?\s*\(\s*"cmd(\.exe)?"/
        $aspx_eval_request = /Eval\s*\(\s*Request\s*\[/

    condition:
        any of them
}
