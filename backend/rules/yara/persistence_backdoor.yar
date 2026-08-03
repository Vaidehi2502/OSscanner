rule SSH_Authorized_Keys_Backdoor
{
    meta:
        description = "Appends an attacker SSH public key to authorized_keys, a common way to plant persistent passwordless access"
        severity = "critical"

    strings:
        $append_authorized_keys = />>\s*~?\/?\.ssh\/authorized_keys/
        $echo_ssh_key = /echo\s+["']?ssh-(rsa|ed25519)/

    condition:
        all of them
}

rule Cron_Backdoor_Injection
{
    meta:
        description = "Silently appends a job to crontab/cron.d, a common Linux persistence mechanism for malware/backdoors"
        severity = "high"

    strings:
        $append_crontab = />>\s*\/etc\/crontab/
        $append_cron_d = />>\s*\/etc\/cron\.d\//
        $crontab_dash_l_pipe = /crontab\s+-l[^\n]{0,40}\|[^\n]{0,40}crontab\s+-/

    condition:
        any of them
}

rule Shell_Profile_Backdoor_Injection
{
    meta:
        description = "Appends attacker-controlled commands to a shell startup file (.bashrc/.profile/.bash_profile), executed on every new login shell"
        severity = "high"

    strings:
        $append_bashrc = />>\s*~?\/?\.bashrc/
        $append_profile = />>\s*~?\/?\.(bash_)?profile/
        $curl_pipe_in_profile = /\.bashrc[^\n]{0,80}curl[^\n]{0,80}\|\s*(sh|bash)/

    condition:
        any of them
}

rule Rogue_Systemd_Service_Definition
{
    meta:
        description = "A systemd unit file that auto-starts a binary from a world-writable temp directory - a common way malware re-establishes persistence after reboot"
        severity = "high"

    strings:
        $unit_section = "[Unit]"
        $service_section = "[Service]"
        $exec_from_tmp = /ExecStart\s*=\s*(\/usr)?\/(tmp|var\/tmp|dev\/shm)\//

    condition:
        ($unit_section or $service_section) and $exec_from_tmp
}
