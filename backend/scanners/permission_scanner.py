"""Scans for world-writable files/directories and unexpected SUID/SGID binaries."""
import os
import stat

SENSITIVE_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]

# Binaries that legitimately carry the SUID bit on most distros.
KNOWN_SUID_BASENAMES = {
    "sudo", "su", "passwd", "chsh", "chfn", "gpasswd", "newgrp",
    "mount", "umount", "ping", "ping6", "pkexec", "fusermount", "fusermount3",
    "pppd", "vmware-authd",
}

# Binaries that legitimately carry the SGID bit on most distros (shadow/crontab
# group tools, ssh-agent, mail delivery helpers).
KNOWN_SGID_BASENAMES = {
    "chage", "crontab", "expiry", "pam_extrausers_chkpwd", "unix_chkpwd",
    "ssh-agent", "wall", "write", "postdrop", "postqueue",
}


def _walk_limited(directory, max_entries=5000):
    count = 0
    for root, dirs, files in os.walk(directory):
        for name in files:
            yield os.path.join(root, name)
            count += 1
            if count >= max_entries:
                return


def scan():
    findings = []

    for directory in SENSITIVE_DIRS:
        if not os.path.isdir(directory):
            continue

        for path in _walk_limited(directory):
            try:
                st = os.lstat(path)
            except OSError:
                continue

            mode = st.st_mode

            if mode & stat.S_IWOTH and not stat.S_ISLNK(mode):
                findings.append({
                    "scanner": "permission_scanner",
                    "severity": "medium",
                    "title": f"World-writable file: {path}",
                    "description": "File in a sensitive directory is writable by any user.",
                    "evidence": {"path": path, "mode": oct(mode)},
                })

            basename = os.path.basename(path)

            if (mode & stat.S_ISUID) and basename not in KNOWN_SUID_BASENAMES:
                findings.append({
                    "scanner": "permission_scanner",
                    "severity": "high",
                    "title": f"Unexpected SUID binary: {path}",
                    "description": "Binary runs with owner privileges and is not a commonly known SUID tool.",
                    "evidence": {"path": path, "mode": oct(mode)},
                })

            if (mode & stat.S_ISGID) and basename not in KNOWN_SGID_BASENAMES:
                findings.append({
                    "scanner": "permission_scanner",
                    "severity": "high",
                    "title": f"Unexpected SGID binary: {path}",
                    "description": "Binary runs with group privileges and is not a commonly known SGID tool.",
                    "evidence": {"path": path, "mode": oct(mode)},
                })

    return findings


if __name__ == "__main__":
    for finding in scan():
        print(finding)
