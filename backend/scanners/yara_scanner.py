"""Scans common dropper locations against YARA rules for known-bad patterns."""
import os
import stat

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

WATCHED_DIRS = ["/tmp", "/var/tmp", "/dev/shm"]
RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "rules", "yara")
# YARA scanning is fast, but not free - skip anything unusually large,
# since dropper payloads and scripts are almost always small.
MAX_FILE_SIZE = 20 * 1024 * 1024


def _compile_rules():
    if not HAVE_YARA or not os.path.isdir(RULES_DIR):
        return None

    rule_files = {
        os.path.splitext(name)[0]: os.path.join(RULES_DIR, name)
        for name in os.listdir(RULES_DIR)
        if name.endswith((".yar", ".yara"))
    }
    if not rule_files:
        return None

    try:
        return yara.compile(filepaths=rule_files)
    except yara.Error:
        return None


def scan():
    findings = []
    rules = _compile_rules()
    if rules is None:
        return findings

    for directory in WATCHED_DIRS:
        if not os.path.isdir(directory):
            continue

        for root, _, files in os.walk(directory):
            for name in files:
                path = os.path.join(root, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue

                # Same regular-file-only guard as file_scanner - temp dirs
                # are full of Unix sockets/FIFOs that YARA can't usefully
                # read as file content anyway.
                if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_SIZE:
                    continue

                try:
                    matches = rules.match(path)
                except yara.Error:
                    continue

                for match in matches:
                    findings.append({
                        "scanner": "yara_scanner",
                        "severity": match.meta.get("severity", "high"),
                        "title": f"YARA match: {match.rule}",
                        "description": match.meta.get("description", "File matched a YARA detection rule."),
                        "evidence": {"path": path, "rule": match.rule, "tags": list(match.tags)},
                    })

    return findings


if __name__ == "__main__":
    for finding in scan():
        print(finding)
