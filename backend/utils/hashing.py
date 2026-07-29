"""File hashing helpers used to fingerprint files for the file/startup scanners."""
import hashlib


def hash_file(path, algo="sha256", chunk_size=65536):
    """Return the hex digest of a file, or None if it can't be read."""
    try:
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def hash_string(value, algo="sha256"):
    h = hashlib.new(algo)
    h.update(value.encode("utf-8", errors="ignore"))
    return h.hexdigest()
