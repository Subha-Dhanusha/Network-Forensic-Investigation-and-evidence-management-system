"""Hashing utilities for evidence integrity."""
import hashlib


def hash_file(path: str, algo: str = "sha256", chunk_size: int = 1024 * 1024) -> str:
    """Stream-hash a file so we don't load huge PCAPs entirely into memory."""
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def hash_file_multi(path: str) -> dict:
    """Return both SHA-256 (primary, court-standard) and MD5 (legacy reference)."""
    return {
        "sha256": hash_file(path, "sha256"),
        "md5": hash_file(path, "md5"),
    }