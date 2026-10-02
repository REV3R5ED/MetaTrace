"""Cryptographic hashing of evidence files.

Hashes are computed by streaming the file so arbitrarily large inputs
do not exhaust memory. Hashing happens *before* any parsing, and the
digests are recorded in the result — the forensic "hash before
analysis" step.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path

_CHUNK_SIZE = 1024 * 1024  # 1 MiB streaming chunks

SUPPORTED_ALGORITHMS = ("sha256", "sha512")


class HashingError(Exception):
    """Raised when a file cannot be hashed."""


def hash_file(
    path: str | Path, algorithms: Iterable[str] = ("sha256",)
) -> dict[str, str]:
    """Return ``{algorithm: hexdigest}`` for *path*, streamed from disk.

    Raises :class:`HashingError` if the file cannot be read.
    """
    algos = list(algorithms)
    for algo in algos:
        if algo not in SUPPORTED_ALGORITHMS:
            raise HashingError(f"unsupported hash algorithm {algo!r}")
    try:
        digests = {algo: hashlib.new(algo) for algo in algos}
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(_CHUNK_SIZE)
                if not chunk:
                    break
                for digest in digests.values():
                    digest.update(chunk)
    except OSError as exc:
        raise HashingError(f"cannot read {path}: {exc}") from exc
    return {algo: digests[algo].hexdigest() for algo in algos}


def hash_bytes(data: bytes, algorithms: Iterable[str] = ("sha256",)) -> dict[str, str]:
    """Hash in-memory bytes (used for thumbnails/embedded content in later phases)."""
    algos = list(algorithms)
    for algo in algos:
        if algo not in SUPPORTED_ALGORITHMS:
            raise HashingError(f"unsupported hash algorithm {algo!r}")
    return {algo: hashlib.new(algo, data).hexdigest() for algo in algos}
