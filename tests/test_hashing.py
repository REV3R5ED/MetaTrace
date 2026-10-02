"""Tests for evidence hashing."""

from __future__ import annotations

import hashlib

import pytest

from metatrace.core.hashing import HashingError, hash_bytes, hash_file


def test_hash_file_known_answer(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"abc")
    result = hash_file(str(p))
    assert result == {"sha256": hashlib.sha256(b"abc").hexdigest()}


def test_hash_file_both_algorithms(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"abc" * 1000)
    result = hash_file(str(p), ("sha256", "sha512"))
    assert result["sha256"] == hashlib.sha256(b"abc" * 1000).hexdigest()
    assert result["sha512"] == hashlib.sha512(b"abc" * 1000).hexdigest()


def test_hash_file_missing():
    with pytest.raises(HashingError):
        hash_file("/no/such/file.bin")


def test_hash_file_unsupported_algorithm(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"abc")
    with pytest.raises(HashingError):
        hash_file(str(p), ("md5",))


def test_hash_bytes():
    assert hash_bytes(b"abc") == {"sha256": hashlib.sha256(b"abc").hexdigest()}
    with pytest.raises(HashingError):
        hash_bytes(b"abc", ("sha1",))


def test_hash_file_streams_large_input(tmp_path):
    # 3 MiB > 1 MiB chunk size forces multiple streaming reads.
    data = b"x" * (3 * 1024 * 1024)
    p = tmp_path / "big.bin"
    p.write_bytes(data)
    assert hash_file(str(p))["sha256"] == hashlib.sha256(data).hexdigest()
