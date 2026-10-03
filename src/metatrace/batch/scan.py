"""Directory scanning for batch runs (v0.5).

Forensic rule: a file is an image because its *header bytes* say so,
never because of its extension. Every regular file under the root is
header-read (bounded by config); files whose magic bytes match no
known image format are reported as skipped, not analyzed.
"""

from __future__ import annotations

from pathlib import Path

from metatrace.image.identify import detect_format, read_header

# Formats MetaTrace can analyze (identify.py's known set).
IMAGE_FORMATS = ("JPEG", "PNG", "GIF", "BMP", "WEBP", "TIFF")


def is_supported_image(path: str, header_bytes: int) -> bool:
    """True when the file's magic bytes identify a supported image."""
    try:
        header = read_header(path, header_bytes)
    except OSError:
        return False
    fmt, _mime = detect_format(header.data)
    return fmt in IMAGE_FORMATS


def iter_candidate_files(root: str, recursive: bool) -> list[str]:
    """Sorted list of regular files under *root*.

    Raises FileNotFoundError / NotADirectoryError for bad input.
    Symlinks to files are followed (they are read, never modified);
    symlinked *directories* are not descended into when recursive, to
    avoid cycles. Unreadable directories are skipped, not fatal.
    """
    base = Path(root)
    if not base.exists():
        raise FileNotFoundError(f"no such directory: {root}")
    if not base.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")

    paths: list[str] = []
    if recursive:
        stack = [base]
        while stack:
            current = stack.pop()
            try:
                entries = sorted(current.iterdir(), key=lambda p: p.name)
            except OSError:
                continue  # unreadable directory: skip, never crash
            for entry in entries:
                try:
                    if entry.is_symlink():
                        # Follow file symlinks, never directory symlinks.
                        if entry.is_file():
                            paths.append(str(entry))
                    elif entry.is_dir():
                        stack.append(entry)
                    elif entry.is_file():
                        paths.append(str(entry))
                except OSError:
                    continue  # entry vanished or unreadable mid-scan
    else:
        try:
            entries = sorted(base.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            raise OSError(f"cannot list directory {root}: {exc}") from exc
        for entry in entries:
            try:
                if entry.is_file() and not entry.is_symlink():
                    paths.append(str(entry))
                elif entry.is_symlink() and entry.is_file():
                    paths.append(str(entry))
            except OSError:
                continue
    return sorted(paths)
