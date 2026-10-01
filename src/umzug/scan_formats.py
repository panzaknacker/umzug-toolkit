from __future__ import annotations

from collections import Counter
import math
from pathlib import PurePosixPath, PureWindowsPath
import zlib


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _validate_png(data: bytes) -> str | None:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "invalid PNG signature"
    offset = 8
    saw_header = False
    saw_end = False
    while offset < len(data):
        if offset + 12 > len(data):
            return "truncated PNG chunk"
        length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if chunk_end > len(data):
            return "PNG chunk exceeds file boundary"
        payload = data[offset + 8 : offset + 8 + length]
        observed_crc = int.from_bytes(data[offset + 8 + length : chunk_end], "big")
        expected_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if observed_crc != expected_crc:
            return "PNG chunk CRC mismatch"
        if not saw_header:
            if chunk_type != b"IHDR" or length != 13:
                return "PNG does not start with a valid IHDR"
            saw_header = True
        if chunk_type == b"IEND":
            if length != 0:
                return "invalid PNG IEND length"
            saw_end = True
            offset = chunk_end
            break
        offset = chunk_end
    if not saw_end:
        return "PNG is missing IEND"
    if offset != len(data):
        return "PNG has a trailing payload"
    return None


def _mime_agrees(detected: str | None, file_mime: str) -> bool:
    mime = file_mime.strip().lower().splitlines()[0]
    if detected in {None, "binary"}:
        return True
    allowed_prefixes: dict[str, tuple[str, ...]] = {
        "text": ("text/", "application/json", "application/xml", "application/javascript"),
        "script": ("text/", "application/x-shellscript", "application/x-executable"),
        "elf": (
            "application/x-executable",
            "application/x-pie-executable",
            "application/x-sharedlib",
            "application/octet-stream",
        ),
        "pe": ("application/vnd.microsoft.portable-executable", "application/x-dosexec", "application/octet-stream"),
        "zip": ("application/zip", "application/java-archive", "application/vnd."),
        "gzip": ("application/gzip", "application/x-gzip"),
        "bzip2": ("application/x-bzip2",),
        "xz": ("application/x-xz",),
        "zstd": ("application/zstd", "application/x-zstd"),
        "tar": ("application/x-tar",),
        "ar": ("application/x-archive",),
        "deb": ("application/vnd.debian.binary-package", "application/x-debian-package"),
        "rpm": ("application/x-rpm", "application/x-redhat-package-manager"),
        "pdf": ("application/pdf",),
        "png": ("image/png",),
        "jpeg": ("image/jpeg",),
        "gif": ("image/gif",),
        "ogg": ("audio/ogg", "video/ogg", "application/ogg"),
        "mp3": ("audio/", "application/octet-stream"),
        "empty": ("inode/x-empty", "application/x-empty", "application/octet-stream"),
    }
    prefixes = allowed_prefixes.get(detected)
    return prefixes is None or mime.startswith(prefixes)


def _rpm_header_end(data: bytes, offset: int) -> tuple[int, str | None]:
    if offset < 0 or offset + 16 > len(data):
        return offset, "truncated header prefix"
    if data[offset : offset + 3] != b"\x8e\xad\xe8" or data[offset + 3] != 1:
        return offset, "invalid header magic/version"
    if any(data[offset + 4 : offset + 8]):
        return offset, "non-zero reserved header bytes"
    index_count = int.from_bytes(data[offset + 8 : offset + 12], "big")
    store_size = int.from_bytes(data[offset + 12 : offset + 16], "big")
    if index_count > 1_000_000:
        return offset, "unreasonable index count"
    index_end = offset + 16 + index_count * 16
    end = index_end + store_size
    if index_end > len(data) or end > len(data):
        return offset, "index/store exceeds file boundary"
    store = data[index_end:end]
    fixed_sizes = {0: 0, 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}
    for position in range(offset + 16, index_end, 16):
        value_type = int.from_bytes(data[position + 4 : position + 8], "big")
        value_offset = int.from_bytes(data[position + 8 : position + 12], "big")
        count = int.from_bytes(data[position + 12 : position + 16], "big")
        if value_offset > store_size or count > 10_000_000:
            return offset, "index value offset/count is unreasonable"
        if value_type in fixed_sizes:
            required = fixed_sizes[value_type] * count
            if value_offset + required > store_size:
                return offset, "fixed-width index value exceeds store"
        elif value_type == 6:
            if count != 1 or store.find(b"\x00", value_offset) < 0:
                return offset, "RPM string value is unterminated"
        elif value_type in {8, 9}:
            if store[value_offset:].count(b"\x00") < count:
                return offset, "RPM string-array value is truncated"
        else:
            return offset, f"unsupported RPM header value type {value_type}"
    return end, None


def _unsafe_archive_path(name: str) -> bool:
    if not name or "\x00" in name:
        return True
    normalized = name.replace("\\", "/")
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(name)
    return (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or any(part == ".." for part in posix.parts)
        or normalized.startswith("//")
    )


def _unsafe_link_from_member(member: str, target: str, hardlink: bool = False) -> bool:
    if _unsafe_archive_path(target):
        return True
    base = PurePosixPath(".") if hardlink else PurePosixPath(member.replace("\\", "/")).parent
    stack: list[str] = []
    for component in (base / target.replace("\\", "/")).parts:
        if component in {"", "."}:
            continue
        if component == "..":
            if not stack:
                return True
            stack.pop()
        else:
            stack.append(component)
    return False
