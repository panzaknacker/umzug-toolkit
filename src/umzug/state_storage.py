"""fail-closed observation and binding of reboot-persistent checkpoint storage."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

from .util import UmzugError, canonical_json


MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
MAX_MOUNTINFO_RECORDS = 16_384
_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")

# a hardware checkpoint must live on a local filesystem with durable write
# semantics and unix ownership/modes. unknown filesystems remain blocked until
# their reboot and durability semantics are reviewed explicitly in code.
_ALLOWED_LOCAL_PERSISTENT_FILESYSTEMS = frozenset(
    {
        "bcachefs",
        "btrfs",
        "ecryptfs",
        "ext2",
        "ext3",
        "ext4",
        "f2fs",
        "jfs",
        "nilfs2",
        "reiserfs",
        "ubifs",
        "xfs",
        "zfs",
    }
)


def _read_mountinfo(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UmzugError("checkpoint mount evidence is unavailable") from exc
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_MOUNTINFO_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_MOUNTINFO_BYTES:
                raise UmzugError("checkpoint mount evidence exceeds its size bound")
        return b"".join(chunks).decode("utf-8", "strict")
    except UnicodeError as exc:
        raise UmzugError("checkpoint mount evidence is not valid UTF-8") from exc
    finally:
        os.close(fd)


def _decode_mount_field(value: str) -> str:
    position = 0
    pieces: list[str] = []
    for match in _MOUNT_ESCAPE.finditer(value):
        if "\\" in value[position : match.start()]:
            raise UmzugError("checkpoint mount evidence contains an invalid escape")
        pieces.append(value[position : match.start()])
        pieces.append(chr(int(match.group(1), 8)))
        position = match.end()
    if "\\" in value[position:]:
        raise UmzugError("checkpoint mount evidence contains an invalid escape")
    pieces.append(value[position:])
    return "".join(pieces)


def _parse_mountinfo(text: str) -> list[dict[str, Any]]:
    lines = text.splitlines()
    if not lines or len(lines) > MAX_MOUNTINFO_RECORDS:
        raise UmzugError("checkpoint mount evidence has an invalid record count")
    rows: list[dict[str, Any]] = []
    for line in lines:
        left, separator, right = line.partition(" - ")
        left_fields = left.split()
        right_fields = right.split()
        if (
            not separator
            or len(left_fields) < 6
            or len(right_fields) < 3
            or not left_fields[0].isdigit()
            or not left_fields[1].isdigit()
            or re.fullmatch(r"[0-9]+:[0-9]+", left_fields[2]) is None
        ):
            raise UmzugError("checkpoint mount evidence contains a malformed record")
        mount_root = _decode_mount_field(left_fields[3])
        mount_point = _decode_mount_field(left_fields[4])
        source = _decode_mount_field(right_fields[1])
        # pseudo mounts such as nsfs legitimately expose roots like
        # ``net:[402653...]``. they may be present elsewhere in mountinfo and
        # must not invalidate an unrelated persistent state mount. the chosen
        # state mount is required to have an absolute root below.
        if not mount_point.startswith("/"):
            raise UmzugError("checkpoint mount evidence contains a relative mount point")
        rows.append(
            {
                "mount_id": int(left_fields[0]),
                "parent_id": int(left_fields[1]),
                "major_minor": left_fields[2],
                "mount_root": mount_root,
                "mount_point": mount_point,
                "mount_options": tuple(left_fields[5].split(",")),
                "filesystem": right_fields[0].lower(),
                "source": source,
            }
        )
    return rows


def _existing_link_free_anchor(path: Path) -> Path:
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise UmzugError("checkpoint state path must be a non-root absolute path")
    current = Path("/")
    anchor = current
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise UmzugError("checkpoint state path cannot be inspected safely") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise UmzugError("checkpoint state path contains a link or non-directory")
        anchor = current
    return anchor


def _covering_mount(anchor: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for row in rows:
        mount_point = Path(str(row["mount_point"]))
        try:
            anchor.relative_to(mount_point)
        except ValueError:
            continue
        candidates.append(row)
    if not candidates:
        raise UmzugError("checkpoint state filesystem has no mountinfo record")
    longest = max(len(Path(str(row["mount_point"])).parts) for row in candidates)
    matches = [row for row in candidates if len(Path(str(row["mount_point"])).parts) == longest]
    identities = {
        (
            row["mount_root"],
            row["mount_point"],
            row["filesystem"],
            row["source"],
        )
        for row in matches
    }
    if len(identities) != 1:
        raise UmzugError("checkpoint state filesystem is hidden by ambiguous stacked mounts")
    return matches[-1]


def observe_persistent_state_storage(
    state_dir: Path,
    *,
    mountinfo_path: Path = Path("/proc/self/mountinfo"),
) -> dict[str, Any]:
    """return stable local mount evidence without creating the state path."""

    if not state_dir.is_absolute() or ".." in state_dir.parts:
        raise UmzugError("checkpoint state path must be absolute and contain no parent traversal")
    anchor = _existing_link_free_anchor(state_dir)
    row = _covering_mount(anchor, _parse_mountinfo(_read_mountinfo(mountinfo_path)))
    filesystem = str(row["filesystem"])
    options = set(row["mount_options"])
    if "rw" not in options or "ro" in options:
        raise UmzugError("checkpoint state filesystem is not mounted read-write")
    if filesystem not in _ALLOWED_LOCAL_PERSISTENT_FILESYSTEMS:
        raise UmzugError("checkpoint state filesystem is not an approved local persistent filesystem: " + filesystem)
    if not str(row["mount_root"]).startswith("/"):
        raise UmzugError("checkpoint state mount has a non-absolute filesystem root")
    identity = {
        "format": 1,
        "mount_root": str(row["mount_root"]),
        "mount_point": str(row["mount_point"]),
        "filesystem": filesystem,
        "source": str(row["source"]),
    }
    return {
        **identity,
        "identity_sha256": hashlib.sha256(canonical_json(identity)).hexdigest(),
        "major_minor": str(row["major_minor"]),
        "existing_anchor": str(anchor),
        "existing_anchor_device": anchor.stat().st_dev,
        "persistent_local_storage_proven": True,
        "created_or_modified": False,
    }


def require_matching_state_storage(
    saved: object,
    observed: dict[str, Any],
) -> None:
    if not isinstance(saved, dict):
        raise UmzugError("checkpoint has no persistent-filesystem binding")
    expected = saved.get("identity_sha256")
    actual = observed.get("identity_sha256")
    if not isinstance(expected, str) or expected != actual:
        raise UmzugError(
            "checkpoint filesystem identity changed; use local recovery and the independently tested backup"
        )


__all__ = ["observe_persistent_state_storage", "require_matching_state_storage"]
