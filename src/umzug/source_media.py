from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import re
import stat
from typing import Iterable

from .util import UmzugError, run


REQUIRED_OPTIONS = frozenset({"ro", "noexec", "nodev", "nosuid"})
_OCTAL = re.compile(r"\\([0-7]{3})")


def _unescape(value: str) -> str:
    return _OCTAL.sub(lambda match: chr(int(match.group(1), 8)), value)


@dataclass(frozen=True)
class MountSafety:
    path: str
    mountpoint: str | None
    filesystem: str | None
    source: str | None
    options: tuple[str, ...]
    missing: tuple[str, ...]

    @property
    def safe(self) -> bool:
        return self.mountpoint is not None and not self.missing

    def to_dict(self) -> dict[str, object]:
        return asdict(self) | {"safe": self.safe}


def inspect_mount(path: Path, mountinfo: Path = Path("/proc/self/mountinfo")) -> MountSafety:
    target = path.absolute().resolve(strict=True)
    best: tuple[int, str, str, str, set[str]] | None = None
    try:
        lines = mountinfo.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise UmzugError(f"cannot inspect mount policy: {exc}") from exc
    for line in lines:
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        after = right.split()
        if len(fields) < 6 or len(after) < 3:
            continue
        mountpoint = Path(_unescape(fields[4]))
        try:
            target.relative_to(mountpoint)
        except ValueError:
            continue
        options = set(fields[5].split(",")) | set(after[2].split(","))
        row = (len(mountpoint.parts), str(mountpoint), after[0], _unescape(after[1]), options)
        if best is None or row[0] > best[0]:
            best = row
    if best is None:
        return MountSafety(str(target), None, None, None, (), tuple(sorted(REQUIRED_OPTIONS)))
    _, mountpoint, filesystem, source, options = best
    missing = tuple(sorted(REQUIRED_OPTIONS - options))
    return MountSafety(str(target), mountpoint, filesystem, source, tuple(sorted(options)), missing)


def require_safe_source_mount(path: Path) -> MountSafety:
    result = inspect_mount(path)
    if not result.safe:
        raise UmzugError(
            "source medium is not mounted with mandatory ro,noexec,nodev,nosuid flags; "
            f"mount={result.mountpoint!r}, missing={','.join(result.missing)}"
        )
    return result


def _open_root_owned_mountpoint(path: Path) -> int:
    """create/open a mountpoint through trusted, non-replaceable parents."""

    path = path.absolute()
    if not path.is_absolute() or path == Path("/"):
        raise UmzugError("source mountpoint must be a non-root absolute directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(path.parts[1:], 1):
            if part in {"", ".", ".."}:
                raise UmzugError("source mountpoint contains an unsafe component")
            final = index == len(path.parts) - 1
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=fd)
                child = os.open(part, flags, dir_fd=fd)
            info = os.fstat(child)
            mode = stat.S_IMODE(info.st_mode)
            sticky_root_directory = info.st_uid == 0 and bool(mode & stat.S_ISVTX) and bool(mode & 0o002)
            if info.st_uid != 0 or (mode & 0o022 and not (not final and sticky_root_directory)):
                os.close(child)
                raise UmzugError("source mountpoint has a non-root-owned or replaceable path component")
            if final and mode & 0o077:
                os.fchmod(child, 0o700)
            os.close(fd)
            fd = child
        return fd
    except OSError as exc:
        os.close(fd)
        raise UmzugError("source mountpoint cannot be opened without following links") from exc
    except BaseException:
        os.close(fd)
        raise


def mount_read_only(device: Path, mountpoint: Path) -> MountSafety:
    if os.geteuid() != 0:
        raise UmzugError("mounting source media requires root")
    try:
        device = device.absolute().resolve(strict=True)
        device.relative_to("/dev")
        info = device.stat(follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise UmzugError("source device must resolve to a real block node below /dev") from exc
    if not stat.S_ISBLK(info.st_mode):
        raise UmzugError("source device must be a block device")
    mountpoint = mountpoint.absolute()
    mountpoint_fd = _open_root_owned_mountpoint(mountpoint)
    try:
        if os.listdir(mountpoint_fd):
            raise UmzugError("mountpoint must be empty")
        before = inspect_mount(mountpoint)
        if before.mountpoint == str(mountpoint):
            raise UmzugError("mountpoint already has a filesystem mounted on it")
        run(
            ["mount", "--options", "ro,noexec,nodev,nosuid", "--", str(device), str(mountpoint)],
            capture=False,
        )
        result = inspect_mount(mountpoint)
        if not result.safe or result.mountpoint != str(mountpoint):
            run(["umount", "--", str(mountpoint)], check=False, capture=False)
            raise UmzugError("kernel did not apply all mandatory source-mount flags")
        return result
    finally:
        os.close(mountpoint_fd)
