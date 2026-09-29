from __future__ import annotations

import contextlib
from dataclasses import dataclass
import datetime as dt
from decimal import Decimal, InvalidOperation
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Any, BinaryIO, Iterable, Iterator, Sequence

from . import __version__
from .limits import MAX_CANDIDATE_OBJECTS, MAX_SIGNED_METADATA_BYTES
from .util import (
    UmzugError,
    atomic_write,
    canonical_json,
    clean_relative,
    contained,
    open_directory_chain,
    rename_noreplace_at,
    run,
    sha256_file,
    which,
)


FORMAT_VERSION = 1
MAX_SELECTIONS = 10_000
MAX_SOURCE_TAR_BYTES = 2**43
BUNDLE_MEMBERS = {
    "umzug/manifest.json",
    "umzug/manifest.sig",
    "umzug/signing-public.pem",
    "umzug/SOURCE.tar",
}

DEFAULT_EXCLUDES = (
    "**/.cache/**",
    "**/__pycache__/**",
    "**/.pytest_cache/**",
    "**/.mypy_cache/**",
    "**/.tox/**",
    "**/.venv/**",
    "**/node_modules/**",
    "**/target/**",
    "**/build/**",
    "**/.Trash*/**",
    "**/Cache/**",
    "**/*.swp",
    "**/*~",
    "**/.DS_Store",
    "**/core",
)

SENSITIVE_EXCLUDES = (
    "**/.ssh/id_*",
    "**/.ssh/*_key",
    "**/.gnupg/**",
    "**/.password-store/**",
    "**/.aws/credentials",
    "**/.config/gcloud/**",
    "**/.docker/config.json",
    "**/.netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/.*_history",
    "**/.kube/config",
    "**/.env",
    "**/.env.*",
    "**/*credentials*",
    "**/*secret*",
    "**/*token*",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/wg*.conf",
    "**/NetworkManager/system-connections/**",
    "**/system-connections/**",
    "**/wpa_supplicant*.conf",
    "**/iwd/*.psk",
    "**/mullvad-vpn/**",
)

_SENSITIVE_CONTENT = (
    ("private-key", re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA |PGP )?PRIVATE KEY-----")),
    ("mullvad-account-shape", re.compile(rb"(?<![0-9])[0-9]{16}(?![0-9])")),
    (
        "token-or-password-assignment",
        re.compile(rb"(?i)(?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*[^\s]{8,}"),
    ),
    ("common-access-token", re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}|gh[opsu]_[A-Za-z0-9]{30,}")),
)


@dataclass(frozen=True)
class Selection:
    path: Path
    category: str = "custom"


def _iso_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _manifest_created_at(source_date_epoch: int | None) -> str:
    if source_date_epoch is None:
        return _iso_now()
    if not isinstance(source_date_epoch, int) or isinstance(source_date_epoch, bool) or source_date_epoch < 0:
        raise UmzugError("SOURCE_DATE_EPOCH must be a non-negative integer")
    try:
        timestamp = dt.datetime(1970, 1, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=source_date_epoch)
    except (OverflowError, ValueError) as exc:
        raise UmzugError("SOURCE_DATE_EPOCH is outside the representable UTC range") from exc
    return timestamp.isoformat(timespec="seconds").replace("+00:00", "Z")


def _matches(path: str, patterns: Iterable[str]) -> bool:
    normalized = path.replace(os.sep, "/")
    variants = (normalized, f"**/{normalized}", Path(normalized).name)
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns for value in variants)


def sensitive_metadata_candidates(**objects: object) -> list[dict[str, Any]]:
    """apply the secret heuristic to every string/key in signed metadata."""

    findings: list[dict[str, Any]] = []

    def scan(label: str, value: object) -> None:
        if isinstance(value, str):
            raw = value.encode("utf-8", "surrogateescape")
            detectors = [detector for detector, pattern in _SENSITIVE_CONTENT if pattern.search(raw)]
            if detectors:
                findings.append({"path": f"metadata:{label}", "detectors": detectors})
        elif isinstance(value, dict):
            for key, child in value.items():
                scan(f"{label}.key", str(key))
                scan(f"{label}.{key}", child)
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                scan(f"{label}[{index}]", child)

    for label, value in objects.items():
        scan(label, value)
    return findings


def preview_selections(
    selections: list[Selection],
    excludes: Iterable[str],
    *,
    include_sensitive: bool = False,
) -> dict[str, Any]:
    patterns = tuple(excludes) + (() if include_sensitive else SENSITIVE_EXCLUDES)
    result: dict[str, Any] = {
        "files": 0,
        "directories": 0,
        "symlinks": 0,
        "bytes": 0,
        "excluded": [],
        "special": [],
        "unreadable": [],
        "sensitive_candidates": [],
        "content_scan_incomplete": [],
        "selections": [],
    }
    for index, selection in enumerate(selections):
        path = selection.path.expanduser().absolute()
        item = {"id": f"item-{index:04d}", "path": str(path), "category": selection.category}
        result["selections"].append(item)
        if not os.path.lexists(path):
            result["unreadable"].append({"path": str(path), "reason": "missing"})
            continue
        walk_errors: list[str] = []
        for source, rel in _walk(path, walk_errors):
            logical = f"{path.name}/{rel}" if rel else path.name
            if _matches(logical, patterns):
                result["excluded"].append(str(source))
                continue
            try:
                info = source.lstat()
            except OSError as exc:
                result["unreadable"].append({"path": str(source), "reason": str(exc)})
                continue
            if stat.S_ISREG(info.st_mode):
                result["files"] += 1
                result["bytes"] += info.st_size
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                try:
                    fd = os.open(source, flags)
                    with os.fdopen(fd, "rb", buffering=0) as handle:
                        sample = handle.read(16 * 1024 * 1024 + 1)
                    if len(sample) > 16 * 1024 * 1024:
                        result["content_scan_incomplete"].append(str(source))
                        sample = sample[: 16 * 1024 * 1024]
                    detectors = [name for name, pattern in _SENSITIVE_CONTENT if pattern.search(sample)]
                    if detectors:
                        result["sensitive_candidates"].append({"path": str(source), "detectors": detectors})
                except OSError as exc:
                    result["unreadable"].append({"path": str(source), "reason": f"content preview failed: {exc}"})
            elif stat.S_ISDIR(info.st_mode):
                result["directories"] += 1
            elif stat.S_ISLNK(info.st_mode):
                result["symlinks"] += 1
            else:
                result["special"].append(str(source))
        result["unreadable"].extend({"path": str(path), "reason": reason} for reason in walk_errors)
    return result


def _walk(root: Path, errors: list[str] | None = None) -> Iterator[tuple[Path, str]]:
    """deterministic lstat walk that never follows a symlink."""
    yield root, ""
    try:
        root_stat = root.lstat()
    except OSError as exc:
        if errors is not None:
            errors.append(f"lstat failed: {root}: {exc}")
        return
    if not stat.S_ISDIR(root_stat.st_mode):
        return
    stack: list[tuple[Path, str]] = [(root, "")]
    while stack:
        directory, rel_dir = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
        except OSError as exc:
            if errors is not None:
                errors.append(f"directory enumeration failed: {directory}: {exc}")
            continue
        subdirs: list[tuple[Path, str]] = []
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}".lstrip("/")
            path = Path(entry.path)
            yield path, rel
            try:
                if entry.is_dir(follow_symlinks=False):
                    subdirs.append((path, rel))
            except OSError:
                continue
        stack.extend(reversed(subdirs))


class _HashingReader(io.RawIOBase):
    def __init__(self, raw: BinaryIO):
        self.raw = raw
        self.digest = hashlib.sha256()

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        chunk = self.raw.read(size)
        self.digest.update(chunk)
        return chunk


def _xattrs(path: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    values: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    if not hasattr(os, "listxattr"):
        return values, ["xattrs unsupported by Python/platform"]
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        return values, [str(exc)]
    for name in sorted(names):
        try:
            raw = os.getxattr(path, name, follow_symlinks=False)
            values[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        except OSError as exc:
            errors.append(f"{name}: {exc}")
    return values, errors


_CAPTURE_STABLE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
_MAX_CAPTURE_DEPTH = 256
_MAX_CAPTURE_ENTRIES = 1_000_000


@dataclass
class _AnchoredEntry:
    path: Path
    rel: str
    parent_fd: int
    name: str
    info: os.stat_result
    descend: bool = True


def _same_capture_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in _CAPTURE_STABLE_FIELDS)


def _selection_parent(path: Path) -> tuple[int, str, Path]:
    absolute = Path(os.path.abspath(os.fspath(path.expanduser())))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if absolute == Path("/"):
            return fd, ".", absolute
        for component in absolute.parts[1:-1]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=fd,
            )
            os.close(fd)
            fd = child
        name = absolute.name
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise UmzugError("selected source has an unsafe final path component")
        return fd, name, absolute
    except BaseException:
        os.close(fd)
        raise


def _walk_anchored(root: Path, errors: list[str]) -> Iterator[_AnchoredEntry]:
    """walk one source tree through held directory fds and never follow symlinks."""

    try:
        parent_fd, name, absolute = _selection_parent(root)
    except OSError as exc:
        errors.append(f"cannot anchor selected source: {root}: {exc}")
        return
    count = 0

    def visit(
        directory_fd: int,
        entry_name: str,
        rel: str,
        display: Path,
        depth: int,
    ) -> Iterator[_AnchoredEntry]:
        nonlocal count
        if depth > _MAX_CAPTURE_DEPTH:
            errors.append(f"capture depth exceeds {_MAX_CAPTURE_DEPTH}: {display}")
            return
        count += 1
        if count > _MAX_CAPTURE_ENTRIES:
            errors.append(f"capture entry count exceeds {_MAX_CAPTURE_ENTRIES}")
            return
        try:
            before = os.stat(entry_name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            errors.append(f"anchored lstat failed: {display}: {exc}")
            return
        entry = _AnchoredEntry(display, rel, directory_fd, entry_name, before)
        yield entry
        if not entry.descend or not stat.S_ISDIR(before.st_mode):
            return
        child_fd = -1
        try:
            child_fd = os.open(
                entry_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            opened = os.fstat(child_fd)
            if not _same_capture_identity(before, opened):
                errors.append(f"directory identity changed before descent: {display}")
                return
            names = sorted(os.listdir(child_fd), key=os.fsencode)
            for child_name in names:
                if child_name in {".", ".."} or "/" in child_name or "\x00" in child_name:
                    errors.append(f"unsafe source directory entry below: {display}")
                    continue
                child_rel = f"{rel}/{child_name}".lstrip("/")
                yield from visit(child_fd, child_name, child_rel, display / child_name, depth + 1)
            after = os.fstat(child_fd)
            if not _same_capture_identity(opened, after):
                errors.append(f"directory changed during capture: {display}")
        except OSError as exc:
            errors.append(f"directory descent failed without following links: {display}: {exc}")
        finally:
            if child_fd >= 0:
                os.close(child_fd)

    try:
        yield from visit(parent_fd, name, "", absolute, 0)
    finally:
        os.close(parent_fd)


def _xattrs_fd(fd: int) -> tuple[dict[str, dict[str, Any]], list[str]]:
    values: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    if not hasattr(os, "listxattr"):
        return values, ["xattrs unsupported by Python/platform"]
    try:
        names = os.listxattr(fd)
    except OSError as exc:
        return values, [str(exc)]
    for name in sorted(names):
        try:
            raw = os.getxattr(fd, name)
            values[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
        except OSError as exc:
            errors.append(f"{name}: {exc}")
    return values, errors


def _anchored_symlink_xattrs(parent_fd: int, name: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    proc_path = Path("/proc/self/fd") / str(parent_fd) / name
    if not Path("/proc/self/fd").is_dir():
        return {}, ["/proc is required for anchored symlink xattrs"]
    return _xattrs(proc_path)


def _tar_info_from_stat(
    arcname: str,
    info: os.stat_result,
    *,
    kind: str,
    mtime_ns: int,
    link_target: str = "",
) -> tarfile.TarInfo:
    tar_info = tarfile.TarInfo(arcname)
    tar_info.mode = stat.S_IMODE(info.st_mode)
    tar_info.uid = info.st_uid
    tar_info.gid = info.st_gid
    seconds, nanoseconds = divmod(mtime_ns, 1_000_000_000)
    tar_info.mtime = seconds
    if nanoseconds:
        tar_info.pax_headers["mtime"] = f"{seconds}.{nanoseconds:09d}"
    if kind == "file":
        tar_info.type = tarfile.REGTYPE
        tar_info.size = info.st_size
    elif kind == "directory":
        tar_info.type = tarfile.DIRTYPE
        tar_info.size = 0
    elif kind == "symlink":
        tar_info.type = tarfile.SYMTYPE
        tar_info.size = 0
        tar_info.linkname = link_target
    else:
        raise UmzugError(f"unsupported capture type: {kind}")
    return tar_info


def build_source_tar(
    destination: Path,
    selections: list[Selection],
    excludes: Iterable[str],
    *,
    include_sensitive: bool = False,
    source_date_epoch: int | None = None,
    forbidden_regular_inodes: set[tuple[int, int]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """create SOURCE.tar and derive the manifest from bytes actually archived."""
    patterns = tuple(excludes) + (() if include_sensitive else SENSITIVE_EXCLUDES)
    entries: list[dict[str, Any]] = []
    selection_rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    forbidden_inodes = forbidden_regular_inodes or set()
    with destination.open("wb") as raw_out:
        with tarfile.open(fileobj=raw_out, mode="w", format=tarfile.PAX_FORMAT, dereference=False) as archive:
            for index, selection in enumerate(selections):
                # hardlinks may only target entries within the same independently
                # approvable candidate selection.
                seen_inodes: dict[tuple[int, int], str] = {}
                source_root = selection.path.expanduser().absolute()
                item_id = f"item-{index:04d}"
                archive_root = f"SOURCE/{item_id}/{source_root.name or 'root'}"
                selection_rows.append(
                    {
                        "id": item_id,
                        "category": selection.category,
                        "original_path": str(source_root),
                        "archive_root": archive_root,
                    }
                )
                walk_errors: list[str] = []
                for anchored in _walk_anchored(source_root, walk_errors):
                    source, rel, st = anchored.path, anchored.rel, anchored.info
                    logical = f"{source_root.name}/{rel}" if rel else source_root.name
                    if _matches(logical, patterns):
                        anchored.descend = False
                        continue
                    arcname = archive_root + (f"/{rel}" if rel else "")
                    if stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) in forbidden_inodes:
                        raise UmzugError(
                            "a selected path aliases the signing private key; private signing keys are never archived"
                        )
                    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                        anchored.descend = False
                        warnings.append(f"omitted special file: {source}")
                        continue
                    mtime_ns = (
                        int(source_date_epoch * 1_000_000_000) if source_date_epoch is not None else st.st_mtime_ns
                    )
                    row: dict[str, Any] = {
                        "path": arcname,
                        "source_selection": item_id,
                        "mode": stat.S_IMODE(st.st_mode),
                        "uid": st.st_uid,
                        "gid": st.st_gid,
                        "mtime_ns": mtime_ns,
                        "size": st.st_size if stat.S_ISREG(st.st_mode) else 0,
                        "xattrs": {},
                        "xattr_errors": [],
                    }
                    if stat.S_ISREG(st.st_mode):
                        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
                        try:
                            fd = os.open(anchored.name, flags, dir_fd=anchored.parent_fd)
                            with os.fdopen(fd, "rb", buffering=0) as file_in:
                                opened = os.fstat(file_in.fileno())
                                if not stat.S_ISREG(opened.st_mode) or not _same_capture_identity(st, opened):
                                    warnings.append(f"source identity changed before capture: {source}")
                                    continue
                                inode = (opened.st_dev, opened.st_ino)
                                if inode in forbidden_inodes:
                                    raise UmzugError(
                                        "a selected path aliases the signing private key; private signing keys are never archived"
                                    )
                                mtime_ns = (
                                    int(source_date_epoch * 1_000_000_000)
                                    if source_date_epoch is not None
                                    else opened.st_mtime_ns
                                )
                                tar_info = _tar_info_from_stat(arcname, opened, kind="file", mtime_ns=mtime_ns)
                                xattrs, xattr_errors = _xattrs_fd(file_in.fileno())
                                warnings.extend(f"xattr incomplete: {source}: {error}" for error in xattr_errors)
                                row.update(
                                    {
                                        "mode": stat.S_IMODE(opened.st_mode),
                                        "uid": opened.st_uid,
                                        "gid": opened.st_gid,
                                        "mtime_ns": mtime_ns,
                                        "size": opened.st_size,
                                        "xattrs": xattrs,
                                        "xattr_errors": xattr_errors,
                                    }
                                )
                                if opened.st_nlink > 1 and inode in seen_inodes:
                                    tar_info.type = tarfile.LNKTYPE
                                    tar_info.linkname = seen_inodes[inode]
                                    tar_info.size = 0
                                    archive.addfile(tar_info)
                                    row.update(
                                        {
                                            "type": "hardlink",
                                            "link_target": seen_inodes[inode],
                                            "size": 0,
                                        }
                                    )
                                else:
                                    reader = _HashingReader(file_in)
                                    archive.addfile(tar_info, reader)
                                    row.update({"type": "file", "sha256": reader.digest.hexdigest()})
                                    seen_inodes[inode] = arcname
                                after = os.fstat(file_in.fileno())
                                if not _same_capture_identity(opened, after):
                                    warnings.append(f"source changed during capture: {source}")
                        except OSError as exc:
                            warnings.append(f"read failed: {source}: {exc}")
                            continue
                    elif stat.S_ISDIR(st.st_mode):
                        directory_fd = -1
                        try:
                            directory_fd = os.open(
                                anchored.name,
                                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=anchored.parent_fd,
                            )
                            opened = os.fstat(directory_fd)
                            if not _same_capture_identity(st, opened):
                                warnings.append(f"directory identity changed before capture: {source}")
                                anchored.descend = False
                                continue
                            xattrs, xattr_errors = _xattrs_fd(directory_fd)
                            warnings.extend(f"xattr incomplete: {source}: {error}" for error in xattr_errors)
                            archive.addfile(_tar_info_from_stat(arcname, opened, kind="directory", mtime_ns=mtime_ns))
                            row.update(
                                {
                                    "type": "directory",
                                    "xattrs": xattrs,
                                    "xattr_errors": xattr_errors,
                                }
                            )
                        except OSError as exc:
                            warnings.append(f"directory capture failed: {source}: {exc}")
                            anchored.descend = False
                            continue
                        finally:
                            if directory_fd >= 0:
                                os.close(directory_fd)
                    else:
                        try:
                            link_target = os.readlink(anchored.name, dir_fd=anchored.parent_fd)
                            after = os.stat(anchored.name, dir_fd=anchored.parent_fd, follow_symlinks=False)
                            if not _same_capture_identity(st, after):
                                warnings.append(f"symlink changed during capture: {source}")
                                continue
                            xattrs, xattr_errors = _anchored_symlink_xattrs(anchored.parent_fd, anchored.name)
                            warnings.extend(f"xattr incomplete: {source}: {error}" for error in xattr_errors)
                            archive.addfile(
                                _tar_info_from_stat(
                                    arcname,
                                    st,
                                    kind="symlink",
                                    mtime_ns=mtime_ns,
                                    link_target=link_target,
                                )
                            )
                            row.update(
                                {
                                    "type": "symlink",
                                    "link_target": link_target,
                                    "xattrs": xattrs,
                                    "xattr_errors": xattr_errors,
                                }
                            )
                        except OSError as exc:
                            warnings.append(f"symlink capture failed: {source}: {exc}")
                            continue
                    entries.append(row)
                warnings.extend(walk_errors)
        raw_out.flush()
        os.fsync(raw_out.fileno())
    return entries, selection_rows, warnings


def preview_captured_source(
    source_tar: Path,
    entries: list[dict[str, Any]],
    selections: list[dict[str, Any]],
    *,
    excluded: Iterable[str] = (),
    inventory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """preview and secret-scan the immutable bytes that will actually be signed."""

    result: dict[str, Any] = {
        "files": sum(row.get("type") == "file" for row in entries),
        "directories": sum(row.get("type") == "directory" for row in entries),
        "symlinks": sum(row.get("type") == "symlink" for row in entries),
        "bytes": sum(int(row.get("size", 0)) for row in entries if row.get("type") == "file"),
        "excluded": list(excluded),
        "special": [],
        "unreadable": [],
        "sensitive_candidates": [],
        "content_scan_incomplete": [],
        "inventory": inventory or {},
        "selections": [
            {
                "id": row.get("id"),
                "path": row.get("original_path"),
                "category": row.get("category"),
            }
            for row in selections
        ],
    }
    expected_files = {str(row["path"]): row for row in entries if row.get("type") == "file"}

    # every string that will appear in the signed metadata is checked, including
    # paths, link targets, categories, xattr names, and explicitly selected
    # inventory. xattr values themselves are never embedded, only hash+size.
    result["sensitive_candidates"].extend(
        sensitive_metadata_candidates(
            selections=selections,
            entries=entries,
            inventory=inventory or {},
            exclusions=list(excluded),
        )
    )
    with tarfile.open(source_tar, mode="r:") as archive:
        members = {member.name: member for member in archive.getmembers()}
        for name, row in expected_files.items():
            member = members.get(name)
            if member is None or not member.isreg() or member.size != row.get("size"):
                raise UmzugError("captured source no longer matches its in-memory manifest")
            stream = archive.extractfile(member)
            if stream is None:
                raise UmzugError("captured regular file cannot be read for secret inspection")
            sample = stream.read(16 * 1024 * 1024 + 1)
            if len(sample) > 16 * 1024 * 1024:
                result["content_scan_incomplete"].append(name)
                sample = sample[: 16 * 1024 * 1024]
            detectors = [detector for detector, pattern in _SENSITIVE_CONTENT if pattern.search(sample)]
            if detectors:
                result["sensitive_candidates"].append({"path": name, "detectors": detectors})
    return result


def create_manifest(
    source_tar: Path,
    entries: list[dict[str, Any]],
    selections: list[dict[str, Any]],
    exclusions: Iterable[str],
    warnings: list[str],
    inventory: dict[str, Any] | None = None,
    *,
    source_date_epoch: int | None = None,
) -> dict[str, Any]:
    manifest = {
        "format_version": FORMAT_VERSION,
        "toolkit_version": __version__,
        "created_at": _manifest_created_at(source_date_epoch),
        "trust_statement": "UNTRUSTED_SOURCE_DATA_REQUIRES_ANALYSIS_AND_EXPLICIT_APPROVAL",
        "payload": {
            "name": "SOURCE.tar",
            "sha256": sha256_file(source_tar),
            "size": source_tar.stat().st_size,
        },
        "selections": selections,
        "entries": entries,
        "exclusions": list(exclusions),
        "warnings": warnings,
        "inventory": inventory or {},
    }
    validate_manifest_structure(manifest)
    return manifest


def validate_manifest_structure(manifest: dict[str, Any]) -> None:
    """bound and cross-bind selections before extraction or candidate scans."""

    if not isinstance(manifest, dict):
        raise UmzugError("manifest root is not an object")
    payload = manifest.get("payload")
    if not isinstance(payload, dict):
        raise UmzugError("manifest payload description is absent or invalid")
    payload_digest = payload.get("sha256")
    payload_size = payload.get("size")
    if (
        payload.get("name") != "SOURCE.tar"
        or not isinstance(payload_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", payload_digest) is None
        or not isinstance(payload_size, int)
        or isinstance(payload_size, bool)
        or not 0 < payload_size <= MAX_SOURCE_TAR_BYTES
    ):
        raise UmzugError("manifest SOURCE.tar description is invalid or exceeds its limit")

    selections = manifest.get("selections")
    entries = manifest.get("entries")
    if (
        not isinstance(selections, list)
        or not 1 <= len(selections) <= MAX_SELECTIONS
        or not isinstance(entries, list)
        or len(entries) > MAX_CANDIDATE_OBJECTS
    ):
        raise UmzugError("manifest selection/entry counts are absent or exceed safety limits")
    by_id: dict[str, str] = {}
    by_root: dict[str, str] = {}
    selection_parts: list[tuple[str, str, tuple[str, ...]]] = []
    original_paths: set[str] = set()
    for row in selections:
        if not isinstance(row, dict):
            raise UmzugError("manifest selection is not an object")
        item_id = row.get("id")
        archive_root = row.get("archive_root")
        category = row.get("category")
        original_path = row.get("original_path")
        if (
            not isinstance(item_id, str)
            or not re.fullmatch(r"item-[0-9]{4}", item_id)
            or not isinstance(archive_root, str)
            or len(archive_root) > 4096
            or not isinstance(category, str)
            or len(category) > 128
            or "\x00" in category
            or not isinstance(original_path, str)
            or len(original_path) > 4096
            or "\x00" in original_path
            or not Path(original_path).is_absolute()
            or original_path in original_paths
        ):
            raise UmzugError("manifest selection identifiers or metadata are invalid")
        if item_id in by_id:
            raise UmzugError(f"duplicate manifest selection ID: {item_id}")
        relative = clean_relative(archive_root)
        if archive_root != relative.as_posix():
            raise UmzugError("manifest selection archive root is not canonical")
        if archive_root in by_root:
            raise UmzugError(f"duplicate manifest selection archive root: {archive_root}")
        by_id[item_id] = archive_root
        by_root[archive_root] = item_id
        selection_parts.append((item_id, archive_root, relative.parts))
        original_paths.add(original_path)

    sorted_roots = sorted(selection_parts, key=lambda value: value[2])
    for previous, current in zip(sorted_roots, sorted_roots[1:]):
        previous_parts = previous[2]
        current_parts = current[2]
        if current_parts[: len(previous_parts)] == previous_parts:
            raise UmzugError("manifest selection archive roots overlap")
    for item_id, _archive_root, root_parts in selection_parts:
        if len(root_parts) < 3 or root_parts[0] != "SOURCE" or root_parts[1] != item_id:
            raise UmzugError("manifest selection archive root is not canonically bound to its ID")

    covered_roots: set[str] = set()
    seen_paths: set[str] = set()
    for row in entries:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or not isinstance(row.get("source_selection"), str)
        ):
            raise UmzugError("manifest entry lacks its selection binding")
        path = row["path"]
        relative = clean_relative(path)
        if path != relative.as_posix():
            raise UmzugError("manifest entry path is not canonical")
        if path in seen_paths:
            raise UmzugError(f"duplicate manifest entry: {path}")
        seen_paths.add(path)
        item_id = row["source_selection"]
        root = by_id.get(item_id)
        if root is None:
            raise UmzugError(f"manifest entry names unknown source selection: {item_id}")
        if path != root and not path.startswith(root + "/"):
            raise UmzugError("manifest entry escapes or misstates its source selection")
        if path == root:
            covered_roots.add(root)
    if covered_roots != set(by_root):
        raise UmzugError("every manifest selection must contain its exact archive root entry")


def generate_signing_key(private_key: Path) -> Path:
    """generate a passphrase-encrypted Ed25519 key; OpenSSL prompts on the TTY."""
    if which("openssl") is None:
        raise UmzugError("OpenSSL is required for Ed25519 manifest signing")
    private_key = private_key.expanduser().absolute()
    public_key = private_key.with_suffix(private_key.suffix + ".pub")
    try:
        parent_fd = open_directory_chain(private_key.parent, create=True)
    except OSError as exc:
        raise UmzugError("signing-key parent cannot be opened without following symlinks") from exc
    try:
        parent_info = os.fstat(parent_fd)
        if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise UmzugError("signing-key parent must be owned by the invoking user and not group/world writable")
        for name in (private_key.name, public_key.name):
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise UmzugError(f"refusing to overwrite signing key artifact: {name}")
        proc_parent = Path("/proc/self/fd") / str(parent_fd)
        if not Path("/proc/self/fd").is_dir():
            raise UmzugError("/proc is required for atomic signing-key publication")
        with tempfile.TemporaryDirectory(prefix=".umzug-keygen-", dir=proc_parent) as tmp_name:
            temporary = Path(tmp_name)
            os.chmod(temporary, 0o700)
            staged_private = temporary / "private.pem"
            staged_public = temporary / "public.pem"
            old_umask = os.umask(0o077)
            try:
                run(
                    [
                        "openssl",
                        "genpkey",
                        "-algorithm",
                        "ED25519",
                        "-aes-256-cbc",
                        "-out",
                        str(staged_private),
                    ],
                    capture=False,
                    timeout=300,
                    pass_fds=(parent_fd,),
                )
            finally:
                os.umask(old_umask)
            os.chmod(staged_private, 0o600)
            public_key_for(staged_private, staged_public, pass_fds=(parent_fd,))
            os.chmod(staged_public, 0o644)
            for staged, expected_mode in (
                (staged_private, 0o600),
                (staged_public, 0o644),
            ):
                info = staged.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != expected_mode
                    or info.st_size <= 0
                ):
                    raise UmzugError("OpenSSL produced an unsafe signing-key artifact")
            temporary_fd = os.open(
                temporary,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )
            public_published = False
            try:
                rename_noreplace_at(temporary_fd, staged_public.name, parent_fd, public_key.name)
                public_published = True
                rename_noreplace_at(temporary_fd, staged_private.name, parent_fd, private_key.name)
            except FileExistsError as exc:
                if public_published:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(public_key.name, dir_fd=parent_fd)
                raise UmzugError("refusing to overwrite a concurrently created signing-key artifact") from exc
            finally:
                os.close(temporary_fd)
    finally:
        os.close(parent_fd)
    return public_key


def public_key_for(
    private_key: Path,
    destination: Path,
    *,
    pass_fds: Sequence[int] = (),
) -> None:
    run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(destination)],
        capture=False,
        timeout=300,
        pass_fds=pass_fds,
    )


def public_key_fingerprint(public_key: Path, *, pass_fds: Sequence[int] = ()) -> str:
    result = run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        pass_fds=pass_fds,
    )
    return hashlib.sha256(result.stdout).hexdigest()


def sign_manifest(
    manifest_path: Path,
    private_key: Path,
    signature_path: Path,
    *,
    pass_fds: Sequence[int] = (),
) -> None:
    if stat.S_IMODE(private_key.stat().st_mode) & 0o077:
        raise UmzugError("signing private key permissions must be 0600 or stricter")
    run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key),
            "-in",
            str(manifest_path),
            "-out",
            str(signature_path),
        ],
        capture=False,
        timeout=300,
        pass_fds=pass_fds,
    )


def verify_manifest(manifest_path: Path, signature_path: Path, public_key: Path) -> None:
    run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-pubin",
            "-rawin",
            "-inkey",
            str(public_key),
            "-in",
            str(manifest_path),
            "-sigfile",
            str(signature_path),
        ]
    )


def assemble_bundle(
    destination: Path,
    manifest_path: Path,
    signature_path: Path,
    public_key: Path,
    source_tar: Path,
    *,
    source_date_epoch: int | None = None,
) -> None:
    members = [
        (manifest_path, "umzug/manifest.json", 0o644),
        (signature_path, "umzug/manifest.sig", 0o644),
        (public_key, "umzug/signing-public.pem", 0o644),
        (source_tar, "umzug/SOURCE.tar", 0o600),
    ]
    with destination.open("wb") as raw:
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, name, mode in members:
                info = archive.gettarinfo(str(path), arcname=name)
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mode = mode
                if source_date_epoch is not None:
                    info.mtime = source_date_epoch
                with path.open("rb") as handle:
                    archive.addfile(info, handle)
        raw.flush()
        os.fsync(raw.fileno())


def encrypt_bundle(
    source: Path,
    destination: Path,
    mode: str,
    recipient: str | None = None,
    *,
    pass_fds: Sequence[int] = (),
) -> None:
    if mode == "age-recipient":
        if not recipient:
            raise UmzugError("age recipient encryption requires --recipient")
        run(
            ["age", "-r", recipient, "-o", str(destination), str(source)],
            capture=False,
            timeout=3600,
            pass_fds=pass_fds,
        )
    elif mode == "age-passphrase":
        run(
            ["age", "-p", "-o", str(destination), str(source)],
            capture=False,
            timeout=3600,
            pass_fds=pass_fds,
        )
    elif mode == "gpg-symmetric":
        run(
            [
                "gpg",
                "--no-options",
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "--output",
                str(destination),
                str(source),
            ],
            capture=False,
            timeout=3600,
            pass_fds=pass_fds,
        )
    else:
        raise UmzugError(f"unsupported encryption mode: {mode}")


def decrypt_bundle(
    source: Path,
    destination: Path,
    mode: str,
    *,
    max_output_bytes: int,
    age_identity: Path | None = None,
) -> None:
    if os.path.lexists(destination):
        raise UmzugError("refusing to overwrite decryption destination")
    if max_output_bytes <= 0:
        raise UmzugError("decryption output limit must be positive")
    try:
        if mode == "age":
            argv = ["age", "--decrypt"]
            if age_identity is not None:
                if age_identity.is_symlink() or not age_identity.is_file():
                    raise UmzugError("age identity must be a non-symlink regular file")
                if stat.S_IMODE(age_identity.stat(follow_symlinks=False).st_mode) & 0o077:
                    raise UmzugError("age identity permissions must be 0600 or stricter")
                argv.extend(("--identity", str(age_identity)))
            argv.extend(("--output", str(destination), "--", str(source)))
            run(argv, capture=False, timeout=3600, max_output_file_bytes=max_output_bytes)
        elif mode == "gpg":
            run(
                [
                    "gpg",
                    "--no-options",
                    "--no-auto-key-retrieve",
                    "--decrypt",
                    "--output",
                    str(destination),
                    "--",
                    str(source),
                ],
                capture=False,
                timeout=3600,
                max_output_file_bytes=max_output_bytes,
            )
        elif mode == "none":
            if source.stat().st_size > max_output_bytes:
                raise UmzugError("plain bundle exceeds configured size limit")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            output_fd = os.open(destination, flags, 0o600)
            try:
                with (
                    source.open("rb", buffering=0) as input_file,
                    os.fdopen(output_fd, "wb", buffering=0) as output_file,
                ):
                    remaining = max_output_bytes
                    while chunk := input_file.read(min(1024 * 1024, remaining + 1)):
                        remaining -= len(chunk)
                        if remaining < 0:
                            raise UmzugError("plain bundle exceeds configured size limit")
                        output_file.write(chunk)
                    output_file.flush()
                    os.fsync(output_file.fileno())
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    destination.unlink()
                raise
        else:
            raise UmzugError(f"unsupported decryption mode: {mode}")
        if not destination.is_file() or destination.is_symlink() or destination.stat().st_size > max_output_bytes:
            raise UmzugError("decrypted bundle is absent, unsafe, or exceeds configured size limit")
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
        raise


def safe_extract_bundle(
    bundle: Path,
    destination: Path,
    *,
    max_payload_bytes: int = MAX_SOURCE_TAR_BYTES,
) -> dict[str, Path]:
    if (
        not isinstance(max_payload_bytes, int)
        or isinstance(max_payload_bytes, bool)
        or not 0 < max_payload_bytes <= MAX_SOURCE_TAR_BYTES
    ):
        raise UmzugError("SOURCE.tar size limit is invalid or exceeds the hard limit")
    if os.path.lexists(destination) and (destination.is_symlink() or not destination.is_dir()):
        raise UmzugError("bundle extraction destination must be a real directory")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)

    def safe_parent(relative: Path) -> Path:
        current = destination
        for part in relative.parts[:-1]:
            current = current / part
            if os.path.lexists(current):
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise UmzugError(f"bundle parent is not a real directory: {current}")
            else:
                current.mkdir(mode=0o700)
        return current

    seen: set[str] = set()
    with tarfile.open(bundle, "r:") as archive:
        members = archive.getmembers()
        _require_canonical_tar_end(bundle, archive.offset)
        for member in members:
            if member.name not in BUNDLE_MEMBERS or member.name in seen:
                raise UmzugError(f"unexpected or duplicate bundle member: {member.name}")
            seen.add(member.name)
            if not member.isfile() or member.islnk() or member.issym():
                raise UmzugError(f"bundle member is not a regular file: {member.name}")
            limit = max_payload_bytes if member.name.endswith("SOURCE.tar") else MAX_SIGNED_METADATA_BYTES
            if member.size < 0 or member.size > limit:
                raise UmzugError(f"bundle member exceeds size limit: {member.name}")
            relative = clean_relative(member.name)
            target = destination / relative
            safe_parent(relative)
            source = archive.extractfile(member)
            if source is None:
                raise UmzugError(f"cannot read bundle member: {member.name}")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags, 0o600)
            written = 0
            try:
                with os.fdopen(fd, "wb") as output:
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        if written > limit:
                            raise UmzugError(f"bundle member expanded beyond limit: {member.name}")
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    target.unlink()
                raise
    if seen != BUNDLE_MEMBERS:
        raise UmzugError(f"bundle is incomplete; missing {sorted(BUNDLE_MEMBERS - seen)}")
    return {name: destination / name for name in BUNDLE_MEMBERS}


def _require_canonical_tar_end(path: Path, logical_end: int) -> None:
    """reject appended polyglots and non-canonical bytes after tar EOA."""

    if logical_end < 0 or logical_end % tarfile.BLOCKSIZE:
        raise UmzugError("tar logical end is invalid")
    fd = -1
    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise UmzugError("tar input is not a regular file")
        trailing_size = before.st_size - logical_end
        if (
            trailing_size < tarfile.BLOCKSIZE * 2
            or trailing_size > tarfile.RECORDSIZE
            or before.st_size % tarfile.BLOCKSIZE
        ):
            raise UmzugError("tar end-of-archive padding is absent or non-canonical")
        os.lseek(fd, logical_end, os.SEEK_SET)
        remaining = trailing_size
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                raise UmzugError("tar end-of-archive padding is truncated")
            if chunk.strip(b"\0"):
                raise UmzugError("tar contains non-zero trailing/polyglot data")
            remaining -= len(chunk)
        after = os.fstat(fd)
        stable = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise UmzugError("tar input changed during end-of-archive validation")
    except OSError as exc:
        raise UmzugError("tar end-of-archive cannot be validated safely") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def load_and_verify_manifest(
    extracted: dict[str, Path],
    *,
    trusted_public_key: Path | None,
    expected_fingerprint: str | None,
) -> tuple[dict[str, Any], str]:
    bundled_key = extracted["umzug/signing-public.pem"]
    key = trusted_public_key or bundled_key
    bundled_fingerprint = public_key_fingerprint(bundled_key)
    key_fingerprint = public_key_fingerprint(key)
    if trusted_public_key and bundled_fingerprint != key_fingerprint:
        raise UmzugError("bundled signing key does not match the independently trusted key")
    if expected_fingerprint and key_fingerprint.lower() != expected_fingerprint.lower().replace(":", ""):
        raise UmzugError("signing key fingerprint mismatch")
    if not trusted_public_key and not expected_fingerprint:
        raise UmzugError("signature key is not trusted: provide --trusted-key or --fingerprint out-of-band")
    verify_manifest(extracted["umzug/manifest.json"], extracted["umzug/manifest.sig"], key)
    try:
        manifest = json.loads(extracted["umzug/manifest.json"].read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"invalid manifest JSON: {exc}") from exc
    validate_manifest_structure(manifest)
    if manifest.get("format_version") != FORMAT_VERSION:
        raise UmzugError("unsupported manifest version")
    if manifest.get("trust_statement") != "UNTRUSTED_SOURCE_DATA_REQUIRES_ANALYSIS_AND_EXPLICIT_APPROVAL":
        raise UmzugError("manifest lacks the mandatory untrusted-source declaration")
    payload = extracted["umzug/SOURCE.tar"]
    try:
        payload_info = payload.stat(follow_symlinks=False)
    except OSError as exc:
        raise UmzugError("SOURCE.tar cannot be inspected safely") from exc
    declared_payload = manifest["payload"]
    if (
        not stat.S_ISREG(payload_info.st_mode)
        or payload_info.st_size > MAX_SOURCE_TAR_BYTES
        or payload_info.st_size != declared_payload["size"]
    ):
        raise UmzugError("SOURCE.tar size mismatch or hard limit exceeded")
    expected = declared_payload["sha256"]
    if sha256_file(payload) != expected:
        raise UmzugError("SOURCE.tar checksum mismatch")
    return manifest, key_fingerprint


def verify_source_tar_manifest(source_tar: Path, manifest: dict[str, Any]) -> None:
    """bind every archive member and regular-file byte to the signed manifest."""
    try:
        source_info = source_tar.stat(follow_symlinks=False)
    except OSError as exc:
        raise UmzugError("SOURCE.tar cannot be inspected safely") from exc
    if not stat.S_ISREG(source_info.st_mode) or not 0 < source_info.st_size <= MAX_SOURCE_TAR_BYTES:
        raise UmzugError("SOURCE.tar is not regular or exceeds its hard size limit")
    rows = manifest.get("entries")
    if not isinstance(rows, list) or len(rows) > MAX_CANDIDATE_OBJECTS:
        raise UmzugError("manifest entry list is missing or exceeds the safety limit")
    expected: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise UmzugError("invalid manifest entry")
        clean_relative(row["path"])
        if row["path"] in expected:
            raise UmzugError(f"duplicate manifest entry: {row['path']}")
        expected[row["path"]] = row
    seen: set[str] = set()
    with tarfile.open(source_tar, "r:") as archive:
        for member in archive:
            clean_relative(member.name)
            if member.name in seen:
                raise UmzugError(f"duplicate SOURCE member: {member.name}")
            seen.add(member.name)
            row = expected.get(member.name)
            if row is None:
                raise UmzugError(f"SOURCE member absent from signed manifest: {member.name}")
            actual_type = (
                "file"
                if member.isfile()
                else "directory"
                if member.isdir()
                else "symlink"
                if member.issym()
                else "hardlink"
                if member.islnk()
                else "special"
            )
            if actual_type != row.get("type"):
                raise UmzugError(f"SOURCE type mismatch: {member.name}")
            if stat.S_IMODE(member.mode) != row.get("mode"):
                raise UmzugError(f"SOURCE mode mismatch: {member.name}")
            if member.uid != row.get("uid") or member.gid != row.get("gid"):
                raise UmzugError(f"SOURCE ownership mismatch: {member.name}")
            try:
                encoded_mtime = member.pax_headers.get("mtime", str(member.mtime))
                observed_mtime_ns = int(Decimal(encoded_mtime) * Decimal(1_000_000_000))
            except (InvalidOperation, ValueError, TypeError) as exc:
                raise UmzugError(f"SOURCE timestamp is invalid: {member.name}") from exc
            if observed_mtime_ns != row.get("mtime_ns"):
                raise UmzugError(f"SOURCE timestamp mismatch: {member.name}")
            if actual_type == "file":
                if member.size != row.get("size"):
                    raise UmzugError(f"SOURCE size mismatch: {member.name}")
                source = archive.extractfile(member)
                if source is None:
                    raise UmzugError(f"SOURCE file unreadable: {member.name}")
                digest = hashlib.sha256()
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise UmzugError(f"SOURCE file truncated: {member.name}")
                    digest.update(chunk)
                    remaining -= len(chunk)
                if digest.hexdigest() != row.get("sha256"):
                    raise UmzugError(f"SOURCE content mismatch: {member.name}")
            elif actual_type in {"symlink", "hardlink"} and member.linkname != row.get("link_target"):
                raise UmzugError(f"SOURCE link target mismatch: {member.name}")
            elif actual_type == "special":
                raise UmzugError(f"SOURCE contains forbidden special member: {member.name}")
        _require_canonical_tar_end(source_tar, archive.offset)
    missing = set(expected) - seen
    if missing:
        sample = sorted(missing)[:10]
        raise UmzugError(f"signed manifest entries absent from SOURCE: {sample}")


def safe_extract_source(
    source_tar: Path,
    destination: Path,
    *,
    max_total_bytes: int = MAX_SOURCE_TAR_BYTES,
) -> list[str]:
    """extract SOURCE without following links, restoring privileges, or special nodes."""
    if (
        not isinstance(max_total_bytes, int)
        or isinstance(max_total_bytes, bool)
        or not 0 < max_total_bytes <= MAX_SOURCE_TAR_BYTES
    ):
        raise UmzugError("SOURCE.tar extraction limit is invalid or exceeds the hard limit")
    try:
        source_info = source_tar.stat(follow_symlinks=False)
    except OSError as exc:
        raise UmzugError("SOURCE.tar cannot be inspected safely") from exc
    if not stat.S_ISREG(source_info.st_mode) or not 0 < source_info.st_size <= max_total_bytes:
        raise UmzugError("SOURCE.tar is not regular or exceeds its extraction limit")
    if os.path.lexists(destination):
        raise UmzugError("SOURCE extraction destination already exists")
    errors: list[str] = []
    total = 0
    created_regular: dict[str, Path] = {}
    seen_members: set[str] = set()

    def safe_parent(target: Path) -> None:
        relative = target.relative_to(destination)
        current = destination
        for part in relative.parts[:-1]:
            current = current / part
            if current.exists() or os.path.lexists(current):
                if current.is_symlink() or not current.is_dir():
                    raise UmzugError(f"archive parent is not a real directory: {current}")
            else:
                current.mkdir(mode=0o700)

    with tarfile.open(source_tar, "r:") as archive:
        members: list[tarfile.TarInfo] = []
        for member in archive:
            members.append(member)
            if len(members) > MAX_CANDIDATE_OBJECTS:
                raise UmzugError("SOURCE archive contains too many members")
        _require_canonical_tar_end(source_tar, archive.offset)
        destination.mkdir(parents=True, exist_ok=False, mode=0o700)
        for member in members:
            if member.name in seen_members:
                errors.append(f"duplicate SOURCE member: {member.name}")
                continue
            seen_members.add(member.name)
            try:
                relative = clean_relative(member.name)
            except UmzugError as exc:
                errors.append(str(exc))
                continue
            target = destination / relative
            if not contained(destination, target.parent):
                errors.append(f"parent escape: {member.name}")
                continue
            try:
                safe_parent(target)
                if member.isdir():
                    if target.exists() and not target.is_dir():
                        raise UmzugError(f"type conflict: {member.name}")
                    target.mkdir(mode=0o700, exist_ok=True)
                elif member.isfile():
                    total += member.size
                    if member.size < 0 or total > max_total_bytes:
                        raise UmzugError("SOURCE extraction size limit exceeded")
                    source = archive.extractfile(member)
                    if source is None:
                        raise UmzugError(f"unreadable member: {member.name}")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                    fd = os.open(target, flags, 0o400)
                    digest = hashlib.sha256()
                    with os.fdopen(fd, "wb") as output:
                        remaining = member.size
                        while remaining:
                            chunk = source.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise UmzugError(f"truncated member: {member.name}")
                            output.write(chunk)
                            digest.update(chunk)
                            remaining -= len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    created_regular[member.name] = target
                elif member.issym():
                    if os.path.lexists(target):
                        raise UmzugError(f"duplicate member: {member.name}")
                    os.symlink(member.linkname, target)
                elif member.islnk():
                    link_rel = clean_relative(member.linkname)
                    link_source = destination / link_rel
                    if member.linkname not in created_regular or not contained(destination, link_source):
                        raise UmzugError(f"unsafe or forward hardlink: {member.name}")
                    os.link(link_source, target, follow_symlinks=False)
                else:
                    raise UmzugError(f"special archive member rejected: {member.name}")
            except (OSError, UmzugError) as exc:
                errors.append(str(exc))
    # SOURCE is immutable by convention and permissions; never chmod through symlinks.
    for current_root, dirs, files in os.walk(destination, topdown=False, followlinks=False):
        for name in files:
            path = Path(current_root) / name
            if not path.is_symlink():
                with contextlib.suppress(OSError):
                    os.chmod(path, 0o400, follow_symlinks=False)
        for name in dirs:
            path = Path(current_root) / name
            if not path.is_symlink():
                with contextlib.suppress(OSError):
                    os.chmod(path, 0o500, follow_symlinks=False)
    os.chmod(destination, 0o500)
    return errors
