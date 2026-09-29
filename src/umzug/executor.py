from __future__ import annotations

import contextlib
import datetime as dt
import difflib
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys
import tempfile
import uuid
from typing import Any

from .console import require_proven_local_console
from .model import Action, EXECUTABLE_SEARCH_PATH, Plan
from .network import verify_host_firewall_json, verify_offline_guard_json
from .state_storage import (
    observe_persistent_state_storage,
    require_matching_state_storage,
)
from .util import (
    AuditLog,
    UmzugError,
    atomic_write,
    canonical_json,
    contained,
    fsync_directory,
    require_root,
    run,
    terminal_safe,
)


PROC_MODULES = Path("/proc/modules")
SYS_MODULE_ROOT = Path("/sys/module")
PROC_SYS_ROOT = Path("/proc/sys")
NIXOS_SYSTEM_PROFILE = Path("/nix/var/nix/profiles/system")
NIXOS_CURRENT_SYSTEM = Path("/run/current-system")
NIXOS_STORE_SYSTEM_RE = re.compile(r"^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._=-]{1,200}$")


def _trusted_executable(name: str) -> Path:
    found = shutil.which(name, path=EXECUTABLE_SEARCH_PATH)
    if found is None:
        raise UmzugError(f"required executable is unavailable before mutation: {name}")
    try:
        resolved = Path(found).resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise UmzugError(f"required executable cannot be inspected safely: {name}") from exc
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or mode & 0o022
        or mode & 0o7000
        or not os.access(resolved, os.X_OK)
    ):
        raise UmzugError(f"required executable is not a root-owned, immutable program: {name}")
    for parent in resolved.parents:
        try:
            parent_info = parent.stat()
        except OSError as exc:
            raise UmzugError(f"required executable parent cannot be inspected: {name}") from exc
        parent_mode = stat.S_IMODE(parent_info.st_mode)
        sticky_root_directory = bool(parent_mode & stat.S_ISVTX) and parent_info.st_uid == 0
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or (parent_mode & 0o022 and not sticky_root_directory)
        ):
            raise UmzugError(f"required executable has an unsafe writable parent: {name}")
    return resolved


def _stable_regular_sha256(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UmzugError(f"required action input cannot be opened safely: {path}") from exc
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise UmzugError(f"required action input is not a regular file: {path}")
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise UmzugError(f"required action input changed while hashing: {path}")
    finally:
        os.close(fd)
    return digest.hexdigest()


def _executable_receipt(path: Path) -> dict[str, Any]:
    digest = _stable_regular_sha256(path)
    try:
        info = path.stat()
    except OSError as exc:
        raise UmzugError(f"required executable disappeared during receipt creation: {path}") from exc
    return {
        "path": str(path),
        "sha256": digest,
        "device": info.st_dev,
        "inode": info.st_ino,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _backup_tree_digest(path: Path) -> str:
    """hash a backup tree before rollback is allowed to delete live state."""

    rows: list[dict[str, Any]] = []

    def add(current: Path, relative: str) -> None:
        info = current.lstat()
        row: dict[str, Any] = {
            "path": relative,
            "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid,
            "gid": info.st_gid,
        }
        if stat.S_ISLNK(info.st_mode):
            row.update(type="symlink", target=os.readlink(current))
        elif stat.S_ISREG(info.st_mode):
            row.update(
                type="file",
                size=info.st_size,
                sha256=_stable_regular_sha256(current),
            )
        elif stat.S_ISDIR(info.st_mode):
            row["type"] = "directory"
        else:
            raise UmzugError(f"backup contains an unsupported special object: {current}")
        rows.append(row)

    add(path, ".")
    if path.is_dir() and not path.is_symlink():
        for current_root, directories, files in os.walk(
            path,
            topdown=True,
            followlinks=False,
        ):
            directories.sort()
            files.sort()
            root_path = Path(current_root)
            for name in [*directories, *files]:
                child = root_path / name
                add(child, str(child.relative_to(path)))
    return hashlib.sha256(canonical_json(rows)).hexdigest()


def _fsync_regular_backup(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise UmzugError(f"backup durability target is not a regular file: {path}")
        os.fsync(fd)
        after = os.fstat(fd)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise UmzugError(f"backup file changed during durability sync: {path}")
    finally:
        os.close(fd)


def _fsync_backup_directory(path: Path) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISDIR(before.st_mode):
            raise UmzugError(f"backup durability target is not a directory: {path}")
        os.fsync(fd)
        after = os.fstat(fd)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise UmzugError(f"backup directory changed during durability sync: {path}")
    finally:
        os.close(fd)


def _fsync_backup_tree(path: Path) -> None:
    """durably persist a private backup tree without following symlinks."""

    try:
        root_info = path.lstat()
        if stat.S_ISLNK(root_info.st_mode):
            return
        if stat.S_ISREG(root_info.st_mode):
            _fsync_regular_backup(path)
            return
        if not stat.S_ISDIR(root_info.st_mode):
            raise UmzugError(f"backup contains an unsupported durability object: {path}")
        for current_root, directories, files in os.walk(
            path,
            topdown=False,
            followlinks=False,
        ):
            directories.sort()
            files.sort()
            current = Path(current_root)
            for name in files:
                child = current / name
                info = child.lstat()
                if stat.S_ISLNK(info.st_mode):
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise UmzugError(f"backup contains an unsupported durability object: {child}")
                _fsync_regular_backup(child)
            for name in directories:
                child = current / name
                info = child.lstat()
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                    raise UmzugError(f"backup contains an unsupported durability object: {child}")
            _fsync_backup_directory(current)
    except OSError as exc:
        raise UmzugError(f"backup durability sync failed: {path}") from exc


def _copy_regular_backup_noreplace(source: Path, target: Path) -> None:
    source_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    source_fd = -1
    target_fd = -1
    try:
        source_fd = os.open(source, source_flags)
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise UmzugError(f"backup source is not a stable regular file: {source}")
        target_fd = os.open(target, target_flags, 0o600)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise UmzugError(f"regular backup write made no progress: {target}")
                view = view[written:]
        after = os.fstat(source_fd)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise UmzugError(f"backup source changed while it was copied: {source}")
        os.fchmod(target_fd, stat.S_IMODE(before.st_mode))
        os.utime(target_fd, ns=(before.st_atime_ns, before.st_mtime_ns))
    except OSError as exc:
        raise UmzugError(f"regular backup cannot be created without overwrite: {target}") from exc
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        if source_fd >= 0:
            os.close(source_fd)


class StateStore:
    def __init__(self, root: Path, *, create: bool = True):
        self.root = root.absolute()
        self.path = self.root / "state.json"
        self.backups = self.root / "backups"
        self.inputs = self.root / "inputs"
        owner_uid = os.geteuid()
        root_fd = self._open_secure_root(self.root, owner_uid=owner_uid, create=create)
        try:
            self._ensure_private_child(root_fd, "backups", owner_uid=owner_uid, create=create)
            self._ensure_private_child(root_fd, "inputs", owner_uid=owner_uid, create=create)
        finally:
            os.close(root_fd)

    @staticmethod
    def _open_secure_root(root: Path, *, owner_uid: int, create: bool = True) -> int:
        if not root.is_absolute() or root == Path("/"):
            raise UmzugError("checkpoint state root must be a non-root absolute directory")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for index, part in enumerate(root.parts[1:], 1):
                if part in {"", ".", ".."}:
                    raise UmzugError("checkpoint path contains an unsafe component")
                final = index == len(root.parts) - 1
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
                try:
                    child = os.open(part, flags, dir_fd=fd)
                except FileNotFoundError as exc:
                    if not create:
                        raise UmzugError("checkpoint state path does not exist for read-only use") from exc
                    os.mkdir(part, 0o700, dir_fd=fd)
                    child = os.open(part, flags, dir_fd=fd)
                info = os.fstat(child)
                mode = stat.S_IMODE(info.st_mode)
                if final:
                    if info.st_uid != owner_uid:
                        os.close(child)
                        raise UmzugError("checkpoint state root owner differs from the invoking user")
                    if mode & 0o077:
                        if not create:
                            os.close(child)
                            raise UmzugError("checkpoint state root is not private for read-only use")
                        os.fchmod(child, 0o700)
                elif owner_uid == 0:
                    sticky_root_directory = info.st_uid == 0 and bool(mode & stat.S_ISVTX) and bool(mode & 0o002)
                    if info.st_uid != 0 or (mode & 0o022 and not sticky_root_directory):
                        os.close(child)
                        raise UmzugError("root checkpoint path has a non-root-owned or writable parent")
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _ensure_private_child(
        root_fd: int,
        name: str,
        *,
        owner_uid: int,
        create: bool = True,
    ) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
        try:
            fd = os.open(name, flags, dir_fd=root_fd)
        except OSError as exc:
            raise UmzugError(f"checkpoint child is not a safe directory: {name}") from exc
        try:
            info = os.fstat(fd)
            if info.st_uid != owner_uid:
                raise UmzugError(f"checkpoint child has the wrong owner: {name}")
            if stat.S_IMODE(info.st_mode) & 0o077:
                if not create:
                    raise UmzugError(f"checkpoint child is not private for read-only use: {name}")
                os.fchmod(fd, 0o700)
        finally:
            os.close(fd)

    def load(self) -> dict[str, Any]:
        try:
            fd = os.open(
                self.path,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            return {
                "format": 1,
                "completed": [],
                "backups": {},
                "created": [],
                "executables": {},
                "pending_reboot": None,
            }
        except OSError as exc:
            raise UmzugError("checkpoint state cannot be opened without following links") from exc
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) & 0o022
                or before.st_size > 64 * 1024 * 1024
            ):
                raise UmzugError("checkpoint state file has unsafe metadata")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    raise UmzugError("checkpoint state was truncated while reading")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(fd, 1):
                raise UmzugError("checkpoint state grew while reading")
            after = os.fstat(fd)
            stable = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_gid",
                "st_nlink",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if any(getattr(before, field) != getattr(after, field) for field in stable):
                raise UmzugError("checkpoint state changed while reading")
            value = json.loads(b"".join(chunks).decode("utf-8", "strict"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise UmzugError(f"checkpoint state is unreadable: {exc}") from exc
        finally:
            os.close(fd)
        if not isinstance(value, dict) or value.get("format") != 1 or not isinstance(value.get("completed"), list):
            raise UmzugError("checkpoint state has an unsupported format")
        return value

    def save(self, state: dict[str, Any]) -> None:
        atomic_write(self.path, canonical_json(state), 0o600)

    def backup(self, path: Path, state: dict[str, Any]) -> None:
        key = str(path)
        if key in state["backups"]:
            return
        digest = hashlib.sha256(key.encode()).hexdigest()
        target = self.backups / digest
        try:
            source_info = path.lstat()
        except FileNotFoundError:
            source_info = None
        except OSError as exc:
            raise UmzugError(f"backup source cannot be inspected safely: {path}") from exc
        if source_info is not None:
            if stat.S_ISLNK(source_info.st_mode):
                target.symlink_to(os.readlink(path))
            elif stat.S_ISDIR(source_info.st_mode):
                shutil.copytree(path, target, symlinks=True)
            elif stat.S_ISREG(source_info.st_mode):
                _copy_regular_backup_noreplace(path, target)
            else:
                raise UmzugError(f"backup source has an unsupported special type: {path}")
            backup_sha256 = _backup_tree_digest(target)
            _fsync_backup_tree(target)
            if _backup_tree_digest(target) != backup_sha256:
                raise UmzugError(f"backup changed after durability sync: {target}")
            try:
                _fsync_backup_directory(self.backups)
            except OSError as exc:
                raise UmzugError("backup root durability sync failed") from exc
            state["backups"][key] = {
                "backup": str(target),
                "existed": True,
                "sha256": backup_sha256,
            }
        else:
            # the non-existence receipt is durable only when the checkpoint
            # directory itself is synced by the following atomic state save.
            state["backups"][key] = {"backup": None, "existed": False}
        self.save(state)


class Executor:
    def __init__(
        self,
        *,
        state_root: Path,
        system_root: Path = Path("/"),
        dry_run: bool = False,
        audit_log: AuditLog | None = None,
        assume_yes: bool = False,
        approvals: set[str] | None = None,
    ):
        self.store = StateStore(state_root)
        self.system_root = system_root.resolve()
        self.dry_run = dry_run
        self.audit = audit_log or AuditLog(None)
        self.assume_yes = assume_yes
        self.approvals = approvals or set()

    def _bound_executable(
        self,
        name: str,
        state: dict[str, Any],
        *,
        allow_initial_bind: bool = False,
    ) -> Path:
        path = _trusted_executable(name)
        observed = _executable_receipt(path)
        receipts = state.get("executables")
        if not isinstance(receipts, dict):
            raise UmzugError("checkpoint executable receipts are invalid")
        expected = receipts.get(name)
        if expected is None:
            if not allow_initial_bind:
                raise UmzugError(f"required executable has no completed bound preflight: {name}")
            receipts[name] = observed
            self.store.save(state)
        elif not isinstance(expected, dict) or expected != observed:
            raise UmzugError(f"required executable changed after its bound preflight: {name}")
        return path

    def _map_path(self, path: str) -> Path:
        raw = Path(path)
        if not raw.is_absolute() or ".." in raw.parts:
            raise UmzugError(f"system action path must be absolute: {path}")
        target = self.system_root / raw.relative_to("/")
        if not contained(self.system_root, target.parent):
            raise UmzugError(f"system action escapes root: {path}")
        return target

    def _assert_safe_target(self, target: Path, *, regular_if_exists: bool = False) -> None:
        """reject symlinked parent components before privileged writes."""

        try:
            relative = target.relative_to(self.system_root)
        except ValueError as exc:
            raise UmzugError(f"system action escapes root: {target}") from exc
        current = self.system_root
        for component in relative.parts[:-1]:
            current /= component
            if not os.path.lexists(current):
                continue
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise UmzugError(f"managed path has a symlink parent: {current}")
            if not stat.S_ISDIR(info.st_mode):
                raise UmzugError(f"managed path parent is not a directory: {current}")
        if os.path.lexists(target):
            info = target.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise UmzugError(f"refusing to replace a symlinked managed path: {target}")
            if regular_if_exists and not stat.S_ISREG(info.st_mode):
                raise UmzugError(f"managed file target is not a regular file: {target}")

    @staticmethod
    def _write_matches(target: Path, content: bytes, mode: int) -> bool:
        try:
            info = target.lstat()
            return stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == mode and target.read_bytes() == content
        except OSError:
            return False

    @staticmethod
    def _required_inputs(parameters: dict[str, Any]) -> dict[Path, str]:
        raw = parameters.get("required_file_hashes", {})
        if not isinstance(raw, dict):
            raise UmzugError("required_file_hashes must be a path-to-SHA256 mapping")
        result: dict[Path, str] = {}
        for raw_path, expected in sorted(raw.items()):
            path = Path(str(raw_path))
            expected_text = str(expected)
            if not path.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", expected_text):
                raise UmzugError("invalid required action input hash")
            if _stable_regular_sha256(path) != expected_text:
                raise UmzugError(f"required action input changed after planning: {path}")
            result[path] = expected_text
        return result

    def _snapshot_required_input(self, source: Path, expected: str) -> Path:
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", source.name)[:120] or "artifact"
        target = self.store.inputs / f"{expected}-{safe_name}"
        if os.path.lexists(target):
            if _stable_regular_sha256(target) != expected:
                raise UmzugError(f"checkpoint input snapshot hash mismatch: {target}")
            return target

        source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            source_fd = os.open(source, source_flags)
        except OSError as exc:
            raise UmzugError(f"required action input cannot be snapshotted safely: {source}") from exc
        temporary_fd, temporary_name = tempfile.mkstemp(prefix=".input-", dir=self.store.inputs)
        temporary = Path(temporary_name)
        digest = hashlib.sha256()
        try:
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode):
                raise UmzugError(f"required action input is not regular: {source}")
            os.fchmod(temporary_fd, 0o400)
            while chunk := os.read(source_fd, 1024 * 1024):
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(temporary_fd, view)
                    view = view[written:]
            os.fsync(temporary_fd)
            after = os.fstat(source_fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise UmzugError(f"required action input changed during snapshot: {source}")
            if digest.hexdigest() != expected:
                raise UmzugError(f"required action input changed after planning: {source}")
            os.close(temporary_fd)
            temporary_fd = -1
            os.replace(temporary, target)
            fsync_directory(self.store.inputs)
        finally:
            os.close(source_fd)
            if temporary_fd >= 0:
                os.close(temporary_fd)
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()
        self.audit.event("action.input_snapshot", source=str(source), sha256=expected, snapshot=str(target))
        return target

    def _diff(self, target: Path, content: bytes) -> str:
        try:
            info = target.lstat()
        except FileNotFoundError:
            return f"--- {target} (missing or non-regular)\n+++ planned\n+{content.decode(errors='replace')}"
        except OSError as exc:
            if not self.dry_run:
                raise UmzugError(f"managed target cannot be inspected safely: {target}") from exc
            return self._uninspectable_diff(target, content)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return f"--- {target} (missing or non-regular)\n+++ planned\n+{content.decode(errors='replace')}"
        try:
            old = target.read_text(encoding="utf-8").splitlines(keepends=True)
            new = content.decode("utf-8").splitlines(keepends=True)
        except UnicodeError:
            return f"binary replacement: {target} ({info.st_size} -> {len(content)} bytes)"
        except OSError as exc:
            if not self.dry_run:
                raise UmzugError(f"managed target cannot be read safely: {target}") from exc
            return self._uninspectable_diff(target, content)
        return "".join(difflib.unified_diff(old, new, fromfile=str(target), tofile=f"{target} (planned)"))

    @staticmethod
    def _uninspectable_diff(target: Path, content: bytes) -> str:
        return (
            f"--- {target} (existing state is not inspectable by this unprivileged dry-run; "
            "productive root apply must re-check and show the real diff before mutation)\n"
            f"+++ planned\n+{content.decode(errors='replace')}"
        )

    def _confirm(self, action: Action) -> None:
        if action.id in self.approvals:
            return
        if not action.requires_confirmation and self.assume_yes:
            return
        if not sys.stdin.isatty():
            raise UmzugError(f"action {action.id} requires explicit approval (--approve {action.id})")
        print(
            f"\n[{terminal_safe(action.risk.upper())}] {terminal_safe(action.summary)}\n"
            f"Grund: {terminal_safe(action.rationale)}"
        )
        if action.destructive:
            answer = input(f"Destruktive Aktion bestätigen; exakt {action.id!r} eingeben: ")
            if answer != action.id:
                raise UmzugError(f"action declined: {action.id}")
        elif input("Anwenden? [y/N] ").strip().lower() not in {"y", "yes", "j", "ja"}:
            raise UmzugError(f"action declined: {action.id}")

    @staticmethod
    def _completed_actions(plan: Plan, state: dict[str, Any]) -> list[Action]:
        completed = state.get("completed")
        if (
            not isinstance(completed, list)
            or any(not isinstance(item, str) for item in completed)
            or len(completed) != len(set(completed))
        ):
            raise UmzugError("checkpoint completed-action list is invalid or contains duplicates")
        by_id = {action.id: action for action in plan.actions}
        unknown = sorted(set(completed) - set(by_id))
        if unknown:
            raise UmzugError("checkpoint contains actions absent from the bound plan: " + ", ".join(unknown))
        completed_set = set(completed)
        expected_prefix = [action.id for action in plan.actions[: len(completed)]]
        if completed != expected_prefix:
            raise UmzugError("checkpoint completed actions must be the exact leading plan prefix")
        return [action for action in plan.actions if action.id in completed_set]

    def _reverify_completed(self, actions: list[Action], state: dict[str, Any]) -> None:
        for action in actions:
            if action.operation != "write_file" and not action.verify:
                continue
            self.audit.event("action.reverify_start", action_id=action.id)
            self._verify(action, state)
            self.audit.event("action.reverify_complete", action_id=action.id)

    def apply(self, plan: Plan) -> dict[str, Any]:
        plan.validate()
        if plan.profile == "test" and self.system_root == Path("/"):
            raise UmzugError("test-profile actions are forbidden against the live system root")
        require_root(dry_run=self.dry_run or self.system_root != Path("/"))
        # validate every immutable external input before the first managed-file,
        # group, service, or package mutation. in particular, management-socket
        # containment must precede mullvad's postinst start, but a stale vendor
        # artifact must still fail before that preparation changes the target.
        for action in plan.actions:
            if action.operation == "run_command":
                self._required_inputs(action.parameters)
        state = self.store.load()
        digest = plan.digest()
        previous_digest = state.get("plan_digest")
        if previous_digest is not None:
            if not isinstance(previous_digest, str) or previous_digest != digest:
                raise UmzugError("checkpoint belongs to a different plan; rollback or use a new state directory")
        elif self.store.path.exists():
            # Any persisted executor state without a plan binding predates the
            # invariant or may be the result of tampering. never adopt it.
            raise UmzugError("existing checkpoint has no immutable plan digest; use a new state directory")
        elif not self.dry_run:
            # this is deliberately the first state write. a crash immediately
            # afterwards still leaves an immutable plan binding and no plan
            # replacement window before the first completed action.
            state["plan_digest"] = digest
            state["profile"] = plan.profile
            self.store.save(state)
        completed_actions = self._completed_actions(plan, state)
        if not self.dry_run:
            # a reboot or interruption is a new trust boundary.  re-prove all
            # completed managed files and effective security controls before
            # accepting a post-reboot checkpoint or executing another action.
            self._reverify_completed(completed_actions, state)
        pending = state.get("pending_reboot")
        if pending and not self.dry_run:
            if not isinstance(pending, dict):
                raise UmzugError("pending reboot checkpoint is invalid")
            previous_boot = _require_boot_id(pending.get("boot_id"), "saved pre-reboot")
            current_boot = _require_boot_id(_boot_id(), "current post-reboot")
            if current_boot == previous_boot:
                raise UmzugError(f"reboot still required after {pending.get('action')}: {pending.get('reason')}")
            if pending.get("action") not in state.get("completed", []):
                raise UmzugError("pending reboot checkpoint is not atomically bound to a completed action")
            pending_action = next(
                (item for item in plan.actions if item.id == pending.get("action")),
                None,
            )
            if pending_action is None:
                raise UmzugError("pending reboot action is absent from the bound plan")
            self._verify_post_reboot(pending_action, state)
            state["last_verified_reboot"] = {
                "action": pending.get("action"),
                "previous_boot_id": previous_boot,
                "current_boot_id": current_boot,
            }
            state["pending_reboot"] = None
            self.store.save(state)
        completed = {action.id for action in completed_actions}
        for position, action in enumerate(plan.actions, 1):
            if action.id in completed:
                continue
            print(f"[{position}/{len(plan.actions)}] {terminal_safe(action.summary)}")
            if action.operation == "write_file":
                target = self._map_path(str(action.parameters["path"]))
                content = str(action.parameters["content"]).encode("utf-8")
                planned_mode = int(action.parameters.get("mode", 0o644))
                try:
                    self._assert_safe_target(target, regular_if_exists=True)
                except PermissionError as exc:
                    if not self.dry_run:
                        raise UmzugError(f"managed target cannot be inspected safely: {target}") from exc
                    diff = self._uninspectable_diff(target, content)
                else:
                    if self.dry_run and not os.access(target.parent, os.X_OK):
                        diff = self._uninspectable_diff(target, content)
                    else:
                        if self._write_matches(target, content, planned_mode):
                            reboot_pending = self._mark_complete(state, action, plan=plan)
                            if reboot_pending:
                                self._print_reboot_required(action)
                                break
                            continue
                        diff = self._diff(target, content)
                if diff:
                    print("\n".join(terminal_safe(line) for line in diff.splitlines()))
                elif target.exists():
                    observed_mode = stat.S_IMODE(target.stat(follow_symlinks=False).st_mode)
                    print(f"mode change: {target}: {observed_mode:#06o} -> {planned_mode:#06o}")
            elif action.operation == "run_command":
                # dry-runs also validate that reviewed external inputs still
                # match the plan, but only productive applies create snapshots.
                self._required_inputs(action.parameters)
            elif action.operation == "check_executable":
                name = str(action.parameters["name"])
                try:
                    executable = _trusted_executable(name)
                except UmzugError:
                    if not self.dry_run:
                        raise
                    print(f"preflight: {name}: MISSING/UNSAFE; productive apply will stop before mutation")
                else:
                    print(f"preflight: {name}: {executable}")
            self._confirm(action)
            self.audit.event("action.start", action_id=action.id, operation=action.operation, risk=action.risk)
            if not self.dry_run:
                for path in action.backup_paths:
                    backup_target = self._map_path(path)
                    self._assert_safe_target(backup_target)
                    self.store.backup(backup_target, state)
                self._execute(action, state)
                self._verify(action, state)
            reboot_pending = self._mark_complete(state, action, plan=plan)
            if reboot_pending:
                self._print_reboot_required(action)
                break
        return state

    def _mark_complete(
        self,
        state: dict[str, Any],
        action: Action,
        *,
        plan: Plan,
    ) -> bool:
        if self.dry_run:
            state.setdefault("dry_run_actions", []).append(action.id)
            self.audit.event("action.preview", action_id=action.id)
            return False
        pending: dict[str, Any] | None = None
        if action.reboot_reason:
            # package/initramfs hooks run as root and may alter persistence
            # while leaving the current live nft/rfkill state intact. re-prove
            # the complete preceding prefix before authorizing a reboot.
            self._reverify_completed(self._completed_actions(plan, state), state)
            pending = {
                "action": action.id,
                "reason": action.reboot_reason,
                "resume": f"setup resume --state-dir {self.store.root}",
                "boot_id": _require_boot_id(_boot_id(), "current pre-reboot"),
            }
        if action.id not in state["completed"]:
            state["completed"].append(action.id)
        if pending is not None:
            state["pending_reboot"] = pending
        # completed and pending_reboot deliberately enter one atomic JSON write.
        self.store.save(state)
        self.audit.event("action.complete", action_id=action.id, dry_run=self.dry_run)
        return pending is not None

    def _print_reboot_required(self, action: Action) -> None:
        print(f"Neustart erforderlich: {action.reboot_reason}")
        print(f"Fortsetzen mit: setup resume --state-dir {self.store.root}")

    def _execute(self, action: Action, state: dict[str, Any]) -> None:
        operation = action.operation
        params = action.parameters
        if operation == "check_executable":
            self._bound_executable(str(params["name"]), state, allow_initial_bind=True)
        elif operation == "write_file":
            target = self._map_path(str(params["path"]))
            self._assert_safe_target(target, regular_if_exists=True)
            existed = os.path.lexists(target)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            atomic_write(target, str(params["content"]).encode(), int(params.get("mode", 0o644)))
            if not existed:
                state["created"].append(str(target))
        elif operation == "ensure_dir":
            target = self._map_path(str(params["path"]))
            self._assert_safe_target(target)
            if not target.exists():
                target.mkdir(parents=True, mode=int(params.get("mode", 0o755)))
                state["created"].append(str(target))
        elif operation == "ensure_group":
            name = str(params["name"])
            if not name or any(
                char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in name
            ):
                raise UmzugError("invalid group name")
            try:
                grp.getgrnam(name)
            except KeyError:
                run([str(self._bound_executable("groupadd", state)), "--system", "--", name])
        elif operation in {"disable_service", "enable_service"}:
            name = str(params["name"])
            if not name or any(
                char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@_.-" for char in name
            ):
                raise UmzugError("invalid service name")
            init = str(params.get("init", "systemd"))
            if init == "openrc" and operation == "disable_service":
                run([str(self._bound_executable("rc-service", state)), name, "stop"], check=False)
                run([str(self._bound_executable("rc-update", state)), "del", name], check=False)
            elif init == "openrc" and operation == "enable_service":
                run([str(self._bound_executable("rc-update", state)), "add", name, "default"])
                run([str(self._bound_executable("rc-service", state)), name, "start"])
            elif init != "systemd":
                raise UmzugError(f"unsupported init-system service action: {init}")
            elif operation == "disable_service":
                argv = ["systemctl", "disable", "--now", name]
                argv[0] = str(self._bound_executable("systemctl", state))
                if params.get("mask", False):
                    run(argv, check=False)
                    run([str(self._bound_executable("systemctl", state)), "mask", name])
                else:
                    run(argv)
            else:
                run([str(self._bound_executable("systemctl", state)), "enable", "--now", name])
        elif operation == "run_command":
            argv = params.get("argv")
            # Action.validate() resolves the ID to an exact argv template.  do
            # not reintroduce a basename allowlist here: allowing a program
            # such as nft/systemctl/apt with arbitrary arguments is equivalent
            # to allowing arbitrary privileged mutation.
            action.validate()
            if not isinstance(argv, list) or not argv:
                raise UmzugError(f"command action lost its typed argv: {action.id}")
            command = [str(item) for item in argv]
            required = self._required_inputs(params)
            for source, expected in required.items():
                raw_source = str(source)
                if raw_source not in command:
                    raise UmzugError(f"required action input is not present in the reviewed argv: {source}")
                snapshot = str(self._snapshot_required_input(source, expected))
                command = [snapshot if item == raw_source else item for item in command]
            command[0] = str(self._bound_executable(command[0], state))
            if params.get("network_policy") == "forbidden":
                command = [str(self._bound_executable("unshare", state)), "--net", "--", *command]
            elif params.get("network_policy") not in {None, "local", "forbidden"}:
                raise UmzugError("network-permitted commands are reserved for the explicit final VPN step")
            run(command, capture=bool(params.get("capture", True)), timeout=int(params.get("timeout", 300)))
            if action.id.startswith("packages.debian.") and "--" in command:
                packages = set(command[command.index("--") + 1 :])
                package_tools = {
                    "curl": ("curl",),
                    "iproute2": ("ip", "ss"),
                    "rfkill": ("rfkill",),
                    "systemd-resolved": ("resolvectl",),
                    "wireguard-tools": ("wg",),
                }
                for package, names in package_tools.items():
                    if package in packages:
                        for name in names:
                            self._bound_executable(name, state, allow_initial_bind=True)
            if action.id == "mullvad-offline-install":
                self._bound_executable("mullvad", state, allow_initial_bind=True)
                post_install = params.get("post_install_argvs")
                if not isinstance(post_install, list):
                    raise UmzugError("Mullvad install lost its immediate activation sequence")
                for reviewed in post_install:
                    if not isinstance(reviewed, list) or not reviewed:
                        raise UmzugError("Mullvad install has a malformed activation command")
                    activation = [str(item) for item in reviewed]
                    activation[0] = str(self._bound_executable(activation[0], state))
                    run(activation, timeout=120)
        elif operation == "checkpoint":
            requirement = params.get("required_evidence") or params.get("manual_verification") or params.get("required")
            if requirement:
                if not sys.stdin.isatty():
                    raise UmzugError(f"manual checkpoint {action.id} requires local-console evidence entry")
                if params.get("evidence_kind") == "nixos-system-store-path":
                    try:
                        previous_system = NIXOS_SYSTEM_PROFILE.resolve(strict=True)
                    except OSError as exc:
                        raise UmzugError("current NixOS system profile cannot be resolved safely") from exc
                    commands = params.get("commands")
                    if not isinstance(commands, list) or not all(isinstance(item, str) and item for item in commands):
                        raise UmzugError("NixOS checkpoint lost its reviewed command sequence")
                    print("Manuell lokal in dieser Reihenfolge ausführen:")
                    for command in commands:
                        print(f"  {terminal_safe(command)}")
                    answer = input(
                        "Exakten getesteten und mit `nixos-rebuild boot` gesetzten /nix/store-Systempfad eingeben: "
                    ).strip()
                    if not NIXOS_STORE_SYSTEM_RE.fullmatch(answer):
                        raise UmzugError("NixOS checkpoint lacks a canonical tested store path")
                    expected_system = Path(answer)
                    try:
                        expected_info = expected_system.stat()
                        boot_default = NIXOS_SYSTEM_PROFILE.resolve(strict=True)
                    except OSError as exc:
                        raise UmzugError("tested NixOS generation cannot be resolved safely") from exc
                    if (
                        not stat.S_ISDIR(expected_info.st_mode)
                        or expected_info.st_uid != 0
                        or stat.S_IMODE(expected_info.st_mode) & 0o022
                        or boot_default != expected_system
                        or previous_system == expected_system
                    ):
                        raise UmzugError("nixos-rebuild boot did not bind a new root-owned tested generation")
                    state.setdefault("manual_attestations", {})[action.id] = {
                        "requirement": str(requirement),
                        "nixos_system_store_path": str(expected_system),
                        "previous_nixos_system_store_path": str(previous_system),
                        "time": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
                    }
                else:
                    phrase = f"VERIFIED:{action.id}"
                    answer = input(
                        f"Manuelle Voraussetzung: {terminal_safe(requirement)}\n"
                        f"Erst nach eigener Prüfung exakt {phrase!r} eingeben: "
                    )
                    if answer != phrase:
                        raise UmzugError(f"manual checkpoint evidence declined: {action.id}")
                    state.setdefault("manual_attestations", {})[action.id] = {
                        "requirement": str(requirement),
                        "time": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
                    }
                self.store.save(state)
            return
        else:
            raise UmzugError(f"executor does not implement operation: {operation}")
        self.store.save(state)

    def _verify_post_reboot(self, action: Action, state: dict[str, Any]) -> None:
        check = action.post_reboot_verify
        kind = check.get("kind")
        if kind == "boot_id_changed":
            return
        if kind == "modules_not_loaded":
            modules = check.get("modules")
            if (
                not isinstance(modules, list)
                or not modules
                or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", item) for item in modules)
            ):
                raise UmzugError("invalid post-reboot module verification")
            try:
                loaded = {
                    line.split()[0].replace("-", "_")
                    for line in PROC_MODULES.read_text(encoding="utf-8").splitlines()
                    if line.split()
                }
            except (OSError, UnicodeError) as exc:
                raise UmzugError("post-reboot loaded-module state is unavailable") from exc
            try:
                loaded.update(entry.name.replace("-", "_") for entry in SYS_MODULE_ROOT.iterdir())
            except OSError as exc:
                raise UmzugError("post-reboot /sys/module state is unavailable") from exc
            forbidden = {name.replace("-", "_") for name in modules}
            observed = sorted(loaded.intersection(forbidden))
            if observed:
                raise UmzugError(
                    "post-reboot verification failed; forbidden modules remain loaded: " + ", ".join(observed)
                )
            if check.get("ipv6_disabled"):
                paths = [
                    Path("/proc/sys/net/ipv6/conf/all/disable_ipv6"),
                    Path("/proc/sys/net/ipv6/conf/default/disable_ipv6"),
                    Path("/proc/sys/net/ipv6/conf/lo/disable_ipv6"),
                ]
                try:
                    if any(path.read_text(encoding="ascii").strip() != "1" for path in paths):
                        raise UmzugError("post-reboot IPv6 sysctl policy is not effective")
                    addresses = Path("/proc/net/if_inet6")
                    if addresses.exists() and addresses.read_text(encoding="ascii").strip():
                        raise UmzugError("post-reboot IPv6 addresses remain configured")
                except (OSError, UnicodeError) as exc:
                    raise UmzugError("post-reboot IPv6 state cannot be proven") from exc
            return
        if kind == "manual_attestation":
            requirement = check.get("requirement")
            if not isinstance(requirement, str) or not requirement:
                raise UmzugError("invalid manual post-reboot verification requirement")
            if not sys.stdin.isatty():
                raise UmzugError("manual post-reboot verification requires the local console")
            phrase = f"POST-REBOOT-VERIFIED:{action.id}"
            answer = input(
                f"Post-Reboot-Prüfung: {terminal_safe(requirement)}\n"
                f"Erst nach eigener Prüfung exakt {phrase!r} eingeben: "
            )
            if answer != phrase:
                raise UmzugError(f"post-reboot verification declined: {action.id}")
            state.setdefault("manual_attestations", {})[f"post-reboot:{action.id}"] = {
                "requirement": requirement,
                "time": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
            }
            self.store.save(state)
            return
        if kind == "nixos_booted_store_path":
            attestations = state.get("manual_attestations")
            evidence = attestations.get(action.id) if isinstance(attestations, dict) else None
            expected_raw = evidence.get("nixos_system_store_path") if isinstance(evidence, dict) else None
            previous_raw = evidence.get("previous_nixos_system_store_path") if isinstance(evidence, dict) else None
            if (
                not isinstance(expected_raw, str)
                or not NIXOS_STORE_SYSTEM_RE.fullmatch(expected_raw)
                or not isinstance(previous_raw, str)
                or not NIXOS_STORE_SYSTEM_RE.fullmatch(previous_raw)
            ):
                raise UmzugError("NixOS reboot checkpoint lacks bound generation evidence")
            try:
                booted = NIXOS_CURRENT_SYSTEM.resolve(strict=True)
                previous = Path(previous_raw).resolve(strict=True)
            except OSError as exc:
                raise UmzugError("NixOS booted or recovery generation is unavailable") from exc
            if booted != Path(expected_raw) or previous == booted:
                raise UmzugError("post-reboot NixOS generation differs from the tested boot generation")
            return
        raise UmzugError(f"unsupported post-reboot verification for {action.id}: {kind}")

    def _verify(self, action: Action, state: dict[str, Any] | None = None) -> None:
        executable = (lambda name: self._bound_executable(name, state)) if state is not None else _trusted_executable
        if action.operation == "write_file":
            target = self._map_path(str(action.parameters["path"]))
            self._assert_safe_target(target, regular_if_exists=True)
            content = str(action.parameters["content"]).encode("utf-8")
            mode = int(action.parameters.get("mode", 0o644))
            if not self._write_matches(target, content, mode):
                raise UmzugError(f"verification failed for {action.id}: managed file content or mode")
        check = action.verify
        if not check:
            return
        kind = check.get("kind")
        if kind == "executable_available":
            name = check.get("name")
            if not isinstance(name, str) or name != action.parameters.get("name"):
                raise UmzugError("executable verifier is not bound to its action")
            executable(name)
        elif kind == "file_sha256":
            target = self._map_path(str(check["path"]))
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if digest != check["sha256"]:
                raise UmzugError(f"verification failed for {action.id}: content digest")
        elif kind == "package_status":
            manager = check.get("manager")
            packages = check.get("packages")
            if manager != "dpkg" or not isinstance(packages, list) or not packages:
                raise UmzugError("typed package verifier has an invalid schema")
            result = run(
                [
                    str(executable("dpkg-query")),
                    "--show",
                    "--showformat=${binary:Package}\t${db:Status-Abbrev}\n",
                    *packages,
                ]
            )
            installed: set[str] = set()
            for line in result.stdout.decode("utf-8", "strict").splitlines():
                fields = line.split("\t", 1)
                if len(fields) == 2 and fields[1].startswith("ii"):
                    installed.add(fields[0].split(":", 1)[0])
            missing = sorted(set(packages) - installed)
            if missing:
                raise UmzugError(f"verification failed for {action.id}: packages not installed: " + ", ".join(missing))
        elif kind == "mullvad_version":
            result = run([str(executable("mullvad")), "version"], check=False, timeout=30)
            if result.returncode != 0 or not result.stdout.strip():
                raise UmzugError("verification failed: installed Mullvad CLI has no version")
            manager = check.get("manager")
            package = check.get("package")
            expected_version = check.get("version")
            expected_architecture = check.get("architecture")
            if package != "mullvad-vpn" or not all(
                isinstance(value, str) and value for value in (expected_version, expected_architecture)
            ):
                raise UmzugError("Mullvad package identity verifier is invalid")
            if manager == "dpkg":
                identity = (
                    run(
                        [
                            str(executable("dpkg-query")),
                            "--show",
                            "--showformat=${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\n",
                            package,
                        ],
                        timeout=30,
                    )
                    .stdout.decode("utf-8", "strict")
                    .splitlines()
                )
                fields = identity[0].split("\t") if len(identity) == 1 else []
                if (
                    len(fields) != 4
                    or fields[0].split(":", 1)[0] != package
                    or fields[1] != expected_version
                    or fields[2] != expected_architecture
                    or not fields[3].startswith("ii")
                ):
                    raise UmzugError(
                        "installed Mullvad package differs from the artifact-bound name/version/architecture"
                    )
                integrity = run(
                    [str(executable("dpkg")), "--verify", package],
                    check=False,
                    timeout=120,
                )
            elif manager == "rpm":
                identity = (
                    run(
                        [
                            str(executable("rpm")),
                            "--query",
                            "--queryformat",
                            "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n",
                            package,
                        ],
                        timeout=30,
                    )
                    .stdout.decode("utf-8", "strict")
                    .splitlines()
                )
                expected = f"{package}\t{expected_version}\t{expected_architecture}"
                if identity != [expected]:
                    raise UmzugError(
                        "installed Mullvad package differs from the artifact-bound name/version/architecture"
                    )
                integrity = run(
                    [str(executable("rpm")), "--verify", package],
                    check=False,
                    timeout=120,
                )
            else:
                raise UmzugError("Mullvad package identity verifier has an unsupported manager")
            if integrity.returncode != 0 or integrity.stdout.strip():
                raise UmzugError("installed Mullvad files differ from the package-manager integrity database")
            group = check.get("management_group")
            if not isinstance(group, str):
                raise UmzugError("Mullvad package verifier has no bound management group")
            if state is None:
                raise UmzugError("Mullvad live management verifier requires executable receipts")

            class ReceiptBoundTools:
                def path(self, name: str) -> str:
                    return str(executable(name))

            from .vpn import _verify_management_restriction

            _verify_management_restriction(group, ReceiptBoundTools())
        elif kind == "restricted_group":
            name = check.get("name")
            if not isinstance(name, str) or name != action.parameters.get("name"):
                raise UmzugError("restricted-group verifier is not bound to its action")
            try:
                group_entry = grp.getgrnam(name)
            except KeyError as exc:
                raise UmzugError(f"dedicated Mullvad management group does not exist: {name}") from exc
            delegated = sorted(
                set(member for member in group_entry.gr_mem if member != "root")
                | {
                    entry.pw_name
                    for entry in pwd.getpwall()
                    if entry.pw_gid == group_entry.gr_gid and entry.pw_uid != 0
                }
            )
            if delegated:
                raise UmzugError(
                    "Mullvad management group delegates daemon control to non-root users: " + ", ".join(delegated)
                )
        elif kind == "service_enabled":
            name = str(check["name"])
            if check.get("init") == "openrc":
                if check.get("runlevel") != "default":
                    raise UmzugError("typed OpenRC persistence verifier has an invalid runlevel")
                result = run(
                    [str(executable("rc-update")), "show", "default"],
                    check=False,
                )
                enabled = any(
                    line.split() and line.split()[0] == name
                    for line in result.stdout.decode(errors="replace").splitlines()
                )
                if result.returncode != 0 or not enabled:
                    raise UmzugError(f"verification failed for {action.id}: OpenRC service is not persistent: {name}")
            elif check.get("init") == "systemd":
                systemctl = str(executable("systemctl"))
                for mode in ("is-enabled", "is-active"):
                    result = run([systemctl, mode, name], check=False)
                    if result.returncode != 0:
                        raise UmzugError(
                            f"verification failed for {action.id}: service is not {mode.removeprefix('is-')}: {name}"
                        )
            else:
                raise UmzugError("typed service-enabled verifier has an invalid init system")
        elif kind == "sysctl_effective":
            values = check.get("values")
            if not isinstance(values, dict) or not values:
                raise UmzugError("typed sysctl verifier has no expected values")
            for key, expected in values.items():
                if not isinstance(key, str) or not re.fullmatch(r"[a-z0-9_.]+", key) or not isinstance(expected, str):
                    raise UmzugError("typed sysctl verifier contains an invalid key/value")
                path = PROC_SYS_ROOT.joinpath(*key.split("."))
                try:
                    observed = path.read_text(encoding="ascii").strip()
                except (OSError, UnicodeError) as exc:
                    raise UmzugError(f"effective sysctl value is unavailable: {key}") from exc
                if observed != expected:
                    raise UmzugError(f"verification failed for {action.id}: effective sysctl differs: {key}")
        elif kind == "service_disabled":
            name = str(check["name"])
            init = str(check.get("init", "systemd"))
            if init == "openrc":
                result = run([str(executable("rc-update")), "show"], check=False)
                enabled = any(
                    line.split() and line.split()[0] == name
                    for line in result.stdout.decode(errors="replace").splitlines()
                )
                active_result = run([str(executable("rc-service")), name, "status"], check=False)
                active = active_result.returncode == 0
            else:
                systemctl = str(executable("systemctl"))
                result = run([systemctl, "is-enabled", name], check=False)
                enabled = result.returncode == 0
                active_result = run([systemctl, "is-active", name], check=False)
                active = active_result.returncode == 0
            if enabled:
                raise UmzugError(f"verification failed: service remains enabled: {name}")
            if active:
                raise UmzugError(f"verification failed: service remains active: {name}")
        elif kind == "radio_blocked":
            result = run([str(executable("rfkill")), "list"])
            output = result.stdout.decode(errors="replace").lower()
            if "soft blocked: no" in output:
                raise UmzugError("verification failed: at least one radio remains soft-unblocked")
        elif kind == "host_firewall":
            interfaces = check.get("interfaces")
            if not isinstance(interfaces, list) or any(not isinstance(item, str) for item in interfaces):
                raise UmzugError("invalid host-firewall verification interfaces")
            result = run([str(executable("nft")), "--json", "list", "table", "inet", "umzug_host"])
            verify_host_firewall_json(
                result.stdout,
                interfaces,
                ipv6_enabled=bool(check.get("ipv6_enabled", False)),
            )
        elif kind == "offline_guard":
            result = run([str(executable("nft")), "--json", "list", "table", "inet", "umzug_offline_guard"])
            verify_offline_guard_json(result.stdout)
        else:
            raise UmzugError(f"unsupported verification type: {kind}")


def rollback(
    state_root: Path,
    *,
    system_root: Path = Path("/"),
    dry_run: bool = False,
    network_recovery_verified: bool = False,
) -> None:
    root = system_root.resolve()
    state_storage: dict[str, Any] | None = None
    if not dry_run and root == Path("/"):
        require_proven_local_console("rollback")
        if network_recovery_verified is not True:
            raise UmzugError("live-system rollback requires a positively verified umzug network recovery first")
        state_storage = observe_persistent_state_storage(state_root)
    store = StateStore(state_root, create=not dry_run)
    state = store.load()
    if state_storage is not None:
        require_matching_state_storage(state.get("state_storage"), state_storage)
    require_root(dry_run=dry_run or system_root != Path("/"))
    backups = state.get("backups", {})
    created = state.get("created", [])
    if not isinstance(backups, dict) or not isinstance(created, list):
        raise UmzugError("rollback checkpoint structure is invalid")
    validated: list[tuple[Path, dict[str, Any], Path | None]] = []
    # validate every source and destination before deleting even the first live
    # path. a damaged or legacy unhashed backup aborts the whole rollback.
    for original, row in reversed(list(backups.items())):
        if not isinstance(original, str) or not isinstance(row, dict):
            raise UmzugError("rollback checkpoint entry is invalid")
        target = Path(original).absolute()
        if not contained(root, target) or target == root:
            raise UmzugError(f"backup target escapes system root: {original}")
        backup: Path | None = None
        if row.get("existed") is True:
            expected = row.get("sha256")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise UmzugError("rollback backup lacks a valid integrity digest")
            backup = Path(str(row.get("backup"))).absolute()
            if backup.parent != store.backups.absolute() or len(backup.name) != 64:
                raise UmzugError(f"backup source escapes checkpoint store: {backup}")
            if not os.path.lexists(backup) or _backup_tree_digest(backup) != expected:
                raise UmzugError(f"rollback backup integrity verification failed: {backup}")
        elif row.get("existed") is not False or row.get("backup") is not None:
            raise UmzugError("rollback non-existing-path receipt is invalid")
        validated.append((target, row, backup))
    validated_created: list[Path] = []
    for value in reversed(created):
        if not isinstance(value, str):
            raise UmzugError("created checkpoint path is invalid")
        path = Path(value).absolute()
        if not contained(root, path) or path == root:
            raise UmzugError(f"created checkpoint path escapes system root: {path}")
        validated_created.append(path)

    for target, row, backup in validated:
        print(f"rollback: {target}")
        if dry_run:
            continue
        if os.path.lexists(target):
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
        if row["existed"]:
            assert backup is not None
            target.parent.mkdir(parents=True, exist_ok=True)
            if backup.is_symlink():
                target.symlink_to(os.readlink(backup))
            elif backup.is_dir():
                shutil.copytree(backup, target, symlinks=True)
            else:
                shutil.copy2(backup, target, follow_symlinks=False)
    for path in validated_created:
        if dry_run or not os.path.lexists(path):
            continue
        if path.is_dir() and not path.is_symlink():
            with contextlib.suppress(OSError):
                path.rmdir()
        else:
            path.unlink()
    if not dry_run:
        state["rolled_back_at"] = dt.datetime.now(dt.UTC).isoformat()
        store.save(state)


def _boot_id() -> str | None:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None
    return _canonical_boot_id(value)


def _canonical_boot_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    canonical = str(parsed)
    return canonical if value.strip().lower() == canonical else None


def _require_boot_id(value: object, label: str) -> str:
    canonical = _canonical_boot_id(value)
    if canonical is None:
        raise UmzugError(f"{label} boot ID is unavailable or not a canonical UUID")
    return canonical
