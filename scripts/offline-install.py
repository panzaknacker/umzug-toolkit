#!/usr/bin/python3
"""install the umzug wheel without pip or ensurepip.

this bootstrap is intentionally limited to the one pure-python wheel produced
by this source tree.  it validates the independently supplied SHA-256, the ZIP
container, wheel metadata and every RECORD entry before creating a private
staging venv.  publication is atomic and refuses an existing runtime.
"""

from __future__ import annotations

import sys as _bootstrap_sys

if not _bootstrap_sys.flags.isolated:
    _bootstrap_sys.stderr.write("offline-install: invoke exactly with a trusted Python and -I\n")
    raise SystemExit(2)

import argparse
import ast
import base64
import binascii
import csv
import ctypes
import errno
import hashlib
import hmac
import io
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import venv
import zipfile


NAME = "umzug_toolkit"
PROJECT = "umzug-toolkit"
VERSION = "0.2.0rc1"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
DATA_SCRIPT = f"{NAME}-{VERSION}.data/scripts/umzug-setup-root"
ENTRY_POINTS = b"[console_scripts]\numzug-pack=umzug.pack_cli:main\n"
PRODUCTION_RUNTIME = Path("/opt/umzug/runtime")
MAX_WHEEL_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 256
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_EXPANDED_BYTES = 16 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
READ_CHUNK = 1024 * 1024
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_MEMBER = re.compile(r"[A-Za-z0-9._/-]+\Z")
RENAME_NOREPLACE = 1
AT_FDCWD = -100


class InstallError(RuntimeError):
    """a fail-closed bootstrap error."""


def _lexists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _stable_snapshot(path: Path, expected_sha256: str, *, production: bool) -> bytes:
    if not HEX_SHA256.fullmatch(expected_sha256):
        raise InstallError("expected wheel SHA-256 must be exactly 64 lowercase hexadecimal characters")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise InstallError(f"cannot safely open wheel: {path}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise InstallError("wheel must be a single-link, non-symlink regular file")
        if before.st_size <= 0 or before.st_size > MAX_WHEEL_BYTES:
            raise InstallError("wheel size is outside the bootstrap limit")
        if production and (
            before.st_uid != 0 or stat.S_IMODE(before.st_mode) & 0o022 or stat.S_IMODE(before.st_mode) & 0o7000
        ):
            raise InstallError("production wheel must be root-owned and not group/world writable")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(READ_CHUNK, remaining))
            if not chunk:
                raise InstallError("wheel became short while it was snapshotted")
            chunks.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise InstallError("wheel grew while it was snapshotted")
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
            raise InstallError("wheel changed while it was snapshotted")
        actual = digest.hexdigest()
        if actual != expected_sha256:
            raise InstallError(f"wheel SHA-256 mismatch: expected {expected_sha256}, got {actual}")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _safe_member_name(name: str) -> PurePosixPath:
    if not name or "\\" in name or "\x00" in name or not SAFE_MEMBER.fullmatch(name):
        raise InstallError(f"unsafe wheel member name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or path.as_posix() != name or any(part in {"", ".", ".."} for part in path.parts):
        raise InstallError(f"wheel member escapes its root: {name!r}")
    return path


def _decode_record_digest(value: str) -> bytes:
    if not value.startswith("sha256="):
        raise InstallError("RECORD permits only sha256 digests")
    encoded = value.removeprefix("sha256=")
    if not encoded or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise InstallError("RECORD contains an invalid base64url digest")
    try:
        decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InstallError("RECORD contains an invalid base64url digest") from exc
    if len(decoded) != hashlib.sha256().digest_size:
        raise InstallError("RECORD digest is not SHA-256 sized")
    return decoded


def _parse_fields(payload: bytes, label: str) -> dict[str, str]:
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise InstallError(f"{label} is not valid UTF-8") from exc
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line[:1].isspace() or ":" not in line:
            raise InstallError(f"{label} contains unsupported folded or malformed metadata")
        key, value = line.split(":", 1)
        if key in fields:
            raise InstallError(f"{label} contains duplicate field {key}")
        fields[key] = value.strip()
    return fields


def _validate_metadata(files: dict[str, bytes]) -> None:
    metadata = _parse_fields(files[f"{DIST_INFO}/METADATA"], "METADATA")
    required_metadata = {
        "Metadata-Version": "2.1",
        "Name": PROJECT,
        "Version": VERSION,
        "Summary": "Offline-first zero-trust Linux migration toolkit",
        "Requires-Python": ">=3.11",
        "License": "GPL-3.0-or-later",
    }
    if metadata != required_metadata:
        raise InstallError("METADATA does not exactly describe the expected toolkit release")
    wheel = _parse_fields(files[f"{DIST_INFO}/WHEEL"], "WHEEL")
    required_wheel = {
        "Wheel-Version": "1.0",
        "Generator": "umzug_build",
        "Root-Is-Purelib": "true",
        "Tag": "py3-none-any",
    }
    if wheel != required_wheel:
        raise InstallError("wheel metadata does not describe the expected pure-Python artifact")
    if files[f"{DIST_INFO}/entry_points.txt"] != ENTRY_POINTS:
        raise InstallError("wheel exposes an unexpected entry point")


def _validate_record(files: dict[str, bytes]) -> None:
    record_name = f"{DIST_INFO}/RECORD"
    try:
        text = files[record_name].decode("utf-8", "strict")
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise InstallError("RECORD is not valid CSV/UTF-8") from exc
    records: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or not row[0] or row[0] in records:
            raise InstallError("RECORD contains a malformed or duplicate row")
        _safe_member_name(row[0])
        records[row[0]] = (row[1], row[2])
    if set(records) != set(files):
        raise InstallError("RECORD does not cover the wheel members exactly")
    if records[record_name] != ("", ""):
        raise InstallError("RECORD must leave its own digest and size empty")
    for name, payload in files.items():
        if name == record_name:
            continue
        digest_text, size_text = records[name]
        if not size_text.isascii() or not size_text.isdecimal() or int(size_text) != len(payload):
            raise InstallError(f"RECORD size mismatch for {name}")
        expected = _decode_record_digest(digest_text)
        if not hmac.compare_digest(expected, hashlib.sha256(payload).digest()):
            raise InstallError(f"RECORD digest mismatch for {name}")


def _read_validated_wheel(snapshot: bytes) -> dict[str, bytes]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(snapshot), "r")
    except (OSError, zipfile.BadZipFile) as exc:
        raise InstallError("wheel is not a valid ZIP archive") from exc
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_MEMBERS:
            raise InstallError("wheel member count is outside the bootstrap limit")
        names: set[str] = set()
        expanded = 0
        for info in infos:
            path = _safe_member_name(info.filename)
            if info.filename in names:
                raise InstallError(f"duplicate wheel member: {info.filename}")
            names.add(info.filename)
            if info.is_dir() or info.flag_bits & 0x1:
                raise InstallError("wheel directories and encrypted members are forbidden")
            if info.create_system != 3 or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise InstallError("wheel member has an unsupported platform or compression method")
            unix_mode = info.external_attr >> 16
            if stat.S_IFMT(unix_mode) != stat.S_IFREG:
                raise InstallError("wheel contains a symlink or special file")
            expected_mode = 0o755 if info.filename == DATA_SCRIPT else 0o644
            if stat.S_IMODE(unix_mode) != expected_mode:
                raise InstallError(f"unexpected wheel mode for {info.filename}")
            if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES or info.compress_size < 0:
                raise InstallError("wheel member exceeds its size limit")
            if info.file_size > info.compress_size * MAX_COMPRESSION_RATIO + READ_CHUNK:
                raise InstallError("wheel member exceeds the compression-ratio limit")
            expanded += info.file_size
            if expanded > MAX_EXPANDED_BYTES:
                raise InstallError("wheel expanded size exceeds the bootstrap limit")
            parts = path.parts
            allowed = (
                (
                    len(parts) == 2
                    and parts[0] == "umzug"
                    and re.fullmatch(r"(?:__init__|[a-z][a-z0-9_]*)\.py", parts[1]) is not None
                )
                or (
                    len(parts) == 2
                    and parts[0] == DIST_INFO
                    and parts[1] in {"METADATA", "WHEEL", "entry_points.txt", "RECORD"}
                )
                or info.filename == DATA_SCRIPT
            )
            if not allowed:
                raise InstallError(f"unexpected wheel member: {info.filename}")
        required = {
            "umzug/__init__.py",
            "umzug/pack_cli.py",
            "umzug/setup_cli.py",
            f"{DIST_INFO}/METADATA",
            f"{DIST_INFO}/WHEEL",
            f"{DIST_INFO}/entry_points.txt",
            f"{DIST_INFO}/RECORD",
            DATA_SCRIPT,
        }
        if not required.issubset(names):
            raise InstallError("wheel is missing a required toolkit member")
        files: dict[str, bytes] = {}
        try:
            for info in infos:
                payload = archive.read(info)
                if len(payload) != info.file_size:
                    raise InstallError(f"short decompression for {info.filename}")
                files[info.filename] = payload
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise InstallError("wheel decompression or CRC verification failed") from exc
    _validate_metadata(files)
    _validate_record(files)
    for name, payload in files.items():
        if name.startswith("umzug/") and name.endswith(".py"):
            try:
                ast.parse(payload.decode("utf-8", "strict"), filename=name)
            except (SyntaxError, UnicodeDecodeError) as exc:
                raise InstallError(f"toolkit module is not valid UTF-8 Python: {name}") from exc
    return files


def _validate_component(path: Path, uid: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError(f"required trusted path is unavailable: {path}") from exc
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink() or info.st_uid != uid:
        raise InstallError(f"trusted path is not an owned, non-symlink directory: {path}")
    if stat.S_IMODE(info.st_mode) & 0o022 or stat.S_IMODE(info.st_mode) & 0o7000:
        raise InstallError(f"trusted path is group/world writable or has special bits: {path}")


def _validate_bootstrap_file(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise InstallError("offline installer must be a root-owned staged file") from exc
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise InstallError("offline installer must be a single-link regular file")
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022 or stat.S_IMODE(info.st_mode) & 0o7000:
        raise InstallError("offline installer must be root-owned and not writable by non-root")
    current = path.parent
    while True:
        _validate_component(current, 0)
        if current == current.parent:
            break
        current = current.parent


def _ensure_parent(runtime: Path, *, production: bool) -> Path:
    parent = runtime.parent
    uid = 0 if production else os.geteuid()
    if production:
        _validate_component(Path("/"), 0)
        if not _lexists(Path("/opt")):
            os.mkdir("/opt", 0o755)
            root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(root_fd)
            finally:
                os.close(root_fd)
        _validate_component(Path("/opt"), 0)
    parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    _validate_component(parent, uid)
    if _lexists(runtime):
        raise InstallError(f"runtime already exists; refusing overwrite: {runtime}")
    return parent


def _write_new(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise InstallError(f"short write while installing {path}")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _normalize_tree(root: Path, *, uid: int) -> None:
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        if base.is_symlink():
            raise InstallError("staged runtime contains a directory symlink")
        os.chmod(base, 0o755)
        if os.geteuid() == 0:
            os.chown(base, uid, 0)
        for name in [*dirnames, *filenames]:
            path = base / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise InstallError(f"staged runtime contains a symlink: {path}")
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise InstallError(f"staged runtime contains a special or hardlinked file: {path}")
            executable = path.parent == root / "bin" and path.name in {
                "python",
                "python3",
                f"python{sys.version_info.major}.{sys.version_info.minor}",
                "umzug-pack",
                "umzug-setup-root",
            }
            os.chmod(path, 0o755 if executable else 0o644)
            if os.geteuid() == 0:
                os.chown(path, uid, 0)


def _sync_tree(root: Path) -> None:
    directories: list[Path] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        directories.append(base)
        for name in [*dirnames, *filenames]:
            path = base / name
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
                raise InstallError(f"cannot synchronize unsafe staged entry: {path}")
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                    raise InstallError(f"staged entry changed before synchronization: {path}")
                os.fsync(fd)
            finally:
                os.close(fd)
    for directory in reversed(directories):
        fd = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise InstallError("Linux renameat2 is required for no-overwrite runtime publication")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise InstallError(f"runtime appeared concurrently; refusing overwrite: {destination}")
        raise InstallError(f"atomic runtime publication failed: {os.strerror(code)}")


def _install(files: dict[str, bytes], runtime: Path, *, production: bool) -> None:
    parent = _ensure_parent(runtime, production=production)
    staging = Path(tempfile.mkdtemp(prefix=".runtime-staging-", dir=parent))
    published = False
    try:
        venv.EnvBuilder(with_pip=False, symlinks=False, clear=False).create(staging)
        lib64 = staging / "lib64"
        if lib64.is_symlink():
            lib64.unlink()
        elif _lexists(lib64):
            raise InstallError("unexpected non-symlink lib64 exists in staged venv")
        purelib = staging / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
        purelib.mkdir(parents=True, mode=0o755, exist_ok=True)
        for name, payload in files.items():
            if name == DATA_SCRIPT:
                destination = staging / "bin" / "umzug-setup-root"
                mode = 0o755
            else:
                destination = purelib.joinpath(*PurePosixPath(name).parts)
                mode = 0o644
            _write_new(destination, payload, mode)
        shebang = f"#!{runtime}/bin/python\n"
        launcher = (
            shebang
            + "from umzug.pack_cli import main\n"
            + "if __name__ == '__main__':\n"
            + "    raise SystemExit(main())\n"
        ).encode("utf-8")
        _write_new(staging / "bin" / "umzug-pack", launcher, 0o755)
        uid = 0 if production else os.geteuid()
        _normalize_tree(staging, uid=uid)
        _sync_tree(staging)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            _rename_noreplace(staging, runtime)
            published = True
            try:
                os.fsync(parent_fd)
            except OSError as sync_error:
                try:
                    _rename_noreplace(runtime, staging)
                    published = False
                    os.fsync(parent_fd)
                except (InstallError, OSError) as rollback_error:
                    published = True
                    raise InstallError(
                        "runtime was published but directory durability could not be proven; do not use it"
                    ) from rollback_error
                raise InstallError("runtime publication was rolled back after directory fsync failure") from sync_error
        finally:
            os.close(parent_fd)
    finally:
        if not published and _lexists(staging):
            shutil.rmtree(staging)


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install the verified umzug wheel without pip or network access.")
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument(
        "--test-root",
        type=Path,
        help="TESTS ONLY: install below this owned private directory instead of /opt/umzug/runtime",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = _arguments(argv)
        if sys.version_info < (3, 11):
            raise InstallError("Python 3.11 or newer is required")
        production = args.test_root is None
        if production:
            if os.geteuid() != 0:
                raise InstallError("production offline installation requires root")
            _validate_bootstrap_file(Path(__file__).absolute())
            runtime = PRODUCTION_RUNTIME
        else:
            test_root = args.test_root.expanduser().resolve(strict=True)
            _validate_component(test_root, os.geteuid())
            runtime = test_root / "opt" / "umzug" / "runtime"
            if runtime == PRODUCTION_RUNTIME:
                raise InstallError("--test-root may never address the production runtime")
        snapshot = _stable_snapshot(args.wheel.expanduser().absolute(), args.expected_sha256, production=production)
        files = _read_validated_wheel(snapshot)
        _install(files, runtime, production=production)
        print(f"installed verified umzug runtime: {runtime}")
        print(f"wheel sha256: {args.expected_sha256}")
        return 0
    except (InstallError, OSError, ValueError) as exc:
        print(f"offline-install: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
