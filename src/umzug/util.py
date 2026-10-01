from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import stat
import subprocess
import tempfile
import time
from typing import Any, Iterable, Iterator, Sequence


class UmzugError(RuntimeError):
    """expected, user-facing failure."""


SECRET_KEY_RE = re.compile(
    r"(?i)(account|authorization|cookie|credential|pass(word|phrase)?|private[_-]?key|secret|token)"
)
SECRET_VALUE_RE = [
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"\b[0-9]{16}\b"),  # mullvad account number shape; never log it.
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"(?i)\b(?:password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]{8,}"),
]


def _open_directory_chain(path: Path, *, create: bool) -> int:
    """open an absolute directory through anchored, no-symlink components."""
    absolute = path.absolute()
    if not absolute.is_absolute():
        raise UmzugError("audit directory must be absolute")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in absolute.parts[1:]:
            if part in {"", ".", ".."}:
                raise UmzugError("unsafe audit directory component")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_directory_chain(path: Path, *, create: bool = False, mode: int = 0o700) -> int:
    """return an fd for an absolute directory without following any component.

    newly created components are deliberately private.  ``mode`` may only make
    them stricter; callers can widen an already anchored directory explicitly.
    """

    if mode & 0o077:
        raise UmzugError("new anchored directories must not be group/world accessible")
    # _open_directory_chain creates with 0700.  tighten the final component if
    # requested, while it is still referred to by the returned descriptor.
    fd = _open_directory_chain(path, create=create)
    if create and mode != 0o700:
        os.fchmod(fd, mode)
    return fd


def rename_noreplace_at(
    source_dir_fd: int,
    source_name: str,
    target_dir_fd: int,
    target_name: str,
) -> None:
    """atomically move one entry while refusing every existing target."""

    for value in (source_name, target_name):
        if not value or value in {".", ".."} or "/" in value or "\x00" in value:
            raise UmzugError("atomic publish needs safe single-component names")
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as exc:
        raise UmzugError("libc lacks renameat2; atomic no-overwrite publish is unavailable") from exc
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            source_dir_fd,
            os.fsencode(source_name),
            target_dir_fd,
            os.fsencode(target_name),
            1,  # RENAME_NOREPLACE
        )
        == 0
    ):
        os.fsync(target_dir_fd)
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(f"refusing to overwrite existing destination entry: {target_name}")
    if error in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
        raise UmzugError("kernel/filesystem lacks atomic RENAME_NOREPLACE support")
    raise OSError(error, os.strerror(error), target_name)


def redact(value: Any, key: str = "") -> Any:
    """return a recursively redacted value suitable for logs."""
    if SECRET_KEY_RE.search(key):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        out = value
        for pattern in SECRET_VALUE_RE:
            out = pattern.sub("<redacted>", out)
        return out
    return value


class AuditLog:
    """append-only JSONL audit log with mandatory secret redaction."""

    def __init__(self, path: Path | None):
        self.path = path.absolute() if path else None
        if path:
            directory_fd = _open_directory_chain(self.path.parent, create=True)
            os.close(directory_fd)

    def event(self, event: str, **fields: Any) -> None:
        if not self.path:
            return
        row = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            **redact(fields),
        }
        directory_fd = -1
        fd = -1
        try:
            directory_fd = _open_directory_chain(self.path.parent, create=False)
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path.name, flags, 0o600, dir_fd=directory_fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise UmzugError("audit log must be a regular file with exactly one link")
            if info.st_uid != os.geteuid():
                raise UmzugError("audit log owner does not match the invoking user")
            os.fchmod(fd, 0o600)
            payload = memoryview((json.dumps(row, sort_keys=True) + "\n").encode())
            while payload:
                payload = payload[os.write(fd, payload) :]
            os.fsync(fd)
        except OSError as exc:
            raise UmzugError("audit log cannot be opened safely") from exc
        finally:
            if fd >= 0:
                os.close(fd)
            if directory_fd >= 0:
                os.close(directory_fd)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb", buffering=0) as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def terminal_safe(value: Any) -> str:
    """render untrusted names/messages without terminal control sequences."""
    output: list[str] = []
    for character in str(value):
        if character.isprintable() and character != "\x1b":
            output.append(character)
        else:
            codepoint = ord(character)
            if codepoint <= 0xFF:
                output.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                output.append(f"\\u{codepoint:04x}")
            else:
                output.append(f"\\U{codepoint:08x}")
    return "".join(output)


def fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_replace(path, data, mode)


def atomic_replace(path: Path, data: bytes, mode: int = 0o600) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        fsync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()
        raise


def contained(root: Path, candidate: Path) -> bool:
    """lexically and physically constrain candidate to root."""
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def clean_relative(name: str) -> Path:
    if "\x00" in name:
        raise UmzugError("NUL byte in path")
    path = Path(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise UmzugError(f"unsafe relative path: {name!r}")
    return path


def run(
    argv: Sequence[str],
    *,
    check: bool = True,
    capture: bool = True,
    input_bytes: bytes | None = None,
    timeout: int = 120,
    env: dict[str, str] | None = None,
    max_output_file_bytes: int | None = None,
    pass_fds: Sequence[int] = (),
) -> subprocess.CompletedProcess[bytes]:
    """run an argv vector without a shell and with a conservative environment.

    file descriptors remain closed by default. callers that address an
    fd-anchored path through ``/proc/self/fd`` must name each descriptor
    explicitly; only open, close-on-exec descriptors are accepted.
    """
    if not argv or not all(isinstance(part, str) and "\x00" not in part for part in argv):
        raise UmzugError("invalid command vector")
    inherited_fds: list[int] = []
    seen_fds: set[int] = set()
    for descriptor in pass_fds:
        if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
            raise UmzugError("invalid pass-through file descriptor")
        try:
            os.fstat(descriptor)
        except OSError as exc:
            raise UmzugError("pass-through file descriptor is not open") from exc
        if os.get_inheritable(descriptor):
            raise UmzugError("pass-through file descriptor must be close-on-exec")
        if descriptor not in seen_fds:
            inherited_fds.append(descriptor)
            seen_fds.add(descriptor)
    safe_env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if env:
        safe_env.update(env)
    preexec_fn = None
    if max_output_file_bytes is not None:
        if max_output_file_bytes <= 0:
            raise UmzugError("output file limit must be positive")

        def limit_output_file() -> None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_output_file_bytes, max_output_file_bytes))

        preexec_fn = limit_output_file
    try:
        return subprocess.run(
            list(argv),
            check=check,
            input=input_bytes,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            timeout=timeout,
            env=safe_env,
            shell=False,
            preexec_fn=preexec_fn,
            close_fds=True,
            pass_fds=tuple(inherited_fds),
        )
    except FileNotFoundError as exc:
        raise UmzugError(f"required program not found: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or b"").decode(errors="replace").strip()
        raise UmzugError(f"command failed ({argv[0]}, exit {exc.returncode}): {stderr[:1000]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise UmzugError(f"command timed out: {argv[0]}") from exc


def which(program: str) -> Path | None:
    for directory in os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").split(os.pathsep):
        candidate = Path(directory) / program
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def minimal_bwrap_runtime() -> list[str]:
    """expose only executable/runtime trees, never the complete host root."""
    usr = Path("/usr")
    if not usr.is_dir() or usr.is_symlink():
        raise UmzugError("a real /usr directory is required for the minimal scanner sandbox")
    arguments = ["--ro-bind", "/usr", "/usr"]
    for name in ("/bin", "/sbin", "/lib", "/lib64"):
        path = Path(name)
        if path.is_symlink():
            target = os.readlink(path)
            if "\x00" in target:
                raise UmzugError(f"unsafe runtime symlink: {name}")
            arguments.extend(("--symlink", target, name))
        elif path.is_dir():
            arguments.extend(("--ro-bind", name, name))
        elif path.exists():
            raise UmzugError(f"runtime path is not a directory or symlink: {name}")
    arguments.extend(("--dir", "/etc", "--dir", "/var"))
    return arguments


def random_token() -> str:
    return secrets.token_hex(16)


def require_root(*, dry_run: bool) -> None:
    if not dry_run and os.geteuid() != 0:
        raise UmzugError("this operation changes the system and must run as root")


def iter_parents_without_follow(path: Path, stop: Path) -> Iterator[Path]:
    current = path
    stop = stop.resolve()
    while True:
        yield current
        if current == stop:
            return
        if current.parent == current:
            raise UmzugError(f"{path} is not below {stop}")
        current = current.parent
