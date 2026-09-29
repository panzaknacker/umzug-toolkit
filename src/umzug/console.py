from __future__ import annotations

import os
from pathlib import Path
import re
import sys
from typing import Mapping

from .util import UmzugError


_REMOTE_ANCESTOR_NAMES = frozenset(
    {
        "dropbear",
        "mosh-server",
        "sshd",
        "teleport",
        "tmate",
    }
)
_MAX_ANCESTORS = 64
_MAX_PROC_TEXT_BYTES = 64 * 1024
_LOCAL_CONSOLE_RE = re.compile(r"/dev/(?:console|tty[0-9]+|ttyS[0-9]+|hvc[0-9]+)\Z")


def _read_small_proc_text(path: Path) -> str:
    """read one bounded procfs text file without following a replacement link."""

    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if before.st_size > _MAX_PROC_TEXT_BYTES:
            raise OSError("procfs record exceeds the bounded size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(4096, _MAX_PROC_TEXT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_PROC_TEXT_BYTES:
                raise OSError("procfs record exceeds the bounded size")
        return b"".join(chunks).decode("utf-8", "strict")
    finally:
        os.close(fd)


def _process_record(proc_root: Path, pid: int) -> tuple[str, int]:
    if pid <= 0:
        raise OSError("invalid process ID")
    root = proc_root / str(pid)
    name = _read_small_proc_text(root / "comm").strip().lower()
    status = _read_small_proc_text(root / "status")
    match = re.search(r"(?m)^PPid:\s*([0-9]+)\s*$", status)
    if not name or match is None:
        raise OSError("incomplete procfs process record")
    return name, int(match.group(1))


def remote_session_evidence(
    *,
    environ: Mapping[str, str] | None = None,
    proc_root: Path = Path("/proc"),
    parent_pid: int | None = None,
) -> dict[str, object]:
    """return conservative evidence that the invocation traversed a remote shell.

    this is an accidental-lockout guard, not an authentication boundary. a
    privileged caller can forge its environment or process tree, while remote
    KVM/IPMI consoles intentionally look local to the operating system.
    """

    environment = os.environ if environ is None else environ
    reasons: list[str] = []
    if environment.get("UMZUG_INVOCATION_REMOTE") == "1":
        reasons.append("root wrapper observed an SSH session variable")
    elif any(environment.get(name) for name in ("SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY")):
        reasons.append("SSH session variable is present")

    ancestors: list[dict[str, object]] = []
    current = os.getppid() if parent_pid is None else parent_pid
    proc_complete = True
    seen: set[int] = set()
    for _ in range(_MAX_ANCESTORS):
        if current <= 1:
            break
        if current in seen:
            proc_complete = False
            break
        seen.add(current)
        try:
            name, next_pid = _process_record(proc_root, current)
        except (OSError, UnicodeError, ValueError):
            proc_complete = False
            break
        ancestors.append({"pid": current, "name": name})
        normalized = name.removesuffix(":")
        if normalized in _REMOTE_ANCESTOR_NAMES or normalized.startswith("sshd"):
            reasons.append(f"remote-session ancestor detected: {name}")
        if next_pid == current or next_pid < 0:
            proc_complete = False
            break
        current = next_pid
    else:
        proc_complete = False

    try:
        stdin_is_tty = bool(sys.stdin.isatty())
    except (AttributeError, OSError, ValueError):
        stdin_is_tty = False
    try:
        stdout_is_tty = bool(sys.stdout.isatty())
    except (AttributeError, OSError, ValueError):
        stdout_is_tty = False
    try:
        tty = os.ttyname(sys.stdin.fileno()) if stdin_is_tty else None
    except (AttributeError, OSError, ValueError):
        tty = None
    local_blockers: list[str] = []
    if reasons:
        local_blockers.append("known remote-session evidence is present")
    if not proc_complete:
        local_blockers.append("process ancestry could not be inspected completely")
    if not stdin_is_tty or not stdout_is_tty:
        local_blockers.append("stdin and stdout are not both attached to a TTY")
    if not tty or _LOCAL_CONSOLE_RE.fullmatch(tty) is None:
        local_blockers.append("TTY is not /dev/console, /dev/ttyN, /dev/ttySN, or /dev/hvcN")
    return {
        "remote_detected": bool(reasons),
        "reasons": reasons,
        "stdin_is_tty": stdin_is_tty,
        "stdout_is_tty": stdout_is_tty,
        "tty": tty,
        "ancestor_scan_complete": proc_complete,
        "ancestors": ancestors,
        "local_console_proven": not local_blockers,
        "local_console_blockers": local_blockers,
    }


def require_not_known_remote(command: str) -> dict[str, object]:
    evidence = remote_session_evidence()
    if evidence["remote_detected"]:
        reasons = "; ".join(str(item) for item in evidence["reasons"])
        raise UmzugError(
            f"{command} is forbidden from a detected remote session ({reasons}); "
            "use the physical, serial, hypervisor, or independently recoverable local console"
        )
    return evidence


def require_proven_local_console(command: str) -> dict[str, object]:
    evidence = remote_session_evidence()
    if evidence.get("local_console_proven") is not True:
        blockers = evidence.get("local_console_blockers")
        details = (
            "; ".join(str(item) for item in blockers)
            if isinstance(blockers, list) and blockers
            else "positive local-console evidence is incomplete"
        )
        raise UmzugError(
            f"{command} requires a proven physical, serial, or hypervisor console ({details}); "
            "SSH, /dev/pts sessions, incomplete process ancestry, and non-interactive execution are forbidden"
        )
    return evidence
