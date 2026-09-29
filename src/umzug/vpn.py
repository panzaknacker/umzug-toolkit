from __future__ import annotations

import ctypes
from collections.abc import Iterator, Mapping
import errno
import getpass
import grp
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
from pathlib import Path
import re
import resource
import shlex
import socket
import stat
import subprocess
import sys
import time
from typing import Any

from .model import Plan
from .network import (
    OFFLINE_GUARD_TABLE,
    _mullvad_cli_status_is_connected,
    _mullvad_cli_status_is_disconnected,
    _mullvad_setting_is_on,
    assert_final_network_evidence,
    parse_effective_dns_sources,
    verify_host_firewall_json,
    verify_loopback_guard_json,
    verify_mullvad_firewall_json,
    verify_offline_guard_json,
    validate_interfaces,
)
from .util import AuditLog, UmzugError, open_directory_chain, run


ACCOUNT_RE = re.compile(r"^[0-9]{16}$")
ANTI_CENSORSHIP_MODES = {"auto", "udp2tcp", "shadowsocks", "quic", "lwo"}
MANAGEMENT_OVERRIDE_PATH = Path("/etc/systemd/system/mullvad-daemon.service.d/90-umzug-security.conf")
MANAGEMENT_SOCKET_PATH = Path("/var/run/mullvad-vpn")
BOOTSTRAP_GUARD_TABLE = "umzug_vpn_bootstrap_guard"
OFFLINE_GUARD_SERVICE = "umzug-offline-guard.service"
MAX_PLAN_STATE_BYTES = 64 * 1024 * 1024
MAX_MOUNTINFO_BYTES = 8 * 1024 * 1024
MAX_PROC_CONTROL_BYTES = 1024 * 1024
MAX_DAEMON_ENV_BYTES = 1024 * 1024
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
EXECUTABLE_RECEIPT_FIELDS = {
    "path",
    "sha256",
    "device",
    "inode",
    "size",
    "mtime_ns",
    "ctime_ns",
}
CONNECTED_DNS_PROBE_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")


def _observe_bound_executable(path: Path) -> dict[str, Any]:
    """return an executor-compatible receipt without following the final path."""

    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise UmzugError(f"bound executable cannot be resolved safely: {path}") from exc
    if resolved != path:
        raise UmzugError(f"bound executable path is not canonical: {path}")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UmzugError(f"bound executable cannot be opened safely: {path}") from exc
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or mode & 0o022 or mode & 0o7000 or not mode & 0o111:
            raise UmzugError(f"bound executable is not a root-owned immutable program: {path}")
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
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
            raise UmzugError(f"bound executable changed while hashing: {path}")
    except OSError as exc:
        raise UmzugError(f"bound executable cannot be hashed safely: {path}") from exc
    finally:
        os.close(fd)

    for parent in path.parents:
        try:
            parent_info = parent.stat()
        except OSError as exc:
            raise UmzugError(f"bound executable parent cannot be inspected: {path}") from exc
        parent_mode = stat.S_IMODE(parent_info.st_mode)
        sticky_root_directory = bool(parent_mode & stat.S_ISVTX) and parent_info.st_uid == 0
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or (parent_mode & 0o022 and not sticky_root_directory)
        ):
            raise UmzugError(f"bound executable has an unsafe writable parent: {path}")
    return {
        "path": str(path),
        "sha256": digest.hexdigest(),
        "device": after.st_dev,
        "inode": after.st_ino,
        "size": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "ctime_ns": after.st_ctime_ns,
    }


class BoundExecutables(Mapping[str, str]):
    """immutable executable receipts revalidated on every path lookup."""

    def __init__(self, receipts: object):
        if not isinstance(receipts, dict) or not receipts or len(receipts) > 256:
            raise UmzugError("checkpoint executable receipts are missing or unbounded")
        copied: dict[str, dict[str, Any]] = {}
        for name, receipt in receipts.items():
            if (
                not isinstance(name, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", name)
                or not isinstance(receipt, dict)
                or set(receipt) != EXECUTABLE_RECEIPT_FIELDS
            ):
                raise UmzugError("checkpoint executable receipt schema is invalid")
            path = receipt.get("path")
            sha256 = receipt.get("sha256")
            numbers = (
                receipt.get("device"),
                receipt.get("inode"),
                receipt.get("size"),
                receipt.get("mtime_ns"),
                receipt.get("ctime_ns"),
            )
            if (
                not isinstance(path, str)
                or not path
                or len(path) > 4096
                or "\x00" in path
                or not Path(path).is_absolute()
                or ".." in Path(path).parts
                or str(Path(path)) != path
                or not isinstance(sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", sha256)
                or any(type(value) is not int or value < 0 for value in numbers)
            ):
                raise UmzugError(f"checkpoint executable receipt is invalid: {name}")
            copied[name] = dict(receipt)
        self._receipts = copied

    def path(self, name: str) -> str:
        receipt = self._receipts.get(name)
        if receipt is None:
            raise UmzugError(f"completed plan lacks a bound executable receipt: {name}")
        observed = _observe_bound_executable(Path(str(receipt["path"])))
        if observed != receipt:
            raise UmzugError(f"bound executable changed after completed-plan apply: {name}")
        return str(observed["path"])

    def require(self, names: set[str]) -> dict[str, str]:
        if not names or any(not isinstance(name, str) for name in names):
            raise UmzugError("required finalization executable set is invalid")
        return {name: self.path(name) for name in sorted(names)}

    def revalidate_all(self) -> dict[str, str]:
        return self.require(set(self._receipts))

    def __getitem__(self, name: str) -> str:
        return self.path(name)

    def __iter__(self) -> Iterator[str]:
        return iter(self._receipts)

    def __len__(self) -> int:
        return len(self._receipts)


def _required_finalization_executables(
    package_manager: str,
    *,
    radios_blocked: bool,
    online_verification: bool,
) -> set[str]:
    tools = {
        "ip",
        "mullvad",
        "nft",
        "ss",
        "systemctl",
        "wg",
    }
    if package_manager == "apt-get":
        tools.update({"dpkg", "dpkg-query"})
    elif package_manager == "rpm":
        tools.add("rpm")
    else:
        raise UmzugError("unsupported package provenance verifier for Mullvad")
    if radios_blocked:
        tools.add("rfkill")
    if online_verification:
        tools.add("curl")
    return tools


def _read_stable_proc_control(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise UmzugError(f"secret-safety kernel state cannot be opened safely: {path}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise UmzugError(f"secret-safety kernel state is not a regular proc file: {path}")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, 64 * 1024):
            total += len(chunk)
            if total > MAX_PROC_CONTROL_BYTES:
                raise UmzugError(f"secret-safety kernel state exceeds its parser limit: {path}")
            chunks.append(chunk)
        after = os.fstat(fd)
        stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise UmzugError(f"secret-safety kernel state changed while reading: {path}")
        return b"".join(chunks).decode("utf-8", "strict")
    except (OSError, UnicodeError) as exc:
        raise UmzugError(f"secret-safety kernel state is unreadable: {path}") from exc
    finally:
        os.close(fd)


def _require_core_dump_disabled(
    pattern_path: Path = Path("/proc/sys/kernel/core_pattern"),
    uses_pid_path: Path = Path("/proc/sys/kernel/core_uses_pid"),
) -> dict[str, Any]:
    """require a global no-core policy; RLIMIT_CORE is ignored for pipe handlers."""

    pattern_first = _read_stable_proc_control(pattern_path)
    uses_pid_first = _read_stable_proc_control(uses_pid_path)
    pattern_second = _read_stable_proc_control(pattern_path)
    uses_pid_second = _read_stable_proc_control(uses_pid_path)
    if pattern_first != pattern_second or uses_pid_first != uses_pid_second:
        raise UmzugError("core-dump kernel policy changed while it was being verified")
    pattern = pattern_first.rstrip("\n")
    uses_pid = uses_pid_first.strip()
    if pattern or uses_pid != "0":
        raise UmzugError(
            "Mullvad account entry requires globally disabled core dumps: "
            "kernel.core_pattern must be empty and kernel.core_uses_pid must be 0"
        )
    return {"core_pattern": "empty", "core_uses_pid": 0}


def _require_no_active_swap(swaps_path: Path = Path("/proc/swaps")) -> dict[str, Any]:
    first = _read_stable_proc_control(swaps_path)
    second = _read_stable_proc_control(swaps_path)
    if first != second:
        raise UmzugError("active swap state changed while it was being verified")
    lines = [line for line in first.splitlines() if line.strip()]
    if not lines or not lines[0].split()[:2] == ["Filename", "Type"]:
        raise UmzugError("active swap state has an unsupported format")
    if len(lines) != 1:
        raise UmzugError(
            "Mullvad account entry requires all swap to be inactive; encrypted swap "
            "is not inferred from names or configuration"
        )
    return {"active_swap_entries": 0}


def _prctl(option: int, argument: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    result = int(prctl(option, argument, 0, 0, 0))
    if result < 0:
        error = ctypes.get_errno()
        raise UmzugError(f"prctl secret-process hardening failed with errno {error}")
    return result


def _harden_secret_process() -> dict[str, Any]:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        core_limit = resource.getrlimit(resource.RLIMIT_CORE)
    except (OSError, ValueError) as exc:
        raise UmzugError("core size limit cannot be locked to zero") from exc
    if core_limit != (0, 0):
        raise UmzugError("core size limit is not locked to zero")
    _prctl(PR_SET_DUMPABLE, 0)
    if _prctl(PR_GET_DUMPABLE) != 0:
        raise UmzugError("secret-bearing setup process remains dumpable")
    return {"rlimit_core_soft": 0, "rlimit_core_hard": 0, "dumpable": False}


def _require_secret_entry_safety() -> dict[str, Any]:
    return {
        "process": _harden_secret_process(),
        "global_core_policy": _require_core_dump_disabled(),
        "swap": _require_no_active_swap(),
    }


def _secret_child_preexec() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    _prctl(PR_SET_DUMPABLE, 0)


def _decode_mountinfo_path(value: str) -> str:
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: escapes.get(match.group(1), match.group(0)),
        value,
    )


def _require_private_procfs(
    mountinfo_path: Path = Path("/proc/self/mountinfo"),
) -> dict[str, Any]:
    """require procfs to hide process arguments from ordinary local users."""

    try:
        fd = os.open(
            mountinfo_path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise UmzugError("procfs privacy options cannot be inspected safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MOUNTINFO_BYTES:
            raise UmzugError("procfs mountinfo has an unsafe type or size")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, 1024 * 1024):
            total += len(chunk)
            if total > MAX_MOUNTINFO_BYTES:
                raise UmzugError("procfs mountinfo exceeds its parser limit")
            chunks.append(chunk)
        text = b"".join(chunks).decode("utf-8", "strict")
    except (OSError, UnicodeError) as exc:
        raise UmzugError("procfs mountinfo is unreadable") from exc
    finally:
        os.close(fd)
    matches: list[set[str]] = []
    for line in text.splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        after = right.split()
        if len(fields) >= 6 and len(after) >= 3 and _decode_mountinfo_path(fields[4]) == "/proc" and after[0] == "proc":
            matches.append(set(fields[5].split(",")) | set(after[2].split(",")))
    if len(matches) != 1:
        raise UmzugError("exactly one effective /proc mount must be provable before account entry")
    options = matches[0]
    private = "hidepid=2" in options or "hidepid=invisible" in options
    if not private or any(option.startswith("gid=") for option in options):
        raise UmzugError(
            "Mullvad account entry requires /proc mounted with hidepid=2 "
            "(or hidepid=invisible) and without a gid bypass"
        )
    return {
        "mountpoint": "/proc",
        "hidepid": "2" if "hidepid=2" in options else "invisible",
        "gid_bypass": False,
    }


def _read_private_state_json(
    directory_fd: int,
    name: str,
    *,
    owner_uid: int,
) -> dict[str, Any]:
    if name not in {"plan.json", "state.json"}:
        raise UmzugError("invalid finalization state filename")
    fd = -1
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != owner_uid
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size < 2
            or before.st_size > MAX_PLAN_STATE_BYTES
        ):
            raise UmzugError(f"{name} is not a private, bounded, single-link regular file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise UmzugError(f"{name} was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise UmzugError(f"{name} grew while reading")
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
            raise UmzugError(f"{name} changed while reading")
        value = json.loads(b"".join(chunks).decode("utf-8", "strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"finalization state cannot be read safely: {name}") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(value, dict):
        raise UmzugError(f"finalization state root is not an object: {name}")
    return value


def _verify_private_input_snapshot(
    state_dir: Path,
    name: str,
    expected_sha256: str,
    *,
    owner_uid: int,
) -> None:
    directory_fd = open_directory_chain(state_dir.absolute() / "inputs", create=False)
    fd = -1
    digest = hashlib.sha256()
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != owner_uid
            or stat.S_IMODE(before.st_mode) != 0o400
        ):
            raise UmzugError("installed vendor input snapshot is not private immutable state")
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
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
            raise UmzugError("installed vendor input snapshot changed while re-verifying")
    except OSError as exc:
        raise UmzugError("installed vendor input snapshot cannot be re-verified") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(directory_fd)
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise UmzugError("installed vendor input snapshot no longer matches the reviewed release")


def _load_completed_plan_context(
    state_dir: Path,
    expected_plan_sha256: str,
    *,
    owner_uid: int,
) -> dict[str, Any]:
    expected = expected_plan_sha256.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise UmzugError("expected finalization plan SHA-256 is invalid")
    directory_fd = open_directory_chain(state_dir.absolute(), create=False)
    try:
        info = os.fstat(directory_fd)
        if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) & 0o022:
            raise UmzugError("finalization state directory has unsafe ownership or permissions")
        plan_value = _read_private_state_json(directory_fd, "plan.json", owner_uid=owner_uid)
        state = _read_private_state_json(directory_fd, "state.json", owner_uid=owner_uid)
    finally:
        os.close(directory_fd)
    plan = Plan.from_dict(plan_value)
    digest = plan.digest()
    if not hmac.compare_digest(digest, expected):
        raise UmzugError("out-of-band plan SHA-256 does not match saved finalization plan")
    if not isinstance(state.get("plan_digest"), str) or not hmac.compare_digest(state["plan_digest"], expected):
        raise UmzugError("checkpoint state is not bound to the reviewed finalization plan")
    if state.get("profile") != plan.profile or state.get("pending_reboot") is not None:
        raise UmzugError("plan profile differs or a required reboot remains unverified")
    if state.get("rolled_back_at") is not None:
        raise UmzugError("rolled-back plans cannot authorize VPN finalization")
    completed = state.get("completed")
    expected_actions = [action.id for action in plan.actions]
    if (
        not isinstance(completed, list)
        or any(not isinstance(item, str) for item in completed)
        or completed != expected_actions
    ):
        raise UmzugError("every reviewed plan action must be completed before VPN finalization")

    host_checks = [action.verify for action in plan.actions if action.verify.get("kind") == "host_firewall"]
    if len(host_checks) != 1:
        raise UmzugError("completed plan does not contain exactly one verifiable host firewall")
    host = host_checks[0]
    interfaces = host.get("interfaces")
    if not isinstance(interfaces, list) or any(not isinstance(item, str) for item in interfaces):
        raise UmzugError("completed plan has an invalid Ethernet-only firewall binding")
    if not any(action.verify.get("kind") == "offline_guard" for action in plan.actions):
        raise UmzugError("completed plan lacks the required persistent offline guard")
    required_actions = {
        "mullvad-offline-install",
        "mullvad-management-group",
        "mullvad-management-socket",
    }
    if not required_actions.issubset(set(expected_actions)):
        raise UmzugError("completed plan lacks verified Mullvad offline preparation")
    install_actions = [action for action in plan.actions if action.id == "mullvad-offline-install"]
    if len(install_actions) != 1:
        raise UmzugError("completed plan has an ambiguous Mullvad install action")
    install = install_actions[0]
    hashes = install.parameters.get("required_file_hashes")
    argv = install.parameters.get("argv")
    if (
        not isinstance(hashes, dict)
        or len(hashes) != 1
        or not isinstance(argv, list)
        or not argv
        or argv[0] not in {"apt-get", "rpm"}
    ):
        raise UmzugError("completed Mullvad install lacks one hash-bound offline artifact")
    artifact_path, artifact_sha256 = next(iter(hashes.items()))
    if (
        not isinstance(artifact_path, str)
        or not isinstance(artifact_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)
        or artifact_path not in argv
    ):
        raise UmzugError("completed Mullvad artifact binding is invalid")
    package_version = install.verify.get("version")
    package_architecture = install.verify.get("architecture")
    package_verifier = install.verify.get("manager")
    expected_verifier = "dpkg" if argv[0] == "apt-get" else "rpm"
    if (
        package_verifier != expected_verifier
        or not isinstance(package_version, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,127}", package_version)
        or not isinstance(package_architecture, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", package_architecture)
    ):
        raise UmzugError("completed Mullvad package identity binding is invalid")
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(artifact_path).name)[:120] or "artifact"
    _verify_private_input_snapshot(
        state_dir,
        f"{artifact_sha256}-{safe_name}",
        artifact_sha256,
        owner_uid=owner_uid,
    )
    disabled = {str(action.parameters.get("name")) for action in plan.actions if action.operation == "disable_service"}
    if not {
        "ssh.service",
        "sshd.service",
        "ssh.socket",
        "sshd.socket",
    }.issubset(disabled):
        raise UmzugError("completed plan does not disable all incoming systemd SSH units")
    radios_blocked = any(action.verify.get("kind") == "radio_blocked" for action in plan.actions)
    planned_tools = {
        str(action.parameters["name"]) for action in plan.actions if action.operation == "check_executable"
    }
    finalization_tools = _required_finalization_executables(
        argv[0],
        radios_blocked=radios_blocked,
        online_verification=False,
    )
    bound_executables = BoundExecutables(state.get("executables"))
    # validate every persisted receipt, not just the subset consumed here.
    # completed preflights without a corresponding receipt are equally fatal.
    bound_executables.revalidate_all()
    bound_executables.require(planned_tools | finalization_tools)
    return {
        "plan": plan,
        "plan_sha256": digest,
        "ethernet_interfaces": interfaces,
        "ipv6_disabled": not bool(host.get("ipv6_enabled", False)),
        "radios_blocked": radios_blocked,
        "package_manager": argv[0],
        "vendor_package_version": package_version,
        "vendor_package_architecture": package_architecture,
        "vendor_artifact_sha256": artifact_sha256,
        "bound_executables": bound_executables,
    }


def require_completed_plan_context(
    state_dir: Path,
    expected_plan_sha256: str,
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise UmzugError("VPN finalization state may only be consumed as root")
    return _load_completed_plan_context(
        state_dir,
        expected_plan_sha256,
        owner_uid=0,
    )


def mullvad_platform_status(distribution: str, version_id: str, architecture: str) -> tuple[bool, str]:
    """conservative matrix from mullvad's current supported-platforms document."""
    distro = distribution.lower()
    arch_ok = architecture.lower() in {"x86_64", "amd64", "aarch64", "arm64"}
    if not arch_ok:
        return False, "Mullvad App officially targets x86-64 and ARM64."
    supported_releases = {
        "debian": {"12", "13"},
        "ubuntu": {"24.04", "25.10", "26.04"},
        "fedora": {"43", "44"},
    }
    if distro in supported_releases:
        normalised = version_id.strip()
        if distro in {"debian", "fedora"}:
            normalised = normalised.split(".")[0]
        if normalised not in supported_releases[distro]:
            return False, (
                f"Mullvad's platform matrix current on 2026-07-15 does not list "
                f"{distribution} {version_id or '(unknown)'}. Re-verify the official matrix before use."
            )
        return True, "Release and architecture are listed in Mullvad's official Linux App matrix current on 2026-07-15."
    if distro == "arch":
        return False, "Arch carries a package, but Mullvad does not maintain or officially support that distribution."
    return (
        False,
        "Mullvad App does not officially support this distribution; use only explicit best-effort or approved vanilla WireGuard.",
    )


def management_override(group: str) -> str:
    if not group or any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in group
    ):
        raise UmzugError("invalid Mullvad management group")
    return f"""[Service]
Environment=
Environment=MULLVAD_MANAGEMENT_SOCKET_GROUP={group}
UMask=0077
"""


def _run_mullvad(
    tools: BoundExecutables,
    argv: list[str],
    *,
    required: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    completed = run([tools.path("mullvad"), *argv], check=False, timeout=120)
    if required and completed.returncode != 0:
        message = completed.stderr.decode(errors="replace")[:1000]
        # account numbers must never escape into errors or logs.
        message = re.sub(r"\b[0-9]{16}\b", "<redacted>", message)
        raise UmzugError(f"Mullvad command failed ({' '.join(argv[:3])}): {message}")
    return completed


def _login_secret(account: bytearray, tools: BoundExecutables) -> None:
    """call the official CLI without shell/history/logging.

    the CLI currently accepts the account number only as an argv value. the
    procfs hidepid precondition prevents ordinary local users from reading it;
    privileged process inspection remains outside this tool's protection.
    """
    _require_private_procfs()
    _require_secret_entry_safety()
    value = account.decode("ascii")
    env = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    completed: subprocess.CompletedProcess[bytes] | None = None
    try:
        completed = subprocess.run(
            [tools.path("mullvad"), "account", "login", value],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=120,
            env=env,
            shell=False,
            preexec_fn=_secret_child_preexec,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise UmzugError(f"Mullvad account login failed safely: {type(exc).__name__}") from exc
    finally:
        value = ""  # best effort; python cannot guarantee erasure of immutable copies.
        for index in range(len(account)):
            account[index] = 0
    if completed is None or completed.returncode != 0:
        raise UmzugError("Mullvad account login failed; no account value was logged")


def _check_account_storage(*, encrypted_storage: bool) -> None:
    if encrypted_storage:
        return
    raise UmzugError(
        "Mullvad's official Linux app stores account and device state root-only but in plaintext. "
        "No encryption protecting the root filesystem was proven, so account entry is "
        "forbidden. Enable full-disk/filesystem encryption and re-run detection first."
    )


def _open_root_control_directory(path: Path) -> int:
    path = path.absolute()
    if not path.is_absolute() or path == Path("/"):
        raise UmzugError("root control directory path is invalid")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            if part in {"", ".", ".."}:
                raise UmzugError("root control directory contains an unsafe component")
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=fd,
            )
            info = os.fstat(child)
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                os.close(child)
                raise UmzugError("root control directory has a non-root-owned or writable component")
            os.close(fd)
            fd = child
        return fd
    except OSError as exc:
        os.close(fd)
        raise UmzugError("root control directory cannot be opened without links") from exc
    except BaseException:
        os.close(fd)
        raise


def _verify_sensitive_mullvad_file_permissions(filename: str) -> dict[str, Any]:
    if filename not in {"account-history.json", "device.json"}:
        raise UmzugError("unsupported Mullvad sensitive-state filename")
    parent = Path("/etc/mullvad-vpn")
    directory_fd = _open_root_control_directory(parent)
    file_fd = -1
    try:
        directory = os.fstat(directory_fd)
        if directory.st_uid != 0 or stat.S_IMODE(directory.st_mode) & 0o022:
            raise UmzugError("Mullvad account-history parent must be root-owned and non-writable by group/other")
        try:
            file_fd = os.open(
                filename,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return {
                "exists": False,
                "filename": filename,
                "parent_uid": directory.st_uid,
                "parent_mode": oct(stat.S_IMODE(directory.st_mode)),
            }
        info = os.fstat(file_fd)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or mode & ~0o600
            or info.st_size > 1024 * 1024
        ):
            raise UmzugError(
                f"Mullvad sensitive state {filename} is not a single-link root-owned mode 0600-or-stricter file"
            )
        return {
            "exists": True,
            "filename": filename,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": oct(mode),
            "parent_uid": directory.st_uid,
            "parent_mode": oct(stat.S_IMODE(directory.st_mode)),
        }
    except OSError as exc:
        raise UmzugError("Mullvad account-history path cannot be inspected without links") from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(directory_fd)


def _verify_account_history_permissions() -> dict[str, Any]:
    return _verify_sensitive_mullvad_file_permissions("account-history.json")


def _verify_device_permissions() -> dict[str, Any]:
    return _verify_sensitive_mullvad_file_permissions("device.json")


def _parse_nul_environment(raw: bytes) -> dict[bytes, bytes]:
    if len(raw) > MAX_DAEMON_ENV_BYTES:
        raise UmzugError("effective Mullvad daemon environment exceeds its parser limit")
    if raw and not raw.endswith(b"\0"):
        raise UmzugError("effective Mullvad daemon environment is not NUL terminated")
    parsed: dict[bytes, bytes] = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        if b"=" not in entry:
            raise UmzugError("effective Mullvad daemon environment contains a malformed entry")
        key, value = entry.split(b"=", 1)
        if not re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]*", key) or key in parsed:
            raise UmzugError("effective Mullvad daemon environment contains an unsafe key")
        parsed[key] = value
    return parsed


def _mullvad_daemon_main_pid(tools: BoundExecutables) -> int:
    raw = run(
        [
            tools.path("systemctl"),
            "show",
            "mullvad-daemon.service",
            "--property=MainPID",
            "--value",
        ]
    ).stdout.strip()
    if not re.fullmatch(rb"[1-9][0-9]{0,9}", raw):
        raise UmzugError("Mullvad daemon has no stable positive MainPID")
    return int(raw)


def _effective_mullvad_daemon_environment(
    tools: BoundExecutables,
) -> dict[bytes, bytes]:
    """read the running daemon's real environment, not just unit metadata."""

    pid_before = _mullvad_daemon_main_pid(tools)
    proc_fd = pid_fd = environment_fd = -1
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        proc_fd = os.open("/proc", directory_flags)
        pid_fd = os.open(str(pid_before), directory_flags, dir_fd=proc_fd)
        process_info = os.fstat(pid_fd)
        if not stat.S_ISDIR(process_info.st_mode) or process_info.st_uid != 0:
            raise UmzugError("Mullvad MainPID is not a root-owned process directory")
        environment_fd = os.open(
            "environ",
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=pid_fd,
        )
        before = os.fstat(environment_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0:
            raise UmzugError("Mullvad daemon environment is not a root-owned proc file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(environment_fd, 64 * 1024):
            total += len(chunk)
            if total > MAX_DAEMON_ENV_BYTES:
                raise UmzugError("effective Mullvad daemon environment exceeds its parser limit")
            chunks.append(chunk)
        after = os.fstat(environment_fd)
        stable = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise UmzugError("Mullvad daemon environment changed while reading")
    except UmzugError:
        raise
    except OSError as exc:
        raise UmzugError("effective Mullvad daemon environment cannot be read safely") from exc
    finally:
        for descriptor in (environment_fd, pid_fd, proc_fd):
            if descriptor >= 0:
                os.close(descriptor)
    if _mullvad_daemon_main_pid(tools) != pid_before:
        raise UmzugError("Mullvad daemon MainPID changed while its environment was verified")
    return _parse_nul_environment(b"".join(chunks))


def _validate_mullvad_daemon_environment(environment: dict[bytes, bytes], group: str) -> None:
    expected_key = b"MULLVAD_MANAGEMENT_SOCKET_GROUP"
    expected_value = group.encode("ascii", "strict")
    if environment.get(expected_key) != expected_value:
        raise UmzugError("running Mullvad daemon lacks the exact management-group restriction")
    forbidden_generic = {
        b"BASH_ENV",
        b"ENV",
        b"HTTP_PROXY",
        b"HTTPS_PROXY",
        b"ALL_PROXY",
        b"http_proxy",
        b"https_proxy",
        b"all_proxy",
        b"SSL_CERT_FILE",
        b"SSL_CERT_DIR",
    }
    for key in environment:
        if (
            (key.startswith(b"MULLVAD_") and key != expected_key)
            or key.startswith(b"TALPID_")
            or key.startswith(b"LD_")
            or key.startswith(b"DYLD_")
            or key in forbidden_generic
        ):
            raise UmzugError("running Mullvad daemon contains an unreviewed security-relevant environment override")


def _verify_management_restriction(group: str, tools: BoundExecutables) -> None:
    """verify the already-restarted daemon without mutating its state."""

    try:
        group_entry = grp.getgrnam(group)
    except KeyError as exc:
        raise UmzugError(f"dedicated Mullvad management group does not exist: {group}") from exc
    explicit_non_root = sorted(name for name in group_entry.gr_mem if name != "root")
    primary_non_root = sorted(
        entry.pw_name for entry in pwd.getpwall() if entry.pw_gid == group_entry.gr_gid and entry.pw_uid != 0
    )
    delegated = sorted(set(explicit_non_root + primary_non_root))
    if delegated:
        raise UmzugError(
            "Mullvad management group has non-root members; refusing privileged daemon "
            f"control delegation: {', '.join(delegated)}"
        )
    override = MANAGEMENT_OVERRIDE_PATH
    expected = f"MULLVAD_MANAGEMENT_SOCKET_GROUP={group}"
    directory_fd = fd = -1
    try:
        directory_fd = _open_root_control_directory(override.parent)
        fd = os.open(
            override.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise UmzugError(f"Mullvad management override is not a single-link regular file: {override}")
        if info.st_uid != 0 or mode & ~0o644:
            raise UmzugError(f"Mullvad management override must be root-owned and mode 0644-or-stricter: {override}")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            content = handle.read(16_385)
        if len(content) > 16_384:
            raise UmzugError("Mullvad management override is unexpectedly large")
    except UmzugError:
        raise
    except (OSError, UnicodeError) as exc:
        raise UmzugError("Mullvad management socket restriction was not installed by the reviewed plan") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if directory_fd >= 0:
            os.close(directory_fd)
    if content != management_override(group):
        raise UmzugError("Mullvad management socket override is not the exact reviewed content")
    effective = run(
        [
            tools.path("systemctl"),
            "show",
            "mullvad-daemon.service",
            "--property=Environment",
            "--value",
        ]
    )
    try:
        environment = shlex.split(effective.stdout.decode("utf-8", "strict"))
    except (UnicodeError, ValueError) as exc:
        raise UmzugError("effective Mullvad daemon environment could not be parsed safely") from exc
    if expected not in environment:
        raise UmzugError("effective Mullvad daemon environment lacks the management-group restriction")
    if any(item.startswith(("MULLVAD_", "TALPID_")) and item != expected for item in environment):
        raise UmzugError("an unreviewed Mullvad daemon environment override is active")
    _validate_mullvad_daemon_environment(
        _effective_mullvad_daemon_environment(tools),
        group,
    )
    effective_umask = (
        run(
            [
                tools.path("systemctl"),
                "show",
                "mullvad-daemon.service",
                "--property=UMask",
                "--value",
            ]
        )
        .stdout.decode("utf-8", "replace")
        .strip()
    )
    if effective_umask != "0077":
        raise UmzugError("effective Mullvad daemon UMask is not the required 0077")

    socket_info: os.stat_result | None = None
    for _attempt in range(50):
        try:
            socket_info = MANAGEMENT_SOCKET_PATH.lstat()
            break
        except FileNotFoundError:
            time.sleep(0.1)
    if socket_info is None or not stat.S_ISSOCK(socket_info.st_mode):
        raise UmzugError("effective Mullvad management endpoint is not the expected Unix socket")
    if socket_info.st_uid != 0 or socket_info.st_gid != group_entry.gr_gid:
        raise UmzugError("effective Mullvad management socket ownership does not match root and the dedicated group")
    if stat.S_IMODE(socket_info.st_mode) & 0o007:
        raise UmzugError("effective Mullvad management socket remains accessible to other users")


def _require_management_restriction(group: str, tools: BoundExecutables) -> None:
    """activate the reviewed drop-in, then verify the effective daemon state."""

    run([tools.path("systemctl"), "daemon-reload"])
    run([tools.path("systemctl"), "restart", "mullvad-daemon.service"])
    _verify_management_restriction(group, tools)


def _install_bootstrap_guard(tools: BoundExecutables) -> None:
    rules = f"""table inet {BOOTSTRAP_GUARD_TABLE}
flush table inet {BOOTSTRAP_GUARD_TABLE}

table inet {BOOTSTRAP_GUARD_TABLE} {{
    chain output {{
        type filter hook output priority -300; policy drop;
        oifname \"lo\" accept
    }}
}}
"""
    run([tools.path("nft"), "--file", "-"], input_bytes=rules.encode("ascii"))


def _remove_bootstrap_guard(tools: BoundExecutables) -> None:
    run(
        [
            tools.path("nft"),
            "delete",
            "table",
            "inet",
            BOOTSTRAP_GUARD_TABLE,
        ]
    )


def _guard_json(
    tools: BoundExecutables,
    table_name: str,
    *,
    required: bool,
) -> bytes:
    result = run(
        [tools.path("nft"), "--json", "list", "table", "inet", table_name],
        check=False,
        timeout=30,
    )
    if required and result.returncode != 0:
        raise UmzugError(f"required fail-closed nftables guard is absent: {table_name}")
    if not required and result.returncode == 0:
        raise UmzugError(f"temporary nftables guard unexpectedly remains active: {table_name}")
    return result.stdout


def _require_bootstrap_guard(tools: BoundExecutables) -> None:
    verify_loopback_guard_json(
        _guard_json(tools, BOOTSTRAP_GUARD_TABLE, required=True),
        table_name=BOOTSTRAP_GUARD_TABLE,
        priority=-300,
    )


def _require_offline_guard(tools: BoundExecutables) -> None:
    verify_offline_guard_json(_guard_json(tools, OFFLINE_GUARD_TABLE, required=True))


def _require_initial_fail_closed_boundary(tools: BoundExecutables) -> str:
    """accept only a proven boundary from which bootstrap can safely resume."""

    try:
        _require_offline_guard(tools)
        return "offline-guard"
    except UmzugError:
        pass
    try:
        _require_bootstrap_guard(tools)
        return "bootstrap-guard"
    except UmzugError:
        pass
    try:
        _require_lockdown_enabled(tools)
        _require_mullvad_firewall(tools)
        return "mullvad-lockdown"
    except UmzugError as exc:
        raise UmzugError("no verified fail-closed boundary exists for Mullvad finalization or resume") from exc


def _require_host_firewall(
    tools: BoundExecutables,
    interfaces: list[str],
    *,
    ipv6_disabled: bool,
) -> None:
    result = run(
        [tools.path("nft"), "--json", "list", "table", "inet", "umzug_host"],
        timeout=30,
    )
    verify_host_firewall_json(
        result.stdout,
        interfaces,
        ipv6_enabled=not ipv6_disabled,
    )


def _require_mullvad_firewall(tools: BoundExecutables) -> None:
    result = run(
        [tools.path("nft"), "--json", "list", "table", "inet", "mullvad"],
        timeout=30,
    )
    verify_mullvad_firewall_json(result.stdout)


def _require_daemon_persistent(tools: BoundExecutables) -> None:
    for mode in ("is-enabled", "is-active"):
        result = run(
            [tools.path("systemctl"), mode, "mullvad-daemon.service"],
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            raise UmzugError(f"Mullvad daemon is not persistently {mode.removeprefix('is-')}")


def _require_installed_mullvad_package(
    package_manager: str,
    tools: BoundExecutables,
    *,
    expected_version: str,
    expected_architecture: str,
) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,127}", expected_version) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", expected_architecture
    ):
        raise UmzugError("reviewed Mullvad package identity is invalid")
    executable = Path(tools.path("mullvad"))
    fd = -1
    try:
        resolved = executable.resolve(strict=True)
        fd = os.open(
            resolved,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        info = os.fstat(fd)
    except OSError as exc:
        raise UmzugError("installed Mullvad executable cannot be opened safely") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or not stat.S_IMODE(info.st_mode) & 0o100
    ):
        raise UmzugError("installed Mullvad executable has unsafe type, owner or mode")

    if package_manager == "apt-get":
        owner = run(
            [tools.path("dpkg-query"), "--search", str(executable)],
            timeout=30,
        ).stdout.decode("utf-8", "replace")
        status = run(
            [
                tools.path("dpkg-query"),
                "--show",
                "--showformat=\x24{binary:Package}\\t\x24{db:Status-Abbrev}\\n",
                "mullvad-vpn",
            ],
            timeout=30,
        ).stdout.decode("utf-8", "replace")
        owner_packages = {line.split(":", 1)[0].split(":")[0] for line in owner.splitlines() if ":" in line}
        if owner_packages != {"mullvad-vpn"} or not any(
            line.split("\t", 1)[0].split(":")[0] == "mullvad-vpn" and line.split("\t", 1)[1].startswith("ii")
            for line in status.splitlines()
            if "\t" in line
        ):
            raise UmzugError("dpkg does not bind the Mullvad CLI to an installed mullvad-vpn package")
        identity = (
            run(
                [
                    tools.path("dpkg-query"),
                    "--show",
                    "--showformat=\x24{binary:Package}\\t\x24{Version}\\t\x24{Architecture}\\t\x24{db:Status-Abbrev}\\n",
                    "mullvad-vpn",
                ],
                timeout=30,
            )
            .stdout.decode("utf-8", "strict")
            .splitlines()
        )
        fields = identity[0].split("\t") if len(identity) == 1 else []
        if (
            len(fields) != 4
            or fields[0].split(":", 1)[0] != "mullvad-vpn"
            or fields[1] != expected_version
            or fields[2] != expected_architecture
            or not fields[3].startswith("ii")
        ):
            raise UmzugError("installed Mullvad package differs from the reviewed version/architecture")
        integrity = run(
            [tools.path("dpkg"), "--verify", "mullvad-vpn"],
            check=False,
            timeout=120,
        )
    elif package_manager == "rpm":
        owner = run(
            [
                tools.path("rpm"),
                "--queryformat",
                "%{NAME}\\n",
                "--file",
                str(executable),
            ],
            timeout=30,
        ).stdout.decode("utf-8", "replace")
        if owner.strip() != "mullvad-vpn":
            raise UmzugError("RPM does not bind the Mullvad CLI to mullvad-vpn")
        identity = (
            run(
                [
                    tools.path("rpm"),
                    "--query",
                    "--queryformat",
                    "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n",
                    "mullvad-vpn",
                ],
                timeout=30,
            )
            .stdout.decode("utf-8", "strict")
            .splitlines()
        )
        expected = f"mullvad-vpn\t{expected_version}\t{expected_architecture}"
        if identity != [expected]:
            raise UmzugError("installed Mullvad package differs from the reviewed version/architecture")
        integrity = run(
            [tools.path("rpm"), "--verify", "mullvad-vpn"],
            check=False,
            timeout=120,
        )
    else:
        raise UmzugError("unsupported package provenance verifier for Mullvad")
    if integrity.returncode != 0 or integrity.stdout.strip():
        raise UmzugError("installed Mullvad files differ from the package-manager integrity database")
    return {
        "path": str(resolved),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": oct(stat.S_IMODE(info.st_mode)),
        "package_manager": package_manager,
        "version": expected_version,
        "architecture": expected_architecture,
    }


def _retire_offline_guard_under_bootstrap(tools: BoundExecutables) -> None:
    """remove the setup guard without ever opening an unguarded transition."""

    _require_bootstrap_guard(tools)
    offline_table = run(
        [
            tools.path("nft"),
            "--json",
            "list",
            "table",
            "inet",
            OFFLINE_GUARD_TABLE,
        ],
        check=False,
        timeout=30,
    )
    if offline_table.returncode == 0:
        verify_offline_guard_json(offline_table.stdout)
    run(
        [
            tools.path("systemctl"),
            "disable",
            "--now",
            OFFLINE_GUARD_SERVICE,
        ]
    )
    for mode in ("is-enabled", "is-active"):
        result = run(
            [tools.path("systemctl"), mode, OFFLINE_GUARD_SERVICE],
            check=False,
            timeout=30,
        )
        if result.returncode == 0:
            raise UmzugError(f"persistent offline guard remains {mode.removeprefix('is-')}")
    # the oneshot unit intentionally has no rule-deleting ExecStop. its table
    # is removed only while the independently verified bootstrap guard is live.
    if offline_table.returncode == 0:
        run(
            [
                tools.path("nft"),
                "delete",
                "table",
                "inet",
                OFFLINE_GUARD_TABLE,
            ]
        )
    _guard_json(tools, OFFLINE_GUARD_TABLE, required=False)
    _require_bootstrap_guard(tools)


def _restore_persistent_offline_guard(tools: BoundExecutables) -> None:
    """make every caught finalization failure survive a subsequent reboot."""

    _install_bootstrap_guard(tools)
    _require_bootstrap_guard(tools)
    run([tools.path("systemctl"), "enable", "--now", OFFLINE_GUARD_SERVICE])
    for mode in ("is-enabled", "is-active"):
        result = run(
            [tools.path("systemctl"), mode, OFFLINE_GUARD_SERVICE],
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            raise UmzugError(f"persistent offline guard is not {mode.removeprefix('is-')} after recovery")
    _require_offline_guard(tools)
    _require_bootstrap_guard(tools)


def _require_lockdown_enabled(tools: BoundExecutables) -> None:
    result = _run_mullvad(tools, ["lockdown-mode", "get"])
    if not _mullvad_setting_is_on(result.stdout):
        raise UmzugError("Mullvad did not prove that Lockdown Mode is enabled")


def _wait_for_mullvad_status(
    tools: BoundExecutables,
    *,
    connected: bool,
    timeout: float = 60.0,
) -> bytes:
    deadline = time.monotonic() + timeout
    last = b""
    while time.monotonic() < deadline:
        completed = _run_mullvad(tools, ["status", "-v"], required=False)
        last = completed.stdout
        observed_connected = _mullvad_cli_status_is_connected(last)
        observed_disconnected = _mullvad_cli_status_is_disconnected(last)
        if completed.returncode == 0 and (
            (connected and observed_connected) or (not connected and observed_disconnected and not observed_connected)
        ):
            return last
        time.sleep(1)
    state = "connected" if connected else "fail-closed disconnected"
    raise UmzugError(f"Mullvad did not reach the required {state} state")


def _prove_connected_dns_containment(
    tools: BoundExecutables,
    ethernet_interfaces: list[str],
) -> dict[str, Any]:
    """probe finite, literal DNS paths while the VPN reports connected.

    each probe is bound with SO_BINDTODEVICE to every reviewed physical NIC.
    UDP and TCP are both exercised against independent anycast resolver
    operators.  this detects an effective direct-ethernet DNS exception; it is
    still a finite observation and therefore is never reported as a universal
    proof that all conceivable DNS transports are contained.
    """

    interfaces = validate_interfaces(ethernet_interfaces)
    connected_status = _wait_for_mullvad_status(tools, connected=True)
    _require_lockdown_enabled(tools)
    _require_mullvad_firewall(tools)
    probes: list[dict[str, Any]] = []
    for interface in interfaces:
        for resolver in CONNECTED_DNS_PROBE_RESOLVERS:
            udp_probe = _probe_udp_dns(interface, resolver)
            probes.append(udp_probe)
            if not udp_probe["blocked"]:
                raise UmzugError(f"connected Mullvad state leaked direct UDP/DNS egress on {interface} to {resolver}")
            tcp_probe = _probe_tcp_connect(interface, resolver, 53)
            probes.append(tcp_probe)
            if not tcp_probe["blocked"]:
                raise UmzugError(f"connected Mullvad state leaked direct TCP/DNS egress on {interface} to {resolver}")
    _require_lockdown_enabled(tools)
    _require_mullvad_firewall(tools)
    return {
        "connected_status": connected_status.decode(errors="replace")[:4000],
        "literal_resolvers": list(CONNECTED_DNS_PROBE_RESOLVERS),
        "physical_dns_probes": probes,
        "scope": (
            "finite interface-bound UDP/TCP literal-IP probes to three external "
            "resolvers; negative observations are not a proof of every DNS or egress path"
        ),
    }


def _prove_fail_closed_disconnect(
    tools: BoundExecutables,
    ethernet_interfaces: list[str],
) -> dict[str, Any]:
    """exercise lockdown mode with a controlled tunnel outage.

    a finite probe cannot prove that no conceivable packet can escape.  it is
    combined with the effective vendor nftables table and literal-IP,
    interface-bound socket probes so neither DNS failure nor CLI prose alone
    can be mistaken for a kill-switch proof.
    """

    _run_mullvad(tools, ["disconnect"])
    disconnected_status = _wait_for_mullvad_status(tools, connected=False)
    _require_lockdown_enabled(tools)
    _require_mullvad_firewall(tools)
    probes: list[dict[str, Any]] = []
    try:
        for interface in ethernet_interfaces:
            for port in (80, 443):
                tcp_probe = _probe_tcp_connect(interface, "1.1.1.1", port)
                probes.append(tcp_probe)
                if not tcp_probe["blocked"]:
                    raise UmzugError(f"Mullvad Lockdown Mode leaked direct physical egress on {interface}")
            udp_probe = _probe_udp_dns(interface, CONNECTED_DNS_PROBE_RESOLVERS[0])
            probes.append(udp_probe)
            if not udp_probe["blocked"]:
                raise UmzugError(f"Mullvad Lockdown Mode leaked direct UDP/DNS egress on {interface}")
    finally:
        # reconnection is attempted even if a leak is detected; the outer
        # failure path additionally installs the independent loopback guard.
        _run_mullvad(tools, ["connect"], required=False)
    reconnected_status = _wait_for_mullvad_status(tools, connected=True)
    _require_lockdown_enabled(tools)
    _require_mullvad_firewall(tools)
    return {
        "disconnected_status": disconnected_status.decode(errors="replace")[:4000],
        "direct_egress_probes": probes,
        "reconnected_status": reconnected_status.decode(errors="replace")[:4000],
        "scope": "finite literal-IP probes plus effective nftables/Lockdown evidence; not a mathematical proof of all egress",
    }


def _blocked_socket_error(exc: OSError) -> bool:
    return isinstance(exc, TimeoutError) or exc.errno in {
        errno.EACCES,
        errno.EPERM,
        errno.ENETDOWN,
        errno.ENETUNREACH,
        errno.EHOSTDOWN,
        errno.EHOSTUNREACH,
        errno.ETIMEDOUT,
    }


def _probe_tcp_connect(interface: str, address: str, port: int) -> dict[str, Any]:
    """a successful bound TCP connect is unambiguously direct egress."""

    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise UmzugError("TCP leak probe destination must be a literal IPv4 address") from exc
    if parsed_address.version != 4 or not 1 <= port <= 65535:
        raise UmzugError("TCP leak probe destination is invalid")
    address = parsed_address.compressed
    probe: socket.socket | None = None
    destination = f"{address}:{port}/tcp"
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(8)
        probe.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            interface.encode("ascii", "strict") + b"\0",
        )
    except (OSError, UnicodeError) as exc:
        if probe is not None:
            probe.close()
        raise UmzugError(f"cannot bind TCP leak probe to physical interface {interface}") from exc
    assert probe is not None
    try:
        try:
            probe.connect((address, port))
            return {
                "interface": interface,
                "destination": destination,
                "connected": True,
                "blocked": False,
            }
        except OSError as exc:
            # refusal/reset requires a peer response and therefore proves that
            # packets escaped even though connect(2) did not return success.
            if exc.errno in {errno.ECONNREFUSED, errno.ECONNRESET}:
                return {
                    "interface": interface,
                    "destination": destination,
                    "connected": False,
                    "blocked": False,
                    "traffic_observed": True,
                    "error": type(exc).__name__,
                }
            if not _blocked_socket_error(exc):
                raise UmzugError(f"TCP leak probe on {interface} failed indeterminately") from exc
            return {
                "interface": interface,
                "destination": destination,
                "connected": False,
                "blocked": True,
                "error": type(exc).__name__,
            }
    finally:
        probe.close()


def _probe_udp_dns(interface: str, address: str) -> dict[str, Any]:
    """try one literal-IP DNS exchange on a physical device without libc DNS."""

    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise UmzugError("UDP/DNS leak probe destination must be a literal IPv4 address") from exc
    if parsed_address.version != 4:
        raise UmzugError("UDP/DNS leak probe destination must be IPv4")
    address = parsed_address.compressed

    transaction = os.urandom(2)
    query = transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x07example\x03com\x00\x00\x01\x00\x01"
    probe: socket.socket | None = None
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(8)
        probe.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_BINDTODEVICE,
            interface.encode("ascii", "strict") + b"\0",
        )
    except (OSError, UnicodeError) as exc:
        if probe is not None:
            probe.close()
        raise UmzugError(f"cannot bind UDP leak probe to physical interface {interface}") from exc
    assert probe is not None
    try:
        try:
            probe.connect((address, 53))
            if probe.send(query) != len(query):
                raise UmzugError(f"UDP/DNS leak probe on {interface} sent an incomplete datagram")
            response = probe.recv(4096)
            return {
                "interface": interface,
                "destination": f"{address}:53/udp",
                "response_bytes": len(response),
                "blocked": False,
                "traffic_observed": True,
            }
        except OSError as exc:
            if exc.errno in {errno.ECONNREFUSED, errno.ECONNRESET}:
                return {
                    "interface": interface,
                    "destination": f"{address}:53/udp",
                    "response_bytes": 0,
                    "blocked": False,
                    "traffic_observed": True,
                    "error": type(exc).__name__,
                }
            if not _blocked_socket_error(exc):
                raise UmzugError(f"UDP leak probe on {interface} failed indeterminately") from exc
            return {
                "interface": interface,
                "destination": f"{address}:53/udp",
                "response_bytes": 0,
                "blocked": True,
                "error": type(exc).__name__,
            }
    finally:
        probe.close()


def _require_units_contained(
    tools: BoundExecutables,
    units: tuple[str, ...],
) -> dict[str, dict[str, int]]:
    evidence: dict[str, dict[str, int]] = {}
    for unit in units:
        enabled = run(
            [tools.path("systemctl"), "is-enabled", unit],
            check=False,
            timeout=30,
        )
        active = run(
            [tools.path("systemctl"), "is-active", unit],
            check=False,
            timeout=30,
        )
        if enabled.returncode == 0 or active.returncode == 0:
            raise UmzugError(f"pre-finalization containment drifted for service: {unit}")
        evidence[unit] = {
            "is_enabled_exit": enabled.returncode,
            "is_active_exit": active.returncode,
        }
    return evidence


def _require_no_listening_ssh(
    tcp_paths: tuple[Path, ...] = (
        Path("/proc/net/tcp"),
        Path("/proc/net/tcp6"),
    ),
) -> dict[str, Any]:
    checked: list[str] = []
    for path in tcp_paths:
        first = _read_stable_proc_control(path)
        second = _read_stable_proc_control(path)
        if first != second:
            raise UmzugError("kernel TCP listener state changed while verifying SSH containment")
        lines = first.splitlines()
        if not lines or "local_address" not in lines[0] or "st" not in lines[0]:
            raise UmzugError(f"kernel TCP listener state has an unsupported format: {path}")
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 4 or ":" not in fields[1]:
                raise UmzugError(f"kernel TCP listener row is malformed: {path}")
            local_port = fields[1].rsplit(":", 1)[1].upper()
            state = fields[3].upper()
            if local_port == "0016" and state == "0A":
                raise UmzugError("pre-finalization state exposes a TCP listener on SSH port 22")
        checked.append(str(path))
    return {"port_22_listeners": 0, "kernel_tables": checked}


def _require_ipv6_off(
    *,
    sysctl_root: Path = Path("/proc/sys/net/ipv6/conf"),
    addresses_path: Path = Path("/proc/net/if_inet6"),
) -> dict[str, Any]:
    sysctls: dict[str, int] = {}
    for name in ("all", "default", "lo"):
        path = sysctl_root / name / "disable_ipv6"
        first = _read_stable_proc_control(path).strip()
        second = _read_stable_proc_control(path).strip()
        if first != "1" or second != first:
            raise UmzugError(f"IPv6 disablement drifted before VPN finalization: {path}")
        sysctls[name] = 1
    first_addresses = _read_stable_proc_control(addresses_path)
    second_addresses = _read_stable_proc_control(addresses_path)
    if first_addresses != second_addresses or first_addresses.strip():
        raise UmzugError("IPv6 addresses remain or changed before VPN finalization")
    return {"sysctls": sysctls, "addresses": 0}


def _require_radios_off(
    tools: BoundExecutables,
    *,
    rfkill_root: Path = Path("/sys/class/rfkill"),
) -> dict[str, Any]:
    result = run([tools.path("rfkill"), "list"], check=False, timeout=30)
    if result.returncode != 0:
        raise UmzugError("rfkill state cannot be proven before VPN finalization")
    output = result.stdout.decode("utf-8", "replace").lower()
    if "soft blocked: no" in output:
        raise UmzugError("a radio is soft-unblocked before VPN finalization")
    try:
        entries = sorted(rfkill_root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise UmzugError("kernel rfkill state cannot be enumerated safely") from exc
    checked: list[str] = []
    for entry in entries:
        soft = entry / "soft"
        state = entry / "state"
        if soft.exists():
            blocked = _read_stable_proc_control(soft).strip() == "1"
        elif state.exists():
            blocked = _read_stable_proc_control(state).strip() == "0"
        else:
            raise UmzugError(f"radio has no provable kernel block state: {entry.name}")
        if not blocked:
            raise UmzugError(f"radio is not kernel-blocked before finalization: {entry.name}")
        checked.append(entry.name)
    return {"rfkill_entries": checked, "soft_unblocked": 0}


def _require_bound_ethernet_hardware(
    ethernet_interfaces: list[str],
    *,
    net_root: Path = Path("/sys/class/net"),
) -> dict[str, Any]:
    expected = validate_interfaces(ethernet_interfaces)
    cellular_drivers = {"cdc_mbim", "qmi_wwan", "cdc_ncm", "mhi_net", "wwan"}
    observed: list[str] = []
    try:
        entries = sorted(net_root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise UmzugError("network hardware cannot be enumerated before VPN finalization") from exc
    for entry in entries:
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", entry.name):
            raise UmzugError("kernel exposed an invalid network interface name")
        if entry.name == "lo":
            continue
        try:
            arp_type = _read_stable_proc_control(entry / "type").strip()
        except UmzugError:
            raise
        physical = (entry / "device").exists()
        wireless = (entry / "wireless").exists() or (entry / "phy80211").exists()
        driver_link = entry / "device" / "driver"
        try:
            driver = driver_link.resolve(strict=True).name if driver_link.exists() else ""
        except OSError as exc:
            raise UmzugError(f"network driver changed while inspecting {entry.name}") from exc
        cellular = entry.name.startswith("wwan") or driver in cellular_drivers
        if arp_type == "1" and physical and not wireless and not cellular:
            observed.append(entry.name)
    observed = sorted(observed)
    if observed != expected:
        raise UmzugError(
            "physical Ethernet hardware drifted from the completed plan: "
            f"expected={','.join(expected)} observed={','.join(observed)}"
        )
    return {"physical_ethernet": observed}


def _require_live_pre_mutation_boundary(
    tools: BoundExecutables,
    ethernet_interfaces: list[str],
    *,
    ipv6_disabled: bool,
    radios_blocked: bool,
) -> dict[str, Any]:
    """re-prove containment immediately before any finalizer mutation."""

    required_tools = {"mullvad", "nft", "systemctl"}
    if radios_blocked:
        required_tools.add("rfkill")
    tools.require(required_tools)
    evidence: dict[str, Any] = {
        "ethernet": _require_bound_ethernet_hardware(ethernet_interfaces),
        "ssh_units": _require_units_contained(
            tools,
            ("ssh.service", "sshd.service", "ssh.socket", "sshd.socket"),
        ),
        "ssh_listener": _require_no_listening_ssh(),
    }
    if ipv6_disabled:
        evidence["ipv6"] = _require_ipv6_off()
    if radios_blocked:
        evidence["radio_units"] = _require_units_contained(
            tools,
            (
                "bluetooth.service",
                "ModemManager.service",
                "wpa_supplicant.service",
                "iwd.service",
            ),
        )
        evidence["radios"] = _require_radios_off(tools)
    evidence["fail_closed_boundary"] = _require_initial_fail_closed_boundary(tools)
    _require_host_firewall(
        tools,
        ethernet_interfaces,
        ipv6_disabled=ipv6_disabled,
    )
    evidence["host_firewall"] = "verified"
    return evidence


def _read_stable_resolv_conf(
    path: Path = Path("/etc/resolv.conf"),
) -> str:
    """read a root-controlled resolver file while detecting replacement."""

    try:
        original_before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise UmzugError("resolv.conf cannot be resolved safely") from exc
    if original_before.st_uid != 0 or not (
        stat.S_ISREG(original_before.st_mode) or stat.S_ISLNK(original_before.st_mode)
    ):
        raise UmzugError("resolv.conf is not a root-owned regular file or symlink")
    try:
        target_path_info = resolved.stat()
        target_parent_info = resolved.parent.stat()
    except OSError as exc:
        raise UmzugError("resolv.conf target cannot be inspected safely") from exc
    service_runtime_owner = (
        resolved.parent == Path("/run/systemd/resolve")
        and target_path_info.st_uid != 0
        and target_path_info.st_uid == target_parent_info.st_uid
    )
    permitted_target_uid = target_path_info.st_uid if service_runtime_owner else 0
    for parent in resolved.parents:
        try:
            parent_info = parent.stat()
        except OSError as exc:
            raise UmzugError("resolv.conf has an unreadable parent directory") from exc
        mode = stat.S_IMODE(parent_info.st_mode)
        sticky_root = bool(mode & stat.S_ISVTX) and parent_info.st_uid == 0
        permitted_parent_uid = permitted_target_uid if service_runtime_owner and parent == resolved.parent else 0
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != permitted_parent_uid
            or (mode & 0o022 and not sticky_root)
        ):
            raise UmzugError("resolv.conf has an unsafe writable parent directory")
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise UmzugError("resolv.conf cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        path_stable_fields = (
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
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != permitted_target_uid
            or mode & 0o022
            or any(getattr(target_path_info, field) != getattr(before, field) for field in path_stable_fields)
        ):
            raise UmzugError("resolv.conf target is not a protected root-owned file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            if total > MAX_PROC_CONTROL_BYTES:
                raise UmzugError("resolv.conf exceeds its parser limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if any(getattr(before, field) != getattr(after, field) for field in path_stable_fields):
            raise UmzugError("resolv.conf changed while being read")
    except OSError as exc:
        raise UmzugError("resolv.conf cannot be read safely") from exc
    finally:
        os.close(descriptor)
    try:
        text = b"".join(chunks).decode("utf-8", "strict")
        original_after = path.lstat()
        resolved_after = path.resolve(strict=True)
        target_path_after = resolved_after.stat()
    except (OSError, UnicodeError) as exc:
        raise UmzugError("resolv.conf changed or is not valid UTF-8") from exc
    original_stable = ("st_dev", "st_ino", "st_uid", "st_mode", "st_mtime_ns", "st_ctime_ns")
    if (
        resolved_after != resolved
        or any(getattr(after, field) != getattr(target_path_after, field) for field in path_stable_fields)
        or any(getattr(original_before, field) != getattr(original_after, field) for field in original_stable)
        or any(character not in "\t\n\r" and ord(character) < 0x20 for character in text)
    ):
        raise UmzugError("resolv.conf changed or contains control characters")
    return text


def _collect_bound_mullvad_online_check(
    tools: BoundExecutables,
) -> dict[str, Any]:
    completed = run(
        [
            tools.path("curl"),
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "15",
            "https://am.i.mullvad.net/connected",
        ],
        check=False,
        timeout=20,
    )
    return {
        "available": True,
        "exit": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", errors="replace")[:1000],
    }


def _collect_bound_network_evidence(
    tools: BoundExecutables,
    *,
    radios_blocked: bool,
) -> dict[str, Any]:
    """collect local evidence without PATH lookup or hostname/network access."""

    commands: dict[str, tuple[str, list[str]]] = {
        "nft_ruleset": ("nft", ["-a", "list", "ruleset"]),
        "nft_host_json": (
            "nft",
            ["--json", "list", "table", "inet", "umzug_host"],
        ),
        "nft_mullvad_json": (
            "nft",
            ["--json", "list", "table", "inet", "mullvad"],
        ),
        "nft_offline_guard_json": (
            "nft",
            ["--json", "list", "table", "inet", OFFLINE_GUARD_TABLE],
        ),
        "nft_bootstrap_guard_json": (
            "nft",
            ["--json", "list", "table", "inet", BOOTSTRAP_GUARD_TABLE],
        ),
        "ip_rules_v4": ("ip", ["-4", "rule", "show"]),
        "ip_routes_v4": ("ip", ["-4", "route", "show", "table", "all"]),
        "ip_rules_v6": ("ip", ["-6", "rule", "show"]),
        "ip_routes_v6": ("ip", ["-6", "route", "show", "table", "all"]),
        "ip_links": ("ip", ["-details", "link", "show"]),
        "listeners": ("ss", ["-lntup"]),
        "ssh_service": ("systemctl", ["is-active", "ssh.service"]),
        "sshd_service": ("systemctl", ["is-active", "sshd.service"]),
        "ssh_socket": ("systemctl", ["is-active", "ssh.socket"]),
        "sshd_socket": ("systemctl", ["is-active", "sshd.socket"]),
        "mullvad": ("mullvad", ["status", "-v"]),
        "mullvad_lockdown": ("mullvad", ["lockdown-mode", "get"]),
        "mullvad_dns": ("mullvad", ["dns", "get"]),
        "mullvad_daemon_enabled": (
            "systemctl",
            ["is-enabled", "mullvad-daemon.service"],
        ),
        "mullvad_daemon_active": (
            "systemctl",
            ["is-active", "mullvad-daemon.service"],
        ),
        "wireguard": ("wg", ["show"]),
        "wireguard_interfaces": ("wg", ["show", "interfaces"]),
    }
    if "resolvectl" in set(tools):
        commands["dns"] = ("resolvectl", ["status"])
    if radios_blocked:
        commands["rfkill"] = ("rfkill", ["list"])
    expected_success = set(commands) - {
        "nft_offline_guard_json",
        "nft_bootstrap_guard_json",
        "ssh_service",
        "sshd_service",
        "ssh_socket",
        "sshd_socket",
    }
    evidence: dict[str, Any] = {}
    for name, (tool, arguments) in commands.items():
        completed = run(
            [tools.path(tool), *arguments],
            check=False,
            timeout=30,
        )
        evidence[name] = {
            "available": True,
            "exit": completed.returncode,
            "stdout": completed.stdout.decode("utf-8", errors="replace")[:2_000_000],
        }
        if name in expected_success and completed.returncode != 0:
            raise UmzugError(f"bound final network evidence command failed: {name}")
    if not radios_blocked:
        evidence["rfkill"] = {"available": False}
    if "dns" not in evidence:
        evidence["dns"] = {"available": False}

    ipv6_sysctls: dict[str, str | None] = {}
    for name in ("all", "default", "lo"):
        try:
            ipv6_sysctls[name] = _read_stable_proc_control(
                Path(f"/proc/sys/net/ipv6/conf/{name}/disable_ipv6")
            ).strip()[:16]
        except UmzugError:
            ipv6_sysctls[name] = None
    try:
        ipv6_addresses = _read_stable_proc_control(Path("/proc/net/if_inet6"))[:2_000_000]
    except UmzugError:
        ipv6_addresses = None
    evidence["ipv6_state"] = {
        "sysctls": ipv6_sysctls,
        "addresses": ipv6_addresses,
    }
    resolv_conf = _read_stable_resolv_conf()
    evidence["resolv_conf"] = {"content": resolv_conf}

    dns_record = evidence["dns"]
    dns_status = str(dns_record["stdout"]) if dns_record.get("available") is True else None
    resolver_sources = parse_effective_dns_sources(dns_status, resolv_conf)
    resolver_scopes: dict[str, set[str]] = {}
    for source in resolver_sources:
        address = str(source["address"])
        scope = source.get("scope")
        if isinstance(scope, str):
            resolver_scopes.setdefault(address, set()).add(scope)
    lookups: list[dict[str, Any]] = []
    for address in sorted({str(source["address"]) for source in resolver_sources}):
        scopes = resolver_scopes.get(address, set())
        if len(scopes) > 1:
            raise UmzugError("effective DNS resolver has ambiguous route scopes")
        parsed_address = ipaddress.ip_address(address)
        query_address = address
        if scopes:
            query_address = f"{address}%{next(iter(scopes))}"
        completed = run(
            [
                tools.path("ip"),
                "-j",
                f"-{parsed_address.version}",
                "route",
                "get",
                query_address,
                "uid",
                "0",
            ],
            check=False,
            timeout=30,
        )
        lookups.append(
            {
                "address": address,
                "family": parsed_address.version,
                "uid": 0,
                "exit": completed.returncode,
                "stdout": completed.stdout.decode("utf-8", errors="replace")[:2_000_000],
            }
        )
    evidence["resolver_routes"] = {
        "available": True,
        "sources": resolver_sources,
        "lookups": lookups,
    }
    # the resolver snapshot and its route lookups are sequential netlink/dbus
    # observations, not an atomic kernel transaction.  re-read both endpoints
    # and fail rather than signing a report across an observed configuration
    # change.
    if dns_status is not None:
        dns_confirmation = run(
            [tools.path("resolvectl"), "status"],
            check=False,
            timeout=30,
        )
        confirmed_dns_status: str | None = dns_confirmation.stdout.decode("utf-8", errors="replace")[:2_000_000]
        dns_confirmation_exit: int | None = dns_confirmation.returncode
    else:
        confirmed_dns_status = None
        dns_confirmation_exit = None
    resolv_conf_confirmation = _read_stable_resolv_conf()
    if (
        (dns_status is not None and dns_confirmation_exit != 0)
        or confirmed_dns_status != dns_status
        or resolv_conf_confirmation != resolv_conf
    ):
        raise UmzugError("effective DNS configuration changed during evidence collection")

    evidence["mullvad_online"] = {"available": False}
    return evidence


def finalize_mullvad_app(
    *,
    bound_executables: BoundExecutables,
    plan_sha256: str,
    ethernet_interfaces: list[str],
    ipv6_disabled: bool,
    radios_blocked: bool,
    package_manager: str,
    vendor_package_version: str,
    vendor_package_architecture: str,
    vendor_artifact_sha256: str,
    encrypted_storage: bool,
    anti_censorship: str = "auto",
    audit: AuditLog | None = None,
    online_verification: bool = True,
    management_group: str = "mullvad-management",
) -> dict[str, Any]:
    """last, and only network-requiring, account/bootstrap step."""
    if os.geteuid() != 0:
        raise UmzugError("Mullvad finalization must run as root")
    if anti_censorship not in ANTI_CENSORSHIP_MODES:
        raise UmzugError("unsupported anti-censorship mode")
    audit = audit or AuditLog(None)
    if not re.fullmatch(r"[0-9a-f]{64}", plan_sha256):
        raise UmzugError("VPN finalization lacks a valid completed-plan binding")
    if not ethernet_interfaces:
        raise UmzugError("VPN finalization lacks a reviewed Ethernet interface set")
    if not re.fullmatch(r"[0-9a-f]{64}", vendor_artifact_sha256):
        raise UmzugError("VPN finalization lacks a reviewed vendor artifact binding")
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,127}",
        vendor_package_version,
    ) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}",
        vendor_package_architecture,
    ):
        raise UmzugError("VPN finalization lacks a reviewed vendor package identity")
    if not isinstance(bound_executables, BoundExecutables):
        raise UmzugError("VPN finalization requires completed-plan executable receipts")
    required_tools = _required_finalization_executables(
        package_manager,
        radios_blocked=radios_blocked,
        online_verification=online_verification,
    )
    # this second validation is deliberate: completed context may have been
    # loaded before target/hardware checks and must not authorize a later swap.
    bound_executables.require(required_tools)
    _check_account_storage(encrypted_storage=encrypted_storage)
    pre_mutation_evidence = _require_live_pre_mutation_boundary(
        bound_executables,
        ethernet_interfaces,
        ipv6_disabled=ipv6_disabled,
        radios_blocked=radios_blocked,
    )
    initial_boundary = str(pre_mutation_evidence["fail_closed_boundary"])
    installed_package = _require_installed_mullvad_package(
        package_manager,
        bound_executables,
        expected_version=vendor_package_version,
        expected_architecture=vendor_package_architecture,
    )
    bootstrap_installed = False
    try:
        _install_bootstrap_guard(bound_executables)
        bootstrap_installed = True
        _require_bootstrap_guard(bound_executables)
        audit.event(
            "mullvad.bootstrap_guard.installed",
            plan_sha256=plan_sha256,
            vendor_artifact_sha256=vendor_artifact_sha256,
            installed_package=installed_package,
            initial_fail_closed_boundary=initial_boundary,
        )
        _require_management_restriction(management_group, bound_executables)
        _require_daemon_persistent(bound_executables)
        _run_mullvad(bound_executables, ["lockdown-mode", "set", "on"])
        _run_mullvad(bound_executables, ["split-tunnel", "clear"])
        _run_mullvad(bound_executables, ["lan", "set", "block"])
        _run_mullvad(bound_executables, ["dns", "set", "default"])
        _run_mullvad(bound_executables, ["auto-connect", "set", "on"])
        if anti_censorship == "auto":
            _run_mullvad(
                bound_executables,
                ["anti-censorship", "set", "mode", "auto"],
            )
        else:
            _run_mullvad(
                bound_executables,
                ["anti-censorship", "set", "mode", anti_censorship],
            )
        _require_lockdown_enabled(bound_executables)
        _require_mullvad_firewall(bound_executables)

        # keep the bootstrap table active while disabling persistence and
        # deleting the stricter offline table. mullvad's effective drop/DNS
        # table is checked both before and immediately after the final handoff.
        _retire_offline_guard_under_bootstrap(bound_executables)
        _require_lockdown_enabled(bound_executables)
        _require_mullvad_firewall(bound_executables)
        _remove_bootstrap_guard(bound_executables)
        bootstrap_installed = False
        _guard_json(bound_executables, BOOTSTRAP_GUARD_TABLE, required=False)
        try:
            _require_lockdown_enabled(bound_executables)
            _require_mullvad_firewall(bound_executables)
        except BaseException:
            _install_bootstrap_guard(bound_executables)
            bootstrap_installed = True
            raise
        audit.event("mullvad.setup_guards.retired_after_effective_lockdown")
        audit.event("mullvad.settings.applied", anti_censorship=anti_censorship)

        procfs_privacy = _require_private_procfs()
        secret_entry_safety = _require_secret_entry_safety()
        account_storage_before = _verify_account_history_permissions()
        device_storage_before = _verify_device_permissions()
        if not sys.stdin.isatty():
            raise UmzugError(
                "account entry is intentionally TTY-only and cannot come from config, argv, or environment"
            )
        account_text = getpass.getpass("Mullvad-Kontonummer (16 Ziffern; wird nicht protokolliert): ").strip()
        if not ACCOUNT_RE.fullmatch(account_text):
            account_text = ""
            raise UmzugError("invalid Mullvad account number format; Lockdown Mode remains enabled")
        account = bytearray(account_text, "ascii")
        account_text = ""
        try:
            audit.event("mullvad.login.begin", plan_sha256=plan_sha256)
            _login_secret(account, bound_executables)
        finally:
            for index in range(len(account)):
                account[index] = 0
        storage = _verify_account_history_permissions()
        device_storage = _verify_device_permissions()
        if storage.get("exists") is not True:
            raise UmzugError("Mullvad login did not create a verifiably private account-history file")
        if device_storage.get("exists") is not True:
            raise UmzugError("Mullvad login did not create a verifiably private device-state file")
        _run_mullvad(bound_executables, ["connect"])
        status = _wait_for_mullvad_status(bound_executables, connected=True)
        initial_evidence = _collect_bound_network_evidence(
            bound_executables,
            radios_blocked=radios_blocked,
        )
        assert_final_network_evidence(
            initial_evidence,
            ethernet_interfaces,
            ipv6_disabled=ipv6_disabled,
            radios_blocked=radios_blocked,
            online_verification=False,
        )
        initial_connected_dns_proof = _prove_connected_dns_containment(
            bound_executables,
            ethernet_interfaces,
        )
        if online_verification:
            initial_evidence["mullvad_online"] = _collect_bound_mullvad_online_check(bound_executables)
            assert_final_network_evidence(
                initial_evidence,
                ethernet_interfaces,
                ipv6_disabled=ipv6_disabled,
                radios_blocked=radios_blocked,
                online_verification=True,
            )
        disconnect_proof = _prove_fail_closed_disconnect(
            bound_executables,
            ethernet_interfaces,
        )
        evidence = _collect_bound_network_evidence(
            bound_executables,
            radios_blocked=radios_blocked,
        )
        assert_final_network_evidence(
            evidence,
            ethernet_interfaces,
            ipv6_disabled=ipv6_disabled,
            radios_blocked=radios_blocked,
            online_verification=False,
        )
        connected_dns_proof = _prove_connected_dns_containment(
            bound_executables,
            ethernet_interfaces,
        )
        if online_verification:
            evidence["mullvad_online"] = _collect_bound_mullvad_online_check(bound_executables)
            assert_final_network_evidence(
                evidence,
                ethernet_interfaces,
                ipv6_disabled=ipv6_disabled,
                radios_blocked=radios_blocked,
                online_verification=True,
            )
        audit.event(
            "mullvad.connected",
            account_storage=storage,
            account_storage_before_login=account_storage_before,
            device_storage=device_storage,
            device_storage_before_login=device_storage_before,
            procfs_privacy=procfs_privacy,
            secret_entry_safety=secret_entry_safety,
            online_verified=online_verification,
            plan_sha256=plan_sha256,
            finite_fail_closed_disconnect_checks_passed=True,
            finite_connected_dns_containment_checks_passed=True,
        )
    except BaseException:
        # Any failure after the handoff reinstalls an independent loopback-only
        # output guard. if the offline guard still exists, this is idempotent
        # defence in depth.
        try:
            # this is an idempotent declare+flush+populate transaction.  run it
            # even when our local flag says a guard exists: the effective table
            # may have been altered between the earlier proof and this failure.
            _restore_persistent_offline_guard(bound_executables)
            bootstrap_installed = True
            audit.event("mullvad.persistent_offline_guard.restored_after_failure")
        except BaseException as guard_error:
            audit.event(
                "mullvad.bootstrap_guard.reinstall_failed",
                error=type(guard_error).__name__,
            )
        raise
    return {
        "status": status.decode(errors="replace")[:4000],
        "plan_sha256": plan_sha256,
        "vendor_artifact_sha256": vendor_artifact_sha256,
        "installed_package": installed_package,
        "account_storage": storage,
        "account_storage_before_login": account_storage_before,
        "device_storage": device_storage,
        "device_storage_before_login": device_storage_before,
        "procfs_privacy": procfs_privacy,
        "secret_entry_safety": secret_entry_safety,
        "pre_mutation_evidence": pre_mutation_evidence,
        "evidence": evidence,
        "initial_connected_evidence": initial_evidence,
        "initial_connected_dns_containment_proof": initial_connected_dns_proof,
        "connected_dns_containment_proof": connected_dns_proof,
        "fail_closed_disconnect_proof": disconnect_proof,
        "limitations": [
            "The official CLI transiently receives the account number in argv. hidepid protects ordinary users; privileged process inspection remains outside this tool's protection.",
            "Account entry is refused while any swap is active or the global kernel core-dump policy is enabled; this is intentionally stricter than inferring encrypted swap.",
            "Mullvad's local management socket and root/API exceptions remain within Mullvad's documented threat model boundaries.",
            "The disconnect test uses finite literal-IP TCP/80, TCP/443 and UDP/53 probes; it materially tests fail-closed behavior but cannot prove every possible egress path.",
            "Connected-state DNS containment combines effective resolver route checks with finite, physical-interface-bound UDP/TCP probes to three external literal resolvers; timeouts are negative observations, not a mathematical proof against every DNS transport or race.",
            "A compromised root user cannot be contained by this local hardening profile.",
        ],
    }
