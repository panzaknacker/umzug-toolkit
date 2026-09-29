from __future__ import annotations

import grp
import os
from pathlib import Path
import pwd
import platform
from typing import Any, Iterable

from .util import run, which


def _command_lines(argv: list[str], timeout: int = 60) -> list[str]:
    if which(argv[0]) is None:
        return []
    try:
        result = run(argv, timeout=timeout)
    except Exception:  # inventory failure must be visible but not abort payload creation.
        return []
    return result.stdout.decode("utf-8", errors="replace").splitlines()


INVENTORY_SECTIONS = ("system", "packages", "accounts", "services")


def collect_inventory(sections: Iterable[str] | None = None) -> dict[str, Any]:
    """collect only explicitly selected local metadata sections."""

    requested = set(INVENTORY_SECTIONS if sections is None else sections)
    unknown = sorted(requested - set(INVENTORY_SECTIONS))
    if unknown:
        raise ValueError(f"unknown inventory sections: {', '.join(unknown)}")
    if not requested:
        return {}
    os_release: dict[str, str] = {}
    if "system" in requested:
        try:
            for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    os_release[key] = value.strip().strip('"')
        except OSError:
            pass

    packages: dict[str, list[str]] = {}
    if "packages" in requested and which("dpkg-query"):
        packages["installed"] = _command_lines(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"])
        packages["manual"] = _command_lines(["apt-mark", "showmanual"]) if which("apt-mark") else []
    elif "packages" in requested and which("pacman"):
        packages["installed"] = _command_lines(["pacman", "-Q"])
        packages["manual"] = _command_lines(["pacman", "-Qqe"])
    elif "packages" in requested and which("nix-env"):
        packages["installed"] = _command_lines(["nix-env", "-q", "--installed"])
    elif "packages" in requested and Path("/var/db/pkg").is_dir():
        installed: list[str] = []
        for category in sorted(Path("/var/db/pkg").iterdir()):
            if category.is_dir():
                installed.extend(
                    f"{category.name}/{entry.name}" for entry in sorted(category.iterdir()) if entry.is_dir()
                )
        packages["installed"] = installed

    users = (
        [
            {
                "name": entry.pw_name,
                "uid": entry.pw_uid,
                "gid": entry.pw_gid,
                "home": entry.pw_dir,
                "shell": entry.pw_shell,
            }
            for entry in pwd.getpwall()
        ]
        if "accounts" in requested
        else []
    )
    groups = (
        [{"name": entry.gr_name, "gid": entry.gr_gid, "members": list(entry.gr_mem)} for entry in grp.getgrall()]
        if "accounts" in requested
        else []
    )
    services = (
        _command_lines(["systemctl", "list-unit-files", "--no-legend", "--no-pager", "--plain"], timeout=120)
        if "services" in requested and which("systemctl")
        else []
    )
    timers = (
        _command_lines(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"], timeout=120)
        if "services" in requested and which("systemctl")
        else []
    )

    result: dict[str, Any] = {}
    if "system" in requested:
        result["system"] = {
            "os_release": os_release,
            "architecture": platform.machine(),
            "kernel": platform.release(),
            "python": platform.python_version(),
        }
    if "packages" in requested:
        result["packages"] = packages
    if "accounts" in requested:
        result.update({"users": users, "groups": groups})
    if "services" in requested:
        result.update({"services": services, "timers": timers})
    result["note"] = (
        "Explicitly selected inventory only; no shadow hashes, environment variables, "
        "Wi-Fi secrets, VPN credentials, or SSH private keys were inventoried."
    )
    return result
