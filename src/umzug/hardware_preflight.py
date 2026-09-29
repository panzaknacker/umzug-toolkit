"""read-only, fail-closed preflight for a reviewed productive setup plan.

the observations in this module are deliberately ephemeral.  they are never
accepted as executor receipts and cannot authorize an apply.  in particular,
this module must not instantiate :class:`StateStore` or :class:`Executor`.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable, Mapping

from . import __version__
from .console import remote_session_evidence
from .detection import SystemFacts
from .executor import _trusted_executable
from .hardening import radio_hardware_inventory, target_system_fingerprint
from .model import Plan, required_preflight_executables
from .state_storage import observe_persistent_state_storage
from .util import UmzugError, terminal_safe


PRODUCTION_RUNTIME = Path("/opt/umzug/runtime")
MIN_FREE_BYTES = 1024**3
BACKUP_HEADROOM_BYTES = 256 * 1024**2
MAX_BACKUP_OBJECTS = 100_000
MIN_BATTERY_PERCENT = 50
AUTOMATIC_STATUSES = frozenset({"pass", "warning", "block"})
ATTESTATION_IDS = frozenset(
    {
        "backup-and-rollback-reviewed",
        "destructive-actions-reviewed",
        "full-backup-restore-tested",
        "network-physically-disconnected",
        "reboot-path-tested",
        "recovery-medium-boot-tested",
        "stable-power-confirmed",
    }
)
_CONSOLE_RE = re.compile(r"/dev/(?:console|tty[0-9]+|ttyS[0-9]+|hvc[0-9]+)\Z")
_PSEUDO_FILESYSTEMS = frozenset({"autofs", "devtmpfs", "overlay", "proc", "ramfs", "sysfs", "tmpfs"})


def _automatic(
    check_id: str,
    status: str,
    summary: str,
    evidence: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if status not in AUTOMATIC_STATUSES:
        raise ValueError(f"invalid automatic preflight status: {status}")
    return {
        "id": check_id,
        "status": status,
        "summary": summary,
        "evidence": dict(evidence or {}),
    }


def compare_plan_target(
    plan: Plan,
    facts: SystemFacts,
    *,
    allow_missing_radio_drivers_after_reboot: bool = False,
) -> dict[str, Any]:
    """compare one validated plan with one already-collected fact snapshot."""

    observed_fingerprint = target_system_fingerprint(facts.to_dict())
    planned_ethernet = sorted(plan.intent.get("ethernet_interfaces", []))
    observed_ethernet = sorted(
        {device.name for device in facts.network_devices if device.kind == "ethernet" and not device.virtual}
    )
    observed_radios = sorted(
        {
            str(device.driver).replace("-", "_")
            for device in facts.network_devices
            if device.kind in {"wifi", "cellular"} and device.driver
        }
    )
    planned_radios = plan.intent.get("radio_modules", [])
    planned_radio_hardware = plan.intent.get("radio_hardware", [])
    observed_radio_hardware = radio_hardware_inventory(facts.to_dict())
    profile_intent = plan.intent.get("profile")
    vpn_killswitch = isinstance(profile_intent, dict) and profile_intent.get("vpn_killswitch") is True
    blockers: list[str] = []
    if observed_fingerprint != plan.system_fingerprint:
        blockers.append(
            "plan target fingerprint does not match this system; create and review a new plan on the target"
        )

    distribution_match = True
    distribution_like_match = True
    init_system_match = True
    package_managers_match = True
    ethernet_match = True
    radio_match = True
    radio_hardware_match = True
    if plan.profile != "test":
        distribution_match = plan.intent.get("distribution") == facts.distribution.id
        distribution_like_match = plan.intent.get("distribution_like") == sorted(set(facts.distribution.id_like))
        init_system_match = plan.intent.get("init_system") == facts.init_system
        package_managers_match = plan.intent.get("package_managers") == sorted(set(facts.package_managers))
        if not all(
            (
                distribution_match,
                distribution_like_match,
                init_system_match,
                package_managers_match,
            )
        ):
            blockers.append("plan distribution/init/adapter intent differs from the detected target")

        if vpn_killswitch:
            ethernet_match = set(planned_ethernet) == set(observed_ethernet)
            if not ethernet_match:
                blockers.append(
                    "VPN kill-switch plan Ethernet intent does not exactly match all physical target hardware"
                )
        else:
            ethernet_match = set(planned_ethernet).issubset(set(observed_ethernet))
            if not ethernet_match:
                blockers.append("plan Ethernet intent is not present as physical target hardware")

        radio_match = isinstance(planned_radios, list) and (
            set(observed_radios).issubset(set(planned_radios))
            if allow_missing_radio_drivers_after_reboot
            else planned_radios == observed_radios
        )
        if not radio_match:
            blockers.append("plan radio-module intent differs from locally detected Wi-Fi/cellular drivers")

        if allow_missing_radio_drivers_after_reboot:
            planned_by_device = {
                (row["name"], row["kind"], row["mac_address"]): row
                for row in planned_radio_hardware
                if isinstance(row, dict)
            }
            radio_hardware_match = all(
                (
                    (observed["name"], observed["kind"], observed["mac_address"]) in planned_by_device
                    and (
                        not observed["driver"]
                        or observed["driver"]
                        == planned_by_device[
                            (
                                observed["name"],
                                observed["kind"],
                                observed["mac_address"],
                            )
                        ]["driver"]
                    )
                )
                for observed in observed_radio_hardware
            )
        else:
            radio_hardware_match = planned_radio_hardware == observed_radio_hardware
        if not radio_hardware_match:
            blockers.append("plan radio-hardware identity differs from locally detected Wi-Fi/cellular devices")

    return {
        "fingerprint_planned": plan.system_fingerprint,
        "fingerprint_observed": observed_fingerprint,
        "fingerprint_match": observed_fingerprint == plan.system_fingerprint,
        "distribution_match": distribution_match,
        "distribution_like_match": distribution_like_match,
        "init_system_match": init_system_match,
        "package_manager_set_match": package_managers_match,
        "ethernet": {
            "policy": "exact-all-physical" if vpn_killswitch else "planned-subset",
            "planned": planned_ethernet,
            "observed_physical": observed_ethernet,
            "match": ethernet_match,
        },
        "radio_modules": {
            "policy": (
                "observed-subset-after-reboot" if allow_missing_radio_drivers_after_reboot else "exact-pre-apply"
            ),
            "planned": planned_radios if isinstance(planned_radios, list) else [],
            "observed": observed_radios,
            "match": radio_match,
        },
        "radio_hardware": {
            "policy": (
                "observed-device-subset-after-reboot" if allow_missing_radio_drivers_after_reboot else "exact-pre-apply"
            ),
            "planned": planned_radio_hardware,
            "observed": observed_radio_hardware,
            "match": radio_hardware_match,
        },
        "blockers": blockers,
    }


def _stable_file_observation(path: Path, *, executable: bool = False) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UmzugError(f"cannot safely open trusted runtime file: {path}") from exc
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or mode & 0o022
            or mode & 0o7000
            or (executable and not mode & 0o100)
        ):
            raise UmzugError(f"trusted runtime file has unsafe metadata: {path}")
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
            raise UmzugError(f"trusted runtime file changed while observed: {path}")
        current = path.lstat()
        if stat.S_ISLNK(current.st_mode) or (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
            current.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise UmzugError(f"trusted runtime file path changed while observed: {path}")
        return {
            "path": str(path),
            "sha256": digest.hexdigest(),
            "size": after.st_size,
            "device": after.st_dev,
            "inode": after.st_ino,
            "mtime_ns": after.st_mtime_ns,
            "ctime_ns": after.st_ctime_ns,
        }
    finally:
        os.close(fd)


def _root_owned_path_chain(path: Path) -> None:
    if not path.is_absolute():
        raise UmzugError("trusted runtime path is not absolute")
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise UmzugError(f"trusted runtime path cannot be inspected: {current}") from exc
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or mode & 0o022:
            raise UmzugError(f"trusted runtime path is mutable or linked: {current}")


def observe_productive_runtime() -> dict[str, Any]:
    """prove the fixed installed launcher/runtime shape without modifying it."""

    expected_python = PRODUCTION_RUNTIME / "bin" / "python"
    wrapper = PRODUCTION_RUNTIME / "bin" / "umzug-setup-root"
    module_path = Path(__file__).absolute()
    actual_python = Path(sys.executable).absolute()
    if actual_python != expected_python:
        raise UmzugError("hardware preflight must run through /opt/umzug/runtime/bin/umzug-setup-root")
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise UmzugError("productive setup runtime lacks Python -I/-B isolation")
    try:
        module_path.relative_to(PRODUCTION_RUNTIME)
    except ValueError as exc:
        raise UmzugError("loaded toolkit module is outside the fixed production runtime") from exc
    for path in (expected_python, wrapper, module_path):
        _root_owned_path_chain(path)
    return {
        "runtime": str(PRODUCTION_RUNTIME),
        "python": _stable_file_observation(expected_python, executable=True),
        "wrapper": _stable_file_observation(wrapper, executable=True),
        "loaded_module": _stable_file_observation(module_path),
        "isolated_python": True,
        "bytecode_writes_disabled": True,
        "cryptographic_install_provenance_rechecked": False,
    }


def observe_local_console(
    *,
    environ: Mapping[str, str] | None = None,
    stdin_fd: int = 0,
    stdout_fd: int = 1,
) -> dict[str, Any]:
    environment = os.environ if environ is None else environ
    ssh_markers = sorted(
        name
        for name in (
            "SSH_CLIENT",
            "SSH_CONNECTION",
            "SSH_TTY",
            "UMZUG_INVOCATION_REMOTE",
        )
        if environment.get(name) and environment.get(name) != "0"
    )
    stdin_tty = os.isatty(stdin_fd)
    stdout_tty = os.isatty(stdout_fd)
    tty_name: str | None = None
    if stdin_tty:
        try:
            tty_name = os.ttyname(stdin_fd)
        except OSError:
            tty_name = None
    console_proven = bool(stdin_tty and tty_name and _CONSOLE_RE.fullmatch(tty_name) and not ssh_markers)
    return {
        "console_proven": console_proven,
        "stdin_tty": stdin_tty,
        "stdout_tty": stdout_tty,
        "tty": tty_name,
        "ssh_environment_markers": ssh_markers,
        "pseudo_terminal_rejected": bool(tty_name and tty_name.startswith("/dev/pts/")),
        "stdout_tty_required_for_report": False,
        "stdout_tty_required_for_productive_apply": True,
    }


def _read_power_attribute(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return None
    if len(value) > 4096:
        return None
    return value.strip()


def observe_power(sys_root: Path = Path("/sys")) -> dict[str, Any]:
    supply_root = sys_root / "class" / "power_supply"
    if not supply_root.is_dir():
        return {
            "status": "warning",
            "summary": "Stromversorgung ist über sysfs nicht erkennbar",
            "supplies": [],
            "stable_power_automatic": False,
        }
    try:
        entries = sorted(supply_root.iterdir(), key=lambda path: path.name)
    except OSError:
        return {
            "status": "block",
            "summary": "Erkannte Stromversorgungsdaten sind nicht vollständig lesbar",
            "supplies": [],
            "stable_power_automatic": False,
        }

    supplies: list[dict[str, Any]] = []
    malformed_battery = False
    mains_online = False
    battery_rows: list[dict[str, Any]] = []
    for entry in entries:
        supply_type = _read_power_attribute(entry / "type")
        if not supply_type:
            continue
        row: dict[str, Any] = {"name": entry.name, "type": supply_type}
        online_text = _read_power_attribute(entry / "online")
        if online_text in {"0", "1"}:
            row["online"] = online_text == "1"
        if supply_type.lower() in {"mains", "usb", "usb_c", "usb-c"}:
            mains_online = mains_online or row.get("online") is True
        if supply_type.lower() == "battery":
            capacity_text = _read_power_attribute(entry / "capacity")
            status_text = _read_power_attribute(entry / "status")
            try:
                capacity = int(capacity_text) if capacity_text is not None else None
            except ValueError:
                capacity = None
            if capacity is None or not 0 <= capacity <= 100 or not status_text:
                malformed_battery = True
            row["capacity_percent"] = capacity
            row["status"] = status_text
            battery_rows.append(row)
        supplies.append(row)

    if malformed_battery:
        status = "block"
        summary = "Eine erkannte Batterie liefert keine vollständigen belastbaren Werte"
        stable = False
    elif mains_online:
        status = "pass"
        summary = "Eine externe Stromversorgung wird als online gemeldet"
        stable = True
    elif battery_rows:
        capacities = [row["capacity_percent"] for row in battery_rows]
        discharging = any(
            str(row.get("status", "")).lower() in {"discharging", "not charging", "unknown"} for row in battery_rows
        )
        if discharging or min(capacities) < MIN_BATTERY_PERCENT:
            status = "block"
            summary = "Batteriebetrieb ist für destruktive Änderungen oder Neustarts nicht stabil genug"
            stable = False
        else:
            status = "warning"
            summary = "Batterie ist ausreichend geladen, aber externe Versorgung ist nicht beweisbar"
            stable = False
    else:
        status = "warning"
        summary = "Keine Batterie oder messbare externe Versorgung erkannt; Desktop-Strom bleibt unbeweisbar"
        stable = False
    return {
        "status": status,
        "summary": summary,
        "supplies": supplies,
        "stable_power_automatic": stable,
    }


def _read_bounded_kernel_text(path: Path, *, max_bytes: int = 1024 * 1024) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UmzugError(f"kernel network evidence is unavailable: {path}") from exc
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise UmzugError(f"kernel network evidence exceeds its bound: {path}")
        return b"".join(chunks).decode("ascii", "strict")
    except UnicodeError as exc:
        raise UmzugError(f"kernel network evidence is not canonical ASCII: {path}") from exc
    finally:
        os.close(fd)


def _ipv4_default_routes(text: str) -> list[dict[str, Any]]:
    lines = [line.split() for line in text.splitlines() if line.strip()]
    if not lines or lines[0][:4] != ["Iface", "Destination", "Gateway", "Flags"]:
        raise UmzugError("/proc/net/route has no canonical header")
    routes: list[dict[str, Any]] = []
    for fields in lines[1:]:
        if (
            len(fields) < 8
            or not fields[0]
            or not re.fullmatch(r"[0-9A-Fa-f]{8}", fields[1])
            or not re.fullmatch(r"[0-9A-Fa-f]{8}", fields[2])
            or not re.fullmatch(r"[0-9A-Fa-f]{4,8}", fields[3])
            or not re.fullmatch(r"[0-9A-Fa-f]{8}", fields[7])
        ):
            raise UmzugError("/proc/net/route contains a malformed record")
        flags = int(fields[3], 16)
        if fields[1] == "00000000" and fields[7] == "00000000" and flags & 0x1:
            routes.append({"family": "ipv4", "interface": fields[0], "up": True})
    return routes


def _ipv6_default_routes(text: str) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for fields in (line.split() for line in text.splitlines() if line.strip()):
        if (
            len(fields) != 10
            or not re.fullmatch(r"[0-9A-Fa-f]{32}", fields[0])
            or not re.fullmatch(r"[0-9A-Fa-f]{2}", fields[1])
            or not re.fullmatch(r"[0-9A-Fa-f]{32}", fields[2])
            or not re.fullmatch(r"[0-9A-Fa-f]{2}", fields[3])
            or not re.fullmatch(r"[0-9A-Fa-f]{32}", fields[4])
            or any(not re.fullmatch(r"[0-9A-Fa-f]{8}", value) for value in fields[5:9])
            or not fields[9]
        ):
            raise UmzugError("/proc/net/ipv6_route contains a malformed record")
        flags = int(fields[8], 16)
        if fields[0] == "0" * 32 and fields[1] == "00" and flags & 0x1:
            routes.append({"family": "ipv6", "interface": fields[9], "up": True})
    return routes


def observe_offline_boundary(
    facts: SystemFacts,
    *,
    proc_root: Path = Path("/proc"),
    sys_root: Path = Path("/sys"),
) -> dict[str, Any]:
    """observe link/carrier/routes without sending any packet or changing a link."""

    interfaces: list[dict[str, Any]] = []
    errors: list[str] = []
    active_interfaces: list[str] = []
    physical = sorted(
        (device for device in facts.network_devices if device.name != "lo" and not device.virtual),
        key=lambda device: device.name,
    )
    if not physical:
        errors.append("no physical non-loopback network interface was detected")
    for device in physical:
        carrier_text = _read_power_attribute(sys_root / "class" / "net" / device.name / "carrier")
        carrier = True if carrier_text == "1" else False if carrier_text == "0" else None
        operstate = str(device.operstate or "unknown").lower()
        active = carrier is True or operstate == "up"
        unclear = carrier is None or operstate in {"", "unknown"}
        if active:
            active_interfaces.append(device.name)
        if unclear:
            errors.append(f"link/carrier evidence is incomplete for {device.name}")
        interfaces.append(
            {
                "name": device.name,
                "kind": device.kind,
                "driver": device.driver,
                "operstate": operstate,
                "carrier": carrier,
                "active": active,
            }
        )

    defaults: list[dict[str, Any]] = []
    try:
        defaults.extend(_ipv4_default_routes(_read_bounded_kernel_text(proc_root / "net" / "route")))
    except UmzugError as exc:
        errors.append(str(exc))
    try:
        defaults.extend(_ipv6_default_routes(_read_bounded_kernel_text(proc_root / "net" / "ipv6_route")))
    except UmzugError as exc:
        errors.append(str(exc))

    blocked = bool(active_interfaces or defaults or errors)
    reasons: list[str] = []
    if active_interfaces:
        reasons.append("physical carrier/operstate active: " + ", ".join(active_interfaces))
    if defaults:
        reasons.append(
            "active default route present: "
            + ", ".join(f"{route['family']}:{route['interface']}" for route in defaults)
        )
    reasons.extend(errors)
    return {
        "status": "block" if blocked else "pass",
        "summary": (
            "Offline-Grenze ist nicht bewiesen: " + "; ".join(reasons)
            if blocked
            else "Alle erkannten physischen Links sind ohne Carrier und IPv4/IPv6 haben keine aktive Default-Route"
        ),
        "physical_interfaces": interfaces,
        "active_default_routes": defaults,
        "evidence_errors": errors,
        "network_probe_sent": False,
        "network_state_changed": False,
    }


def _existing_state_parent(state_dir: Path, owner_uid: int) -> tuple[Path, bool, bool]:
    if not state_dir.is_absolute() or state_dir == Path("/"):
        raise UmzugError("state directory must be a non-root absolute path")
    current = Path("/")
    state_exists = False
    state_empty = True
    for index, part in enumerate(state_dir.parts[1:], 1):
        current /= part
        final = index == len(state_dir.parts) - 1
        try:
            info = current.lstat()
        except FileNotFoundError:
            return current.parent, False, True
        except OSError as exc:
            raise UmzugError(f"state path cannot be inspected safely: {current}") from exc
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise UmzugError(f"state path contains a link or non-directory: {current}")
        if final:
            state_exists = True
            if info.st_uid != owner_uid or mode & 0o077:
                raise UmzugError("existing state directory is not private and owned by root")
            try:
                with os.scandir(current) as entries:
                    state_empty = next(entries, None) is None
            except OSError as exc:
                raise UmzugError("existing state directory cannot be enumerated") from exc
            if not state_empty:
                raise UmzugError(
                    "state directory is not empty; use the matching resume/rollback flow or a fresh state path"
                )
        elif owner_uid == 0:
            sticky_root = info.st_uid == 0 and bool(mode & stat.S_ISVTX) and bool(mode & 0o002)
            if info.st_uid != 0 or (mode & 0o022 and not sticky_root):
                raise UmzugError(f"root state path has a non-root-owned or writable parent: {current}")
    return state_dir, state_exists, state_empty


def observe_state_path(
    state_dir: Path,
    *,
    owner_uid: int | None = None,
    mountinfo_path: Path = Path("/proc/self/mountinfo"),
) -> dict[str, Any]:
    owner = os.geteuid() if owner_uid is None else owner_uid
    parent, exists, empty = _existing_state_parent(state_dir, owner)
    persistent = observe_persistent_state_storage(
        state_dir,
        mountinfo_path=mountinfo_path,
    )
    try:
        filesystem = os.statvfs(parent)
    except OSError as exc:
        raise UmzugError("state filesystem capacity cannot be inspected") from exc
    read_only_flag = getattr(os, "ST_RDONLY", 1)
    if filesystem.f_flag & read_only_flag:
        raise UmzugError("state filesystem is read-only")
    return {
        "state_dir": str(state_dir),
        "backup_dir": str(state_dir / "backups"),
        "existing_parent": str(parent),
        "state_exists": exists,
        "state_empty": empty,
        "available_bytes": filesystem.f_bavail * filesystem.f_frsize,
        "persistent_storage": persistent,
        "created_or_modified": False,
    }


def _scan_backup_target(path: Path) -> tuple[int, int, str]:
    try:
        root_info = path.lstat()
    except FileNotFoundError:
        return 0, 0, "absent-will-record-nonexistence"
    except OSError as exc:
        raise UmzugError(f"backup target cannot be inspected: {path}") from exc
    if stat.S_ISLNK(root_info.st_mode):
        raise UmzugError(f"planned managed/backup target is a symlink and would be rejected during apply: {path}")
    if stat.S_ISREG(root_info.st_mode):
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise UmzugError(f"backup file cannot be read: {path}") from exc
        else:
            os.close(fd)
        return 1, root_info.st_size, "file"
    if not stat.S_ISDIR(root_info.st_mode):
        raise UmzugError(f"backup target is a device, FIFO, socket, or unsupported object: {path}")

    objects = 1
    estimated_bytes = 4096
    stack = [path]
    while stack:
        directory = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise UmzugError(f"backup directory cannot be enumerated: {directory}") from exc
        for entry in entries:
            objects += 1
            if objects > MAX_BACKUP_OBJECTS:
                raise UmzugError(f"backup target exceeds the {MAX_BACKUP_OBJECTS}-object preflight bound: {path}")
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise UmzugError(f"backup object cannot be inspected: {entry.path}") from exc
            if stat.S_ISLNK(info.st_mode):
                continue
            if stat.S_ISREG(info.st_mode):
                flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
                try:
                    fd = os.open(entry.path, flags)
                except OSError as exc:
                    raise UmzugError(f"backup file cannot be read: {entry.path}") from exc
                else:
                    os.close(fd)
                estimated_bytes += info.st_size
            elif stat.S_ISDIR(info.st_mode):
                estimated_bytes += 4096
                stack.append(Path(entry.path))
            else:
                raise UmzugError(f"backup tree contains a device, FIFO, socket, or unsupported object: {entry.path}")
    return objects, estimated_bytes, "directory"


def observe_backup_targets(plan: Plan) -> dict[str, Any]:
    paths = sorted({path for action in plan.actions for path in action.backup_paths})
    rows: list[dict[str, Any]] = []
    total_objects = 0
    estimated_bytes = 0
    for raw_path in paths:
        objects, size, object_type = _scan_backup_target(Path(raw_path))
        total_objects += objects
        estimated_bytes += size
        if total_objects > MAX_BACKUP_OBJECTS:
            raise UmzugError(f"all backup targets together exceed the {MAX_BACKUP_OBJECTS}-object preflight bound")
        rows.append(
            {
                "path": raw_path,
                "type": object_type,
                "objects": objects,
                "estimated_bytes": size,
            }
        )
    return {
        "targets": rows,
        "target_count": len(rows),
        "objects": total_objects,
        "estimated_bytes": estimated_bytes,
        "point_in_time_only": True,
    }


def observe_recovery_plan(plan: Plan) -> dict[str, Any]:
    positions = {action.id: index for index, action in enumerate(plan.actions)}
    activation_ids = [
        action_id for action_id in ("offline-guard-activate", "firewall-enable") if action_id in positions
    ]
    recovery_ids = [
        action_id for action_id in ("network-recovery-command", "nixos-local-recovery") if action_id in positions
    ]
    recovery_before_activation = all(
        any(positions[recovery] < positions[activation] for recovery in recovery_ids) for activation in activation_ids
    )
    required = bool(
        activation_ids
        or any(action.destructive or action.risk == "critical" for action in plan.actions)
        or any(action.reboot_reason for action in plan.actions)
    )
    if required and not recovery_ids:
        raise UmzugError("destructive plan has no locally planned recovery command")
    if activation_ids and not recovery_before_activation:
        raise UmzugError("network activation is ordered before local recovery")
    return {
        "required": required,
        "planned_recovery_action_ids": recovery_ids,
        "network_activation_action_ids": activation_ids,
        "recovery_before_network_activation": recovery_before_activation,
        "reboot_action_ids": [action.id for action in plan.actions if action.reboot_reason],
        "installed_or_tested_by_preflight": False,
    }


def observe_recovery_medium(
    path: Path | None,
    facts: SystemFacts,
    *,
    required: bool,
    system_root: Path = Path("/"),
) -> dict[str, Any]:
    if not required:
        return {"required": False, "path": None, "separate_mount": None}
    if path is None:
        raise UmzugError("a mounted separate recovery medium is required")
    if not path.is_absolute() or path == Path("/"):
        raise UmzugError("recovery medium must be an absolute non-root mountpoint")
    try:
        info = path.lstat()
        root_info = system_root.stat()
    except OSError as exc:
        raise UmzugError("recovery medium cannot be inspected") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise UmzugError("recovery medium must be a non-symlink directory mountpoint")
    if not os.path.ismount(path) or info.st_dev == root_info.st_dev:
        raise UmzugError("recovery medium is not a separate mounted filesystem")
    mount = next((item for item in facts.storage.mounts if item.target == str(path)), None)
    if mount is None or mount.filesystem.lower() in _PSEUDO_FILESYSTEMS:
        raise UmzugError("recovery medium is not a detected non-ephemeral filesystem mount")
    if facts.storage.root_source and mount.source == facts.storage.root_source:
        raise UmzugError("recovery medium resolves to the root filesystem source")
    return {
        "required": True,
        "path": str(path),
        "separate_mount": True,
        "source": mount.source,
        "filesystem": mount.filesystem,
        "mount_options": list(mount.options),
        "bootability_automatically_proven": False,
    }


def _observe_tool(name: str) -> dict[str, Any]:
    path = _trusted_executable(name)
    observation = _stable_file_observation(path, executable=True)
    return {
        "name": name,
        "status": "trusted-observation",
        **observation,
        "durable_receipt": False,
    }


def observe_required_tools(plan: Plan) -> dict[str, Any]:
    without_preflights = [action for action in plan.actions if action.operation != "check_executable"]
    derived = required_preflight_executables(without_preflights)
    planned = tuple(str(action.parameters["name"]) for action in plan.actions if action.operation == "check_executable")
    if planned != derived:
        raise UmzugError("plan executable preflight prefix differs from its complete action set")
    observations = [_observe_tool(name) for name in planned]
    return {
        "required_before_first_mutation": list(planned),
        "observations": observations,
        "rechecked_by_productive_apply": True,
    }


def _hardware_observations(facts: SystemFacts, power: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "architecture": facts.architecture,
        "kernel": facts.kernel,
        "firmware": {
            "mode": facts.firmware.mode,
            "secure_boot": facts.firmware.secure_boot,
        },
        "gpus": [
            {
                "name": gpu.sys_name,
                "vendor": gpu.vendor,
                "device_id": gpu.device_id,
                "driver": gpu.driver,
                "boot_vga": gpu.boot_vga,
            }
            for gpu in facts.gpus
        ],
        "network": [
            {
                "name": device.name,
                "kind": device.kind,
                "driver": device.driver,
                "operstate": device.operstate,
                "virtual": device.virtual,
            }
            for device in facts.network_devices
        ],
        "radios": [
            {
                "name": radio.name,
                "kind": radio.kind,
                "soft_blocked": radio.soft_blocked,
                "hard_blocked": radio.hard_blocked,
            }
            for radio in facts.radios
        ],
        "hardware_security": {
            "tpm_devices": list(facts.hardware_security.tpm_devices),
            "tpm_versions": list(facts.hardware_security.tpm_versions),
            "iommu": facts.hardware_security.iommu,
            "kernel_lockdown": facts.hardware_security.kernel_lockdown,
            "cpu_security_features": list(facts.hardware_security.cpu_security_features),
        },
        "root_storage": {
            "source": facts.storage.root_source,
            "filesystem": facts.storage.root_filesystem,
            "encrypted": facts.storage.root_encrypted,
            "encryption_types": list(facts.storage.encryption_types),
        },
        "power": dict(power),
        "detection_warnings": list(facts.warnings),
    }


def _risk_inventory(plan: Plan) -> dict[str, Any]:
    rows = [
        {
            "position": index,
            "id": action.id,
            "phase": action.phase,
            "summary": action.summary,
            "operation": action.operation,
            "risk": action.risk,
            "destructive": action.destructive,
            "requires_confirmation": action.requires_confirmation,
            "reboot_required": action.reboot_reason is not None,
        }
        for index, action in enumerate(plan.actions)
        if action.destructive or action.risk in {"high", "critical"}
    ]
    return {
        "high_or_critical_or_destructive": rows,
        "destructive_count": sum(action.destructive for action in plan.actions),
        "high_count": sum(action.risk == "high" for action in plan.actions),
        "critical_count": sum(action.risk == "critical" for action in plan.actions),
        "reboot_count": sum(action.reboot_reason is not None for action in plan.actions),
    }


def build_hardware_preflight_report(
    plan: Plan,
    facts: SystemFacts,
    *,
    plan_digest: str,
    state_dir: Path,
    recovery_medium: Path | None,
    attestations: Iterable[str] = (),
    proc_root: Path = Path("/proc"),
    sys_root: Path = Path("/sys"),
    system_root: Path = Path("/"),
) -> dict[str, Any]:
    """build one point-in-time report without writing state or changing hardware."""

    plan.validate()
    if plan.profile == "test":
        raise UmzugError("hardware preflight accepts only a productive reviewed plan")
    supplied_attestations = set(attestations)
    unknown = supplied_attestations - ATTESTATION_IDS
    if unknown:
        raise UmzugError("unknown hardware-preflight attestation: " + ", ".join(sorted(unknown)))

    checks: list[dict[str, Any]] = []
    rc_scope_supported = (
        plan.profile == "compatible"
        and facts.distribution.id in {"debian", "ubuntu"}
        and facts.init_system == "systemd"
    )
    checks.append(
        _automatic(
            "hardware-rc-scope",
            "pass" if rc_scope_supported else "block",
            (
                "Dieser RC unterstützt den reversiblen H0-Hardwarelauf auf Debian/Ubuntu mit systemd"
                if rc_scope_supported
                else "Dieser RC gibt nur compatible/H0 auf Debian oder Ubuntu mit systemd für produktive Hardwaretests frei; H1/H2 und andere Zielpfade bleiben blockiert"
            ),
            {
                "profile": plan.profile,
                "distribution": facts.distribution.id,
                "version_id": facts.distribution.version_id,
                "init_system": facts.init_system,
                "accepted_profile": "compatible",
                "accepted_distributions": ["debian", "ubuntu"],
                "accepted_init_system": "systemd",
                "h1_h2_nixos_other_distributions_released": False,
            },
        )
    )
    checks.append(
        _automatic(
            "root-privileges",
            "pass" if os.geteuid() == 0 else "block",
            "Produktiver Hardware-Preflight läuft als root"
            if os.geteuid() == 0
            else "Produktiver Hardware-Preflight erfordert root",
            {"effective_uid": os.geteuid()},
        )
    )

    try:
        runtime = observe_productive_runtime()
    except (OSError, UmzugError) as exc:
        runtime = {"error": str(exc)}
        checks.append(_automatic("productive-runtime", "block", str(exc)))
    else:
        checks.append(
            _automatic(
                "productive-runtime",
                "pass",
                "Fester root-eigener Produktivwrapper und isolierte Laufzeit wurden beobachtet",
                runtime,
            )
        )

    console = observe_local_console()
    checks.append(
        _automatic(
            "local-console",
            "pass" if console["console_proven"] else "block",
            "Lokale Systemkonsole ohne SSH-Kontext wurde nachgewiesen"
            if console["console_proven"]
            else "Lokale Systemkonsole ist nicht beweisbar; SSH und Pseudo-Terminals sind unzulässig",
            console,
        )
    )

    remote = remote_session_evidence()
    preflight_console_proven = bool(
        remote.get("remote_detected") is False
        and remote.get("ancestor_scan_complete") is True
        and remote.get("stdin_is_tty") is True
        and isinstance(remote.get("tty"), str)
        and _CONSOLE_RE.fullmatch(str(remote["tty"])) is not None
    )
    remote = {**remote, "preflight_local_console_proven": preflight_console_proven}
    checks.append(
        _automatic(
            "remote-session",
            "pass" if preflight_console_proven else "block",
            "Vollständige Prozesskette und echte stdin-Konsole wurden nachgewiesen; stdout darf für den JSON-Beweisbericht umgeleitet sein"
            if preflight_console_proven
            else "Positive lokale Konsolenevidenz fehlt; Remote-, /dev/pts- oder unvollständige Sitzungen sind unzulässig",
            remote,
        )
    )

    offline = observe_offline_boundary(facts, proc_root=proc_root, sys_root=sys_root)
    checks.append(
        _automatic(
            "offline-boundary",
            str(offline["status"]),
            str(offline["summary"]),
            offline,
        )
    )

    power = observe_power(sys_root)
    checks.append(_automatic("stable-power", str(power["status"]), str(power["summary"]), power))

    target = compare_plan_target(plan, facts)
    checks.append(
        _automatic(
            "plan-target-binding",
            "pass" if not target["blockers"] else "block",
            "Plan ist an die aktuell beobachtete Zielhardware gebunden"
            if not target["blockers"]
            else "; ".join(target["blockers"]),
            {key: value for key, value in target.items() if key != "blockers"},
        )
    )

    try:
        state = observe_state_path(state_dir)
    except (OSError, UmzugError) as exc:
        state = {"state_dir": str(state_dir), "error": str(exc), "created_or_modified": False}
        checks.append(_automatic("state-path", "block", str(exc), state))
    else:
        checks.append(
            _automatic(
                "state-path",
                "pass",
                "State- und Backup-Pfade sind privat, leer/prospektiv und beschreibbar eingeplant",
                state,
            )
        )

    try:
        backups = observe_backup_targets(plan)
    except (OSError, UmzugError) as exc:
        backups = {"error": str(exc), "targets": [], "estimated_bytes": 0}
        checks.append(_automatic("backup-targets", "block", str(exc), backups))
    else:
        checks.append(
            _automatic(
                "backup-targets",
                "pass",
                "Alle geplanten Backup-Ziele sind lesbar und enthalten keine Spezialobjekte",
                backups,
            )
        )

    required_bytes = max(
        MIN_FREE_BYTES,
        int(backups.get("estimated_bytes", 0)) * 2 + BACKUP_HEADROOM_BYTES,
    )
    available_bytes = state.get("available_bytes")
    storage_ok = isinstance(available_bytes, int) and available_bytes >= required_bytes
    checks.append(
        _automatic(
            "free-storage",
            "pass" if storage_ok else "block",
            "Ausreichender freier Platz für Checkpoints und Backups ist vorhanden"
            if storage_ok
            else "Freier Platz für Checkpoints und Backups ist nicht ausreichend beweisbar",
            {
                "available_bytes": available_bytes,
                "required_bytes": required_bytes,
                "backup_estimate_bytes": backups.get("estimated_bytes", 0),
            },
        )
    )

    try:
        recovery = observe_recovery_plan(plan)
    except (OSError, UmzugError) as exc:
        recovery = {"required": True, "error": str(exc)}
        checks.append(_automatic("recovery-plan", "block", str(exc), recovery))
    else:
        checks.append(
            _automatic(
                "recovery-plan",
                "pass",
                "Lokaler Recovery-Befehl ist vor Netzwerk-Lockdown eingeplant",
                recovery,
            )
        )

    try:
        medium = observe_recovery_medium(
            recovery_medium,
            facts,
            required=bool(recovery.get("required", True)),
            system_root=system_root,
        )
    except (OSError, UmzugError) as exc:
        medium = {"path": str(recovery_medium) if recovery_medium else None, "error": str(exc)}
        checks.append(_automatic("recovery-medium", "block", str(exc), medium))
    else:
        checks.append(
            _automatic(
                "recovery-medium",
                "pass",
                "Separates nichtflüchtiges Recovery-Dateisystem ist eingehängt"
                if medium.get("required")
                else "Für diesen Plan ist kein separates Recovery-Medium erforderlich",
                medium,
            )
        )

    try:
        tools = observe_required_tools(plan)
    except (OSError, UmzugError) as exc:
        tools = {"error": str(exc), "observations": []}
        checks.append(_automatic("required-tools", "block", str(exc), tools))
    else:
        checks.append(
            _automatic(
                "required-tools",
                "pass",
                "Alle vor der ersten Mutation benötigten Werkzeuge sind root-eigen und unveränderbar beobachtet",
                tools,
            )
        )

    checks.append(
        _automatic(
            "plan-digest",
            "pass",
            "Plan stimmt mit dem unabhängig gelieferten SHA-256 überein",
            {"sha256": plan_digest},
        )
    )
    version_match = plan.toolkit_version == __version__
    checks.append(
        _automatic(
            "toolkit-version",
            "pass" if version_match else "block",
            "Plan- und Laufzeitversion stimmen überein"
            if version_match
            else "Plan- und Laufzeitversion unterscheiden sich; Plan mit dieser Laufzeit neu erzeugen und prüfen",
            {
                "plan": plan.toolkit_version,
                "runtime": __version__,
                "productive_apply_has_independent_version_equality_gate": True,
                "preflight_blocks_conservatively": not version_match,
            },
        )
    )

    risks = _risk_inventory(plan)
    required_attestations: set[str] = set()
    required_attestations.update({"full-backup-restore-tested", "network-physically-disconnected"})
    if risks["destructive_count"]:
        required_attestations.add("destructive-actions-reviewed")
    if backups.get("target_count", 0):
        required_attestations.add("backup-and-rollback-reviewed")
    if recovery.get("required", True):
        required_attestations.add("recovery-medium-boot-tested")
    if risks["reboot_count"]:
        required_attestations.add("reboot-path-tested")
    if power.get("status") == "warning":
        required_attestations.add("stable-power-confirmed")
    manual = [
        {
            "id": attestation,
            "status": "attested" if attestation in supplied_attestations else "required",
            "statement": {
                "backup-and-rollback-reviewed": "Backup-Ziele, Vergleich und Rollback wurden lokal überprüft.",
                "destructive-actions-reviewed": "Alle aufgelisteten destruktiven/hohen Risiken wurden einzeln geprüft.",
                "full-backup-restore-tested": "Ein unabhängiges Vollbackup oder Blockabbild auf einem anderen Medium wurde stichprobenweise wiederhergestellt.",
                "network-physically-disconnected": "Für H0/H1 wurden Ethernet-Kabel und andere externe WAN-Verbindungen physisch getrennt; Funk bleibt deaktiviert.",
                "reboot-path-tested": "Lokaler Neustart-, Boot- und Fortsetzungspfad wurde praktisch getestet.",
                "recovery-medium-boot-tested": "Das separate Medium wurde auf genau dieser Hardware gebootet; Boot- und Toolkit-Hashes wurden über einen unabhängigen authentifizierten Kanal geprüft und die Recovery-Anleitung ist offline verfügbar.",
                "stable-power-confirmed": "Stabile externe Stromversorgung wurde physisch bestätigt.",
            }[attestation],
        }
        for attestation in sorted(required_attestations)
    ]

    blockers = [check for check in checks if check["status"] == "block"]
    pending_manual = [row for row in manual if row["status"] == "required"]
    status = "blocked" if blockers else "manual-attestation-required" if pending_manual else "ready"
    return {
        "format": 1,
        "kind": "umzug-hardware-preflight",
        "read_only": True,
        "authorization_to_apply": False,
        "status": status,
        "automated_checks_passed": not blockers,
        "manual_attestations_complete": not pending_manual,
        "plan": {
            "sha256": plan_digest,
            "profile": plan.profile,
            "format_version": plan.format_version,
            "toolkit_version": plan.toolkit_version,
            "action_count": len(plan.actions),
            "canonical_action_set_valid": True,
        },
        "automatic_checks": checks,
        "manual_attestations": manual,
        "risk_summary": risks,
        "hardware_observations": _hardware_observations(facts, power),
        "separate_open_gates": [
            {
                "id": "scanner-pipeline-private-empty-candidate",
                "status": "not-evaluated-by-read-only-hardware-preflight",
                "blocks": "migration promotion and approval, not this hardware observation",
                "reason": (
                    "A real scanner/Bubblewrap/rule-material probe requires a private temporary "
                    "candidate and executable snapshots. That write/execute boundary is kept in "
                    "the separate zero-trust scan workflow."
                ),
            },
            {
                "id": "vendor-artifact-reverification",
                "status": "deferred-to-productive-apply",
                "blocks": "vendor installation if re-verification later fails",
                "reason": "Vendor re-verification snapshots and executes pinned parsers and is intentionally outside this read-only command.",
            },
        ],
        "limitations": [
            "This release candidate authorizes preflight readiness only for compatible/H0 on dedicated Debian/Ubuntu systemd test hardware.",
            "Every observation is point-in-time evidence and is rechecked by productive execution where applicable.",
            "Root ownership and file hashes do not prove a trusted kernel, firmware, dynamic loader, libraries, or malware-free system.",
            "A mounted recovery filesystem does not prove bootability; the explicit manual attestation is mandatory.",
            "Power-supply sysfs is platform-dependent; UPS and firmware-controlled power paths may remain invisible.",
            "No check in this report authorizes destructive changes or silently satisfies an apply confirmation.",
        ],
    }


def human_hardware_preflight(report: Mapping[str, Any]) -> str:
    lines = [
        f"Hardware-Preflight: {terminal_safe(report.get('status', 'unknown'))}",
        f"Plan SHA-256: {terminal_safe(report.get('plan', {}).get('sha256', '-'))}",
        "Automatische Prüfungen:",
    ]
    markers = {"pass": "OK", "warning": "WARNUNG", "block": "BLOCKIERT"}
    for check in report.get("automatic_checks", []):
        status = str(check.get("status", "block"))
        lines.append(
            f"  [{markers.get(status, 'BLOCKIERT')}] "
            f"{terminal_safe(check.get('id', '?'))}: {terminal_safe(check.get('summary', ''))}"
        )
    lines.append("Manuelle Attestierungen:")
    manual = report.get("manual_attestations", [])
    if manual:
        for row in manual:
            marker = "BESTÄTIGT" if row.get("status") == "attested" else "ERFORDERLICH"
            lines.append(f"  [{marker}] {terminal_safe(row.get('id', '?'))}: {terminal_safe(row.get('statement', ''))}")
    else:
        lines.append("  keine")
    risks = report.get("risk_summary", {})
    lines.append(
        "Risiken: "
        f"destruktiv={int(risks.get('destructive_count', 0))}, "
        f"hoch={int(risks.get('high_count', 0))}, "
        f"kritisch={int(risks.get('critical_count', 0))}, "
        f"Neustarts={int(risks.get('reboot_count', 0))}"
    )
    lines.append("Dieser Bericht ist rein lesend, zeitpunktbezogen und keine Apply-Freigabe.")
    return "\n".join(lines)


__all__ = [
    "ATTESTATION_IDS",
    "build_hardware_preflight_report",
    "compare_plan_target",
    "human_hardware_preflight",
    "observe_backup_targets",
    "observe_local_console",
    "observe_offline_boundary",
    "observe_power",
    "observe_productive_runtime",
    "observe_recovery_medium",
    "observe_recovery_plan",
    "observe_required_tools",
    "observe_state_path",
]
