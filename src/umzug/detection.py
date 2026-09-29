"""read-only platform facts from injectable /etc, /proc and /sys trees.

symlinks stay within their injected tree, including absolute os-release links.
optional probing is a fixed lsblk argument vector, enabled only for the live
root. mounted targets and tests must not query or change the real host.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any


_MAX_TEXT_FILE = 1024 * 1024
_OS_RELEASE_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")
_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")
_SAFE_ENV_OVERRIDES = frozenset({"HOME", "TMPDIR", "TZ", "SOURCE_DATE_EPOCH"})


@dataclass(frozen=True)
class CommandResult:
    """bounded result returned by :func:`safe_run`."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None


def safe_run(
    argv: Sequence[str],
    *,
    timeout: float = 5.0,
    cwd: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
    max_output: int = _MAX_TEXT_FILE,
) -> CommandResult:
    """run a command without a shell and with a small, deterministic environment.

    this wrapper is suitable for *read-only* probes.  it rejects NUL bytes,
    closes inherited file descriptors, supplies no stdin, applies a timeout,
    and bounds the returned text.  a missing command or timeout is represented
    as data instead of raising.  callers must still use a fixed executable and
    must not turn untrusted data into options.
    """

    args = tuple(argv)
    if not args or any(not isinstance(arg, str) or "\x00" in arg for arg in args):
        raise ValueError("argv must contain non-empty, NUL-free strings")
    if not args[0]:
        raise ValueError("executable must not be empty")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if max_output < 0:
        raise ValueError("max_output must not be negative")

    command_env = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }
    if env:
        for key, value in env.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("environment keys and values must be strings")
            if "\x00" in key or "\x00" in value or "=" in key:
                raise ValueError("invalid environment entry")
            if key not in _SAFE_ENV_OVERRIDES:
                raise ValueError(f"unsafe environment override: {key}")
            command_env[key] = value

    def decode(value: bytes | None) -> str:
        return (value or b"")[:max_output].decode("utf-8", "replace")

    try:
        completed = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=command_env,
            timeout=timeout,
            check=False,
            shell=False,
            close_fds=True,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            args,
            124,
            decode(exc.stdout),
            decode(exc.stderr),
            timed_out=True,
            error="command timed out",
        )
    except OSError as exc:
        return CommandResult(args, 127, error=f"{type(exc).__name__}: {exc}")
    return CommandResult(
        args,
        completed.returncode,
        decode(completed.stdout),
        decode(completed.stderr),
    )


@dataclass(frozen=True)
class DistributionInfo:
    id: str
    name: str
    version_id: str = ""
    version: str = ""
    codename: str = ""
    id_like: tuple[str, ...] = ()
    pretty_name: str = ""
    source: str = "unknown"


@dataclass(frozen=True)
class FirmwareInfo:
    mode: str  # uefi, bios, unknown
    secure_boot: str  # enabled, disabled, setup, unsupported, unknown
    secure_boot_variable: str | None = None


@dataclass(frozen=True)
class GPUDevice:
    sys_name: str
    vendor_id: str = ""
    device_id: str = ""
    vendor: str = "unknown"
    driver: str | None = None
    recommended_drivers: tuple[str, ...] = ()
    pci_address: str | None = None
    boot_vga: bool = False


@dataclass(frozen=True)
class NetworkDevice:
    name: str
    kind: str
    mac_address: str = ""
    operstate: str = "unknown"
    driver: str | None = None
    wireless: bool = False
    virtual: bool = False


@dataclass(frozen=True)
class RadioDevice:
    name: str
    kind: str
    soft_blocked: bool | None = None
    hard_blocked: bool | None = None


@dataclass(frozen=True)
class HardwareSecurityInfo:
    tpm_devices: tuple[str, ...] = ()
    tpm_versions: tuple[str, ...] = ()
    iommu: bool = False
    kernel_lockdown: str = "unsupported"
    cpu_security_features: tuple[str, ...] = ()
    security_notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class MountInfo:
    source: str
    target: str
    filesystem: str
    options: tuple[str, ...] = ()


@dataclass(frozen=True)
class BlockDevice:
    name: str
    device: str
    kind: str
    parent: str | None = None
    size_bytes: int | None = None
    read_only: bool = False
    removable: bool = False
    mapper_name: str | None = None
    dm_uuid: str | None = None
    encrypted: bool = False
    slaves: tuple[str, ...] = ()
    filesystem: str | None = None
    filesystem_uuid: str | None = None
    partition_uuid: str | None = None
    partition_table: str | None = None
    mountpoints: tuple[str, ...] = ()


@dataclass(frozen=True)
class StorageInfo:
    root_source: str | None = None
    root_filesystem: str | None = None
    root_encrypted: bool | None = None
    encryption_types: tuple[str, ...] = ()
    configured_crypt_mappings: tuple[str, ...] = ()
    mounts: tuple[MountInfo, ...] = ()
    block_devices: tuple[BlockDevice, ...] = ()


@dataclass(frozen=True)
class SystemFacts:
    distribution: DistributionInfo
    package_manager: str
    package_managers: tuple[str, ...]
    init_system: str
    architecture: str
    kernel: str
    firmware: FirmwareInfo
    # hash only: the raw machine-id is local identifying information and must
    # not be copied into reports or migration bundles.
    machine_identity_sha256: str = ""
    gpus: tuple[GPUDevice, ...] = ()
    network_devices: tuple[NetworkDevice, ...] = ()
    radios: tuple[RadioDevice, ...] = ()
    hardware_security: HardwareSecurityInfo = field(default_factory=HardwareSecurityInfo)
    storage: StorageInfo = field(default_factory=StorageInfo)
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """return a JSON-serialisable, stable representation."""

        return dataclasses.asdict(self)


def _normalise_architecture(machine: str) -> str:
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "i386": "x86",
        "i486": "x86",
        "i586": "x86",
        "i686": "x86",
        "arm64": "aarch64",
        "armv8l": "aarch64",
    }
    lowered = machine.strip().lower()
    return aliases.get(lowered, lowered or "unknown")


def _unescape_proc(value: str) -> str:
    return _OCTAL_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _bool_file(value: str | None) -> bool | None:
    if value is None:
        return None
    value = value.strip().lower()
    if value in {"1", "y", "yes", "true", "enabled"}:
        return True
    if value in {"0", "n", "no", "false", "disabled"}:
        return False
    return None


def _int_file(value: str | None, default: int | None = None) -> int | None:
    try:
        return int((value or "").strip(), 0)
    except ValueError:
        return default


def _confined_path(base: Path, relative: str | PurePosixPath, *, follow_final: bool = True) -> Path:
    """resolve symlinks as if *base* were ``/``, never outside *base*.

    linux virtual filesystems use many relative and absolute symlinks.  calling
    ``Path.resolve`` on an injected tree would incorrectly follow an absolute
    link into the host.  this small resolver maps such links back under the
    injected root and rejects lexical traversal above it.
    """

    rel = PurePosixPath(str(relative))
    pending = [part for part in rel.parts if part not in {"", "/", "."}]
    resolved: list[str] = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part == "..":
            if not resolved:
                raise ValueError(f"path escapes injected tree: {relative}")
            resolved.pop()
            continue
        candidate = base.joinpath(*resolved, part)
        is_final = not pending
        if os.path.islink(candidate) and (follow_final or not is_final):
            links += 1
            if links > 40:
                raise OSError(f"too many symlinks below {base}")
            target = os.readlink(candidate)
            target_path = PurePosixPath(target)
            target_parts = [item for item in target_path.parts if item not in {"", "/", "."}]
            if target_path.is_absolute():
                resolved = []
            pending = target_parts + pending
            continue
        resolved.append(part)
    return base.joinpath(*resolved)


class SystemDetector:
    """detect a linux target using only local, read-only information."""

    def __init__(
        self,
        *,
        root: str | os.PathLike[str] = "/",
        proc: str | os.PathLike[str] = "/proc",
        sys: str | os.PathLike[str] = "/sys",
        machine: str | None = None,
        allow_commands: bool = True,
        runner: Callable[..., CommandResult] = safe_run,
    ) -> None:
        self.root = Path(root).absolute()
        self.proc = Path(proc).absolute()
        self.sys = Path(sys).absolute()
        self.machine = machine
        self.runner = runner
        # Never supplement an injected snapshot with facts from the live host.
        self.allow_commands = bool(
            allow_commands and self.root == Path("/") and self.proc == Path("/proc") and self.sys == Path("/sys")
        )

    def _path(self, tree: Path, relative: str, *, follow_final: bool = True) -> Path:
        return _confined_path(tree, relative, follow_final=follow_final)

    def _read(self, tree: Path, relative: str, *, binary: bool = False) -> str | bytes | None:
        try:
            path = self._path(tree, relative)
            with path.open("rb") as handle:
                data = handle.read(_MAX_TEXT_FILE + 1)
        except (OSError, ValueError):
            return None
        if len(data) > _MAX_TEXT_FILE:
            return None
        return data if binary else data.decode("utf-8", "replace").strip()

    def _read_root(self, relative: str) -> str | None:
        value = self._read(self.root, relative)
        return value if isinstance(value, str) else None

    def _read_proc(self, relative: str) -> str | None:
        value = self._read(self.proc, relative)
        return value if isinstance(value, str) else None

    def _read_sys(self, relative: str) -> str | None:
        value = self._read(self.sys, relative)
        return value if isinstance(value, str) else None

    def _read_sys_binary(self, relative: str) -> bytes | None:
        value = self._read(self.sys, relative, binary=True)
        return value if isinstance(value, bytes) else None

    def _exists(self, tree: Path, relative: str) -> bool:
        try:
            return self._path(tree, relative).exists()
        except (OSError, ValueError):
            return False

    def _names(self, tree: Path, relative: str) -> tuple[str, ...]:
        try:
            directory = self._path(tree, relative)
            with os.scandir(directory) as entries:
                return tuple(sorted(entry.name for entry in entries if "/" not in entry.name))
        except (OSError, ValueError):
            return ()

    def _link_basename(self, tree: Path, relative: str) -> str | None:
        try:
            link = self._path(tree, relative, follow_final=False)
            if not os.path.islink(link):
                return None
            return PurePosixPath(os.readlink(link)).name or None
        except (OSError, ValueError):
            return None

    def detect(self) -> SystemFacts:
        warnings: list[str] = []
        distro = self.detect_distribution()
        managers = self.detect_package_managers(distro)
        firmware = self.detect_firmware()
        storage = self.detect_storage()
        if distro.id == "unknown":
            warnings.append("Distribution konnte nicht sicher erkannt werden.")
        if not managers:
            warnings.append("Kein standardisierter Paketmanager erkannt.")
        if firmware.secure_boot == "unknown":
            warnings.append("Secure-Boot-Status ist lokal nicht lesbar.")
        if storage.root_encrypted is None:
            warnings.append("Verschlüsselungsstatus des Root-Dateisystems ist unklar.")
        return SystemFacts(
            distribution=distro,
            package_manager=managers[0] if managers else "none",
            package_managers=managers,
            init_system=self.detect_init_system(),
            architecture=_normalise_architecture(self.machine or platform.machine()),
            kernel=self.detect_kernel(),
            firmware=firmware,
            machine_identity_sha256=self.detect_machine_identity_hash(),
            gpus=self.detect_gpus(),
            network_devices=self.detect_network_devices(),
            radios=self.detect_radios(),
            hardware_security=self.detect_hardware_security(),
            storage=storage,
            warnings=tuple(warnings),
        )

    def detect_machine_identity_hash(self) -> str:
        """return a privacy-preserving hash of the target's stable machine-id.

        only the conventional local files are considered, and malformed ids
        are ignored.  the un-hashed identifier never leaves this method.
        """

        for relative in ("etc/machine-id", "var/lib/dbus/machine-id"):
            value = (self._read_root(relative) or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{32}", value):
                return hashlib.sha256(value.encode("ascii")).hexdigest()
        return ""

    def detect_distribution(self) -> DistributionInfo:
        candidates = ("etc/os-release", "usr/lib/os-release")
        for candidate in candidates:
            text = self._read_root(candidate)
            if text:
                values = self._parse_os_release(text)
                distro_id = values.get("ID", "unknown").strip().lower() or "unknown"
                return DistributionInfo(
                    id=distro_id,
                    name=values.get("NAME", distro_id),
                    version_id=values.get("VERSION_ID", ""),
                    version=values.get("VERSION", ""),
                    codename=values.get("VERSION_CODENAME", values.get("UBUNTU_CODENAME", "")),
                    id_like=tuple(values.get("ID_LIKE", "").lower().split()),
                    pretty_name=values.get("PRETTY_NAME", values.get("NAME", distro_id)),
                    source="/" + candidate,
                )

        fallbacks = (
            ("etc/nixos-version", "nixos", "NixOS"),
            ("etc/gentoo-release", "gentoo", "Gentoo Linux"),
            ("etc/arch-release", "arch", "Arch Linux"),
            ("etc/debian_version", "debian", "Debian GNU/Linux"),
            ("etc/lfs-release", "lfs", "Linux From Scratch"),
        )
        for path, distro_id, name in fallbacks:
            version = self._read_root(path)
            if version is not None:
                # arch-release and gentoo-release may contain a display string,
                # while the other marker files normally contain the version.
                version_id = version if distro_id in {"nixos", "debian", "lfs"} else ""
                return DistributionInfo(
                    id=distro_id,
                    name=name,
                    version_id=version_id,
                    version=version,
                    pretty_name=version or name,
                    source="/" + path,
                )
        return DistributionInfo(id="unknown", name="Unknown Linux")

    @staticmethod
    def _parse_os_release(text: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            if not _OS_RELEASE_KEY.fullmatch(key):
                continue
            try:
                tokens = shlex.split(raw_value, comments=True, posix=True)
            except ValueError:
                continue
            # valid os-release values form one shell word.  joining also
            # handles conservative, unquoted vendor values without executing
            # expansions or accepting assignments.
            result[key] = " ".join(tokens)
        return result

    def detect_package_managers(self, distribution: DistributionInfo | None = None) -> tuple[str, ...]:
        distro = distribution or self.detect_distribution()
        probes: tuple[tuple[str, tuple[str, ...]], ...] = (
            ("apt", ("usr/bin/apt-get", "usr/bin/dpkg-query")),
            ("pacman", ("usr/bin/pacman",)),
            ("nix", ("nix/var/nix/profiles/default/bin/nix", "usr/bin/nix")),
            ("portage", ("usr/bin/emerge",)),
            ("dnf", ("usr/bin/dnf",)),
            ("zypper", ("usr/bin/zypper",)),
            ("apk", ("sbin/apk", "usr/sbin/apk")),
            ("xbps", ("usr/bin/xbps-install",)),
            ("slackpkg", ("usr/sbin/slackpkg",)),
        )
        found = [manager for manager, paths in probes if any(self._exists(self.root, path) for path in paths)]
        family_defaults = {
            "debian": "apt",
            "ubuntu": "apt",
            "linuxmint": "apt",
            "arch": "pacman",
            "manjaro": "pacman",
            "endeavouros": "pacman",
            "nixos": "nix",
            "gentoo": "portage",
            "fedora": "dnf",
            "rhel": "dnf",
            "alpine": "apk",
            "opensuse": "zypper",
            "suse": "zypper",
            "void": "xbps",
        }
        preferred = family_defaults.get(distro.id)
        if preferred is None:
            for family in distro.id_like:
                if family in family_defaults:
                    preferred = family_defaults[family]
                    break
        if preferred and preferred not in found:
            found.insert(0, preferred)
        elif preferred in found:
            found.remove(preferred)
            found.insert(0, preferred)
        return tuple(found)

    def detect_init_system(self) -> str:
        comm = (self._read_proc("1/comm") or "").strip().lower()
        aliases = {
            "systemd": "systemd",
            "init": "sysvinit",
            "openrc-init": "openrc",
            "runit": "runit",
            "s6-svscan": "s6",
            "dinit": "dinit",
        }
        if comm in aliases:
            # an executable named init is ambiguous, so inspect the target too.
            if comm != "init":
                return aliases[comm]
        if self._exists(self.root, "run/systemd/system"):
            return "systemd"
        init_target = self._link_basename(self.root, "sbin/init")
        if init_target:
            lowered = init_target.lower()
            for token, result in (
                ("systemd", "systemd"),
                ("openrc", "openrc"),
                ("runit", "runit"),
                ("busybox", "busybox"),
                ("sysv", "sysvinit"),
            ):
                if token in lowered:
                    return result
        if self._exists(self.root, "sbin/openrc"):
            return "openrc"
        if self._exists(self.root, "etc/inittab"):
            return "sysvinit"
        return aliases.get(comm, comm or "unknown")

    def detect_kernel(self) -> str:
        release = self._read_proc("sys/kernel/osrelease")
        if release:
            return release.splitlines()[0].strip()
        if self.proc == Path("/proc"):
            return platform.release() or "unknown"
        return "unknown"

    def detect_firmware(self) -> FirmwareInfo:
        if not self._exists(self.sys, "firmware/efi"):
            # On a live Linux system a populated /sys without EFI means legacy
            # boot.  For an absent injected /sys, keep the result unknown.
            mode = "bios" if self.sys.exists() else "unknown"
            return FirmwareInfo(mode=mode, secure_boot="unsupported")

        variables = self._names(self.sys, "firmware/efi/efivars")
        secure_vars = sorted(name for name in variables if name.startswith("SecureBoot-"))
        setup_vars = sorted(name for name in variables if name.startswith("SetupMode-"))
        setup_mode: int | None = None
        if setup_vars:
            raw_setup = self._read_sys_binary(f"firmware/efi/efivars/{setup_vars[0]}")
            if raw_setup and len(raw_setup) >= 5:
                setup_mode = raw_setup[4]
        if not secure_vars:
            return FirmwareInfo(mode="uefi", secure_boot="unknown")
        raw = self._read_sys_binary(f"firmware/efi/efivars/{secure_vars[0]}")
        if not raw or len(raw) < 5:
            return FirmwareInfo(mode="uefi", secure_boot="unknown", secure_boot_variable=secure_vars[0])
        if setup_mode == 1:
            state = "setup"
        else:
            state = "enabled" if raw[4] == 1 else "disabled"
        return FirmwareInfo(mode="uefi", secure_boot=state, secure_boot_variable=secure_vars[0])

    def detect_gpus(self) -> tuple[GPUDevice, ...]:
        devices: list[GPUDevice] = []
        names = self._names(self.sys, "class/drm")
        cards = [name for name in names if re.fullmatch(r"card\d+", name)]
        # some minimal kernels expose PCI display controllers but no DRM card.
        if not cards:
            for pci_name in self._names(self.sys, "bus/pci/devices"):
                class_code = (self._read_sys(f"bus/pci/devices/{pci_name}/class") or "").lower()
                if class_code.startswith("0x03"):
                    cards.append(f"pci:{pci_name}")

        vendor_names = {
            "0x1002": "AMD",
            "0x10de": "NVIDIA",
            "0x8086": "Intel",
            "0x1a03": "ASPEED",
            "0x1234": "QEMU",
            "0x1af4": "Virtio",
        }
        driver_candidates = {
            "0x1002": ("amdgpu",),
            # the proprietary NVIDIA module and nouveau have materially
            # different trust, signing and compatibility properties.  the
            # planner must choose explicitly after inspecting the exact GPU.
            "0x10de": ("nvidia", "nouveau"),
            # new intel devices can use xe; i915 remains correct for most
            # supported generations, hence both are candidates rather than an
            # unsafe automatic choice based only on the vendor id.
            "0x8086": ("i915", "xe"),
            "0x1a03": ("ast",),
            "0x1234": ("bochs_drm",),
            "0x1af4": ("virtio_gpu",),
        }
        seen: set[str] = set()
        for card in cards:
            if card.startswith("pci:"):
                pci_address = card[4:]
                prefix = f"bus/pci/devices/{pci_address}"
                sys_name = pci_address
            else:
                prefix = f"class/drm/{card}/device"
                pci_address = self._link_basename(self.sys, prefix)
                if not (pci_address and re.fullmatch(r"[0-9a-fA-F:.]+", pci_address)):
                    pci_address = None
                sys_name = card
            vendor_id = (self._read_sys(f"{prefix}/vendor") or "").lower()
            device_id = (self._read_sys(f"{prefix}/device") or "").lower()
            identity = pci_address or f"{vendor_id}:{device_id}:{sys_name}"
            if identity in seen:
                continue
            seen.add(identity)
            devices.append(
                GPUDevice(
                    sys_name=sys_name,
                    vendor_id=vendor_id,
                    device_id=device_id,
                    vendor=vendor_names.get(vendor_id, "unknown"),
                    driver=self._link_basename(self.sys, f"{prefix}/driver"),
                    recommended_drivers=driver_candidates.get(vendor_id, ()),
                    pci_address=pci_address,
                    boot_vga=_bool_file(self._read_sys(f"{prefix}/boot_vga")) is True,
                )
            )
        return tuple(devices)

    def detect_network_devices(self) -> tuple[NetworkDevice, ...]:
        result: list[NetworkDevice] = []
        cellular_drivers = {"cdc_mbim", "qmi_wwan", "cdc_ncm", "mhi_net", "wwan"}
        for name in self._names(self.sys, "class/net"):
            prefix = f"class/net/{name}"
            driver = self._link_basename(self.sys, f"{prefix}/device/driver")
            wireless = self._exists(self.sys, f"{prefix}/wireless") or self._exists(self.sys, f"{prefix}/phy80211")
            arp_type = _int_file(self._read_sys(f"{prefix}/type"))
            if name == "lo" or arp_type == 772:
                kind = "loopback"
            elif wireless:
                kind = "wifi"
            elif name.startswith(("wg", "tun", "tap")):
                kind = "tunnel"
            elif name.startswith("wwan") or driver in cellular_drivers:
                kind = "cellular"
            elif arp_type == 1:
                kind = "ethernet"
            else:
                kind = "other"
            result.append(
                NetworkDevice(
                    name=name,
                    kind=kind,
                    mac_address=self._read_sys(f"{prefix}/address") or "",
                    operstate=self._read_sys(f"{prefix}/operstate") or "unknown",
                    driver=driver,
                    wireless=wireless,
                    virtual=not self._exists(self.sys, f"{prefix}/device"),
                )
            )
        return tuple(result)

    def detect_radios(self) -> tuple[RadioDevice, ...]:
        radios: list[RadioDevice] = []
        seen: set[tuple[str, str]] = set()
        for rfkill in self._names(self.sys, "class/rfkill"):
            kind = (self._read_sys(f"class/rfkill/{rfkill}/type") or "unknown").lower()
            name = self._read_sys(f"class/rfkill/{rfkill}/name") or rfkill
            soft = _bool_file(self._read_sys(f"class/rfkill/{rfkill}/soft"))
            hard = _bool_file(self._read_sys(f"class/rfkill/{rfkill}/hard"))
            # older kernels expose only state (1 means unblocked).
            state = _bool_file(self._read_sys(f"class/rfkill/{rfkill}/state"))
            if soft is None and state is not None:
                soft = not state
            radios.append(RadioDevice(name=name, kind=kind, soft_blocked=soft, hard_blocked=hard))
            seen.add((name, kind))

        for interface in self.detect_network_devices():
            if interface.kind in {"wifi", "cellular"}:
                kind = "wlan" if interface.kind == "wifi" else "wwan"
                key = (interface.name, kind)
                if key not in seen:
                    radios.append(RadioDevice(name=interface.name, kind=kind))
                    seen.add(key)
        for hci in self._names(self.sys, "class/bluetooth"):
            key = (hci, "bluetooth")
            if key not in seen:
                radios.append(RadioDevice(name=hci, kind="bluetooth"))
                seen.add(key)
        return tuple(radios)

    def detect_hardware_security(self) -> HardwareSecurityInfo:
        tpm_devices = tuple(name for name in self._names(self.sys, "class/tpm") if re.fullmatch(r"tpm\d+", name))
        versions: list[str] = []
        for name in tpm_devices:
            major = self._read_sys(f"class/tpm/{name}/tpm_version_major")
            if major in {"1", "2"}:
                versions.append(major + ".0")
                continue
            caps = (self._read_sys(f"class/tpm/{name}/caps") or "").lower()
            if "tcg version: 2" in caps:
                versions.append("2.0")
            elif caps:
                versions.append("1.2")
            else:
                versions.append("unknown")

        iommu = bool(self._names(self.sys, "kernel/iommu_groups"))
        lockdown_raw = self._read_sys("kernel/security/lockdown")
        if lockdown_raw is None:
            lockdown = "unsupported"
        else:
            active = re.search(r"\[([^]]+)]", lockdown_raw)
            lockdown = active.group(1) if active else lockdown_raw.strip() or "unknown"

        cpuinfo = (self._read_proc("cpuinfo") or "").lower()
        flags: set[str] = set()
        for line in cpuinfo.splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() in {"flags", "features"}:
                flags.update(value.split())
        interesting = (
            "nx",
            "smep",
            "smap",
            "umip",
            "ibrs",
            "ibpb",
            "stibp",
            "ssbd",
            "md_clear",
            "arch_capabilities",
            "sev",
            "sev_es",
            "sme",
            "sgx",
            "pauth",
            "bti",
        )
        present = tuple(feature for feature in interesting if feature in flags)
        notes: list[str] = []
        if not tpm_devices:
            notes.append("Kein lokal sichtbares TPM erkannt.")
        if not iommu:
            notes.append("Keine aktiven IOMMU-Gruppen erkannt; Firmware-Einstellung prüfen.")
        return HardwareSecurityInfo(
            tpm_devices=tpm_devices,
            tpm_versions=tuple(versions),
            iommu=iommu,
            kernel_lockdown=lockdown,
            cpu_security_features=present,
            security_notes=tuple(notes),
        )

    def _parse_mounts(self) -> tuple[MountInfo, ...]:
        text = self._read_proc("self/mounts") or self._read_proc("mounts") or ""
        mounts: list[MountInfo] = []
        for line in text.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            mounts.append(
                MountInfo(
                    source=_unescape_proc(fields[0]),
                    target=_unescape_proc(fields[1]),
                    filesystem=fields[2],
                    options=tuple(option for option in fields[3].split(",") if option),
                )
            )
        return tuple(mounts)

    @staticmethod
    def _infer_partition_parent(name: str, all_names: set[str]) -> str | None:
        candidates: list[str] = []
        if re.search(r"p\d+$", name):
            candidates.append(re.sub(r"p\d+$", "", name))
        candidates.append(re.sub(r"\d+$", "", name))
        for candidate in candidates:
            if candidate and candidate != name and candidate in all_names:
                return candidate
        return None

    def _sys_block_devices(self) -> dict[str, BlockDevice]:
        names = set(self._names(self.sys, "class/block"))
        result: dict[str, BlockDevice] = {}
        for name in sorted(names):
            prefix = f"class/block/{name}"
            is_partition = self._exists(self.sys, f"{prefix}/partition")
            dm_uuid = self._read_sys(f"{prefix}/dm/uuid")
            mapper_name = self._read_sys(f"{prefix}/dm/name")
            if dm_uuid and dm_uuid.upper().startswith("CRYPT-"):
                kind = "crypt"
            elif dm_uuid and dm_uuid.upper().startswith("LVM-"):
                kind = "lvm"
            elif dm_uuid:
                kind = "device-mapper"
            elif is_partition:
                kind = "partition"
            elif self._exists(self.sys, f"{prefix}/md"):
                kind = "raid"
            elif name.startswith("loop"):
                kind = "loop"
            elif name.startswith("zram"):
                kind = "zram"
            else:
                kind = "disk"
            sectors = _int_file(self._read_sys(f"{prefix}/size"))
            slaves = self._names(self.sys, f"{prefix}/slaves")
            result[name] = BlockDevice(
                name=name,
                device=f"/dev/{name}",
                kind=kind,
                parent=self._infer_partition_parent(name, names) if is_partition else None,
                size_bytes=sectors * 512 if sectors is not None else None,
                read_only=_bool_file(self._read_sys(f"{prefix}/ro")) is True,
                removable=_bool_file(self._read_sys(f"{prefix}/removable")) is True,
                mapper_name=mapper_name,
                dm_uuid=dm_uuid,
                encrypted=kind == "crypt",
                slaves=slaves,
            )
        return result

    def _lsblk_facts(self) -> dict[str, dict[str, Any]]:
        if not self.allow_commands:
            return {}
        argv = (
            "lsblk",
            "--json",
            "--bytes",
            "--output",
            "NAME,KNAME,TYPE,SIZE,FSTYPE,UUID,PARTUUID,PTTYPE,PKNAME,RO,RM,MOUNTPOINTS",
        )
        try:
            result = self.runner(argv, timeout=5.0, max_output=4 * _MAX_TEXT_FILE)
        except (OSError, TypeError, ValueError):
            return {}
        if not result.ok:
            return {}
        try:
            document = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError):
            return {}
        flattened: dict[str, dict[str, Any]] = {}

        def visit(item: object) -> None:
            if not isinstance(item, dict):
                return
            key = item.get("kname") or item.get("name")
            if isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_.!+-]+", key):
                flattened[key] = item
            children = item.get("children", [])
            if isinstance(children, list):
                for child in children:
                    visit(child)

        for item in document.get("blockdevices", []) if isinstance(document, dict) else []:
            visit(item)
        return flattened

    def _merge_lsblk(self, devices: dict[str, BlockDevice], facts: dict[str, dict[str, Any]]) -> dict[str, BlockDevice]:
        for name, item in facts.items():
            existing = devices.get(name)
            raw_mounts = item.get("mountpoints")
            if isinstance(raw_mounts, list):
                mountpoints = tuple(str(value) for value in raw_mounts if value)
            elif isinstance(raw_mounts, str) and raw_mounts:
                mountpoints = (raw_mounts,)
            else:
                mountpoints = ()
            if existing is None:
                raw_size = item.get("size")
                size = raw_size if isinstance(raw_size, int) else _int_file(str(raw_size or ""))
                lsblk_kind = str(item.get("type") or "unknown")
                existing = BlockDevice(
                    name=name,
                    device=f"/dev/{name}",
                    kind={"part": "partition", "crypt": "crypt"}.get(lsblk_kind, lsblk_kind),
                    parent=str(item.get("pkname")) if item.get("pkname") else None,
                    size_bytes=size,
                    encrypted=lsblk_kind == "crypt",
                )
            devices[name] = dataclasses.replace(
                existing,
                filesystem=str(item["fstype"]) if item.get("fstype") else existing.filesystem,
                filesystem_uuid=str(item["uuid"]) if item.get("uuid") else existing.filesystem_uuid,
                partition_uuid=(str(item["partuuid"]) if item.get("partuuid") else existing.partition_uuid),
                partition_table=(str(item["pttype"]) if item.get("pttype") else existing.partition_table),
                mountpoints=mountpoints or existing.mountpoints,
                read_only=bool(item.get("ro", existing.read_only)),
                removable=bool(item.get("rm", existing.removable)),
            )
        return devices

    @staticmethod
    def _source_block_name(source: str, devices: Mapping[str, BlockDevice]) -> str | None:
        if source.startswith("/dev/mapper/"):
            mapper = source.rsplit("/", 1)[-1]
            for name, device in devices.items():
                if device.mapper_name == mapper:
                    return name
        if source.startswith("/dev/"):
            name = source.rsplit("/", 1)[-1]
            if name in devices:
                return name
        return None

    @staticmethod
    def _has_encrypted_ancestor(name: str, devices: Mapping[str, BlockDevice]) -> bool:
        pending = [name]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            device = devices.get(current)
            if not device:
                continue
            if device.encrypted:
                return True
            if device.parent:
                pending.append(device.parent)
            pending.extend(device.slaves)
        return False

    def detect_storage(self) -> StorageInfo:
        mounts = self._parse_mounts()
        devices = self._sys_block_devices()
        devices = self._merge_lsblk(devices, self._lsblk_facts())
        root_mount = next((mount for mount in mounts if mount.target == "/"), None)
        root_source = root_mount.source if root_mount else None
        root_name = self._source_block_name(root_source or "", devices)
        if root_name:
            root_encrypted: bool | None = self._has_encrypted_ancestor(root_name, devices)
        elif root_source and root_source in {"overlay", "rootfs"}:
            root_encrypted = None
        elif root_source and root_source.startswith(("UUID=", "PARTUUID=")):
            # resolve UUID-labelled sources when lsblk supplied identifiers.
            matches = [
                name
                for name, device in devices.items()
                if root_source
                in {
                    f"UUID={device.filesystem_uuid}",
                    f"PARTUUID={device.partition_uuid}",
                }
            ]
            root_encrypted = self._has_encrypted_ancestor(matches[0], devices) if len(matches) == 1 else None
        else:
            root_encrypted = None

        crypt_mappings: list[str] = []
        crypttab = self._read_root("etc/crypttab") or ""
        for line in crypttab.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                fields = shlex.split(stripped, comments=True, posix=True)
            except ValueError:
                continue
            if fields and re.fullmatch(r"[A-Za-z0-9_.+-]+", fields[0]):
                crypt_mappings.append(fields[0])
        for device in devices.values():
            if device.encrypted and device.mapper_name:
                crypt_mappings.append(device.mapper_name)

        encryption_types: set[str] = set()
        for device in devices.values():
            if device.encrypted:
                if device.dm_uuid and device.dm_uuid.upper().startswith("CRYPT-LUKS"):
                    encryption_types.add("LUKS")
                else:
                    encryption_types.add("dm-crypt")
        if crypt_mappings and not encryption_types:
            encryption_types.add("configured-dm-crypt")
        return StorageInfo(
            root_source=root_source,
            root_filesystem=root_mount.filesystem if root_mount else None,
            root_encrypted=root_encrypted,
            encryption_types=tuple(sorted(encryption_types)),
            configured_crypt_mappings=tuple(sorted(set(crypt_mappings))),
            mounts=mounts,
            block_devices=tuple(devices[name] for name in sorted(devices)),
        )


def detect_system(
    *,
    root: str | os.PathLike[str] = "/",
    proc: str | os.PathLike[str] = "/proc",
    sys: str | os.PathLike[str] = "/sys",
    machine: str | None = None,
    allow_commands: bool = True,
) -> SystemFacts:
    """convenience entry point for one-shot detection."""

    return SystemDetector(
        root=root,
        proc=proc,
        sys=sys,
        machine=machine,
        allow_commands=allow_commands,
    ).detect()


__all__ = [
    "BlockDevice",
    "CommandResult",
    "DistributionInfo",
    "FirmwareInfo",
    "GPUDevice",
    "HardwareSecurityInfo",
    "MountInfo",
    "NetworkDevice",
    "RadioDevice",
    "StorageInfo",
    "SystemDetector",
    "SystemFacts",
    "detect_system",
    "safe_run",
]
