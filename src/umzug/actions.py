from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any

from .util import UmzugError, canonical_json


ALLOWED_OPERATIONS = {
    "check_executable",
    "write_file",
    "ensure_group",
    "disable_service",
    "enable_service",
    "run_command",
    "checkpoint",
}
MAX_TEXT = 16_384
MAX_CONTENT_BYTES = 4 * 1024 * 1024
MAX_PARAMETERS_BYTES = 8 * 1024 * 1024
PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:@/-]{0,127}$")
PACKAGE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+.:~_-]{0,127}$")
PACKAGE_ARCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
GROUP_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
MODULE_RE = re.compile(r"^[A-Za-z0-9_]{1,128}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXECUTABLE_SEARCH_PATH = "/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin"
PREFLIGHT_EXECUTABLES = frozenset(
    {
        "apt-get",
        "curl",
        "dnf",
        "dpkg",
        "dpkg-query",
        "dracut",
        "groupadd",
        "ip",
        "mkinitcpio",
        "nft",
        "nixos-rebuild",
        "rc-service",
        "rc-update",
        "rfkill",
        "resolvectl",
        "rpm",
        "ss",
        "sysctl",
        "systemctl",
        "unshare",
        "update-initramfs",
        "wg",
    }
)


# every privileged file destination is owned by one reviewed action type.  the
# content is additionally checked in Plan.validate(); a path allowlist alone
# would still permit service-unit, shell, sudoers, or nix code injection.
WRITE_FILE_SCHEMA: dict[str, tuple[str, int, str]] = {
    "nixos-local-recovery": ("/usr/local/sbin/umzug-nixos-recovery", 0o700, "medium"),
    "nixos-hardening-module": ("/etc/nixos/umzug-hardening.nix", 0o600, "critical"),
    "hardening-sysctl": ("/etc/sysctl.d/90-umzug-hardening.conf", 0o644, "high"),
    "offline-guard-rules": ("/etc/umzug/offline-guard.nft", 0o600, "critical"),
    "offline-guard-unit": ("/etc/systemd/system/umzug-offline-guard.service", 0o644, "critical"),
    "hardening-module-policy": ("/etc/modprobe.d/90-umzug-deny.conf", 0o644, "critical"),
    "radio-systemd-unit": ("/etc/systemd/system/umzug-radio-off.service", 0o644, "high"),
    "radio-openrc-start": ("/etc/local.d/umzug-radio-off.start", 0o700, "high"),
    "network-recovery-command": ("/usr/local/sbin/umzug-network-recovery", 0o700, "medium"),
    "firewall-rules": ("/etc/umzug/firewall.nft", 0o600, "critical"),
    "firewall-unit": ("/etc/systemd/system/umzug-firewall.service", 0o644, "critical"),
    "firewall-openrc-start": ("/etc/local.d/umzug-firewall.start", 0o700, "critical"),
    "sudo-policy": ("/etc/sudoers.d/90-umzug-hardening", 0o440, "high"),
    "journald-policy": ("/etc/systemd/journald.conf.d/90-umzug-hardening.conf", 0o644, "medium"),
    "mullvad-management-socket": (
        "/etc/systemd/system/mullvad-daemon.service.d/90-umzug-security.conf",
        0o644,
        "high",
    ),
}

RUN_COMMAND_SCHEMA: dict[str, tuple[tuple[tuple[str, ...], ...], str]] = {
    "hardening-sysctl-apply": ((("sysctl", "--system"),), "high"),
    "offline-guard-syntax": (
        (("nft", "--check", "--file", "/etc/umzug/offline-guard.nft"),),
        "low",
    ),
    "offline-guard-activate": (
        (
            ("systemctl", "restart", "umzug-offline-guard.service"),
            ("nft", "--file", "/etc/umzug/offline-guard.nft"),
        ),
        "critical",
    ),
    "hardening-initramfs-rebuild": (
        (
            ("update-initramfs", "-u", "-k", "all"),
            ("mkinitcpio", "-P"),
            ("dracut", "--regenerate-all", "--force"),
        ),
        "critical",
    ),
    "radio-block-now": ((("rfkill", "block", "all"),), "high"),
    "firewall-syntax": (
        (("nft", "--check", "--file", "/etc/umzug/firewall.nft"),),
        "low",
    ),
    "firewall-openrc-persist": (
        (("rc-update", "add", "local", "default"),),
        "high",
    ),
    "firewall-enable": (
        (
            ("systemctl", "restart", "umzug-firewall.service"),
            ("nft", "--file", "/etc/umzug/firewall.nft"),
        ),
        "critical",
    ),
}

SYSTEMD_DISABLED = {
    "ssh.service",
    "sshd.service",
    "ssh.socket",
    "sshd.socket",
    "telnet.socket",
    "rsh.socket",
    "bluetooth.service",
    "ModemManager.service",
    "wpa_supplicant.service",
    "iwd.service",
}
OPENRC_DISABLED = {
    "sshd",
    "telnetd",
    "rshd",
    "bluetooth",
    "modemmanager",
    "wpa_supplicant",
    "iwd",
}
ENABLED_SERVICES = {
    "offline-guard-persist": ("umzug-offline-guard.service", "critical"),
    "radio-systemd-enable": ("umzug-radio-off.service", "high"),
    "firewall-persist": ("umzug-firewall.service", "critical"),
}


def _exact_keys(value: dict[str, Any], required: set[str], optional: set[str] = set()) -> None:
    if set(value) - required - optional or not required.issubset(value):
        raise UmzugError(
            "action field schema mismatch: required="
            + ",".join(sorted(required))
            + "; optional="
            + ",".join(sorted(optional))
        )


def _safe_absolute_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise UmzugError("action path must be a bounded NUL-free absolute string")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise UmzugError(f"action path is not canonical and absolute: {value!r}")
    return value


def _require_metadata(action: "Action", *, risk: str, confirmation: bool, destructive: bool) -> None:
    if action.risk != risk:
        raise UmzugError(f"action {action.id} must use derived risk {risk}")
    if action.requires_confirmation is not confirmation:
        raise UmzugError(f"action {action.id} has an invalid confirmation policy")
    if action.destructive is not destructive:
        raise UmzugError(f"action {action.id} has an invalid destructive policy")


def _disable_action_id(name: str) -> str:
    return "disable-" + name.lower().replace(".", "-").replace("@", "-")


def preflight_action_id(name: str) -> str:
    if name not in PREFLIGHT_EXECUTABLES:
        raise UmzugError(f"unsupported executable preflight: {name}")
    return "preflight-executable-" + name


def required_preflight_executables(actions: list["Action"]) -> tuple[str, ...]:
    tools: set[str] = set()
    provisioned_tools: set[str] = set()
    positions = {action.id: index for index, action in enumerate(actions)}
    rfkill_provisioned_before_use = False
    radio_position = positions.get("radio-block-now")
    for index, action in enumerate(actions):
        if action.operation == "check_executable":
            continue
        if action.id == "nixos-local-recovery":
            tools.add("nixos-rebuild")
        if action.operation == "run_command":
            argv = action.parameters.get("argv")
            if isinstance(argv, list) and argv and isinstance(argv[0], str):
                tools.add(argv[0])
                if action.id == "mullvad-offline-install":
                    if argv[0] == "apt-get":
                        tools.update({"dpkg", "dpkg-query"})
                    else:
                        tools.add("rpm")
                if (
                    radio_position is not None
                    and index < radio_position
                    and argv[0] == "apt-get"
                    and "--" in argv
                    and "rfkill" in argv[argv.index("--") + 1 :]
                ):
                    rfkill_provisioned_before_use = True
                if argv[0] == "apt-get" and "--" in argv:
                    packages = set(argv[argv.index("--") + 1 :])
                    package_tools = {
                        "curl": {"curl"},
                        "iproute2": {"ip", "ss"},
                        "rfkill": {"rfkill"},
                        "systemd-resolved": {"resolvectl"},
                        "wireguard-tools": {"wg"},
                    }
                    for package, supplied in package_tools.items():
                        if package in packages:
                            provisioned_tools.update(supplied)
                if action.id == "mullvad-offline-install":
                    tools.update({"curl", "ip", "nft", "ss", "systemctl", "wg"})
            if action.parameters.get("network_policy") == "forbidden":
                tools.add("unshare")
        elif action.operation in {"disable_service", "enable_service"}:
            init = action.parameters.get("init", "systemd")
            if init == "systemd":
                tools.add("systemctl")
            elif init == "openrc":
                tools.update({"rc-service", "rc-update"})
        elif action.operation == "ensure_group":
            tools.add("groupadd")

        kind = action.verify.get("kind") if isinstance(action.verify, dict) else None
        if kind in {"host_firewall", "offline_guard"}:
            tools.add("nft")
        elif kind == "radio_blocked":
            tools.add("rfkill")
        elif kind == "package_status":
            tools.add("dpkg-query")
        elif kind == "service_disabled":
            init = action.verify.get("init", "systemd")
            tools.update({"rc-service", "rc-update"} if init == "openrc" else {"systemctl"})

    if rfkill_provisioned_before_use:
        tools.discard("rfkill")
    tools.difference_update(provisioned_tools)
    unsupported = tools - PREFLIGHT_EXECUTABLES
    if unsupported:
        raise UmzugError("plan requires executables outside the preflight registry: " + ", ".join(sorted(unsupported)))
    return tuple(sorted(tools))


def prepend_executable_preflights(actions: list["Action"]) -> list["Action"]:
    """return a final action sequence with exact, immutable preflights first.

    callers must compose the complete ordered action list before invoking this
    helper.  refusing existing preflight actions avoids silently normalizing a
    duplicated or attacker-modified sequence.
    """

    if any(action.operation == "check_executable" for action in actions):
        raise UmzugError("executable preflights may only be added once after plan composition")
    preflights = [
        Action(
            id=preflight_action_id(name),
            phase="preflight",
            summary=f"Erforderliches lokales Werkzeug {name} vor Änderungen prüfen",
            rationale=(
                "Fehlende oder veränderbare Systemwerkzeuge müssen den produktiven "
                "Lauf vor der ersten Mutation stoppen."
            ),
            risk="low",
            operation="check_executable",
            parameters={"name": name},
            verify={"kind": "executable_available", "name": name},
        )
        for name in required_preflight_executables(actions)
    ]
    return [*preflights, *actions]


def _validate_required_hashes(value: object, artifact: str) -> None:
    if not isinstance(value, dict) or set(value) != {artifact}:
        raise UmzugError("vendor install must bind exactly its sole local artifact")
    digest = value.get(artifact)
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise UmzugError("vendor install artifact has no valid SHA-256 binding")


def _validate_command_action(action: "Action") -> None:
    params = action.parameters
    _exact_keys(
        params,
        {"argv"},
        {
            "network_policy",
            "timeout",
            "required_file_hashes",
            "post_install_argvs",
        },
    )
    argv = params.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 4096
        or any(not isinstance(item, str) or not item or "\x00" in item or len(item) > 4096 for item in argv)
    ):
        raise UmzugError(f"action {action.id} has an invalid argv")
    command = tuple(argv)
    fixed = RUN_COMMAND_SCHEMA.get(action.id)
    if fixed is not None:
        allowed, risk = fixed
        if command not in allowed:
            raise UmzugError(f"action {action.id} does not match its fixed argv template")
        if action.id in {"offline-guard-syntax", "firewall-syntax"}:
            _require_metadata(action, risk=risk, confirmation=False, destructive=False)
        else:
            _require_metadata(action, risk=risk, confirmation=True, destructive=True)
        if set(params) != {"argv"} and not (
            action.id == "hardening-initramfs-rebuild"
            and set(params) == {"argv", "network_policy", "timeout"}
            and params["network_policy"] == "forbidden"
            and type(params["timeout"]) is int
            and params["timeout"] == 1800
        ):
            raise UmzugError(f"action {action.id} has unexpected command parameters")
        return

    if re.fullmatch(r"packages\.debian\.[0-9a-f]{16}", action.id):
        prefix = ("apt-get", "install", "--yes", "--no-install-recommends", "--no-download", "--")
        if command[: len(prefix)] != prefix or len(command) <= len(prefix):
            raise UmzugError("Debian package action has an unreviewed argv template")
        packages = list(command[len(prefix) :])
        if any(not PACKAGE_RE.fullmatch(item) or item.startswith("-") or "/" in item for item in packages):
            raise UmzugError("Debian package action has an unsafe native package name")
        try:
            from .adapters import _PACKAGE_MAP  # local import avoids an import cycle.

            mapped = {package for target in _PACKAGE_MAP["debian"].values() for package in target.packages}
        except (ImportError, KeyError, AttributeError) as exc:
            raise UmzugError("Debian package policy registry is unavailable") from exc
        if not set(packages).issubset(mapped) or len(packages) != len(set(packages)):
            raise UmzugError("Debian package action is outside the finite capability map")
        payload = json.dumps(["debian", packages], separators=(",", ":"), sort_keys=False)
        expected_id = f"packages.debian.{hashlib.sha256(payload.encode()).hexdigest()[:16]}"
        if action.id != expected_id:
            raise UmzugError("Debian package action ID is not bound to its package list")
        if params != {
            "argv": argv,
            "network_policy": "forbidden",
            "timeout": 3600,
        }:
            raise UmzugError("Debian package action is not an exact offline command")
        _require_metadata(action, risk="high", confirmation=True, destructive=True)
        expected_verify = {
            "kind": "package_status",
            "manager": "dpkg",
            "packages": packages,
        }
        if action.verify != expected_verify:
            raise UmzugError("Debian package verifier is not bound to the installed package list")
        return

    if action.id == "mullvad-offline-install":
        deb_prefix = (
            "apt-get",
            "install",
            "--yes",
            "--reinstall",
            "--no-download",
            "--no-install-recommends",
            "--",
        )
        rpm_prefix = ("rpm", "--upgrade", "--replacepkgs", "--")
        if command[: len(deb_prefix)] == deb_prefix and len(command) == len(deb_prefix) + 1:
            artifact = command[-1]
            suffix = ".deb"
        elif command[: len(rpm_prefix)] == rpm_prefix and len(command) == len(rpm_prefix) + 1:
            artifact = command[-1]
            suffix = ".rpm"
        else:
            raise UmzugError("Mullvad install does not match a fixed offline package template")
        _safe_absolute_path(artifact)
        if not artifact.lower().endswith(suffix):
            raise UmzugError("Mullvad artifact suffix does not match its package manager")
        if params.get("network_policy") != "forbidden" or params.get("timeout") != 1800:
            raise UmzugError("Mullvad install is not network-isolated and time-bounded")
        _validate_required_hashes(params.get("required_file_hashes"), artifact)
        if params.get("post_install_argvs") != [
            ["systemctl", "daemon-reload"],
            ["systemctl", "restart", "mullvad-daemon.service"],
        ]:
            raise UmzugError("Mullvad install lacks its fixed immediate systemd activation sequence")
        expected_manager = "dpkg" if suffix == ".deb" else "rpm"
        if (
            set(action.verify)
            != {
                "kind",
                "manager",
                "package",
                "version",
                "architecture",
                "management_group",
            }
            or action.verify.get("kind") != "mullvad_version"
            or action.verify.get("manager") != expected_manager
            or action.verify.get("package") != "mullvad-vpn"
            or not isinstance(action.verify.get("version"), str)
            or not PACKAGE_VERSION_RE.fullmatch(action.verify["version"])
            or not isinstance(action.verify.get("architecture"), str)
            or not PACKAGE_ARCH_RE.fullmatch(action.verify["architecture"])
            or not isinstance(action.verify.get("management_group"), str)
            or not GROUP_RE.fullmatch(action.verify["management_group"])
        ):
            raise UmzugError("Mullvad install lacks its exact package identity verifier")
        _require_metadata(action, risk="critical", confirmation=True, destructive=True)
        return
    raise UmzugError(f"run_command action ID has no privileged schema: {action.id}")


def _validate_write_action(action: "Action", *, test_mode: bool) -> None:
    params = action.parameters
    _exact_keys(params, {"path", "content"}, {"mode"})
    path = _safe_absolute_path(params.get("path"))
    content = params.get("content")
    mode = params.get("mode", 0o644)
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_CONTENT_BYTES or "\x00" in content:
        raise UmzugError(f"action {action.id} has invalid or oversized file content")
    if type(mode) is not int or not 0 <= mode <= 0o777 or mode & 0o7000:
        raise UmzugError(f"action {action.id} has an invalid file mode")
    if test_mode:
        if action.backup_paths not in ([], [path]):
            raise UmzugError("test write may back up only its exact target")
        _require_metadata(action, risk="low", confirmation=False, destructive=False)
        return
    if "mode" not in params:
        raise UmzugError(f"action {action.id} must state its exact managed file mode")
    schema = WRITE_FILE_SCHEMA.get(action.id)
    if schema is None and re.fullmatch(r"package-file-[0-9]+-(?:nixos|gentoo)", action.id):
        allowed = {
            "/etc/nixos/umzug-packages.nix": 0o644,
            "/etc/portage/package.use/umzug": 0o644,
        }
        expected_mode = allowed.get(path)
        if expected_mode is None or expected_mode != mode:
            raise UmzugError("package declarative file target is outside its adapter schema")
        risk = "high"
    elif schema is not None:
        expected_path, expected_mode, risk = schema
        if path != expected_path or mode != expected_mode:
            raise UmzugError(f"action {action.id} does not match its fixed path/mode schema")
    else:
        raise UmzugError(f"write_file action ID has no privileged schema: {action.id}")
    if action.backup_paths != [path]:
        raise UmzugError(f"action {action.id} must back up exactly its mutated path")
    _require_metadata(action, risk=risk, confirmation=True, destructive=True)


def _validate_checkpoint(action: "Action") -> None:
    expected: dict[str, dict[str, Any]] = {
        "nixos-import-rebuild-checkpoint": {
            "commands": [
                "nixos-rebuild dry-build",
                "nixos-rebuild test",
                "nixos-rebuild boot",
            ],
            "required_evidence": (
                "reviewed import diff; successful local test; exact tested /nix/store "
                "system path selected as the boot generation"
            ),
            "evidence_kind": "nixos-system-store-path",
        },
        "offline-guard-persistence-checkpoint": {
            "required_evidence": "early-boot load of /etc/umzug/offline-guard.nft before all network services",
        },
        "hardening-initramfs-manual-checkpoint": {
            "manual_verification": "rebuild initramfs with target-native tooling and record its hash",
        },
        "firewall-init-manual-checkpoint": {
            "rules": "/etc/umzug/firewall.nft",
            "required": "early-boot load plus console recovery test",
        },
    }
    if action.id not in expected or action.parameters != expected[action.id]:
        raise UmzugError(f"checkpoint {action.id} has no exact evidence schema")
    _require_metadata(action, risk="critical", confirmation=True, destructive=True)


@dataclass(frozen=True)
class Action:
    id: str
    phase: str
    summary: str
    rationale: str
    risk: str
    operation: str
    parameters: dict[str, Any] = field(default_factory=dict)
    backup_paths: list[str] = field(default_factory=list)
    verify: dict[str, Any] = field(default_factory=dict)
    requires_confirmation: bool = False
    destructive: bool = False
    reboot_reason: str | None = None
    post_reboot_verify: dict[str, Any] = field(default_factory=dict)

    def validate(self, *, test_mode: bool = False) -> None:
        if (
            not isinstance(self.id, str)
            or not self.id
            or len(self.id) > 128
            or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for char in self.id)
        ):
            raise UmzugError(f"invalid action id: {self.id!r}")
        for label, value in (("phase", self.phase), ("summary", self.summary), ("rationale", self.rationale)):
            if not isinstance(value, str) or not value or len(value) > MAX_TEXT or "\x00" in value:
                raise UmzugError(f"action {self.id} has invalid {label}")
        if self.operation not in ALLOWED_OPERATIONS:
            raise UmzugError(f"unsupported operation: {self.operation}")
        if self.risk not in {"low", "medium", "high", "critical"}:
            raise UmzugError(f"invalid risk for {self.id}")
        if type(self.requires_confirmation) is not bool or type(self.destructive) is not bool:
            raise UmzugError(f"action {self.id} has non-boolean safety flags")
        if (
            not isinstance(self.parameters, dict)
            or not isinstance(self.verify, dict)
            or not isinstance(self.post_reboot_verify, dict)
        ):
            raise UmzugError(f"action {self.id} has invalid structured fields")
        if len(canonical_json(self.parameters)) > MAX_PARAMETERS_BYTES:
            raise UmzugError(f"action {self.id} parameters exceed the bounded limit")
        if (
            not isinstance(self.backup_paths, list)
            or len(self.backup_paths) > 1
            or any(not isinstance(path, str) for path in self.backup_paths)
        ):
            raise UmzugError(f"action {self.id} has invalid backup paths")
        if self.reboot_reason is not None and (
            not isinstance(self.reboot_reason, str) or not self.reboot_reason or len(self.reboot_reason) > MAX_TEXT
        ):
            raise UmzugError(f"action {self.id} has an invalid reboot reason")
        if self.reboot_reason and not self.post_reboot_verify:
            raise UmzugError(f"reboot action {self.id} lacks a post-reboot verification")
        if self.post_reboot_verify and not self.reboot_reason:
            raise UmzugError(f"post-reboot verifier {self.id} has no required reboot boundary")

        if self.operation == "check_executable":
            _exact_keys(self.parameters, {"name"})
            name = self.parameters.get("name")
            if not isinstance(name, str) or name not in PREFLIGHT_EXECUTABLES or self.id != preflight_action_id(name):
                raise UmzugError("executable preflight is outside the finite registry")
            if self.verify != {"kind": "executable_available", "name": name}:
                raise UmzugError("executable preflight verifier is not bound to the same name")
            if self.backup_paths or self.post_reboot_verify or self.reboot_reason:
                raise UmzugError("executable preflight contains unsupported side fields")
            _require_metadata(self, risk="low", confirmation=False, destructive=False)
        elif self.operation == "write_file":
            _validate_write_action(self, test_mode=test_mode)
        elif self.operation == "run_command":
            _validate_command_action(self)
        elif self.operation == "ensure_group":
            _exact_keys(self.parameters, {"name"})
            name = self.parameters.get("name")
            if self.id != "mullvad-management-group" or not isinstance(name, str) or not GROUP_RE.fullmatch(name):
                raise UmzugError("only the bounded dedicated Mullvad management group may be created")
            if (
                self.backup_paths
                or self.verify != {"kind": "restricted_group", "name": name}
                or self.post_reboot_verify
                or self.reboot_reason
            ):
                raise UmzugError("group action contains unsupported side fields")
            _require_metadata(self, risk="medium", confirmation=True, destructive=True)
        elif self.operation == "disable_service":
            _exact_keys(self.parameters, {"name", "mask", "init"})
            name = self.parameters.get("name")
            init = self.parameters.get("init")
            mask = self.parameters.get("mask")
            allowed = SYSTEMD_DISABLED if init == "systemd" else OPENRC_DISABLED if init == "openrc" else set()
            if not isinstance(name, str) or name not in allowed or self.id != _disable_action_id(name):
                raise UmzugError("service disable action is outside the no-inbound/radio policy")
            if type(mask) is not bool or mask is not (init == "systemd"):
                raise UmzugError("service disable action has an invalid mask/init policy")
            if self.verify != {"kind": "service_disabled", "name": name, "init": init}:
                raise UmzugError("service disable verifier is not bound to the same unit")
            if self.backup_paths or self.post_reboot_verify or self.reboot_reason:
                raise UmzugError("service disable action contains unsupported side fields")
            _require_metadata(self, risk="high", confirmation=True, destructive=True)
        elif self.operation == "enable_service":
            _exact_keys(self.parameters, {"name"}, {"init"})
            schema = ENABLED_SERVICES.get(self.id)
            init = self.parameters.get("init", "systemd")
            if schema is None or self.parameters.get("name") != schema[0] or init != "systemd":
                raise UmzugError("only toolkit-owned systemd services may be enabled")
            if self.verify != {
                "kind": "service_enabled",
                "name": schema[0],
                "init": "systemd",
            }:
                raise UmzugError("toolkit service enable verifier is not bound to the same unit")
            if self.backup_paths or self.post_reboot_verify or self.reboot_reason:
                raise UmzugError("service enable action contains unsupported side fields")
            _require_metadata(self, risk=schema[1], confirmation=True, destructive=True)
        elif self.operation == "checkpoint":
            if self.backup_paths or self.verify:
                raise UmzugError("checkpoint action contains unsupported side fields")
            if test_mode:
                _require_metadata(self, risk="low", confirmation=False, destructive=False)
            else:
                _validate_checkpoint(self)
