from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any

from . import __version__
from .util import UmzugError, canonical_json
from .actions import (
    ALLOWED_OPERATIONS,
    Action,
    ENABLED_SERVICES,
    EXECUTABLE_SEARCH_PATH,
    GROUP_RE,
    MAX_CONTENT_BYTES,
    MAX_PARAMETERS_BYTES,
    MAX_TEXT,
    MODULE_RE,
    OPENRC_DISABLED,
    PACKAGE_ARCH_RE,
    PACKAGE_RE,
    PACKAGE_VERSION_RE,
    PREFLIGHT_EXECUTABLES,
    RUN_COMMAND_SCHEMA,
    SHA256_RE,
    SYSTEMD_DISABLED,
    WRITE_FILE_SCHEMA,
    _disable_action_id,
    _safe_absolute_path,
    preflight_action_id,
    prepend_executable_preflights,
    required_preflight_executables,
)


ALLOWED_PROFILES = {"compatible", "strict", "maximal", "test"}
MAX_ACTIONS = 10_000


@dataclass
class Plan:
    profile: str
    system_fingerprint: str
    actions: list[Action]
    created_at: str
    intent: dict[str, Any] = field(default_factory=dict)
    format_version: int = 1
    toolkit_version: str = __version__

    def validate(self) -> None:
        if type(self.format_version) is not int or self.format_version != 1:
            raise UmzugError("unsupported plan format")
        if self.profile not in ALLOWED_PROFILES:
            raise UmzugError("unsupported plan hardening profile")
        if (
            not isinstance(self.system_fingerprint, str)
            or not SHA256_RE.fullmatch(self.system_fingerprint)
            and self.profile != "test"
        ):
            raise UmzugError("plan has an invalid target fingerprint")
        if not isinstance(self.created_at, str) or not self.created_at or len(self.created_at) > 128:
            raise UmzugError("plan has an invalid creation time")
        if (
            not isinstance(self.toolkit_version, str)
            or re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}", self.toolkit_version) is None
        ):
            raise UmzugError("plan has an invalid toolkit version")
        if not isinstance(self.actions, list) or len(self.actions) > MAX_ACTIONS:
            raise UmzugError("plan action list exceeds the bounded limit")
        seen: set[str] = set()
        by_id: dict[str, Action] = {}
        for action in self.actions:
            if not isinstance(action, Action):
                raise UmzugError("plan contains a non-Action entry")
            action.validate(test_mode=self.profile == "test")
            if action.id in seen:
                raise UmzugError(f"duplicate action id: {action.id}")
            seen.add(action.id)
            by_id[action.id] = action
        self._validate_intent(by_id)
        self._validate_verifiers(by_id)
        self._validate_rendered_content(by_id)
        self._validate_order()

    def _validate_intent(self, by_id: dict[str, Action]) -> None:
        if self.profile == "test":
            if self.intent:
                raise UmzugError("test plans may not carry a productive target intent")
            return
        required = {
            "distribution",
            "distribution_like",
            "init_system",
            "profile",
            "ethernet_interfaces",
            "radio_modules",
            "radio_hardware",
            "package_adapter",
            "package_managers",
            "package_requests",
            "vendor",
            "mullvad_management_group",
        }
        if not isinstance(self.intent, dict) or set(self.intent) != required:
            raise UmzugError("productive plan lacks its exact declarative target intent")
        distribution = self.intent.get("distribution")
        init_system = self.intent.get("init_system")
        if (
            not isinstance(distribution, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", distribution)
            or not isinstance(init_system, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,31}", init_system)
        ):
            raise UmzugError("plan target distribution/init intent is invalid")
        distribution_like = self.intent.get("distribution_like")
        package_managers = self.intent.get("package_managers")
        for values, label in (
            (distribution_like, "distribution-like"),
            (package_managers, "package-manager"),
        ):
            if (
                not isinstance(values, list)
                or values != sorted(set(values))
                or any(
                    not isinstance(item, str) or not re.fullmatch(r"[a-z0-9][a-z0-9+._-]{0,63}", item)
                    for item in values
                )
            ):
                raise UmzugError(f"plan {label} intent is not canonical")

        try:
            from .hardening_policy import hardening_actions, validate_profile
            from .network import validate_interfaces
        except ImportError as exc:
            raise UmzugError("trusted hardening intent renderers are unavailable") from exc
        profile = validate_profile(self.intent.get("profile", {}))
        if profile["name"] != self.profile:
            raise UmzugError("plan profile name differs from its bound policy intent")
        interfaces = self.intent.get("ethernet_interfaces")
        if not isinstance(interfaces, list) or validate_interfaces(interfaces) != interfaces:
            raise UmzugError("plan Ethernet intent is not canonical")
        radios = self.intent.get("radio_modules")
        if (
            not isinstance(radios, list)
            or radios != sorted(set(radios))
            or any(not isinstance(item, str) or not MODULE_RE.fullmatch(item) for item in radios)
        ):
            raise UmzugError("plan radio-module intent is not canonical")
        radio_hardware = self.intent.get("radio_hardware")
        canonical_radio_hardware: list[dict[str, str]] = []
        if not isinstance(radio_hardware, list):
            raise UmzugError("plan radio-hardware intent is not a list")
        for item in radio_hardware:
            if not isinstance(item, dict) or set(item) != {
                "name",
                "kind",
                "mac_address",
                "driver",
            }:
                raise UmzugError("plan radio-hardware intent has invalid fields")
            name = item.get("name")
            kind = item.get("kind")
            mac = item.get("mac_address")
            driver = item.get("driver")
            if (
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", name) is None
                or kind not in {"wifi", "cellular"}
                or not isinstance(mac, str)
                or (mac and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac) is None)
                or not isinstance(driver, str)
                or (driver and MODULE_RE.fullmatch(driver) is None)
            ):
                raise UmzugError("plan radio-hardware intent is invalid")
            canonical_radio_hardware.append(dict(item))
        canonical_radio_hardware.sort(
            key=lambda row: (
                row["name"],
                row["kind"],
                row["mac_address"],
                row["driver"],
            )
        )
        if radio_hardware != canonical_radio_hardware or len(
            {(row["name"], row["kind"], row["mac_address"], row["driver"]) for row in radio_hardware}
        ) != len(radio_hardware):
            raise UmzugError("plan radio-hardware intent is not canonical")

        expected_hardening_order = hardening_actions(
            distribution=distribution,
            init_system=init_system,
            profile=profile,
            ethernet_interfaces=interfaces,
            radio_modules=radios,
        )
        expected_body = {action.id: action for action in expected_hardening_order}
        known_hardening_ids = (
            (set(WRITE_FILE_SCHEMA) - {"mullvad-management-socket"})
            | set(RUN_COMMAND_SCHEMA)
            | set(ENABLED_SERVICES)
            | {_disable_action_id(name) for name in SYSTEMD_DISABLED | OPENRC_DISABLED}
            | {
                "hardening-initramfs-manual-checkpoint",
                "offline-guard-persistence-checkpoint",
                "firewall-init-manual-checkpoint",
                "nixos-import-rebuild-checkpoint",
            }
        )
        missing = sorted(set(expected_body) - set(by_id))
        extra = sorted((set(by_id) & known_hardening_ids) - set(expected_body))
        if missing or extra:
            raise UmzugError(
                "plan hardening actions differ from its declarative target intent"
                + (f"; missing={','.join(missing)}" if missing else "")
                + (f"; extraneous={','.join(extra)}" if extra else "")
            )
        for action_id, expected in expected_body.items():
            if by_id[action_id] != expected:
                raise UmzugError(f"hardening action {action_id} differs from its regenerated target intent")

        adapter_id = self.intent.get("package_adapter")
        requests = self.intent.get("package_requests")
        allowed_adapters = {"none", "debian", "arch", "nixos", "gentoo", "lfs", "generic"}
        if adapter_id not in allowed_adapters or not isinstance(requests, list):
            raise UmzugError("plan package intent has an invalid adapter or request list")
        if len(requests) > 4096 or any(not isinstance(item, str) or not item or len(item) > 128 for item in requests):
            raise UmzugError("plan package request intent is not bounded")
        if adapter_id == "none" and requests:
            raise UmzugError("hardening-only plans may not carry package requests")
        package_ids = {
            action.id
            for action in self.actions
            if action.id.startswith("packages.") or action.id.startswith("package-file-")
        }
        expected_package_order: list[Action] = []
        expected_package: dict[str, Action] = {}
        if adapter_id != "none":
            try:
                from .adapters import select_adapter
                from .detection import DistributionInfo
                from .package_actions import package_actions

                adapter = select_adapter(
                    DistributionInfo(
                        id=distribution,
                        name=distribution,
                        id_like=tuple(distribution_like),
                    ),
                    tuple(package_managers),
                )
                if adapter.adapter_id != adapter_id:
                    raise UmzugError("package adapter is not bound to the target distribution")
                regenerated = package_actions(adapter.plan_packages(requests, offline=True))
                expected_package_order = regenerated
                expected_package = {action.id: action for action in regenerated}
            except (ImportError, KeyError, TypeError, ValueError) as exc:
                raise UmzugError("package intent cannot be regenerated safely") from exc
        if package_ids != set(expected_package):
            raise UmzugError("package actions differ from the bound adapter capability intent")
        for action_id, expected in expected_package.items():
            if by_id[action_id] != expected:
                raise UmzugError(f"package action {action_id} differs from its regenerated capability intent")

        try:
            from .package_actions import (
                mullvad_install_action,
                mullvad_management_actions,
            )
        except ImportError as exc:
            raise UmzugError("trusted Mullvad intent renderers are unavailable") from exc

        vendor_intent = self.intent.get("vendor")
        group = self.intent.get("mullvad_management_group")
        expected_vendor: list[Action] = []
        if vendor_intent is not None:
            vendor_keys = {
                "kind",
                "workspace",
                "candidate",
                "artifact",
                "receipt",
                "artifact_sha256",
                "fingerprint",
                "gpg_sha256",
                "gpgv_sha256",
                "bwrap_sha256",
                "receipt_sha256",
                "package_version",
                "package_architecture",
            }
            if not isinstance(vendor_intent, dict) or set(vendor_intent) != vendor_keys:
                raise UmzugError("Mullvad vendor intent has an invalid exact schema")
            workspace = _safe_absolute_path(vendor_intent.get("workspace"))
            artifact = _safe_absolute_path(vendor_intent.get("artifact"))
            receipt = _safe_absolute_path(vendor_intent.get("receipt"))
            candidate = vendor_intent.get("candidate")
            if (
                vendor_intent.get("kind") != "mullvad-openpgp-v4"
                or not isinstance(candidate, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", candidate)
                or not isinstance(vendor_intent.get("fingerprint"), str)
                or not re.fullmatch(r"[0-9A-F]{40}", vendor_intent["fingerprint"])
            ):
                raise UmzugError("Mullvad vendor intent identity is invalid")
            for key in (
                "artifact_sha256",
                "gpg_sha256",
                "gpgv_sha256",
                "bwrap_sha256",
                "receipt_sha256",
            ):
                if not isinstance(vendor_intent.get(key), str) or not SHA256_RE.fullmatch(vendor_intent[key]):
                    raise UmzugError(f"Mullvad vendor intent has an invalid {key}")
            if (
                not isinstance(vendor_intent.get("package_version"), str)
                or not PACKAGE_VERSION_RE.fullmatch(vendor_intent["package_version"])
                or not isinstance(vendor_intent.get("package_architecture"), str)
                or not PACKAGE_ARCH_RE.fullmatch(vendor_intent["package_architecture"])
            ):
                raise UmzugError("Mullvad vendor package identity intent is invalid")
            workspace_path = PurePosixPath(workspace)
            artifact_path = PurePosixPath(artifact)
            receipt_path = PurePosixPath(receipt)
            approved_candidate = workspace_path / "APPROVED" / candidate
            vendor_receipts = workspace_path / "state" / "vendor"
            if approved_candidate not in artifact_path.parents:
                raise UmzugError("Mullvad artifact intent is not below its APPROVED candidate")
            if vendor_receipts not in receipt_path.parents:
                raise UmzugError("Mullvad receipt intent is outside workspace/state/vendor")
            expected_vendor = [
                mullvad_install_action(
                    distribution=distribution,
                    package_adapter=adapter_id,
                    artifact=artifact,
                    artifact_sha256=vendor_intent["artifact_sha256"],
                    package_version=vendor_intent["package_version"],
                    package_architecture=vendor_intent["package_architecture"],
                    management_group=group,
                )
            ]
        observed_vendor = [action for action in self.actions if action.id == "mullvad-offline-install"]
        if observed_vendor != expected_vendor:
            raise UmzugError("Mullvad install action differs from its bound vendor intent")

        expected_management: list[Action] = []
        if group is not None:
            if (
                not isinstance(group, str)
                or not GROUP_RE.fullmatch(group)
                or init_system != "systemd"
                or distribution not in {"debian", "ubuntu", "fedora"}
            ):
                raise UmzugError("Mullvad management preparation differs from target intent")
            expected_management = mullvad_management_actions(group)
        observed_management = [
            action for action in self.actions if action.id in {"mullvad-management-group", "mullvad-management-socket"}
        ]
        if observed_management != expected_management:
            raise UmzugError("Mullvad management actions differ from their bound intent")
        if vendor_intent is not None and not expected_management:
            raise UmzugError("Mullvad vendor installation requires bound management-socket preparation")
        if distribution == "nixos":
            canonical_body = [
                *expected_hardening_order,
                *expected_package_order,
                *expected_management,
                *expected_vendor,
            ]
        else:
            network_gates = [
                action
                for action in expected_hardening_order
                if action.phase in {"recovery", "bootstrap-security"}
                or (action.phase == "network" and not action.id.startswith("radio-"))
            ]
            containment = [
                action
                for action in expected_hardening_order
                if action.phase == "services" or action.id.startswith("radio-")
            ]
            deferred = [
                action
                for action in expected_hardening_order
                if action not in network_gates and action not in containment
            ]
            canonical_body = [
                *network_gates,
                *expected_package_order,
                *containment,
                *expected_management,
                *expected_vendor,
                *deferred,
            ]
        actual_body = [action for action in self.actions if action.operation != "check_executable"]
        if actual_body != canonical_body:
            raise UmzugError("productive action order or content differs from the complete regenerated intent")

    def _validate_verifiers(self, by_id: dict[str, Action]) -> None:
        allowed_kinds = {
            "file_sha256",
            "service_disabled",
            "service_enabled",
            "sysctl_effective",
            "radio_blocked",
            "host_firewall",
            "offline_guard",
            "package_status",
            "mullvad_version",
            "restricted_group",
            "executable_available",
        }
        for action in self.actions:
            if action.verify and action.verify.get("kind") not in allowed_kinds:
                raise UmzugError(f"action {action.id} has an unsupported verifier")
            if action.operation == "write_file" and action.verify:
                check = action.verify
                if set(check) != {"kind", "path", "sha256"} or check.get("kind") != "file_sha256":
                    raise UmzugError("write verifier must be a path-bound SHA-256 check")
                content = action.parameters["content"].encode("utf-8")
                if (
                    check.get("path") != action.parameters["path"]
                    or check.get("sha256") != hashlib.sha256(content).hexdigest()
                ):
                    raise UmzugError("write verifier does not match its exact planned bytes")
            if (
                action.operation
                not in {
                    "check_executable",
                    "write_file",
                    "run_command",
                    "ensure_group",
                    "disable_service",
                    "enable_service",
                }
                and action.verify
            ):
                raise UmzugError(f"operation {action.operation} may not carry an independent verifier")
            if action.operation == "check_executable" and action.verify != {
                "kind": "executable_available",
                "name": action.parameters.get("name"),
            }:
                raise UmzugError("executable preflight verifier differs from its action")
            if action.id == "offline-guard-activate" and action.verify != {"kind": "offline_guard"}:
                raise UmzugError("offline guard activation lacks its exact effective-state verifier")
            if action.id == "radio-block-now" and action.verify != {"kind": "radio_blocked"}:
                raise UmzugError("radio blocking lacks its exact effective-state verifier")
            if action.id == "firewall-enable":
                if (
                    set(action.verify) != {"kind", "interfaces", "ipv6_enabled"}
                    or action.verify.get("kind") != "host_firewall"
                    or not isinstance(action.verify.get("interfaces"), list)
                    or not action.verify["interfaces"]
                    or any(not isinstance(item, str) for item in action.verify["interfaces"])
                    or type(action.verify.get("ipv6_enabled")) is not bool
                ):
                    raise UmzugError("host firewall activation lacks its typed effective-state verifier")
            if (
                action.id in RUN_COMMAND_SCHEMA
                and action.id
                not in {
                    "offline-guard-activate",
                    "radio-block-now",
                    "firewall-enable",
                    "firewall-openrc-persist",
                    "hardening-sysctl-apply",
                }
                and action.verify
            ):
                raise UmzugError(f"action {action.id} may not carry an independent verifier")
            if action.id == "mullvad-management-group" and action.verify != {
                "kind": "restricted_group",
                "name": action.parameters.get("name"),
            }:
                raise UmzugError("Mullvad management group lacks its exact membership verifier")
            if action.id == "hardening-sysctl-apply":
                source = by_id.get("hardening-sysctl")
                content = source.parameters.get("content") if source is not None else None
                expected_values = (
                    {
                        key.strip(): value.strip()
                        for line in content.splitlines()
                        if line and not line.startswith("#") and "=" in line
                        for key, value in (line.split("=", 1),)
                    }
                    if isinstance(content, str)
                    else None
                )
                if action.verify != {"kind": "sysctl_effective", "values": expected_values}:
                    raise UmzugError("sysctl application lacks its exact effective-value verifier")
            if action.id == "firewall-openrc-persist" and action.verify != {
                "kind": "service_enabled",
                "name": "local",
                "init": "openrc",
                "runlevel": "default",
            }:
                raise UmzugError("OpenRC firewall persistence lacks its exact runlevel verifier")
            post = action.post_reboot_verify
            if not post:
                continue
            kind = post.get("kind")
            if action.id == "nixos-import-rebuild-checkpoint":
                expected = {"kind": "nixos_booted_store_path"}
                if post != expected:
                    raise UmzugError("NixOS post-reboot attestation differs from its fixed policy")
            elif action.id in {"hardening-initramfs-rebuild", "hardening-initramfs-manual-checkpoint"}:
                if set(post) != {"kind", "modules", "ipv6_disabled"} or kind != "modules_not_loaded":
                    raise UmzugError("initramfs post-reboot verifier has an invalid schema")
                modules = post.get("modules")
                if (
                    not isinstance(modules, list)
                    or not modules
                    or len(modules) > 1024
                    or any(not isinstance(item, str) or not MODULE_RE.fullmatch(item) for item in modules)
                ):
                    raise UmzugError("initramfs post-reboot module list is invalid")
                if type(post.get("ipv6_disabled")) is not bool:
                    raise UmzugError("initramfs IPv6 postcondition is not boolean")
            elif self.profile == "test" and action.operation == "write_file" and post == {"kind": "boot_id_changed"}:
                pass
            else:
                raise UmzugError(f"action {action.id} may not execute a post-reboot verifier")

    def _validate_rendered_content(self, by_id: dict[str, Action]) -> None:
        try:
            from .hardening_policy import (
                _journald,
                _nixos_module,
                _openrc_firewall_start,
                _radio_openrc_start,
                _radio_systemd_unit,
                _sudoers,
                _sysctl,
            )
            from .network import (
                firewall_systemd_unit,
                host_firewall_rules,
                offline_guard_rules,
                offline_guard_systemd_unit,
                recovery_script,
            )
            from .vpn import management_override
        except ImportError as exc:
            raise UmzugError("trusted action renderers are unavailable") from exc

        contents = {
            action_id: action.parameters["content"]
            for action_id, action in by_id.items()
            if action.operation == "write_file"
        }
        exact: dict[str, str] = {
            "nixos-local-recovery": (
                "#!/bin/sh\n"
                "set -eu\n"
                "PATH=/run/current-system/sw/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "export PATH\n"
                "exec /run/current-system/sw/bin/nixos-rebuild switch --rollback\n"
            ),
            "offline-guard-rules": offline_guard_rules(),
            "offline-guard-unit": offline_guard_systemd_unit("/etc/umzug/offline-guard.nft"),
            "radio-systemd-unit": _radio_systemd_unit(),
            "radio-openrc-start": _radio_openrc_start(),
            "network-recovery-command": recovery_script(),
            "firewall-unit": firewall_systemd_unit("/etc/umzug/firewall.nft"),
            "firewall-openrc-start": _openrc_firewall_start("/etc/umzug/firewall.nft"),
            "journald-policy": _journald(),
        }
        for action_id, expected in exact.items():
            if action_id in contents and contents[action_id] != expected:
                raise UmzugError(f"action {action_id} content differs from its trusted renderer")

        if "hardening-sysctl" in contents:
            allowed = {
                _sysctl(
                    {
                        "name": name,
                        "disable_ipv6": disable_ipv6,
                        "vpn_killswitch": name in {"strict", "maximal"},
                    }
                )
                for name in (self.profile,)
                if name in {"compatible", "strict", "maximal"}
                for disable_ipv6 in (False, True)
            }
            if contents["hardening-sysctl"] not in allowed:
                raise UmzugError("sysctl file is outside the finite hardening renderer")
        if "sudo-policy" in contents and contents["sudo-policy"] not in {_sudoers(0), _sudoers(5), _sudoers(15)}:
            raise UmzugError("sudoers content differs from the finite policy renderer")
        if "mullvad-management-socket" in contents:
            group = by_id.get("mullvad-management-group")
            if group is None or contents["mullvad-management-socket"] != management_override(group.parameters["name"]):
                raise UmzugError("Mullvad management drop-in is not bound to its dedicated group")

        if "firewall-rules" in contents:
            activation = by_id.get("firewall-enable")
            check = activation.verify if activation is not None else None
            text = contents["firewall-rules"]
            interface_match = re.search(
                r"elements = \{ (?P<items>(?:\"[A-Za-z0-9_.:-]{1,15}\"(?:, )?)+) \}",
                text,
            )
            inferred_interfaces = (
                re.findall(r"\"([A-Za-z0-9_.:-]{1,15})\"", interface_match.group("items"))
                if interface_match is not None
                else []
            )
            inferred_ipv6 = "meta l4proto ipv6-icmp" in text
            interfaces = check.get("interfaces") if check is not None else inferred_interfaces
            ipv6 = check.get("ipv6_enabled") if check is not None else inferred_ipv6
            if (
                (check is not None and check.get("kind") != "host_firewall")
                or not isinstance(interfaces, list)
                or not interfaces
                or any(not isinstance(item, str) for item in interfaces)
                or type(ipv6) is not bool
                or interfaces != inferred_interfaces
                or ipv6 is not inferred_ipv6
                or contents["firewall-rules"] != host_firewall_rules(interfaces, ipv6_enabled=ipv6)
            ):
                raise UmzugError("host firewall bytes are not bound to their typed verifier")

        if "hardening-module-policy" in contents:
            text = contents["hardening-module-policy"]
            lines = text.splitlines()
            header = "# Managed by umzug. Remove only from the local console, then rebuild initramfs."
            if not lines or lines[0] != header or len(lines[1:]) % 2:
                raise UmzugError("kernel module policy is not in the inert finite grammar")
            modules: list[str] = []
            for index in range(1, len(lines), 2):
                match = re.fullmatch(r"blacklist ([A-Za-z0-9_]{1,128})", lines[index])
                if match is None or lines[index + 1] != f"install {match.group(1)} /bin/false":
                    raise UmzugError("kernel module policy contains an executable or malformed directive")
                modules.append(match.group(1))
            required = {"dccp", "rds", "sctp", "tipc"}
            if self.profile == "maximal":
                required.update({"cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "udf"})
            if modules != sorted(set(modules)) or not required.issubset(modules):
                raise UmzugError("kernel module policy is missing its baseline or is ambiguous")
            initramfs = by_id.get("hardening-initramfs-rebuild") or by_id.get("hardening-initramfs-manual-checkpoint")
            if initramfs is None or initramfs.post_reboot_verify.get("modules") != modules:
                raise UmzugError("module policy is not bound to its post-reboot loaded-module check")

        if "nixos-hardening-module" in contents:
            text = contents["nixos-hardening-module"]
            match = re.search(r"boot\.blacklistedKernelModules = \[ (?P<items>[^\n]*) \];", text)
            if match is None:
                raise UmzugError("NixOS hardening module has no bounded module list")
            observed = re.findall(r'"([A-Za-z0-9_]{1,128})"', match.group("items"))
            if " ".join(f'"{item}"' for item in observed) != match.group("items"):
                raise UmzugError("NixOS hardening module contains an unsafe module expression")
            matched = False
            for disable_ipv6 in (False, True):
                for disable_radios in (False, True):
                    for blacklist_radios in (False, True):
                        for minutes in (0, 5, 15):
                            profile = {
                                "name": self.profile,
                                "disable_ipv6": disable_ipv6,
                                "disable_radios": disable_radios,
                                "blacklist_radio_modules": blacklist_radios,
                                "firewall": True,
                                "vpn_killswitch": self.profile != "compatible",
                                "sudo_timestamp_minutes": minutes,
                            }
                            baseline = {"dccp", "rds", "sctp", "tipc"}
                            if self.profile == "maximal":
                                baseline.update({"cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "udf"})
                            extras = sorted(set(observed) - baseline) if blacklist_radios else []
                            if _nixos_module(profile, extras) == text:
                                matched = True
                                break
                        if matched:
                            break
                    if matched:
                        break
                if matched:
                    break
            if not matched:
                raise UmzugError("NixOS module differs from all finite trusted renderer outputs")

        for action in self.actions:
            if not re.fullmatch(r"package-file-[0-9]+-(?:nixos|gentoo)", action.id):
                continue
            path = action.parameters["path"]
            content = action.parameters["content"]
            if path == "/etc/nixos/umzug-packages.nix":
                if not action.id.endswith("-nixos"):
                    raise UmzugError("NixOS package file uses a mismatched adapter action ID")
                match = re.fullmatch(
                    r"# Managed by umzug\. Review and import explicitly\.\n"
                    r"\{ pkgs, \.\.\. \}:\n\{\n  environment\.systemPackages = with pkgs; \[\n"
                    r"(?P<body>(?:    [A-Za-z_][A-Za-z0-9_'.-]*(?:\.[A-Za-z_][A-Za-z0-9_'.-]*)*\n)+)"
                    r"  \];\n\}\n",
                    content,
                )
                if match is None:
                    raise UmzugError("NixOS package module is outside its inert finite grammar")
                packages = [line.strip() for line in match.group("body").splitlines()]
                try:
                    from .adapters import _PACKAGE_MAP

                    allowed = {package for target in _PACKAGE_MAP["nixos"].values() for package in target.packages}
                except (ImportError, KeyError, AttributeError) as exc:
                    raise UmzugError("NixOS package registry is unavailable") from exc
                if len(packages) != len(set(packages)) or not set(packages).issubset(allowed):
                    raise UmzugError("NixOS package module escapes the finite capability map")
            elif path == "/etc/portage/package.use/umzug":
                if not action.id.endswith("-gentoo"):
                    raise UmzugError("Portage package file uses a mismatched adapter action ID")
                allowed_lines = {"*/* apparmor", "*/* selinux", "app-admin/sudo pam"}
                lines = content.splitlines()
                if (
                    not lines
                    or lines != sorted(set(lines))
                    or not set(lines).issubset(allowed_lines)
                    or not content.endswith("\n")
                ):
                    raise UmzugError("Portage USE file escapes the finite capability map")

    def _validate_order(self) -> None:
        position = {action.id: index for index, action in enumerate(self.actions)}
        by_id = {action.id: action for action in self.actions}
        if self.profile != "test":
            expected_tools = required_preflight_executables(self.actions)
            expected_preflights = [preflight_action_id(name) for name in expected_tools]
            actual_preflights = [action.id for action in self.actions if action.operation == "check_executable"]
            if actual_preflights != expected_preflights:
                raise UmzugError("plan executable preflights are incomplete, extraneous, or non-canonical")
            if [action.id for action in self.actions[: len(expected_preflights)]] != expected_preflights:
                raise UmzugError("all executable preflights must form the leading plan prefix")
        edges = [
            ("hardening-sysctl", "hardening-sysctl-apply"),
            ("network-recovery-command", "offline-guard-rules"),
            ("offline-guard-rules", "offline-guard-syntax"),
            ("offline-guard-rules", "offline-guard-unit"),
            ("offline-guard-unit", "offline-guard-persist"),
            ("offline-guard-syntax", "offline-guard-persist"),
            ("offline-guard-persist", "offline-guard-activate"),
            ("offline-guard-syntax", "offline-guard-activate"),
            ("offline-guard-activate", "offline-guard-persistence-checkpoint"),
            ("offline-guard-activate", "firewall-rules"),
            ("firewall-rules", "firewall-syntax"),
            ("firewall-rules", "firewall-unit"),
            ("firewall-rules", "firewall-openrc-start"),
            ("firewall-unit", "firewall-persist"),
            ("firewall-openrc-start", "firewall-openrc-persist"),
            ("firewall-syntax", "firewall-persist"),
            ("firewall-syntax", "firewall-openrc-persist"),
            ("firewall-syntax", "firewall-init-manual-checkpoint"),
            ("firewall-persist", "firewall-enable"),
            ("firewall-openrc-persist", "firewall-enable"),
            ("firewall-syntax", "firewall-enable"),
            ("radio-block-now", "radio-systemd-unit"),
            ("radio-block-now", "radio-openrc-start"),
            ("radio-systemd-unit", "radio-systemd-enable"),
            ("mullvad-management-group", "mullvad-management-socket"),
            ("mullvad-management-socket", "mullvad-offline-install"),
            ("hardening-module-policy", "hardening-initramfs-rebuild"),
            ("hardening-module-policy", "hardening-initramfs-manual-checkpoint"),
            ("nixos-local-recovery", "nixos-hardening-module"),
            ("nixos-hardening-module", "nixos-import-rebuild-checkpoint"),
        ]
        for before, after in edges:
            if before in position and after in position and position[before] >= position[after]:
                raise UmzugError(f"unsafe action order: {before} must precede {after}")
        if "firewall-enable" in position:
            for action_id, index in position.items():
                if action_id.startswith("disable-") and position["firewall-enable"] >= index:
                    raise UmzugError("host firewall must be active before disabling incoming services")
        package_positions = [
            index
            for action_id, index in position.items()
            if action_id.startswith("packages.") or action_id.startswith("package-file-")
        ]
        if package_positions:
            if self.intent.get("distribution") == "nixos" and (
                "nixos-import-rebuild-checkpoint" not in position
                or position["nixos-import-rebuild-checkpoint"] >= min(package_positions)
            ):
                raise UmzugError("NixOS package module must follow the reviewed test generation checkpoint")
            last_network_gate = max(
                (
                    position[action_id]
                    for action_id in {"offline-guard-activate", "firewall-enable"}
                    if action_id in position
                ),
                default=-1,
            )
            first_containment = min(
                (
                    index
                    for action_id, index in position.items()
                    if action_id.startswith("disable-") or action_id.startswith("radio-")
                ),
                default=len(self.actions),
            )
            if min(package_positions) <= last_network_gate or max(package_positions) >= first_containment:
                raise UmzugError(
                    "adapter package operations must run after network gates and before service/radio containment"
                )
        if "mullvad-offline-install" in position:
            if not {
                "mullvad-management-group",
                "mullvad-management-socket",
            }.issubset(position):
                raise UmzugError("Mullvad vendor installation lacks management-socket containment")
            last_containment = max(
                (
                    index
                    for action_id, index in position.items()
                    if action_id.startswith("disable-") or action_id.startswith("radio-")
                ),
                default=-1,
            )
            if position["mullvad-offline-install"] <= last_containment:
                raise UmzugError("Mullvad vendor installation must follow service/radio containment")
        dependencies = {
            "offline-guard-persist": {"offline-guard-rules", "offline-guard-unit"},
            "firewall-persist": {"firewall-rules", "firewall-unit"},
            "radio-systemd-enable": {"radio-systemd-unit"},
        }
        for action_id, required in dependencies.items():
            if action_id in position and not required.issubset(position):
                raise UmzugError(f"action {action_id} lacks its trusted declarative inputs")
        if "offline-guard-rules" in position and not {
            "network-recovery-command",
            "offline-guard-syntax",
            "offline-guard-activate",
        }.issubset(position):
            raise UmzugError("offline guard plan is incomplete")
        if "offline-guard-activate" in position:
            command = tuple(by_id["offline-guard-activate"].parameters["argv"])
            persistence = (
                "offline-guard-persist" if command[0] == "systemctl" else "offline-guard-persistence-checkpoint"
            )
            if persistence not in position:
                raise UmzugError("offline guard activation lacks reviewed boot persistence")
        if "firewall-rules" in position:
            if not {"network-recovery-command", "firewall-syntax"}.issubset(position):
                raise UmzugError("host firewall plan lacks recovery or syntax validation")
            if not {"firewall-enable", "firewall-init-manual-checkpoint"}.intersection(position):
                raise UmzugError("host firewall plan lacks activation or a fail-closed manual checkpoint")
        if "firewall-enable" in position:
            command = tuple(by_id["firewall-enable"].parameters["argv"])
            required = (
                {"firewall-unit", "firewall-persist"}
                if command[0] == "systemctl"
                else {"firewall-openrc-start", "firewall-openrc-persist"}
            )
            if not required.issubset(position):
                raise UmzugError("host firewall activation lacks its reviewed persistence path")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict())).hexdigest()

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Plan":
        if not isinstance(value, dict):
            raise UmzugError("invalid plan: root must be an object")
        allowed = {
            "profile",
            "system_fingerprint",
            "actions",
            "created_at",
            "intent",
            "format_version",
            "toolkit_version",
        }
        if set(value) - allowed:
            raise UmzugError("invalid plan: unknown root fields")
        raw_actions = value.get("actions")
        if not isinstance(raw_actions, list) or len(raw_actions) > MAX_ACTIONS:
            raise UmzugError("invalid plan: actions must be a bounded list")
        action_fields = set(Action.__dataclass_fields__)
        actions: list[Action] = []
        try:
            for item in raw_actions:
                if not isinstance(item, dict) or set(item) != action_fields:
                    raise UmzugError("invalid plan: action fields are missing or unknown")
                actions.append(Action(**item))
            plan = cls(
                profile=value["profile"],
                system_fingerprint=value["system_fingerprint"],
                actions=actions,
                created_at=value["created_at"],
                intent=value.get("intent", {}),
                format_version=value.get("format_version", 1),
                toolkit_version=value.get("toolkit_version", "unknown"),
            )
        except (KeyError, TypeError) as exc:
            raise UmzugError(f"invalid plan: {exc}") from exc
        plan.validate()
        return plan
