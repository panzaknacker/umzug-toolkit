from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
import tomllib
from typing import Any, Mapping

from .actions import prepend_executable_preflights
from .model import Plan
from .hardening_policy import (
    BUILTIN_PROFILES,
    _journald,
    _nixos_module,
    _openrc_firewall_start,
    _radio_openrc_start,
    _radio_systemd_unit,
    _sudoers,
    _sysctl,
    hardening_actions,
    validate_profile,
)
from .network import validate_interfaces
from .util import UmzugError, canonical_json


def target_system_fingerprint(facts: Mapping[str, Any]) -> str:
    """bind stable target identity without state changed by apply or reboot.
    
    exclude kernel versions, radio state, operstate, loaded drivers and encryption
    state. WLAN/WWAN may disappear after blacklisting; the plan binds their exact
    radio-module intent separately. physical ethernet and non-radio devices stay bound.
    """

    distribution = facts.get("distribution") if isinstance(facts.get("distribution"), Mapping) else {}
    firmware = facts.get("firmware") if isinstance(facts.get("firmware"), Mapping) else {}
    storage = facts.get("storage") if isinstance(facts.get("storage"), Mapping) else {}

    gpus: list[dict[str, str]] = []
    for item in facts.get("gpus", ()) if isinstance(facts.get("gpus", ()), (list, tuple)) else ():
        if isinstance(item, Mapping):
            gpus.append(
                {
                    "pci_address": str(item.get("pci_address") or ""),
                    "sys_name": str(item.get("sys_name") or ""),
                    "vendor_id": str(item.get("vendor_id") or ""),
                    "device_id": str(item.get("device_id") or ""),
                }
            )
    networks: list[dict[str, str]] = []
    for item in facts.get("network_devices", ()) if isinstance(facts.get("network_devices", ()), (list, tuple)) else ():
        if (
            isinstance(item, Mapping)
            and not bool(item.get("virtual"))
            and str(item.get("kind") or "") not in {"wifi", "cellular"}
        ):
            networks.append(
                {
                    "name": str(item.get("name") or ""),
                    "kind": str(item.get("kind") or ""),
                    "mac_address": str(item.get("mac_address") or "").lower(),
                }
            )
    identity = {
        "format": 1,
        "machine_identity_sha256": str(facts.get("machine_identity_sha256") or ""),
        "distribution": {
            "id": str(distribution.get("id") or ""),
            "version_id": str(distribution.get("version_id") or ""),
        },
        "architecture": str(facts.get("architecture") or ""),
        "firmware_mode": str(firmware.get("mode") or ""),
        "init_system": str(facts.get("init_system") or ""),
        "root_source": str(storage.get("root_source") or ""),
        "root_filesystem": str(storage.get("root_filesystem") or ""),
        "gpus": sorted(gpus, key=lambda value: tuple(value.values())),
        "physical_non_radio_network_devices": sorted(
            networks, key=lambda value: tuple(value.values())
        ),
    }
    return hashlib.sha256(canonical_json(identity)).hexdigest()


def radio_hardware_inventory(facts: Mapping[str, Any]) -> list[dict[str, str]]:
    """canonical pre-apply identity for physical wi-fi/cellular devices."""

    rows: dict[tuple[str, str, str, str], dict[str, str]] = {}
    raw_devices = facts.get("network_devices", ())
    for item in raw_devices if isinstance(raw_devices, (list, tuple)) else ():
        if (
            not isinstance(item, Mapping)
            or bool(item.get("virtual"))
            or str(item.get("kind") or "") not in {"wifi", "cellular"}
        ):
            continue
        row = {
            "name": str(item.get("name") or ""),
            "kind": str(item.get("kind") or ""),
            "mac_address": str(item.get("mac_address") or "").lower(),
            "driver": str(item.get("driver") or "").replace("-", "_"),
        }
        key = (row["name"], row["kind"], row["mac_address"], row["driver"])
        rows[key] = row
    return [rows[key] for key in sorted(rows)]


def load_profile(name: str, profile_file: Path | None = None) -> dict[str, Any]:
    if profile_file:
        try:
            root = tomllib.loads(profile_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise UmzugError(f"invalid hardening profile: {exc}") from exc
        value = root.get("hardening")
        if not isinstance(value, dict):
            raise UmzugError("profile needs a [hardening] table")
        profile = dict(value)
    elif name in BUILTIN_PROFILES:
        profile = {"name": name, **BUILTIN_PROFILES[name]}
    else:
        raise UmzugError(f"unknown hardening profile: {name}")
    return validate_profile(profile)


def build_hardening_plan(
    facts: dict[str, Any],
    *,
    profile: dict[str, Any],
    ethernet_interfaces: list[str],
    radio_modules: list[str] | None = None,
) -> Plan:
    ethernet_interfaces = validate_interfaces(ethernet_interfaces)
    radio_modules = sorted(
        {
            module.replace("-", "_")
            for module in (radio_modules or [])
            if isinstance(module, str) and module
        }
    )
    if any(not module.replace("_", "").isalnum() for module in radio_modules):
        raise UmzugError("invalid radio module in hardening intent")
    profile = validate_profile(profile)
    profile_name = str(profile["name"])
    system_fingerprint = target_system_fingerprint(facts)
    radio_hardware = radio_hardware_inventory(facts)
    distro_id = str(facts.get("distribution", {}).get("id", ""))
    init_system = str(facts.get("init_system", "unknown"))
    distribution_like = sorted(
        {
            str(item).lower()
            for item in facts.get("distribution", {}).get("id_like", ())
            if isinstance(item, str) and item
        }
    )
    package_managers = sorted(
        {
            str(item).lower()
            for item in facts.get("package_managers", ())
            if isinstance(item, str) and item
        }
    )
    actions = prepend_executable_preflights(
        hardening_actions(
            distribution=distro_id,
            init_system=init_system,
            profile=profile,
            ethernet_interfaces=ethernet_interfaces,
            radio_modules=radio_modules,
        )
    )
    plan = Plan(
        profile=profile_name,
        system_fingerprint=system_fingerprint,
        actions=actions,
        created_at=dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        intent={
            "distribution": distro_id or "unknown",
            "distribution_like": distribution_like,
            "init_system": init_system,
            "profile": profile,
            "ethernet_interfaces": ethernet_interfaces,
            "radio_modules": radio_modules,
            "radio_hardware": radio_hardware,
            "package_adapter": "none",
            "package_managers": package_managers,
            "package_requests": [],
            "vendor": None,
            "mullvad_management_group": None,
        },
    )
    plan.validate()
    return plan
