from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from umzug.hardening import build_hardening_plan, load_profile, target_system_fingerprint
from umzug.adapters import DebianAdapter, NixOSAdapter
from umzug.model import (
    Action,
    Plan,
    preflight_action_id,
    prepend_executable_preflights,
)
from umzug.package_actions import (
    mullvad_install_action,
    mullvad_management_actions,
    package_actions,
)
from umzug.util import UmzugError


def _facts() -> dict:
    return {
        "distribution": {"id": "debian", "version_id": "13"},
        "architecture": "x86_64",
        "kernel": "6.12.1",
        "init_system": "systemd",
        "machine_identity_sha256": "a" * 64,
        "firmware": {"mode": "uefi", "secure_boot": "enabled"},
        "storage": {"root_source": "/dev/mapper/root", "root_filesystem": "ext4", "root_encrypted": True},
        "gpus": [
            {
                "sys_name": "card0",
                "pci_address": "0000:00:02.0",
                "vendor_id": "0x8086",
                "device_id": "0x1234",
                "driver": "i915",
            }
        ],
        "network_devices": [
            {
                "name": "enp1s0",
                "kind": "ethernet",
                "mac_address": "02:00:00:00:00:01",
                "operstate": "up",
                "driver": "igc",
                "virtual": False,
            }
        ],
        "warnings": [],
    }


def test_target_fingerprint_survives_expected_runtime_changes() -> None:
    first = _facts()
    second = _facts()
    second["kernel"] = "6.12.2"
    second["firmware"]["secure_boot"] = "disabled"
    second["storage"]["root_encrypted"] = False
    second["gpus"][0]["driver"] = "xe"
    second["network_devices"][0]["operstate"] = "down"
    second["warnings"] = ["changed"]
    assert target_system_fingerprint(first) == target_system_fingerprint(second)


def test_target_fingerprint_changes_for_other_machine() -> None:
    first = _facts()
    second = _facts()
    second["machine_identity_sha256"] = "b" * 64
    assert target_system_fingerprint(first) != target_system_fingerprint(second)


def test_target_fingerprint_allows_reviewed_radio_devices_to_disappear() -> None:
    with_radios = _facts()
    with_radios["network_devices"].extend(
        [
            {
                "name": "wlp2s0",
                "kind": "wifi",
                "mac_address": "02:00:00:00:00:02",
                "driver": "iwlwifi",
                "virtual": False,
            },
            {
                "name": "wwan0",
                "kind": "cellular",
                "mac_address": "02:00:00:00:00:03",
                "driver": "cdc_mbim",
                "virtual": False,
            },
        ]
    )
    without_radios = _facts()

    assert target_system_fingerprint(with_radios) == target_system_fingerprint(without_radios)


@pytest.mark.parametrize(
    "replacement",
    [[], [{"name": "enp9s0", "kind": "ethernet", "virtual": False}]],
)
def test_target_fingerprint_still_binds_physical_ethernet(
    replacement: list[dict[str, object]],
) -> None:
    first = _facts()
    second = _facts()
    second["network_devices"] = replacement

    assert target_system_fingerprint(first) != target_system_fingerprint(second)


def test_recovery_is_installed_before_firewall_activation() -> None:
    plan = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    order = [action.id for action in plan.actions]
    assert order.index("network-recovery-command") < order.index("firewall-enable")


def test_hardening_plan_has_exact_canonical_executable_preflight_prefix() -> None:
    plan = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    names = [str(action.parameters["name"]) for action in plan.actions if action.operation == "check_executable"]

    assert names == sorted(names)
    assert set(names) == {
        "nft",
        "rfkill",
        "sysctl",
        "systemctl",
        "unshare",
        "update-initramfs",
    }
    assert all(action.operation == "check_executable" for action in plan.actions[: len(names)])
    plan.validate()


def _preflight(name: str) -> Action:
    return Action(
        id=preflight_action_id(name),
        phase="preflight",
        summary=f"check {name}",
        rationale="test exact executable prefix validation",
        risk="low",
        operation="check_executable",
        parameters={"name": name},
        verify={"kind": "executable_available", "name": name},
    )


def _mullvad_vendor_plan() -> Plan:
    hardening = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    hardening_body = [action for action in hardening.actions if action.operation != "check_executable"]
    network_gates = [
        action
        for action in hardening_body
        if action.phase in {"recovery", "bootstrap-security"}
        or (action.phase == "network" and not action.id.startswith("radio-"))
    ]
    containment = [action for action in hardening_body if action.phase == "services" or action.id.startswith("radio-")]
    deferred = [action for action in hardening_body if action not in network_gates and action not in containment]
    group = "mullvad-management"
    artifact = "/workspace/APPROVED/mullvad/mullvad.deb"
    vendor = {
        "kind": "mullvad-openpgp-v4",
        "workspace": "/workspace",
        "candidate": "mullvad",
        "artifact": artifact,
        "receipt": "/workspace/state/vendor/mullvad.json",
        "artifact_sha256": "1" * 64,
        "fingerprint": "A" * 40,
        "gpg_sha256": "2" * 64,
        "gpgv_sha256": "3" * 64,
        "bwrap_sha256": "4" * 64,
        "receipt_sha256": "5" * 64,
        "package_version": "2026.1",
        "package_architecture": "amd64",
    }
    install = mullvad_install_action(
        distribution="debian",
        package_adapter="debian",
        artifact=artifact,
        artifact_sha256=vendor["artifact_sha256"],
        package_version=vendor["package_version"],
        package_architecture=vendor["package_architecture"],
        management_group=group,
    )
    return dataclasses.replace(
        hardening,
        actions=prepend_executable_preflights(
            [
                *network_gates,
                *containment,
                *mullvad_management_actions(group),
                install,
                *deferred,
            ]
        ),
        intent={
            **hardening.intent,
            "package_adapter": "debian",
            "vendor": vendor,
            "mullvad_management_group": group,
        },
    )


def test_vendor_plan_prepares_management_before_atomic_install_and_live_check() -> None:
    plan = _mullvad_vendor_plan()
    plan.validate()
    order = [action.id for action in plan.actions]
    assert (
        order.index("mullvad-management-group")
        < order.index("mullvad-management-socket")
        < order.index("mullvad-offline-install")
    )
    group = next(action for action in plan.actions if action.id == "mullvad-management-group")
    install = next(action for action in plan.actions if action.id == "mullvad-offline-install")
    assert group.verify == {
        "kind": "restricted_group",
        "name": "mullvad-management",
    }
    assert install.parameters["post_install_argvs"] == [
        ["systemctl", "daemon-reload"],
        ["systemctl", "restart", "mullvad-daemon.service"],
    ]
    assert install.verify["management_group"] == "mullvad-management"


@pytest.mark.parametrize("tamper", ["reorder", "remove-reload", "change-group"])
def test_vendor_plan_rejects_management_activation_tampering(tamper: str) -> None:
    plan = _mullvad_vendor_plan()
    actions = list(plan.actions)
    install_index = next(index for index, action in enumerate(actions) if action.id == "mullvad-offline-install")
    if tamper == "reorder":
        socket_index = next(index for index, action in enumerate(actions) if action.id == "mullvad-management-socket")
        actions[install_index], actions[socket_index] = (
            actions[socket_index],
            actions[install_index],
        )
    elif tamper == "remove-reload":
        parameters = dict(actions[install_index].parameters)
        parameters["post_install_argvs"] = [["systemctl", "restart", "mullvad-daemon.service"]]
        actions[install_index] = dataclasses.replace(actions[install_index], parameters=parameters)
    else:
        verify = dict(actions[install_index].verify)
        verify["management_group"] = "wheel"
        actions[install_index] = dataclasses.replace(actions[install_index], verify=verify)

    with pytest.raises(UmzugError):
        dataclasses.replace(plan, actions=actions).validate()


@pytest.mark.parametrize("tamper", ["missing", "extra", "late", "unsorted"])
def test_hardening_plan_rejects_tampered_executable_preflight_prefix(tamper: str) -> None:
    original = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    actions = list(original.actions)
    prefix_length = len([action for action in actions if action.operation == "check_executable"])
    if tamper == "missing":
        actions.pop(0)
    elif tamper == "extra":
        actions.insert(0, _preflight("dnf"))
    elif tamper == "late":
        actions.insert(prefix_length + 1, actions.pop(0))
    else:
        actions[0], actions[1] = actions[1], actions[0]

    with pytest.raises(UmzugError, match="preflight"):
        dataclasses.replace(original, actions=actions).validate()


@pytest.mark.parametrize("removed", ["sudo-policy", "firewall-enable", "all"])
def test_productive_plan_cannot_delete_mandatory_hardening_actions(removed: str) -> None:
    original = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    body = [action for action in original.actions if action.operation != "check_executable"]
    body = [] if removed == "all" else [action for action in body if action.id != removed]
    actions = prepend_executable_preflights(body)

    with pytest.raises(UmzugError, match="hardening actions differ"):
        dataclasses.replace(original, actions=actions).validate()


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("hardening-sysctl", "hardening-sysctl-apply"),
        ("hardening-module-policy", "hardening-initramfs-rebuild"),
        ("offline-guard-unit", "offline-guard-persist"),
        ("radio-systemd-unit", "radio-systemd-enable"),
    ],
)
def test_productive_plan_rejects_reordered_apply_dependencies(before: str, after: str) -> None:
    original = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    actions = list(original.actions)
    left = next(index for index, action in enumerate(actions) if action.id == before)
    right = next(index for index, action in enumerate(actions) if action.id == after)
    actions[left], actions[right] = actions[right], actions[left]

    with pytest.raises(UmzugError, match="complete regenerated intent"):
        dataclasses.replace(original, actions=actions).validate()


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("offline-guard-activate", "offline-guard-persistence-checkpoint"),
        ("firewall-syntax", "firewall-init-manual-checkpoint"),
    ],
)
def test_lfs_best_effort_plan_rejects_attestation_before_effective_step(before: str, after: str) -> None:
    facts = _facts()
    facts["distribution"]["id"] = "lfs"
    facts["init_system"] = "unknown"
    original = build_hardening_plan(
        facts,
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    actions = list(original.actions)
    left = next(index for index, action in enumerate(actions) if action.id == before)
    right = next(index for index, action in enumerate(actions) if action.id == after)
    actions[left], actions[right] = actions[right], actions[left]

    with pytest.raises(UmzugError, match="complete regenerated intent"):
        dataclasses.replace(original, actions=actions).validate()


def test_debian_plan_rejects_foreign_nixos_package_action() -> None:
    original = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    body = [action for action in original.actions if action.operation != "check_executable"]
    foreign = package_actions(NixOSAdapter().plan_packages(["firewall"], offline=True))

    with pytest.raises(UmzugError, match="package actions differ"):
        dataclasses.replace(
            original,
            actions=prepend_executable_preflights([*body, *foreign]),
        ).validate()


def test_debian_offline_intent_rejects_injected_cache_install_action() -> None:
    original = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    body = [action for action in original.actions if action.operation != "check_executable"]
    online = DebianAdapter().plan_packages(["firewall"], offline=False).commands[0]
    injected = Action(
        id=online.action_id,
        phase="packages",
        summary="Syntaktisch gültige, aber nicht freigegebene Cache-Installation",
        rationale="Der Test bildet eine eingeschleuste Altplan-Aktion ab.",
        risk="high",
        operation="run_command",
        parameters={
            "argv": [
                "apt-get",
                "install",
                "--yes",
                "--no-install-recommends",
                "--no-download",
                "--",
                "nftables",
            ],
            "network_policy": "forbidden",
            "timeout": 3600,
        },
        verify={
            "kind": "package_status",
            "manager": "dpkg",
            "packages": ["nftables"],
        },
        requires_confirmation=True,
        destructive=True,
    )

    with pytest.raises(UmzugError, match="package actions differ"):
        dataclasses.replace(
            original,
            actions=prepend_executable_preflights([*body, injected]),
            intent={
                **original.intent,
                "package_adapter": "debian",
                "package_requests": ["firewall"],
            },
        ).validate()


def test_nixos_package_module_is_intent_bound_and_follows_test_generation() -> None:
    facts = _facts()
    facts["distribution"]["id"] = "nixos"
    hardening = build_hardening_plan(
        facts,
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    body = [action for action in hardening.actions if action.operation != "check_executable"]
    package = package_actions(NixOSAdapter().plan_packages(["firewall"], offline=True))
    plan = dataclasses.replace(
        hardening,
        actions=prepend_executable_preflights([*body, *package]),
        intent={
            **hardening.intent,
            "package_adapter": "nixos",
            "package_requests": ["firewall"],
        },
    )
    plan.validate()
    actions = list(plan.actions)
    package_index = next(index for index, action in enumerate(actions) if action.id.startswith("package-file-"))
    checkpoint_index = next(
        index for index, action in enumerate(actions) if action.id == "nixos-import-rebuild-checkpoint"
    )
    actions[package_index], actions[checkpoint_index] = (
        actions[checkpoint_index],
        actions[package_index],
    )

    with pytest.raises(UmzugError, match="complete regenerated intent"):
        dataclasses.replace(plan, actions=actions).validate()


def test_initramfs_block_cannot_move_before_network_and_containment_gates() -> None:
    original = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    preflights = [action for action in original.actions if action.operation == "check_executable"]
    body = [action for action in original.actions if action.operation != "check_executable"]
    moved = [action for action in body if action.id in {"hardening-module-policy", "hardening-initramfs-rebuild"}]
    remainder = [action for action in body if action not in moved]

    with pytest.raises(UmzugError, match="complete regenerated intent"):
        dataclasses.replace(
            original,
            actions=[*preflights, *moved, *remainder],
        ).validate()


def test_initramfs_rebuild_is_always_network_namespaced() -> None:
    plan = build_hardening_plan(
        _facts(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    action = next(item for item in plan.actions if item.id == "hardening-initramfs-rebuild")
    assert action.parameters["network_policy"] == "forbidden"
    assert any(
        item.parameters.get("name") == "unshare" for item in plan.actions if item.operation == "check_executable"
    )


@pytest.mark.parametrize("profile_name", ["strict", "maximal"])
def test_vpn_profiles_disable_global_core_dump_persistence(profile_name: str) -> None:
    plan = build_hardening_plan(
        _facts(),
        profile=load_profile(profile_name),
        ethernet_interfaces=["enp1s0"],
    )
    action = next(item for item in plan.actions if item.id == "hardening-sysctl")
    content = str(action.parameters["content"])

    assert "fs.suid_dumpable = 0\n" in content
    assert "kernel.core_pattern =\n" in content
    assert "kernel.core_uses_pid = 0\n" in content
    assert "kernel.core_uses_pid = 1" not in content


def test_nixos_plan_writes_generation_recovery_before_module() -> None:
    facts = _facts()
    facts["distribution"]["id"] = "nixos"
    plan = build_hardening_plan(
        facts,
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
    )
    body = [action for action in plan.actions if action.operation != "check_executable"]
    assert [action.id for action in body][:2] == [
        "nixos-local-recovery",
        "nixos-hardening-module",
    ]
    assert plan.actions[0].id == "preflight-executable-nixos-rebuild"
    recovery = str(body[0].parameters["content"])
    assert "PATH=/run/current-system/sw/bin:/usr/sbin:/usr/bin:/sbin:/bin" in recovery
    assert "exec /run/current-system/sw/bin/nixos-rebuild switch --rollback" in recovery
    module = str(body[1].parameters["content"])
    assert '"kernel.core_pattern" = "";' in module
    assert '"kernel.core_uses_pid" = 0;' in module
    assert '"kernel.core_pattern" = ;' not in module


def test_profile_rejects_unknown_security_switches(tmp_path: Path) -> None:
    profile = tmp_path / "profile.toml"
    profile.write_text(
        """[hardening]
name = "strict"
disable_ipv6 = true
disable_radios = true
blacklist_radio_modules = false
firewall = true
vpn_killswitch = true
sudo_timestamp_minutes = 0
apparmor_or_selinux = "pretend-enforced"
""",
        encoding="utf-8",
    )
    with pytest.raises(UmzugError, match="unknown hardening profile fields"):
        load_profile("strict", profile)


@pytest.mark.parametrize(
    "weakened",
    [
        "disable_ipv6 = false",
        "disable_radios = false",
        "vpn_killswitch = false",
        "sudo_timestamp_minutes = 5",
    ],
)
def test_strict_profile_cannot_weaken_its_named_security_floor(tmp_path: Path, weakened: str) -> None:
    values = {
        "disable_ipv6": "true",
        "disable_radios": "true",
        "vpn_killswitch": "true",
        "sudo_timestamp_minutes": "0",
    }
    key, value = weakened.split(" = ", 1)
    values[key] = value
    profile = tmp_path / "profile.toml"
    profile.write_text(
        "[hardening]\n"
        'name = "strict"\n'
        f"disable_ipv6 = {values['disable_ipv6']}\n"
        f"disable_radios = {values['disable_radios']}\n"
        "blacklist_radio_modules = false\n"
        "firewall = true\n"
        f"vpn_killswitch = {values['vpn_killswitch']}\n"
        f"sudo_timestamp_minutes = {values['sudo_timestamp_minutes']}\n",
        encoding="utf-8",
    )

    with pytest.raises(UmzugError, match="mandatory security floor"):
        load_profile("strict", profile)


def test_profile_cannot_disable_mandatory_ingress_firewall(tmp_path: Path) -> None:
    profile = tmp_path / "profile.toml"
    profile.write_text(
        """[hardening]
name = "compatible"
disable_ipv6 = false
disable_radios = false
blacklist_radio_modules = false
firewall = false
vpn_killswitch = false
sudo_timestamp_minutes = 5
""",
        encoding="utf-8",
    )
    with pytest.raises(UmzugError, match="require the no-inbound-service firewall"):
        load_profile("compatible", profile)
