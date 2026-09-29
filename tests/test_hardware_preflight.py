from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

import pytest

import umzug.hardware_preflight as hardware_preflight
import umzug.setup_cli as setup_cli
from umzug.detection import (
    DistributionInfo,
    FirmwareInfo,
    MountInfo,
    NetworkDevice,
    StorageInfo,
    SystemFacts,
)
from umzug.hardening import build_hardening_plan, load_profile
from umzug.util import AuditLog, UmzugError


def _facts(*, interfaces: tuple[str, ...] = ("enp1s0",)) -> SystemFacts:
    return SystemFacts(
        distribution=DistributionInfo(
            id="debian",
            name="Debian GNU/Linux",
            version_id="13",
            id_like=("debian",),
        ),
        package_manager="apt",
        package_managers=("apt",),
        init_system="systemd",
        architecture="x86_64",
        kernel="6.12.0",
        firmware=FirmwareInfo(mode="uefi", secure_boot="enabled"),
        machine_identity_sha256="a" * 64,
        network_devices=tuple(
            NetworkDevice(
                name=name,
                kind="ethernet",
                driver="virtio_net",
                operstate="up",
            )
            for name in interfaces
        ),
        storage=StorageInfo(
            root_source="/dev/mapper/root",
            root_filesystem="ext4",
            root_encrypted=True,
            encryption_types=("LUKS",),
            mounts=(MountInfo("/dev/mapper/root", "/", "ext4", ("rw",)),),
        ),
    )


def _plan(facts: SystemFacts | None = None):
    facts = facts or _facts()
    return build_hardening_plan(
        facts.to_dict(),
        profile=load_profile("compatible"),
        ethernet_interfaces=[device.name for device in facts.network_devices],
        radio_modules=[],
    )


def _patch_passing_observers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hardware_preflight.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        hardware_preflight,
        "observe_productive_runtime",
        lambda: {"runtime": "/opt/umzug/runtime"},
    )
    monkeypatch.setattr(
        hardware_preflight,
        "observe_local_console",
        lambda: {
            "console_proven": True,
            "stdin_tty": True,
            "stdout_tty": True,
            "tty": "/dev/tty2",
            "ssh_environment_markers": [],
            "pseudo_terminal_rejected": False,
        },
    )
    monkeypatch.setattr(
        hardware_preflight,
        "remote_session_evidence",
        lambda: {
            "remote_detected": False,
            "reasons": [],
            "stdin_is_tty": True,
            "stdout_is_tty": True,
            "tty": "/dev/tty2",
            "ancestor_scan_complete": True,
            "ancestors": [],
            "local_console_proven": True,
            "local_console_blockers": [],
        },
    )
    monkeypatch.setattr(
        hardware_preflight,
        "observe_offline_boundary",
        lambda facts, *, proc_root=Path("/proc"), sys_root=Path("/sys"): {
            "status": "pass",
            "summary": "offline",
            "physical_interfaces": [],
            "active_default_routes": [],
            "evidence_errors": [],
            "network_probe_sent": False,
            "network_state_changed": False,
        },
    )
    monkeypatch.setattr(
        hardware_preflight,
        "observe_power",
        lambda _sys=Path("/sys"): {
            "status": "pass",
            "summary": "AC online",
            "supplies": [{"name": "AC", "type": "Mains", "online": True}],
            "stable_power_automatic": True,
        },
    )
    monkeypatch.setattr(
        hardware_preflight,
        "observe_state_path",
        lambda state_dir: {
            "state_dir": str(state_dir),
            "backup_dir": str(state_dir / "backups"),
            "existing_parent": str(state_dir.parent),
            "state_exists": False,
            "state_empty": True,
            "available_bytes": 16 * 1024**3,
            "created_or_modified": False,
        },
    )
    monkeypatch.setattr(
        hardware_preflight,
        "observe_backup_targets",
        lambda _plan: {
            "targets": [{"path": "/etc/example", "type": "file"}],
            "target_count": 1,
            "objects": 1,
            "estimated_bytes": 4096,
            "point_in_time_only": True,
        },
    )
    monkeypatch.setattr(
        hardware_preflight,
        "observe_recovery_medium",
        lambda path, facts, *, required, system_root=Path("/"): {
            "required": required,
            "path": str(path) if path else "/mnt/recovery",
            "separate_mount": True,
            "bootability_automatically_proven": False,
        },
    )
    monkeypatch.setattr(
        hardware_preflight,
        "observe_required_tools",
        lambda _plan: {
            "required_before_first_mutation": ["nft"],
            "observations": [{"name": "nft", "status": "trusted-observation"}],
            "rechecked_by_productive_apply": True,
        },
    )


def test_report_distinguishes_automatic_checks_and_manual_attestations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    facts = _facts()
    plan = _plan(facts)
    _patch_passing_observers(monkeypatch)

    pending = hardware_preflight.build_hardware_preflight_report(
        plan,
        facts,
        plan_digest=plan.digest(),
        state_dir=tmp_path / "state",
        recovery_medium=tmp_path / "recovery",
    )

    assert pending["automated_checks_passed"] is True
    assert pending["status"] == "manual-attestation-required"
    assert all(row["status"] == "required" for row in pending["manual_attestations"])
    assert {
        "full-backup-restore-tested",
        "network-physically-disconnected",
    }.issubset({row["id"] for row in pending["manual_attestations"]})
    assert pending["authorization_to_apply"] is False
    assert pending["separate_open_gates"][0]["id"] == ("scanner-pipeline-private-empty-candidate")

    ready = hardware_preflight.build_hardware_preflight_report(
        plan,
        facts,
        plan_digest=plan.digest(),
        state_dir=tmp_path / "state",
        recovery_medium=tmp_path / "recovery",
        attestations=hardware_preflight.ATTESTATION_IDS,
    )

    assert ready["status"] == "ready"
    assert ready["manual_attestations_complete"] is True
    assert ready["authorization_to_apply"] is False


def test_remote_session_and_toolkit_version_drift_are_automatic_blockers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    facts = _facts()
    plan = _plan(facts)
    plan.toolkit_version = "0.0.0-stale"
    _patch_passing_observers(monkeypatch)
    monkeypatch.setattr(
        hardware_preflight,
        "remote_session_evidence",
        lambda: {
            "remote_detected": True,
            "reasons": ["sshd ancestor"],
            "stdin_is_tty": True,
            "stdout_is_tty": True,
            "tty": "/dev/tty2",
            "ancestor_scan_complete": True,
            "ancestors": [{"pid": 10, "name": "sshd"}],
            "local_console_proven": False,
            "local_console_blockers": ["known remote-session evidence is present"],
        },
    )

    report = hardware_preflight.build_hardware_preflight_report(
        plan,
        facts,
        plan_digest=plan.digest(),
        state_dir=tmp_path / "state",
        recovery_medium=tmp_path / "recovery",
        attestations=hardware_preflight.ATTESTATION_IDS,
    )

    blockers = {check["id"]: check for check in report["automatic_checks"] if check["status"] == "block"}
    assert report["status"] == "blocked"
    assert {"remote-session", "toolkit-version"}.issubset(blockers)
    assert blockers["toolkit-version"]["evidence"]["productive_apply_has_independent_version_equality_gate"] is True


@pytest.mark.parametrize(
    ("profile", "distribution", "init_system"),
    [
        ("strict", "debian", "systemd"),
        ("maximal", "ubuntu", "systemd"),
        ("compatible", "nixos", "systemd"),
        ("compatible", "debian", "openrc"),
    ],
)
def test_hardware_rc_scope_blocks_unreleased_productive_paths(
    profile: str,
    distribution: str,
    init_system: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _facts()
    facts = dataclasses.replace(
        base,
        distribution=dataclasses.replace(base.distribution, id=distribution),
        init_system=init_system,
    )
    plan = build_hardening_plan(
        facts.to_dict(),
        profile=load_profile(profile),
        ethernet_interfaces=["enp1s0"],
        radio_modules=[],
    )
    _patch_passing_observers(monkeypatch)

    report = hardware_preflight.build_hardware_preflight_report(
        plan,
        facts,
        plan_digest=plan.digest(),
        state_dir=tmp_path / "state",
        recovery_medium=tmp_path / "recovery",
        attestations=hardware_preflight.ATTESTATION_IDS,
    )

    scope = next(row for row in report["automatic_checks"] if row["id"] == "hardware-rc-scope")
    assert scope["status"] == "block"
    assert report["status"] == "blocked"


def test_preflight_allows_json_stdout_redirection_with_proven_stdin_console(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    facts = _facts()
    plan = _plan(facts)
    _patch_passing_observers(monkeypatch)
    monkeypatch.setattr(
        hardware_preflight,
        "observe_local_console",
        lambda: {
            "console_proven": True,
            "stdin_tty": True,
            "stdout_tty": False,
            "tty": "/dev/tty2",
            "ssh_environment_markers": [],
            "pseudo_terminal_rejected": False,
            "stdout_tty_required_for_report": False,
            "stdout_tty_required_for_productive_apply": True,
        },
    )
    monkeypatch.setattr(
        hardware_preflight,
        "remote_session_evidence",
        lambda: {
            "remote_detected": False,
            "reasons": [],
            "stdin_is_tty": True,
            "stdout_is_tty": False,
            "tty": "/dev/tty2",
            "ancestor_scan_complete": True,
            "ancestors": [],
            "local_console_proven": False,
            "local_console_blockers": ["stdin and stdout are not both attached to a TTY"],
        },
    )

    report = hardware_preflight.build_hardware_preflight_report(
        plan,
        facts,
        plan_digest=plan.digest(),
        state_dir=tmp_path / "state",
        recovery_medium=tmp_path / "recovery",
        attestations=hardware_preflight.ATTESTATION_IDS,
    )

    assert report["status"] == "ready"
    checks = {row["id"]: row for row in report["automatic_checks"]}
    assert checks["local-console"]["status"] == "pass"
    assert checks["remote-session"]["status"] == "pass"
    assert checks["remote-session"]["evidence"]["stdout_is_tty"] is False


def test_local_console_observation_allows_only_stdout_redirection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hardware_preflight.os, "isatty", lambda fd: fd == 0)
    monkeypatch.setattr(hardware_preflight.os, "ttyname", lambda _fd: "/dev/tty2")

    result = hardware_preflight.observe_local_console(environ={})

    assert result["console_proven"] is True
    assert result["stdin_tty"] is True
    assert result["stdout_tty"] is False
    assert result["stdout_tty_required_for_report"] is False
    assert result["stdout_tty_required_for_productive_apply"] is True


def test_old_plan_version_is_rejected_even_for_apply_dry_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    plan.toolkit_version = "0.1.0"
    monkeypatch.setattr(setup_cli, "_load_plan", lambda _path: plan)
    args = setup_cli._parser().parse_args(["apply", "/tmp/old-plan.json", "--dry-run"])

    with pytest.raises(UmzugError, match="toolkit version does not match"):
        setup_cli.dispatch(args, AuditLog(None))


@pytest.mark.parametrize("invalid", [None, "", "x" * 65, "bad version"])
def test_plan_validation_bounds_toolkit_version(invalid: object) -> None:
    plan = _plan()
    plan.toolkit_version = invalid  # type: ignore[assignment]

    with pytest.raises(UmzugError, match="invalid toolkit version"):
        plan.validate()


def test_state_path_observation_creates_nothing(tmp_path: Path) -> None:
    state_dir = tmp_path / "future" / "state"
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "36 25 253:0 / / rw - ext4 /dev/mapper/root rw\n",
        encoding="utf-8",
    )

    result = hardware_preflight.observe_state_path(
        state_dir,
        owner_uid=os.geteuid(),
        mountinfo_path=mountinfo,
    )

    assert result["created_or_modified"] is False
    assert result["state_exists"] is False
    assert result["persistent_storage"]["filesystem"] == "ext4"
    assert not (tmp_path / "future").exists()


def test_backup_preflight_rejects_special_objects(tmp_path: Path) -> None:
    fifo = tmp_path / "unsafe.fifo"
    os.mkfifo(fifo)
    plan = _plan()
    for action in plan.actions:
        action.backup_paths[:] = []
    target_action = next(action for action in plan.actions if action.operation == "write_file")
    target_action.backup_paths[:] = [str(fifo)]

    with pytest.raises(UmzugError, match="device, FIFO, socket"):
        hardware_preflight.observe_backup_targets(plan)


def test_backup_preflight_rejects_symlink_target_before_any_apply(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.write_text("existing\n", encoding="utf-8")
    link = tmp_path / "managed-link"
    link.symlink_to(real)
    plan = _plan()
    for action in plan.actions:
        action.backup_paths[:] = []
    target_action = next(action for action in plan.actions if action.operation == "write_file")
    target_action.backup_paths[:] = [str(link)]

    with pytest.raises(UmzugError, match="target is a symlink"):
        hardware_preflight.observe_backup_targets(plan)


def test_power_observation_blocks_discharge_and_accepts_online_mains(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sys"
    battery = root / "class" / "power_supply" / "BAT0"
    battery.mkdir(parents=True)
    (battery / "type").write_text("Battery\n", encoding="utf-8")
    (battery / "capacity").write_text("80\n", encoding="utf-8")
    (battery / "status").write_text("Discharging\n", encoding="utf-8")

    assert hardware_preflight.observe_power(root)["status"] == "block"

    mains = root / "class" / "power_supply" / "AC"
    mains.mkdir()
    (mains / "type").write_text("Mains\n", encoding="utf-8")
    (mains / "online").write_text("1\n", encoding="utf-8")

    assert hardware_preflight.observe_power(root)["status"] == "pass"


def test_target_comparison_exposes_exact_ethernet_drift() -> None:
    planned_facts = _facts(interfaces=("enp1s0",))
    plan = build_hardening_plan(
        planned_facts.to_dict(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
        radio_modules=[],
    )
    observed = dataclasses.replace(
        planned_facts,
        network_devices=(NetworkDevice(name="enp2s0", kind="ethernet"),),
    )

    comparison = hardware_preflight.compare_plan_target(plan, observed)

    assert comparison["ethernet"]["policy"] == "exact-all-physical"
    assert comparison["ethernet"]["match"] is False
    assert any("exactly match" in message for message in comparison["blockers"])


def test_radio_disappearance_is_allowed_only_for_post_reboot_target_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ethernet = NetworkDevice(name="enp1s0", kind="ethernet", driver="igc", operstate="down")
    wifi = NetworkDevice(
        name="wlp2s0",
        kind="wifi",
        driver="iwlwifi",
        operstate="down",
        wireless=True,
    )
    planned_facts = dataclasses.replace(_facts(), network_devices=(ethernet, wifi))
    plan = build_hardening_plan(
        planned_facts.to_dict(),
        profile=load_profile("maximal"),
        ethernet_interfaces=["enp1s0"],
        radio_modules=["iwlwifi"],
    )
    after_blacklist = dataclasses.replace(planned_facts, network_devices=(ethernet,))
    monkeypatch.setattr(setup_cli, "_facts", lambda **_kwargs: after_blacklist)

    with pytest.raises(UmzugError, match="radio-module intent differs"):
        setup_cli._verify_plan_target(plan)

    setup_cli._verify_plan_target(plan, allow_missing_radio_drivers_after_reboot=True)


@pytest.mark.parametrize("name", [None, "enp9s0"])
def test_post_reboot_target_check_still_rejects_ethernet_drift(
    name: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ethernet = NetworkDevice(name="enp1s0", kind="ethernet", driver="igc")
    planned_facts = dataclasses.replace(_facts(), network_devices=(ethernet,))
    plan = build_hardening_plan(
        planned_facts.to_dict(),
        profile=load_profile("strict"),
        ethernet_interfaces=["enp1s0"],
        radio_modules=[],
    )
    observed_devices = () if name is None else (NetworkDevice(name=name, kind="ethernet", driver="igc"),)
    observed = dataclasses.replace(planned_facts, network_devices=observed_devices)
    monkeypatch.setattr(setup_cli, "_facts", lambda **_kwargs: observed)

    with pytest.raises(UmzugError, match="fingerprint does not match"):
        setup_cli._verify_plan_target(plan, allow_missing_radio_drivers_after_reboot=True)


def test_same_driver_cannot_hide_replaced_radio_hardware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ethernet = NetworkDevice(name="enp1s0", kind="ethernet", driver="igc")
    original_radio = NetworkDevice(
        name="wlp2s0",
        kind="wifi",
        driver="iwlwifi",
        mac_address="02:00:00:00:00:02",
    )
    planned_facts = dataclasses.replace(_facts(), network_devices=(ethernet, original_radio))
    plan = build_hardening_plan(
        planned_facts.to_dict(),
        profile=load_profile("maximal"),
        ethernet_interfaces=["enp1s0"],
        radio_modules=["iwlwifi"],
    )
    replacement = NetworkDevice(
        name="wlp9s0",
        kind="wifi",
        driver="iwlwifi",
        mac_address="02:00:00:00:00:99",
    )
    observed = dataclasses.replace(planned_facts, network_devices=(ethernet, replacement))
    monkeypatch.setattr(setup_cli, "_facts", lambda **_kwargs: observed)

    with pytest.raises(UmzugError, match="radio-hardware identity differs"):
        setup_cli._verify_plan_target(plan)
    with pytest.raises(UmzugError, match="radio-hardware identity differs"):
        setup_cli._verify_plan_target(plan, allow_missing_radio_drivers_after_reboot=True)


def _offline_evidence_tree(
    tmp_path: Path,
    *,
    carrier: str = "0",
    ipv4_default: bool = False,
) -> tuple[Path, Path]:
    proc_root = tmp_path / "proc"
    net_root = proc_root / "net"
    net_root.mkdir(parents=True)
    route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
    if ipv4_default:
        route += "enp1s0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
    (net_root / "route").write_text(route, encoding="ascii")
    (net_root / "ipv6_route").write_text("", encoding="ascii")
    sys_root = tmp_path / "sys"
    interface = sys_root / "class" / "net" / "enp1s0"
    interface.mkdir(parents=True)
    (interface / "carrier").write_text(carrier + "\n", encoding="ascii")
    return proc_root, sys_root


def test_offline_boundary_blocks_active_carrier(tmp_path: Path) -> None:
    proc_root, sys_root = _offline_evidence_tree(tmp_path, carrier="1")
    facts = dataclasses.replace(
        _facts(),
        network_devices=(NetworkDevice(name="enp1s0", kind="ethernet", operstate="down"),),
    )

    result = hardware_preflight.observe_offline_boundary(facts, proc_root=proc_root, sys_root=sys_root)

    assert result["status"] == "block"
    assert result["physical_interfaces"][0]["carrier"] is True
    assert result["network_probe_sent"] is False


def test_offline_boundary_blocks_default_route_without_carrier(tmp_path: Path) -> None:
    proc_root, sys_root = _offline_evidence_tree(tmp_path, carrier="0", ipv4_default=True)
    facts = dataclasses.replace(
        _facts(),
        network_devices=(NetworkDevice(name="enp1s0", kind="ethernet", operstate="down"),),
    )

    result = hardware_preflight.observe_offline_boundary(facts, proc_root=proc_root, sys_root=sys_root)

    assert result["status"] == "block"
    assert result["active_default_routes"] == [{"family": "ipv4", "interface": "enp1s0", "up": True}]


def test_offline_boundary_blocks_missing_route_and_carrier_evidence(
    tmp_path: Path,
) -> None:
    facts = dataclasses.replace(
        _facts(),
        network_devices=(NetworkDevice(name="enp1s0", kind="ethernet", operstate="unknown"),),
    )

    result = hardware_preflight.observe_offline_boundary(
        facts,
        proc_root=tmp_path / "missing-proc",
        sys_root=tmp_path / "missing-sys",
    )

    assert result["status"] == "block"
    assert len(result["evidence_errors"]) >= 3


def test_dispatch_emits_json_and_exit_three_for_preflight_blockers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    facts = _facts()
    plan = _plan(facts)
    digest = plan.digest()
    args = setup_cli._parser().parse_args(
        [
            "hardware-preflight",
            str(tmp_path / "plan.json"),
            "--expected-plan-sha256",
            digest,
            "--state-dir",
            str(tmp_path / "state"),
            "--json",
        ]
    )
    monkeypatch.setattr(setup_cli, "_load_plan", lambda _path: plan)
    monkeypatch.setattr(
        setup_cli,
        "_confirm_plan_digest",
        lambda loaded, supplied, *, dry_run: digest,
    )
    monkeypatch.setattr(
        setup_cli,
        "_facts",
        lambda *, allow_commands=True: (
            facts if allow_commands is False else pytest.fail("hardware preflight enabled command probes")
        ),
    )
    monkeypatch.setattr(
        setup_cli,
        "build_hardware_preflight_report",
        lambda *args, **kwargs: {
            "status": "blocked",
            "read_only": True,
            "authorization_to_apply": False,
        },
    )

    result = setup_cli.dispatch(args, AuditLog(None))

    assert result == 3
    assert json.loads(capsys.readouterr().out) == {
        "authorization_to_apply": False,
        "read_only": True,
        "status": "blocked",
    }
    assert not (tmp_path / "state").exists()


def test_hardware_preflight_rejects_log_before_auditlog_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(setup_cli, "_require_root_owned_runtime", lambda: None)

    def forbidden_audit(_path: Path | None) -> AuditLog:
        raise AssertionError("read-only preflight constructed AuditLog")

    monkeypatch.setattr(setup_cli, "AuditLog", forbidden_audit)
    result = setup_cli.main(
        [
            "--log",
            str(tmp_path / "must-not-exist" / "audit.jsonl"),
            "hardware-preflight",
            str(tmp_path / "plan.json"),
            "--expected-plan-sha256",
            "a" * 64,
            "--json",
        ]
    )

    assert result == 2
    assert json.loads(capsys.readouterr().out)["status"] == "error"
    assert not (tmp_path / "must-not-exist").exists()


@pytest.mark.parametrize("command", ["resume", "vpn-finalize"])
def test_old_plan_version_blocks_resume_and_vpn_before_execution(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    plan.toolkit_version = "0.1.0"
    monkeypatch.setattr(setup_cli, "require_proven_local_console", lambda _label: {})
    if command == "resume":
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "plan.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr(setup_cli, "_load_plan", lambda *args, **kwargs: plan)
        monkeypatch.setattr(
            setup_cli,
            "_require_saved_state_storage_binding",
            lambda _path: {"identity_sha256": "f" * 64},
        )
        args = setup_cli._parser().parse_args(["resume", "--state-dir", str(state_dir)])
    else:
        monkeypatch.setattr(
            setup_cli,
            "require_completed_plan_context",
            lambda *_args, **_kwargs: {"plan": plan},
        )
        args = setup_cli._parser().parse_args(["vpn-finalize", "--expected-plan-sha256", "a" * 64])

    with pytest.raises(UmzugError, match="toolkit version does not match"):
        setup_cli.dispatch(args, AuditLog(None))


def test_productive_apply_checks_offline_boundary_before_state_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    args = setup_cli._parser().parse_args(
        [
            "apply",
            "/tmp/plan.json",
            "--expected-plan-sha256",
            plan.digest(),
        ]
    )
    monkeypatch.setattr(setup_cli, "_load_plan", lambda _path: plan)
    monkeypatch.setattr(setup_cli, "_confirm_plan_digest", lambda *args, **kwargs: plan.digest())
    monkeypatch.setattr(setup_cli, "require_proven_local_console", lambda _label: {})
    monkeypatch.setattr(setup_cli, "_verify_plan_target", lambda _plan: None)
    monkeypatch.setattr(setup_cli, "_verify_plan_vendor_intent", lambda _plan: None)
    monkeypatch.setattr(
        setup_cli,
        "_require_offline_boundary",
        lambda: (_ for _ in ()).throw(UmzugError("active default route")),
    )
    monkeypatch.setattr(
        setup_cli,
        "_save_plan_for_resume",
        lambda *_args, **_kwargs: pytest.fail("state was written before offline gate"),
    )

    with pytest.raises(UmzugError, match="active default route"):
        setup_cli.dispatch(args, AuditLog(None))


def test_apply_dry_run_does_not_require_offline_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _plan()
    args = setup_cli._parser().parse_args(["apply", "/tmp/plan.json", "--dry-run"])
    monkeypatch.setattr(setup_cli, "_load_plan", lambda _path: plan)
    monkeypatch.setattr(setup_cli, "_confirm_plan_digest", lambda *args, **kwargs: plan.digest())
    monkeypatch.setattr(setup_cli, "_verify_plan_target", lambda _plan: None)
    monkeypatch.setattr(setup_cli, "_verify_plan_vendor_intent", lambda _plan: None)
    monkeypatch.setattr(
        setup_cli,
        "_require_offline_boundary",
        lambda: pytest.fail("dry-run invoked productive offline gate"),
    )

    class FakeExecutor:
        def __init__(self, **_kwargs: object):
            pass

        def apply(self, _plan: object) -> dict[str, object]:
            return {"format": 1, "completed": []}

    monkeypatch.setattr(setup_cli, "Executor", FakeExecutor)

    assert setup_cli.dispatch(args, AuditLog(None)) == 0


@pytest.mark.parametrize(
    ("command", "argv", "guard_label"),
    [
        (
            "apply",
            ["apply", "/tmp/plan.json", "--expected-plan-sha256", "a" * 64],
            "productive apply",
        ),
        ("resume", ["resume"], "resume"),
        (
            "vpn-finalize",
            ["vpn-finalize", "--expected-plan-sha256", "a" * 64],
            "vpn-finalize",
        ),
    ],
)
def test_productive_entrypoints_apply_remote_guard_before_mutation(
    command: str,
    argv: list[str],
    guard_label: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if command == "apply":
        plan = _plan()
        monkeypatch.setattr(setup_cli, "_load_plan", lambda _path: plan)
        monkeypatch.setattr(
            setup_cli,
            "_confirm_plan_digest",
            lambda *args, **kwargs: plan.digest(),
        )

    def blocked(label: str) -> None:
        assert label == guard_label
        raise UmzugError("known remote session")

    monkeypatch.setattr(setup_cli, "require_proven_local_console", blocked)
    args = setup_cli._parser().parse_args(argv)

    with pytest.raises(UmzugError, match="known remote"):
        setup_cli.dispatch(args, AuditLog(None))
