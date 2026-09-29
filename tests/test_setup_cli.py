from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from umzug.detection import DistributionInfo, FirmwareInfo, NetworkDevice, SystemFacts
from umzug.model import Plan
import umzug.setup_cli as setup_cli
from umzug.restore_trust import (
    prepare_private_restore_staging,
    require_inert_restore_destination,
)
from umzug.setup_cli import (
    _mullvad_state_covered_by_encrypted_root,
    _confirm_plan_digest,
    _build_plan,
    _require_clean_ingest,
    _load_plan,
    _load_scanner_policy,
    _parser,
    _save_plan_for_resume,
)
from umzug.util import UmzugError, terminal_safe


def _plan() -> Plan:
    return Plan(
        profile="test",
        system_fingerprint="fixture-system",
        actions=[],
        created_at="2026-07-15T00:00:00+00:00",
    )


def _state_storage() -> dict[str, object]:
    return {
        "format": 1,
        "filesystem": "ext4",
        "mount_point": "/",
        "mount_root": "/",
        "source": "/dev/mapper/root",
        "identity_sha256": "f" * 64,
        "persistent_local_storage_proven": True,
    }


def _two_ethernet_facts() -> SystemFacts:
    return SystemFacts(
        distribution=DistributionInfo(id="debian", name="Debian GNU/Linux", version_id="13", id_like=("debian",)),
        package_manager="apt",
        package_managers=("apt",),
        init_system="systemd",
        architecture="x86_64",
        kernel="6.12.0",
        firmware=FirmwareInfo(mode="uefi", secure_boot="disabled"),
        machine_identity_sha256="a" * 64,
        network_devices=(
            NetworkDevice(name="ens5", kind="ethernet"),
            NetworkDevice(name="ens6", kind="ethernet"),
        ),
    )


@pytest.mark.parametrize("profile", ["strict", "maximal"])
def test_vpn_killswitch_plan_rejects_partial_physical_ethernet_set(
    profile: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_cli, "_facts", _two_ethernet_facts)
    args = _parser().parse_args(
        [
            "plan",
            "--profile",
            profile,
            "--output",
            str(tmp_path / "plan.json"),
            "--ethernet",
            "ens5",
            "--no-mullvad-app-preparation",
        ]
    )

    with pytest.raises(UmzugError, match="exact complete set"):
        _build_plan(args)


def test_compatible_plan_may_select_physical_ethernet_subset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_cli, "_facts", _two_ethernet_facts)
    args = _parser().parse_args(
        [
            "plan",
            "--profile",
            "compatible",
            "--output",
            str(tmp_path / "plan.json"),
            "--ethernet",
            "ens5",
            "--no-mullvad-app-preparation",
        ]
    )

    plan, report = _build_plan(args)

    assert plan.intent["ethernet_interfaces"] == ["ens5"]
    assert report["ethernet_interfaces"] == ["ens5"]
    setup_cli._verify_plan_target(plan)


def test_apply_rejects_legacy_vpn_plan_bound_to_ethernet_subset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = _two_ethernet_facts()
    monkeypatch.setattr(setup_cli, "_facts", lambda: facts)
    profile = setup_cli.load_profile("strict")
    legacy_plan = setup_cli.build_hardening_plan(
        facts.to_dict(),
        profile=profile,
        ethernet_interfaces=["ens5"],
        radio_modules=[],
    )

    with pytest.raises(UmzugError, match="exactly match all physical"):
        setup_cli._verify_plan_target(legacy_plan)


def test_debian_capabilities_are_non_executable_and_tools_must_preexist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    facts = SystemFacts(
        distribution=DistributionInfo(id="debian", name="Debian GNU/Linux", version_id="13", id_like=("debian",)),
        package_manager="apt",
        package_managers=("apt",),
        init_system="systemd",
        architecture="x86_64",
        kernel="6.12.0",
        firmware=FirmwareInfo(mode="uefi", secure_boot="disabled"),
        machine_identity_sha256="a" * 64,
        network_devices=(NetworkDevice(name="ens5", kind="ethernet"),),
    )
    monkeypatch.setattr(setup_cli, "_facts", lambda: facts)
    args = _parser().parse_args(
        [
            "plan",
            "--profile",
            "strict",
            "--output",
            str(tmp_path / "plan.json"),
            "--ethernet",
            "ens5",
            "--capability",
            "firewall",
            "--capability",
            "radio-control",
            "--no-mullvad-app-preparation",
        ]
    )

    plan, report = _build_plan(args)
    order = [action.id for action in plan.actions]
    preflight_names = [
        str(action.parameters["name"]) for action in plan.actions if action.operation == "check_executable"
    ]

    assert not any(action_id.startswith("packages.") for action_id in order)
    assert "apt-get" not in preflight_names
    assert "dpkg-query" not in preflight_names
    assert {"nft", "rfkill", "unshare"}.issubset(preflight_names)
    checkpoint = "\n".join(report["warnings"])
    assert "NICHT AUSFÜHREN" in checkpoint
    assert "APPROVED" in checkpoint
    assert "SHA-256" in checkpoint
    assert "kein privilegiertes APT-Installationskommando" in checkpoint
    assert [item["name"] for item in report["executable_preflight"]] == preflight_names
    plan.validate()


def test_vendor_install_cannot_disable_preinstall_management_containment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    facts = SystemFacts(
        distribution=DistributionInfo(id="debian", name="Debian GNU/Linux", version_id="13", id_like=("debian",)),
        package_manager="apt",
        package_managers=("apt",),
        init_system="systemd",
        architecture="x86_64",
        kernel="6.12.0",
        firmware=FirmwareInfo(mode="uefi", secure_boot="disabled"),
        machine_identity_sha256="a" * 64,
        network_devices=(NetworkDevice(name="ens5", kind="ethernet"),),
    )
    monkeypatch.setattr(setup_cli, "_facts", lambda: facts)
    args = _parser().parse_args(
        [
            "plan",
            "--output",
            str(tmp_path / "plan.json"),
            "--ethernet",
            "ens5",
            "--mullvad-artifact",
            str(tmp_path / "mullvad.deb"),
            "--mullvad-vendor-receipt",
            str(tmp_path / "receipt.json"),
            "--no-mullvad-app-preparation",
        ]
    )

    with pytest.raises(UmzugError, match="requires management-socket preparation"):
        _build_plan(args)


def test_supplied_apply_digest_must_match() -> None:
    plan = _plan()
    assert _confirm_plan_digest(plan, plan.digest(), dry_run=False) == plan.digest()
    with pytest.raises(UmzugError, match="does not match"):
        _confirm_plan_digest(plan, "0" * 64, dry_run=False)


def test_mullvad_state_requires_unshadowed_encrypted_root_mount() -> None:
    assert _mullvad_state_covered_by_encrypted_root(
        SimpleNamespace(
            root_encrypted=True,
            mounts=(SimpleNamespace(target="/"), SimpleNamespace(target="/home")),
        )
    )
    for target in (
        "/etc",
        "/etc/mullvad-vpn",
        "/etc/mullvad-vpn/account-history.json",
        "/etc/mullvad-vpn/device.json",
    ):
        assert not _mullvad_state_covered_by_encrypted_root(
            SimpleNamespace(
                root_encrypted=True,
                mounts=(SimpleNamespace(target="/"), SimpleNamespace(target=target)),
            )
        )
    assert not _mullvad_state_covered_by_encrypted_root(
        SimpleNamespace(root_encrypted=False, mounts=(SimpleNamespace(target="/"),))
    )


def test_terminal_safe_escapes_controls_but_preserves_unicode() -> None:
    assert terminal_safe("gut ä\x1b[31m\n") == "gut ä\\x1b[31m\\x0a"


def test_root_restore_destination_is_limited_to_inert_staging(
    tmp_path: Path,
) -> None:
    candidate = "item-0000"
    staging_root = tmp_path / "var" / "lib" / "umzug" / "restored-staging"
    expected = staging_root / candidate

    assert (
        require_inert_restore_destination(
            candidate=candidate,
            destination=expected,
            staging_root=staging_root,
        )
        == expected
    )
    prepare_private_restore_staging(expected)
    assert staging_root.stat().st_mode & 0o077 == 0

    for active_path in (Path("/etc/ld.so.preload"), Path.home() / ".bashrc"):
        with pytest.raises(UmzugError, match="dedicated inert staging"):
            require_inert_restore_destination(
                candidate=candidate,
                destination=active_path,
                staging_root=staging_root,
            )


def _write_ingest_state(workspace: Path, **values: object) -> dict[str, object]:
    state: dict[str, object] = {
        "extraction_errors": [],
        "manifest_warnings": [],
        "xattr_failures": [],
        **values,
    }
    state_dir = workspace / "state"
    state_dir.mkdir(parents=True)
    (state_dir / "ingest.json").write_text(json.dumps(state), encoding="utf-8")
    return state


def test_clean_ingest_explicit_safe_mount_taint_false_is_allowed(
    tmp_path: Path,
) -> None:
    expected = _write_ingest_state(tmp_path, unsafe_source_mount_tainted=False)

    assert _require_clean_ingest(tmp_path) == expected


def test_clean_ingest_unsafe_mount_taint_true_is_blocked(tmp_path: Path) -> None:
    _write_ingest_state(tmp_path, unsafe_source_mount_tainted=True)

    with pytest.raises(UmzugError, match="unsafe_source_mount_tainted"):
        _require_clean_ingest(tmp_path)


def test_clean_ingest_missing_mount_taint_is_blocked(tmp_path: Path) -> None:
    _write_ingest_state(tmp_path)

    with pytest.raises(UmzugError, match="unsafe_source_mount_tainted"):
        _require_clean_ingest(tmp_path)


def test_resume_state_binds_digest_before_plan_file_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan = _plan()
    state_dir = tmp_path / "state"

    def crash_before_plan_file(*_args: object, **_kwargs: object) -> None:
        raise UmzugError("simulated crash before plan.json")

    monkeypatch.setattr(setup_cli, "atomic_write", crash_before_plan_file)
    with pytest.raises(UmzugError, match="simulated crash"):
        _save_plan_for_resume(plan, state_dir, state_storage=_state_storage())

    state = json.loads((state_dir / "state.json").read_text(encoding="utf-8"))
    assert state["plan_digest"] == plan.digest()
    assert not (state_dir / "plan.json").exists()
    replacement = Plan(
        profile="test",
        system_fingerprint="different-fixture-system",
        actions=[],
        created_at="2026-07-15T00:00:01+00:00",
    )
    with pytest.raises(UmzugError, match="different plan"):
        _save_plan_for_resume(replacement, state_dir, state_storage=_state_storage())


def test_replaced_resume_plan_cannot_override_bound_state(tmp_path: Path) -> None:
    plan = _plan()
    state_dir = tmp_path / "state"
    saved = _save_plan_for_resume(plan, state_dir, state_storage=_state_storage())
    replacement = Plan(
        profile="test",
        system_fingerprint="different-fixture-system",
        actions=[],
        created_at="2026-07-15T00:00:01+00:00",
    )
    saved.write_bytes(json.dumps(replacement.to_dict()).encode("utf-8"))

    with pytest.raises(UmzugError, match="different plan"):
        _save_plan_for_resume(replacement, state_dir, state_storage=_state_storage())


def test_plan_reader_refuses_symlinks(tmp_path: Path) -> None:
    plan_file = tmp_path / "real.json"
    plan_file.write_text(json.dumps(_plan().to_dict()), encoding="utf-8")
    link = tmp_path / "plan.json"
    link.symlink_to(plan_file)

    with pytest.raises(UmzugError, match="without following links"):
        _load_plan(link)


def test_saved_resume_plan_must_remain_private(tmp_path: Path) -> None:
    saved = _save_plan_for_resume(_plan(), tmp_path / "state", state_storage=_state_storage())
    saved.chmod(0o640)

    with pytest.raises(UmzugError, match="not private"):
        _load_plan(saved, private=True)


@pytest.mark.parametrize(
    "setting",
    [
        "required_external_scanners = []",
        "require_verified_external_material = false",
        "run_external_scanners = false",
        'external_isolation_backend = "none"',
        "block_all_unknown_binary = false",
        "require_secure_source_mount = false",
        "allow_cross_filesystems = true",
        "allow_executable_files_after_review = true",
        "max_archive_expanded_bytes = 2147483648",
    ],
)
def test_migration_scanner_config_cannot_lower_security_floor(tmp_path: Path, setting: str) -> None:
    config = tmp_path / "scanner.toml"
    config.write_text(f"[scanner]\n{setting}\n", encoding="utf-8")

    with pytest.raises(UmzugError, match="may not weaken security floors"):
        _load_scanner_policy(config)
