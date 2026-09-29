from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

import umzug.executor as executor_module
import umzug.vpn as vpn_module
from umzug.executor import Executor, StateStore, rollback
from umzug.hardening import _radio_systemd_unit
from umzug.model import Action, Plan, prepend_executable_preflights
from umzug.package_actions import mullvad_install_action
from umzug.util import UmzugError
from umzug.vpn import management_override


BOOT_BEFORE = "11111111-1111-4111-8111-111111111111"
BOOT_AFTER = "22222222-2222-4222-8222-222222222222"


def _action(
    action_id: str,
    *,
    operation: str = "write_file",
    parameters: dict[str, object] | None = None,
    backup_paths: list[str] | None = None,
    verify: dict[str, object] | None = None,
    reboot_reason: str | None = None,
    post_reboot_verify: dict[str, object] | None = None,
    risk: str = "low",
    requires_confirmation: bool = False,
    destructive: bool = False,
) -> Action:
    return Action(
        id=action_id,
        phase="test",
        summary=f"apply {action_id}",
        rationale="exercise the transactional executor",
        risk=risk,
        operation=operation,
        parameters=parameters or {},
        backup_paths=backup_paths or [],
        verify=verify or {},
        reboot_reason=reboot_reason,
        post_reboot_verify=post_reboot_verify or {},
        requires_confirmation=requires_confirmation,
        destructive=destructive,
    )


def _plan(*actions: Action, profile: str = "test") -> Plan:
    return Plan(
        profile=profile,
        system_fingerprint="fixture-system",
        actions=list(actions),
        created_at="2026-07-15T00:00:00Z",
    )


def _mullvad_test_preparation(
    group: str = "mullvad-management",
) -> list[Action]:
    override = "/etc/systemd/system/mullvad-daemon.service.d/90-umzug-security.conf"
    return [
        _action(
            "mullvad-management-group",
            operation="ensure_group",
            parameters={"name": group},
            verify={"kind": "restricted_group", "name": group},
            risk="medium",
            requires_confirmation=True,
            destructive=True,
        ),
        _action(
            "mullvad-management-socket",
            parameters={
                "path": override,
                "content": management_override(group),
                "mode": 0o644,
            },
            backup_paths=[override],
        ),
    ]


def _fixed_command_plan() -> Plan:
    command = Action(
        id="offline-guard-syntax",
        phase="hardening",
        summary="check nftables fixture",
        rationale="exercise fail-before-mutation executable preflight",
        risk="low",
        operation="run_command",
        parameters={"argv": ["nft", "--check", "--file", "/etc/umzug/offline-guard.nft"]},
    )
    return Plan(
        profile="test",
        system_fingerprint="fixture-system",
        actions=prepend_executable_preflights([command]),
        created_at="2026-07-15T00:00:00Z",
    )


def test_missing_executable_stops_productive_apply_before_system_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _fixed_command_plan()
    system_root = tmp_path / "system"
    system_root.mkdir()

    def unavailable(_name: str) -> Path:
        raise UmzugError("required executable is unavailable before mutation")

    def command_must_not_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a command ran after a failed leading preflight")

    monkeypatch.setattr(executor_module, "_trusted_executable", unavailable)
    monkeypatch.setattr(executor_module, "run", command_must_not_run)
    with pytest.raises(UmzugError, match="before mutation"):
        Executor(
            state_root=tmp_path / "state",
            system_root=system_root,
            approvals=set(),
        ).apply(plan)

    assert list(system_root.iterdir()) == []
    state = json.loads((tmp_path / "state" / "state.json").read_text(encoding="utf-8"))
    assert state["completed"] == []


def test_missing_executable_is_explicit_but_non_mutating_in_dry_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan = _fixed_command_plan()
    system_root = tmp_path / "system"
    system_root.mkdir()

    def unavailable(_name: str) -> Path:
        raise UmzugError("required executable is unavailable before mutation")

    monkeypatch.setattr(executor_module, "_trusted_executable", unavailable)
    state = Executor(
        state_root=tmp_path / "state",
        system_root=system_root,
        dry_run=True,
        assume_yes=True,
        approvals=set(),
    ).apply(plan)

    assert "MISSING/UNSAFE; productive apply will stop before mutation" in capsys.readouterr().out
    assert state["completed"] == []
    assert state["dry_run_actions"] == [
        "preflight-executable-nft",
        "offline-guard-syntax",
    ]
    assert list(system_root.iterdir()) == []


def test_executable_receipt_rejects_tool_change_after_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "nft"
    executable.write_bytes(b"first trusted bytes")
    executor = Executor(
        state_root=tmp_path / "state",
        system_root=tmp_path / "system",
        assume_yes=True,
    )
    state = executor.store.load()
    monkeypatch.setattr(executor_module, "_trusted_executable", lambda _name: executable)

    assert executor._bound_executable("nft", state, allow_initial_bind=True) == executable
    executable.write_bytes(b"different bytes")
    with pytest.raises(UmzugError, match="changed after its bound preflight"):
        executor._bound_executable("nft", state)


def test_resume_rejects_missing_receipt_for_completed_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "nft"
    executable.write_bytes(b"trusted nft fixture")
    plan = _fixed_command_plan()
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"
    monkeypatch.setattr(executor_module, "_trusted_executable", lambda _name: executable)
    monkeypatch.setattr(
        executor_module,
        "run",
        lambda argv, **kwargs: type("Result", (), {"returncode": 0, "stdout": b"", "stderr": b""})(),
    )
    executor = Executor(
        state_root=state_root,
        system_root=system_root,
        assume_yes=True,
        approvals=set(),
    )
    executor.apply(plan)
    state_path = state_root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    del state["executables"]["nft"]
    state_path.write_text(json.dumps(state), encoding="utf-8")
    state_path.chmod(0o600)

    with pytest.raises(UmzugError, match="no completed bound preflight"):
        executor.apply(plan)


def test_resume_completed_actions_must_be_exact_plan_prefix(tmp_path: Path) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    first = _action(
        "first",
        parameters={"path": "/etc/first", "content": "first\n"},
    )
    second = _action(
        "second",
        parameters={"path": "/etc/second", "content": "second\n"},
    )
    plan = _plan(first, second)
    store = StateStore(tmp_path / "state")
    state = store.load()
    state.update(
        {
            "plan_digest": plan.digest(),
            "profile": plan.profile,
            "completed": [second.id],
        }
    )
    store.save(state)

    with pytest.raises(UmzugError, match="exact leading plan prefix"):
        Executor(
            state_root=tmp_path / "state",
            system_root=system_root,
            assume_yes=True,
        ).apply(plan)
    assert list(system_root.iterdir()) == []


def test_backup_tree_is_recursively_fsynced_before_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    nested = source / "nested"
    nested.mkdir(parents=True)
    (source / "top.txt").write_text("top\n", encoding="utf-8")
    (nested / "child.txt").write_text("child\n", encoding="utf-8")
    (nested / "link").symlink_to("child.txt")
    store = StateStore(tmp_path / "state")
    state = store.load()
    synced_types: list[int] = []
    real_fsync = executor_module.os.fsync

    def recording_fsync(fd: int) -> None:
        synced_types.append(stat.S_IFMT(executor_module.os.fstat(fd).st_mode))
        real_fsync(fd)

    saved_after_sync: list[list[int]] = []
    monkeypatch.setattr(executor_module.os, "fsync", recording_fsync)
    monkeypatch.setattr(
        store,
        "save",
        lambda _state: saved_after_sync.append(list(synced_types)),
    )

    store.backup(source, state)

    assert saved_after_sync
    before_receipt = saved_after_sync[0]
    assert before_receipt.count(stat.S_IFREG) >= 2
    assert before_receipt.count(stat.S_IFDIR) >= 3
    receipt = state["backups"][str(source)]
    assert receipt["existed"] is True
    assert isinstance(receipt["sha256"], str) and len(receipt["sha256"]) == 64


def test_backup_fsync_failure_publishes_no_success_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.conf"
    source.write_text("critical\n", encoding="utf-8")
    store = StateStore(tmp_path / "state")
    state = store.load()
    monkeypatch.setattr(
        executor_module.os,
        "fsync",
        lambda _fd: (_ for _ in ()).throw(OSError("simulated disk failure")),
    )

    with pytest.raises(UmzugError, match="backup durability sync failed"):
        store.backup(source, state)

    assert str(source) not in state["backups"]
    assert not store.path.exists()
    backup = store.backups / hashlib.sha256(str(source).encode()).hexdigest()
    assert backup.read_text(encoding="utf-8") == "critical\n"
    source.write_text("changed after failed fsync\n", encoding="utf-8")
    monkeypatch.undo()
    with pytest.raises(UmzugError, match="without overwrite"):
        store.backup(source, state)
    assert backup.read_text(encoding="utf-8") == "critical\n"


def test_reboot_checkpoint_reverifies_service_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = tmp_path / "systemctl"
    executable.write_bytes(b"trusted systemctl fixture")
    enabled_checks = {"count": 0}

    def fake_run(argv: list[str], **kwargs: object) -> object:
        returncode = 0
        if len(argv) > 1 and argv[1] == "is-enabled":
            enabled_checks["count"] += 1
            if enabled_checks["count"] > 1:
                returncode = 1
        return type(
            "Result",
            (),
            {"returncode": returncode, "stdout": b"", "stderr": b""},
        )()

    monkeypatch.setattr(executor_module, "_trusted_executable", lambda _name: executable)
    monkeypatch.setattr(executor_module, "run", fake_run)
    unit = _action(
        "radio-systemd-unit",
        parameters={
            "path": "/etc/systemd/system/umzug-radio-off.service",
            "content": _radio_systemd_unit(),
            "mode": 0o644,
        },
    )
    service = Action(
        id="radio-systemd-enable",
        phase="bootstrap-security",
        summary="persist guard",
        rationale="test persistence re-verification",
        risk="high",
        operation="enable_service",
        parameters={"name": "umzug-radio-off.service", "init": "systemd"},
        verify={
            "kind": "service_enabled",
            "name": "umzug-radio-off.service",
            "init": "systemd",
        },
        requires_confirmation=True,
        destructive=True,
    )
    reboot = _action(
        "reboot-boundary",
        parameters={"path": "/etc/reboot-boundary", "content": "changed\n"},
        reboot_reason="verify persistence before reboot",
        post_reboot_verify={"kind": "boot_id_changed"},
    )
    plan = _plan(*prepend_executable_preflights([unit, service, reboot]))
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"

    with pytest.raises(UmzugError, match="service is not enabled"):
        Executor(
            state_root=state_root,
            system_root=system_root,
            assume_yes=True,
            approvals={service.id},
        ).apply(plan)
    state = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    assert state["pending_reboot"] is None
    assert reboot.id not in state["completed"]


def test_dry_run_does_not_poison_checkpoint_for_later_real_apply(tmp_path: Path) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"
    plan = _plan(
        _action(
            "write-config",
            parameters={"path": "/etc/umzug.conf", "content": "enabled=true\n"},
        )
    )

    Executor(
        state_root=state_root,
        system_root=system_root,
        dry_run=True,
        assume_yes=True,
    ).apply(plan)
    assert not (system_root / "etc/umzug.conf").exists()

    real_state = Executor(
        state_root=state_root,
        system_root=system_root,
        assume_yes=True,
    ).apply(plan)

    assert (system_root / "etc/umzug.conf").read_text(encoding="utf-8") == "enabled=true\n"
    assert real_state["completed"] == ["write-config"]


def test_unprivileged_dry_run_marks_root_only_diff_uninspectable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    system_root = tmp_path / "system"
    protected_parent = system_root / "etc" / "sudoers.d"
    protected_parent.mkdir(parents=True)
    target = protected_parent / "90-umzug-hardening"
    plan = _plan(
        _action(
            "protected-preview",
            parameters={"path": "/etc/sudoers.d/90-umzug-hardening", "content": "Defaults use_pty\n", "mode": 0o440},
        )
    )
    real_access = executor_module.os.access

    def access(path: object, mode: int) -> bool:
        if Path(path) == protected_parent and mode == executor_module.os.X_OK:
            return False
        return real_access(path, mode)

    monkeypatch.setattr(executor_module.os, "access", access)
    state = Executor(
        state_root=tmp_path / "state",
        system_root=system_root,
        dry_run=True,
        assume_yes=True,
    ).apply(plan)

    output = capsys.readouterr().out
    assert "not inspectable by this unprivileged dry-run" in output
    assert "productive root apply must re-check" in output
    assert state["completed"] == []
    assert state["dry_run_actions"] == ["protected-preview"]
    assert not target.exists()


def test_apply_checkpoint_is_idempotent_and_backup_is_created_once(tmp_path: Path) -> None:
    system_root = tmp_path / "system"
    target = system_root / "etc/application.conf"
    target.parent.mkdir(parents=True)
    target.write_text("old=true\n", encoding="utf-8")
    target.chmod(0o600)
    state_root = tmp_path / "state"
    content = "old=false\n"
    plan = _plan(
        _action(
            "replace-config",
            parameters={"path": "/etc/application.conf", "content": content, "mode": 0o640},
            backup_paths=["/etc/application.conf"],
            verify={
                "kind": "file_sha256",
                "path": "/etc/application.conf",
                "sha256": hashlib.sha256(content.encode()).hexdigest(),
            },
        ),
        _action("durable-checkpoint", operation="checkpoint"),
    )
    executor = Executor(
        state_root=state_root,
        system_root=system_root,
        assume_yes=True,
    )

    first = executor.apply(plan)
    inode_after_first_apply = target.stat().st_ino
    backup_rows = dict(first["backups"])
    second = executor.apply(plan)

    assert target.read_text(encoding="utf-8") == content
    assert target.stat().st_ino == inode_after_first_apply
    assert stat_mode(target) == 0o640
    assert second["completed"] == ["replace-config", "durable-checkpoint"]
    assert second["backups"] == backup_rows
    assert len(list((state_root / "backups").iterdir())) == 1
    backup = Path(next(iter(backup_rows.values()))["backup"])
    assert backup.read_text(encoding="utf-8") == "old=true\n"
    assert stat_mode(backup) == 0o600


def stat_mode(path: Path) -> int:
    return path.stat(follow_symlinks=False).st_mode & 0o7777


def test_rollback_restores_backup_and_removes_created_file_under_injected_root(
    tmp_path: Path,
) -> None:
    system_root = tmp_path / "system"
    existing = system_root / "etc/existing.conf"
    existing.parent.mkdir(parents=True)
    existing.write_text("before\n", encoding="utf-8")
    existing.chmod(0o600)
    state_root = tmp_path / "state"
    plan = _plan(
        _action(
            "replace-existing",
            parameters={"path": "/etc/existing.conf", "content": "after\n", "mode": 0o644},
            backup_paths=["/etc/existing.conf"],
        ),
        _action(
            "create-new",
            parameters={"path": "/etc/new.conf", "content": "temporary\n"},
            backup_paths=["/etc/new.conf"],
        ),
    )
    Executor(
        state_root=state_root,
        system_root=system_root,
        assume_yes=True,
    ).apply(plan)

    assert existing.read_text(encoding="utf-8") == "after\n"
    assert (system_root / "etc/new.conf").exists()
    rollback(state_root, system_root=system_root)

    assert existing.read_text(encoding="utf-8") == "before\n"
    assert stat_mode(existing) == 0o600
    assert not (system_root / "etc/new.conf").exists()
    state = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    assert "rolled_back_at" in state


def test_rollback_verifies_every_backup_before_deleting_live_target(
    tmp_path: Path,
) -> None:
    system_root = tmp_path / "system"
    target = system_root / "etc/value.conf"
    target.parent.mkdir(parents=True)
    target.write_text("before\n", encoding="utf-8")
    state_root = tmp_path / "state"
    plan = _plan(
        _action(
            "replace",
            parameters={"path": "/etc/value.conf", "content": "after\n"},
            backup_paths=["/etc/value.conf"],
        )
    )
    state = Executor(
        state_root=state_root,
        system_root=system_root,
        assume_yes=True,
    ).apply(plan)
    backup = Path(next(iter(state["backups"].values()))["backup"])
    backup.write_text("attacker-modified-backup\n", encoding="utf-8")

    with pytest.raises(UmzugError, match="integrity verification failed"):
        rollback(state_root, system_root=system_root)

    assert target.read_text(encoding="utf-8") == "after\n"


def test_state_store_rejects_symlinked_private_child(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()
    (state_root / "backups").symlink_to(outside, target_is_directory=True)

    with pytest.raises(UmzugError, match="safe directory"):
        StateStore(state_root)


def test_state_store_never_follows_state_file_symlink(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state")
    outside = tmp_path / "outside.json"
    outside.write_text('{"format":1,"completed":[]}', encoding="utf-8")
    store.path.symlink_to(outside)

    with pytest.raises(UmzugError, match="without following"):
        store.load()


def test_root_state_store_rejects_user_owned_parent(tmp_path: Path) -> None:
    with pytest.raises(UmzugError, match="non-root-owned or writable parent"):
        StateStore._open_secure_root(tmp_path / "state", owner_uid=0)


def test_checkpoint_digest_rejects_resume_with_a_different_plan(tmp_path: Path) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"
    first_plan = _plan(
        _action(
            "first",
            parameters={"path": "/etc/value", "content": "one\n"},
        )
    )
    executor = Executor(
        state_root=state_root,
        system_root=system_root,
        assume_yes=True,
    )
    executor.apply(first_plan)
    other_plan = _plan(
        _action(
            "second",
            parameters={"path": "/etc/value", "content": "two\n"},
        )
    )

    with pytest.raises(UmzugError, match="different plan"):
        executor.apply(other_plan)
    assert (system_root / "etc/value").read_text(encoding="utf-8") == "one\n"


def test_plan_digest_is_bound_before_first_completed_action_after_crash(tmp_path: Path) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"
    first_plan = _plan(_action("never-completed", parameters={"path": "/etc/value", "content": "one\n"}))
    executor = Executor(state_root=state_root, system_root=system_root, assume_yes=True)

    def crash_before_action(_action: Action) -> None:
        raise UmzugError("simulated crash before first action")

    executor._confirm = crash_before_action  # type: ignore[method-assign]
    with pytest.raises(UmzugError, match="simulated crash"):
        executor.apply(first_plan)

    persisted = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    assert persisted["plan_digest"] == first_plan.digest()
    assert persisted["completed"] == []
    replacement = _plan(_action("replacement", parameters={"path": "/etc/value", "content": "two\n"}))
    with pytest.raises(UmzugError, match="different plan"):
        Executor(state_root=state_root, system_root=system_root, assume_yes=True).apply(replacement)
    assert not (system_root / "etc/value").exists()


def test_existing_unbound_executor_state_is_never_adopted(tmp_path: Path) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"
    store = StateStore(state_root)
    store.save(store.load())

    with pytest.raises(UmzugError, match="no immutable plan digest"):
        Executor(state_root=state_root, system_root=system_root, assume_yes=True).apply(_plan())


def test_mode_only_drift_is_corrected_and_verified(tmp_path: Path) -> None:
    system_root = tmp_path / "system"
    target = system_root / "etc/managed.conf"
    target.parent.mkdir(parents=True)
    target.write_text("same\n", encoding="utf-8")
    target.chmod(0o666)
    plan = _plan(
        _action(
            "mode-correction",
            parameters={"path": "/etc/managed.conf", "content": "same\n", "mode": 0o600},
            backup_paths=["/etc/managed.conf"],
        )
    )

    Executor(
        state_root=tmp_path / "state",
        system_root=system_root,
        assume_yes=True,
    ).apply(plan)

    assert target.read_text(encoding="utf-8") == "same\n"
    assert stat_mode(target) == 0o600


def test_write_rejects_symlinked_parent_component(tmp_path: Path) -> None:
    system_root = tmp_path / "system"
    outside = tmp_path / "outside"
    outside.mkdir()
    system_root.mkdir()
    (system_root / "etc").symlink_to(outside, target_is_directory=True)
    plan = _plan(
        _action(
            "symlink-parent",
            parameters={"path": "/etc/managed.conf", "content": "must-not-escape\n"},
        )
    )

    with pytest.raises(UmzugError, match="symlink parent|escapes root"):
        Executor(
            state_root=tmp_path / "state",
            system_root=system_root,
            assume_yes=True,
        ).apply(plan)
    assert not (outside / "managed.conf").exists()


def test_required_command_input_is_hash_bound_and_snapshotted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    artifact = tmp_path / "package.deb"
    artifact.write_bytes(b"reviewed package")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    observed: list[list[str]] = []
    live_checks: list[tuple[str, str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> object:
        observed.append(argv)
        command = Path(argv[0]).name
        if command == "mullvad":
            stdout = b"2026.1\n"
        elif command == "dpkg-query":
            stdout = b"mullvad-vpn\t2026.1\tamd64\tii \n"
        else:
            stdout = b""
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": b""})()

    monkeypatch.setattr(executor_module, "run", fake_run)
    monkeypatch.setattr(
        executor_module,
        "_trusted_executable",
        lambda name: Path("/trusted") / name,
    )
    monkeypatch.setattr(
        executor_module,
        "_executable_receipt",
        lambda path: {"path": str(path), "sha256": "a" * 64},
    )
    monkeypatch.setattr(
        executor_module.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_gid=555, gr_mem=[]),
    )
    monkeypatch.setattr(executor_module.pwd, "getpwall", lambda: [])

    def live_restriction(group: str, tools: object) -> None:
        live_checks.append((group, tools.path("systemctl")))

    monkeypatch.setattr(
        vpn_module,
        "_verify_management_restriction",
        live_restriction,
    )
    action = _action(
        "mullvad-offline-install",
        operation="run_command",
        parameters={
            "argv": [
                "apt-get",
                "install",
                "--yes",
                "--reinstall",
                "--no-download",
                "--no-install-recommends",
                "--",
                str(artifact),
            ],
            "network_policy": "forbidden",
            "timeout": 1800,
            "required_file_hashes": {str(artifact): digest},
            "post_install_argvs": [
                ["systemctl", "daemon-reload"],
                ["systemctl", "restart", "mullvad-daemon.service"],
            ],
        },
        verify={
            "kind": "mullvad_version",
            "manager": "dpkg",
            "package": "mullvad-vpn",
            "version": "2026.1",
            "architecture": "amd64",
            "management_group": "mullvad-management",
        },
        risk="critical",
        requires_confirmation=True,
        destructive=True,
    )
    state_root = tmp_path / "state"
    Executor(
        state_root=state_root,
        system_root=system_root,
        assume_yes=True,
        approvals={"mullvad-management-group", "mullvad-offline-install"},
    ).apply(_plan(*prepend_executable_preflights([*_mullvad_test_preparation(), action])))

    snapshots = list((state_root / "inputs").iterdir())
    assert len(snapshots) == 1
    assert snapshots[0].read_bytes() == b"reviewed package"
    assert stat_mode(snapshots[0]) == 0o400
    assert observed and observed[0][:3] == ["/trusted/unshare", "--net", "--"]
    assert str(snapshots[0]) in observed[0]
    assert str(artifact) not in observed[0]
    assert observed[1:3] == [
        ["/trusted/systemctl", "daemon-reload"],
        ["/trusted/systemctl", "restart", "mullvad-daemon.service"],
    ]
    assert live_checks == [("mullvad-management", "/trusted/systemctl")]


def test_required_command_input_change_aborts_before_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    artifact = tmp_path / "package.deb"
    artifact.write_bytes(b"changed")
    called = False

    def fake_run(argv: list[str], **kwargs: object) -> object:
        nonlocal called
        called = True
        return object()

    monkeypatch.setattr(executor_module, "run", fake_run)
    action = _action(
        "mullvad-offline-install",
        operation="run_command",
        parameters={
            "argv": [
                "apt-get",
                "install",
                "--yes",
                "--reinstall",
                "--no-download",
                "--no-install-recommends",
                "--",
                str(artifact),
            ],
            "network_policy": "forbidden",
            "timeout": 1800,
            "required_file_hashes": {str(artifact): "0" * 64},
            "post_install_argvs": [
                ["systemctl", "daemon-reload"],
                ["systemctl", "restart", "mullvad-daemon.service"],
            ],
        },
        verify={
            "kind": "mullvad_version",
            "manager": "dpkg",
            "package": "mullvad-vpn",
            "version": "2026.1",
            "architecture": "amd64",
            "management_group": "mullvad-management",
        },
        risk="critical",
        requires_confirmation=True,
        destructive=True,
    )
    with pytest.raises(UmzugError, match="changed after planning"):
        Executor(
            state_root=tmp_path / "state",
            system_root=system_root,
            assume_yes=True,
            approvals={"mullvad-management-group", "mullvad-offline-install"},
        ).apply(_plan(*_mullvad_test_preparation(), action))
    assert not called
    assert not (system_root / "etc/systemd/system/mullvad-daemon.service.d/90-umzug-security.conf").exists()


def test_restricted_group_verifier_rejects_explicit_and_primary_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action = _mullvad_test_preparation()[0]
    monkeypatch.setattr(
        executor_module.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_gid=555, gr_mem=["alice"]),
    )
    monkeypatch.setattr(
        executor_module.pwd,
        "getpwall",
        lambda: [SimpleNamespace(pw_name="bob", pw_gid=555, pw_uid=1000)],
    )

    with pytest.raises(UmzugError, match="alice, bob"):
        Executor(
            state_root=tmp_path / "state",
            system_root=tmp_path,
            approvals={"mullvad-management-group"},
        ).apply(_plan(action))


def test_completed_restricted_group_is_reverified_on_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    members: list[str] = []
    monkeypatch.setattr(
        executor_module.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_gid=555, gr_mem=list(members)),
    )
    monkeypatch.setattr(executor_module.pwd, "getpwall", lambda: [])
    system_root = tmp_path / "system"
    system_root.mkdir()
    plan = _plan(_mullvad_test_preparation()[0])
    executor = Executor(
        state_root=tmp_path / "state",
        system_root=system_root,
        approvals={"mullvad-management-group"},
    )
    executor.apply(plan)

    members.append("alice")
    with pytest.raises(UmzugError, match="alice"):
        executor.apply(plan)


def test_vendor_action_is_not_completed_when_immediate_live_check_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    artifact = tmp_path / "mullvad.deb"
    artifact.write_bytes(b"reviewed")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    observed: list[list[str]] = []

    def fake_run(argv: list[str], **kwargs: object) -> object:
        observed.append(argv)
        command = Path(argv[0]).name
        if command == "mullvad":
            stdout = b"2026.1\n"
        elif command == "dpkg-query":
            stdout = b"mullvad-vpn\t2026.1\tamd64\tii \n"
        else:
            stdout = b""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(executor_module, "run", fake_run)
    monkeypatch.setattr(
        executor_module,
        "_trusted_executable",
        lambda name: Path("/trusted") / name,
    )
    monkeypatch.setattr(
        executor_module,
        "_executable_receipt",
        lambda path: {"path": str(path), "sha256": "a" * 64},
    )
    monkeypatch.setattr(
        executor_module.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_gid=555, gr_mem=[]),
    )
    monkeypatch.setattr(executor_module.pwd, "getpwall", lambda: [])

    def reject_live(group: str, tools: object) -> None:
        assert group == "mullvad-management"
        assert tools.path("systemctl") == "/trusted/systemctl"
        raise UmzugError("simulated live containment failure")

    monkeypatch.setattr(
        vpn_module,
        "_verify_management_restriction",
        reject_live,
    )
    install = mullvad_install_action(
        distribution="debian",
        package_adapter="debian",
        artifact=str(artifact),
        artifact_sha256=digest,
        package_version="2026.1",
        package_architecture="amd64",
        management_group="mullvad-management",
    )
    plan = _plan(*prepend_executable_preflights([*_mullvad_test_preparation(), install]))
    state_root = tmp_path / "state"
    with pytest.raises(UmzugError, match="live containment failure"):
        Executor(
            state_root=state_root,
            system_root=system_root,
            assume_yes=True,
            approvals={"mullvad-management-group", "mullvad-offline-install"},
        ).apply(plan)

    assert [item[1:] for item in observed[1:3]] == [
        ["daemon-reload"],
        ["restart", "mullvad-daemon.service"],
    ]
    state = StateStore(state_root).load()
    assert "mullvad-offline-install" not in state["completed"]


def test_disabled_service_verification_rejects_still_active_sshd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(argv: list[str], **kwargs: object) -> object:
        del kwargs
        command = Path(argv[0]).name
        return type(
            "Result",
            (),
            {
                "returncode": 0 if [command, *argv[1:2]] == ["systemctl", "is-active"] else 1,
                "stdout": b"active\n" if [command, *argv[1:2]] == ["systemctl", "is-active"] else b"disabled\n",
                "stderr": b"",
            },
        )()

    monkeypatch.setattr(executor_module, "run", fake_run)
    monkeypatch.setattr(
        executor_module,
        "_trusted_executable",
        lambda name: Path("/trusted") / name,
    )
    action = _action(
        "disable-sshd",
        operation="disable_service",
        parameters={"name": "sshd.service", "mask": True, "init": "systemd"},
        verify={"kind": "service_disabled", "name": "sshd.service", "init": "systemd"},
    )

    with pytest.raises(UmzugError, match="remains active"):
        Executor(
            state_root=tmp_path / "state",
            system_root=tmp_path / "system",
            assume_yes=True,
        )._verify(action)


def test_command_allowlist_rejects_path_with_allowed_basename(tmp_path: Path) -> None:
    action = _action(
        "path-spoof",
        operation="run_command",
        parameters={"argv": ["/tmp/nft", "list", "ruleset"]},
    )
    with pytest.raises(UmzugError, match="no privileged schema|fixed argv"):
        Executor(
            state_root=tmp_path / "state",
            system_root=tmp_path / "system",
            assume_yes=True,
        ).apply(_plan(action))


@pytest.mark.parametrize(
    ("operation", "parameters", "verify"),
    [
        ("run_command", {"argv": ["nft", "flush", "ruleset"]}, {}),
        ("enable_service", {"name": "sshd.service"}, {}),
        (
            "write_file",
            {"path": "/etc/ld.so.preload", "content": "/tmp/evil.so\n", "mode": 0o644},
            {},
        ),
        (
            "write_file",
            {"path": "/etc/value", "content": "safe\n", "mode": 0o644},
            {"kind": "command", "argv": ["systemctl", "enable", "--now", "sshd"]},
        ),
    ],
)
def test_typed_action_registry_rejects_privileged_plan_injection(
    operation: str,
    parameters: dict[str, object],
    verify: dict[str, object],
) -> None:
    action = Action(
        id="apparently-safe",
        phase="test",
        summary="harmless summary",
        rationale="attacker-controlled prose",
        risk="low",
        operation=operation,
        parameters=parameters,
        verify=verify,
    )
    with pytest.raises(UmzugError):
        Plan(
            profile="strict",
            system_fingerprint="0" * 64,
            actions=[action],
            created_at="2026-07-15T00:00:00Z",
        ).validate()


def test_backup_path_must_equal_the_typed_mutation_target() -> None:
    action = Action(
        id="hardening-sysctl",
        phase="hardening",
        summary="write sysctls",
        rationale="test unsafe backup injection",
        risk="high",
        operation="write_file",
        parameters={
            "path": "/etc/sysctl.d/90-umzug-hardening.conf",
            "content": "x\n",
            "mode": 0o644,
        },
        backup_paths=["/"],
        requires_confirmation=True,
        destructive=True,
    )
    with pytest.raises(UmzugError, match="back up exactly"):
        action.validate()


def test_test_profile_is_never_accepted_for_live_root(tmp_path: Path) -> None:
    with pytest.raises(UmzugError, match="forbidden against the live system root"):
        Executor(state_root=tmp_path / "state", system_root=Path("/"), dry_run=True).apply(
            _plan(_action("fixture", parameters={"path": "/etc/value", "content": "x\n"}))
        )


def test_reboot_checkpoint_stops_and_resume_continues_at_next_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"
    plan = _plan(
        _action(
            "initramfs-change",
            parameters={"path": "/etc/initramfs-change", "content": "done\n"},
            reboot_reason="initramfs must be reloaded",
            post_reboot_verify={"kind": "boot_id_changed"},
        ),
        _action(
            "post-reboot",
            parameters={"path": "/etc/post-reboot", "content": "verified\n"},
        ),
    )
    executor = Executor(
        state_root=state_root,
        system_root=system_root,
        assume_yes=True,
    )
    boot_ids = iter([BOOT_BEFORE, BOOT_AFTER])
    monkeypatch.setattr(executor_module, "_boot_id", lambda: next(boot_ids))

    first = executor.apply(plan)
    assert first["completed"] == ["initramfs-change"]
    assert first["pending_reboot"]["action"] == "initramfs-change"
    assert not (system_root / "etc/post-reboot").exists()

    resumed = executor.apply(plan)
    assert resumed["completed"] == ["initramfs-change", "post-reboot"]
    assert resumed["pending_reboot"] is None
    assert resumed["last_verified_reboot"]["previous_boot_id"] == BOOT_BEFORE
    assert resumed["last_verified_reboot"]["current_boot_id"] == BOOT_AFTER
    assert (system_root / "etc/post-reboot").read_text(encoding="utf-8") == "verified\n"


def test_resume_reverifies_completed_control_before_reboot_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"
    control = _action(
        "managed-control",
        parameters={"path": "/etc/managed-control", "content": "enabled\n"},
        reboot_reason="test boundary",
        post_reboot_verify={"kind": "boot_id_changed"},
    )
    plan = _plan(control)
    executor = Executor(state_root=state_root, system_root=system_root, assume_yes=True)
    executor.store.save(
        {
            "format": 1,
            "plan_digest": plan.digest(),
            "profile": plan.profile,
            "completed": [control.id],
            "backups": {},
            "created": [],
            "pending_reboot": {
                "action": control.id,
                "reason": "test boundary",
                "resume": "setup resume",
                "boot_id": BOOT_BEFORE,
            },
        }
    )
    monkeypatch.setattr(executor_module, "_boot_id", lambda: BOOT_AFTER)

    def reject_missing_control(action: Action, _state: dict[str, object] | None = None) -> None:
        assert action.id == "managed-control"
        raise UmzugError("completed control is absent")

    monkeypatch.setattr(executor, "_verify", reject_missing_control)
    with pytest.raises(UmzugError, match="completed control is absent"):
        executor.apply(plan)


@pytest.mark.parametrize("completed", [["known", "known"], ["unknown"], [7]])
def test_resume_rejects_malformed_completed_action_bindings(tmp_path: Path, completed: list[object]) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    plan = _plan(_action("known", parameters={"path": "/etc/value", "content": "x\n"}))
    executor = Executor(
        state_root=tmp_path / ("state-" + hashlib.sha256(repr(completed).encode()).hexdigest()),
        system_root=system_root,
        dry_run=True,
        assume_yes=True,
    )
    executor.store.save(
        {
            "format": 1,
            "plan_digest": plan.digest(),
            "profile": plan.profile,
            "completed": completed,
            "backups": {},
            "created": [],
            "pending_reboot": None,
        }
    )

    with pytest.raises(UmzugError, match="completed-action|absent from the bound plan"):
        executor.apply(plan)


def test_reboot_completion_and_pending_checkpoint_are_saved_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    action = _action(
        "reboot-action",
        parameters={"path": "/etc/reboot-action", "content": "done\n"},
        reboot_reason="load changed boot state",
        post_reboot_verify={"kind": "boot_id_changed"},
    )
    executor = Executor(
        state_root=tmp_path / "state",
        system_root=system_root,
        assume_yes=True,
    )
    monkeypatch.setattr(executor_module, "_boot_id", lambda: BOOT_BEFORE)
    snapshots: list[dict[str, object]] = []
    real_save = executor.store.save

    def recording_save(state: dict[str, object]) -> None:
        snapshots.append(json.loads(json.dumps(state)))
        real_save(state)

    monkeypatch.setattr(executor.store, "save", recording_save)
    result = executor.apply(_plan(action))

    completed_writes = [row for row in snapshots if "reboot-action" in row.get("completed", [])]
    assert len(completed_writes) == 1
    assert completed_writes[0]["pending_reboot"]["action"] == "reboot-action"  # type: ignore[index]
    assert result["completed"] == ["reboot-action"]
    assert result["pending_reboot"]["boot_id"] == BOOT_BEFORE


def test_already_matching_reboot_action_still_requires_reboot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system_root = tmp_path / "system"
    target = system_root / "etc/already-matching"
    target.parent.mkdir(parents=True)
    target.write_text("done\n", encoding="utf-8")
    target.chmod(0o644)
    plan = _plan(
        _action(
            "matching-reboot",
            parameters={"path": "/etc/already-matching", "content": "done\n", "mode": 0o644},
            reboot_reason="matching config still needs a boot boundary",
            post_reboot_verify={"kind": "boot_id_changed"},
        ),
        _action("must-wait", parameters={"path": "/etc/must-wait", "content": "later\n"}),
    )
    monkeypatch.setattr(executor_module, "_boot_id", lambda: BOOT_BEFORE)

    state = Executor(
        state_root=tmp_path / "state",
        system_root=system_root,
        assume_yes=True,
    ).apply(plan)

    assert state["completed"] == ["matching-reboot"]
    assert state["pending_reboot"]["action"] == "matching-reboot"
    assert not (system_root / "etc/must-wait").exists()


def test_reboot_checkpoint_rejects_non_uuid_current_boot_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    action = _action(
        "invalid-boot-id",
        parameters={"path": "/etc/value", "content": "changed\n"},
        reboot_reason="requires reboot",
        post_reboot_verify={"kind": "boot_id_changed"},
    )
    state_root = tmp_path / "state"
    monkeypatch.setattr(executor_module, "_boot_id", lambda: "not-a-uuid")

    with pytest.raises(UmzugError, match="canonical UUID"):
        Executor(state_root=state_root, system_root=system_root, assume_yes=True).apply(_plan(action))

    state = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    assert state["completed"] == []
    assert state["pending_reboot"] is None


def test_resume_rejects_same_or_invalid_boot_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"
    action = _action(
        "boot-boundary",
        parameters={"path": "/etc/value", "content": "changed\n"},
        reboot_reason="requires reboot",
        post_reboot_verify={"kind": "boot_id_changed"},
    )
    plan = _plan(action)
    executor = Executor(state_root=state_root, system_root=system_root, assume_yes=True)
    monkeypatch.setattr(executor_module, "_boot_id", lambda: BOOT_BEFORE)
    executor.apply(plan)

    with pytest.raises(UmzugError, match="reboot still required"):
        executor.apply(plan)

    monkeypatch.setattr(executor_module, "_boot_id", lambda: "invalid-current-id")
    with pytest.raises(UmzugError, match="current post-reboot.*canonical UUID"):
        executor.apply(plan)

    state = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    state["pending_reboot"]["boot_id"] = "invalid-saved-id"
    (state_root / "state.json").write_text(json.dumps(state), encoding="utf-8")
    monkeypatch.setattr(executor_module, "_boot_id", lambda: BOOT_AFTER)
    with pytest.raises(UmzugError, match="saved pre-reboot.*canonical UUID"):
        executor.apply(plan)


def test_manual_security_checkpoint_cannot_complete_noninteractively(tmp_path: Path) -> None:
    action = _action(
        "manual-initramfs",
        operation="checkpoint",
        parameters={"manual_verification": "rebuild and inspect initramfs"},
    )
    with pytest.raises(UmzugError, match="local-console evidence"):
        Executor(
            state_root=tmp_path / "state",
            system_root=tmp_path / "system",
            assume_yes=True,
        ).apply(_plan(action))


def test_post_reboot_module_verification_rejects_loaded_forbidden_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    action = _action(
        "module-policy",
        reboot_reason="new initramfs",
        post_reboot_verify={"kind": "modules_not_loaded", "modules": ["danger-radio"]},
    )
    original_read_text = Path.read_text

    def fake_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path == Path("/proc/modules"):
            return "danger_radio 1 0 - Live 0x0\n"
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fake_read_text)
    with pytest.raises(UmzugError, match="remain loaded"):
        Executor(
            state_root=tmp_path / "state",
            system_root=tmp_path / "system",
            assume_yes=True,
        )._verify_post_reboot(action, {})


def test_post_reboot_module_verification_checks_sys_module_for_builtins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc_modules = tmp_path / "proc-modules"
    proc_modules.write_text("", encoding="utf-8")
    sys_modules = tmp_path / "sys-module"
    (sys_modules / "danger_radio").mkdir(parents=True)
    monkeypatch.setattr(executor_module, "PROC_MODULES", proc_modules)
    monkeypatch.setattr(executor_module, "SYS_MODULE_ROOT", sys_modules)
    action = _action(
        "builtin-module-policy",
        reboot_reason="new module policy",
        post_reboot_verify={"kind": "modules_not_loaded", "modules": ["danger-radio"]},
    )

    with pytest.raises(UmzugError, match="remain loaded.*danger_radio"):
        Executor(
            state_root=tmp_path / "state",
            system_root=tmp_path / "system",
            assume_yes=True,
        )._verify_post_reboot(action, {})


def test_rollback_rejects_checkpoint_created_path_outside_injected_root(
    tmp_path: Path,
) -> None:
    system_root = tmp_path / "system"
    system_root.mkdir()
    state_root = tmp_path / "state"
    store = StateStore(state_root)
    outside = tmp_path / "outside-must-survive"
    outside.write_text("safe\n", encoding="utf-8")
    state = store.load()
    state["created"] = [str(outside)]
    store.save(state)

    with pytest.raises(UmzugError, match="escapes system root"):
        rollback(state_root, system_root=system_root)
    assert outside.read_text(encoding="utf-8") == "safe\n"
