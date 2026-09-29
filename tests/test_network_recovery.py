from __future__ import annotations

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

import umzug.network as network
import umzug.setup_cli as setup_cli
from umzug.executor import rollback
from umzug.util import AuditLog, UmzugError


def _completed(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> Any:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_generated_recovery_script_is_fail_closed_and_shell_valid() -> None:
    script = network.recovery_script()

    checked = subprocess.run(
        ["sh", "-n"],
        input=script.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert checked.returncode == 0, checked.stderr.decode(errors="replace")
    assert "|| true" not in script
    assert "SSH_CONNECTION" in script
    assert "remote-session ancestor detected" in script
    assert "/dev/ttyS" in script
    assert "/etc/local.d/umzug-offline-guard.start" in script
    assert '"$NFT" --file -' in script
    assert "owned nftables table remains active" in script
    assert "flush ruleset" not in script
    assert "delete table inet mullvad" not in script
    assert "positively verified" in script


def test_recover_network_dry_run_is_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        network,
        "_recovery_executable",
        lambda _name: pytest.fail("dry-run resolved or executed a system program"),
    )
    monkeypatch.setattr(
        network,
        "require_proven_local_console",
        lambda _label: pytest.fail("dry-run invoked the productive console gate"),
    )
    monkeypatch.setattr(
        network,
        "_systemd_runtime_active",
        lambda: pytest.fail("dry-run inspected the live init runtime"),
    )

    report = network.recover_network(dry_run=True)

    assert report["status"] == "dry-run"
    assert report["authorization_to_mutate"] is False
    assert "/etc/local.d/umzug-offline-guard.start" in report["owned_openrc_hooks"]


def test_direct_productive_recovery_stops_at_console_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        network,
        "require_proven_local_console",
        lambda _label: (_ for _ in ()).throw(UmzugError("not a local console")),
    )
    monkeypatch.setattr(
        network,
        "require_root",
        lambda **_kwargs: pytest.fail("root or mutation checks ran before the console gate"),
    )

    with pytest.raises(UmzugError, match="not a local console"):
        network.recover_network()


def test_recover_network_removes_only_owned_objects_and_verifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hooks = tuple(tmp_path / name for name in ("firewall.start", "radio.start", "offline.start"))
    for hook in hooks:
        hook.write_text("owned\n", encoding="utf-8")
    monkeypatch.setattr(network, "OWNED_OPENRC_HOOKS", hooks)
    monkeypatch.setattr(network, "_systemd_runtime_active", lambda: True)
    monkeypatch.setattr(network, "require_root", lambda *, dry_run: None)
    monkeypatch.setattr(network, "require_proven_local_console", lambda _label: {})
    monkeypatch.setattr(
        network,
        "_recovery_executable",
        lambda name: Path("/trusted") / name,
    )

    units = {
        name: {"load": "loaded", "active": "active", "unit_file": "enabled"} for name in network.OWNED_SYSTEMD_UNITS
    }
    tables = {"umzug_host", "umzug_offline_guard", "foreign_firewall"}
    submitted_batches: list[str] = []

    def fake_run(
        argv: list[str],
        *,
        check: bool = True,
        input_bytes: bytes | None = None,
        **_kwargs: object,
    ) -> Any:
        program = Path(argv[0]).name
        if program == "systemctl":
            if argv[1] == "daemon-reload":
                return _completed()
            if argv[1] == "disable":
                row = units[argv[-1]]
                row["active"] = "inactive"
                row["unit_file"] = "disabled"
                return _completed()
            assert argv[1] == "show"
            property_name = argv[2].split("=", 1)[1]
            row = units[argv[-1]]
            value = {
                "LoadState": row["load"],
                "ActiveState": row["active"],
                "UnitFileState": row["unit_file"],
            }[property_name]
            return _completed(stdout=(value + "\n").encode())
        if program == "nft":
            if argv[1:] == ["--json", "list", "tables"]:
                rows = [{"metainfo": {"json_schema_version": 1}}]
                rows.extend({"table": {"family": "inet", "name": name}} for name in sorted(tables))
                return _completed(stdout=json.dumps({"nftables": rows}).encode())
            assert argv[1:] == ["--file", "-"]
            assert input_bytes is not None
            batch = input_bytes.decode("ascii")
            submitted_batches.append(batch)
            assert "foreign_firewall" not in batch
            for line in batch.splitlines():
                prefix = "delete table inet "
                assert line.startswith(prefix)
                tables.remove(line.removeprefix(prefix))
            return _completed()
        if program == "rfkill":
            if argv[1:] == ["unblock", "all"]:
                return _completed()
            assert argv[1:] == ["list"]
            return _completed(stdout=b"0: phy0: Wireless LAN\n\tSoft blocked: no\n\tHard blocked: no\n")
        raise AssertionError(argv)

    monkeypatch.setattr(network, "run", fake_run)

    report = network.recover_network()

    assert report["status"] == "verified"
    assert report["authorization_to_rollback"] is True
    assert report["nftables"]["removed"] == ["umzug_host", "umzug_offline_guard"]
    assert tables == {"foreign_firewall"}
    assert len(submitted_batches) == 1
    for hook in hooks:
        assert not hook.exists()
        assert hook.with_name(hook.name + ".disabled-by-recovery").exists()
    assert all(row["active"] == "inactive" for row in units.values())
    assert all(row["unit_file"] == "disabled" for row in units.values())


def test_recover_network_fails_if_atomic_nft_removal_is_unproven(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(network, "OWNED_OPENRC_HOOKS", (tmp_path / "absent.start",))
    monkeypatch.setattr(network, "_systemd_runtime_active", lambda: False)
    monkeypatch.setattr(network, "require_root", lambda *, dry_run: None)
    monkeypatch.setattr(network, "require_proven_local_console", lambda _label: {})
    monkeypatch.setattr(
        network,
        "_recovery_executable",
        lambda name: Path("/trusted/nft") if name == "nft" else None,
    )

    def fake_run(
        argv: list[str],
        *,
        input_bytes: bytes | None = None,
        **_kwargs: object,
    ) -> Any:
        if argv[1:] == ["--json", "list", "tables"]:
            payload = {"nftables": [{"table": {"family": "inet", "name": "umzug_host"}}]}
            return _completed(stdout=json.dumps(payload).encode())
        assert argv[1:] == ["--file", "-"]
        assert input_bytes == b"delete table inet umzug_host\n"
        return _completed(returncode=1, stderr=b"transaction rejected")

    monkeypatch.setattr(network, "run", fake_run)

    with pytest.raises(UmzugError, match="atomic|command failed"):
        network.recover_network()


def test_recover_network_missing_objects_is_idempotently_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disabled = tmp_path / "offline.start.disabled-by-recovery"
    disabled.write_text("already disabled\n", encoding="utf-8")
    monkeypatch.setattr(network, "OWNED_OPENRC_HOOKS", (tmp_path / "offline.start",))
    monkeypatch.setattr(network, "_systemd_runtime_active", lambda: False)
    monkeypatch.setattr(network, "require_root", lambda *, dry_run: None)
    monkeypatch.setattr(network, "require_proven_local_console", lambda _label: {})
    monkeypatch.setattr(
        network,
        "_recovery_executable",
        lambda name: Path("/trusted/nft") if name == "nft" else None,
    )
    monkeypatch.setattr(
        network,
        "run",
        lambda *_args, **_kwargs: _completed(stdout=b'{"nftables":[]}'),
    )

    first = network.recover_network()
    active = tmp_path / "offline.start"
    active.write_text("restored by rollback\n", encoding="utf-8")
    second = network.recover_network()

    assert first["status"] == second["status"] == "verified"
    assert first["nftables"]["removed"] == second["nftables"]["removed"] == []
    assert not active.exists()
    assert (tmp_path / "offline.start.disabled-by-recovery.1").exists()


def test_cli_productive_recovery_requires_console_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        setup_cli,
        "require_proven_local_console",
        lambda label: events.append(f"console:{label}"),
    )
    monkeypatch.setattr(
        setup_cli,
        "recover_network",
        lambda **_kwargs: events.append("recover") or {"status": "verified"},
    )
    args = setup_cli._parser().parse_args(["recover-network", "--confirm-recovery"])

    assert setup_cli.dispatch(args, AuditLog(None)) == 0
    assert events == ["console:recover-network", "recover"]


def test_cli_productive_rollback_recovers_before_and_after_file_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        setup_cli,
        "require_proven_local_console",
        lambda label: events.append(f"console:{label}"),
    )
    monkeypatch.setattr(
        setup_cli,
        "_require_saved_state_storage_binding",
        lambda _path: events.append("state-bound") or {},
    )

    def fake_recover(**_kwargs: object) -> dict[str, object]:
        events.append("recover")
        return {"status": "verified", "authorization_to_rollback": True}

    def fake_rollback(*_args: object, **kwargs: object) -> None:
        events.append(f"rollback:{kwargs['network_recovery_verified']}")

    monkeypatch.setattr(setup_cli, "recover_network", fake_recover)
    monkeypatch.setattr(setup_cli, "rollback", fake_rollback)
    args = setup_cli._parser().parse_args(["rollback", "--confirm-rollback"])

    assert setup_cli.dispatch(args, AuditLog(None)) == 0
    assert events == [
        "console:rollback",
        "state-bound",
        "recover",
        "rollback:True",
        "recover",
    ]


def test_cli_rollback_aborts_before_files_if_recovery_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(setup_cli, "require_proven_local_console", lambda _label: {})
    monkeypatch.setattr(
        setup_cli,
        "_require_saved_state_storage_binding",
        lambda _path: {},
    )
    monkeypatch.setattr(
        setup_cli,
        "recover_network",
        lambda **_kwargs: (_ for _ in ()).throw(UmzugError("recovery not proven")),
    )
    monkeypatch.setattr(
        setup_cli,
        "rollback",
        lambda *_args, **_kwargs: pytest.fail("rollback ran without recovery proof"),
    )
    args = setup_cli._parser().parse_args(["rollback", "--confirm-rollback"])

    with pytest.raises(UmzugError, match="not proven"):
        setup_cli.dispatch(args, AuditLog(None))


def test_executor_live_rollback_rejects_missing_network_recovery_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "must-not-be-created"
    monkeypatch.setattr(
        "umzug.executor.require_proven_local_console",
        lambda _label: {},
    )

    with pytest.raises(UmzugError, match="requires a positively verified"):
        rollback(state)

    assert not state.exists()


def test_rollback_dry_run_does_not_create_a_missing_checkpoint(
    tmp_path: Path,
) -> None:
    state = tmp_path / "must-remain-missing"

    with pytest.raises(UmzugError, match="does not exist for read-only"):
        rollback(state, system_root=tmp_path / "system", dry_run=True)

    assert not state.exists()
