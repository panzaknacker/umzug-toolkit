from __future__ import annotations

import json
import subprocess
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

import umzug.vpn as vpn
from umzug.util import AuditLog, UmzugError


def _receipt() -> dict[str, object]:
    path = Path("/usr/bin/true").resolve(strict=True)
    return vpn._observe_bound_executable(path)


def _bound_tools(*names: str) -> vpn.BoundExecutables:
    receipt = _receipt()
    return vpn.BoundExecutables({name: dict(receipt) for name in names})


def test_login_timeout_zeroes_mutable_account(monkeypatch: pytest.MonkeyPatch) -> None:
    account = bytearray(b"1234567890123456")

    def timeout(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired("mullvad", 120)

    monkeypatch.setattr(vpn, "_require_private_procfs", lambda: {"hidepid": "2"})
    monkeypatch.setattr(vpn, "_require_secret_entry_safety", lambda: {})
    monkeypatch.setattr(vpn.subprocess, "run", timeout)
    with pytest.raises(UmzugError, match="failed safely"):
        vpn._login_secret(account, _bound_tools("mullvad"))
    assert account == b"\0" * 16


def test_finalize_enables_fail_closed_settings_before_account_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, ...]] = []
    account_reference: list[bytearray] = []
    tools = _bound_tools(
        "curl",
        "mullvad",
        "nft",
        "systemctl",
        "dpkg",
        "dpkg-query",
        "ip",
        "rfkill",
        "resolvectl",
        "ss",
        "wg",
    )

    monkeypatch.setattr(vpn.os, "geteuid", lambda: 0)
    monkeypatch.setattr(vpn, "_require_management_restriction", lambda group, tools: None)
    monkeypatch.setattr(vpn, "_check_account_storage", lambda **kwargs: None)
    monkeypatch.setattr(vpn, "_require_private_procfs", lambda: {"hidepid": "2"})
    monkeypatch.setattr(vpn, "_require_secret_entry_safety", lambda: {"safe": True})
    monkeypatch.setattr(
        vpn,
        "_require_installed_mullvad_package",
        lambda manager, tools, **identity: {
            "package_manager": manager,
            **identity,
        },
    )

    def live_boundary(*args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        events.append(("offline-guard-proof",))
        events.append(("host-firewall-proof",))
        return {"fail_closed_boundary": "offline-guard"}

    monkeypatch.setattr(vpn, "_require_live_pre_mutation_boundary", live_boundary)
    monkeypatch.setattr(vpn, "_install_bootstrap_guard", lambda tools: events.append(("guard-install",)))
    monkeypatch.setattr(vpn, "_require_bootstrap_guard", lambda tools: events.append(("guard-proof",)))
    monkeypatch.setattr(vpn, "_remove_bootstrap_guard", lambda tools: events.append(("guard-remove",)))
    monkeypatch.setattr(vpn, "_guard_json", lambda *args, **kwargs: b"")
    monkeypatch.setattr(vpn, "_require_daemon_persistent", lambda tools: None)
    monkeypatch.setattr(vpn, "_require_mullvad_firewall", lambda tools: events.append(("mullvad-firewall-proof",)))
    monkeypatch.setattr(
        vpn,
        "_retire_offline_guard_under_bootstrap",
        lambda tools: events.append(("offline-guard-retire",)),
    )

    def command(tools: object, argv: list[str], *, required: bool = True) -> subprocess.CompletedProcess[bytes]:
        del tools
        events.append(tuple(argv))
        output = (
            b"Connected\n"
            if argv[:1] == ["status"]
            else b"Lockdown mode is on\n"
            if argv == ["lockdown-mode", "get"]
            else b""
        )
        return subprocess.CompletedProcess(argv, 0, output, b"")

    def prompt(prompt_text: str) -> str:
        events.append(("account-prompt",))
        return "1234567890123456"

    def login(account: bytearray, tools: object) -> None:
        del tools
        events.append(("account-login",))
        account_reference.append(account)

    monkeypatch.setattr(vpn, "_run_mullvad", command)
    monkeypatch.setattr(vpn.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(vpn.getpass, "getpass", prompt)
    monkeypatch.setattr(vpn, "_login_secret", login)
    storage_checks = {"count": 0}

    def storage_permissions() -> dict[str, object]:
        storage_checks["count"] += 1
        events.append(("account-storage-proof", str(storage_checks["count"])))
        return {"exists": storage_checks["count"] >= 2, "mode": "0o600"}

    monkeypatch.setattr(vpn, "_verify_account_history_permissions", storage_permissions)
    device_checks = {"count": 0}

    def device_permissions() -> dict[str, object]:
        device_checks["count"] += 1
        events.append(("device-storage-proof", str(device_checks["count"])))
        return {"exists": device_checks["count"] >= 2, "mode": "0o600"}

    monkeypatch.setattr(vpn, "_verify_device_permissions", device_permissions)
    monkeypatch.setattr(vpn, "_collect_bound_network_evidence", lambda *args, **kwargs: {})
    monkeypatch.setattr(vpn, "assert_final_network_evidence", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        vpn,
        "_prove_connected_dns_containment",
        lambda tools, interfaces: (
            events.append(("connected-dns-proof",)) or {"interfaces": interfaces, "blocked": True}
        ),
    )
    monkeypatch.setattr(
        vpn,
        "_collect_bound_mullvad_online_check",
        lambda tools: events.append(("online-check",)) or {"available": True, "exit": 0, "stdout": "connected"},
    )
    monkeypatch.setattr(
        vpn,
        "_prove_fail_closed_disconnect",
        lambda tools, interfaces: {"interfaces": interfaces, "blocked": True},
    )

    vpn.finalize_mullvad_app(
        bound_executables=tools,
        plan_sha256="a" * 64,
        ethernet_interfaces=["eth0"],
        ipv6_disabled=True,
        radios_blocked=True,
        package_manager="apt-get",
        vendor_package_version="2026.1",
        vendor_package_architecture="amd64",
        vendor_artifact_sha256="b" * 64,
        encrypted_storage=True,
        online_verification=True,
        audit=AuditLog(None),
    )

    prompt_index = events.index(("account-prompt",))
    for required_setting in (
        ("split-tunnel", "clear"),
        ("lan", "set", "block"),
        ("dns", "set", "default"),
        ("auto-connect", "set", "on"),
        ("lockdown-mode", "set", "on"),
        ("anti-censorship", "set", "mode", "auto"),
    ):
        assert events.index(required_setting) < prompt_index
    lockdown_index = events.index(("lockdown-mode", "set", "on"))
    assert events.index(("guard-install",)) < lockdown_index
    assert lockdown_index < events.index(("split-tunnel", "clear"))
    assert lockdown_index < events.index(("lan", "set", "block"))
    assert lockdown_index < events.index(("auto-connect", "set", "on"))
    assert events.index(("lockdown-mode", "get")) < events.index(("guard-remove",))
    assert events.index(("offline-guard-proof",)) < events.index(("account-prompt",))
    assert events.index(("offline-guard-retire",)) < events.index(("guard-remove",))
    assert events.index(("guard-remove",)) < prompt_index
    assert events.index(("account-storage-proof", "1")) < prompt_index
    assert events.index(("device-storage-proof", "1")) < prompt_index
    assert events.index(("account-login",)) < events.index(("connect",))
    assert events.index(("account-storage-proof", "2")) < events.index(("connect",))
    assert events.index(("device-storage-proof", "2")) < events.index(("connect",))
    proof_positions = [index for index, event in enumerate(events) if event == ("connected-dns-proof",)]
    online_positions = [index for index, event in enumerate(events) if event == ("online-check",)]
    assert len(proof_positions) == len(online_positions) == 2
    assert all(proof < online for proof, online in zip(proof_positions, online_positions))
    assert account_reference[0] == b"\0" * 16


@pytest.mark.parametrize("failure", ["missing", "changed"])
def test_finalize_rejects_unbound_or_changed_tool_before_prompt_or_mutation(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    names = {
        "mullvad",
        "nft",
        "systemctl",
        "dpkg",
        "dpkg-query",
        "ip",
        "resolvectl",
        "ss",
        "wg",
    }
    receipts = {name: dict(_receipt()) for name in names}
    if failure == "missing":
        del receipts["mullvad"]
    else:
        receipts["mullvad"]["sha256"] = "0" * 64
    tools = vpn.BoundExecutables(receipts)
    events: list[str] = []
    monkeypatch.setattr(vpn.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        vpn,
        "_require_live_pre_mutation_boundary",
        lambda *args, **kwargs: events.append("network-boundary"),
    )
    monkeypatch.setattr(
        vpn,
        "_install_bootstrap_guard",
        lambda *args, **kwargs: events.append("guard-mutation"),
    )
    monkeypatch.setattr(
        vpn.getpass,
        "getpass",
        lambda prompt: events.append("account-prompt") or "1234567890123456",
    )

    with pytest.raises(UmzugError, match="bound executable|lacks a bound"):
        vpn.finalize_mullvad_app(
            bound_executables=tools,
            plan_sha256="a" * 64,
            ethernet_interfaces=["eth0"],
            ipv6_disabled=True,
            radios_blocked=False,
            package_manager="apt-get",
            vendor_package_version="2026.1",
            vendor_package_architecture="amd64",
            vendor_artifact_sha256="b" * 64,
            encrypted_storage=True,
            online_verification=False,
        )
    assert events == []


def test_completed_vendor_only_plan_requires_every_finalization_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    digest = "a" * 64
    artifact_digest = "b" * 64
    artifact = "/approved/mullvad.deb"
    actions = [
        SimpleNamespace(
            id="host-firewall",
            operation="write_file",
            verify={
                "kind": "host_firewall",
                "interfaces": ["eth0"],
                "ipv6_enabled": False,
            },
            parameters={},
        ),
        SimpleNamespace(
            id="offline-guard",
            operation="write_file",
            verify={"kind": "offline_guard"},
            parameters={},
        ),
        SimpleNamespace(
            id="mullvad-management-group",
            operation="ensure_group",
            verify={"kind": "restricted_group", "name": "mullvad-management"},
            parameters={"name": "mullvad-management"},
        ),
        SimpleNamespace(
            id="mullvad-management-socket",
            operation="write_file",
            verify={},
            parameters={},
        ),
        SimpleNamespace(
            id="mullvad-offline-install",
            operation="run_command",
            verify={
                "kind": "mullvad_version",
                "manager": "dpkg",
                "package": "mullvad-vpn",
                "version": "2026.1",
                "architecture": "amd64",
                "management_group": "mullvad-management",
            },
            parameters={
                "argv": [
                    "apt-get",
                    "install",
                    "--yes",
                    "--reinstall",
                    "--no-download",
                    "--no-install-recommends",
                    "--",
                    artifact,
                ],
                "required_file_hashes": {artifact: artifact_digest},
                "post_install_argvs": [
                    ["systemctl", "daemon-reload"],
                    ["systemctl", "restart", "mullvad-daemon.service"],
                ],
            },
        ),
    ]
    for unit in ("ssh.service", "sshd.service", "ssh.socket", "sshd.socket"):
        actions.append(
            SimpleNamespace(
                id=f"disable-{unit}",
                operation="disable_service",
                verify={},
                parameters={"name": unit},
            )
        )
    fake_plan = SimpleNamespace(
        profile="strict",
        actions=actions,
        digest=lambda: digest,
    )
    monkeypatch.setattr(
        vpn.Plan,
        "from_dict",
        classmethod(lambda cls, value: fake_plan),
    )
    monkeypatch.setattr(vpn, "_verify_private_input_snapshot", lambda *args, **kwargs: None)
    required = vpn._required_finalization_executables(
        "apt-get",
        radios_blocked=False,
        online_verification=False,
    )
    state = {
        "plan_digest": digest,
        "profile": "strict",
        "pending_reboot": None,
        "rolled_back_at": None,
        "completed": [action.id for action in actions],
        "executables": {name: dict(_receipt()) for name in required},
    }
    tmp_path.chmod(0o700)
    (tmp_path / "plan.json").write_text("{}", encoding="utf-8")
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")
    (tmp_path / "plan.json").chmod(0o600)
    (tmp_path / "state.json").chmod(0o600)

    context = vpn._load_completed_plan_context(
        tmp_path,
        digest,
        owner_uid=vpn.os.geteuid(),
    )
    assert context["vendor_package_version"] == "2026.1"
    assert context["vendor_package_architecture"] == "amd64"
    assert Path(context["bound_executables"].path("dpkg-query")).is_absolute()

    del state["executables"]["dpkg-query"]
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")
    (tmp_path / "state.json").chmod(0o600)
    with pytest.raises(UmzugError, match="lacks a bound executable receipt: dpkg-query"):
        vpn._load_completed_plan_context(
            tmp_path,
            digest,
            owner_uid=vpn.os.geteuid(),
        )


def test_radio_drift_aborts_finalize_before_guard_daemon_or_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools(
        "mullvad",
        "nft",
        "systemctl",
        "dpkg",
        "dpkg-query",
        "ip",
        "rfkill",
        "resolvectl",
        "ss",
        "wg",
    )
    events: list[str] = []
    monkeypatch.setattr(vpn.os, "geteuid", lambda: 0)
    monkeypatch.setattr(vpn, "_check_account_storage", lambda **kwargs: None)
    monkeypatch.setattr(
        vpn,
        "_require_bound_ethernet_hardware",
        lambda interfaces: {"physical_ethernet": interfaces},
    )
    monkeypatch.setattr(vpn, "_require_units_contained", lambda *args: {})
    monkeypatch.setattr(vpn, "_require_no_listening_ssh", lambda: {})
    monkeypatch.setattr(vpn, "_require_ipv6_off", lambda: {})

    def radio_drift(*args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        events.append("radio-proof")
        raise UmzugError("a radio is soft-unblocked before VPN finalization")

    monkeypatch.setattr(vpn, "_require_radios_off", radio_drift)
    monkeypatch.setattr(
        vpn,
        "_require_initial_fail_closed_boundary",
        lambda tools: events.append("guard-proof") or "offline-guard",
    )
    monkeypatch.setattr(
        vpn,
        "_install_bootstrap_guard",
        lambda tools: events.append("guard-mutation"),
    )
    monkeypatch.setattr(
        vpn,
        "_run_mullvad",
        lambda *args, **kwargs: events.append("daemon-command"),
    )
    monkeypatch.setattr(
        vpn.getpass,
        "getpass",
        lambda prompt: events.append("account-prompt") or "1234567890123456",
    )

    with pytest.raises(UmzugError, match="soft-unblocked"):
        vpn.finalize_mullvad_app(
            bound_executables=tools,
            plan_sha256="a" * 64,
            ethernet_interfaces=["eth0"],
            ipv6_disabled=True,
            radios_blocked=True,
            package_manager="apt-get",
            vendor_package_version="2026.1",
            vendor_package_architecture="amd64",
            vendor_artifact_sha256="b" * 64,
            encrypted_storage=True,
            online_verification=False,
        )
    assert events == ["radio-proof"]


def test_live_boundary_helpers_detect_ipv6_ssh_and_ethernet_drift(
    tmp_path: Path,
) -> None:
    sysctl_root = tmp_path / "ipv6"
    for name in ("all", "default", "lo"):
        path = sysctl_root / name / "disable_ipv6"
        path.parent.mkdir(parents=True)
        path.write_text("1\n", encoding="ascii")
    addresses = tmp_path / "if_inet6"
    addresses.write_text("", encoding="ascii")
    assert (
        vpn._require_ipv6_off(
            sysctl_root=sysctl_root,
            addresses_path=addresses,
        )["addresses"]
        == 0
    )
    addresses.write_text("00000000000000000000000000000001 01 80 10 80 lo\n", encoding="ascii")
    with pytest.raises(UmzugError, match="IPv6 addresses remain"):
        vpn._require_ipv6_off(
            sysctl_root=sysctl_root,
            addresses_path=addresses,
        )

    tcp4 = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    header = "  sl  local_address rem_address   st\n"
    tcp4.write_text(header, encoding="ascii")
    tcp6.write_text(
        header + "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A\n",
        encoding="ascii",
    )
    with pytest.raises(UmzugError, match="SSH port 22"):
        vpn._require_no_listening_ssh((tcp4, tcp6))

    net_root = tmp_path / "net"
    ethernet = net_root / "eth0"
    (ethernet / "device").mkdir(parents=True)
    (ethernet / "type").write_text("1\n", encoding="ascii")
    virtual = net_root / "docker0"
    virtual.mkdir()
    (virtual / "type").write_text("1\n", encoding="ascii")
    assert vpn._require_bound_ethernet_hardware(
        ["eth0"],
        net_root=net_root,
    ) == {"physical_ethernet": ["eth0"]}
    extra = net_root / "eth1"
    (extra / "device").mkdir(parents=True)
    (extra / "type").write_text("1\n", encoding="ascii")
    with pytest.raises(UmzugError, match="hardware drifted"):
        vpn._require_bound_ethernet_hardware(["eth0"], net_root=net_root)


def test_direct_mullvad_and_rfkill_calls_use_receipt_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tools = _bound_tools("mullvad", "rfkill")
    commands: list[list[str]] = []

    def command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        commands.append(argv)
        output = b"Soft blocked: no\n" if argv[1:] == ["list"] else b""
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(vpn, "run", command)
    vpn._run_mullvad(tools, ["status", "-v"])
    with pytest.raises(UmzugError, match="soft-unblocked"):
        vpn._require_radios_off(tools, rfkill_root=tmp_path)
    assert commands[0][0] == tools.path("mullvad")
    assert commands[1][0] == tools.path("rfkill")
    assert all(Path(argv[0]).is_absolute() for argv in commands)


def test_final_evidence_never_resolves_commands_through_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = {
        "ip",
        "mullvad",
        "nft",
        "resolvectl",
        "ss",
        "systemctl",
        "wg",
    }
    tools = _bound_tools(*names)
    commands: list[list[str]] = []

    def command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        commands.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(vpn, "run", command)
    monkeypatch.setattr(
        vpn,
        "_read_stable_resolv_conf",
        lambda: "nameserver 10.64.0.1\n",
    )
    vpn._collect_bound_network_evidence(
        tools,
        radios_blocked=False,
    )
    assert commands
    assert {argv[0] for argv in commands} == {tools.path(name) for name in names}
    assert all(Path(argv[0]).is_absolute() for argv in commands)


def test_final_evidence_routes_each_literal_resolver_with_bound_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = {
        "ip",
        "mullvad",
        "nft",
        "resolvectl",
        "ss",
        "systemctl",
        "wg",
    }
    tools = _bound_tools(*names)
    commands: list[list[str]] = []
    status = b"Global\n       Current DNS Server: 10.64.0.1\n"

    def command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        commands.append(argv)
        arguments = argv[1:]
        if arguments == ["status"]:
            output = status
        elif arguments == ["show", "interfaces"]:
            output = b"wg-mullvad\n"
        elif arguments[:4] in (["-j", "-4", "route", "get"],):
            address = arguments[4]
            device = "lo" if address.startswith("127.") else "wg-mullvad"
            output = json.dumps([{"dst": address, "dev": device}]).encode()
        else:
            output = b""
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(vpn, "run", command)
    monkeypatch.setattr(
        vpn,
        "_read_stable_resolv_conf",
        lambda: "nameserver 127.0.0.53\n",
    )
    evidence = vpn._collect_bound_network_evidence(
        tools,
        radios_blocked=False,
    )

    route_commands = [argv for argv in commands if argv[1:5] == ["-j", "-4", "route", "get"]]
    assert [argv[5] for argv in route_commands] == ["10.64.0.1", "127.0.0.53"]
    assert all(argv[6:] == ["uid", "0"] for argv in route_commands)
    assert all(argv[0] == tools.path("ip") for argv in route_commands)
    assert evidence["resolver_routes"]["available"] is True


def test_static_resolv_conf_collects_routes_without_resolvectl_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = {"ip", "mullvad", "nft", "ss", "systemctl", "wg"}
    tools = _bound_tools(*names)
    commands: list[list[str]] = []

    def command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        commands.append(argv)
        arguments = argv[1:]
        if arguments == ["show", "interfaces"]:
            output = b"wg-mullvad\n"
        elif arguments[:4] == ["-j", "-4", "route", "get"]:
            output = json.dumps([{"dst": arguments[4], "dev": "wg-mullvad"}]).encode()
        else:
            output = b""
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(vpn, "run", command)
    monkeypatch.setattr(
        vpn,
        "_read_stable_resolv_conf",
        lambda: "nameserver 10.64.0.1\n",
    )
    evidence = vpn._collect_bound_network_evidence(
        tools,
        radios_blocked=False,
    )

    assert evidence["dns"] == {"available": False}
    assert not any(argv[1:] == ["status"] for argv in commands)
    assert all(Path(argv[0]).is_absolute() for argv in commands)
    assert "resolvectl" not in vpn._required_finalization_executables(
        "apt-get",
        radios_blocked=False,
        online_verification=False,
    )


def test_final_package_provenance_rejects_version_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools("mullvad", "dpkg", "dpkg-query")
    commands: list[list[str]] = []

    def command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        commands.append(argv)
        if "--search" in argv:
            output = f"mullvad-vpn: {tools.path('mullvad')}\n".encode()
        elif any("Version" in item for item in argv):
            output = b"mullvad-vpn\t2026.2\tamd64\tii \n"
        else:
            output = b"mullvad-vpn\tii \n"
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(vpn, "run", command)
    with pytest.raises(UmzugError, match="differs from the reviewed version"):
        vpn._require_installed_mullvad_package(
            "apt-get",
            tools,
            expected_version="2026.1",
            expected_architecture="amd64",
        )
    assert commands
    assert all(Path(argv[0]).is_absolute() for argv in commands)


def test_final_rpm_provenance_uses_bound_rpm_and_exact_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools("mullvad", "rpm")
    commands: list[list[str]] = []

    def command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        commands.append(argv)
        if "--file" in argv:
            output = b"mullvad-vpn\n"
        elif "--query" in argv:
            output = b"mullvad-vpn\t2026.1-1\tx86_64\n"
        else:
            output = b""
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(vpn, "run", command)
    result = vpn._require_installed_mullvad_package(
        "rpm",
        tools,
        expected_version="2026.1-1",
        expected_architecture="x86_64",
    )
    assert result["version"] == "2026.1-1"
    assert commands
    assert all(argv[0] == tools.path("rpm") for argv in commands)


def test_initial_boundary_can_resume_from_bootstrap_or_mullvad(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools("mullvad", "nft")
    monkeypatch.setattr(
        vpn,
        "_require_offline_guard",
        lambda tools: (_ for _ in ()).throw(UmzugError("absent")),
    )
    monkeypatch.setattr(vpn, "_require_bootstrap_guard", lambda tools: None)
    assert vpn._require_initial_fail_closed_boundary(tools) == "bootstrap-guard"

    monkeypatch.setattr(
        vpn,
        "_require_bootstrap_guard",
        lambda tools: (_ for _ in ()).throw(UmzugError("absent")),
    )
    monkeypatch.setattr(vpn, "_require_lockdown_enabled", lambda tools: None)
    monkeypatch.setattr(vpn, "_require_mullvad_firewall", lambda tools: None)
    assert vpn._require_initial_fail_closed_boundary(tools) == "mullvad-lockdown"


def test_failure_recovery_restores_persistent_offline_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, ...]] = []
    tools = _bound_tools("nft", "systemctl")
    monkeypatch.setattr(vpn, "_install_bootstrap_guard", lambda tools: events.append(("bootstrap",)))
    monkeypatch.setattr(vpn, "_require_bootstrap_guard", lambda tools: events.append(("bootstrap-proof",)))
    monkeypatch.setattr(vpn, "_require_offline_guard", lambda tools: events.append(("offline-proof",)))

    def command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        events.append(tuple(argv))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(vpn, "run", command)
    vpn._restore_persistent_offline_guard(tools)
    assert (
        tools.path("systemctl"),
        "enable",
        "--now",
        vpn.OFFLINE_GUARD_SERVICE,
    ) in events
    assert events[-2:] == [("offline-proof",), ("bootstrap-proof",)]


def test_account_entry_is_forbidden_without_encrypted_root_storage() -> None:
    with pytest.raises(UmzugError, match="account entry is forbidden"):
        vpn._check_account_storage(encrypted_storage=False)


def _mock_sensitive_mullvad_metadata(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: int = stat.S_IFREG | 0o600,
    nlink: int = 1,
    size: int = 128,
) -> None:
    directory = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
    target = SimpleNamespace(
        st_uid=0,
        st_gid=0,
        st_mode=mode,
        st_nlink=nlink,
        st_size=size,
    )
    monkeypatch.setattr(vpn, "_open_root_control_directory", lambda path: 10)
    monkeypatch.setattr(vpn.os, "open", lambda *args, **kwargs: 11)
    monkeypatch.setattr(vpn.os, "fstat", lambda fd: directory if fd == 10 else target)
    monkeypatch.setattr(vpn.os, "close", lambda fd: None)


def test_sensitive_mullvad_state_accepts_only_private_regular_single_link_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_sensitive_mullvad_metadata(monkeypatch)
    evidence = vpn._verify_sensitive_mullvad_file_permissions("device.json")
    assert evidence["exists"] is True
    assert evidence["mode"] == "0o600"


@pytest.mark.parametrize(
    ("mode", "nlink", "size"),
    [
        (stat.S_IFREG | 0o644, 1, 128),
        (stat.S_IFREG | 0o700, 1, 128),
        (stat.S_IFREG | 0o600, 2, 128),
        (stat.S_IFLNK | 0o600, 1, 128),
        (stat.S_IFREG | 0o600, 1, 1024 * 1024 + 1),
    ],
)
def test_sensitive_mullvad_state_rejects_unsafe_metadata(
    monkeypatch: pytest.MonkeyPatch,
    mode: int,
    nlink: int,
    size: int,
) -> None:
    _mock_sensitive_mullvad_metadata(
        monkeypatch,
        mode=mode,
        nlink=nlink,
        size=size,
    )
    with pytest.raises(UmzugError, match="not a single-link root-owned"):
        vpn._verify_sensitive_mullvad_file_permissions("device.json")


def test_daemon_environment_parser_and_policy_reject_path_and_security_overrides() -> None:
    expected = b"MULLVAD_MANAGEMENT_SOCKET_GROUP=umzug-mullvad\0"
    parsed = vpn._parse_nul_environment(expected + b"INVOCATION_ID=abc\0")
    vpn._validate_mullvad_daemon_environment(parsed, "umzug-mullvad")

    for override in (
        b"MULLVAD_SETTINGS_DIR=/var\0",
        b"MULLVAD_RPC_SOCKET_PATH=/tmp/socket\0",
        b"TALPID_DISABLE_OFFLINE_MONITOR=1\0",
        b"MULLVAD_API_DISABLE_TLS=1\0",
        b"LD_PRELOAD=/tmp/evil.so\0",
        b"HTTPS_PROXY=http://127.0.0.1:8080\0",
    ):
        environment = vpn._parse_nul_environment(expected + override)
        with pytest.raises(UmzugError, match="unreviewed security-relevant"):
            vpn._validate_mullvad_daemon_environment(environment, "umzug-mullvad")


def test_daemon_environment_parser_rejects_duplicate_or_unterminated_entries() -> None:
    with pytest.raises(UmzugError, match="NUL terminated"):
        vpn._parse_nul_environment(b"A=B")
    with pytest.raises(UmzugError, match="unsafe key"):
        vpn._parse_nul_environment(b"A=B\0A=C\0")


def test_core_dump_gate_accepts_only_empty_global_policy(tmp_path: Path) -> None:
    pattern = tmp_path / "core_pattern"
    uses_pid = tmp_path / "core_uses_pid"
    pattern.write_text("\n", encoding="utf-8")
    uses_pid.write_text("0\n", encoding="utf-8")

    assert vpn._require_core_dump_disabled(pattern, uses_pid) == {
        "core_pattern": "empty",
        "core_uses_pid": 0,
    }

    pattern.write_text("|/usr/lib/systemd/systemd-coredump\n", encoding="utf-8")
    with pytest.raises(UmzugError, match="globally disabled core dumps"):
        vpn._require_core_dump_disabled(pattern, uses_pid)


def test_account_entry_rejects_every_active_swap(tmp_path: Path) -> None:
    swaps = tmp_path / "swaps"
    swaps.write_text("Filename\tType\tSize\tUsed\tPriority\n", encoding="utf-8")
    assert vpn._require_no_active_swap(swaps) == {"active_swap_entries": 0}

    swaps.write_text(
        "Filename\tType\tSize\tUsed\tPriority\n/dev/dm-1 partition 1024 0 -2\n",
        encoding="utf-8",
    )
    with pytest.raises(UmzugError, match="all swap to be inactive"):
        vpn._require_no_active_swap(swaps)


def test_secret_process_hardening_requires_zero_limits_and_nondumpable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(vpn.resource, "setrlimit", lambda kind, value: calls.append((kind, value[0])))
    monkeypatch.setattr(vpn.resource, "getrlimit", lambda kind: (0, 0))

    def prctl(option: int, argument: int = 0) -> int:
        calls.append((option, argument))
        return 0

    monkeypatch.setattr(vpn, "_prctl", prctl)
    assert vpn._harden_secret_process()["dumpable"] is False
    assert (vpn.resource.RLIMIT_CORE, 0) in calls
    assert (vpn.PR_SET_DUMPABLE, 0) in calls


def test_procfs_privacy_requires_hidepid_without_group_bypass(tmp_path: Path) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "36 25 0:32 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=2\n",
        encoding="utf-8",
    )
    assert vpn._require_private_procfs(mountinfo)["hidepid"] == "2"

    mountinfo.write_text(
        "36 25 0:32 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw,hidepid=invisible\n",
        encoding="utf-8",
    )
    assert vpn._require_private_procfs(mountinfo)["hidepid"] == "invisible"


@pytest.mark.parametrize(
    "options",
    [
        "rw",
        "rw,hidepid=1",
        "rw,hidepid=2,gid=42",
    ],
)
def test_procfs_privacy_rejects_visible_or_bypassed_processes(
    tmp_path: Path,
    options: str,
) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        f"36 25 0:32 / /proc rw,nosuid,nodev,noexec - proc proc {options}\n",
        encoding="utf-8",
    )
    with pytest.raises(UmzugError, match="hidepid=2"):
        vpn._require_private_procfs(mountinfo)


def test_management_override_enforces_private_daemon_umask() -> None:
    assert vpn.management_override("mullvad-management") == (
        "[Service]\nEnvironment=\nEnvironment=MULLVAD_MANAGEMENT_SOCKET_GROUP=mullvad-management\nUMask=0077\n"
    )


def test_connected_state_probes_every_physical_nic_and_literal_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools("mullvad", "nft")
    udp_calls: list[tuple[str, str]] = []
    tcp_calls: list[tuple[str, str, int]] = []
    monkeypatch.setattr(
        vpn,
        "_wait_for_mullvad_status",
        lambda tools, **kwargs: b"Connected\n",
    )
    monkeypatch.setattr(vpn, "_require_lockdown_enabled", lambda tools: None)
    monkeypatch.setattr(vpn, "_require_mullvad_firewall", lambda tools: None)

    def udp(interface: str, address: str) -> dict[str, object]:
        udp_calls.append((interface, address))
        return {
            "interface": interface,
            "destination": f"{address}:53/udp",
            "blocked": True,
        }

    def tcp(interface: str, address: str, port: int) -> dict[str, object]:
        tcp_calls.append((interface, address, port))
        return {
            "interface": interface,
            "destination": f"{address}:{port}/tcp",
            "blocked": True,
        }

    monkeypatch.setattr(vpn, "_probe_udp_dns", udp)
    monkeypatch.setattr(vpn, "_probe_tcp_connect", tcp)
    proof = vpn._prove_connected_dns_containment(tools, ["eth1", "eth0"])

    expected_udp = [
        (interface, resolver) for interface in ("eth0", "eth1") for resolver in vpn.CONNECTED_DNS_PROBE_RESOLVERS
    ]
    assert udp_calls == expected_udp
    assert tcp_calls == [(*call, 53) for call in expected_udp]
    assert proof["literal_resolvers"] == list(vpn.CONNECTED_DNS_PROBE_RESOLVERS)
    assert len(proof["physical_dns_probes"]) == 12
    assert "not a proof" in str(proof["scope"])


def test_connected_state_fails_on_direct_physical_udp_dns_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools("mullvad", "nft")
    monkeypatch.setattr(
        vpn,
        "_wait_for_mullvad_status",
        lambda tools, **kwargs: b"Connected\n",
    )
    monkeypatch.setattr(vpn, "_require_lockdown_enabled", lambda tools: None)
    monkeypatch.setattr(vpn, "_require_mullvad_firewall", lambda tools: None)
    monkeypatch.setattr(
        vpn,
        "_probe_udp_dns",
        lambda interface, address: {
            "interface": interface,
            "destination": f"{address}:53/udp",
            "blocked": address != "8.8.8.8",
        },
    )
    monkeypatch.setattr(
        vpn,
        "_probe_tcp_connect",
        lambda interface, address, port: {
            "interface": interface,
            "destination": f"{address}:{port}/tcp",
            "blocked": True,
        },
    )

    with pytest.raises(UmzugError, match="connected Mullvad state leaked direct UDP/DNS"):
        vpn._prove_connected_dns_containment(tools, ["eth0"])


def test_connected_state_fails_on_direct_physical_tcp_dns_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools("mullvad", "nft")
    monkeypatch.setattr(
        vpn,
        "_wait_for_mullvad_status",
        lambda tools, **kwargs: b"Connected\n",
    )
    monkeypatch.setattr(vpn, "_require_lockdown_enabled", lambda tools: None)
    monkeypatch.setattr(vpn, "_require_mullvad_firewall", lambda tools: None)
    monkeypatch.setattr(
        vpn,
        "_probe_udp_dns",
        lambda interface, address: {
            "interface": interface,
            "destination": f"{address}:53/udp",
            "blocked": True,
        },
    )
    monkeypatch.setattr(
        vpn,
        "_probe_tcp_connect",
        lambda interface, address, port: {
            "interface": interface,
            "destination": f"{address}:{port}/tcp",
            "blocked": address != "9.9.9.9",
        },
    )

    with pytest.raises(UmzugError, match="connected Mullvad state leaked direct TCP/DNS"):
        vpn._prove_connected_dns_containment(tools, ["eth0"])


def test_controlled_disconnect_proves_direct_ethernet_probe_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools("mullvad", "nft")
    state = {"connected": True}
    commands: list[tuple[str, ...]] = []

    def mullvad(tools: object, argv: list[str], *, required: bool = True) -> subprocess.CompletedProcess[bytes]:
        del tools
        del required
        commands.append(tuple(argv))
        if argv == ["disconnect"]:
            state["connected"] = False
        elif argv == ["connect"]:
            state["connected"] = True
        output = (
            b"Connected\n"
            if argv[:1] == ["status"] and state["connected"]
            else b"Disconnected; Lockdown mode blocking traffic\n"
            if argv[:1] == ["status"]
            else b""
        )
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(vpn, "_run_mullvad", mullvad)
    monkeypatch.setattr(vpn, "_require_lockdown_enabled", lambda tools: None)
    monkeypatch.setattr(vpn, "_require_mullvad_firewall", lambda tools: None)
    monkeypatch.setattr(
        vpn,
        "_probe_tcp_connect",
        lambda interface, address, port: {
            "interface": interface,
            "destination": f"{address}:{port}/tcp",
            "connected": False,
            "blocked": True,
            "error": "TimeoutError",
        },
    )
    monkeypatch.setattr(
        vpn,
        "_probe_udp_dns",
        lambda interface, address: {
            "interface": interface,
            "destination": f"{address}:53/udp",
            "response_bytes": 0,
            "blocked": True,
            "error": "TimeoutError",
        },
    )

    proof = vpn._prove_fail_closed_disconnect(tools, ["eth0"])

    assert proof["direct_egress_probes"] == [
        {
            "interface": "eth0",
            "destination": "1.1.1.1:80/tcp",
            "connected": False,
            "blocked": True,
            "error": "TimeoutError",
        },
        {
            "interface": "eth0",
            "destination": "1.1.1.1:443/tcp",
            "connected": False,
            "blocked": True,
            "error": "TimeoutError",
        },
        {
            "interface": "eth0",
            "destination": "1.1.1.1:53/udp",
            "response_bytes": 0,
            "blocked": True,
            "error": "TimeoutError",
        },
    ]
    assert ("disconnect",) in commands
    assert ("connect",) in commands


def test_controlled_disconnect_fails_on_any_direct_ethernet_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools("mullvad", "nft")
    state = {"connected": True}
    reconnected = False

    def mullvad(tools: object, argv: list[str], *, required: bool = True) -> subprocess.CompletedProcess[bytes]:
        nonlocal reconnected
        del tools, required
        if argv == ["disconnect"]:
            state["connected"] = False
        elif argv == ["connect"]:
            state["connected"] = True
            reconnected = True
        output = b"Connected\n" if state["connected"] else b"Disconnected\n"
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(vpn, "_run_mullvad", mullvad)
    monkeypatch.setattr(vpn, "_require_lockdown_enabled", lambda tools: None)
    monkeypatch.setattr(vpn, "_require_mullvad_firewall", lambda tools: None)
    monkeypatch.setattr(
        vpn,
        "_probe_tcp_connect",
        lambda interface, address, port: {
            "interface": interface,
            "destination": f"{address}:{port}/tcp",
            "connected": True,
            "blocked": False,
        },
    )

    with pytest.raises(UmzugError, match="leaked direct physical egress"):
        vpn._prove_fail_closed_disconnect(tools, ["eth0"])
    assert reconnected is True


def test_controlled_disconnect_fails_on_direct_udp_dns_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = _bound_tools("mullvad", "nft")
    state = {"connected": True}
    reconnected = False

    def mullvad(tools: object, argv: list[str], *, required: bool = True) -> subprocess.CompletedProcess[bytes]:
        nonlocal reconnected
        del tools, required
        if argv == ["disconnect"]:
            state["connected"] = False
        elif argv == ["connect"]:
            state["connected"] = True
            reconnected = True
        output = b"Connected\n" if state["connected"] else b"Disconnected\n"
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(vpn, "_run_mullvad", mullvad)
    monkeypatch.setattr(vpn, "_require_lockdown_enabled", lambda tools: None)
    monkeypatch.setattr(vpn, "_require_mullvad_firewall", lambda tools: None)
    monkeypatch.setattr(
        vpn,
        "_probe_tcp_connect",
        lambda interface, address, port: {
            "interface": interface,
            "destination": f"{address}:{port}/tcp",
            "connected": False,
            "blocked": True,
            "error": "TimeoutError",
        },
    )
    monkeypatch.setattr(
        vpn,
        "_probe_udp_dns",
        lambda interface, address: {
            "interface": interface,
            "destination": f"{address}:53/udp",
            "response_bytes": 64,
            "blocked": False,
        },
    )

    with pytest.raises(UmzugError, match="leaked direct UDP/DNS egress"):
        vpn._prove_fail_closed_disconnect(tools, ["eth0"])
    assert reconnected is True


def test_udp_probe_treats_every_received_datagram_as_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Probe:
        def settimeout(self, timeout: int) -> None:
            del timeout

        def setsockopt(self, *args: object) -> None:
            del args

        def connect(self, destination: tuple[str, int]) -> None:
            del destination

        def send(self, payload: bytes) -> int:
            return len(payload)

        def recv(self, size: int) -> bytes:
            del size
            return b"bad"

        def close(self) -> None:
            return None

    monkeypatch.setattr(vpn.socket, "socket", lambda *args: Probe())
    result = vpn._probe_udp_dns("eth0", "1.1.1.1")
    assert result["blocked"] is False
    assert result["traffic_observed"] is True
    assert result["response_bytes"] == 3


def test_tcp_probe_treats_connection_refusal_as_observed_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Probe:
        def settimeout(self, timeout: int) -> None:
            del timeout

        def setsockopt(self, *args: object) -> None:
            del args

        def connect(self, destination: tuple[str, int]) -> None:
            del destination
            raise ConnectionRefusedError(vpn.errno.ECONNREFUSED, "refused")

        def close(self) -> None:
            return None

    monkeypatch.setattr(vpn.socket, "socket", lambda *args: Probe())
    result = vpn._probe_tcp_connect("eth0", "1.1.1.1", 443)
    assert result["blocked"] is False
    assert result["traffic_observed"] is True


def test_management_group_may_not_delegate_to_explicit_non_root_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        vpn.grp,
        "getgrnam",
        lambda _name: SimpleNamespace(gr_gid=555, gr_mem=["alice"]),
    )
    monkeypatch.setattr(vpn.pwd, "getpwall", lambda: [])
    with pytest.raises(UmzugError, match="non-root members"):
        vpn._require_management_restriction(
            "mullvad-management",
            _bound_tools("systemctl"),
        )


def test_management_group_may_not_delegate_via_primary_gid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        vpn.grp,
        "getgrnam",
        lambda _name: SimpleNamespace(gr_gid=555, gr_mem=[]),
    )
    monkeypatch.setattr(
        vpn.pwd,
        "getpwall",
        lambda: [SimpleNamespace(pw_name="bob", pw_gid=555, pw_uid=1000)],
    )
    with pytest.raises(UmzugError, match="non-root members"):
        vpn._require_management_restriction(
            "mullvad-management",
            _bound_tools("systemctl"),
        )
