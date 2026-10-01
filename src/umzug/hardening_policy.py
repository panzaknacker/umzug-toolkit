from __future__ import annotations

from typing import Any, Mapping

from .actions import Action
from .network import (
    assert_no_ssh_exposure,
    firewall_systemd_unit,
    host_firewall_rules,
    offline_guard_rules,
    offline_guard_systemd_unit,
    recovery_script,
)
from .util import UmzugError


BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "compatible": {
        "disable_ipv6": False,
        "disable_radios": False,
        "blacklist_radio_modules": False,
        "firewall": True,
        "vpn_killswitch": False,
        "sudo_timestamp_minutes": 5,
    },
    "strict": {
        "disable_ipv6": True,
        "disable_radios": True,
        "blacklist_radio_modules": False,
        "firewall": True,
        "vpn_killswitch": True,
        "sudo_timestamp_minutes": 0,
    },
    "maximal": {
        "disable_ipv6": True,
        "disable_radios": True,
        "blacklist_radio_modules": True,
        "firewall": True,
        "vpn_killswitch": True,
        "sudo_timestamp_minutes": 0,
    },
}


def validate_profile(profile: Mapping[str, Any]) -> dict[str, Any]:
    profile = dict(profile)
    if profile.get("name") not in BUILTIN_PROFILES:
        raise UmzugError("profile name must be compatible, strict, or maximal")
    allowed = {
        "name",
        "disable_ipv6",
        "disable_radios",
        "blacklist_radio_modules",
        "firewall",
        "vpn_killswitch",
        "sudo_timestamp_minutes",
    }
    unknown = sorted(set(profile) - allowed)
    missing = sorted(allowed - set(profile))
    if unknown:
        raise UmzugError(f"unknown hardening profile fields: {', '.join(unknown)}")
    if missing:
        raise UmzugError(f"missing hardening profile fields: {', '.join(missing)}")
    for key in ("disable_ipv6", "disable_radios", "blacklist_radio_modules", "firewall", "vpn_killswitch"):
        if not isinstance(profile.get(key), bool):
            raise UmzugError(f"profile field {key} must be boolean")
    if profile["firewall"] is not True:
        raise UmzugError("all shipped hardening profiles require the no-inbound-service firewall")
    if profile.get("sudo_timestamp_minutes") not in {0, 5, 15}:
        raise UmzugError("sudo_timestamp_minutes must be 0, 5, or 15")
    if profile["name"] in {"strict", "maximal"} and (
        profile["disable_ipv6"] is not True
        or profile["disable_radios"] is not True
        or profile["vpn_killswitch"] is not True
        or profile["sudo_timestamp_minutes"] != 0
    ):
        raise UmzugError("strict and maximal profiles may not weaken their mandatory security floor")
    if profile["name"] == "maximal" and profile["blacklist_radio_modules"] is not True:
        raise UmzugError("maximal profile must blacklist explicitly detected radio modules")
    return profile


def _sysctl(profile: dict[str, Any]) -> str:
    values: dict[str, int | str] = {
        "fs.protected_fifos": 2,
        "fs.protected_hardlinks": 1,
        "fs.protected_regular": 2,
        "fs.protected_symlinks": 1,
        "kernel.dmesg_restrict": 1,
        "kernel.kptr_restrict": 2,
        "kernel.perf_event_paranoid": 3,
        "kernel.randomize_va_space": 2,
        "kernel.unprivileged_bpf_disabled": 1,
        "kernel.yama.ptrace_scope": 1,
        "net.core.bpf_jit_harden": 2,
        "net.ipv4.conf.all.accept_redirects": 0,
        "net.ipv4.conf.all.accept_source_route": 0,
        "net.ipv4.conf.all.log_martians": 1,
        "net.ipv4.conf.all.rp_filter": 2,
        "net.ipv4.conf.all.secure_redirects": 0,
        "net.ipv4.conf.all.send_redirects": 0,
        "net.ipv4.conf.all.src_valid_mark": 1,
        "net.ipv4.conf.default.accept_redirects": 0,
        "net.ipv4.conf.default.accept_source_route": 0,
        "net.ipv4.conf.default.log_martians": 1,
        "net.ipv4.conf.default.rp_filter": 2,
        "net.ipv4.conf.default.secure_redirects": 0,
        "net.ipv4.icmp_echo_ignore_broadcasts": 1,
        "net.ipv4.icmp_ignore_bogus_error_responses": 1,
    }
    if profile["disable_ipv6"]:
        values.update(
            {
                "net.ipv6.conf.all.disable_ipv6": 1,
                "net.ipv6.conf.default.disable_ipv6": 1,
                "net.ipv6.conf.lo.disable_ipv6": 1,
            }
        )
    if profile["vpn_killswitch"]:
        # the final account step refuses piped/systemd core dumps because the
        # kernel ignores RLIMIT_CORE for pipe handlers.  empty is an
        # intentional sysctl value, not an omitted placeholder.
        values.update(
            {
                "fs.suid_dumpable": 0,
                "kernel.core_pattern": "",
                "kernel.core_uses_pid": 0,
            }
        )
    if profile["name"] == "maximal":
        values.update(
            {
                "dev.tty.ldisc_autoload": 0,
                "kernel.kexec_load_disabled": 1,
                "kernel.perf_event_paranoid": 4,
                "kernel.sysrq": 0,
                "user.max_user_namespaces": 0,
            }
        )
    return "# Managed by umzug; src_valid_mark=1 is required by Mullvad on Linux.\n" + "".join(
        f"{key} = {value}\n" if value != "" else f"{key} =\n"
        for key, value in sorted(values.items())
    )


def _modprobe(profile: dict[str, Any], radio_modules: list[str]) -> str:
    modules = ["dccp", "rds", "sctp", "tipc"]
    if profile["name"] == "maximal":
        modules.extend(["cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "udf"])
    if profile["blacklist_radio_modules"]:
        modules.extend(radio_modules)
    lines = ["# Managed by umzug. Remove only from the local console, then rebuild initramfs."]
    for module in sorted(set(value.replace("-", "_") for value in modules if value)):
        if not module.replace("_", "").isalnum():
            raise UmzugError(f"invalid kernel module name: {module}")
        lines.extend([f"blacklist {module}", f"install {module} /bin/false"])
    return "\n".join(lines) + "\n"


def _journald() -> str:
    return """[Journal]
Storage=persistent
Compress=yes
Seal=yes
ForwardToSyslog=no
MaxRetentionSec=30day
SystemMaxUse=1G
"""


def _sudoers(minutes: int) -> str:
    return f"""# Managed by umzug; validate with visudo before activation.
Defaults use_pty
Defaults !pwfeedback
Defaults passwd_timeout=1
Defaults timestamp_timeout={minutes}
"""


def _nixos_module(profile: dict[str, Any], radio_modules: list[str]) -> str:
    sysctls = _sysctl(profile).splitlines()
    assignments: list[str] = []
    for line in sysctls:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (item.strip() for item in line.split("=", 1))
        nix_value = '""' if value == "" else value
        assignments.append(f'    "{key}" = {nix_value};')
    modules = ["dccp", "rds", "sctp", "tipc"]
    if profile["name"] == "maximal":
        modules.extend(["cramfs", "freevxfs", "hfs", "hfsplus", "jffs2", "udf"])
    if profile["blacklist_radio_modules"]:
        modules.extend(radio_modules)
    module_values = " ".join(f'"{value.replace("-", "_")}"' for value in sorted(set(modules)))
    radio = ""
    if profile["disable_radios"]:
        radio = """
  networking.wireless.enable = false;
  hardware.bluetooth.enable = false;
"""
    ipv6 = '  boot.kernelParams = [ "ipv6.disable=1" ];\n' if profile["disable_ipv6"] else ""
    return f"""# Managed by umzug. Import manually after reviewing a diff.
{{ config, lib, pkgs, ... }}:
{{
  boot.kernel.sysctl = {{
{chr(10).join(assignments)}
  }};
  boot.blacklistedKernelModules = [ {module_values} ];
{ipv6}{radio.rstrip()}
  networking.firewall = {{
    enable = true;
    allowedTCPPorts = [ ];
    allowedUDPPorts = [ ];
    allowPing = false;
  }};
  services.openssh.enable = false;
  security.sudo.extraConfig = ''
    Defaults use_pty
    Defaults !pwfeedback
    Defaults passwd_timeout=1
    Defaults timestamp_timeout={int(profile['sudo_timestamp_minutes'])}
  '';
  services.journald.extraConfig = ''
    Storage=persistent
    Compress=yes
    Seal=yes
    ForwardToSyslog=no
    MaxRetentionSec=30day
    SystemMaxUse=1G
  '';
}}
"""


def _openrc_firewall_start(rules_path: str) -> str:
    return f"""#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
exec nft -f {rules_path}
"""


def _radio_systemd_unit() -> str:
    return """[Unit]
Description=umzug persistent radio disablement
Before=network-pre.target bluetooth.service ModemManager.service wpa_supplicant.service iwd.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=rfkill block all
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""


def _radio_openrc_start() -> str:
    return """#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
exec rfkill block all
"""


def hardening_actions(
    *,
    distribution: str,
    init_system: str,
    profile: dict[str, Any],
    ethernet_interfaces: list[str],
    radio_modules: list[str],
) -> list[Action]:
    if distribution == "nixos":
        module_path = "/etc/nixos/umzug-hardening.nix"
        nix_actions = [
            Action(
                id="nixos-local-recovery",
                phase="recovery",
                summary="Lokalen NixOS-Generations-Rollback installieren",
                rationale="Eine getestete vorherige Generation kann an der Konsole ohne eingehendes SSH wieder aktiviert werden.",
                risk="medium",
                operation="write_file",
                parameters={
                    "path": "/usr/local/sbin/umzug-nixos-recovery",
                    "content": (
                        "#!/bin/sh\n"
                        "set -eu\n"
                        "PATH=/run/current-system/sw/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                        "export PATH\n"
                        "exec /run/current-system/sw/bin/nixos-rebuild switch --rollback\n"
                    ),
                    "mode": 0o700,
                },
                backup_paths=["/usr/local/sbin/umzug-nixos-recovery"],
                requires_confirmation=True,
                destructive=True,
            ),
            Action(
                id="nixos-hardening-module",
                phase="hardening",
                summary="Native deklarative NixOS-Hardening-Konfiguration erzeugen",
                rationale="NixOS-Optionen bleiben reproduzierbar und werden nicht imperativ an der Konfigurationsdatenbank vorbei geändert.",
                risk="critical",
                operation="write_file",
                parameters={"path": module_path, "content": _nixos_module(profile, radio_modules), "mode": 0o600},
                backup_paths=[module_path],
                requires_confirmation=True,
                destructive=True,
            ),
            Action(
                id="nixos-import-rebuild-checkpoint",
                phase="hardening",
                summary="NixOS-Modul importieren, dry-build und test manuell verifizieren",
                rationale="Imports der bestehenden configuration.nix werden nie automatisch überschrieben; erst nixos-rebuild dry-build/test und lokaler Recovery-Test erlauben einen Boot.",
                risk="critical",
                operation="checkpoint",
                parameters={
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
                requires_confirmation=True,
                destructive=True,
                reboot_reason="Die getestete deklarative NixOS-Generation muss gebootet und hinsichtlich Firewall, Funk und SSH verifiziert werden.",
                post_reboot_verify={
                    "kind": "nixos_booted_store_path",
                },
            ),
        ]
        return nix_actions
    actions: list[Action] = []
    sysctl_content = _sysctl(profile)
    sysctl_values = {
        key.strip(): value.strip()
        for line in sysctl_content.splitlines()
        if line and not line.startswith("#") and "=" in line
        for key, value in (line.split("=", 1),)
    }
    actions.append(
        Action(
            id="hardening-sysctl",
            phase="hardening",
            summary="Kernel- und Netzwerkparameter absichern",
            rationale="Reduziert Informationslecks, unsichere Redirects, BPF- und ptrace-Angriffsfläche.",
            risk="high",
            operation="write_file",
            parameters={"path": "/etc/sysctl.d/90-umzug-hardening.conf", "content": sysctl_content, "mode": 0o644},
            backup_paths=["/etc/sysctl.d/90-umzug-hardening.conf"],
            requires_confirmation=True,
            destructive=True,
        )
    )
    actions.append(
        Action(
            id="hardening-sysctl-apply",
            phase="hardening",
            summary="Unterstützte sysctl-Werte laden",
            rationale="Aktiviert die zuvor sichtbare deklarative Konfiguration.",
            risk="high",
            operation="run_command",
            parameters={"argv": ["sysctl", "--system"]},
            verify={"kind": "sysctl_effective", "values": sysctl_values},
            requires_confirmation=True,
            destructive=True,
        )
    )

    guard_path = "/etc/umzug/offline-guard.nft"
    actions.extend(
        [
            Action(
                id="offline-guard-rules",
                phase="bootstrap-security",
                summary="Hostweiten Offline-Egress-Guard schreiben",
                rationale="Bis zum expliziten VPN-Finalizer darf auch durch Paket-Hooks oder neu gestartete Daemons kein Netzwerkverkehr entstehen.",
                risk="critical",
                operation="write_file",
                parameters={"path": guard_path, "content": offline_guard_rules(), "mode": 0o600},
                backup_paths=[guard_path],
                requires_confirmation=True,
                destructive=True,
            ),
            Action(
                id="offline-guard-syntax",
                phase="bootstrap-security",
                summary="Offline-Egress-Guard syntaktisch prüfen",
                rationale="Ein ungültiger Guard darf die bestehende Firewall nicht verändern.",
                risk="low",
                operation="run_command",
                parameters={"argv": ["nft", "--check", "--file", guard_path]},
            ),
        ]
    )
    if init_system == "systemd":
        actions.extend(
            [
                Action(
                    id="offline-guard-unit",
                    phase="bootstrap-security",
                    summary="Persistente Offline-Guard-Unit installieren",
                    rationale="Der Egress-Drop bleibt über frühe Reboots hinweg aktiv.",
                    risk="critical",
                    operation="write_file",
                    parameters={
                        "path": "/etc/systemd/system/umzug-offline-guard.service",
                        "content": offline_guard_systemd_unit(guard_path),
                        "mode": 0o644,
                    },
                    backup_paths=["/etc/systemd/system/umzug-offline-guard.service"],
                    requires_confirmation=True,
                    destructive=True,
                ),
                Action(
                    id="offline-guard-persist",
                    phase="bootstrap-security",
                    summary="Offline-Guard persistent aktivieren",
                    rationale="Schließt Egress vor Paketinstallation, Initramfs-Neubau und Reboots.",
                    risk="critical",
                    operation="enable_service",
                    parameters={"name": "umzug-offline-guard.service"},
                    verify={
                        "kind": "service_enabled",
                        "name": "umzug-offline-guard.service",
                        "init": "systemd",
                    },
                    requires_confirmation=True,
                    destructive=True,
                ),
                Action(
                    id="offline-guard-activate",
                    phase="bootstrap-security",
                    summary="Offline-Guard neu laden und effektiv prüfen",
                    rationale="Beweist die hostweite Output-Default-Drop-Policy statt nur eine Datei zu schreiben.",
                    risk="critical",
                    operation="run_command",
                    parameters={"argv": ["systemctl", "restart", "umzug-offline-guard.service"]},
                    verify={"kind": "offline_guard"},
                    requires_confirmation=True,
                    destructive=True,
                ),
            ]
        )
    else:
        actions.append(
            Action(
                id="offline-guard-activate",
                phase="bootstrap-security",
                summary="Offline-Guard sofort aktivieren und effektiv prüfen",
                rationale="Schließt Egress vor weiteren Änderungen; Persistenz wird separat bestätigt.",
                risk="critical",
                operation="run_command",
                parameters={"argv": ["nft", "--file", guard_path]},
                verify={"kind": "offline_guard"},
                requires_confirmation=True,
                destructive=True,
            )
        )
        actions.append(
            Action(
                id="offline-guard-persistence-checkpoint",
                phase="bootstrap-security",
                summary="Offline-Guard in das Ziel-Init integrieren",
                rationale="Nicht-systemd-Systeme unterscheiden sich; ein unbestätigter geratenes Boot-Hook wäre unsicher.",
                risk="critical",
                operation="checkpoint",
                parameters={"required_evidence": f"early-boot load of {guard_path} before all network services"},
                requires_confirmation=True,
                destructive=True,
            )
        )

    modprobe_content = _modprobe(profile, radio_modules)
    blocked_modules = [
        line.split()[1]
        for line in modprobe_content.splitlines()
        if line.startswith("blacklist ") and len(line.split()) == 2
    ]
    actions.append(
        Action(
            id="hardening-module-policy",
            phase="hardening",
            summary="Unnötige Protokoll-, Dateisystem- und optional Funkmodule sperren",
            rationale="Verhindert späteres Laden ausgewählter Kernelmodule; kann Hardware oder Dateisysteme unbenutzbar machen.",
            risk="critical",
            operation="write_file",
            parameters={"path": "/etc/modprobe.d/90-umzug-deny.conf", "content": modprobe_content, "mode": 0o644},
            backup_paths=["/etc/modprobe.d/90-umzug-deny.conf"],
            requires_confirmation=True,
            destructive=True,
        )
    )
    initramfs_argv: list[str] | None = None
    if distribution in {"debian", "ubuntu", "linuxmint", "pop", "kali"}:
        initramfs_argv = ["update-initramfs", "-u", "-k", "all"]
    elif distribution in {"arch", "manjaro", "endeavouros", "garuda"}:
        initramfs_argv = ["mkinitcpio", "-P"]
    elif distribution in {"fedora", "rhel", "centos", "rocky", "almalinux"}:
        initramfs_argv = ["dracut", "--regenerate-all", "--force"]
    if initramfs_argv:
        actions.append(
            Action(
                id="hardening-initramfs-rebuild",
                phase="hardening",
                summary="Initramfs nach Kernelmodul-Sperren neu erzeugen",
                rationale="Früh geladene Treiber würden die Modprobe-Policy sonst möglicherweise umgehen.",
                risk="critical",
                operation="run_command",
                parameters={
                    "argv": initramfs_argv,
                    "network_policy": "forbidden",
                    "timeout": 1800,
                },
                backup_paths=[],
                requires_confirmation=True,
                destructive=True,
                reboot_reason="Die neu erzeugte Initramfs und Kernelmodul-Sperren müssen in einem neuen Boot verifiziert werden.",
                post_reboot_verify={
                    "kind": "modules_not_loaded",
                    "modules": blocked_modules,
                    "ipv6_disabled": bool(profile["disable_ipv6"]),
                },
            )
        )
    else:
        actions.append(
            Action(
                id="hardening-initramfs-manual-checkpoint",
                phase="hardening",
                summary="Distributionseigenen Initramfs-Neubau manuell durchführen",
                rationale="Für diese Distribution wurde kein standardisierter, sicher beweisbarer Initramfs-Befehl erkannt; die Modulpolicy ist bis dahin nicht freigabefähig.",
                risk="critical",
                operation="checkpoint",
                parameters={"manual_verification": "rebuild initramfs with target-native tooling and record its hash"},
                requires_confirmation=True,
                destructive=True,
                reboot_reason="Initramfs und Modulpolicy müssen nach einem manuell dokumentierten Neubau neu gestartet und geprüft werden.",
                post_reboot_verify={
                    "kind": "modules_not_loaded",
                    "modules": blocked_modules,
                    "ipv6_disabled": bool(profile["disable_ipv6"]),
                },
            )
        )

    services = list(
        (
            "ssh.service",
            "sshd.service",
            "ssh.socket",
            "sshd.socket",
            "telnet.socket",
            "rsh.socket",
        )
        if init_system == "systemd"
        else ("sshd", "telnetd", "rshd") if init_system == "openrc" else ()
    )
    if profile["disable_radios"]:
        if init_system == "systemd":
            services.extend(("bluetooth.service", "ModemManager.service", "wpa_supplicant.service", "iwd.service"))
        elif init_system == "openrc":
            services.extend(("bluetooth", "modemmanager", "wpa_supplicant", "iwd"))
    for service in services:
        identifier = service.lower().replace(".", "-").replace("@", "-")
        actions.append(
            Action(
                id=f"disable-{identifier}",
                phase="services",
                summary=f"Eingehenden Dienst {service} deaktivieren und maskieren",
                rationale="Das Basissicherheitsprofil veröffentlicht weder SSH noch Legacy-Remote-Shells.",
                risk="high",
                operation="disable_service",
                parameters={"name": service, "mask": init_system == "systemd", "init": init_system},
                verify={"kind": "service_disabled", "name": service, "init": init_system},
                requires_confirmation=True,
                destructive=True,
            )
        )

    if profile["disable_radios"]:
        actions.append(
            Action(
                id="radio-block-now",
                phase="network",
                summary="Alle WLAN-, Bluetooth- und Mobilfunk-Sender per rfkill blockieren",
                rationale="Das Zielprofil erlaubt ausschließlich kabelgebundenes Ethernet.",
                risk="high",
                operation="run_command",
                parameters={"argv": ["rfkill", "block", "all"]},
                verify={"kind": "radio_blocked"},
                requires_confirmation=True,
                destructive=True,
            )
        )
        if init_system == "systemd":
            actions.extend(
                [
                    Action(
                        id="radio-systemd-unit",
                        phase="network",
                        summary="Persistente systemd-RFKill-Sperre installieren",
                        rationale="Blockiert sämtliche Funkgeräte bei jedem Boot vor Netzwerkdiensten.",
                        risk="high",
                        operation="write_file",
                        parameters={
                            "path": "/etc/systemd/system/umzug-radio-off.service",
                            "content": _radio_systemd_unit(),
                            "mode": 0o644,
                        },
                        backup_paths=["/etc/systemd/system/umzug-radio-off.service"],
                        requires_confirmation=True,
                        destructive=True,
                    ),
                    Action(
                        id="radio-systemd-enable",
                        phase="network",
                        summary="Persistente RFKill-Sperre aktivieren",
                        rationale="Stellt die Ethernet-only-Policy nach Neustarts wieder her.",
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
                    ),
                ]
            )
        elif init_system == "openrc":
            actions.append(
                Action(
                    id="radio-openrc-start",
                    phase="network",
                    summary="Persistenten OpenRC-RFKill-Hook installieren",
                    rationale="Blockiert Funkgeräte bei jedem Boot über local.d.",
                    risk="high",
                    operation="write_file",
                    parameters={
                        "path": "/etc/local.d/umzug-radio-off.start",
                        "content": _radio_openrc_start(),
                        "mode": 0o700,
                    },
                    backup_paths=["/etc/local.d/umzug-radio-off.start"],
                    requires_confirmation=True,
                    destructive=True,
                )
            )

    # the recovery command must exist *before* any action can activate a
    # restrictive firewall.  Plan order is execution order, so keep this
    # adjacent to (and ahead of) the network lock-down actions.
    actions.append(
        Action(
            id="network-recovery-command",
            phase="recovery",
            summary="Lokalen Firewall-Recovery-Befehl installieren",
            rationale="Ermöglicht an der Konsole die Entfernung der Toolkit-Regeln, ohne SSH zu aktivieren.",
            risk="medium",
            operation="write_file",
            parameters={
                "path": "/usr/local/sbin/umzug-network-recovery",
                "content": recovery_script(),
                "mode": 0o700,
            },
            backup_paths=["/usr/local/sbin/umzug-network-recovery"],
            requires_confirmation=True,
            destructive=True,
        )
    )

    firewall = host_firewall_rules(ethernet_interfaces, ipv6_enabled=not profile["disable_ipv6"])
    assert_no_ssh_exposure(firewall)
    firewall_path = "/etc/umzug/firewall.nft"
    actions.append(
        Action(
                id="firewall-rules",
                phase="network",
                summary="Host-Firewall mit eingehender Default-Drop-Policy schreiben",
                rationale="Nur Loopback, etablierte Antworten, notwendiges ICMP und DHCP werden angenommen; kein SSH-Port wird geöffnet.",
                risk="critical",
                operation="write_file",
                parameters={"path": firewall_path, "content": firewall, "mode": 0o600},
                backup_paths=[firewall_path],
                requires_confirmation=True,
                destructive=True,
            )
    )
    if init_system == "systemd":
        actions.extend(
            [
                Action(
                id="firewall-unit",
                phase="network",
                summary="Früh startende, persistente Firewall-Unit installieren",
                rationale="Lädt die atomisch validierten Regeln vor Netzwerk und VPN.",
                risk="critical",
                operation="write_file",
                parameters={
                    "path": "/etc/systemd/system/umzug-firewall.service",
                    "content": firewall_systemd_unit(firewall_path),
                    "mode": 0o644,
                },
                backup_paths=["/etc/systemd/system/umzug-firewall.service"],
                requires_confirmation=True,
                destructive=True,
                ),
                Action(
                id="firewall-syntax",
                phase="network",
                summary="nftables-Regeln ohne Aktivierung syntaktisch prüfen",
                rationale="Ein Syntaxfehler darf die aktive Firewall niemals ersetzen.",
                risk="low",
                operation="run_command",
                parameters={"argv": ["nft", "--check", "--file", firewall_path]},
                ),
                Action(
                id="firewall-persist",
                phase="network",
                summary="Host-Firewall für den Boot aktivieren",
                rationale="Registriert die Unit persistent; die folgende Restart-Aktion lädt und prüft den aktuellen Regelsatz.",
                risk="critical",
                operation="enable_service",
                parameters={"name": "umzug-firewall.service"},
                verify={
                    "kind": "service_enabled",
                    "name": "umzug-firewall.service",
                    "init": "systemd",
                },
                requires_confirmation=True,
                destructive=True,
                ),
                Action(
                id="firewall-enable",
                phase="network",
                summary="Host-Firewall atomisch neu laden und verifizieren",
                rationale="Ein Restart lädt auch bei bereits aktiver oneshot-Unit die aktuelle, transaktionale Regeldatei.",
                risk="critical",
                operation="run_command",
                parameters={"argv": ["systemctl", "restart", "umzug-firewall.service"]},
                verify={
                    "kind": "host_firewall",
                    "interfaces": list(ethernet_interfaces),
                    "ipv6_enabled": not profile["disable_ipv6"],
                },
                requires_confirmation=True,
                destructive=True,
                ),
            ]
        )
    elif init_system == "openrc":
        actions.extend(
            [
                Action(
                    id="firewall-openrc-start",
                    phase="network",
                    summary="OpenRC-local.d-Startskript für die Host-Firewall installieren",
                    rationale="Lädt die geprüften Regeln bei jedem Boot ohne systemd-Annahme.",
                    risk="critical",
                    operation="write_file",
                    parameters={
                        "path": "/etc/local.d/umzug-firewall.start",
                        "content": _openrc_firewall_start(firewall_path),
                        "mode": 0o700,
                    },
                    backup_paths=["/etc/local.d/umzug-firewall.start"],
                    requires_confirmation=True,
                    destructive=True,
                ),
                Action(
                    id="firewall-syntax",
                    phase="network",
                    summary="nftables-Regeln ohne Aktivierung syntaktisch prüfen",
                    rationale="Ein Syntaxfehler darf die aktive Firewall niemals ersetzen.",
                    risk="low",
                    operation="run_command",
                    parameters={"argv": ["nft", "--check", "--file", firewall_path]},
                ),
                Action(
                    id="firewall-openrc-persist",
                    phase="network",
                    summary="OpenRC-local-Service für Boot-Persistenz eintragen",
                    rationale="Registriert nur den lokalen Boot-Hook; führt andere lokale Skripte jetzt nicht aus.",
                    risk="high",
                operation="run_command",
                parameters={"argv": ["rc-update", "add", "local", "default"]},
                verify={
                    "kind": "service_enabled",
                    "name": "local",
                    "init": "openrc",
                    "runlevel": "default",
                },
                    requires_confirmation=True,
                    destructive=True,
                ),
                Action(
                    id="firewall-enable",
                    phase="network",
                    summary="Host-Firewall atomisch aktivieren",
                    rationale="Eingehender Verkehr wird anschließend verworfen; der Konsolen-Recovery-Befehl bleibt verfügbar.",
                    risk="critical",
                    operation="run_command",
                parameters={"argv": ["nft", "--file", firewall_path]},
                verify={
                    "kind": "host_firewall",
                    "interfaces": list(ethernet_interfaces),
                    "ipv6_enabled": not profile["disable_ipv6"],
                },
                    requires_confirmation=True,
                    destructive=True,
                ),
            ]
        )
    else:
        actions.extend(
            [
                Action(
                    id="firewall-syntax",
                    phase="network",
                    summary="nftables-Regeln ohne Aktivierung syntaktisch prüfen",
                    rationale="Die Regeldatei ist gültig, wird bei unbekanntem Init-System aber nicht automatisch geladen.",
                    risk="low",
                    operation="run_command",
                    parameters={"argv": ["nft", "--check", "--file", firewall_path]},
                ),
                Action(
                    id="firewall-init-manual-checkpoint",
                    phase="network",
                    summary="Firewall-Persistenz mit zielsystemeigenem Init manuell integrieren",
                    rationale="LFS/generische Systeme besitzen keinen verlässlich standardisierten Service-Manager; eine geratenen Boot-Aktion wäre gefährlich.",
                    risk="critical",
                    operation="checkpoint",
                    parameters={"rules": firewall_path, "required": "early-boot load plus console recovery test"},
                    requires_confirmation=True,
                    destructive=True,
                ),
            ]
        )

    actions.append(
        Action(
                id="sudo-policy",
                phase="access",
                summary="sudo-Sitzungen und TTY-Nutzung härten",
                rationale="Verhindert Passwort-Feedback und reduziert die Gültigkeit gecachter sudo-Anmeldungen.",
                risk="high",
                operation="write_file",
                parameters={
                    "path": "/etc/sudoers.d/90-umzug-hardening",
                    "content": _sudoers(int(profile["sudo_timestamp_minutes"])),
                    "mode": 0o440,
                },
                backup_paths=["/etc/sudoers.d/90-umzug-hardening"],
                requires_confirmation=True,
                destructive=True,
            )
    )
    if init_system == "systemd":
        actions.append(
            Action(
                id="journald-policy",
                phase="logging",
                summary="Persistente, komprimierte und versiegelte Journale konfigurieren",
                rationale="Verbessert lokale Nachvollziehbarkeit ohne Netzwerk-Logging.",
                risk="medium",
                operation="write_file",
                parameters={
                    "path": "/etc/systemd/journald.conf.d/90-umzug-hardening.conf",
                    "content": _journald(),
                    "mode": 0o644,
                },
                backup_paths=["/etc/systemd/journald.conf.d/90-umzug-hardening.conf"],
                requires_confirmation=True,
                destructive=True,
            )
        )
    bootstrap_order = {
        "network-recovery-command": 0,
        "offline-guard-rules": 1,
        "offline-guard-syntax": 2,
        "offline-guard-unit": 3,
        "offline-guard-persist": 4,
        "offline-guard-activate": 5,
        "offline-guard-persistence-checkpoint": 6,
        "firewall-rules": 10,
        "firewall-unit": 11,
        "firewall-syntax": 12,
        "firewall-persist": 13,
        "firewall-openrc-start": 13,
        "firewall-openrc-persist": 14,
        "firewall-enable": 15,
        "firewall-init-manual-checkpoint": 16,
    }

    def action_order(action: Action) -> tuple[int, int]:
        if action.id in bootstrap_order:
            return (bootstrap_order[action.id], 0)
        if action.id.startswith("disable-"):
            return (20, 0)
        if action.id.startswith("radio-"):
            return (21, 0)
        return (100, 0)

    return sorted(actions, key=action_order)
