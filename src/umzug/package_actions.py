"""typed conversion from distribution package plans to executor actions."""

from __future__ import annotations

from pathlib import Path

from .adapters import PackagePlan
from .actions import Action
from .util import UmzugError, sha256_file
from .vpn import management_override


def package_actions(
    package_plan: PackagePlan,
    approved_artifacts: dict[str, str] | None = None,
) -> list[Action]:
    actions: list[Action] = []
    for index, file in enumerate(package_plan.files):
        actions.append(
            Action(
                id=f"package-file-{index}-{package_plan.adapter}",
                phase="packages",
                summary=file.description or f"Distributionsdatei {file.path} erzeugen",
                rationale=f"Adapter {package_plan.adapter}; Merge-Strategie {file.merge_strategy}.",
                risk="high",
                operation="write_file",
                parameters={"path": file.path, "content": file.content, "mode": file.mode},
                backup_paths=[file.path],
                requires_confirmation=True,
                destructive=True,
            )
        )
    for command in package_plan.commands:
        if command.network_policy != "forbidden":
            raise UmzugError("network-permitted package action cannot enter the offline setup plan")
        hashes = {
            path: sha256_file(Path(path))
            for path in (approved_artifacts or {}).values()
            if path in command.argv
        }
        if not command.argv or command.argv[0] != "apt-get" or "--" not in command.argv:
            raise UmzugError("offline package command lacks a typed executor schema")
        packages = list(command.argv[command.argv.index("--") + 1 :])
        actions.append(
            Action(
                id=command.action_id,
                phase="packages",
                summary=command.description,
                rationale=(
                    command.idempotency
                    + "; execution is isolated in a network namespace."
                ),
                risk="high",
                operation="run_command",
                parameters={
                    "argv": list(command.argv),
                    "network_policy": "forbidden",
                    "timeout": 3600,
                    **({"required_file_hashes": hashes} if hashes else {}),
                },
                verify={
                    "kind": "package_status",
                    "manager": "dpkg",
                    "packages": packages,
                },
                requires_confirmation=True,
                destructive=True,
                reboot_reason=(
                    "Der Distributionsadapter meldet eine mögliche bootrelevante Paketänderung."
                    if command.reboot_may_be_required
                    else None
                ),
                post_reboot_verify={},
            )
        )
    return actions


def mullvad_install_action(
    *,
    distribution: str,
    package_adapter: str,
    artifact: str,
    artifact_sha256: str,
    package_version: str,
    package_architecture: str,
    management_group: str,
) -> Action:
    """render the sole privileged mullvad package action from bound intent."""

    if distribution in {"debian", "ubuntu"} and package_adapter == "debian":
        if not artifact.lower().endswith(".deb"):
            raise UmzugError("Mullvad artifact format does not match the Debian adapter")
        argv = [
            "apt-get",
            "install",
            "--yes",
            "--reinstall",
            "--no-download",
            "--no-install-recommends",
            "--",
            artifact,
        ]
        package_manager = "dpkg"
    elif distribution == "fedora" and package_adapter == "generic":
        if not artifact.lower().endswith(".rpm"):
            raise UmzugError("Mullvad artifact format does not match the Fedora adapter")
        argv = [
            "rpm",
            "--upgrade",
            "--replacepkgs",
            "--",
            artifact,
        ]
        package_manager = "rpm"
    else:
        raise UmzugError("Mullvad vendor installation is not modelled for this target adapter")
    return Action(
        id="mullvad-offline-install",
        phase="vpn-offline-preparation",
        summary="Signatur- und hashgebundenes Mullvad-Herstellerpaket offline installieren",
        rationale=(
            "Das Paket stammt aus APPROVED, stimmt mit dem Vendor-Beleg überein "
            "und wird in einem Netzwerk-Namespace installiert."
        ),
        risk="critical",
        operation="run_command",
        parameters={
            "argv": argv,
            "network_policy": "forbidden",
            "timeout": 1800,
            "required_file_hashes": {artifact: artifact_sha256},
            "post_install_argvs": [
                ["systemctl", "daemon-reload"],
                ["systemctl", "restart", "mullvad-daemon.service"],
            ],
        },
        verify={
            "kind": "mullvad_version",
            "manager": package_manager,
            "package": "mullvad-vpn",
            "version": package_version,
            "architecture": package_architecture,
            "management_group": management_group,
        },
        requires_confirmation=True,
        destructive=True,
    )


def mullvad_management_actions(group: str) -> list[Action]:
    """create the management group and drop-in before installing the vendor package.
    
    systemd reads the drop-in on the unit's first load, including a postinst start.
    do not reload unrelated units before that unit exists. the vendor action owns
    the post-install reload/restart and must verify the live endpoint before completion.
    """

    return [
        Action(
            id="mullvad-management-group",
            phase="vpn-offline-preparation",
            summary="Dedizierte Mullvad-Managementgruppe anlegen",
            rationale=(
                "Beschränkt den lokalen Management-Socket; die Gruppe erhält "
                "standardmäßig keine nicht-root Mitglieder."
            ),
            risk="medium",
            operation="ensure_group",
            parameters={"name": group},
            verify={"kind": "restricted_group", "name": group},
            requires_confirmation=True,
            destructive=True,
        ),
        Action(
            id="mullvad-management-socket",
            phase="vpn-offline-preparation",
            summary="Mullvad-Management-Socket auf dedizierte Gruppe beschränken",
            rationale=(
                "Ohne diese Herstelleroption könnten lokale Prozesse VPN-Zustand "
                "und Kontoinformationen steuern."
            ),
            risk="high",
            operation="write_file",
            parameters={
                "path": "/etc/systemd/system/mullvad-daemon.service.d/90-umzug-security.conf",
                "content": management_override(group),
                "mode": 0o644,
            },
            backup_paths=[
                "/etc/systemd/system/mullvad-daemon.service.d/90-umzug-security.conf"
            ],
            requires_confirmation=True,
            destructive=True,
        ),
    ]
