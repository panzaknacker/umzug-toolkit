"""map known package capabilities to deterministic plans; never execute them.

untrusted package names cannot become command arguments: adapters map only
known capabilities to fixed native packages. unknown names stay unresolved.
the executor still owes a diff, confirmation, backup, network_policy enforcement
and a verified postcondition.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

from .detection import DistributionInfo, SystemFacts


_CAPABILITY = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,63}$")
_NATIVE_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:@/-]{0,127}$")
_NIX_ATTRIBUTE = re.compile(r"^[A-Za-z_][A-Za-z0-9_'-]*(?:\.[A-Za-z_][A-Za-z0-9_'-]*)*$")
_MAX_PACKAGE_REQUESTS = 4096


@dataclass(frozen=True)
class PackageResolution:
    requested: str
    canonical: str | None
    native_packages: tuple[str, ...] = ()
    status: str = "unresolved"  # mapped, alternative, manual, unresolved
    rationale: str = ""

    @property
    def resolved(self) -> bool:
        return self.status in {"mapped", "alternative"} and bool(self.native_packages)


@dataclass(frozen=True)
class PlannedCommand:
    """an inert command intent; this class deliberately has no run method."""

    action_id: str
    argv: tuple[str, ...]
    description: str
    idempotency: str
    verify_argv: tuple[str, ...] = ()
    requires_root: bool = True
    requires_confirmation: bool = True
    network_policy: str = "forbidden"  # forbidden, permitted
    reboot_may_be_required: bool = False

    def __post_init__(self) -> None:
        if not self.argv or not all(isinstance(item, str) and "\x00" not in item for item in self.argv):
            raise ValueError("planned argv must be a non-empty, NUL-free string tuple")
        if self.network_policy not in {"forbidden", "permitted"}:
            raise ValueError("invalid network policy")


@dataclass(frozen=True)
class DeclarativeFile:
    path: str
    content: str
    mode: int = 0o644
    merge_strategy: str = "replace-managed-file"
    description: str = ""
    requires_confirmation: bool = True

    def __post_init__(self) -> None:
        path = PurePosixPath(self.path)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("declarative path must be absolute and traversal-free")
        if self.merge_strategy not in {
            "replace-managed-file",
            "merge-keyed-lines",
            "manual-import",
        }:
            raise ValueError("unsupported merge strategy")
        if not 0 <= self.mode <= 0o7777:
            raise ValueError("invalid file mode")


@dataclass(frozen=True)
class UseFlagSetting:
    target: str
    enable: tuple[str, ...] = ()
    disable: tuple[str, ...] = ()
    rationale: str = ""


@dataclass(frozen=True)
class PackagePlan:
    adapter: str
    offline: bool
    requested: tuple[str, ...]
    resolutions: tuple[PackageResolution, ...]
    commands: tuple[PlannedCommand, ...] = ()
    files: tuple[DeclarativeFile, ...] = ()
    use_flags: tuple[UseFlagSetting, ...] = ()
    manual_actions: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def unresolved(self) -> tuple[PackageResolution, ...]:
        return tuple(item for item in self.resolutions if not item.resolved)

    @property
    def native_packages(self) -> tuple[str, ...]:
        result: list[str] = []
        seen: set[str] = set()
        for resolution in self.resolutions:
            for package in resolution.native_packages:
                if package not in seen:
                    seen.add(package)
                    result.append(package)
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class _PackageTarget:
    packages: tuple[str, ...]
    status: str = "mapped"
    rationale: str = ""


def _target(*packages: str, status: str = "mapped", rationale: str = "") -> _PackageTarget:
    if status not in {"mapped", "alternative"}:
        raise ValueError("mapped targets must be mapped or alternative")
    if not packages or any(not _NATIVE_PACKAGE.fullmatch(package) for package in packages):
        raise ValueError("invalid fixed native package mapping")
    return _PackageTarget(tuple(packages), status=status, rationale=rationale)


# capabilities are intentionally finite.  native names are maintained as code,
# never accepted from a migration archive.  availability must additionally be
# checked against the target's signed local repository metadata before apply.
_PACKAGE_MAP: dict[str, dict[str, _PackageTarget]] = {
    "debian": {
        "archive-tools": _target("tar", "xz-utils", "zstd", "unzip"),
        "audit": _target("auditd"),
        "build-tools": _target("build-essential", "pkg-config"),
        "ca-certificates": _target("ca-certificates"),
        "curl": _target("curl"),
        "firewall": _target("nftables"),
        "git": _target("git"),
        "gnupg": _target("gnupg"),
        "integrity-checker": _target("aide"),
        "mac-apparmor": _target("apparmor", "apparmor-utils"),
        "mac-selinux": _target(
            "selinux-basics",
            "policycoreutils",
            status="alternative",
            rationale="Debian-Werkzeuge; Policy und Bootparameter müssen separat geplant werden.",
        ),
        "malware-scanner": _target("clamav", "clamav-daemon"),
        "neovim": _target("neovim"),
        "python": _target("python3"),
        "rsync": _target("rsync"),
        "radio-control": _target("rfkill"),
        "sandbox": _target("bubblewrap"),
        "ssh-client": _target("openssh-client"),
        "sudo": _target("sudo"),
        "tpm-tools": _target("tpm2-tools"),
        "usb-control": _target("usbguard"),
        "vim": _target("vim"),
        "wget": _target("wget"),
        "wireguard": _target("wireguard-tools"),
        "yara": _target("yara"),
        "zsh": _target("zsh"),
    },
    "arch": {
        "archive-tools": _target("tar", "xz", "zstd", "unzip"),
        "audit": _target("audit"),
        "build-tools": _target("base-devel"),
        "ca-certificates": _target("ca-certificates"),
        "curl": _target("curl"),
        "firewall": _target("nftables"),
        "git": _target("git"),
        "gnupg": _target("gnupg"),
        "integrity-checker": _target("aide"),
        "mac-apparmor": _target("apparmor"),
        "malware-scanner": _target("clamav"),
        "neovim": _target("neovim"),
        "python": _target("python"),
        "rsync": _target("rsync"),
        "radio-control": _target("rfkill"),
        "sandbox": _target("bubblewrap"),
        "ssh-client": _target("openssh"),
        "sudo": _target("sudo"),
        "tpm-tools": _target("tpm2-tools"),
        "usb-control": _target("usbguard"),
        "vim": _target("vim"),
        "wget": _target("wget"),
        "wireguard": _target("wireguard-tools"),
        "yara": _target("yara"),
        "zsh": _target("zsh"),
    },
    "nixos": {
        "archive-tools": _target("gnutar", "xz", "zstd", "unzip"),
        "audit": _target("audit"),
        "build-tools": _target("gcc", "gnumake", "pkg-config"),
        "ca-certificates": _target("cacert"),
        "curl": _target("curl"),
        "firewall": _target("nftables"),
        "git": _target("git"),
        "gnupg": _target("gnupg"),
        "integrity-checker": _target("aide"),
        "malware-scanner": _target("clamav"),
        "neovim": _target("neovim"),
        "python": _target("python3"),
        "rsync": _target("rsync"),
        "radio-control": _target("util-linux"),
        "sandbox": _target("bubblewrap"),
        "ssh-client": _target("openssh"),
        "sudo": _target("sudo"),
        "tpm-tools": _target("tpm2-tools"),
        "usb-control": _target("usbguard"),
        "vim": _target("vim"),
        "wget": _target("wget"),
        "wireguard": _target("wireguard-tools"),
        "yara": _target("yara"),
        "zsh": _target("zsh"),
    },
    "gentoo": {
        "archive-tools": _target("app-arch/tar", "app-arch/xz-utils", "app-arch/zstd", "app-arch/unzip"),
        "audit": _target("sys-process/audit"),
        "build-tools": _target("sys-devel/gcc", "sys-devel/make", "virtual/pkgconfig"),
        "ca-certificates": _target("app-misc/ca-certificates"),
        "curl": _target("net-misc/curl"),
        "firewall": _target("net-firewall/nftables"),
        "git": _target("dev-vcs/git"),
        "gnupg": _target("app-crypt/gnupg"),
        "integrity-checker": _target("app-forensics/aide"),
        "mac-apparmor": _target("sys-apps/apparmor", "sys-apps/apparmor-utils"),
        "mac-selinux": _target("sec-policy/selinux-base"),
        "malware-scanner": _target("app-antivirus/clamav"),
        "neovim": _target("app-editors/neovim"),
        "python": _target("dev-lang/python"),
        "rsync": _target("net-misc/rsync"),
        "radio-control": _target("sys-apps/util-linux"),
        "sandbox": _target("sys-apps/bubblewrap"),
        "ssh-client": _target("net-misc/openssh"),
        "sudo": _target("app-admin/sudo"),
        "tpm-tools": _target("app-crypt/tpm2-tools"),
        "usb-control": _target("sys-apps/usbguard"),
        "vim": _target("app-editors/vim"),
        "wget": _target("net-misc/wget"),
        "wireguard": _target("net-vpn/wireguard-tools"),
        "yara": _target("app-forensics/yara"),
        "zsh": _target("app-shells/zsh"),
    },
}


_ALIASES = {
    "aide": "integrity-checker",
    "apparmor": "mac-apparmor",
    "build-essential": "build-tools",
    "bubblewrap": "sandbox",
    "clamav": "malware-scanner",
    "firewall": "firewall",
    "nftables": "firewall",
    "openssh-client": "ssh-client",
    "python3": "python",
    "selinux": "mac-selinux",
    "tpm2-tools": "tpm-tools",
    "usbguard": "usb-control",
    "wireguard-tools": "wireguard",
}


def canonical_capabilities() -> tuple[str, ...]:
    """return the capabilities accepted from an untrusted package manifest."""

    names = set(_ALIASES.values())
    for mapping in _PACKAGE_MAP.values():
        names.update(mapping)
    return tuple(sorted(names))


def _stable_action_id(adapter: str, packages: Sequence[str]) -> str:
    payload = json.dumps([adapter, list(packages)], separators=(",", ":"), sort_keys=False)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"packages.{adapter}.{digest}"


def _deduplicate(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


class DistributionAdapter:
    """base class for a distribution-specific declarative planner."""

    adapter_id = "generic"
    family = "generic"
    distribution_ids: frozenset[str] = frozenset()
    distribution_likes: frozenset[str] = frozenset()
    package_managers: frozenset[str] = frozenset()
    priority = 0

    def matches(self, distro: DistributionInfo, managers: Sequence[str]) -> bool:
        return bool(
            distro.id in self.distribution_ids
            or self.distribution_likes.intersection(distro.id_like)
            or self.package_managers.intersection(managers)
        )

    def resolve_package(self, requested: str) -> PackageResolution:
        if not isinstance(requested, str):
            return PackageResolution(
                requested=repr(requested),
                canonical=None,
                status="unresolved",
                rationale="Paketanforderung ist keine Zeichenkette.",
            )
        normalised = requested.strip().lower()
        if not _CAPABILITY.fullmatch(normalised):
            return PackageResolution(
                requested=requested,
                canonical=None,
                status="unresolved",
                rationale="Ungültiger oder potenziell gefährlicher Capability-Name.",
            )
        canonical = _ALIASES.get(normalised, normalised)
        mapping = _PACKAGE_MAP.get(self.family, {}).get(canonical)
        if mapping is None:
            return PackageResolution(
                requested=requested,
                canonical=canonical,
                status="manual",
                rationale=(
                    f"Für {canonical!r} existiert im Adapter {self.adapter_id} keine "
                    "geprüfte Zuordnung. Keine Paketzeichenkette wird ungeprüft übernommen."
                ),
            )
        return PackageResolution(
            requested=requested,
            canonical=canonical,
            native_packages=mapping.packages,
            status=mapping.status,
            rationale=mapping.rationale or "Geprüfte distributionsspezifische Zuordnung.",
        )

    def plan_packages(
        self,
        requested: Iterable[str],
        *,
        offline: bool = True,
        offline_artifacts: Mapping[str, str] | None = None,
    ) -> PackagePlan:
        requested_list: list[str] = []
        for item in requested:
            if len(requested_list) >= _MAX_PACKAGE_REQUESTS:
                raise ValueError("package request exceeds the bounded planning limit")
            requested_list.append(item)
        requested_tuple = tuple(requested_list)
        resolutions = tuple(self.resolve_package(item) for item in requested_tuple)
        native = _deduplicate(
            package for resolution in resolutions if resolution.resolved for package in resolution.native_packages
        )
        for package in native:
            if not _NATIVE_PACKAGE.fullmatch(package) or package.startswith("-"):
                raise ValueError("adapter produced an unsafe native package name")
        commands, files, flags, manual, warnings = self._build_plan(
            native,
            resolutions,
            offline=offline,
            offline_artifacts=offline_artifacts or {},
        )
        if any(not resolution.resolved for resolution in resolutions):
            warnings = tuple(warnings) + (
                "Nicht aufgelöste Capabilities bleiben gesperrt, bis sie manuell zugeordnet oder verworfen wurden.",
            )
        if native:
            warnings = tuple(warnings) + (
                "Paketverfügbarkeit und Signaturen sind vor der Ausführung gegen lokale, vertrauenswürdige Repository-Metadaten zu prüfen.",
            )
        return PackagePlan(
            adapter=self.adapter_id,
            offline=offline,
            requested=requested_tuple,
            resolutions=resolutions,
            commands=tuple(commands),
            files=tuple(files),
            use_flags=tuple(flags),
            manual_actions=tuple(manual),
            warnings=tuple(_deduplicate(warnings)),
        )

    def _build_plan(
        self,
        native: tuple[str, ...],
        resolutions: tuple[PackageResolution, ...],
        *,
        offline: bool,
        offline_artifacts: Mapping[str, str],
    ) -> tuple[
        tuple[PlannedCommand, ...],
        tuple[DeclarativeFile, ...],
        tuple[UseFlagSetting, ...],
        tuple[str, ...],
        tuple[str, ...],
    ]:
        del native, resolutions, offline, offline_artifacts
        return (), (), (), (), ()


class DebianAdapter(DistributionAdapter):
    adapter_id = "debian"
    family = "debian"
    distribution_ids = frozenset({"debian", "ubuntu", "linuxmint", "pop", "kali"})
    distribution_likes = frozenset({"debian", "ubuntu"})
    package_managers = frozenset({"apt"})
    priority = 80

    def _build_plan(self, native, resolutions, *, offline, offline_artifacts):
        del resolutions, offline_artifacts
        if not native:
            return (), (), (), (), ()
        if offline:
            manual = (
                (
                    "NICHT AUSFÜHREN (Fail-closed-Checkpoint): Der generische "
                    "Debian/Ubuntu-Adapter installiert keine Capability-Pakete aus "
                    "/var/cache/apt/archives oder anderen lediglich bereitgestellten "
                    "DEB-Dateien."
                ),
                (
                    "Eine künftige Freigabe erfordert ein vollständig unter APPROVED "
                    "liegendes Offline-Repository-Snapshot mit unabhängig verankertem "
                    "OpenPGP-Signer, signiertem InRelease/Release und SHA-256-geprüften "
                    "Packages-Indizes."
                ),
                (
                    "Ein plan- und receiptgebundener Resolver muss daraus die exakte "
                    "transitive Closure aus Paketname, Version, Architektur, Archivpfad, "
                    "Größe und SHA-256 ableiten und alle Archive unmittelbar vor der "
                    "Installation erneut prüfen."
                ),
            )
            warnings = (
                (
                    "Fail-closed: apt-get --no-download beweist weder die SHA-256-Integrität "
                    "gleich großer Cache-Archive noch eine signatur- und hashgebundene "
                    "Abhängigkeits-Closure; deshalb wird kein privilegiertes "
                    "APT-Installationskommando erzeugt."
                ),
            )
            return (), (), (), manual, warnings
        argv = ["apt-get", "install", "--yes", "--no-install-recommends"]
        argv.extend(("--", *native))
        command = PlannedCommand(
            action_id=_stable_action_id(self.adapter_id, native),
            argv=tuple(argv),
            description="Signaturgeprüfte Debian-Pakete idempotent installieren.",
            idempotency="apt bestätigt bereits korrekt installierte Versionen ohne erneute Änderung",
            verify_argv=("dpkg-query", "--show", "--showformat=${binary:Package}\t${db:Status-Abbrev}\n", *native),
            network_policy="permitted",
        )
        return (command,), (), (), (), ()


class ArchAdapter(DistributionAdapter):
    adapter_id = "arch"
    family = "arch"
    distribution_ids = frozenset({"arch", "manjaro", "endeavouros", "garuda"})
    distribution_likes = frozenset({"arch"})
    package_managers = frozenset({"pacman"})
    priority = 80

    def _build_plan(self, native, resolutions, *, offline, offline_artifacts):
        del resolutions
        if not native:
            return (), (), (), (), ()
        if offline:
            missing: list[str] = []
            supplied: list[str] = []
            for package in native:
                artifact = offline_artifacts.get(package)
                if artifact is None:
                    missing.append(package)
                    continue
                path = PurePosixPath(artifact)
                if not path.is_absolute() or ".." in path.parts or str(path).startswith("-"):
                    raise ValueError(f"unsafe offline artifact path for {package}")
                supplied.append(package)

            manual = [
                (
                    "NICHT AUSFÜHREN (Fail-closed-Checkpoint): Lokale Pacman-Pakete aus "
                    "APPROVED werden weder mit 'pacman -U' noch durch einen anderen Root-Befehl "
                    "installiert."
                ),
                (
                    "Vor einer künftigen Freigabe muss für jedes Paket ein außerhalb des "
                    "Migrationspakets verankerter Vendor-/Repository-Signaturreceipt den exakten "
                    "SHA-256-Hash sowie Paketname, Version und Architektur an den erwarteten "
                    "Signer-Fingerprint binden."
                ),
                (
                    "Zusätzlich muss die effektiv ausgewertete Pacman-Signaturpolicy einschließlich "
                    "aller Include-Dateien, SigLevel-Werte und des vertrauenswürdig provisionierten "
                    "Schlüsselbunds unabhängig nachgewiesen werden; die aktuelle Adapter-Schnittstelle "
                    "kann diese Beweise nicht transportieren oder bis zur Ausführung binden."
                ),
            ]
            if missing:
                manual.append("Nicht bereitgestellte lokale Paketartefakte: " + ", ".join(missing) + ".")
            if supplied:
                manual.append(
                    "Als Pfad registrierte, aber ausdrücklich nicht ausführbare Paketartefakte: "
                    + ", ".join(supplied)
                    + "."
                )
            warnings = (
                (
                    "Fail-closed: APPROVED bestätigt nur die Migrationsfreigabe; es ersetzt weder "
                    "eine extern verankerte Repository-/Vendor-Signatur noch den Nachweis der "
                    "effektiven Pacman-Policy. Deshalb wird kein Root-Installationskommando erzeugt."
                ),
                (
                    "Der Offline-Adapter bleibt ein manueller Nicht-Ausführungs-Checkpoint, bis "
                    "Receipt, Artefakthash, Paketmetadaten und Zielpolicy atomar verifiziert werden können."
                ),
            )
            return (), (), (), tuple(manual), warnings

        argv = ("pacman", "--sync", "--needed", "--noconfirm", "--", *native)
        command = PlannedCommand(
            action_id=_stable_action_id(self.adapter_id, native),
            argv=argv,
            description="Signaturgeprüfte Arch-Pakete mit --needed installieren.",
            idempotency="pacman --needed überspringt bereits aktuelle Pakete",
            verify_argv=("pacman", "--query", "--", *native),
            network_policy="permitted",
        )
        return (command,), (), (), (), ()


class NixOSAdapter(DistributionAdapter):
    adapter_id = "nixos"
    family = "nixos"
    distribution_ids = frozenset({"nixos"})
    distribution_likes = frozenset({"nixos"})
    # nix is commonly installed on non-NixOS systems, so its mere presence is
    # not sufficient evidence for applying a NixOS module.
    package_managers = frozenset()
    priority = 100

    def _build_plan(self, native, resolutions, *, offline, offline_artifacts):
        del resolutions, offline_artifacts
        if not native:
            return (), (), (), (), ()
        if any(not _NIX_ATTRIBUTE.fullmatch(package) for package in native):
            raise ValueError("unsafe Nix attribute in fixed mapping")
        body = "\n".join(f"    {package}" for package in native)
        content = (
            "# Managed by umzug. Review and import explicitly.\n"
            "{ pkgs, ... }:\n"
            "{\n"
            "  environment.systemPackages = with pkgs; [\n"
            f"{body}\n"
            "  ];\n"
            "}\n"
        )
        file = DeclarativeFile(
            path="/etc/nixos/umzug-packages.nix",
            content=content,
            merge_strategy="manual-import",
            description="Deterministisches NixOS-Modul für die ausgewählten Pakete.",
        )
        manual = (
            "Nach Diff und Backup ./umzug-packages.nix explizit in imports der configuration.nix aufnehmen.",
            "Danach zuerst 'nixos-rebuild dry-build' und 'nixos-rebuild test' ausführen; erst nach Verifikation boot/switch verwenden.",
        )
        warnings = (
            "Das Modul wird nicht automatisch importiert; damit kann eine fremde Migration die aktive NixOS-Konfiguration nicht still verändern.",
        )
        if offline:
            warnings += (
                "Der lokale Nix-Store muss sämtliche referenzierten, signatur- beziehungsweise hashgeprüften Derivationen enthalten; Substituter sind während des Tests zu deaktivieren.",
            )
        return (), (file,), (), manual, warnings


class GentooAdapter(DistributionAdapter):
    adapter_id = "gentoo"
    family = "gentoo"
    distribution_ids = frozenset({"gentoo", "funtoo"})
    distribution_likes = frozenset({"gentoo"})
    package_managers = frozenset({"portage"})
    priority = 90

    def _build_plan(self, native, resolutions, *, offline, offline_artifacts):
        del offline_artifacts
        if not native:
            return (), (), (), (), ()
        canonical = {item.canonical for item in resolutions if item.resolved}
        flags: list[UseFlagSetting] = []
        if "mac-apparmor" in canonical:
            flags.append(
                UseFlagSetting(
                    target="*/*",
                    enable=("apparmor",),
                    rationale="AppArmor-Unterstützung konsistent in abhängigen Paketen aktivieren.",
                )
            )
        if "mac-selinux" in canonical:
            flags.append(
                UseFlagSetting(
                    target="*/*",
                    enable=("selinux",),
                    rationale="SELinux-Unterstützung ist auf Gentoo eine systemweite ABI-/USE-Entscheidung.",
                )
            )
        if "sudo" in canonical:
            flags.append(
                UseFlagSetting(
                    target="app-admin/sudo",
                    enable=("pam",),
                    rationale="PAM-Integration für das geplante Authentifizierungsprofil erhalten.",
                )
            )
        files: tuple[DeclarativeFile, ...] = ()
        if flags:
            lines = []
            for setting in flags:
                values = [*setting.enable, *(f"-{flag}" for flag in setting.disable)]
                lines.append(f"{setting.target} {' '.join(values)}")
            files = (
                DeclarativeFile(
                    path="/etc/portage/package.use/umzug",
                    content="\n".join(sorted(lines)) + "\n",
                    merge_strategy="merge-keyed-lines",
                    description="Explizite, prüfbare USE-Flag-Anforderungen des Migrationsplans.",
                ),
            )
        if offline:
            manual = (
                (
                    "NICHT AUSFÜHREN (Fail-closed-Checkpoint): Lokale Gentoo-Binärpakete aus "
                    "APPROVED werden nicht durch emerge oder einen anderen Root-Befehl installiert."
                ),
                (
                    "Vor einer künftigen Freigabe muss ein außerhalb des Migrationspakets "
                    "verankerter Vendor-/Repository-Signaturreceipt für jedes Binärpaket den "
                    "exakten SHA-256-Hash, CPV/Paketidentität, BUILD_ID, Zielarchitektur/CHOST und "
                    "die relevanten USE-Metadaten an den erwarteten Signer-Fingerprint binden."
                ),
                (
                    "Zusätzlich muss die effektiv ausgewertete Portage-Signaturpolicy mitsamt "
                    "Includes, aktiven Binpkg-Verifikationsoptionen und vertrauenswürdig "
                    "provisioniertem Schlüsselmaterial unabhängig nachgewiesen werden; die "
                    "aktuelle Adapter-Schnittstelle kann diese Beweise nicht transportieren oder "
                    "bis zur Ausführung binden."
                ),
            )
            warnings = (
                (
                    "Vor Apply müssen die deklarativen USE-Flag-Änderungen und daraus folgende "
                    "Rebuilds separat geprüft und bestätigt werden."
                ),
                (
                    "Fail-closed: APPROVED ist kein Vendor-Vertrauensbeweis. Der Offline-Adapter "
                    "erzeugt weder 'emerge --usepkgonly' noch ein anderes Root-Installationskommando."
                ),
                (
                    "Die Paketinstallation bleibt ein manueller Nicht-Ausführungs-Checkpoint, bis "
                    "Receipt, Artefakthash, Paketmetadaten und Zielpolicy atomar verifiziert werden können."
                ),
            )
            return (), files, tuple(flags), manual, warnings

        argv = ["emerge", "--noreplace"]
        argv.extend(("--", *native))
        command = PlannedCommand(
            action_id=_stable_action_id(self.adapter_id, native),
            argv=tuple(argv),
            description="Gentoo-Pakete unter Berücksichtigung bestätigter USE-Flags planen/installieren.",
            idempotency="emerge --noreplace installiert vorhandene Atome nicht erneut",
            verify_argv=("qlist", "-IC", *native),
            network_policy="permitted",
            reboot_may_be_required=bool({"mac-apparmor", "mac-selinux"}.intersection(canonical)),
        )
        warnings = (
            "Vor Apply müssen 'emerge --pretend --verbose' sowie Änderungen der USE-Flags und daraus folgende Rebuilds separat bestätigt werden.",
        )
        return (command,), files, tuple(flags), (), warnings


class LFSAdapter(DistributionAdapter):
    adapter_id = "lfs"
    family = "lfs"
    distribution_ids = frozenset({"lfs", "linuxfromscratch"})
    distribution_likes = frozenset({"lfs"})
    priority = 110

    def resolve_package(self, requested: str) -> PackageResolution:
        base = super().resolve_package(requested)
        canonical = base.canonical
        if canonical and canonical in canonical_capabilities():
            return PackageResolution(
                requested=requested,
                canonical=canonical,
                status="manual",
                rationale=(
                    "LFS besitzt keinen standardisierten Paketmanager. Quelle, Version, Patchsatz, "
                    "Build-Anleitung, Hash und installierte Dateiliste müssen lokal dokumentiert und "
                    "manuell bestätigt werden."
                ),
            )
        return base

    def _build_plan(self, native, resolutions, *, offline, offline_artifacts):
        del native, offline, offline_artifacts
        actions = tuple(
            f"LFS-Buildrezept für Capability {item.canonical!r} erstellen oder Anforderung verwerfen."
            for item in resolutions
            if item.canonical
        )
        warnings = (
            "Best-Effort-Modus: Ohne lokale Paketdatenbank sind Vollständigkeit, Updates und sicherer Rollback nicht automatisch beweisbar.",
            "Es werden absichtlich keine Build-Skripte aus der Migration ausgeführt und keine Installationskommandos erzeugt.",
        )
        return (), (), (), actions, warnings


class GenericAdapter(DistributionAdapter):
    """safe fallback: inventory and manual decisions, never guessed commands."""

    adapter_id = "generic"
    family = "generic"
    priority = -100

    def __init__(self, package_manager: str = "none") -> None:
        self.detected_package_manager = package_manager

    def _build_plan(self, native, resolutions, *, offline, offline_artifacts):
        del native, offline, offline_artifacts
        actions = tuple(
            f"Capability {item.canonical or item.requested!r} für Paketmanager {self.detected_package_manager!r} manuell zuordnen oder verwerfen."
            for item in resolutions
        )
        return (
            (),
            (),
            (),
            actions,
            ("Generischer Adapter: Es werden keine Paketnamen oder privilegierten Kommandos geraten.",),
        )


class AdapterRegistry:
    """small extensibility point for additional distribution adapters."""

    def __init__(self, adapters: Iterable[type[DistributionAdapter]] | None = None) -> None:
        initial = adapters or (
            LFSAdapter,
            NixOSAdapter,
            GentooAdapter,
            DebianAdapter,
            ArchAdapter,
        )
        self._adapters: list[type[DistributionAdapter]] = []
        for adapter in initial:
            self.register(adapter)

    def register(self, adapter: type[DistributionAdapter]) -> None:
        if not isinstance(adapter, type) or not issubclass(adapter, DistributionAdapter):
            raise TypeError("adapter must be a DistributionAdapter class")
        if adapter in self._adapters:
            return
        self._adapters.append(adapter)
        self._adapters.sort(key=lambda item: item.priority, reverse=True)

    def select(
        self,
        system: SystemFacts | DistributionInfo | str,
        package_managers: Sequence[str] | None = None,
    ) -> DistributionAdapter:
        if isinstance(system, SystemFacts):
            distro = system.distribution
            managers = system.package_managers
        elif isinstance(system, DistributionInfo):
            distro = system
            managers = tuple(package_managers or ())
        elif isinstance(system, str):
            distro = DistributionInfo(id=system.strip().lower(), name=system)
            managers = tuple(package_managers or ())
        else:
            raise TypeError("system must be SystemFacts, DistributionInfo, or distribution id")
        # distribution identity is stronger evidence than an additional
        # package manager (for example debian may also have nix installed).
        for adapter_type in self._adapters:
            adapter = adapter_type()
            if distro.id in adapter.distribution_ids or adapter.distribution_likes.intersection(distro.id_like):
                return adapter
        for adapter_type in self._adapters:
            adapter = adapter_type()
            if adapter.package_managers.intersection(managers):
                return adapter
        return GenericAdapter(managers[0] if managers else "none")


DEFAULT_REGISTRY = AdapterRegistry()


def select_adapter(
    system: SystemFacts | DistributionInfo | str,
    package_managers: Sequence[str] | None = None,
) -> DistributionAdapter:
    return DEFAULT_REGISTRY.select(system, package_managers)


# explicit aliases keep the extension API unsurprising for callers while all
# selection remains centralised in the registry.
get_adapter = select_adapter
adapter_for = select_adapter


__all__ = [
    "AdapterRegistry",
    "ArchAdapter",
    "DebianAdapter",
    "DeclarativeFile",
    "DistributionAdapter",
    "GenericAdapter",
    "GentooAdapter",
    "LFSAdapter",
    "NixOSAdapter",
    "PackagePlan",
    "PackageResolution",
    "PlannedCommand",
    "UseFlagSetting",
    "adapter_for",
    "canonical_capabilities",
    "get_adapter",
    "select_adapter",
]
