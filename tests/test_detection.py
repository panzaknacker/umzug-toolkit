from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from umzug.adapters import (  # noqa: E402
    ArchAdapter,
    DebianAdapter,
    GenericAdapter,
    GentooAdapter,
    LFSAdapter,
    NixOSAdapter,
    select_adapter,
)
from umzug.detection import (  # noqa: E402
    DistributionInfo,
    SystemDetector,
    safe_run,
)


class LinuxTree:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "root"
        self.proc = self.base / "proc"
        self.sys = self.base / "sys"
        for directory in (self.root, self.proc, self.sys):
            directory.mkdir()

    def close(self) -> None:
        self.temporary.cleanup()

    def text(self, tree: Path, relative: str, value: str = "") -> Path:
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
        return path

    def binary(self, tree: Path, relative: str, value: bytes) -> Path:
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return path

    def directory(self, tree: Path, relative: str) -> Path:
        path = tree / relative
        path.mkdir(parents=True, exist_ok=True)
        return path

    def symlink(self, tree: Path, relative: str, target: str) -> Path:
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
        return path

    def detector(self, **kwargs) -> SystemDetector:
        return SystemDetector(
            root=self.root,
            proc=self.proc,
            sys=self.sys,
            machine=kwargs.pop("machine", "x86_64"),
            allow_commands=False,
            **kwargs,
        )


class DetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = LinuxTree()

    def tearDown(self) -> None:
        self.tree.close()

    def test_complete_debian_uefi_hardware_and_encrypted_storage(self) -> None:
        # test the common absolute /etc/os-release link.  the injected resolver
        # must map it into tree.root, not read the test host's distribution.
        self.tree.text(
            self.tree.root,
            "usr/lib/os-release",
            'NAME="Debian GNU/Linux"\n'
            'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n'
            "ID=debian\n"
            "VERSION_ID=13\n"
            "VERSION_CODENAME=trixie\n",
        )
        self.tree.symlink(self.tree.root, "etc/os-release", "/usr/lib/os-release")
        self.tree.text(self.tree.root, "usr/bin/apt-get")
        self.tree.text(self.tree.proc, "1/comm", "systemd\n")
        self.tree.text(self.tree.proc, "sys/kernel/osrelease", "6.12.30-test\n")
        self.tree.text(
            self.tree.proc,
            "cpuinfo",
            "processor: 0\nflags: fpu nx smep smap ibrs md_clear\n",
        )
        self.tree.text(
            self.tree.proc,
            "self/mounts",
            "/dev/mapper/cryptroot / ext4 rw,relatime 0 0\n/dev/sda1 /boot vfat rw,nosuid,nodev 0 0\n",
        )

        self.tree.directory(self.tree.sys, "firmware/efi/efivars")
        guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
        # efivarfs prefixes values with four attribute bytes.
        self.tree.binary(
            self.tree.sys,
            f"firmware/efi/efivars/SecureBoot-{guid}",
            b"\x07\x00\x00\x00\x01",
        )
        self.tree.binary(
            self.tree.sys,
            f"firmware/efi/efivars/SetupMode-{guid}",
            b"\x07\x00\x00\x00\x00",
        )

        self.tree.directory(self.tree.sys, "class/drm/card0")
        self.tree.symlink(
            self.tree.sys,
            "class/drm/card0/device",
            "/devices/pci0000:00/0000:00:02.0",
        )
        gpu = "devices/pci0000:00/0000:00:02.0"
        self.tree.text(self.tree.sys, f"{gpu}/vendor", "0x8086\n")
        self.tree.text(self.tree.sys, f"{gpu}/device", "0x46a6\n")
        self.tree.text(self.tree.sys, f"{gpu}/boot_vga", "1\n")
        self.tree.symlink(self.tree.sys, f"{gpu}/driver", "/bus/pci/drivers/i915")

        net = "devices/pci0000:00/0000:00:1f.6/net/enp0s31f6"
        self.tree.directory(self.tree.sys, net)
        self.tree.symlink(self.tree.sys, "class/net/enp0s31f6", "/" + net)
        self.tree.text(self.tree.sys, f"{net}/type", "1\n")
        self.tree.text(self.tree.sys, f"{net}/address", "02:00:00:00:00:01\n")
        self.tree.text(self.tree.sys, f"{net}/operstate", "up\n")
        self.tree.directory(self.tree.sys, f"{net}/device")
        self.tree.symlink(
            self.tree.sys,
            f"{net}/device/driver",
            "/bus/pci/drivers/e1000e",
        )
        wlan = "devices/pci0000:00/0000:00:14.3/net/wlan0"
        self.tree.directory(self.tree.sys, f"{wlan}/wireless")
        self.tree.symlink(self.tree.sys, "class/net/wlan0", "/" + wlan)
        self.tree.text(self.tree.sys, f"{wlan}/type", "1\n")
        self.tree.text(self.tree.sys, f"{wlan}/operstate", "down\n")
        self.tree.directory(self.tree.sys, f"{wlan}/device")

        self.tree.text(self.tree.sys, "class/rfkill/rfkill0/type", "wlan\n")
        self.tree.text(self.tree.sys, "class/rfkill/rfkill0/name", "phy0\n")
        self.tree.text(self.tree.sys, "class/rfkill/rfkill0/soft", "1\n")
        self.tree.text(self.tree.sys, "class/rfkill/rfkill0/hard", "0\n")
        self.tree.directory(self.tree.sys, "class/bluetooth/hci0")

        self.tree.text(self.tree.sys, "class/tpm/tpm0/tpm_version_major", "2\n")
        self.tree.directory(self.tree.sys, "kernel/iommu_groups/0")
        self.tree.text(
            self.tree.sys,
            "kernel/security/lockdown",
            "none [integrity] confidentiality\n",
        )

        disk = "devices/virtual/block/sda"
        part = f"{disk}/sda1"
        crypt = "devices/virtual/block/dm-0"
        self.tree.directory(self.tree.sys, disk)
        self.tree.directory(self.tree.sys, part)
        self.tree.directory(self.tree.sys, crypt)
        self.tree.symlink(self.tree.sys, "class/block/sda", "/" + disk)
        self.tree.symlink(self.tree.sys, "class/block/sda1", "/" + part)
        self.tree.symlink(self.tree.sys, "class/block/dm-0", "/" + crypt)
        self.tree.text(self.tree.sys, f"{disk}/size", "2000000\n")
        self.tree.text(self.tree.sys, f"{disk}/ro", "0\n")
        self.tree.text(self.tree.sys, f"{disk}/removable", "0\n")
        self.tree.text(self.tree.sys, f"{part}/partition", "1\n")
        self.tree.text(self.tree.sys, f"{part}/size", "1990000\n")
        self.tree.text(self.tree.sys, f"{crypt}/size", "1980000\n")
        self.tree.text(self.tree.sys, f"{crypt}/dm/name", "cryptroot\n")
        self.tree.text(self.tree.sys, f"{crypt}/dm/uuid", "CRYPT-LUKS2-deadbeef-cryptroot\n")
        self.tree.symlink(self.tree.sys, f"{crypt}/slaves/sda1", "/" + part)

        facts = self.tree.detector().detect()
        self.assertEqual(facts.distribution.id, "debian")
        self.assertEqual(facts.distribution.version_id, "13")
        self.assertEqual(facts.package_manager, "apt")
        self.assertEqual(facts.init_system, "systemd")
        self.assertEqual(facts.kernel, "6.12.30-test")
        self.assertEqual(facts.firmware.mode, "uefi")
        self.assertEqual(facts.firmware.secure_boot, "enabled")
        self.assertEqual(facts.gpus[0].vendor, "Intel")
        self.assertEqual(facts.gpus[0].driver, "i915")
        self.assertTrue(facts.gpus[0].boot_vga)
        self.assertEqual(
            {device.name: device.kind for device in facts.network_devices},
            {"enp0s31f6": "ethernet", "wlan0": "wifi"},
        )
        self.assertTrue(any(radio.kind == "bluetooth" for radio in facts.radios))
        self.assertTrue(any(radio.kind == "wlan" and radio.soft_blocked for radio in facts.radios))
        self.assertEqual(facts.hardware_security.tpm_versions, ("2.0",))
        self.assertTrue(facts.hardware_security.iommu)
        self.assertEqual(facts.hardware_security.kernel_lockdown, "integrity")
        self.assertIn("smep", facts.hardware_security.cpu_security_features)
        self.assertTrue(facts.storage.root_encrypted)
        self.assertEqual(facts.storage.encryption_types, ("LUKS",))
        cryptroot = next(device for device in facts.storage.block_devices if device.name == "dm-0")
        self.assertEqual(cryptroot.slaves, ("sda1",))

    def test_arch_bios_fallback_and_architecture_normalisation(self) -> None:
        self.tree.text(
            self.tree.root,
            "etc/os-release",
            "NAME=Arch Linux\nID=arch\nBUILD_ID=rolling\n",
        )
        self.tree.text(self.tree.root, "usr/bin/pacman")
        self.tree.text(self.tree.proc, "1/comm", "runit\n")
        facts = self.tree.detector(machine="arm64").detect()
        self.assertEqual(facts.distribution.id, "arch")
        self.assertEqual(facts.package_manager, "pacman")
        self.assertEqual(facts.init_system, "runit")
        self.assertEqual(facts.architecture, "aarch64")
        self.assertEqual(facts.firmware.mode, "bios")
        self.assertEqual(facts.firmware.secure_boot, "unsupported")

    def test_distribution_marker_fallbacks(self) -> None:
        cases = (
            ("etc/nixos-version", "24.11", "nixos", "nix"),
            ("etc/gentoo-release", "Gentoo Base System", "gentoo", "portage"),
            ("etc/lfs-release", "12.2", "lfs", "none"),
        )
        for marker, value, distro_id, manager in cases:
            with self.subTest(distro=distro_id):
                tree = LinuxTree()
                try:
                    tree.text(tree.root, marker, value + "\n")
                    facts = tree.detector().detect()
                    self.assertEqual(facts.distribution.id, distro_id)
                    self.assertEqual(facts.package_manager, manager)
                finally:
                    tree.close()

    def test_secure_boot_setup_mode_and_unreadable_variable(self) -> None:
        self.tree.directory(self.tree.sys, "firmware/efi/efivars")
        guid = "00000000-0000-0000-0000-000000000000"
        self.tree.binary(
            self.tree.sys,
            f"firmware/efi/efivars/SecureBoot-{guid}",
            b"\x07\x00\x00\x00\x00",
        )
        self.tree.binary(
            self.tree.sys,
            f"firmware/efi/efivars/SetupMode-{guid}",
            b"\x07\x00\x00\x00\x01",
        )
        self.assertEqual(self.tree.detector().detect_firmware().secure_boot, "setup")
        (self.tree.sys / f"firmware/efi/efivars/SecureBoot-{guid}").write_bytes(b"bad")
        self.assertEqual(self.tree.detector().detect_firmware().secure_boot, "unknown")

    def test_proc_mount_escaping_and_crypttab_are_parsed_without_shell(self) -> None:
        self.tree.text(
            self.tree.proc,
            "self/mounts",
            "/dev/sdb1 /media/My\\040Disk ext4 ro,nodev,nosuid,noexec 0 0\n",
        )
        self.tree.text(
            self.tree.root,
            "etc/crypttab",
            "# comment\narchive UUID=123 none luks\n'bad name' UUID=bad none luks\n",
        )
        storage = self.tree.detector().detect_storage()
        self.assertEqual(storage.mounts[0].target, "/media/My Disk")
        self.assertEqual(storage.configured_crypt_mappings, ("archive",))

    def test_missing_injected_proc_does_not_leak_host_kernel(self) -> None:
        missing_proc = self.tree.base / "missing-proc"
        detector = SystemDetector(
            root=self.tree.root,
            proc=missing_proc,
            sys=self.tree.sys,
            machine="i686",
            allow_commands=True,
        )
        facts = detector.detect()
        self.assertEqual(facts.kernel, "unknown")
        self.assertEqual(facts.architecture, "x86")

    def test_safe_run_preserves_arguments_and_rejects_nul(self) -> None:
        result = safe_run(("/usr/bin/printf", "%s", "$(not-executed)"))
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout, "$(not-executed)")
        with self.assertRaises(ValueError):
            safe_run(("/usr/bin/printf", "bad\x00value"))
        with self.assertRaises(ValueError):
            safe_run(("/usr/bin/printf", "safe"), env={"LD_PRELOAD": "/tmp/evil.so"})


class AdapterTests(unittest.TestCase):
    def test_selection_prefers_distribution_over_secondary_nix_manager(self) -> None:
        distro = DistributionInfo(id="debian", name="Debian", id_like=("debian",))
        adapter = select_adapter(distro, ("apt", "nix"))
        self.assertIsInstance(adapter, DebianAdapter)
        self.assertIsInstance(select_adapter("arch", ("pacman",)), ArchAdapter)
        self.assertIsInstance(select_adapter("nixos", ("nix",)), NixOSAdapter)
        self.assertIsInstance(select_adapter("gentoo", ("portage",)), GentooAdapter)
        self.assertIsInstance(select_adapter("lfs", ()), LFSAdapter)

    def test_debian_offline_plan_is_a_non_execution_checkpoint(self) -> None:
        plan = DebianAdapter().plan_packages(
            ("git", "build-essential", "--option", "evil package", "git"),
            offline=True,
        )
        self.assertEqual(plan.native_packages, ("git", "build-essential", "pkg-config"))
        self.assertFalse(plan.commands)
        self.assertEqual(len(plan.unresolved), 2)
        checkpoint = "\n".join((*plan.manual_actions, *plan.warnings))
        self.assertIn("NICHT AUSFÜHREN", checkpoint)
        self.assertIn("APPROVED", checkpoint)
        self.assertIn("InRelease/Release", checkpoint)
        self.assertIn("SHA-256", checkpoint)
        self.assertIn("transitive Closure", checkpoint)
        self.assertIn("kein privilegiertes APT-Installationskommando", checkpoint)
        self.assertIn("apt-get --no-download", checkpoint)
        self.assertNotIn("--option", " ".join(argument for command in plan.commands for argument in command.argv))
        self.assertNotIn("evil package", " ".join(argument for command in plan.commands for argument in command.argv))

    def test_debian_online_plan_remains_explicitly_network_permitted(self) -> None:
        plan = DebianAdapter().plan_packages(("git", "curl"), offline=False)
        self.assertEqual(len(plan.commands), 1)
        command = plan.commands[0]
        self.assertEqual(command.network_policy, "permitted")
        self.assertNotIn("--no-download", command.argv)
        self.assertIn("idempotent", command.description)

    def test_plan_action_id_and_nix_module_are_deterministic(self) -> None:
        first = DebianAdapter().plan_packages(("git", "curl"), offline=False)
        second = DebianAdapter().plan_packages(("git", "curl"), offline=False)
        self.assertEqual(first.commands[0].action_id, second.commands[0].action_id)

        nix = NixOSAdapter().plan_packages(("git", "python3", "firewall"))
        self.assertFalse(nix.commands)
        self.assertEqual(nix.files[0].path, "/etc/nixos/umzug-packages.nix")
        self.assertIn("environment.systemPackages", nix.files[0].content)
        self.assertIn("    nftables\n", nix.files[0].content)
        self.assertEqual(nix.files[0].merge_strategy, "manual-import")

    def test_arch_offline_local_packages_are_a_non_execution_checkpoint(self) -> None:
        missing = ArchAdapter().plan_packages(("git",), offline=True)
        self.assertFalse(missing.commands)
        self.assertTrue(missing.manual_actions)
        supplied = ArchAdapter().plan_packages(
            ("git",),
            offline=True,
            offline_artifacts={"git": "/mnt/approved/packages/git.pkg.tar.zst"},
        )
        self.assertFalse(supplied.commands)
        checkpoint = "\n".join((*supplied.manual_actions, *supplied.warnings))
        self.assertIn("NICHT AUSFÜHREN", checkpoint)
        self.assertIn("Vendor-/Repository-Signaturreceipt", checkpoint)
        self.assertIn("SHA-256", checkpoint)
        self.assertIn("Paketname, Version und Architektur", checkpoint)
        self.assertIn("effektiv ausgewertete Pacman-Signaturpolicy", checkpoint)
        self.assertIn("kein Root-Installationskommando", checkpoint)
        with self.assertRaises(ValueError):
            ArchAdapter().plan_packages(
                ("git",),
                offline=True,
                offline_artifacts={"git": "../../untrusted.pkg.tar.zst"},
            )

        online = ArchAdapter().plan_packages(("git",), offline=False)
        self.assertEqual(online.commands[0].argv[1], "--sync")
        self.assertEqual(online.commands[0].network_policy, "permitted")

    def test_gentoo_offline_binpkgs_are_a_non_execution_checkpoint(self) -> None:
        plan = GentooAdapter().plan_packages(("apparmor", "selinux", "sudo"), offline=True)
        self.assertEqual({flag.enable[0] for flag in plan.use_flags}, {"apparmor", "selinux", "pam"})
        self.assertFalse(plan.commands)
        self.assertEqual(plan.files[0].path, "/etc/portage/package.use/umzug")
        checkpoint = "\n".join((*plan.manual_actions, *plan.warnings))
        self.assertIn("NICHT AUSFÜHREN", checkpoint)
        self.assertIn("Vendor-/Repository-Signaturreceipt", checkpoint)
        self.assertIn("SHA-256", checkpoint)
        self.assertIn("CPV/Paketidentität", checkpoint)
        self.assertIn("effektiv ausgewertete Portage-Signaturpolicy", checkpoint)
        self.assertNotIn(
            "emerge --usepkgonly", " ".join(argument for command in plan.commands for argument in command.argv)
        )

        online = GentooAdapter().plan_packages(("sudo",), offline=False)
        self.assertEqual(online.commands[0].argv[0], "emerge")
        self.assertEqual(online.commands[0].network_policy, "permitted")

    def test_lfs_and_generic_never_guess_privileged_commands(self) -> None:
        lfs = LFSAdapter().plan_packages(("git", "firewall"))
        self.assertFalse(lfs.commands)
        self.assertEqual(len(lfs.unresolved), 2)
        self.assertTrue(lfs.manual_actions)
        generic = GenericAdapter("custom-pm").plan_packages(("git", "odd-package"))
        self.assertFalse(generic.commands)
        self.assertTrue(all(item.status == "manual" for item in generic.resolutions))

    def test_untrusted_package_request_count_is_bounded(self) -> None:
        with self.assertRaises(ValueError):
            DebianAdapter().plan_packages("git" for _ in range(4097))


if __name__ == "__main__":
    unittest.main()
