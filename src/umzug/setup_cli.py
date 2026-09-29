from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import tarfile
import tomllib
from typing import Any, Iterable

from . import __version__
from .adapters import select_adapter
from .console import require_proven_local_console
from .detection import SystemFacts, detect_system
from .executor import Executor, StateStore, rollback
from .hardening import build_hardening_plan, load_profile
from .hardware_preflight import (
    ATTESTATION_IDS,
    build_hardware_preflight_report,
    compare_plan_target,
    human_hardware_preflight,
    observe_offline_boundary,
)
from .manifest import (
    decrypt_bundle,
    load_and_verify_manifest,
    safe_extract_bundle,
    safe_extract_source,
    verify_source_tar_manifest,
)
from .model import (
    Action,
    EXECUTABLE_SEARCH_PATH,
    Plan,
    prepend_executable_preflights,
)
from .network import collect_network_evidence, recover_network, validate_interfaces
from .package_actions import (
    mullvad_install_action,
    mullvad_management_actions,
    package_actions,
)
from .projects import inspect_project
from .restore_metadata import apply_safe_restore_metadata
from .restore_trust import (
    private_restore_workspace_snapshot,
    prepare_private_restore_staging,
    publish_restore_receipts,
    require_inert_restore_destination,
    reverify_restore_trust as _reverify_restore_trust,
)
from .scanner import (
    SCHEMA_VERSION,
    ApprovalDecision,
    ApprovalRecord,
    ScanPolicy,
    ScannerError,
    Stage,
    ZeroTrustPipeline,
    ZeroTrustScanner,
)
from .state_storage import (
    observe_persistent_state_storage,
    require_matching_state_storage,
)
from .source_media import inspect_mount, mount_read_only, require_safe_source_mount
from .transport import reassemble
from .util import (
    AuditLog,
    UmzugError,
    atomic_write,
    canonical_json,
    clean_relative,
    contained,
    sha256_file,
    terminal_safe,
)
from .vpn import (
    finalize_mullvad_app,
    mullvad_platform_status,
    require_completed_plan_context,
)
from .vendor import load_vendor_receipt, verify_detached_openpgp


DEFAULT_STATE = Path("/var/lib/umzug")
MAX_PLAN_BYTES = 16 * 1024 * 1024
MULLVAD_SENSITIVE_STATE = (
    Path("/etc/mullvad-vpn/account-history.json"),
    Path("/etc/mullvad-vpn/device.json"),
)


def _mullvad_state_covered_by_encrypted_root(storage: Any) -> bool:
    if getattr(storage, "root_encrypted", None) is not True:
        return False
    for mount in getattr(storage, "mounts", ()):
        raw_target = getattr(mount, "target", None)
        if not isinstance(raw_target, str) or not raw_target.startswith("/"):
            return False
        target = Path(raw_target)
        if target != Path("/") and any(
            target == sensitive or target in sensitive.parents for sensitive in MULLVAD_SENSITIVE_STATE
        ):
            # detection currently proves encryption ancestry only for the root
            # mount.  never infer protection for a separate /etc subtree.
            return False
    return True


def _require_root_owned_runtime() -> None:
    """reject privileged execution from a mutable user-owned python tree."""

    if os.geteuid() != 0:
        return
    package_dir = Path(__file__).resolve().parent
    targets = [
        Path(sys.executable).resolve(strict=True),
        package_dir,
        *sorted(package_dir.glob("*.py")),
    ]
    checked: set[Path] = set()
    for target in targets:
        for current in (target, *target.parents):
            if current == Path("/") or current in checked:
                continue
            checked.add(current)
            try:
                info = current.lstat()
            except OSError as exc:
                raise UmzugError("privileged toolkit runtime cannot be inspected safely") from exc
            if stat.S_ISLNK(info.st_mode):
                raise UmzugError(f"privileged toolkit runtime contains a symlink: {current}")
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise UmzugError(f"privileged toolkit runtime is not root-owned and non-writable: {current}")
    if not targets[0].is_file() or any(not path.is_file() for path in targets[2:]):
        raise UmzugError("privileged toolkit runtime contains a non-regular program file")


def _add_scanner_config(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--scanner-config", type=Path, help="TOML with pinned scanner/rule/signature hashes")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="setup",
        description="Offline-first zero-trust migration and hardening planner/executor.",
    )
    parser.add_argument("--log", type=Path, help="redacted local JSONL audit log")
    sub = parser.add_subparsers(dest="command")

    detect = sub.add_parser("detect", help="read-only distribution and hardware detection")
    detect.add_argument("--root", type=Path, default=Path("/"))
    detect.add_argument("--proc", type=Path, default=Path("/proc"))
    detect.add_argument("--sys", type=Path, default=Path("/sys"))
    detect.add_argument("--no-commands", action="store_true")
    detect.add_argument("--json", action="store_true")

    mount = sub.add_parser("mount-source", help="mount a block device read-only and inert")
    mount.add_argument("device", type=Path)
    mount.add_argument("mountpoint", type=Path)
    mount.add_argument("--confirm", action="store_true", required=True)

    ingest = sub.add_parser("ingest", help="verify and import a signed bundle into zero-trust stages")
    ingest.add_argument("package", type=Path)
    ingest.add_argument("--workspace", type=Path, required=True)
    ingest.add_argument("--decrypt", choices=("auto", "none", "age", "gpg"), default="auto")
    trust = ingest.add_mutually_exclusive_group(required=True)
    trust.add_argument("--trusted-key", type=Path)
    trust.add_argument("--fingerprint")
    ingest.add_argument("--allow-unsafe-source-mount-for-testing", action="store_true")
    ingest.add_argument("--max-payload-bytes", type=int, default=2**43)
    ingest.add_argument("--age-identity", type=Path, help="explicit local age identity (mode 0600 or stricter)")
    _add_scanner_config(ingest)

    scan = sub.add_parser("scan", help="scan one trust-stage candidate and write a report")
    scan.add_argument("--workspace", type=Path, required=True)
    scan.add_argument("--candidate", required=True)
    scan.add_argument("--stage", choices=("SOURCE", "QUARANTINE", "SANITIZED", "APPROVED"), default="QUARANTINE")
    scan.add_argument("--report", type=Path)
    scan.add_argument("--relaxed-test-mode", action="store_true")
    _add_scanner_config(scan)

    promote = sub.add_parser("promote", help="promote an unchanged QUARANTINE candidate to SANITIZED")
    promote.add_argument("--workspace", type=Path, required=True)
    promote.add_argument("--candidate", required=True)
    promote.add_argument("--expected-manifest", required=True)
    promote.add_argument("--accept-finding", action="append", default=[])
    _add_scanner_config(promote)

    approve = sub.add_parser("approve", help="explicitly approve a hash-bound SANITIZED candidate")
    approve.add_argument("--workspace", type=Path, required=True)
    approve.add_argument("--candidate", required=True)
    approve.add_argument("--expected-manifest", required=True)
    approve.add_argument("--actor", required=True)
    approve.add_argument("--reason", required=True)
    approve.add_argument("--accept-finding", action="append", default=[])
    approve.add_argument("--confirm-approval", required=True, metavar="CANDIDATE")
    _add_scanner_config(approve)

    restore = sub.add_parser("restore", help="restore only unchanged APPROVED content; never overwrite")
    restore.add_argument("--workspace", type=Path, required=True)
    restore.add_argument("--candidate", required=True)
    restore.add_argument(
        "--destination",
        type=Path,
        required=True,
        help=("must equal /var/lib/umzug/restored-staging/CANDIDATE; active system and dotfile targets are forbidden"),
    )
    restore.add_argument("--confirm-restore", required=True, metavar="CANDIDATE")
    restore.add_argument("--trusted-key", type=Path, help="independent signing public key outside the workspace")
    restore.add_argument("--fingerprint", help="independently recorded SHA-256 fingerprint of the signing key")
    restore.add_argument("--expected-approval-sha256", required=True, help="out-of-band approval receipt SHA-256")
    restore.add_argument("--max-payload-bytes", type=int, default=2**43)
    _add_scanner_config(restore)

    project = sub.add_parser("project-report", help="inspect an APPROVED project without executing it")
    project.add_argument("--workspace", type=Path, required=True)
    project.add_argument("--candidate", required=True)
    project.add_argument("--output", type=Path)

    vendor = sub.add_parser(
        "verify-vendor", help="verify an APPROVED offline vendor artifact with a pinned detached signature"
    )
    vendor.add_argument("--workspace", type=Path, required=True)
    vendor.add_argument("--candidate", required=True)
    vendor.add_argument("--artifact", required=True, help="relative path below APPROVED candidate")
    vendor.add_argument("--signature", required=True, help="relative detached-signature path below APPROVED candidate")
    vendor.add_argument("--signing-key", type=Path, required=True)
    vendor.add_argument(
        "--artifact-sha256",
        required=True,
        help="independently obtained SHA-256 of the exact vendor release artifact",
    )
    vendor.add_argument("--fingerprint", required=True)
    vendor.add_argument("--gpg-sha256", required=True)
    vendor.add_argument("--gpgv-sha256", required=True)
    vendor.add_argument("--bwrap-sha256", required=True)
    vendor.add_argument("--receipt", type=Path)

    plan = sub.add_parser("plan", help="create a declarative offline package/hardening plan")
    plan.add_argument("--profile", choices=("compatible", "strict", "maximal"), default="strict")
    plan.add_argument("--profile-file", type=Path)
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--ethernet", action="append", default=[])
    plan.add_argument("--radio-module", action="append", default=[])
    plan.add_argument("--capability", action="append", default=[])
    plan.add_argument("--offline-artifact", action="append", default=[], metavar="NATIVE_PACKAGE=/APPROVED/PATH")
    plan.add_argument("--workspace", type=Path, help="required when offline artifacts are referenced")
    plan.add_argument("--mullvad-management-group", default="mullvad-management")
    plan.add_argument("--no-mullvad-app-preparation", action="store_true")
    plan.add_argument("--mullvad-artifact", type=Path, help="APPROVED .deb/.rpm bound to a vendor receipt")
    plan.add_argument("--mullvad-vendor-receipt", type=Path)
    plan.add_argument(
        "--mullvad-artifact-sha256",
        help="independent SHA-256 of the exact Mullvad release artifact",
    )
    plan.add_argument("--mullvad-fingerprint", help="independent 40-hex vendor key anchor, required with artifact")
    plan.add_argument("--mullvad-gpg-sha256", help="independent gpg binary hash, required with artifact")
    plan.add_argument("--mullvad-gpgv-sha256", help="independent gpgv binary hash, required with artifact")
    plan.add_argument("--mullvad-bwrap-sha256", help="independent bubblewrap binary hash, required with artifact")
    plan.add_argument(
        "--mullvad-package-version",
        help="independently recorded exact mullvad-vpn package version, required with artifact",
    )
    plan.add_argument(
        "--mullvad-package-architecture",
        help="independently recorded exact package architecture, required with artifact",
    )

    hardware_preflight = sub.add_parser(
        "hardware-preflight",
        help="read-only local-console hardware/recovery preflight for a reviewed plan",
    )
    hardware_preflight.add_argument("plan", type=Path)
    hardware_preflight.add_argument(
        "--expected-plan-sha256",
        required=True,
        help="independently recorded SHA-256 shown during plan creation",
    )
    hardware_preflight.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    hardware_preflight.add_argument(
        "--recovery-medium",
        type=Path,
        help="already mounted, separate non-ephemeral recovery filesystem",
    )
    hardware_preflight.add_argument(
        "--attest",
        action="append",
        choices=sorted(ATTESTATION_IDS),
        default=[],
        metavar="STATEMENT",
        help="explicit manual statement; repeat only after performing the stated local test",
    )
    hardware_preflight.add_argument("--json", action="store_true")

    apply = sub.add_parser("apply", help="apply an already reviewed plan with checkpoints")
    apply.add_argument("plan", type=Path)
    apply.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    apply.add_argument("--system-root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    apply.add_argument("--dry-run", action="store_true")
    apply.add_argument(
        "--expected-plan-sha256",
        help="out-of-band SHA-256 shown during plan creation; required for every productive apply",
    )
    apply.add_argument("--yes", action="store_true")
    apply.add_argument("--approve", action="append", default=[], metavar="ACTION_ID")

    resume = sub.add_parser("resume", help="resume the saved plan after a verified reboot")
    resume.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    resume.add_argument("--yes", action="store_true")
    resume.add_argument("--approve", action="append", default=[])

    undo = sub.add_parser("rollback", help="restore all backed-up configuration from a checkpoint")
    undo.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    undo.add_argument("--system-root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    undo.add_argument("--dry-run", action="store_true")
    undo.add_argument("--confirm-rollback", action="store_true", required=True)

    recovery = sub.add_parser("recover-network", help="local-console removal of umzug firewall tables")
    recovery.add_argument("--dry-run", action="store_true")
    recovery.add_argument("--confirm-recovery", action="store_true", required=True)

    report = sub.add_parser("report", help="write final local security/function evidence")
    report.add_argument("--output", type=Path, required=True)
    report.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    report.add_argument("--workspace", type=Path)

    vpn = sub.add_parser("vpn-finalize", help="final TTY-only Mullvad account/bootstrap step")
    vpn.add_argument("--state-dir", type=Path, default=DEFAULT_STATE)
    vpn.add_argument(
        "--expected-plan-sha256",
        required=True,
        help="out-of-band SHA-256 of the fully completed reviewed plan",
    )
    vpn.add_argument("--anti-censorship", choices=("auto", "udp2tcp", "shadowsocks", "quic", "lwo"), default="auto")
    vpn.add_argument("--management-group", default="mullvad-management")

    wizard = sub.add_parser("wizard", help="interactive detect/recommend/plan wizard")
    wizard.add_argument("--output", type=Path, default=Path("umzug-plan.json"))
    return parser


def _facts(*, allow_commands: bool = True) -> SystemFacts:
    return detect_system(allow_commands=allow_commands)


def _human_facts(facts: SystemFacts) -> None:
    print(
        f"Distribution: {facts.distribution.pretty_name or facts.distribution.name} ({facts.distribution.id} {facts.distribution.version_id})"
    )
    print(f"Paketmanager: {facts.package_manager}; Init: {facts.init_system}")
    print(f"Architektur/Kernel: {facts.architecture} / {facts.kernel}")
    print(f"Firmware: {facts.firmware.mode}; Secure Boot: {facts.firmware.secure_boot}")
    print(
        f"Root-Verschlüsselung: {facts.storage.root_encrypted}; Typen: {', '.join(facts.storage.encryption_types) or '-'}"
    )
    for gpu in facts.gpus:
        print(
            f"GPU: {gpu.vendor} {gpu.device_id}, Treiber={gpu.driver or '-'}, Kandidaten={','.join(gpu.recommended_drivers) or '-'}"
        )
    for device in facts.network_devices:
        print(f"Netz: {device.name}: {device.kind}, Treiber={device.driver or '-'}, Status={device.operstate}")
    if facts.radios:
        print("Funkgeräte: " + ", ".join(f"{item.name}({item.kind})" for item in facts.radios))
    if facts.hardware_security.tpm_devices:
        print("TPM: " + ", ".join(facts.hardware_security.tpm_devices))
    for warning in facts.warnings:
        print(f"WARNUNG: {warning}")


def _load_scanner_policy(path: Path | None, *, relaxed: bool = False) -> ScanPolicy:
    if relaxed:
        return ScanPolicy(strict_external=False, run_external_scanners=False)
    if path is None:
        return ScanPolicy()
    try:
        root = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise UmzugError(f"invalid scanner configuration: {exc}") from exc
    table = root.get("scanner")
    if not isinstance(table, dict):
        raise UmzugError("scanner configuration needs a [scanner] table")
    aliases = {
        "tool_hashes": "trusted_tool_hashes",
        "yara_rule_hashes": "trusted_yara_rule_hashes",
        "clam_signature_hashes": "trusted_clam_signature_hashes",
    }
    allowed = {field.name: field for field in dataclasses.fields(ScanPolicy)}
    boolean_fields = {name for name, field in allowed.items() if isinstance(field.default, bool)}
    integer_fields = {
        name
        for name, field in allowed.items()
        if isinstance(field.default, int) and not isinstance(field.default, bool)
    }
    kwargs: dict[str, Any] = {}
    for raw_key, value in table.items():
        key = aliases.get(raw_key, raw_key)
        if key not in allowed:
            raise UmzugError(f"unknown scanner policy field: {raw_key}")
        if key in {"yara_rule_paths", "clam_signature_paths"}:
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise UmzugError(f"{key} must be a list of path strings")
            kwargs[key] = tuple(Path(item).absolute() for item in value)
        elif key in {"required_external_scanners", "required_source_mount_options"}:
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise UmzugError(f"{key} must be a list of strings")
            kwargs[key] = tuple(value)
        elif key in {"trusted_tool_hashes", "trusted_yara_rule_hashes", "trusted_clam_signature_hashes"}:
            if not isinstance(value, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()
            ):
                raise UmzugError(f"{key} must be a string-to-string table")
            kwargs[key] = {k: v.lower() for k, v in value.items()}
        elif key in boolean_fields:
            if not isinstance(value, bool):
                raise UmzugError(f"{key} must be boolean")
            kwargs[key] = value
        elif key in integer_fields:
            if not isinstance(value, int) or isinstance(value, bool):
                raise UmzugError(f"{key} must be an integer")
            kwargs[key] = value
        elif key == "max_compression_ratio":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise UmzugError("max_compression_ratio must be numeric")
            kwargs[key] = float(value)
        else:
            kwargs[key] = value
    policy = ScanPolicy(**kwargs)
    _require_migration_scanner_floor(policy)
    return policy


def _require_migration_scanner_floor(policy: ScanPolicy) -> None:
    required_true = (
        "run_external_scanners",
        "strict_external",
        "require_verified_external_material",
        "require_secure_source_mount",
        "block_all_unknown_binary",
    )
    required_false = (
        "allow_unisolated_external_in_relaxed_mode",
        "allow_executable_files_after_review",
        "allow_cross_filesystems",
    )
    weakened = [name for name in required_true if getattr(policy, name) is not True]
    weakened.extend(name for name in required_false if getattr(policy, name) is not False)
    if policy.external_isolation_backend != "bubblewrap":
        weakened.append("external_isolation_backend")
    if not {"file", "clamscan", "yara"}.issubset(set(policy.required_external_scanners)):
        weakened.append("required_external_scanners")
    if not {"ro", "noexec", "nodev", "nosuid"}.issubset(set(policy.required_source_mount_options)):
        weakened.append("required_source_mount_options")

    defaults = ScanPolicy()
    bounded_fields = (
        "max_files",
        "max_inspect_bytes",
        "max_archive_input_bytes",
        "max_archive_member_bytes",
        "max_archive_expanded_bytes",
        "max_archive_members",
        "max_archive_depth",
        "max_compression_ratio",
        "max_text_bytes",
        "max_external_output_bytes",
        "external_timeout_seconds",
        "max_external_address_space_bytes",
        "max_external_cpu_seconds",
        "max_external_processes",
        "max_external_open_files",
    )
    for name in bounded_fields:
        if getattr(policy, name) > getattr(defaults, name):
            weakened.append(name)
    if weakened:
        raise UmzugError(
            "migration scanner policy may not weaken security floors: "
            + ", ".join(sorted(set(weakened)))
            + "; use --relaxed-test-mode only for isolated tests"
        )


def _pipeline(
    workspace: Path,
    config: Path | None,
    *,
    relaxed: bool = False,
    verified_derived_source: bool = False,
) -> ZeroTrustPipeline:
    policy = _load_scanner_policy(config, relaxed=relaxed)
    if verified_derived_source:
        # the actual transport was already proven ro/noexec/nodev/nosuid and
        # is bound below by transport, manifest and payload hashes. the safely
        # extracted local tree is an inert derived input, not a new source
        # medium. scanner reports make this narrowly scoped relaxation visible.
        policy = dataclasses.replace(policy, require_secure_source_mount=False)
    return ZeroTrustPipeline(workspace, ZeroTrustScanner(policy))


def _decrypt_mode(path: Path, selected: str) -> str:
    if selected != "auto":
        return selected
    lowered = path.name.lower()
    if lowered.endswith(".age"):
        return "age"
    if lowered.endswith((".gpg", ".pgp")):
        return "gpg"
    return "none"


def _snapshot_transport_input(source: Path, destination: Path, *, max_bytes: int) -> None:
    """copy one stable transport inode once, with a hard byte ceiling."""

    source_fd = destination_fd = -1
    destination_created = False
    try:
        source_fd = os.open(
            source,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise UmzugError("transport input must be a non-symlink regular file")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise UmzugError("transport package exceeds configured size limit")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        destination_created = True
        copied = 0
        while True:
            chunk = os.read(source_fd, min(1024 * 1024, max_bytes + 1 - copied))
            if not chunk:
                break
            copied += len(chunk)
            if copied > max_bytes:
                raise UmzugError("transport package grew beyond the configured size limit")
            view = memoryview(chunk)
            while view:
                view = view[os.write(destination_fd, view) :]
        after = os.fstat(source_fd)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if copied != before.st_size or any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise UmzugError("transport input changed while its bounded snapshot was created")
        os.fsync(destination_fd)
    except OSError as exc:
        if destination_created:
            with contextlib.suppress(FileNotFoundError):
                destination.unlink()
        raise UmzugError("transport input cannot be snapshotted safely") from exc
    except BaseException:
        if destination_created:
            with contextlib.suppress(FileNotFoundError):
                destination.unlink()
        raise
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)


def _ingest(args: argparse.Namespace, audit: AuditLog) -> dict[str, Any]:
    source = args.package.expanduser().absolute()
    if not args.allow_unsafe_source_mount_for_testing:
        mount = require_safe_source_mount(source)
    else:
        mount = inspect_mount(source)
        audit.event("source_mount.override_for_testing", mount=mount.to_dict())
    workspace = args.workspace.expanduser().absolute()
    if workspace.exists() and any(workspace.iterdir()):
        raise UmzugError("ingest workspace must be absent or empty")
    workspace.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(workspace, 0o700)
    state_dir = workspace / "state" / "bundle"
    state_dir.mkdir(parents=True, mode=0o700)
    material = state_dir / "transport-input"
    if source.name.endswith(".parts.json"):
        reassemble(source, material, max_bytes=args.max_payload_bytes + 128 * 1024 * 1024)
        source_name = json.loads(source.read_text(encoding="utf-8"))["source_name"]
        mode_hint = Path(str(source_name))
    else:
        # copy through a bounded local file before any parser consumes the untrusted medium.
        _snapshot_transport_input(source, material, max_bytes=args.max_payload_bytes)
        mode_hint = source
    bundle = state_dir / "bundle.tar"
    decrypt_bundle(
        material,
        bundle,
        _decrypt_mode(mode_hint, args.decrypt),
        max_output_bytes=args.max_payload_bytes + 128 * 1024 * 1024,
        age_identity=args.age_identity.expanduser().absolute() if args.age_identity else None,
    )
    extracted_dir = state_dir / "verified-container"
    extracted = safe_extract_bundle(bundle, extracted_dir, max_payload_bytes=args.max_payload_bytes)
    manifest, fingerprint = load_and_verify_manifest(
        extracted,
        trusted_public_key=args.trusted_key,
        expected_fingerprint=args.fingerprint,
    )
    verify_source_tar_manifest(extracted["umzug/SOURCE.tar"], manifest)
    raw_source = state_dir / "raw-source"
    extraction_errors = safe_extract_source(
        extracted["umzug/SOURCE.tar"], raw_source, max_total_bytes=args.max_payload_bytes
    )
    pipeline = _pipeline(workspace, args.scanner_config, verified_derived_source=True)
    candidates: list[dict[str, Any]] = []
    for row in manifest.get("selections", []):
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("id"), str)
            or not isinstance(row.get("archive_root"), str)
        ):
            extraction_errors.append("invalid selection mapping in manifest")
            continue
        relative = clean_relative(row["archive_root"])
        path = raw_source / relative
        if not os.path.lexists(path):
            extraction_errors.append(f"selection absent after safe extraction: {row['id']}")
            continue
        try:
            result = pipeline.ingest(path, row["id"])
            candidates.append(
                {
                    "id": row["id"],
                    "category": row.get("category"),
                    "original_path": row.get("original_path"),
                    "source_manifest": result.source_report.manifest_sha256,
                    "source_blockers": len(result.source_report.blockers),
                    "quarantine_manifest": result.quarantine_report.manifest_sha256,
                    "quarantine_blockers": len(result.quarantine_report.blockers),
                }
            )
        except (OSError, ScannerError, ValueError) as exc:
            extraction_errors.append(f"candidate {row['id']} ingest failed: {exc}")
    xattr_failures = [
        {"path": row.get("path"), "errors": row.get("xattr_errors")}
        for row in manifest.get("entries", [])
        if isinstance(row, dict) and row.get("xattr_errors")
    ]
    ingest_state = {
        "format": 1,
        "package": str(source),
        "source_mount": mount.to_dict(),
        "unsafe_source_mount_tainted": bool(args.allow_unsafe_source_mount_for_testing),
        "signing_key_fingerprint": fingerprint,
        "manifest_sha256": hashlib.sha256(extracted["umzug/manifest.json"].read_bytes()).hexdigest(),
        "transport_sha256": sha256_file(material),
        "verified_bundle_sha256": sha256_file(bundle),
        "source_payload_sha256": manifest["payload"]["sha256"],
        "extraction_policy": "regular-files/directories/symlinks/safe-hardlinks only; no devices/FIFOs/sockets; no path traversal; inert pipeline copy",
        "derived_source_mount_policy_relaxed": True,
        "manifest_warnings": manifest.get("warnings", []),
        "xattr_failures": xattr_failures,
        "extraction_errors": extraction_errors,
        "candidates": candidates,
        "status": "quarantined" if not extraction_errors else "quarantined-with-blockers",
        "statement": "All candidate bytes remain untrusted. Only an explicit SANITIZED->APPROVED transition can make them restorable.",
    }
    atomic_write(workspace / "state" / "ingest.json", canonical_json(ingest_state), 0o600)
    audit.event(
        "bundle.ingested",
        fingerprint=fingerprint,
        candidate_count=len(candidates),
        extraction_error_count=len(extraction_errors),
        manifest_warning_count=len(ingest_state["manifest_warnings"]),
    )
    return ingest_state


def _require_clean_ingest(workspace: Path) -> dict[str, Any]:
    path = workspace / "state" / "ingest.json"
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"ingest state missing or invalid: {exc}") from exc
    blockers = {
        "extraction_errors": state.get("extraction_errors", []),
        "manifest_warnings": state.get("manifest_warnings", []),
        "xattr_failures": state.get("xattr_failures", []),
    }
    active = {key: value for key, value in blockers.items() if value}
    if state.get("unsafe_source_mount_tainted") is not False:
        active["unsafe_source_mount_tainted"] = (
            "true or missing/invalid; begin with a fresh ingest from a verified ro,noexec,nodev,nosuid source mount"
        )
    if active:
        raise UmzugError(
            f"package-level ingest blockers prevent promotion/approval: {json.dumps(active, sort_keys=True)[:2000]}"
        )
    return state


def _print_scan(report: Any) -> None:
    print(f"Scan-ID: {terminal_safe(report.scan_id)}")
    print(f"Manifest SHA-256: {terminal_safe(report.manifest_sha256)}")
    print(f"Dateien/Objekte: {len(report.records)}; Blocker: {len(report.blockers)}; Review: {len(report.reviews)}")
    for finding in report.findings:
        print(
            f"[{terminal_safe(finding.severity.value.upper())}] {terminal_safe(finding.id)} "
            f"{terminal_safe(finding.rule)} {terminal_safe(finding.path)}: {terminal_safe(finding.message)}"
        )
    print(terminal_safe(report.disclaimer))


def _load_approval(workspace: Path, candidate: str) -> ApprovalRecord:
    path = workspace / "state" / "approvals" / f"{candidate}.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        expected_fields = {
            "schema_version",
            "candidate",
            "actor",
            "reason",
            "approved_at",
            "source_stage",
            "manifest_sha256",
            "approved_manifest_sha256",
            "accepted_findings",
            "report_scan_id",
            "report_sha256",
            "ingest_provenance_sha256",
            "promotion_sha256",
            "source_manifest_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_manifest_sha256",
            "sanitized_manifest_sha256",
            "quarantine_report_scan_id",
            "quarantine_report_sha256",
            "promotion_accepted_findings",
            "approval_sha256",
        }
        if not isinstance(value, dict) or set(value) != expected_fields:
            raise UmzugError("approval record does not match the required exact schema")
        supplied_hash = value.pop("approval_sha256")
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        observed_hash = hashlib.sha256(canonical).hexdigest()
        if (
            not isinstance(supplied_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", supplied_hash)
            or not hmac.compare_digest(observed_hash, supplied_hash)
        ):
            raise UmzugError("approval record hash mismatch")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise UmzugError("approval record has an unsupported schema version")
        hash_fields = (
            "manifest_sha256",
            "approved_manifest_sha256",
            "report_sha256",
            "ingest_provenance_sha256",
            "promotion_sha256",
            "source_manifest_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_manifest_sha256",
            "sanitized_manifest_sha256",
            "quarantine_report_sha256",
        )
        if (
            type(value.get("schema_version")) is not int
            or value.get("candidate") != candidate
            or value.get("source_stage") != Stage.SANITIZED.value
            or any(
                not isinstance(value.get(field), str) or not value[field].strip()
                for field in (
                    "actor",
                    "reason",
                    "approved_at",
                    "report_scan_id",
                    "quarantine_report_scan_id",
                )
            )
            or any(
                not isinstance(value.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", value[field])
                for field in hash_fields
            )
            or not isinstance(value.get("accepted_findings"), list)
            or not isinstance(value.get("promotion_accepted_findings"), list)
            or any(not isinstance(row, str) or not row for row in value["accepted_findings"])
            or any(not isinstance(row, str) or not row for row in value["promotion_accepted_findings"])
            or value["accepted_findings"] != sorted(set(value["accepted_findings"]))
            or value["promotion_accepted_findings"] != sorted(set(value["promotion_accepted_findings"]))
        ):
            raise UmzugError("approval record has invalid candidate or finding bindings")
        return ApprovalRecord(
            schema_version=value["schema_version"],
            candidate=value["candidate"],
            actor=value["actor"],
            reason=value["reason"],
            approved_at=value["approved_at"],
            source_stage=Stage(value["source_stage"]),
            manifest_sha256=value["manifest_sha256"],
            approved_manifest_sha256=value["approved_manifest_sha256"],
            accepted_findings=tuple(value["accepted_findings"]),
            report_scan_id=value["report_scan_id"],
            report_sha256=value["report_sha256"],
            ingest_provenance_sha256=value["ingest_provenance_sha256"],
            promotion_sha256=value["promotion_sha256"],
            source_manifest_sha256=value["source_manifest_sha256"],
            source_snapshot_manifest_sha256=value["source_snapshot_manifest_sha256"],
            quarantine_manifest_sha256=value["quarantine_manifest_sha256"],
            sanitized_manifest_sha256=value["sanitized_manifest_sha256"],
            quarantine_report_scan_id=value["quarantine_report_scan_id"],
            quarantine_report_sha256=value["quarantine_report_sha256"],
            promotion_accepted_findings=tuple(value["promotion_accepted_findings"]),
            approval_sha256=supplied_hash,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, UmzugError):
            raise
        raise UmzugError(f"invalid approval record: {exc}") from exc


def _require_approved_unchanged(workspace: Path, candidate: str) -> tuple[Path, ApprovalRecord]:
    approval = _load_approval(workspace, candidate)
    root = (workspace / "APPROVED" / candidate).absolute()
    scanner = ZeroTrustScanner(
        ScanPolicy(
            strict_external=False,
            run_external_scanners=False,
            require_secure_source_mount=False,
        )
    )
    if scanner.current_manifest_sha256(root) != approval.approved_manifest_sha256:
        raise UmzugError("APPROVED candidate changed after its hash-bound approval")
    return root, approval


def _approved_relative(workspace: Path, candidate: str, raw: str) -> Path:
    root, _ = _require_approved_unchanged(workspace, candidate)
    relative = clean_relative(raw)
    path = root / relative
    if not contained(root, path) or path.is_symlink() or not path.is_file():
        raise UmzugError("vendor input must be a non-symlink regular file below the unchanged APPROVED candidate")
    return path


def _parse_artifacts(values: Iterable[str], workspace: Path | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if values and workspace is None:
        raise UmzugError("--workspace is mandatory with offline artifacts")
    approved = (workspace / "APPROVED").resolve() if workspace else None
    for value in values:
        if "=" not in value:
            raise UmzugError("offline artifacts use NATIVE_PACKAGE=/absolute/path")
        package, raw = value.split("=", 1)
        path = Path(raw).absolute().resolve(strict=True)
        if approved is None or not contained(approved, path) or path.is_symlink() or not path.is_file():
            raise UmzugError(f"offline artifact is not a regular file below APPROVED: {path}")
        relative = path.relative_to(approved)
        if len(relative.parts) < 2:
            raise UmzugError("offline artifact must belong to an approved candidate")
        _require_approved_unchanged(workspace, relative.parts[0])  # type: ignore[arg-type]
        result[package] = str(path)
    return result


def _build_plan(args: argparse.Namespace) -> tuple[Plan, dict[str, Any]]:
    facts = _facts()
    profile = load_profile(args.profile, args.profile_file)
    detected_ethernet = sorted(
        {item.name for item in facts.network_devices if item.kind == "ethernet" and not item.virtual}
    )
    requested_ethernet = args.ethernet or detected_ethernet
    if not requested_ethernet:
        raise UmzugError("no physical Ethernet interface detected; specify --ethernet only after verifying the device")
    ethernet = validate_interfaces(requested_ethernet)
    if profile["vpn_killswitch"] and ethernet != detected_ethernet:
        raise UmzugError(
            "a VPN kill-switch plan must bind the exact complete set of detected physical "
            "Ethernet interfaces; unselected interfaces are not disabled"
        )
    detected_radios = sorted(
        {item.driver for item in facts.network_devices if item.kind in {"wifi", "cellular"} and item.driver}
    )
    requested_radios = sorted({item.replace("-", "_") for item in args.radio_module if isinstance(item, str) and item})
    detected_radios = sorted({item.replace("-", "_") for item in detected_radios})
    if requested_radios and requested_radios != detected_radios:
        raise UmzugError(
            "--radio-module may only confirm the exact locally detected Wi-Fi/cellular driver set; "
            "arbitrary kernel-module overrides are forbidden"
        )
    radios = detected_radios
    hardening = build_hardening_plan(
        facts.to_dict(), profile=profile, ethernet_interfaces=ethernet, radio_modules=radios
    )
    # build_hardening_plan is independently valid and therefore contains its
    # own exact preflights.  the final setup plan has additional adapter and
    # vendor actions, so compose from the already-validated non-preflight
    # actions and derive one new exact prefix only after final ordering.
    hardening_actions = [action for action in hardening.actions if action.operation != "check_executable"]
    adapter = select_adapter(facts)
    artifacts = _parse_artifacts(args.offline_artifact, args.workspace)
    package_plan = adapter.plan_packages(args.capability, offline=True, offline_artifacts=artifacts)
    adapter_package_actions = package_actions(package_plan, artifacts)
    if facts.distribution.id == "nixos":
        # NixOS applies firewall/SSH/radio controls as one native generation.
        # that tested generation must be booted before any package action.
        actions = [*hardening_actions, *adapter_package_actions]
        deferred_hardening = []
    else:
        network_gates = [
            action
            for action in hardening_actions
            if action.phase in {"recovery", "bootstrap-security"}
            or (action.phase == "network" and not action.id.startswith("radio-"))
        ]
        containment = [
            action for action in hardening_actions if action.phase == "services" or action.id.startswith("radio-")
        ]
        deferred_hardening = [
            action for action in hardening_actions if action not in network_gates and action not in containment
        ]
        # the active offline guard and ingress firewall contain package hooks.
        # adapter packages then provide tools such as rfkill before service and
        # radio containment consumes them.
        actions = [*network_gates, *adapter_package_actions, *containment]
    supported, mullvad_note = mullvad_platform_status(
        facts.distribution.id, facts.distribution.version_id, facts.architecture
    )
    if bool(args.mullvad_artifact) != bool(args.mullvad_vendor_receipt):
        raise UmzugError("--mullvad-artifact and --mullvad-vendor-receipt must be provided together")
    if args.mullvad_artifact and args.no_mullvad_app_preparation:
        raise UmzugError(
            "a Mullvad vendor installation requires management-socket preparation before package installation"
        )
    if args.mullvad_artifact and facts.init_system != "systemd":
        raise UmzugError("a Mullvad vendor installation requires systemd management-socket containment")
    vendor_report: dict[str, Any] | None = None
    vendor_intent: dict[str, Any] | None = None
    vendor_action: Action | None = None
    management_intent: str | None = None
    if args.mullvad_artifact:
        if not supported:
            raise UmzugError(f"Mullvad vendor package requested for an unsupported target: {mullvad_note}")
        if args.workspace is None:
            raise UmzugError("--workspace is required for a Mullvad artifact")
        artifact = args.mullvad_artifact.absolute().resolve(strict=True)
        approved_root = (args.workspace / "APPROVED").absolute().resolve(strict=True)
        if not contained(approved_root, artifact) or artifact.is_symlink() or not artifact.is_file():
            raise UmzugError("Mullvad artifact must be an unchanged regular file below APPROVED")
        relative = artifact.relative_to(approved_root)
        if len(relative.parts) < 2:
            raise UmzugError("Mullvad artifact must belong to an approved candidate directory")
        _require_approved_unchanged(args.workspace, relative.parts[0])
        anchors = {
            "artifact": args.mullvad_artifact_sha256,
            "fingerprint": args.mullvad_fingerprint,
            "gpg": args.mullvad_gpg_sha256,
            "gpgv": args.mullvad_gpgv_sha256,
            "bwrap": args.mullvad_bwrap_sha256,
            "package_version": args.mullvad_package_version,
            "package_architecture": args.mullvad_package_architecture,
        }
        if not all(isinstance(value, str) and value for value in anchors.values()):
            raise UmzugError(
                "Mullvad planning requires independent --mullvad-fingerprint, --mullvad-gpg-sha256, "
                "--mullvad-gpgv-sha256, --mullvad-bwrap-sha256 and "
                "--mullvad-artifact-sha256 plus exact package version/architecture anchors"
            )
        receipt_root = (args.workspace / "state" / "vendor").absolute()
        receipt = args.mullvad_vendor_receipt.absolute().resolve(strict=True)
        if not contained(receipt_root, receipt) or receipt.is_symlink() or not receipt.is_file():
            raise UmzugError("Mullvad vendor receipt must be a local re-verifiable record below workspace/state/vendor")
        vendor_report = load_vendor_receipt(
            receipt,
            artifact,
            expected_artifact_sha256=anchors["artifact"],
            expected_fingerprint=anchors["fingerprint"],
            expected_gpg_sha256=anchors["gpg"],
            expected_gpgv_sha256=anchors["gpgv"],
            expected_bwrap_sha256=anchors["bwrap"],
        )
        workspace_root = args.workspace.absolute().resolve(strict=True)
        candidate = artifact.relative_to(approved_root).parts[0]
        normalized_fingerprint = str(anchors["fingerprint"]).replace(" ", "").replace(":", "").upper()
        vendor_intent = {
            "kind": "mullvad-openpgp-v4",
            "workspace": str(workspace_root),
            "candidate": candidate,
            "artifact": str(artifact),
            "receipt": str(receipt),
            "artifact_sha256": str(anchors["artifact"]).lower(),
            "fingerprint": normalized_fingerprint,
            "gpg_sha256": str(anchors["gpg"]).lower(),
            "gpgv_sha256": str(anchors["gpgv"]).lower(),
            "bwrap_sha256": str(anchors["bwrap"]).lower(),
            "receipt_sha256": str(vendor_report["receipt_sha256"]).lower(),
            "package_version": str(anchors["package_version"]),
            "package_architecture": str(anchors["package_architecture"]),
        }
        vendor_action = mullvad_install_action(
            distribution=facts.distribution.id,
            package_adapter=package_plan.adapter,
            artifact=str(artifact),
            artifact_sha256=vendor_intent["artifact_sha256"],
            package_version=vendor_intent["package_version"],
            package_architecture=vendor_intent["package_architecture"],
            management_group=args.mullvad_management_group,
        )
    if not args.no_mullvad_app_preparation and supported and facts.init_system == "systemd":
        group = args.mullvad_management_group
        actions.extend(mullvad_management_actions(group))
        management_intent = group
    # systemd parses a unit's .service.d drop-ins after its main unit file when
    # that unit is loaded. keeping this write ahead of the package action means
    # even a postinst-triggered first load sees the restriction. a daemon-reload
    # before the main unit exists cannot strengthen that guarantee and would
    # needlessly reload unrelated system units.
    if vendor_action is not None:
        actions.append(vendor_action)
        if management_intent is None:
            raise UmzugError("Mullvad vendor installation lost its management-socket containment intent")
    actions.extend(deferred_hardening)
    actions = prepend_executable_preflights(actions)
    preflight_tools = tuple(
        str(action.parameters["name"]) for action in actions if action.operation == "check_executable"
    )
    plan = Plan(
        profile=hardening.profile,
        system_fingerprint=hardening.system_fingerprint,
        actions=actions,
        created_at=hardening.created_at,
        intent={
            **hardening.intent,
            "package_adapter": package_plan.adapter,
            "package_requests": list(package_plan.requested),
            "vendor": vendor_intent,
            "mullvad_management_group": management_intent,
        },
    )
    plan.validate()
    report = {
        "facts": facts.to_dict(),
        "adapter": package_plan.to_dict(),
        "mullvad_app_officially_supported": supported,
        "mullvad_note": mullvad_note,
        "mullvad_vendor_receipt": vendor_report,
        "ethernet_interfaces": ethernet,
        "radio_modules": radios,
        "hardening_profile": profile,
        "executable_preflight": [
            {
                "name": name,
                "path": shutil.which(name, path=EXECUTABLE_SEARCH_PATH),
                "status": "present"
                if shutil.which(name, path=EXECUTABLE_SEARCH_PATH)
                else "missing-blocks-productive-apply-before-mutation",
            }
            for name in preflight_tools
        ],
        "vpn_killswitch": {
            "required_by_profile": bool(profile["vpn_killswitch"]),
            "status": "deferred-to-explicit-vpn-finalize" if profile["vpn_killswitch"] else "not-required-by-profile",
            "official_app_supported": supported,
            "enforcement": (
                "Mullvad Lockdown Mode and auto-connect are enabled before the TTY-only account login, then the effective state is verified."
                if profile["vpn_killswitch"] and supported
                else "No automatic app finalization is claimed for this target. Use a separately reviewed vanilla-WireGuard policy or keep the system offline."
                if profile["vpn_killswitch"]
                else "The compatible profile retains an ingress-default-drop firewall but does not claim an egress VPN kill-switch."
            ),
        },
        "plan_sha256": plan.digest(),
        "warnings": [
            "No package name from the source manifest is executed; only fixed canonical capability mappings are accepted.",
            *(
                [
                    "One or more required executables are missing. Dry-run remains available, but productive apply will stop in the leading preflight before any system mutation."
                ]
                if any(shutil.which(name, path=EXECUTABLE_SEARCH_PATH) is None for name in preflight_tools)
                else []
            ),
            "Secure Boot, disk partitioning, FDE, bootloader changes, and MAC policy conversion require distribution-native recovery planning and are not performed by this generic MVP plan.",
            *(
                [
                    "The strict/maximal VPN egress kill-switch is deliberately not marked complete by the offline plan. It becomes active only in the final TTY-only vpn-finalize step."
                ]
                if profile["vpn_killswitch"] and supported
                else [
                    "This target lacks an officially supported Mullvad App path. The strict/maximal VPN requirement remains unresolved until an explicitly reviewed vanilla-WireGuard setup and nftables egress policy are supplied."
                ]
                if profile["vpn_killswitch"]
                else []
            ),
            *package_plan.warnings,
            *package_plan.manual_actions,
        ],
    }
    return plan, report


def _read_plan_bytes(path: Path, *, private: bool = False) -> bytes:
    """read one immutable regular plan without following a replacement link."""

    try:
        fd = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise UmzugError(f"plan file cannot be opened without following links: {exc}") from exc
    try:
        before = os.fstat(fd)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_PLAN_BYTES
        ):
            raise UmzugError("plan file has unsafe type, link count, or size")
        if private and (before.st_uid != os.geteuid() or mode & 0o077):
            raise UmzugError("saved resume plan is not private and owned by the invoking user")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise UmzugError("plan file was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise UmzugError("plan file grew while reading")
        after = os.fstat(fd)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in stable):
            raise UmzugError("plan file changed while reading")
        return b"".join(chunks)
    except OSError as exc:
        raise UmzugError(f"plan file is unreadable: {exc}") from exc
    finally:
        os.close(fd)


def _load_plan(path: Path, *, private: bool = False) -> Plan:
    try:
        return Plan.from_dict(json.loads(_read_plan_bytes(path, private=private).decode("utf-8", "strict")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"invalid plan file: {exc}") from exc


def _require_plan_runtime_version(plan: Plan) -> None:
    if plan.toolkit_version != __version__:
        raise UmzugError("plan toolkit version does not match this runtime; create, review, and digest-bind a new plan")


def _verify_plan_target(
    plan: Plan,
    *,
    allow_missing_radio_drivers_after_reboot: bool = False,
) -> None:
    facts = _facts()
    comparison = compare_plan_target(
        plan,
        facts,
        allow_missing_radio_drivers_after_reboot=allow_missing_radio_drivers_after_reboot,
    )
    blockers = comparison["blockers"]
    if blockers:
        raise UmzugError(str(blockers[0]))


def _require_offline_boundary() -> dict[str, Any]:
    facts = _facts(allow_commands=False)
    evidence = observe_offline_boundary(facts)
    if evidence.get("status") != "pass":
        raise UmzugError(
            "productive offline boundary is not proven immediately before mutation: "
            + str(evidence.get("summary") or "incomplete carrier/default-route evidence")
        )
    return evidence


def _verify_plan_vendor_intent(plan: Plan) -> None:
    """re-prove APPROVED and the detached vendor signature before mutation."""

    if plan.profile == "test":
        return
    vendor = plan.intent.get("vendor")
    if vendor is None:
        return
    if not isinstance(vendor, dict):
        raise UmzugError("plan vendor intent is invalid")
    workspace = Path(str(vendor["workspace"]))
    artifact = Path(str(vendor["artifact"]))
    receipt = Path(str(vendor["receipt"]))
    candidate = str(vendor["candidate"])
    try:
        workspace_resolved = workspace.resolve(strict=True)
        artifact_resolved = artifact.resolve(strict=True)
        receipt_resolved = receipt.resolve(strict=True)
    except OSError as exc:
        raise UmzugError("bound Mullvad workspace, artifact, or receipt is unavailable") from exc
    if (
        str(workspace_resolved) != str(workspace)
        or str(artifact_resolved) != str(artifact)
        or str(receipt_resolved) != str(receipt)
        or artifact.is_symlink()
        or receipt.is_symlink()
        or not artifact.is_file()
        or not receipt.is_file()
    ):
        raise UmzugError("bound Mullvad paths changed or are not regular non-symlink files")
    approved_root, _approval = _require_approved_unchanged(workspace, candidate)
    if not contained(approved_root, artifact) or artifact.relative_to(approved_root).parts[0:] == ():
        raise UmzugError("bound Mullvad artifact left its unchanged APPROVED candidate")
    receipt_root = (workspace / "state" / "vendor").resolve(strict=True)
    if not contained(receipt_root, receipt):
        raise UmzugError("bound Mullvad receipt left workspace/state/vendor")
    result = load_vendor_receipt(
        receipt,
        artifact,
        expected_artifact_sha256=str(vendor["artifact_sha256"]),
        expected_fingerprint=str(vendor["fingerprint"]),
        expected_gpg_sha256=str(vendor["gpg_sha256"]),
        expected_gpgv_sha256=str(vendor["gpgv_sha256"]),
        expected_bwrap_sha256=str(vendor["bwrap_sha256"]),
    )
    if not hmac.compare_digest(str(result.get("receipt_sha256", "")), str(vendor["receipt_sha256"])):
        raise UmzugError("Mullvad vendor receipt differs from the reviewed plan intent")


def _confirm_plan_digest(plan: Plan, supplied: str | None, *, dry_run: bool) -> str:
    digest = plan.digest()
    if supplied is not None:
        normalized = supplied.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized) or not hmac.compare_digest(normalized, digest):
            raise UmzugError("reviewed plan SHA-256 does not match the plan file")
        return digest
    if dry_run:
        print(f"Plan SHA-256 (für den produktiven Apply getrennt notieren): {digest}")
        return digest
    raise UmzugError("every productive apply requires --expected-plan-sha256 recorded separately from plan creation")


def _save_plan_for_resume(
    plan: Plan,
    state_dir: Path,
    *,
    state_storage: dict[str, Any],
) -> Path:
    store = StateStore(state_dir)
    state = store.load()
    digest = plan.digest()
    previous_digest = state.get("plan_digest")
    if previous_digest is not None:
        if not isinstance(previous_digest, str) or not hmac.compare_digest(previous_digest, digest):
            raise UmzugError("resume state is immutably bound to a different plan")
        require_matching_state_storage(state.get("state_storage"), state_storage)
    elif store.path.exists():
        raise UmzugError("existing resume state has no immutable plan digest")
    else:
        # the digest-bearing state is deliberately durable before plan.json.
        # a crash between these writes cannot open a plan-replacement window.
        state["plan_digest"] = digest
        state["profile"] = plan.profile
        state["state_storage"] = state_storage
        store.save(state)

    target = state_dir / "plan.json"
    data = canonical_json(plan.to_dict())
    if os.path.lexists(target):
        if _read_plan_bytes(target, private=True) != data:
            raise UmzugError("state directory already contains a different resume plan")
    else:
        atomic_write(target, data, 0o600)
    return target


def _require_saved_state_storage_binding(state_dir: Path) -> dict[str, Any]:
    observed = observe_persistent_state_storage(state_dir)
    checkpoint = StateStore(state_dir).load()
    require_matching_state_storage(checkpoint.get("state_storage"), observed)
    return observed


def _security_report(args: argparse.Namespace) -> dict[str, Any]:
    facts = _facts()
    state: dict[str, Any] | None = None
    state_path = args.state_dir / "state.json"
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            state = {"error": str(exc)}
    workspace: dict[str, Any] | None = None
    if args.workspace:
        ingest = args.workspace / "state" / "ingest.json"
        approvals = args.workspace / "state" / "approvals"
        workspace = {
            "path": str(args.workspace),
            "ingest": json.loads(ingest.read_text(encoding="utf-8")) if ingest.exists() else None,
            "approvals": sorted(path.name for path in approvals.glob("*.json")) if approvals.exists() else [],
            "restored_receipts": sorted(path.name for path in (args.workspace / "RESTORED").glob("*.json")),
        }
    evidence = collect_network_evidence(include_online_check=False)
    listeners = str(evidence.get("listeners", {}).get("stdout", ""))
    ssh_listener = any(
        "sshd" in line.lower() or re.search(r"(?:^|[\]\s:])22(?:\s|$)", line) is not None
        for line in listeners.splitlines()
    )
    active_ssh_units = [
        name
        for name in ("ssh_service", "sshd_service", "ssh_socket", "sshd_socket")
        if evidence.get(name, {}).get("exit") == 0
    ]
    nft = str(evidence.get("nft_ruleset", {}).get("stdout", ""))
    return {
        "format": 1,
        "facts": facts.to_dict(),
        "execution_state": state,
        "migration_workspace": workspace,
        "network_evidence": evidence,
        "assertions": {
            "no_listening_ssh_observed": not ssh_listener,
            "no_active_ssh_units_observed": not active_ssh_units,
            "umzug_host_firewall_observed": "table inet umzug_host" in nft,
            "root_storage_encryption_detected": facts.storage.root_encrypted,
        },
        "limitations": [
            "This report is point-in-time evidence, not a malware-free or future-security guarantee.",
            "Secure Boot/FDE/firmware state cannot be made reliable across all distributions without platform-specific installation and recovery steps.",
            "Root compromise, malicious firmware, and compromised analysis binaries remain outside a same-host guarantee.",
        ],
    }


def _wizard(args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise UmzugError("wizard requires a TTY")
    facts = _facts()
    _human_facts(facts)
    print("\nKeine Änderung erfolgt vor einem gespeicherten, geprüften Plan.")
    raw = input("Hardening-Stufe [strict] (compatible/strict/maximal): ").strip() or "strict"
    if raw not in {"compatible", "strict", "maximal"}:
        raise UmzugError("invalid profile")
    ethernet = [item.name for item in facts.network_devices if item.kind == "ethernet" and not item.virtual]
    if not ethernet:
        raise UmzugError("no physical Ethernet interface detected")
    print("Erkannte Ethernet-Interfaces: " + ", ".join(ethernet))
    if input("Diese Interfaces in den Plan übernehmen? [y/N] ").strip().lower() not in {"y", "yes", "j", "ja"}:
        raise UmzugError("wizard stopped before plan creation")
    namespace = argparse.Namespace(
        profile=raw,
        profile_file=None,
        output=args.output,
        ethernet=ethernet,
        radio_module=[],
        capability=["firewall", "wireguard", "audit", "integrity-checker", "ssh-client", "radio-control"],
        offline_artifact=[],
        workspace=None,
        mullvad_management_group="mullvad-management",
        no_mullvad_app_preparation=False,
        mullvad_artifact=None,
        mullvad_vendor_receipt=None,
        mullvad_artifact_sha256=None,
        mullvad_fingerprint=None,
        mullvad_gpg_sha256=None,
        mullvad_gpgv_sha256=None,
        mullvad_bwrap_sha256=None,
    )
    plan, report = _build_plan(namespace)
    report_output = args.output.with_suffix(args.output.suffix + ".report.json")
    if os.path.lexists(args.output) or os.path.lexists(report_output):
        raise UmzugError("wizard refuses to overwrite an existing plan or report")
    atomic_write(args.output, canonical_json(plan.to_dict()), 0o600)
    atomic_write(report_output, canonical_json(report), 0o600)
    print(f"Plan gespeichert: {args.output} ({len(plan.actions)} Aktionen)")
    print(f"Plan SHA-256: {plan.digest()}")
    print(f"Nur prüfen: setup apply {args.output} --dry-run")
    print(
        f"Anwenden: setup apply {args.output} --expected-plan-sha256 {plan.digest()} "
        "(jede riskante/destruktive Aktion wird zusätzlich bestätigt)"
    )
    return 0


def dispatch(args: argparse.Namespace, audit: AuditLog) -> int:
    if args.command in {None, "wizard"}:
        return _wizard(args if args.command else argparse.Namespace(output=Path("umzug-plan.json")))
    if args.command == "detect":
        facts = detect_system(root=args.root, proc=args.proc, sys=args.sys, allow_commands=not args.no_commands)
        if args.json:
            print(json.dumps(facts.to_dict(), indent=2, sort_keys=True))
        else:
            _human_facts(facts)
        return 0
    if args.command == "mount-source":
        result = mount_read_only(args.device, args.mountpoint)
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "ingest":
        state = _ingest(args, audit)
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0 if not state["extraction_errors"] else 3
    if args.command == "scan":
        pipeline = _pipeline(args.workspace, args.scanner_config, relaxed=args.relaxed_test_mode)
        stage = Stage(args.stage)
        report = pipeline.scanner.scan(pipeline.stage_path(stage, args.candidate), stage)
        _print_scan(report)
        if args.report:
            if os.path.lexists(args.report):
                raise UmzugError("refusing to overwrite an existing scan report")
            report.write_json(args.report)
        return 3 if report.blockers else 0
    if args.command == "promote":
        _require_clean_ingest(args.workspace)
        pipeline = _pipeline(args.workspace, args.scanner_config)
        source = pipeline.stage_path(Stage.QUARANTINE, args.candidate)
        report = pipeline.scanner.scan(source, Stage.QUARANTINE)
        if report.manifest_sha256 != args.expected_manifest:
            raise UmzugError("QUARANTINE manifest differs from the explicitly reviewed hash")
        result = pipeline.promote_to_sanitized(args.candidate, report, accepted_findings=args.accept_finding)
        _print_scan(result)
        return 3 if result.blockers else 0
    if args.command == "approve":
        _require_clean_ingest(args.workspace)
        if args.confirm_approval != args.candidate:
            raise UmzugError("--confirm-approval must exactly equal the candidate ID")
        pipeline = _pipeline(args.workspace, args.scanner_config)
        if not pipeline.scanner.policy.strict_external:
            raise UmzugError("approval is forbidden without strict external evidence")
        source = pipeline.stage_path(Stage.SANITIZED, args.candidate)
        report = pipeline.scanner.scan(source, Stage.SANITIZED)
        if report.manifest_sha256 != args.expected_manifest:
            raise UmzugError("SANITIZED manifest differs from the explicitly reviewed hash")
        decision = ApprovalDecision(
            approved=True,
            actor=args.actor,
            reason=args.reason,
            expected_manifest_sha256=args.expected_manifest,
            accepted_findings=tuple(args.accept_finding),
        )
        record = pipeline.approve(args.candidate, report, decision)
        audit.event(
            "candidate.approved", candidate=args.candidate, manifest=record.approved_manifest_sha256, actor=args.actor
        )
        print(json.dumps(record.to_dict(), indent=2, sort_keys=True))
        return 0
    if args.command == "restore":
        if args.confirm_restore != args.candidate:
            raise UmzugError("--confirm-restore must exactly equal the candidate ID")
        if os.geteuid() != 0:
            raise UmzugError("restore requires root for safe name-based UID/GID reconciliation")
        destination = require_inert_restore_destination(
            candidate=args.candidate,
            destination=args.destination,
            staging_root=DEFAULT_STATE / "restored-staging",
        )
        prepare_private_restore_staging(destination)
        if os.path.lexists(destination):
            raise UmzugError(
                "destination exists; restore never overwrites. Choose a new path and compare/merge manually."
            )
        metadata_receipt = args.workspace / "RESTORED" / f"{args.candidate}.metadata.json"
        content_receipt = (args.workspace / "RESTORED" / args.candidate).with_suffix(".json")
        if (
            metadata_receipt.exists()
            or metadata_receipt.is_symlink()
            or content_receipt.exists()
            or content_receipt.is_symlink()
        ):
            raise UmzugError("restore receipt already exists; refusing to overwrite prior restore evidence")
        with private_restore_workspace_snapshot(
            workspace=args.workspace,
            candidate=args.candidate,
            max_payload_bytes=args.max_payload_bytes,
        ) as restore_workspace:
            _require_clean_ingest(restore_workspace)
            pipeline = _pipeline(restore_workspace, args.scanner_config)
            approval = _load_approval(restore_workspace, args.candidate)
            trust = _reverify_restore_trust(
                workspace=restore_workspace,
                candidate=args.candidate,
                approval=approval,
                expected_approval_sha256=args.expected_approval_sha256,
                trusted_key=args.trusted_key,
                expected_fingerprint=args.fingerprint,
                max_payload_bytes=args.max_payload_bytes,
            )
            restored = pipeline.restore(
                args.candidate,
                destination,
                approval,
                confirmed=True,
            )
            metadata = apply_safe_restore_metadata(
                workspace=restore_workspace,
                candidate=args.candidate,
                destination=restored,
                approval_manifest_sha256=approval.approved_manifest_sha256,
                approval_sha256=approval.approval_sha256,
                verified_manifest=trust.manifest,
                verified_manifest_sha256=trust.manifest_sha256,
            )
            _, metadata_receipt = publish_restore_receipts(
                snapshot_workspace=restore_workspace,
                workspace=args.workspace,
                candidate=args.candidate,
            )
            audit.event(
                "candidate.restored",
                candidate=args.candidate,
                destination=str(restored),
                manifest=approval.approved_manifest_sha256,
                metadata_receipt=metadata["receipt_sha256"],
                signing_key_fingerprint=trust.signing_key_fingerprint,
                signed_selection=trust.signed_selection["signed_selection_sha256"],
                source_boundary="root-private-fd-anchored-snapshot",
            )
        print(f"Restored without overwrite: {restored}")
        print(f"Safe metadata receipt: {metadata_receipt}")
        print(
            "Signed rw/mtime metadata and exact-name UID/GID mappings were applied; regular executable bits, SUID/SGID, capabilities, ACLs and xattrs remain stripped."
        )
        return 0
    if args.command == "project-report":
        project, _ = _require_approved_unchanged(args.workspace, args.candidate)
        result = inspect_project(project).to_dict()
        data = canonical_json(result)
        if args.output:
            if os.path.lexists(args.output):
                raise UmzugError("refusing to overwrite an existing project report")
            atomic_write(args.output, data, 0o600)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "verify-vendor":
        artifact = _approved_relative(args.workspace, args.candidate, args.artifact)
        signature = _approved_relative(args.workspace, args.candidate, args.signature)
        receipt_root = (args.workspace / "state" / "vendor").absolute()
        receipt = (args.receipt or (receipt_root / f"{args.candidate}.json")).absolute()
        if not contained(receipt_root, receipt):
            raise UmzugError("vendor receipts are trusted local state and must stay below workspace/state/vendor")
        result = verify_detached_openpgp(
            artifact=artifact,
            signature=signature,
            signing_key=args.signing_key.absolute(),
            expected_artifact_sha256=args.artifact_sha256,
            expected_fingerprint=args.fingerprint,
            expected_gpg_sha256=args.gpg_sha256,
            expected_gpgv_sha256=args.gpgv_sha256,
            expected_bwrap_sha256=args.bwrap_sha256,
            receipt_path=receipt,
        )
        audit.event(
            "vendor.signature_verified",
            candidate=args.candidate,
            artifact_sha256=result["artifact_sha256"],
            signing_key_fingerprint=result["signing_key_fingerprint"],
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "plan":
        plan, report = _build_plan(args)
        report_path = args.output.with_suffix(args.output.suffix + ".report.json")
        if os.path.lexists(args.output) or os.path.lexists(report_path):
            raise UmzugError("refusing to overwrite an existing plan or report")
        atomic_write(args.output, canonical_json(plan.to_dict()), 0o600)
        atomic_write(report_path, canonical_json(report), 0o600)
        print(f"Plan: {args.output}; Aktionen: {len(plan.actions)}; SHA-256: {plan.digest()}")
        print(f"Erkennungs-/Adapterbericht: {report_path}")
        for action in plan.actions:
            marker = "DESTRUKTIV" if action.destructive else action.risk.upper()
            print(f"  [{marker}] {action.id}: {action.summary}")
        return 0
    if args.command == "hardware-preflight":
        plan = _load_plan(args.plan)
        digest = _confirm_plan_digest(
            plan,
            args.expected_plan_sha256,
            dry_run=False,
        )
        facts = _facts(allow_commands=False)
        report = build_hardware_preflight_report(
            plan,
            facts,
            plan_digest=digest,
            state_dir=args.state_dir.expanduser().absolute(),
            recovery_medium=(args.recovery_medium.expanduser().absolute() if args.recovery_medium else None),
            attestations=args.attest,
        )
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(human_hardware_preflight(report))
        return 0 if report["status"] == "ready" else 3
    if args.command == "apply":
        plan = _load_plan(args.plan)
        _require_plan_runtime_version(plan)
        _confirm_plan_digest(plan, args.expected_plan_sha256, dry_run=args.dry_run)
        if not args.dry_run:
            require_proven_local_console("productive apply")
        _verify_plan_target(plan)
        _verify_plan_vendor_intent(plan)
        if not args.dry_run:
            _require_offline_boundary()
            state_storage = observe_persistent_state_storage(args.state_dir)
            _save_plan_for_resume(
                plan,
                args.state_dir,
                state_storage=state_storage,
            )
        approvals = set(args.approve)
        if args.dry_run:
            approvals.update(action.id for action in plan.actions)
        executor = Executor(
            state_root=args.state_dir,
            system_root=args.system_root,
            dry_run=args.dry_run,
            audit_log=audit,
            assume_yes=args.yes,
            approvals=approvals,
        )
        state = executor.apply(plan)
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0
    if args.command == "resume":
        require_proven_local_console("resume")
        _require_saved_state_storage_binding(args.state_dir)
        saved = args.state_dir / "plan.json"
        if not os.path.lexists(saved):
            raise UmzugError("no saved resume plan")
        plan = _load_plan(saved, private=True)
        _require_plan_runtime_version(plan)
        _verify_plan_target(plan, allow_missing_radio_drivers_after_reboot=True)
        _verify_plan_vendor_intent(plan)
        _require_offline_boundary()
        executor = Executor(
            state_root=args.state_dir,
            audit_log=audit,
            assume_yes=args.yes,
            approvals=set(args.approve),
        )
        print(json.dumps(executor.apply(plan), indent=2, sort_keys=True))
        return 0
    if args.command == "rollback":
        live_system = args.system_root.resolve() == Path("/")
        recovery_proof: dict[str, Any] | None = None
        if not args.dry_run:
            require_proven_local_console("rollback")
            _require_saved_state_storage_binding(args.state_dir)
            if live_system:
                # a rollback may remove the on-disk recovery script and unit
                # files. first stop persistence and atomically remove the
                # active owned tables; abort before touching backups unless
                # that postcondition is positively proven.
                recovery_proof = recover_network(audit=audit, dry_run=False)
        else:
            recover_network(audit=audit, dry_run=True)
        rollback(
            args.state_dir,
            system_root=args.system_root,
            dry_run=args.dry_run,
            network_recovery_verified=(
                recovery_proof is not None
                and recovery_proof.get("status") == "verified"
                and recovery_proof.get("authorization_to_rollback") is True
            ),
        )
        if not args.dry_run and live_system:
            # rollback can restore an older owned unit/hook. disable persistence
            # once more and prove that no owned active table survived.
            recover_network(audit=audit, dry_run=False)
        return 0
    if args.command == "recover-network":
        if not args.dry_run:
            require_proven_local_console("recover-network")
        print(json.dumps(recover_network(audit=audit, dry_run=args.dry_run), indent=2, sort_keys=True))
        return 0
    if args.command == "report":
        result = _security_report(args)
        if os.path.lexists(args.output):
            raise UmzugError("refusing to overwrite an existing security report")
        atomic_write(args.output, canonical_json(result), 0o600)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if args.command == "vpn-finalize":
        require_proven_local_console("vpn-finalize")
        context = require_completed_plan_context(
            args.state_dir,
            args.expected_plan_sha256,
        )
        _require_plan_runtime_version(context["plan"])
        _require_saved_state_storage_binding(args.state_dir)
        _verify_plan_target(context["plan"], allow_missing_radio_drivers_after_reboot=True)
        _verify_plan_vendor_intent(context["plan"])
        facts = _facts()
        supported, note = mullvad_platform_status(
            facts.distribution.id, facts.distribution.version_id, facts.architecture
        )
        if not supported:
            raise UmzugError(f"official Mullvad app support could not be established: {note}")
        result = finalize_mullvad_app(
            bound_executables=context["bound_executables"],
            plan_sha256=context["plan_sha256"],
            ethernet_interfaces=context["ethernet_interfaces"],
            ipv6_disabled=context["ipv6_disabled"],
            radios_blocked=context["radios_blocked"],
            package_manager=context["package_manager"],
            vendor_package_version=context["vendor_package_version"],
            vendor_package_architecture=context["vendor_package_architecture"],
            vendor_artifact_sha256=context["vendor_artifact_sha256"],
            encrypted_storage=_mullvad_state_covered_by_encrypted_root(facts.storage),
            anti_censorship=args.anti_censorship,
            audit=audit,
            online_verification=True,
            management_group=args.management_group,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    raise UmzugError(f"unknown command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    try:
        _require_root_owned_runtime()
    except UmzugError as exc:
        print(f"setup: error: {terminal_safe(exc)}", file=sys.stderr)
        return 2
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "hardware-preflight" and args.log is not None:
        message = "hardware-preflight is read-only and therefore rejects --log"
        if args.json:
            print(json.dumps({"status": "error", "error": message}, sort_keys=True))
        else:
            print(f"setup: error: {message}", file=sys.stderr)
        return 2
    audit = AuditLog(None if args.command == "hardware-preflight" else args.log)
    try:
        return dispatch(args, audit)
    except (UmzugError, ScannerError, OSError, ValueError, tarfile.TarError) as exc:
        audit.event("setup.error", command=args.command, error=str(exc))
        print(f"setup: error: {terminal_safe(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
