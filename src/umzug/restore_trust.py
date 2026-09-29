from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterator

from .manifest import (
    BUNDLE_MEMBERS,
    load_and_verify_manifest,
    safe_extract_bundle,
    verify_source_tar_manifest,
)
from .restore_metadata import verify_candidate_against_signed_manifest
from .scanner import (
    ApprovalRecord,
    SCHEMA_VERSION,
    ScanPolicy,
    Stage,
    ZeroTrustScanner,
    _open_destination_parent,
    _require_root_private_restore_source,
    _safe_copy_atomic,
)
from .util import UmzugError, atomic_write, canonical_json, contained, sha256_file


@dataclasses.dataclass(frozen=True)
class RestoreTrustEvidence:
    manifest: dict[str, Any]
    manifest_sha256: str
    signing_key_fingerprint: str
    source_payload_sha256: str
    bundle_sha256: str
    approval_sha256: str
    approved_manifest_sha256: str
    signed_selection: dict[str, Any]


def _snapshot_regular_file(source: Path, destination: Path, *, max_bytes: int) -> str:
    """make one stable, nofollow snapshot and return its SHA-256."""

    if max_bytes <= 0 or os.path.lexists(destination):
        raise UmzugError("invalid or pre-existing trust-verification snapshot")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        raise UmzugError(f"trust-verification input cannot be opened safely: {source}") from exc
    output_fd = -1
    digest = hashlib.sha256()
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise UmzugError(f"trust-verification input is not regular or exceeds its limit: {source}")
        output_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        remaining = max_bytes
        while chunk := os.read(source_fd, min(1024 * 1024, remaining + 1)):
            remaining -= len(chunk)
            if remaining < 0:
                raise UmzugError(f"trust-verification input grew beyond its limit: {source}")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output_fd, view)
                view = view[written:]
        os.fsync(output_fd)
        after = os.fstat(source_fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise UmzugError(f"trust-verification input changed while being snapshotted: {source}")
        return digest.hexdigest()
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
        raise
    finally:
        os.close(source_fd)
        if output_fd >= 0:
            os.close(output_fd)


def _load_clean_ingest(workspace: Path) -> dict[str, Any]:
    path = workspace / "state" / "ingest.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"ingest state is missing or invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise UmzugError("ingest state must be a JSON object")
    blockers = {
        key: value.get(key, [])
        for key in ("extraction_errors", "manifest_warnings", "xattr_failures")
        if value.get(key)
    }
    if blockers:
        raise UmzugError(
            f"package-level ingest blockers prevent restore: {json.dumps(blockers, sort_keys=True)[:2000]}"
        )
    return value


def _require_regular_snapshot(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise UmzugError(f"{label} snapshot is missing: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise UmzugError(f"{label} snapshot must be a regular file owned by the restore process")


@contextlib.contextmanager
def private_restore_workspace_snapshot(
    *,
    workspace: Path,
    candidate: str,
    max_payload_bytes: int,
) -> Iterator[Path]:
    """copy only restore inputs into a new process-private workspace.

    every source component is opened relative to held directory descriptors.
    the source workspace may therefore remain owned and writable by the
    unprivileged ingest operator; no productive root read is performed from it
    after this context has yielded.
    """

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", candidate) or candidate in {
        ".",
        "..",
    }:
        raise UmzugError("candidate ID must be a safe ASCII identifier")
    if max_payload_bytes <= 0 or max_payload_bytes > 2**43:
        raise UmzugError("restore payload limit must be between 1 byte and 8 TiB")
    workspace = workspace.expanduser().absolute()

    with tempfile.TemporaryDirectory(prefix="umzug-root-restore-") as temporary_name:
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o700)
        snapshot = temporary / "workspace"
        snapshot.mkdir(mode=0o700)
        private_directories = (
            snapshot / "state" / "approvals",
            snapshot / "state" / "promotions",
            snapshot / "state" / "reports",
            snapshot / "state" / "bundle" / "verified-container" / "umzug",
            snapshot / Stage.APPROVED.value,
            snapshot / Stage.RESTORED.value,
        )
        for directory in private_directories:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in (
            snapshot,
            snapshot / "state",
            snapshot / "state" / "approvals",
            snapshot / "state" / "promotions",
            snapshot / "state" / "reports",
            snapshot / "state" / "bundle",
            snapshot / "state" / "bundle" / "verified-container",
            snapshot / "state" / "bundle" / "verified-container" / "umzug",
            snapshot / Stage.APPROVED.value,
            snapshot / Stage.RESTORED.value,
        ):
            os.chmod(directory, 0o700)
        atomic_write(
            snapshot / "state" / "restore-source.json",
            canonical_json(
                {
                    "format": 1,
                    "candidate": candidate,
                    "source_workspace": str(workspace),
                }
            ),
            0o600,
        )

        required_files = (
            (Path("state/ingest.json"), 64 * 1024 * 1024, "ingest state"),
            (
                Path("state") / f"{candidate}.provenance.json",
                64 * 1024 * 1024,
                "SOURCE-to-QUARANTINE provenance receipt",
            ),
            (
                Path("state/promotions") / f"{candidate}.json",
                64 * 1024 * 1024,
                "QUARANTINE-to-SANITIZED promotion receipt",
            ),
            (
                Path("state/approvals") / f"{candidate}.json",
                64 * 1024 * 1024,
                "approval record",
            ),
            (
                Path("state/reports") / f"{candidate}.source.json",
                64 * 1024 * 1024,
                "SOURCE scan report",
            ),
            (
                Path("state/reports") / f"{candidate}.quarantine.ingest.json",
                64 * 1024 * 1024,
                "ingest QUARANTINE scan report",
            ),
            (
                Path("state/reports") / f"{candidate}.quarantine.json",
                64 * 1024 * 1024,
                "QUARANTINE scan report",
            ),
            (
                Path("state/reports") / f"{candidate}.sanitized.json",
                64 * 1024 * 1024,
                "SANITIZED scan report",
            ),
            (
                Path("state/bundle/bundle.tar"),
                max_payload_bytes + 2**31,
                "signed transport bundle",
            ),
            (
                Path("state/bundle/verified-container/umzug/manifest.json"),
                64 * 1024 * 1024,
                "verified workspace manifest",
            ),
        )
        for relative, limit, label in required_files:
            destination = snapshot / relative
            _safe_copy_atomic(
                workspace / relative,
                destination,
                inert=True,
                max_bytes=limit,
            )
            _require_regular_snapshot(destination, label)

        _safe_copy_atomic(
            workspace / Stage.APPROVED.value / candidate,
            snapshot / Stage.APPROVED.value / candidate,
            inert=False,
            preserve_owner=True,
            max_bytes=max_payload_bytes,
        )
        _require_root_private_restore_source(snapshot)
        yield snapshot


def publish_restore_receipts(
    *,
    snapshot_workspace: Path,
    workspace: Path,
    candidate: str,
) -> tuple[Path, Path]:
    """publish fixed receipt bytes exclusively; never read APPROVED again."""

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", candidate) or candidate in {
        ".",
        "..",
    }:
        raise UmzugError("candidate ID must be a safe ASCII identifier")
    source_content = (snapshot_workspace / Stage.RESTORED.value / candidate).with_suffix(".json")
    source_metadata = snapshot_workspace / Stage.RESTORED.value / f"{candidate}.metadata.json"
    destination_content = (workspace.expanduser().absolute() / Stage.RESTORED.value / candidate).with_suffix(".json")
    destination_metadata = workspace.expanduser().absolute() / Stage.RESTORED.value / f"{candidate}.metadata.json"
    _safe_copy_atomic(
        source_content,
        destination_content,
        inert=True,
        max_bytes=64 * 1024 * 1024,
    )
    _safe_copy_atomic(
        source_metadata,
        destination_metadata,
        inert=True,
        max_bytes=64 * 1024 * 1024,
    )
    return destination_content, destination_metadata


def require_inert_restore_destination(
    *,
    candidate: str,
    destination: Path,
    staging_root: Path,
) -> Path:
    """allow restore only at the candidate's inactive staging location."""

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", candidate) or candidate in {
        ".",
        "..",
    }:
        raise UmzugError("candidate ID must be a safe ASCII identifier")
    destination = destination.expanduser().absolute()
    staging_root = staging_root.expanduser().absolute()
    if ".." in destination.parts or ".." in staging_root.parts or destination != staging_root / candidate:
        raise UmzugError(
            "root restore destination must be the dedicated inert staging path "
            f"{staging_root / candidate}; active paths require a typed planner "
            "action with diff, backup, and explicit confirmation"
        )
    return destination


def prepare_private_restore_staging(destination: Path) -> None:
    """create/open the staging parent without symlinks and require exclusivity."""

    parent_fd = _open_destination_parent(destination.parent)
    try:
        info = os.fstat(parent_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise UmzugError(
                "restore staging directory must be owned by the restore process and inaccessible to group/other users"
            )
    finally:
        os.close(parent_fd)


def _canonical_object_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_derivation_receipt(
    path: Path,
    *,
    label: str,
    receipt_type: str,
    hash_field: str,
    expected_fields: set[str],
) -> dict[str, Any]:
    """load an exact-schema, canonical self-hashed derivation receipt."""

    _require_regular_snapshot(path, label)
    try:
        raw = path.read_bytes()
        if len(raw) > 64 * 1024 * 1024:
            raise UmzugError(f"{label} exceeds its size limit")
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"{label} is missing or invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise UmzugError(f"{label} does not match the required exact schema")
    supplied = value.get(hash_field)
    if not isinstance(supplied, str) or not re.fullmatch(r"[0-9a-f]{64}", supplied):
        raise UmzugError(f"{label} has no valid {hash_field}")
    payload = dict(value)
    del payload[hash_field]
    if not hmac.compare_digest(supplied, _canonical_object_sha256(payload)):
        raise UmzugError(f"{label} canonical self-hash mismatch")
    if value.get("schema_version") != SCHEMA_VERSION or value.get("receipt_type") != receipt_type:
        raise UmzugError(f"{label} has an unsupported schema or receipt type")
    return value


def _require_sha256_fields(value: dict[str, Any], fields: tuple[str, ...], label: str) -> None:
    if any(
        not isinstance(value.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]) for field in fields
    ):
        raise UmzugError(f"{label} contains an invalid SHA-256 binding")


def _load_scan_report(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    _require_regular_snapshot(path, label)
    try:
        raw = path.read_bytes()
        if len(raw) > 64 * 1024 * 1024:
            raise UmzugError(f"{label} exceeds its size limit")
        report = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"{label} is missing or invalid: {exc}") from exc
    if not isinstance(report, dict):
        raise UmzugError(f"{label} must be a JSON object")
    return report, _canonical_object_sha256(report)


def _approval_report_workspace(snapshot_workspace: Path, candidate: str) -> Path:
    """return the original report root recorded by the trusted snapshotter."""

    provenance_path = snapshot_workspace / "state" / "restore-source.json"
    try:
        info = provenance_path.lstat()
    except FileNotFoundError:
        return snapshot_workspace
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise UmzugError("restore snapshot provenance is not process-private")
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"restore snapshot provenance is invalid: {exc}") from exc
    if (
        not isinstance(provenance, dict)
        or provenance.get("format") != 1
        or provenance.get("candidate") != candidate
        or not isinstance(provenance.get("source_workspace"), str)
    ):
        raise UmzugError("restore snapshot provenance does not bind this candidate")
    source_workspace = Path(provenance["source_workspace"]).absolute()
    if not source_workspace.is_absolute() or ".." in source_workspace.parts:
        raise UmzugError("restore snapshot provenance has an unsafe source path")
    return source_workspace


def reverify_restore_trust(
    *,
    workspace: Path,
    candidate: str,
    approval: ApprovalRecord,
    expected_approval_sha256: str,
    trusted_key: Path | None,
    expected_fingerprint: str | None,
    max_payload_bytes: int,
) -> RestoreTrustEvidence:
    """rebuild the source-to-approval trust chain from independent anchors."""

    workspace = workspace.expanduser().absolute()
    _require_root_private_restore_source(workspace)
    if trusted_key is None and expected_fingerprint is None:
        raise UmzugError(
            "productive restore requires --trusted-key and/or --fingerprint as an out-of-band trust anchor"
        )
    normalized_approval = expected_approval_sha256.strip().lower()
    if (
        not isinstance(approval.approval_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", normalized_approval)
        or not hmac.compare_digest(normalized_approval, approval.approval_sha256)
    ):
        raise UmzugError("out-of-band approval SHA-256 does not match the approval record")
    try:
        approval_payload = approval.to_dict()
    except (AttributeError, TypeError, ValueError) as exc:
        raise UmzugError(f"approval record has invalid field types: {exc}") from exc
    supplied_approval_hash = approval_payload.pop("approval_sha256", None)
    if (
        not isinstance(supplied_approval_hash, str)
        or not re.fullmatch(r"[0-9a-f]{64}", supplied_approval_hash)
        or not hmac.compare_digest(
            supplied_approval_hash,
            _canonical_object_sha256(approval_payload),
        )
    ):
        raise UmzugError("approval record canonical self-hash mismatch")
    approval_hash_fields = (
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
        approval.schema_version != SCHEMA_VERSION
        or approval.candidate != candidate
        or approval.source_stage is not Stage.SANITIZED
        or any(
            not isinstance(value, str) or not value.strip()
            for value in (
                approval.actor,
                approval.reason,
                approval.approved_at,
                approval.report_scan_id,
                approval.quarantine_report_scan_id,
            )
        )
        or any(
            not isinstance(getattr(approval, field), str) or not re.fullmatch(r"[0-9a-f]{64}", getattr(approval, field))
            for field in approval_hash_fields
        )
        or any(
            not isinstance(rows, tuple)
            or any(not isinstance(row, str) or not row for row in rows)
            or list(rows) != sorted(set(rows))
            for rows in (approval.accepted_findings, approval.promotion_accepted_findings)
        )
    ):
        raise UmzugError("approval record has invalid schema, types, or bindings")
    normalized_fingerprint: str | None = None
    if expected_fingerprint is not None:
        normalized_fingerprint = expected_fingerprint.strip().lower().replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{64}", normalized_fingerprint):
            raise UmzugError("restore signing-key fingerprint must be exactly 64 hexadecimal characters")
    if max_payload_bytes <= 0 or max_payload_bytes > 2**43:
        raise UmzugError("restore payload limit must be between 1 byte and 8 TiB")

    trusted_key_path: Path | None = None
    if trusted_key is not None:
        trusted_key_path = trusted_key.expanduser().absolute()
        workspace_resolved = workspace.resolve(strict=True)
        if (
            trusted_key_path == workspace
            or workspace in trusted_key_path.parents
            or contained(workspace_resolved, trusted_key_path)
        ):
            raise UmzugError("trusted restore key must be stored independently outside the migration workspace")

    bundle_source = workspace / "state" / "bundle" / "bundle.tar"
    workspace_manifest = workspace / "state" / "bundle" / "verified-container" / "umzug" / "manifest.json"
    with tempfile.TemporaryDirectory(prefix="umzug-restore-trust-") as temporary_name:
        temporary = Path(temporary_name)
        os.chmod(temporary, 0o700)
        bundle_snapshot = temporary / "bundle.tar"
        bundle_sha256 = _snapshot_regular_file(
            bundle_source,
            bundle_snapshot,
            max_bytes=max_payload_bytes + 2**31,
        )
        extracted = safe_extract_bundle(
            bundle_snapshot,
            temporary / "container",
            max_payload_bytes=max_payload_bytes,
        )
        if set(extracted) != BUNDLE_MEMBERS:
            raise UmzugError("restore bundle snapshot is incomplete")
        key_snapshot: Path | None = None
        if trusted_key_path is not None:
            key_snapshot = temporary / "independent-signing-public.pem"
            _snapshot_regular_file(trusted_key_path, key_snapshot, max_bytes=4 * 1024 * 1024)
        manifest, fingerprint = load_and_verify_manifest(
            extracted,
            trusted_public_key=key_snapshot,
            expected_fingerprint=normalized_fingerprint,
        )
        verify_source_tar_manifest(extracted["umzug/SOURCE.tar"], manifest)
        manifest_sha256 = sha256_file(extracted["umzug/manifest.json"])
        source_payload_sha256 = sha256_file(extracted["umzug/SOURCE.tar"])
        workspace_manifest_sha256 = _snapshot_regular_file(
            workspace_manifest,
            temporary / "workspace-manifest.json",
            max_bytes=64 * 1024 * 1024,
        )
        if not hmac.compare_digest(workspace_manifest_sha256, manifest_sha256):
            raise UmzugError("workspace manifest differs from the independently signature-verified bundle")

    ingest = _load_clean_ingest(workspace)
    bindings = {
        "manifest_sha256": manifest_sha256,
        "source_payload_sha256": source_payload_sha256,
        "verified_bundle_sha256": bundle_sha256,
        "signing_key_fingerprint": fingerprint,
    }
    for key, expected in bindings.items():
        observed = ingest.get(key)
        if not isinstance(observed, str) or not hmac.compare_digest(observed.lower(), expected.lower()):
            raise UmzugError(f"ingest-state {key} differs from independent restore verification")

    provenance = _load_derivation_receipt(
        workspace / "state" / f"{candidate}.provenance.json",
        label="SOURCE-to-QUARANTINE provenance receipt",
        receipt_type="source-to-quarantine",
        hash_field="provenance_sha256",
        expected_fields={
            "schema_version",
            "receipt_type",
            "candidate",
            "ingested_at",
            "original_source",
            "source_mount_enforced",
            "source_report_scan_id",
            "source_report_sha256",
            "source_manifest_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_report_scan_id",
            "quarantine_report_sha256",
            "quarantine_manifest_sha256",
            "provenance_sha256",
        },
    )
    _require_sha256_fields(
        provenance,
        (
            "provenance_sha256",
            "source_report_sha256",
            "source_manifest_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_report_sha256",
            "quarantine_manifest_sha256",
        ),
        "SOURCE-to-QUARANTINE provenance receipt",
    )
    if (
        provenance.get("candidate") != candidate
        or not isinstance(provenance.get("source_mount_enforced"), bool)
        or not all(
            isinstance(provenance.get(field), str) and bool(provenance[field])
            for field in (
                "ingested_at",
                "original_source",
                "source_report_scan_id",
                "quarantine_report_scan_id",
            )
        )
    ):
        raise UmzugError("SOURCE-to-QUARANTINE provenance receipt is incomplete or misbound")

    promotion = _load_derivation_receipt(
        workspace / "state" / "promotions" / f"{candidate}.json",
        label="QUARANTINE-to-SANITIZED promotion receipt",
        receipt_type="quarantine-to-sanitized",
        hash_field="promotion_sha256",
        expected_fields={
            "schema_version",
            "receipt_type",
            "candidate",
            "promoted_at",
            "source_stage",
            "target_stage",
            "ingest_provenance_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_report_scan_id",
            "quarantine_report_sha256",
            "quarantine_manifest_sha256",
            "accepted_findings",
            "sanitized_report_scan_id",
            "sanitized_report_sha256",
            "sanitized_manifest_sha256",
            "promotion_sha256",
        },
    )
    _require_sha256_fields(
        promotion,
        (
            "promotion_sha256",
            "ingest_provenance_sha256",
            "source_snapshot_manifest_sha256",
            "quarantine_report_sha256",
            "quarantine_manifest_sha256",
            "sanitized_report_sha256",
            "sanitized_manifest_sha256",
        ),
        "QUARANTINE-to-SANITIZED promotion receipt",
    )
    promotion_accepted = promotion.get("accepted_findings")
    if (
        promotion.get("candidate") != candidate
        or promotion.get("source_stage") != Stage.QUARANTINE.value
        or promotion.get("target_stage") != Stage.SANITIZED.value
        or not isinstance(promotion.get("promoted_at"), str)
        or not promotion["promoted_at"]
        or not all(
            isinstance(promotion.get(field), str) and bool(promotion[field])
            for field in ("quarantine_report_scan_id", "sanitized_report_scan_id")
        )
        or not isinstance(promotion_accepted, list)
        or any(not isinstance(row, str) or not row for row in promotion_accepted)
        or promotion_accepted != sorted(set(promotion_accepted))
    ):
        raise UmzugError("QUARANTINE-to-SANITIZED promotion receipt is incomplete or misbound")

    chain_pairs = (
        (promotion["ingest_provenance_sha256"], provenance["provenance_sha256"]),
        (promotion["source_snapshot_manifest_sha256"], provenance["source_snapshot_manifest_sha256"]),
        (promotion["quarantine_manifest_sha256"], provenance["quarantine_manifest_sha256"]),
        (approval.ingest_provenance_sha256, provenance["provenance_sha256"]),
        (approval.promotion_sha256, promotion["promotion_sha256"]),
        (approval.source_manifest_sha256, provenance["source_manifest_sha256"]),
        (approval.source_snapshot_manifest_sha256, provenance["source_snapshot_manifest_sha256"]),
        (approval.quarantine_manifest_sha256, promotion["quarantine_manifest_sha256"]),
        (approval.sanitized_manifest_sha256, promotion["sanitized_manifest_sha256"]),
        (approval.quarantine_report_sha256, promotion["quarantine_report_sha256"]),
    )
    if (
        any(
            not isinstance(left, str) or not isinstance(right, str) or not hmac.compare_digest(left, right)
            for left, right in chain_pairs
        )
        or approval.quarantine_report_scan_id != promotion["quarantine_report_scan_id"]
    ):
        raise UmzugError("approval derivation chain contains a mismatched receipt binding")
    if tuple(promotion_accepted) != approval.promotion_accepted_findings:
        raise UmzugError("approval does not bind the exact QUARANTINE review acknowledgements")

    if approval.candidate != candidate or approval.source_stage is not Stage.SANITIZED:
        raise UmzugError("approval is not bound to this candidate's SANITIZED stage")
    if not approval.actor.strip() or not approval.reason.strip():
        raise UmzugError("approval has no accountable actor or reason")
    if not (
        hmac.compare_digest(approval.manifest_sha256, approval.approved_manifest_sha256)
        and hmac.compare_digest(approval.manifest_sha256, approval.sanitized_manifest_sha256)
    ):
        raise UmzugError("approval report, SANITIZED, and APPROVED manifest bindings differ")

    report_workspace = _approval_report_workspace(workspace, candidate)
    source_report, source_report_sha256 = _load_scan_report(
        workspace / "state" / "reports" / f"{candidate}.source.json",
        label="SOURCE scan report",
    )
    if (
        source_report.get("stage") != Stage.SOURCE.value
        or source_report.get("scan_id") != provenance["source_report_scan_id"]
        or source_report.get("manifest_sha256") != provenance["source_manifest_sha256"]
        or not hmac.compare_digest(
            source_report_sha256,
            str(provenance["source_report_sha256"]),
        )
        or Path(str(source_report.get("root"))).absolute() != Path(str(provenance["original_source"])).absolute()
    ):
        raise UmzugError("ingest provenance is not bound to its SOURCE scan report")

    ingest_quarantine_report, ingest_quarantine_report_sha256 = _load_scan_report(
        workspace / "state" / "reports" / f"{candidate}.quarantine.ingest.json",
        label="ingest QUARANTINE scan report",
    )
    ingest_quarantine_findings = ingest_quarantine_report.get("findings")
    expected_quarantine_root = (report_workspace / Stage.QUARANTINE.value / candidate).absolute()
    if (
        ingest_quarantine_report.get("stage") != Stage.QUARANTINE.value
        or ingest_quarantine_report.get("scan_id") != provenance["quarantine_report_scan_id"]
        or ingest_quarantine_report.get("manifest_sha256") != provenance["quarantine_manifest_sha256"]
        or not hmac.compare_digest(
            ingest_quarantine_report_sha256,
            str(provenance["quarantine_report_sha256"]),
        )
        or Path(str(ingest_quarantine_report.get("root"))).absolute() != expected_quarantine_root
        or not isinstance(ingest_quarantine_report.get("policy"), dict)
        or ingest_quarantine_report["policy"].get("strict_external") is not True
        or not isinstance(ingest_quarantine_findings, list)
        or any(
            not isinstance(row, dict)
            or row.get("severity") not in {"info", "review", "blocker"}
            or not isinstance(row.get("id"), str)
            for row in ingest_quarantine_findings
        )
        or any(row.get("severity") == "blocker" for row in ingest_quarantine_findings)
    ):
        raise UmzugError("ingest provenance is not bound to a blocker-free strict QUARANTINE report")

    quarantine_report, quarantine_report_sha256 = _load_scan_report(
        workspace / "state" / "reports" / f"{candidate}.quarantine.json",
        label="QUARANTINE scan report",
    )
    quarantine_findings = quarantine_report.get("findings")
    if (
        quarantine_report.get("stage") != Stage.QUARANTINE.value
        or quarantine_report.get("scan_id") != promotion["quarantine_report_scan_id"]
        or quarantine_report.get("manifest_sha256") != promotion["quarantine_manifest_sha256"]
        or not hmac.compare_digest(
            quarantine_report_sha256,
            str(promotion["quarantine_report_sha256"]),
        )
        or Path(str(quarantine_report.get("root"))).absolute() != expected_quarantine_root
        or not isinstance(quarantine_report.get("policy"), dict)
        or quarantine_report["policy"].get("strict_external") is not True
        or quarantine_report.get("policy") != ingest_quarantine_report.get("policy")
        or quarantine_report.get("tools") != ingest_quarantine_report.get("tools")
        or not isinstance(quarantine_findings, list)
    ):
        raise UmzugError("promotion is not bound to its strict QUARANTINE scan report")
    if any(
        not isinstance(row, dict)
        or row.get("severity") not in {"info", "review", "blocker"}
        or not isinstance(row.get("id"), str)
        for row in quarantine_findings
    ):
        raise UmzugError("QUARANTINE scan report findings are malformed")
    quarantine_blockers = [row for row in quarantine_findings if row.get("severity") == "blocker"]
    quarantine_reviews = sorted(str(row["id"]) for row in quarantine_findings if row.get("severity") == "review")
    if quarantine_blockers or quarantine_reviews != promotion_accepted:
        raise UmzugError("promotion does not resolve exactly the QUARANTINE review findings")

    report_path = workspace / "state" / "reports" / f"{candidate}.sanitized.json"
    report, report_sha256 = _load_scan_report(report_path, label="SANITIZED approval report")
    if not hmac.compare_digest(report_sha256, approval.report_sha256):
        raise UmzugError("SANITIZED scan report SHA-256 differs from the externally bound approval")
    expected_root = (report_workspace / Stage.SANITIZED.value / candidate).absolute()
    report_root = Path(str(report.get("root"))).absolute()
    if (
        report.get("stage") != Stage.SANITIZED.value
        or report.get("scan_id") != approval.report_scan_id
        or report.get("manifest_sha256") != approval.manifest_sha256
        or report_root != expected_root
        or not isinstance(report.get("policy"), dict)
        or report["policy"].get("strict_external") is not True
    ):
        raise UmzugError("approval is not bound to its strict SANITIZED scan report")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise UmzugError("SANITIZED approval report findings are invalid")
    if any(
        not isinstance(row, dict)
        or row.get("severity") not in {"info", "review", "blocker"}
        or not isinstance(row.get("id"), str)
        for row in findings
    ):
        raise UmzugError("SANITIZED approval report findings are malformed")
    blockers = [row for row in findings if row.get("severity") == "blocker"]
    review_ids = sorted(str(row["id"]) for row in findings if row.get("severity") == "review")
    if blockers or review_ids != list(approval.accepted_findings):
        raise UmzugError("approval does not resolve exactly the strict SANITIZED scan report findings")

    approved_root = (workspace / Stage.APPROVED.value / candidate).absolute()
    scanner = ZeroTrustScanner(
        ScanPolicy(strict_external=False, run_external_scanners=False, require_secure_source_mount=False)
    )
    approved_manifest = scanner.current_manifest_sha256(approved_root)
    if not hmac.compare_digest(approved_manifest, approval.approved_manifest_sha256):
        raise UmzugError("APPROVED candidate changed after its externally bound approval")
    signed_selection = verify_candidate_against_signed_manifest(manifest, candidate, approved_root)
    return RestoreTrustEvidence(
        manifest=manifest,
        manifest_sha256=manifest_sha256,
        signing_key_fingerprint=fingerprint,
        source_payload_sha256=source_payload_sha256,
        bundle_sha256=bundle_sha256,
        approval_sha256=approval.approval_sha256,
        approved_manifest_sha256=approved_manifest,
        signed_selection=signed_selection,
    )
