from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile

import pytest

from umzug.manifest import (
    Selection,
    assemble_bundle,
    build_source_tar,
    create_manifest,
    public_key_fingerprint,
    public_key_for,
    safe_extract_bundle,
    sign_manifest,
)
from umzug.restore_metadata import apply_safe_restore_metadata
from umzug.restore_trust import (
    private_restore_workspace_snapshot,
    publish_restore_receipts,
)
from umzug.scanner import ApprovalDecision, ScanPolicy, ZeroTrustPipeline, ZeroTrustScanner
from umzug.setup_cli import _load_approval, _reverify_restore_trust
from umzug.util import UmzugError, canonical_json, run, sha256_file


pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is not installed")


def _fixture(tmp_path: Path) -> tuple[Path, str, object, Path, str]:
    source = tmp_path / "untrusted-project"
    source.mkdir()
    (source / "notes.txt").write_text("signed offline bytes\n", encoding="utf-8")
    source_tar = tmp_path / "SOURCE.tar"
    entries, selections, warnings = build_source_tar(
        source_tar,
        [Selection(source, "project")],
        (),
    )
    manifest = create_manifest(source_tar, entries, selections, (), warnings)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    private_key = tmp_path / "signing-private.pem"
    public_key = tmp_path / "independent-signing-public.pem"
    signature = tmp_path / "manifest.sig"
    run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)])
    private_key.chmod(0o600)
    public_key_for(private_key, public_key)
    sign_manifest(manifest_path, private_key, signature)

    workspace = tmp_path / "workspace"
    scanner = ZeroTrustScanner(
        ScanPolicy(strict_external=False, run_external_scanners=False, require_secure_source_mount=False)
    )
    pipeline = ZeroTrustPipeline(workspace, scanner)
    candidate = "item-0000"
    ingested = pipeline.ingest(source, candidate)
    strict_quarantine = dataclasses.replace(
        ingested.quarantine_report,
        policy={**ingested.quarantine_report.policy, "strict_external": True},
    )
    strict_quarantine.write_json(workspace / "state" / "reports" / f"{candidate}.quarantine.ingest.json")
    provenance_path = workspace / "state" / f"{candidate}.provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance.pop("provenance_sha256")
    provenance["quarantine_report_sha256"] = hashlib.sha256(
        json.dumps(
            strict_quarantine.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    provenance["provenance_sha256"] = hashlib.sha256(
        json.dumps(
            provenance,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    provenance_path.write_bytes(canonical_json(provenance))
    quarantine_reviews = tuple(row.id for row in strict_quarantine.reviews)
    sanitized = pipeline.promote_to_sanitized(
        candidate,
        strict_quarantine,
        accepted_findings=quarantine_reviews,
    )
    strict_sanitized = dataclasses.replace(
        sanitized,
        policy={**sanitized.policy, "strict_external": True},
    )
    strict_sanitized.write_json(workspace / "state" / "reports" / f"{candidate}.sanitized.json")
    sanitized_reviews = tuple(row.id for row in strict_sanitized.reviews)
    approval = pipeline.approve(
        candidate,
        strict_sanitized,
        ApprovalDecision(
            approved=True,
            actor="offline-reviewer",
            reason="strict evidence reviewed out of band",
            expected_manifest_sha256=strict_sanitized.manifest_sha256,
            accepted_findings=sanitized_reviews,
        ),
    )

    bundle_dir = workspace / "state" / "bundle"
    bundle_dir.mkdir()
    bundle = bundle_dir / "bundle.tar"
    assemble_bundle(bundle, manifest_path, signature, public_key, source_tar)
    extracted = safe_extract_bundle(bundle, bundle_dir / "verified-container")
    fingerprint = public_key_fingerprint(public_key)
    ingest_state = {
        "format": 1,
        "manifest_sha256": sha256_file(extracted["umzug/manifest.json"]),
        "source_payload_sha256": sha256_file(extracted["umzug/SOURCE.tar"]),
        "verified_bundle_sha256": sha256_file(bundle),
        "signing_key_fingerprint": fingerprint,
        "candidates": [{"id": candidate}],
        "extraction_errors": [],
        "manifest_warnings": [],
        "xattr_failures": [],
    }
    (workspace / "state" / "ingest.json").write_bytes(canonical_json(ingest_state))
    return workspace, candidate, approval, public_key, fingerprint


def _verify(
    workspace: Path,
    candidate: str,
    approval: object,
    *,
    trusted_key: Path | None,
    fingerprint: str | None,
) -> object:
    return _reverify_restore_trust(
        workspace=workspace,
        candidate=candidate,
        approval=approval,  # type: ignore[arg-type]
        expected_approval_sha256=approval.approval_sha256,  # type: ignore[attr-defined]
        trusted_key=trusted_key,
        expected_fingerprint=fingerprint,
        max_payload_bytes=64 * 1024 * 1024,
    )


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _rewrite_self_hashed_receipt(
    path: Path,
    *,
    hash_field: str,
    field: str,
    value: object,
) -> dict[str, object]:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt[field] = value
    receipt.pop(hash_field)
    receipt[hash_field] = _canonical_hash(receipt)
    path.write_bytes(canonical_json(receipt))
    return receipt


def test_restore_reverification_accepts_independent_key_and_fingerprint(tmp_path: Path) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)

    evidence = _verify(
        workspace,
        candidate,
        approval,
        trusted_key=public_key,
        fingerprint=fingerprint,
    )

    assert evidence.signing_key_fingerprint == fingerprint
    assert evidence.approval_sha256 == approval.approval_sha256
    assert evidence.signed_selection["candidate"] == candidate
    assert evidence.signed_selection["entry_count"] == 2


def test_restore_reverification_accepts_out_of_band_fingerprint_without_key_file(tmp_path: Path) -> None:
    workspace, candidate, approval, _, fingerprint = _fixture(tmp_path)

    evidence = _verify(
        workspace,
        candidate,
        approval,
        trusted_key=None,
        fingerprint=fingerprint,
    )

    assert evidence.signing_key_fingerprint == fingerprint


def test_user_writable_ingest_workspace_is_restored_only_from_private_snapshot(
    tmp_path: Path,
) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    workspace.chmod(0o700)
    restored_destination = tmp_path / "inert-restored" / candidate

    with private_restore_workspace_snapshot(
        workspace=workspace,
        candidate=candidate,
        max_payload_bytes=64 * 1024 * 1024,
    ) as snapshot:
        assert snapshot != workspace
        assert snapshot.stat().st_uid == os.geteuid()
        assert snapshot.stat().st_mode & 0o077 == 0

        original_approved = workspace / "APPROVED" / candidate / "notes.txt"
        original_approved.write_text(
            "source-user raced after snapshot\n",
            encoding="utf-8",
        )
        evidence = _verify(
            snapshot,
            candidate,
            approval,
            trusted_key=public_key,
            fingerprint=fingerprint,
        )
        pipeline = ZeroTrustPipeline(
            snapshot,
            ZeroTrustScanner(
                ScanPolicy(
                    strict_external=False,
                    run_external_scanners=False,
                    require_secure_source_mount=False,
                )
            ),
        )
        restored = pipeline.restore(
            candidate,
            restored_destination,
            approval,
            confirmed=True,
        )
        metadata = apply_safe_restore_metadata(
            workspace=snapshot,
            candidate=candidate,
            destination=restored,
            approval_manifest_sha256=approval.approved_manifest_sha256,
            approval_sha256=approval.approval_sha256,
            target_users=[],
            target_groups=[],
            require_root=False,
            verified_manifest=evidence.manifest,
            verified_manifest_sha256=evidence.manifest_sha256,
        )
        content_receipt, metadata_receipt = publish_restore_receipts(
            snapshot_workspace=snapshot,
            workspace=workspace,
            candidate=candidate,
        )

    assert (restored_destination / "notes.txt").read_text(encoding="utf-8") == "signed offline bytes\n"
    assert metadata["status"] == "safe-metadata-applied"
    assert content_receipt.is_file()
    assert metadata_receipt.is_file()


def test_restore_reverification_requires_external_source_anchor(tmp_path: Path) -> None:
    workspace, candidate, approval, _, _ = _fixture(tmp_path)

    with pytest.raises(UmzugError, match="out-of-band trust anchor"):
        _verify(workspace, candidate, approval, trusted_key=None, fingerprint=None)


def test_restore_reverification_rejects_workspace_key_as_independent(tmp_path: Path) -> None:
    workspace, candidate, approval, public_key, _ = _fixture(tmp_path)
    workspace_key = workspace / "copied-key.pem"
    workspace_key.write_bytes(public_key.read_bytes())

    with pytest.raises(UmzugError, match="outside the migration workspace"):
        _verify(workspace, candidate, approval, trusted_key=workspace_key, fingerprint=None)


def test_restore_reverification_rejects_rewritten_workspace_json(tmp_path: Path) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    manifest_path = workspace / "state" / "bundle" / "verified-container" / "umzug" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["created_at"] = "2099-01-01T00:00:00Z"
    manifest_path.write_bytes(canonical_json(manifest))
    ingest_path = workspace / "state" / "ingest.json"
    ingest = json.loads(ingest_path.read_text(encoding="utf-8"))
    ingest["manifest_sha256"] = sha256_file(manifest_path)
    ingest_path.write_bytes(canonical_json(ingest))

    with pytest.raises(UmzugError, match="signature-verified bundle"):
        _verify(
            workspace,
            candidate,
            approval,
            trusted_key=public_key,
            fingerprint=fingerprint,
        )


def test_restore_reverification_rejects_bundle_manifest_signature_tamper(tmp_path: Path) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    bundle = workspace / "state" / "bundle" / "bundle.tar"
    with tarfile.open(bundle, "r:") as archive:
        member = archive.getmember("umzug/manifest.json")
        extracted = archive.extractfile(member)
        assert extracted is not None
        data = extracted.read()
    marker = b"UNTRUSTED_SOURCE_DATA_REQUIRES_ANALYSIS_AND_EXPLICIT_APPROVAL"
    assert marker in data
    tampered = data.replace(marker, b"UNTRUSTED_SOURCE_DATA_REQUIRES_ANALYSIS_AND_EXPLICIT_APPROVAM", 1)
    assert len(tampered) == len(data)
    with bundle.open("r+b", buffering=0) as handle:
        handle.seek(member.offset_data)
        handle.write(tampered)
        handle.flush()
        os.fsync(handle.fileno())

    with pytest.raises(UmzugError, match="command failed|mandatory untrusted-source"):
        _verify(
            workspace,
            candidate,
            approval,
            trusted_key=public_key,
            fingerprint=fingerprint,
        )


def test_restore_reverification_rejects_source_payload_tamper(tmp_path: Path) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    bundle = workspace / "state" / "bundle" / "bundle.tar"
    with tarfile.open(bundle, "r:") as archive:
        member = archive.getmember("umzug/SOURCE.tar")
    with bundle.open("r+b", buffering=0) as handle:
        handle.seek(member.offset_data + 1024)
        original = handle.read(1)
        assert original
        handle.seek(member.offset_data + 1024)
        handle.write(bytes([original[0] ^ 0x01]))
        handle.flush()
        os.fsync(handle.fileno())

    with pytest.raises(UmzugError, match="SOURCE.tar checksum mismatch"):
        _verify(
            workspace,
            candidate,
            approval,
            trusted_key=public_key,
            fingerprint=fingerprint,
        )


def test_restore_reverification_rejects_unconfirmed_approval_hash(tmp_path: Path) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    forged = dataclasses.replace(approval, approval_sha256="0" * 64)

    with pytest.raises(UmzugError, match="out-of-band approval"):
        _reverify_restore_trust(
            workspace=workspace,
            candidate=candidate,
            approval=forged,
            expected_approval_sha256=approval.approval_sha256,
            trusted_key=public_key,
            expected_fingerprint=fingerprint,
            max_payload_bytes=64 * 1024 * 1024,
        )


@pytest.mark.parametrize(
    "field,value",
    (
        ("source_report_sha256", "0" * 64),
        ("source_manifest_sha256", "1" * 64),
        ("source_snapshot_manifest_sha256", "2" * 64),
        ("quarantine_report_sha256", "3" * 64),
        ("quarantine_manifest_sha256", "4" * 64),
        ("source_report_scan_id", "forged-source-scan"),
        ("quarantine_report_scan_id", "forged-ingest-quarantine-scan"),
    ),
)
def test_restore_reverification_rejects_rehashed_provenance_link_tamper(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    _rewrite_self_hashed_receipt(
        workspace / "state" / f"{candidate}.provenance.json",
        hash_field="provenance_sha256",
        field=field,
        value=value,
    )

    with pytest.raises(UmzugError, match="derivation chain|provenance|receipt"):
        _verify(
            workspace,
            candidate,
            approval,
            trusted_key=public_key,
            fingerprint=fingerprint,
        )


@pytest.mark.parametrize(
    "field,value",
    (
        ("ingest_provenance_sha256", "0" * 64),
        ("source_snapshot_manifest_sha256", "1" * 64),
        ("quarantine_report_sha256", "2" * 64),
        ("quarantine_manifest_sha256", "3" * 64),
        ("sanitized_report_sha256", "4" * 64),
        ("sanitized_manifest_sha256", "5" * 64),
        ("quarantine_report_scan_id", "forged-promotion-scan"),
        ("sanitized_report_scan_id", "forged-sanitized-scan"),
        ("accepted_findings", ["0" * 24]),
    ),
)
def test_restore_reverification_rejects_rehashed_promotion_link_tamper(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    _rewrite_self_hashed_receipt(
        workspace / "state" / "promotions" / f"{candidate}.json",
        hash_field="promotion_sha256",
        field=field,
        value=value,
    )

    with pytest.raises(UmzugError, match="derivation chain|receipt|acknowledgements"):
        _verify(
            workspace,
            candidate,
            approval,
            trusted_key=public_key,
            fingerprint=fingerprint,
        )


@pytest.mark.parametrize(
    "field,value",
    (
        ("ingest_provenance_sha256", "0" * 64),
        ("promotion_sha256", "1" * 64),
        ("source_manifest_sha256", "2" * 64),
        ("source_snapshot_manifest_sha256", "3" * 64),
        ("quarantine_manifest_sha256", "4" * 64),
        ("sanitized_manifest_sha256", "5" * 64),
        ("quarantine_report_sha256", "6" * 64),
        ("quarantine_report_scan_id", "forged-approval-scan"),
        ("promotion_accepted_findings", ("0" * 24,)),
    ),
)
def test_restore_reverification_rejects_approval_chain_member_tamper(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    forged = dataclasses.replace(approval, **{field: value})

    with pytest.raises(UmzugError, match="canonical self-hash"):
        _reverify_restore_trust(
            workspace=workspace,
            candidate=candidate,
            approval=forged,
            expected_approval_sha256=approval.approval_sha256,
            trusted_key=public_key,
            expected_fingerprint=fingerprint,
            max_payload_bytes=64 * 1024 * 1024,
        )


@pytest.mark.parametrize("receipt", ("provenance", "promotion"))
def test_restore_reverification_rejects_missing_derivation_receipt(
    tmp_path: Path,
    receipt: str,
) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    path = (
        workspace / "state" / f"{candidate}.provenance.json"
        if receipt == "provenance"
        else workspace / "state" / "promotions" / f"{candidate}.json"
    )
    path.unlink()

    with pytest.raises(UmzugError, match="receipt.*missing|snapshot is missing"):
        _verify(
            workspace,
            candidate,
            approval,
            trusted_key=public_key,
            fingerprint=fingerprint,
        )


def test_legacy_approval_without_derivation_fields_is_rejected(tmp_path: Path) -> None:
    workspace, candidate, _, _, _ = _fixture(tmp_path)
    approval_path = workspace / "state" / "approvals" / f"{candidate}.json"
    value = json.loads(approval_path.read_text(encoding="utf-8"))
    value.pop("promotion_sha256")
    value.pop("approval_sha256")
    value["approval_sha256"] = _canonical_hash(value)
    approval_path.write_bytes(canonical_json(value))

    with pytest.raises(UmzugError, match="required exact schema"):
        _load_approval(workspace, candidate)


def test_restore_reverification_rejects_rewritten_scan_report(tmp_path: Path) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    report_path = workspace / "state" / "reports" / f"{candidate}.sanitized.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["findings"] = []
    report_path.write_bytes(canonical_json(report))

    with pytest.raises(UmzugError, match="scan report SHA-256"):
        _verify(
            workspace,
            candidate,
            approval,
            trusted_key=public_key,
            fingerprint=fingerprint,
        )


def test_restore_reverification_rejects_changed_approved_bytes(tmp_path: Path) -> None:
    workspace, candidate, approval, public_key, fingerprint = _fixture(tmp_path)
    (workspace / "APPROVED" / candidate / "notes.txt").write_text("changed after approval\n", encoding="utf-8")

    with pytest.raises(UmzugError, match="changed after"):
        _verify(
            workspace,
            candidate,
            approval,
            trusted_key=public_key,
            fingerprint=fingerprint,
        )
