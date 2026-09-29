from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest
import umzug.scanner as scanner_module

from umzug.scanner import (
    ApprovalDecision,
    ApprovalError,
    ExternalScanResult,
    IntegrityError,
    ScanPolicy,
    Severity,
    Stage,
    ToolEvidence,
    UnsafeInputError,
    ZeroTrustPipeline,
    ZeroTrustScanner,
)


def relaxed_scanner(**overrides: object) -> ZeroTrustScanner:
    values: dict[str, object] = {
        "strict_external": False,
        "run_external_scanners": False,
        "require_secure_source_mount": False,
        "max_archive_expanded_bytes": 8 * 1024 * 1024,
        "max_archive_member_bytes": 4 * 1024 * 1024,
        "max_compression_ratio": 50.0,
    }
    values.update(overrides)
    return ZeroTrustScanner(ScanPolicy(**values))


def rules(report: object, severity: Severity | None = None) -> set[str]:
    findings = getattr(report, "findings")
    return {finding.rule for finding in findings if severity is None or finding.severity is severity}


def test_zip_path_traversal_is_a_blocker(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    archive_path = candidate / "payload.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../../outside", b"not executable")

    report = relaxed_scanner().scan(candidate)

    assert "archive_path_traversal" in rules(report, Severity.BLOCKER)
    assert not report.can_promote()


def test_tar_absolute_path_and_escaping_link_are_blocked(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    archive_path = candidate / "payload.tar"
    with tarfile.open(archive_path, "w") as archive:
        absolute = tarfile.TarInfo("/etc/cron.d/implant")
        absolute.size = 4
        archive.addfile(absolute, io.BytesIO(b"data"))
        link = tarfile.TarInfo("safe/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../etc/shadow"
        archive.addfile(link)

    report = relaxed_scanner().scan(candidate)

    blocker_rules = rules(report, Severity.BLOCKER)
    assert "archive_path_traversal" in blocker_rules
    assert "archive_link_escape" in blocker_rules


def test_archive_bomb_ratio_is_rejected_before_expansion(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    archive_path = candidate / "bomb.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("zeros.bin", b"\x00" * (1024 * 1024))

    report = relaxed_scanner(max_compression_ratio=10.0).scan(candidate)

    assert "archive_compression_ratio" in rules(report, Severity.BLOCKER)
    assert not report.can_promote()


def test_encrypted_zip_member_is_never_released_without_inspection(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    archive_path = candidate / "encrypted.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("opaque.txt", b"hidden")
    encoded = bytearray(archive_path.read_bytes())
    local = encoded.find(b"PK\x03\x04")
    central = encoded.find(b"PK\x01\x02")
    assert local >= 0 and central >= 0
    encoded[local + 6 : local + 8] = (int.from_bytes(encoded[local + 6 : local + 8], "little") | 1).to_bytes(
        2, "little"
    )
    encoded[central + 8 : central + 10] = (int.from_bytes(encoded[central + 8 : central + 10], "little") | 1).to_bytes(
        2, "little"
    )
    archive_path.write_bytes(encoded)

    report = relaxed_scanner().scan(candidate)

    assert "encrypted_archive_member" in rules(report, Severity.BLOCKER)


def test_archive_with_appended_payload_is_fail_closed(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    archive_path = candidate / "polyglot.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("plain.txt", b"plain")
    with archive_path.open("ab") as handle:
        handle.write(b"MZ-appended-payload")

    report = relaxed_scanner().scan(candidate)

    assert "archive_trailing_payload" in rules(report, Severity.BLOCKER)


def test_deb_is_structurally_inspected_but_requires_vendor_bound_review(tmp_path: Path) -> None:
    def tar_gzip(name: str, content: bytes, mode: int = 0o644) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = mode
            archive.addfile(member, io.BytesIO(content))
        return output.getvalue()

    def ar_member(name: str, content: bytes) -> bytes:
        encoded_name = f"{name}/".encode("ascii").ljust(16, b" ")
        header = (
            encoded_name
            + b"0".ljust(12, b" ")
            + b"0".ljust(6, b" ")
            + b"0".ljust(6, b" ")
            + b"100644".ljust(8, b" ")
            + str(len(content)).encode("ascii").ljust(10, b" ")
            + b"`\n"
        )
        assert len(header) == 60
        return header + content + (b"\n" if len(content) & 1 else b"")

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    package = candidate / "vendor.deb"
    package.write_bytes(
        b"!<arch>\n"
        + ar_member("debian-binary", b"2.0\n")
        + ar_member("control.tar.gz", tar_gzip("control", b"Package: vendor-app\nVersion: 1\n"))
        + ar_member("data.tar.gz", tar_gzip("usr/bin/vendor-app", b"\x7fELF" + b"\x00" * 64, 0o755))
    )

    report = relaxed_scanner(max_compression_ratio=500.0).scan(candidate)

    package_record = next(record for record in report.records if record.path == "vendor.deb")
    assert package_record.detected_type == "deb"
    assert "distribution_package_review" in rules(report, Severity.REVIEW)
    assert "packaged_native_executable" in rules(report, Severity.REVIEW)
    assert "native_executable" not in rules(report, Severity.BLOCKER)
    assert not report.blockers
    assert report.can_promote(finding.id for finding in report.reviews)


def test_rpm_zstd_payload_without_pinned_isolated_decompressor_is_blocked(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    lead = bytearray(96)
    lead[:4] = b"\xed\xab\xee\xdb"
    lead[4] = 4
    empty_header = b"\x8e\xad\xe8\x01" + b"\x00" * 12
    # a vendor signature never substitutes for complete payload inspection.
    payload = b"\x28\xb5\x2f\xfd" + b"opaque-payload"
    (candidate / "vendor.rpm").write_bytes(bytes(lead) + empty_header + empty_header + payload)

    report = relaxed_scanner().scan(candidate)

    record = next(record for record in report.records if record.path == "vendor.rpm")
    assert record.detected_type == "rpm"
    assert "distribution_package_review" in rules(report, Severity.REVIEW)
    assert "rpm_payload_decompression_failed" in rules(report, Severity.BLOCKER)
    assert report.blockers


def test_zstd_expansion_is_recursively_inspected_when_pinned_decoder_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "package.tar.zst").write_bytes(b"\x28\xb5\x2f\xfd" + b"fixture")
    compressed = io.BytesIO()
    with tarfile.open(fileobj=compressed, mode="w:gz") as archive:
        member = tarfile.TarInfo("safe.txt")
        member.size = len(b"plain data")
        archive.addfile(member, io.BytesIO(b"plain data"))
    expanded = compressed.getvalue()
    # tar_gzip returns gzip; the recursive pass must therefore continue through
    # another bounded decompression and inspect its tar member.
    scanner = relaxed_scanner(max_compression_ratio=10_000.0)
    monkeypatch.setattr(scanner, "_bounded_zstd_decompress", lambda data, limit: expanded)

    report = scanner.scan(candidate)

    assert "zstd_decompression_unavailable" not in rules(report, Severity.BLOCKER)
    assert "archive_parse_failed" not in rules(report, Severity.BLOCKER)
    assert not report.blockers


def test_secret_material_is_never_acknowledgeable(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "credentials.txt").write_text(
        "aws_access_key_id=AKIAABCDEFGHIJKLMNOP\n-----BEGIN OPENSSH PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    report = relaxed_scanner().scan(candidate)
    secret_findings = [finding for finding in report.findings if finding.rule == "secret_material"]

    assert secret_findings
    assert all(finding.severity is Severity.BLOCKER for finding in secret_findings)
    assert not report.can_promote(finding.id for finding in secret_findings)


def test_filesystem_symlink_escape_is_rejected_without_following_it(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("outside secret", encoding="utf-8")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "escape").symlink_to("../outside.txt")

    report = relaxed_scanner().scan(candidate)

    assert {"unsafe_symlink_target", "symlink_escape"} & rules(report, Severity.BLOCKER)
    link_record = next(record for record in report.records if record.path == "escape")
    assert link_record.kind == "symlink"
    assert link_record.link_target == "../outside.txt"


def test_review_findings_need_exact_explicit_acceptance(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "config.txt").write_text("upstream=https://example.invalid/api\n", encoding="utf-8")
    report = relaxed_scanner().scan(candidate, Stage.SANITIZED)
    review_ids = tuple(finding.id for finding in report.reviews)

    assert review_ids
    assert not report.can_approve()
    assert report.can_approve(review_ids)


def test_approval_requires_sanitized_stage_and_explicit_hash_binding(tmp_path: Path) -> None:
    scanner = relaxed_scanner()
    pipeline = ZeroTrustPipeline(tmp_path / "pipeline", scanner)
    source = tmp_path / "clean-source"
    source.mkdir()
    notes = source / "notes.txt"
    notes.write_text("plain offline notes\n", encoding="utf-8")
    notes.chmod(0o600)
    ingested = pipeline.ingest(source, "clean")
    report = pipeline.promote_to_sanitized(
        "clean",
        ingested.quarantine_report,
        accepted_findings=tuple(finding.id for finding in ingested.quarantine_report.reviews),
    )
    accepted_reviews = tuple(finding.id for finding in report.reviews)
    assert report.can_approve(accepted_reviews)

    with pytest.raises(ApprovalError, match="negative"):
        pipeline.approve(
            "clean",
            report,
            ApprovalDecision(False, "operator", "reviewed", report.manifest_sha256),
        )
    with pytest.raises(ApprovalError, match="bind"):
        pipeline.approve(
            "clean",
            report,
            ApprovalDecision(True, "operator", "reviewed", "0" * 64),
        )

    wrong_stage = scanner.scan(pipeline.stage_path(Stage.SANITIZED, "clean"), Stage.QUARANTINE)
    with pytest.raises(ApprovalError, match="SANITIZED"):
        pipeline.approve(
            "clean",
            wrong_stage,
            ApprovalDecision(True, "operator", "reviewed", wrong_stage.manifest_sha256),
        )

    record = pipeline.approve(
        "clean",
        report,
        ApprovalDecision(True, "operator", "reviewed offline", report.manifest_sha256, accepted_reviews),
    )
    approved = pipeline.stage_path(Stage.APPROVED, "clean")
    assert (approved / "notes.txt").read_text(encoding="utf-8") == "plain offline notes\n"
    assert record.manifest_sha256 == report.manifest_sha256
    assert record.sanitized_manifest_sha256 == report.manifest_sha256
    assert len(record.ingest_provenance_sha256) == 64
    assert len(record.promotion_sha256) == 64
    assert len(record.approval_sha256) == 64


def test_tamper_after_scan_aborts_approval_and_copies_nothing(tmp_path: Path) -> None:
    scanner = relaxed_scanner()
    pipeline = ZeroTrustPipeline(tmp_path / "pipeline", scanner)
    sanitized = pipeline.stage_path(Stage.SANITIZED, "tampered")
    sanitized.mkdir()
    payload = sanitized / "data.txt"
    payload.write_text("version one\n", encoding="utf-8")
    report = scanner.scan(sanitized, Stage.SANITIZED)

    payload.write_text("version two\n", encoding="utf-8")

    with pytest.raises(IntegrityError, match="changed after scan"):
        pipeline.approve(
            "tampered",
            report,
            ApprovalDecision(
                True,
                "operator",
                "reviewed",
                report.manifest_sha256,
                tuple(finding.id for finding in report.reviews),
            ),
        )
    assert not pipeline.stage_path(Stage.APPROVED, "tampered").exists()


def test_complete_pipeline_moves_only_forward_through_all_trust_zones(tmp_path: Path) -> None:
    source = tmp_path / "untrusted-source"
    source.mkdir()
    (source / "notes.txt").write_text("offline notes\n", encoding="utf-8")
    scanner = relaxed_scanner()
    pipeline = ZeroTrustPipeline(tmp_path / "pipeline", scanner)

    ingested = pipeline.ingest(source, "candidate")
    assert pipeline.stage_path(Stage.SOURCE, "candidate").exists()
    assert pipeline.stage_path(Stage.QUARANTINE, "candidate").exists()
    quarantine_reviews = tuple(finding.id for finding in ingested.quarantine_report.reviews)
    sanitized_report = pipeline.promote_to_sanitized(
        "candidate",
        ingested.quarantine_report,
        accepted_findings=quarantine_reviews,
    )
    sanitized_reviews = tuple(finding.id for finding in sanitized_report.reviews)
    approval = pipeline.approve(
        "candidate",
        sanitized_report,
        ApprovalDecision(
            True,
            "offline-operator",
            "content reviewed",
            sanitized_report.manifest_sha256,
            sanitized_reviews,
        ),
    )
    restored = pipeline.restore(
        "candidate",
        tmp_path / "restored-output",
        approval,
        confirmed=True,
    )

    assert (restored / "notes.txt").read_text(encoding="utf-8") == "offline notes\n"
    assert pipeline.stage_path(Stage.RESTORED, "candidate").with_suffix(".json").is_file()


@pytest.mark.parametrize("existing_kind", ["file", "directory"])
def test_restore_preserves_existing_destination(tmp_path: Path, existing_kind: str) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("approved incoming content\n", encoding="utf-8")
    pipeline = ZeroTrustPipeline(tmp_path / "pipeline", relaxed_scanner())
    ingested = pipeline.ingest(source, "candidate")
    report = pipeline.promote_to_sanitized(
        "candidate",
        ingested.quarantine_report,
        accepted_findings=tuple(row.id for row in ingested.quarantine_report.reviews),
    )
    approval = pipeline.approve(
        "candidate",
        report,
        ApprovalDecision(
            True,
            "demo-operator",
            "synthetic data reviewed",
            report.manifest_sha256,
            tuple(row.id for row in report.reviews),
        ),
    )
    destination = tmp_path / "existing-target"
    if existing_kind == "directory":
        destination.mkdir(mode=0o700)
        existing = destination / "notes.txt"
    else:
        existing = destination
    existing.write_bytes(b"existing content must survive\n")
    existing.chmod(0o600)
    before = existing.stat()

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        pipeline.restore("candidate", destination, approval, confirmed=True)

    assert existing.read_bytes() == b"existing content must survive\n"
    after = existing.stat()
    assert (after.st_ino, after.st_mode, after.st_mtime_ns) == (
        before.st_ino,
        before.st_mode,
        before.st_mtime_ns,
    )
    if existing_kind == "directory":
        assert sorted(path.name for path in destination.iterdir()) == ["notes.txt"]
    assert not pipeline.stage_path(Stage.RESTORED, "candidate").with_suffix(".json").exists()


def test_restore_rejects_symlinked_destination_parent_without_escape(tmp_path: Path) -> None:
    source = tmp_path / "untrusted-source"
    source.mkdir()
    (source / "notes.txt").write_text("offline notes\n", encoding="utf-8")
    pipeline = ZeroTrustPipeline(tmp_path / "pipeline", relaxed_scanner())
    ingested = pipeline.ingest(source, "candidate")
    sanitized = pipeline.promote_to_sanitized(
        "candidate",
        ingested.quarantine_report,
        accepted_findings=tuple(row.id for row in ingested.quarantine_report.reviews),
    )
    approval = pipeline.approve(
        "candidate",
        sanitized,
        ApprovalDecision(
            True,
            "offline-operator",
            "content reviewed",
            sanitized.manifest_sha256,
            tuple(row.id for row in sanitized.reviews),
        ),
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(outside, target_is_directory=True)

    with pytest.raises((UnsafeInputError, OSError), match="symlink|non-directory"):
        pipeline.restore(
            "candidate",
            linked_parent / "must-not-appear",
            approval,
            confirmed=True,
        )

    assert not (outside / "must-not-appear").exists()
    assert not pipeline.stage_path(Stage.RESTORED, "candidate").with_suffix(".json").exists()


def test_fd_copy_rejects_directory_to_symlink_swap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "approved"
    source.mkdir()
    (source / "safe.txt").write_text("approved bytes\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "safe.txt").write_text("attacker bytes\n", encoding="utf-8")
    detached = tmp_path / "detached-approved"
    destination = tmp_path / "restored"
    real_listdir = scanner_module.os.listdir
    swapped = False

    def swap_after_directory_open(directory: object) -> list[str]:
        nonlocal swapped
        names = real_listdir(directory)
        if not swapped and isinstance(directory, int):
            source.rename(detached)
            source.symlink_to(outside, target_is_directory=True)
            swapped = True
        return names

    monkeypatch.setattr(scanner_module.os, "listdir", swap_after_directory_open)

    with pytest.raises(IntegrityError, match="directory changed while copying"):
        scanner_module._safe_copy_atomic(source, destination, inert=False)

    assert swapped
    assert not destination.exists()
    assert (outside / "safe.txt").read_text(encoding="utf-8") == "attacker bytes\n"


def test_direct_root_restore_rejects_user_owned_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "user-workspace"
    approved = workspace / "APPROVED"
    approved.mkdir(parents=True, mode=0o700)
    workspace.chmod(0o700)
    approved.chmod(0o700)
    if os.geteuid() == 0:
        os.chown(workspace, 65534, 65534)
    else:
        monkeypatch.setattr(scanner_module.os, "geteuid", lambda: 0)

    with pytest.raises(UnsafeInputError, match="root-owned.*private workspace"):
        scanner_module._require_root_private_restore_source(workspace)


def test_walk_nofollow_never_enters_directory_swapped_to_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate"
    nested = candidate / "nested"
    nested.mkdir(parents=True)
    (nested / "safe.txt").write_text("approved bytes\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.txt").write_text("must never be walked\n", encoding="utf-8")
    detached = candidate / "nested-detached"
    real_listdir = scanner_module.os.listdir
    swapped = False

    def swap_child_to_symlink(directory: object) -> list[str]:
        nonlocal swapped
        names = real_listdir(directory)
        if not swapped and isinstance(directory, int):
            nested.rename(detached)
            nested.symlink_to(outside, target_is_directory=True)
            swapped = True
        return names

    monkeypatch.setattr(scanner_module.os, "listdir", swap_child_to_symlink)
    findings: list[object] = []
    paths = relaxed_scanner()._walk_nofollow(candidate, findings)  # type: ignore[arg-type]

    assert swapped
    assert any(
        getattr(row, "rule", None) == "directory_enumeration_failed"
        and getattr(row, "severity", None) is Severity.BLOCKER
        for row in findings
    )
    assert all(not path.name.endswith("evil.txt") for path in paths)


def test_default_strict_policy_never_silently_degrades_external_evidence(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "plain.txt").write_text("plain text\n", encoding="utf-8")
    # avoid running local scanners in the test; strict policy must turn that
    # deliberate omission and missing cryptographic pins into blockers.
    scanner = ZeroTrustScanner(ScanPolicy(run_external_scanners=False))

    report = scanner.scan(candidate)

    blocker_rules = rules(report, Severity.BLOCKER)
    assert "external_scanners_not_run" in blocker_rules
    assert "scanner_binary_unverified" in blocker_rules or "required_scanner_missing" in blocker_rules
    assert "yara_rule_missing" in blocker_rules
    assert "clam_signature_missing" in blocker_rules
    assert {"external_isolator_missing", "external_isolator_unverified"} & blocker_rules
    assert not report.can_promote()


def test_strict_policy_never_runs_tools_without_network_process_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "plain.txt").write_text("plain text\n", encoding="utf-8")
    scanner = ZeroTrustScanner(
        ScanPolicy(
            strict_external=True,
            run_external_scanners=True,
            external_isolation_backend="none",
            required_external_scanners=(),
            require_verified_external_material=False,
        )
    )

    def forbidden_direct_execution(*args: object, **kwargs: object) -> object:
        raise AssertionError("strict scan attempted an unisolated subprocess")

    monkeypatch.setattr(scanner_module.subprocess, "run", forbidden_direct_execution)
    report = scanner.scan(candidate)

    blocker_rules = rules(report, Severity.BLOCKER)
    assert "external_isolation_disabled" in blocker_rules
    assert "external_isolation_unavailable" in blocker_rules
    assert not report.external_results
    assert not report.can_promote()


def test_bubblewrap_profile_maps_input_read_only_and_unshares_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    scanner = relaxed_scanner(run_external_scanners=True)
    bwrap_snapshot = tmp_path / "bwrap.snapshot"
    bwrap_snapshot.write_bytes(b"private bwrap")
    bwrap_snapshot.chmod(0o500)
    tools = {"bwrap": ToolEvidence("bwrap", "/usr/bin/bwrap", "test", "a" * 64, "a" * 64, True, True)}
    invocations: list[list[str]] = []

    def successful_probe(name: str, args: object, rel: str, root: Path) -> ExternalScanResult:
        invocations.append(list(args))  # type: ignore[arg-type]
        return ExternalScanResult(name, rel, 0, "completed", "")

    monkeypatch.setattr(scanner, "_invoke_tool", successful_probe)
    findings: list[object] = []
    results: list[ExternalScanResult] = []
    trust = scanner_module._ScannerTrustSnapshots(  # noqa: SLF001
        tools={"bwrap": bwrap_snapshot},
        yara_rules=(),
        clam_signatures=(),
    )
    prefix = scanner._establish_external_isolation(  # noqa: SLF001
        candidate,
        tools,
        findings,  # type: ignore[arg-type]
        results,
        trust,
    )

    assert prefix is not None
    assert "--unshare-net" in prefix
    assert "--unshare-pid" in prefix
    assert "--cap-drop" in prefix
    assert not any(prefix[index : index + 3] == ["--ro-bind", "/", "/"] for index in range(len(prefix) - 2))
    assert "/usr" in prefix
    root_bind = prefix.index(str(candidate))
    assert prefix[root_bind - 1 : root_bind + 2] == ["--ro-bind", str(candidate), "/input"]
    assert "/home" in prefix and "/run" in prefix and "/tmp" in prefix
    assert prefix[0] == str(bwrap_snapshot)
    assert invocations and invocations[0][-2:] == ["/analysis/tools/bwrap", "--version"]


def test_external_scanners_receive_immutable_snapshot_and_source_drift_blocks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    original = candidate / "notes.txt"
    original.write_text("reviewed bytes\n", encoding="utf-8")
    scanner = relaxed_scanner()
    observed_snapshot: list[Path] = []

    def inspect_snapshot(
        root: Path,
        regular_paths: object,
        tools: object,
        findings: object,
        detected_types: object,
        trust: object,
    ) -> list[ExternalScanResult]:
        del tools, findings, detected_types, trust
        rows = list(regular_paths)  # type: ignore[arg-type]
        snapshot_path, rel = rows[0]
        assert rel == "notes.txt"
        assert snapshot_path.is_relative_to(root)
        assert snapshot_path.read_text(encoding="utf-8") == "reviewed bytes\n"
        observed_snapshot.append(snapshot_path)
        original.write_text("changed during external analysis\n", encoding="utf-8")
        return []

    monkeypatch.setattr(scanner, "_run_external_scanners", inspect_snapshot)
    report = scanner.scan(candidate)

    assert observed_snapshot and not observed_snapshot[0].exists()
    assert "candidate_changed_during_scan" in rules(report, Severity.BLOCKER)


def test_source_intake_rejects_a_writable_transport_mount(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "data.txt").write_text("data\n", encoding="utf-8")
    scanner = ZeroTrustScanner(
        ScanPolicy(
            strict_external=False,
            run_external_scanners=False,
            require_secure_source_mount=True,
        )
    )
    report = scanner.scan(source, Stage.SOURCE)

    assert "source_mount_insecure" in rules(report, Severity.BLOCKER)
    pipeline = ZeroTrustPipeline(tmp_path / "pipeline", scanner)
    with pytest.raises(UnsafeInputError, match="ro,noexec,nodev,nosuid"):
        pipeline.ingest(source, "unsafe-mount")


def test_clamscan_argv_is_bound_to_the_single_configured_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    payload = candidate / "plain.txt"
    payload.write_text("plain\n", encoding="utf-8")
    database = tmp_path / "verified-clam-db"
    database.mkdir()
    (database / "main.hdb").write_text("deadbeef:1:Example\n", encoding="ascii")
    scanner = ZeroTrustScanner(
        ScanPolicy(
            strict_external=False,
            run_external_scanners=True,
            external_isolation_backend="none",
            allow_unisolated_external_in_relaxed_mode=True,
            clam_signature_paths=(database,),
            require_secure_source_mount=False,
        )
    )
    tools = {"clamscan": ToolEvidence("clamscan", "/usr/bin/clamscan", "test", "a" * 64, None, True, False)}
    trust_root = tmp_path / "trust"
    trust_root.mkdir(mode=0o700)
    clam_tool_snapshot = trust_root / "clamscan"
    clam_tool_snapshot.write_bytes(b"private clamscan")
    clam_tool_snapshot.chmod(0o500)
    database_snapshot = trust_root / "clam-database"
    database_digest, is_directory, _total = scanner_module._snapshot_path_or_tree(  # noqa: SLF001
        database,
        database_snapshot,
        max_files=100,
        max_file_bytes=1024 * 1024,
        max_total_bytes=1024 * 1024,
    )
    trust = scanner_module._ScannerTrustSnapshots(  # noqa: SLF001
        tools={"clamscan": clam_tool_snapshot},
        yara_rules=(),
        clam_signatures=(
            scanner_module._MaterialSnapshot(  # noqa: SLF001
                str(database),
                str(database),
                database_snapshot,
                database_digest,
                None,
                False,
                is_directory,
                None,
            ),
        ),
    )
    invocations: list[tuple[str, list[str]]] = []

    def record_invocation(name: str, args: object, rel: str, root: Path) -> ExternalScanResult:
        invocation = list(args)  # type: ignore[arg-type]
        invocations.append((name, invocation))
        return ExternalScanResult(name, rel, 0, "completed", "")

    monkeypatch.setattr(scanner, "_invoke_tool", record_invocation)
    findings: list[object] = []
    scanner._run_external_scanners(  # noqa: SLF001 - security contract test
        candidate,
        [(payload, "plain.txt")],
        tools,
        findings,  # type: ignore[arg-type]
        {"plain.txt": "text"},
        trust,
    )

    clam_args = next(args for name, args in invocations if name == "clamscan")
    database_args = [arg for arg in clam_args if arg.startswith("--database=")]
    assert database_args == [f"--database={database_snapshot}"]
    assert str(candidate) in clam_args


def test_scanner_tools_and_materials_use_private_snapshots_across_a_b_a_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "plain.txt").write_text("plain text\n", encoding="utf-8")
    source_tool_root = tmp_path / "source-tools"
    source_tool_root.mkdir()
    tool_sources = {name: source_tool_root / name for name in ("file", "clamscan", "yara", "bwrap")}
    tool_bytes = {name: f"trusted {name} executable".encode() for name in tool_sources}
    for name, source in tool_sources.items():
        source.write_bytes(tool_bytes[name])
        source.chmod(0o755)

    yara_rules = tmp_path / "trusted.yar"
    yara_bytes = b"rule harmless { condition: false }\n"
    yara_rules.write_bytes(yara_bytes)
    clam_database = tmp_path / "clam-db"
    clam_database.mkdir()
    clam_entry = clam_database / "main.hdb"
    clam_bytes = b"deadbeef:1:Example\n"
    clam_entry.write_bytes(clam_bytes)
    clam_digest = scanner_module._hash_path_or_tree(clam_database)  # noqa: SLF001

    tool_hashes = {name: hashlib.sha256(contents).hexdigest() for name, contents in tool_bytes.items()}
    policy = ScanPolicy(
        strict_external=True,
        run_external_scanners=True,
        require_secure_source_mount=False,
        trusted_tool_hashes=tool_hashes,
        yara_rule_paths=(yara_rules,),
        trusted_yara_rule_hashes={str(yara_rules): hashlib.sha256(yara_bytes).hexdigest()},
        clam_signature_paths=(clam_database,),
        trusted_clam_signature_hashes={str(clam_database): clam_digest},
        max_archive_expanded_bytes=8 * 1024 * 1024,
        max_archive_member_bytes=4 * 1024 * 1024,
    )
    scanner = ZeroTrustScanner(policy)
    monkeypatch.setattr(
        scanner_module.shutil,
        "which",
        lambda name: str(tool_sources[name]) if name in tool_sources else None,
    )
    observed_private_paths: set[Path] = set()
    invocations: list[list[str]] = []
    raced = False

    def successful_private_invocation(name: str, args: object, rel: str, root: Path) -> ExternalScanResult:
        nonlocal raced
        invocation = list(args)  # type: ignore[arg-type]
        invocations.append(invocation)
        for source in (*tool_sources.values(), yara_rules, clam_database, clam_entry):
            assert str(source) not in invocation
        if name == "isolation-probe":
            bindings = {
                invocation[index + 2]: Path(invocation[index + 1])
                for index, value in enumerate(invocation[:-2])
                if value == "--ro-bind"
            }
            for tool_name, expected in tool_bytes.items():
                snapshot = bindings[f"/analysis/tools/{tool_name}"]
                observed_private_paths.add(snapshot)
                assert snapshot.read_bytes() == expected
                assert stat.S_IMODE(snapshot.stat().st_mode) == 0o500
                assert stat.S_IMODE(snapshot.parent.stat().st_mode) == 0o700
            rule_snapshot = bindings["/analysis/yara-0"]
            database_snapshot = bindings["/analysis/clam-db"]
            observed_private_paths.update((rule_snapshot, database_snapshot))
            assert rule_snapshot.read_bytes() == yara_bytes
            assert stat.S_IMODE(rule_snapshot.stat().st_mode) == 0o400
            assert (database_snapshot / "main.hdb").read_bytes() == clam_bytes
            assert stat.S_IMODE(database_snapshot.stat().st_mode) == 0o700
            assert stat.S_IMODE((database_snapshot / "main.hdb").stat().st_mode) == 0o400
            if not raced:
                raced = True
                for tool_name, source in tool_sources.items():
                    source.write_bytes(f"attacker {tool_name}".encode())
                    source.write_bytes(tool_bytes[tool_name])
                    source.chmod(0o755)
                yara_rules.write_bytes(b"rule attacker { condition: true }\n")
                yara_rules.write_bytes(yara_bytes)
                clam_entry.write_bytes(b"attacker database\n")
                clam_entry.write_bytes(clam_bytes)
                for tool_name, expected in tool_bytes.items():
                    assert bindings[f"/analysis/tools/{tool_name}"].read_bytes() == expected
                assert rule_snapshot.read_bytes() == yara_bytes
                assert (database_snapshot / "main.hdb").read_bytes() == clam_bytes
            return ExternalScanResult(name, rel, 0, "completed", "bwrap 1")
        if name.endswith("-version"):
            return ExternalScanResult(name, rel, 0, "completed", f"{name} 1")
        if name == "file":
            return ExternalScanResult(name, rel, 0, "completed", "text/plain")
        return ExternalScanResult(name, rel, 0, "completed", "")

    monkeypatch.setattr(scanner, "_invoke_tool", successful_private_invocation)
    report = scanner.scan(candidate)

    assert raced
    assert invocations
    assert "external_trust_snapshot_incomplete" not in rules(report, Severity.BLOCKER)
    assert observed_private_paths
    assert all(not path.exists() for path in observed_private_paths)


def test_clam_directory_capture_detects_in_place_a_b_a_race(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database = tmp_path / "clam-db"
    database.mkdir()
    entry = database / "main.hdb"
    original = b"trusted database bytes\n"
    entry.write_bytes(original)
    inode = entry.stat().st_ino
    original_read = scanner_module.os.read
    raced = False

    def read_then_race(fd: int, size: int) -> bytes:
        nonlocal raced
        chunk = original_read(fd, size)
        if not raced and chunk and os.fstat(fd).st_ino == inode:
            raced = True
            entry.write_bytes(b"attacker database bytes\n")
            entry.write_bytes(original)
        return chunk

    monkeypatch.setattr(scanner_module.os, "read", read_then_race)
    destination = tmp_path / "private-database"
    with pytest.raises(IntegrityError, match="changed during capture"):
        scanner_module._snapshot_path_or_tree(  # noqa: SLF001
            database,
            destination,
            max_files=100,
            max_file_bytes=1024 * 1024,
            max_total_bytes=1024 * 1024,
        )

    assert raced
    assert not destination.exists()


def test_bounded_zstd_executes_only_private_tool_snapshots_during_a_b_a_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_tool_root = tmp_path / "source-tools"
    source_tool_root.mkdir()
    tool_sources = {name: source_tool_root / name for name in ("zstd", "bwrap")}
    tool_bytes = {name: f"trusted {name} executable".encode() for name in tool_sources}
    for name, source in tool_sources.items():
        source.write_bytes(tool_bytes[name])
        source.chmod(0o755)
    scanner = ZeroTrustScanner(
        ScanPolicy(
            strict_external=False,
            run_external_scanners=False,
            require_secure_source_mount=False,
            trusted_tool_hashes={name: hashlib.sha256(contents).hexdigest() for name, contents in tool_bytes.items()},
        )
    )
    monkeypatch.setattr(
        scanner_module.shutil,
        "which",
        lambda name: str(tool_sources[name]) if name in tool_sources else None,
    )
    observed_snapshots: set[Path] = set()

    class StopAfterInspection(RuntimeError):
        pass

    def inspect_popen(command: list[str], **kwargs: object) -> object:
        assert callable(kwargs.get("preexec_fn"))
        assert kwargs["env"] == {
            "PATH": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        for source in tool_sources.values():
            assert str(source) not in command
        assert command[-7] == "/analysis/tools/zstd"
        bindings = {
            command[index + 2]: Path(command[index + 1])
            for index, value in enumerate(command[:-2])
            if value == "--ro-bind"
        }
        for name, expected in tool_bytes.items():
            snapshot = bindings[f"/analysis/tools/{name}"]
            observed_snapshots.add(snapshot)
            assert snapshot.read_bytes() == expected
            assert stat.S_IMODE(snapshot.stat().st_mode) == 0o500
            tool_sources[name].write_bytes(f"attacker {name}".encode())
            tool_sources[name].write_bytes(expected)
            tool_sources[name].chmod(0o755)
            assert snapshot.read_bytes() == expected
        input_snapshot = bindings["/analysis/input.zst"]
        observed_snapshots.add(input_snapshot)
        assert stat.S_IMODE(input_snapshot.stat().st_mode) == 0o400
        raise StopAfterInspection

    monkeypatch.setattr(scanner_module.subprocess, "Popen", inspect_popen)
    with pytest.raises(StopAfterInspection):
        scanner._bounded_zstd_decompress(b"not executed", 1024)  # noqa: SLF001

    assert observed_snapshots
    assert all(not path.exists() for path in observed_snapshots)


def test_strict_clamav_rejects_ambiguous_multiple_database_paths(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "plain.txt").write_text("plain\n", encoding="utf-8")
    first = tmp_path / "db-one"
    second = tmp_path / "db-two"
    first.mkdir()
    second.mkdir()
    scanner = ZeroTrustScanner(
        ScanPolicy(
            run_external_scanners=False,
            clam_signature_paths=(first, second),
            require_secure_source_mount=False,
        )
    )

    report = scanner.scan(candidate)

    assert "clam_signature_configuration_ambiguous" in rules(report, Severity.BLOCKER)


def test_special_fifo_is_fail_closed(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO creation is unavailable")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    os.mkfifo(candidate / "channel")

    report = relaxed_scanner().scan(candidate)

    assert "special_file" in rules(report, Severity.BLOCKER)


@pytest.mark.parametrize(
    ("relative", "content", "severity", "category"),
    (
        (".bashrc", "export PATH=/opt/bin\n", Severity.BLOCKER, "shell-startup"),
        (".config/fish/config.fish", "set -gx PATH /opt/bin $PATH\n", Severity.BLOCKER, "shell-startup"),
        ("units/backup.service", "[Unit]\nDescription=review\n", Severity.REVIEW, "systemd"),
        ("units/backup.service", "[Service]\nExecStart=/bin/true\n", Severity.BLOCKER, "systemd"),
        ("units/backup.timer", "[Timer]\nOnCalendar=daily\n", Severity.BLOCKER, "systemd"),
        ("etc/cron.d/job", "* * * * * user /bin/true\n", Severity.BLOCKER, "cron"),
        (".config/autostart/demo.desktop", "[Desktop Entry]\nExec=/bin/true\n", Severity.BLOCKER, "desktop"),
        (".ssh/config", "Host example\n  User offline\n", Severity.REVIEW, "ssh-client"),
        (".ssh/config", "Host *\n  ProxyCommand sh -c payload\n", Severity.BLOCKER, "ssh-client"),
        (".ssh/config", 'Match exec "payload"\n', Severity.BLOCKER, "ssh-client"),
        (".ssh/config", "Host *\n  LocalCommand payload\n", Severity.BLOCKER, "ssh-client"),
        (".ssh/config", "Host *\n  KnownHostsCommand payload\n", Severity.BLOCKER, "ssh-client"),
        (".envrc", "export SAFE=value\n", Severity.BLOCKER, "direnv"),
        ("Makefile", "VALUE = inert\n", Severity.REVIEW, "make"),
        ("Makefile", "all:\n\t/bin/true\n", Severity.BLOCKER, "make"),
        ("default.nix", "{ value = 1; }\n", Severity.REVIEW, "nix"),
        ("default.nix", 'runCommand "payload" {} "true"\n', Severity.BLOCKER, "nix"),
        (".github/workflows/ci.yml", "steps:\n  - run: /bin/true\n", Severity.BLOCKER, "ci"),
        (".vscode/tasks.json", '{"command":"payload"}\n', Severity.BLOCKER, "editor-task"),
        ("etc/udev/rules.d/99-test.rules", 'ACTION=="add", RUN+="/bin/true"\n', Severity.BLOCKER, "udev"),
        ("etc/NetworkManager/dispatcher.d/10-test", "#!/bin/sh\ntrue\n", Severity.BLOCKER, "network-dispatcher"),
    ),
)
def test_path_activated_configuration_never_passes_silently(
    tmp_path: Path,
    relative: str,
    content: str,
    severity: Severity,
    category: str,
) -> None:
    candidate = tmp_path / "candidate"
    path = candidate / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

    report = relaxed_scanner().scan(candidate)
    expected_rule = "active_config_execution" if severity is Severity.BLOCKER else "active_config_review"
    matching = [
        finding
        for finding in report.findings
        if finding.path == relative and finding.rule == expected_rule and finding.severity is severity
    ]

    assert matching
    assert any(finding.evidence.get("category") == category for finding in matching)


def test_group_or_world_writable_files_and_directories_are_blocked(tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    writable_directory = candidate / "shared"
    writable_directory.mkdir(parents=True)
    writable_file = candidate / "shared.txt"
    writable_file.write_text("data\n", encoding="utf-8")
    writable_directory.chmod(0o777)
    writable_file.chmod(0o664)

    report = relaxed_scanner().scan(candidate)
    blocked_paths = {
        finding.path
        for finding in report.findings
        if finding.rule == "group_or_world_writable" and finding.severity is Severity.BLOCKER
    }

    assert {"shared", "shared.txt"} <= blocked_paths


def test_repository_local_git_config_unknown_keys_are_blocked_by_scanner(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    config = candidate / ".git" / "config"
    config.parent.mkdir(parents=True)
    config.write_text("[gui]\n\twmState = normal\n", encoding="utf-8")

    report = relaxed_scanner().scan(candidate)
    finding = next(row for row in report.findings if row.path == ".git/config" and row.rule == "git_active_config")

    entries = finding.evidence["entries"]
    assert isinstance(entries, list)
    assert entries[0]["reason"] == "repository-key-not-allowlisted"


def test_inert_and_sanitized_copies_normalize_to_private_modes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    nested = source / "nested"
    nested.mkdir(parents=True)
    payload = nested / "payload.txt"
    payload.write_text("content\n", encoding="utf-8")
    source.chmod(0o777)
    nested.chmod(0o733)
    payload.chmod(0o666)

    inert = tmp_path / "sanitized"
    scanner_module._safe_copy_atomic(source, inert, inert=True)  # noqa: SLF001

    assert stat.S_IMODE(inert.stat().st_mode) == 0o700
    assert stat.S_IMODE((inert / "nested").stat().st_mode) == 0o700
    assert stat.S_IMODE((inert / "nested" / "payload.txt").stat().st_mode) == 0o600

    restored = tmp_path / "restored"
    scanner_module._safe_copy_atomic(inert, restored, inert=False)  # noqa: SLF001
    assert stat.S_IMODE(restored.stat().st_mode) & 0o022 == 0
    assert stat.S_IMODE((restored / "nested").stat().st_mode) & 0o022 == 0
    assert stat.S_IMODE((restored / "nested" / "payload.txt").stat().st_mode) & 0o022 == 0
