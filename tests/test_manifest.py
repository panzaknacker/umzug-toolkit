from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
from typing import Any

import pytest
import umzug.manifest as manifest_module

from umzug.manifest import (
    BUNDLE_MEMBERS,
    MAX_SOURCE_TAR_BYTES,
    Selection,
    assemble_bundle,
    build_source_tar,
    create_manifest,
    decrypt_bundle,
    load_and_verify_manifest,
    public_key_fingerprint,
    public_key_for,
    safe_extract_bundle,
    safe_extract_source,
    sign_manifest,
    validate_manifest_structure,
    verify_manifest,
    verify_source_tar_manifest,
)
from umzug.transport import reassemble, split_file
from umzug.util import UmzugError, atomic_write, canonical_json, run, sha256_file


def _add_regular(archive: tarfile.TarFile, name: str, data: bytes = b"data") -> None:
    member = tarfile.TarInfo(name)
    member.mode = 0o600
    member.uid = 123
    member.gid = 456
    member.size = len(data)
    archive.addfile(member, io.BytesIO(data))


def _supply_openssl_test_passphrase(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    """keep an encrypted test key non-interactive without exposing its passphrase."""
    passphrase_file = directory / "openssl-test-passphrase"
    descriptor = os.open(
        passphrase_file,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, os.urandom(32).hex().encode("ascii") + b"\n")
    finally:
        os.close(descriptor)
    original_run = manifest_module.run

    def run_with_passphrase(argv: list[str], **kwargs: Any) -> Any:
        command = list(argv)
        needs_passphrase = False
        if command[:2] == ["openssl", "genpkey"]:
            command.extend(("-pass", f"file:{passphrase_file}"))
            needs_passphrase = True
        elif command[:2] == ["openssl", "pkey"] and "-pubin" not in command:
            command.extend(("-passin", f"file:{passphrase_file}"))
            needs_passphrase = True
        elif command[:2] == ["openssl", "pkeyutl"] and "-sign" in command:
            command.extend(("-passin", f"file:{passphrase_file}"))
            needs_passphrase = True
        if needs_passphrase:
            assert "input_bytes" not in kwargs
        return original_run(command, **kwargs)

    monkeypatch.setattr(manifest_module, "run", run_with_passphrase)


def _minimal_bundle(path: Path) -> None:
    with tarfile.open(path, "w") as archive:
        for name in sorted(BUNDLE_MEMBERS):
            _add_regular(archive, name, name.encode("utf-8"))


def _source_fixture(tmp_path: Path) -> tuple[Path, dict[str, object], Path]:
    source = tmp_path / "project"
    source.mkdir(mode=0o750)
    payload = source / "a-data.txt"
    payload.write_bytes(b"offline payload\n")
    payload.chmod(0o640)
    timestamp_ns = 1_700_000_000_123_456_789
    os.utime(payload, ns=(timestamp_ns, timestamp_ns))
    os.link(payload, source / "b-hardlink.txt")
    (source / "c-symlink").symlink_to("a-data.txt")

    source_tar = tmp_path / "SOURCE.tar"
    entries, selections, warnings = build_source_tar(
        source_tar,
        [Selection(source, "project")],
        (),
    )
    manifest = create_manifest(source_tar, entries, selections, (), warnings)
    return source_tar, manifest, payload


def _valid_structure_manifest() -> dict[str, Any]:
    return {
        "format_version": 1,
        "trust_statement": "UNTRUSTED_SOURCE_DATA_REQUIRES_ANALYSIS_AND_EXPLICIT_APPROVAL",
        "payload": {
            "name": "SOURCE.tar",
            "sha256": "0" * 64,
            "size": tarfile.RECORDSIZE,
        },
        "selections": [
            {
                "id": "item-0000",
                "category": "project",
                "original_path": "/source/alpha",
                "archive_root": "SOURCE/item-0000/alpha",
            },
            {
                "id": "item-0001",
                "category": "dotfiles",
                "original_path": "/source/beta",
                "archive_root": "SOURCE/item-0001/beta",
            },
        ],
        "entries": [
            {
                "path": "SOURCE/item-0000/alpha",
                "source_selection": "item-0000",
            },
            {
                "path": "SOURCE/item-0001/beta",
                "source_selection": "item-0001",
            },
        ],
    }


def _fake_extracted_manifest(tmp_path: Path, value: dict[str, Any]) -> dict[str, Path]:
    extracted: dict[str, Path] = {}
    for name in BUNDLE_MEMBERS:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"placeholder")
        extracted[name] = path
    extracted["umzug/manifest.json"].write_bytes(canonical_json(value))
    return extracted


def test_manifest_structure_accepts_unambiguous_selection_bindings() -> None:
    validate_manifest_structure(_valid_structure_manifest())


def test_manifest_structure_rejects_duplicate_selection_ids() -> None:
    value = _valid_structure_manifest()
    value["selections"][1]["id"] = "item-0000"

    with pytest.raises(UmzugError, match="duplicate manifest selection ID"):
        validate_manifest_structure(value)


def test_manifest_structure_rejects_duplicate_archive_roots() -> None:
    value = _valid_structure_manifest()
    value["selections"][1]["archive_root"] = "SOURCE/item-0000/alpha"

    with pytest.raises(UmzugError, match="duplicate manifest selection archive root"):
        validate_manifest_structure(value)


def test_manifest_structure_rejects_overlapping_archive_roots() -> None:
    value = _valid_structure_manifest()
    value["selections"][1]["archive_root"] = "SOURCE/item-0000/alpha/nested"

    with pytest.raises(UmzugError, match="archive roots overlap"):
        validate_manifest_structure(value)


def test_manifest_structure_rejects_unknown_source_selection() -> None:
    value = _valid_structure_manifest()
    value["entries"][0]["source_selection"] = "item-9999"

    with pytest.raises(UmzugError, match="unknown source selection"):
        validate_manifest_structure(value)


def test_manifest_structure_rejects_wrongly_bound_source_selection() -> None:
    value = _valid_structure_manifest()
    value["entries"][0]["source_selection"] = "item-0001"

    with pytest.raises(UmzugError, match="misstates its source selection"):
        validate_manifest_structure(value)


def test_manifest_structure_rejects_source_tar_above_hard_limit() -> None:
    value = _valid_structure_manifest()
    value["payload"]["size"] = MAX_SOURCE_TAR_BYTES + 1

    with pytest.raises(UmzugError, match="exceeds its limit"):
        validate_manifest_structure(value)


def test_manifest_loading_validates_structure_before_reading_source_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = _valid_structure_manifest()
    value["selections"][1]["id"] = "item-0000"
    extracted = _fake_extracted_manifest(tmp_path, value)
    monkeypatch.setattr(manifest_module, "public_key_fingerprint", lambda _path: "a" * 64)
    monkeypatch.setattr(manifest_module, "verify_manifest", lambda *_args: None)

    def payload_must_not_be_hashed(_path: Path) -> str:
        raise AssertionError("SOURCE payload was processed before structure validation")

    monkeypatch.setattr(manifest_module, "sha256_file", payload_must_not_be_hashed)
    with pytest.raises(UmzugError, match="duplicate manifest selection ID"):
        load_and_verify_manifest(
            extracted,
            trusted_public_key=extracted["umzug/signing-public.pem"],
            expected_fingerprint=None,
        )


def test_source_tar_never_archives_a_hardlink_alias_of_private_signing_key(tmp_path: Path) -> None:
    private_key = tmp_path / "signing.pem"
    private_key.write_bytes(b"private signing material")
    selected = tmp_path / "selected"
    selected.mkdir()
    os.link(private_key, selected / "innocent-name.txt")
    info = private_key.stat()

    with pytest.raises(UmzugError, match="aliases the signing private key"):
        build_source_tar(
            tmp_path / "SOURCE.tar",
            [Selection(selected, "project")],
            (),
            forbidden_regular_inodes={(info.st_dev, info.st_ino)},
        )


def test_source_identity_swap_before_open_is_not_archived(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    victim = tmp_path / "notes.txt"
    victim.write_bytes(b"benign preview")
    private_key = tmp_path / "private.pem"
    private_key.write_bytes(b"private signing material")
    private_info = private_key.stat()
    original_open = manifest_module.os.open
    swapped = False

    def swapping_open(path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        nonlocal swapped
        if path == victim.name and dir_fd is not None and not swapped:
            victim.unlink()
            os.link(private_key, victim)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(manifest_module.os, "open", swapping_open)
    source_tar = tmp_path / "SOURCE.tar"
    entries, _selections, warnings = build_source_tar(
        source_tar,
        [Selection(victim, "project")],
        (),
        forbidden_regular_inodes={(private_info.st_dev, private_info.st_ino)},
    )

    assert entries == []
    assert any("source identity changed" in warning for warning in warnings)
    with tarfile.open(source_tar, "r:") as archive:
        assert archive.getnames() == []


def test_directory_replaced_by_symlink_before_descent_is_never_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    selected = tmp_path / "selected"
    selected.mkdir()
    queued = selected / "queued"
    queued.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.txt").write_text("DO-NOT-CAPTURE", encoding="utf-8")
    original_open = manifest_module.os.open
    swapped = False

    def swapping_open(path: object, flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        nonlocal swapped
        if path == "queued" and dir_fd is not None and flags & os.O_DIRECTORY and not swapped:
            queued.rmdir()
            queued.symlink_to(outside, target_is_directory=True)
            swapped = True
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(manifest_module.os, "open", swapping_open)
    source_tar = tmp_path / "SOURCE.tar"
    _entries, _selections, warnings = build_source_tar(source_tar, [Selection(selected, "project")], ())

    assert warnings
    assert b"DO-NOT-CAPTURE" not in source_tar.read_bytes()


def test_secret_scan_is_bound_to_captured_bytes_not_the_earlier_live_preview(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("benign preview\n", encoding="utf-8")
    initial = manifest_module.preview_selections([Selection(source)], ())
    assert not initial["sensitive_candidates"]
    source.write_text("password=super-secret-value\n", encoding="utf-8")

    source_tar = tmp_path / "SOURCE.tar"
    entries, selections, warnings = build_source_tar(source_tar, [Selection(source)], ())
    assert not warnings
    captured = manifest_module.preview_captured_source(source_tar, entries, selections)

    assert captured["sensitive_candidates"]


def test_source_tar_manifest_records_bytes_and_filesystem_metadata(tmp_path: Path) -> None:
    source_tar, manifest, payload = _source_fixture(tmp_path)

    assert manifest["trust_statement"] == ("UNTRUSTED_SOURCE_DATA_REQUIRES_ANALYSIS_AND_EXPLICIT_APPROVAL")
    assert manifest["payload"] == {
        "name": "SOURCE.tar",
        "sha256": sha256_file(source_tar),
        "size": source_tar.stat().st_size,
    }
    assert manifest["selections"][0]["category"] == "project"

    rows = {row["path"]: row for row in manifest["entries"]}
    file_name = next(name for name in rows if name.endswith("/a-data.txt"))
    hardlink_name = next(name for name in rows if name.endswith("/b-hardlink.txt"))
    symlink_name = next(name for name in rows if name.endswith("/c-symlink"))
    file_row = rows[file_name]
    source_stat = payload.lstat()

    assert file_row["type"] == "file"
    assert file_row["mode"] == 0o640
    assert file_row["uid"] == source_stat.st_uid
    assert file_row["gid"] == source_stat.st_gid
    assert file_row["mtime_ns"] == source_stat.st_mtime_ns
    assert file_row["size"] == len(b"offline payload\n")
    assert file_row["sha256"] == hashlib.sha256(b"offline payload\n").hexdigest()
    assert isinstance(file_row["xattrs"], dict)
    assert isinstance(file_row["xattr_errors"], list)
    assert rows[hardlink_name]["type"] == "hardlink"
    assert rows[hardlink_name]["link_target"] == file_name
    assert rows[symlink_name]["type"] == "symlink"
    assert rows[symlink_name]["link_target"] == "a-data.txt"

    with tarfile.open(source_tar, "r:") as archive:
        member = archive.getmember(file_name)
        assert stat.S_IMODE(member.mode) == file_row["mode"]
        assert member.uid == file_row["uid"]
        assert member.gid == file_row["gid"]
        assert member.mtime == pytest.approx(file_row["mtime_ns"] / 1_000_000_000)
        archived = archive.extractfile(member)
        assert archived is not None
        assert archived.read() == b"offline payload\n"

    verify_source_tar_manifest(source_tar, manifest)


def test_manifest_source_date_epoch_is_canonical_and_fail_closed(tmp_path: Path) -> None:
    source_tar, baseline, _payload = _source_fixture(tmp_path)
    manifest = create_manifest(
        source_tar,
        baseline["entries"],
        baseline["selections"],
        (),
        [],
        source_date_epoch=1_767_225_600,
    )

    assert manifest["created_at"] == "2026-01-01T00:00:00Z"
    for invalid_epoch in (-1, True, 1.5, 10**100):
        with pytest.raises(UmzugError, match="SOURCE_DATE_EPOCH"):
            create_manifest(
                source_tar,
                baseline["entries"],
                baseline["selections"],
                (),
                [],
                source_date_epoch=invalid_epoch,  # type: ignore[arg-type]
            )

    verify_source_tar_manifest(source_tar, manifest)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("sha256", "0" * 64, "content mismatch"),
        ("mode", 0o777, "mode mismatch"),
        ("uid", 2**31 - 1, "ownership mismatch"),
        ("mtime_ns", 0, "timestamp mismatch"),
    ],
)
def test_source_manifest_detects_hash_and_metadata_tampering(
    tmp_path: Path,
    field: str,
    replacement: object,
    message: str,
) -> None:
    source_tar, manifest, _ = _source_fixture(tmp_path)
    tampered = copy.deepcopy(manifest)
    row = next(row for row in tampered["entries"] if row["type"] == "file")
    row[field] = replacement

    with pytest.raises(UmzugError, match=message):
        verify_source_tar_manifest(source_tar, tampered)


def test_source_verifier_rejects_appended_polyglot_bytes(tmp_path: Path) -> None:
    source_tar, manifest, _ = _source_fixture(tmp_path)
    with source_tar.open("ab") as handle:
        handle.write(b"MZ-appended-program")

    with pytest.raises(UmzugError, match="trailing|end-of-archive"):
        verify_source_tar_manifest(source_tar, manifest)


def test_safe_source_extraction_rejects_aligned_polyglot_before_writing(
    tmp_path: Path,
) -> None:
    source_tar, _manifest, _ = _source_fixture(tmp_path)
    with source_tar.open("ab") as handle:
        handle.write(b"MZ" + (b"\0" * (tarfile.BLOCKSIZE - 2)))
    destination = tmp_path / "must-not-be-created"

    with pytest.raises(UmzugError, match="trailing|polyglot|end-of-archive"):
        safe_extract_source(source_tar, destination)

    assert not destination.exists()


def test_safe_source_extraction_applies_limit_to_source_tar_itself(tmp_path: Path) -> None:
    source_tar, _manifest, _ = _source_fixture(tmp_path)
    destination = tmp_path / "must-not-be-created"

    with pytest.raises(UmzugError, match="exceeds its extraction limit"):
        safe_extract_source(
            source_tar,
            destination,
            max_total_bytes=source_tar.stat().st_size - 1,
        )

    assert not destination.exists()


@pytest.mark.parametrize("bad_kind", ["traversal", "symlink", "fifo", "duplicate"])
def test_safe_bundle_extraction_rejects_unexpected_special_and_duplicate_members(
    tmp_path: Path,
    bad_kind: str,
) -> None:
    bundle = tmp_path / f"{bad_kind}.tar"
    with tarfile.open(bundle, "w") as archive:
        if bad_kind == "traversal":
            _add_regular(archive, "../../escaped")
        elif bad_kind == "symlink":
            member = tarfile.TarInfo("umzug/SOURCE.tar")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../escaped"
            archive.addfile(member)
        elif bad_kind == "fifo":
            member = tarfile.TarInfo("umzug/SOURCE.tar")
            member.type = tarfile.FIFOTYPE
            archive.addfile(member)
        else:
            _add_regular(archive, "umzug/SOURCE.tar", b"first")
            _add_regular(archive, "umzug/SOURCE.tar", b"second")

    with pytest.raises(UmzugError):
        safe_extract_bundle(bundle, tmp_path / "extracted")
    assert not (tmp_path / "escaped").exists()


def test_safe_bundle_extraction_does_not_follow_preexisting_parent_symlink(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle.tar"
    _minimal_bundle(bundle)
    destination = tmp_path / "extract"
    destination.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (destination / "umzug").symlink_to(outside, target_is_directory=True)

    with pytest.raises(UmzugError):
        safe_extract_bundle(bundle, destination)

    assert list(outside.iterdir()) == []


def test_safe_bundle_extraction_rejects_bytes_after_tar_end(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle-polyglot.tar"
    _minimal_bundle(bundle)
    with bundle.open("ab") as handle:
        handle.write(b"#!/bin/sh\nmalicious trailing payload\n")

    with pytest.raises(UmzugError, match="trailing|end-of-archive"):
        safe_extract_bundle(bundle, tmp_path / "polyglot-extracted")


def test_safe_source_extraction_contains_traversal_and_rejects_special_members(
    tmp_path: Path,
) -> None:
    source_tar = tmp_path / "hostile.tar"
    with tarfile.open(source_tar, "w") as archive:
        _add_regular(archive, "SOURCE/item/safe.txt", b"safe")
        _add_regular(archive, "../../escaped", b"escape")
        fifo = tarfile.TarInfo("SOURCE/item/channel")
        fifo.type = tarfile.FIFOTYPE
        archive.addfile(fifo)

    destination = tmp_path / "SOURCE-stage"
    errors = safe_extract_source(source_tar, destination)

    assert any("unsafe relative path" in error for error in errors)
    assert any("special archive member rejected" in error for error in errors)
    assert (destination / "SOURCE/item/safe.txt").read_bytes() == b"safe"
    assert stat.S_IMODE((destination / "SOURCE/item/safe.txt").stat().st_mode) == 0o400
    assert not (tmp_path / "escaped").exists()
    assert not (destination / "SOURCE/item/channel").exists()


def test_safe_source_extraction_rejects_duplicate_regular_and_directory_members(
    tmp_path: Path,
) -> None:
    source_tar = tmp_path / "duplicates.tar"
    with tarfile.open(source_tar, "w") as archive:
        directory = tarfile.TarInfo("SOURCE/item")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        archive.addfile(directory)
        _add_regular(archive, "SOURCE/item/file", b"first")
        _add_regular(archive, "SOURCE/item/file", b"second")

    errors = safe_extract_source(source_tar, tmp_path / "extracted-source")

    assert {error for error in errors if error.startswith("duplicate SOURCE member:")} == {
        "duplicate SOURCE member: SOURCE/item",
        "duplicate SOURCE member: SOURCE/item/file",
    }


def test_safe_source_extraction_never_writes_through_archived_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    source_tar = tmp_path / "symlink-parent.tar"
    with tarfile.open(source_tar, "w") as archive:
        link = tarfile.TarInfo("SOURCE/link")
        link.type = tarfile.SYMTYPE
        link.linkname = str(outside)
        archive.addfile(link)
        _add_regular(archive, "SOURCE/link/implant", b"must not escape")

    errors = safe_extract_source(source_tar, tmp_path / "staged")

    assert any("parent escape" in error or "archive parent is not a real directory" in error for error in errors)
    assert not (outside / "implant").exists()


def test_source_verifier_rejects_duplicate_and_special_members(tmp_path: Path) -> None:
    source_tar = tmp_path / "invalid-source.tar"
    with tarfile.open(source_tar, "w") as archive:
        _add_regular(archive, "SOURCE/item/file", b"one")
        _add_regular(archive, "SOURCE/item/file", b"two")
        fifo = tarfile.TarInfo("SOURCE/item/fifo")
        fifo.type = tarfile.FIFOTYPE
        archive.addfile(fifo)
    manifest = {
        "entries": [
            {
                "path": "SOURCE/item/file",
                "type": "file",
                "mode": 0o600,
                "uid": 123,
                "gid": 456,
                "mtime_ns": 0,
                "size": 3,
                "sha256": hashlib.sha256(b"one").hexdigest(),
            },
            {
                "path": "SOURCE/item/fifo",
                "type": "special",
                "mode": 0,
                "uid": 0,
                "gid": 0,
                "mtime_ns": 0,
            },
        ]
    }

    with pytest.raises(UmzugError, match="duplicate SOURCE member"):
        verify_source_tar_manifest(source_tar, manifest)


def test_transport_split_reassemble_and_tamper_detection(tmp_path: Path) -> None:
    bundle = tmp_path / "migration.bundle"
    payload = (bytes(range(256)) * 8193) + b"tail"
    bundle.write_bytes(payload)

    index = split_file(bundle, 1024 * 1024)
    restored = tmp_path / "restored.bundle"
    reassemble(index, restored)
    assert restored.read_bytes() == payload

    index_value = json.loads(index.read_text(encoding="utf-8"))
    first_part = tmp_path / index_value["parts"][0]["name"]
    content = bytearray(first_part.read_bytes())
    content[0] ^= 0xFF
    first_part.write_bytes(content)
    failed_destination = tmp_path / "must-not-exist.bundle"
    with pytest.raises(UmzugError, match="integrity check failed"):
        reassemble(index, failed_destination)
    assert not failed_destination.exists()


def test_transport_split_never_overwrites_existing_part_or_index(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.bin"
    bundle.write_bytes(b"x" * (1024 * 1024 + 1))
    existing = tmp_path / "bundle.bin.part00001"
    existing.write_bytes(b"must survive")
    with pytest.raises(UmzugError, match="refusing to overwrite"):
        split_file(bundle, 1024 * 1024)
    assert existing.read_bytes() == b"must survive"

    existing.unlink()
    index = tmp_path / "bundle.bin.parts.json"
    index.write_text("must survive", encoding="utf-8")
    with pytest.raises(UmzugError, match="refusing to overwrite"):
        split_file(bundle, 1024 * 1024)
    assert index.read_text(encoding="utf-8") == "must survive"


def test_plain_decryption_copy_is_bounded_and_never_leaves_partial_output(tmp_path: Path) -> None:
    source = tmp_path / "plain.bundle"
    source.write_bytes(b"0123456789")
    destination = tmp_path / "copy.bundle"
    with pytest.raises(UmzugError, match="exceeds configured size"):
        decrypt_bundle(source, destination, "none", max_output_bytes=5)
    assert not destination.exists()

    decrypt_bundle(source, destination, "none", max_output_bytes=10)
    assert destination.read_bytes() == source.read_bytes()
    with pytest.raises(UmzugError, match="overwrite"):
        decrypt_bundle(source, destination, "none", max_output_bytes=10)


def test_reassembly_rejects_declared_source_larger_than_limit(tmp_path: Path) -> None:
    bundle = tmp_path / "bounded.bundle"
    bundle.write_bytes(b"x" * (1024 * 1024 + 1))
    index = split_file(bundle, 1024 * 1024)
    destination = tmp_path / "must-not-exist"
    with pytest.raises(UmzugError, match="reassembly limit"):
        reassemble(index, destination, max_bytes=1024)
    assert not destination.exists()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is not installed")
def test_generate_signing_key_keeps_openssl_fd_anchored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _supply_openssl_test_passphrase(monkeypatch, tmp_path)
    key_directory = tmp_path / "keys"
    key_directory.mkdir(mode=0o700)
    private_key = key_directory / "signing-private.pem"

    public_key = manifest_module.generate_signing_key(private_key)

    assert public_key == private_key.with_suffix(".pem.pub")
    assert private_key.is_file() and not private_key.is_symlink()
    assert public_key.is_file() and not public_key.is_symlink()
    assert stat.S_IMODE(private_key.stat().st_mode) == 0o600
    assert stat.S_IMODE(public_key.stat().st_mode) == 0o644
    with private_key.open("rb") as handle:
        assert handle.readline() == b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    assert len(public_key_fingerprint(public_key)) == 64


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is not installed")
def test_signed_bundle_roundtrip_and_payload_tamper_detection(tmp_path: Path) -> None:
    source_tar, manifest, _ = _source_fixture(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig"
    private_key = tmp_path / "signing-private.pem"
    public_key = tmp_path / "signing-public.pem"
    atomic_write(manifest_path, canonical_json(manifest), 0o600)
    run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)])
    private_key.chmod(0o600)
    public_key_for(private_key, public_key)
    sign_manifest(manifest_path, private_key, signature)
    verify_manifest(manifest_path, signature, public_key)

    bundle = tmp_path / "bundle.tar"
    assemble_bundle(bundle, manifest_path, signature, public_key, source_tar)
    extracted = safe_extract_bundle(bundle, tmp_path / "bundle-content")
    expected_fingerprint = public_key_fingerprint(public_key)
    loaded, actual_fingerprint = load_and_verify_manifest(
        extracted,
        trusted_public_key=public_key,
        expected_fingerprint=expected_fingerprint,
    )
    assert loaded == manifest
    assert actual_fingerprint == expected_fingerprint
    verify_source_tar_manifest(extracted["umzug/SOURCE.tar"], loaded)

    with extracted["umzug/SOURCE.tar"].open("ab") as handle:
        handle.write(b"tamper")
    with pytest.raises(UmzugError, match=r"SOURCE\.tar (?:size|checksum) mismatch"):
        load_and_verify_manifest(
            extracted,
            trusted_public_key=public_key,
            expected_fingerprint=expected_fingerprint,
        )


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is not installed")
def test_manifest_signature_detects_modified_manifest(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    manifest_path = tmp_path / "manifest.json"
    signature = tmp_path / "manifest.sig"
    run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)])
    private_key.chmod(0o600)
    public_key_for(private_key, public_key)
    atomic_write(manifest_path, b'{"value":"original"}\n', 0o600)
    sign_manifest(manifest_path, private_key, signature)

    atomic_write(manifest_path, b'{"value":"tampered"}\n', 0o600)
    with pytest.raises(UmzugError, match="command failed"):
        verify_manifest(manifest_path, signature, public_key)
