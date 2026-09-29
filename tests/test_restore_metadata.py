from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

import pytest

import umzug.restore_metadata as restore_metadata
from umzug.restore_metadata import _identity_plan, apply_safe_restore_metadata
from umzug.util import UmzugError, canonical_json, sha256_file


def _workspace(tmp_path: Path, *, with_symlink: bool = False) -> tuple[Path, Path, str]:
    candidate = "item-0000"
    workspace = tmp_path / "workspace"
    verified = workspace / "state" / "bundle" / "verified-container" / "umzug"
    verified.mkdir(parents=True)
    (workspace / "RESTORED").mkdir()
    destination = tmp_path / "restored"
    destination.mkdir(mode=0o700)
    data = destination / "tool.sh"
    data.write_bytes(b"#!/bin/sh\necho inert\n")
    data.chmod(0o700)
    timestamp = 1_700_000_000_123_456_789
    archive_root = f"SOURCE/{candidate}/project"
    entries: list[dict[str, object]] = [
        {
            "path": archive_root,
            "source_selection": candidate,
            "type": "directory",
            "mode": 0o2750,
            "uid": 4242,
            "gid": 4343,
            "mtime_ns": timestamp,
            "size": 0,
            "xattrs": {},
            "xattr_errors": [],
        },
        {
            "path": f"{archive_root}/tool.sh",
            "source_selection": candidate,
            "type": "file",
            "mode": 0o6755,
            "uid": 4242,
            "gid": 4343,
            "mtime_ns": timestamp + 1,
            "size": data.stat().st_size,
            "sha256": sha256_file(data),
            "xattrs": {"security.capability": "untrusted-signed-evidence-only"},
            "xattr_errors": [],
        },
    ]
    if with_symlink:
        link = destination / "link"
        link.symlink_to("tool.sh")
        entries.append(
            {
                "path": f"{archive_root}/link",
                "source_selection": candidate,
                "type": "symlink",
                "mode": 0o777,
                "uid": 4242,
                "gid": 4343,
                "mtime_ns": timestamp + 2,
                "size": 0,
                "link_target": "tool.sh",
                "xattrs": {},
                "xattr_errors": [],
            }
        )
    manifest = {
        "format_version": 1,
        "trust_statement": "UNTRUSTED_SOURCE_DATA_REQUIRES_ANALYSIS_AND_EXPLICIT_APPROVAL",
        "payload": {"name": "SOURCE.tar", "sha256": "a" * 64, "size": 123},
        "selections": [
            {
                "id": candidate,
                "category": "project",
                "original_path": "/untrusted/project",
                "archive_root": archive_root,
            }
        ],
        "entries": entries,
        "inventory": {
            "users": [{"name": "alice", "uid": 4242, "gid": 4343}],
            "groups": [{"name": "developers", "gid": 4343}],
        },
        "warnings": [],
    }
    manifest_path = verified / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    ingest = {
        "format": 1,
        "manifest_sha256": sha256_file(manifest_path),
        "source_payload_sha256": "a" * 64,
        "candidates": [{"id": candidate}],
        "extraction_errors": [],
        "manifest_warnings": [],
        "xattr_failures": [],
    }
    (workspace / "state" / "ingest.json").write_bytes(canonical_json(ingest))
    return workspace, destination, candidate


def _apply(workspace: Path, destination: Path, candidate: str, **kwargs: object) -> dict[str, object]:
    return apply_safe_restore_metadata(
        workspace=workspace,
        candidate=candidate,
        destination=destination,
        approval_manifest_sha256="b" * 64,
        approval_sha256="c" * 64,
        require_root=False,
        **kwargs,
    )


def test_safe_restore_metadata_maps_names_but_never_reactivates_privilege(tmp_path: Path) -> None:
    workspace, destination, candidate = _workspace(tmp_path)
    target_uid, target_gid = os.getuid(), os.getgid()
    data = destination / "tool.sh"
    try:
        os.setxattr(data, "user.umzug-test", b"must disappear")
    except (AttributeError, OSError):
        pass

    report = _apply(
        workspace,
        destination,
        candidate,
        target_users=[
            {"name": "alice", "uid": target_uid},
            {"name": "unrelated", "uid": 4242},
        ],
        target_groups=[
            {"name": "developers", "gid": target_gid},
            {"name": "unrelated", "gid": 4343},
        ],
    )

    assert stat.S_IMODE(data.lstat().st_mode) == 0o644
    assert stat.S_IMODE(destination.lstat().st_mode) == 0o750
    assert data.lstat().st_uid == target_uid
    assert data.lstat().st_gid == target_gid
    assert data.lstat().st_mtime_ns == 1_700_000_000_123_456_790
    assert not os.listxattr(data)
    uid = report["identity_mapping"]["uids"]["4242"]  # type: ignore[index]
    assert uid["status"] == "mapped_by_identical_name"
    assert uid["numeric_conflict_avoided"] is True
    receipt = workspace / "RESTORED" / f"{candidate}.metadata.json"
    stored = json.loads(receipt.read_text(encoding="utf-8"))
    supplied = stored.pop("receipt_sha256")
    assert supplied == hashlib.sha256(canonical_json(stored)).hexdigest()


def test_numeric_collision_without_same_name_is_reported_and_never_replayed(tmp_path: Path) -> None:
    workspace, destination, candidate = _workspace(tmp_path)
    before = (destination / "tool.sh").lstat()

    report = _apply(
        workspace,
        destination,
        candidate,
        target_users=[{"name": "mallory", "uid": 4242}],
        target_groups=[{"name": "mallory", "gid": 4343}],
    )

    after = (destination / "tool.sh").lstat()
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert report["identity_mapping"]["uids"]["4242"]["status"] == "blocked_numeric_conflict"  # type: ignore[index]
    assert report["identity_mapping"]["gids"]["4343"]["status"] == "blocked_numeric_conflict"  # type: ignore[index]


def test_changed_verified_manifest_fails_before_metadata_change(tmp_path: Path) -> None:
    workspace, destination, candidate = _workspace(tmp_path)
    before_mode = stat.S_IMODE((destination / "tool.sh").stat().st_mode)
    manifest = workspace / "state" / "bundle" / "verified-container" / "umzug" / "manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b" ")

    with pytest.raises(UmzugError, match="ingest-state SHA-256"):
        _apply(
            workspace,
            destination,
            candidate,
            target_users=[],
            target_groups=[],
        )

    assert stat.S_IMODE((destination / "tool.sh").stat().st_mode) == before_mode
    assert not (workspace / "RESTORED" / f"{candidate}.metadata.json").exists()


def test_symlink_is_verified_and_never_followed_for_mode_changes(tmp_path: Path) -> None:
    workspace, destination, candidate = _workspace(tmp_path, with_symlink=True)
    link = destination / "link"
    assert link.is_symlink()

    report = _apply(
        workspace,
        destination,
        candidate,
        target_users=[{"name": "alice", "uid": os.getuid()}],
        target_groups=[{"name": "developers", "gid": os.getgid()}],
    )

    assert link.is_symlink()
    assert os.readlink(link) == "tool.sh"
    assert stat.S_IMODE((destination / "tool.sh").stat().st_mode) == 0o644
    link_row = next(row for row in report["entries"] if row["path"] == "link")  # type: ignore[union-attr]
    assert link_row["safe_mode"] is None


def test_receipt_is_never_overwritten(tmp_path: Path) -> None:
    workspace, destination, candidate = _workspace(tmp_path)
    arguments = {
        "target_users": [{"name": "alice", "uid": os.getuid()}],
        "target_groups": [{"name": "developers", "gid": os.getgid()}],
    }
    _apply(workspace, destination, candidate, **arguments)

    with pytest.raises(UmzugError, match="receipt already exists"):
        _apply(workspace, destination, candidate, **arguments)


def test_same_source_name_on_multiple_ids_is_ambiguous() -> None:
    mapping, decisions = _identity_plan(
        [
            {"name": "alice", "uid": 1000},
            {"name": "alice", "uid": 2000},
        ],
        [{"name": "alice", "uid": 3000}],
        id_key="uid",
        kind="user",
    )

    assert mapping == {}
    assert decisions["1000"] == {
        "status": "blocked_ambiguous_source_name",
        "source_name": "alice",
        "source_ids": [1000, 2000],
    }
    assert decisions["2000"]["status"] == "blocked_ambiguous_source_name"


def test_post_apply_verification_rejects_inexact_safe_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, destination, candidate = _workspace(tmp_path)
    real_fchmod = restore_metadata.os.fchmod

    def incomplete_fchmod(fd: int, mode: int) -> None:
        adjusted = mode & ~stat.S_IWUSR if stat.S_ISREG(os.fstat(fd).st_mode) else mode
        real_fchmod(fd, adjusted)

    monkeypatch.setattr(restore_metadata.os, "fchmod", incomplete_fchmod)
    with pytest.raises(UmzugError, match="safe mode verification failed"):
        _apply(workspace, destination, candidate, target_users=[], target_groups=[])


def test_post_apply_verification_rejects_unapplied_ownership(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, destination, candidate = _workspace(tmp_path)
    monkeypatch.setattr(restore_metadata.os, "fchown", lambda _fd, _uid, _gid: None)

    with pytest.raises(UmzugError, match="ownership verification failed"):
        _apply(
            workspace,
            destination,
            candidate,
            target_users=[{"name": "alice", "uid": os.getuid() + 10000}],
            target_groups=[{"name": "developers", "gid": os.getgid() + 10000}],
        )


def test_post_apply_verification_rejects_inexact_mtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace, destination, candidate = _workspace(tmp_path)
    real_utime = restore_metadata.os.utime

    def shifted_utime(path: object, *args: object, **kwargs: object) -> None:
        ns = kwargs.get("ns")
        if isinstance(ns, tuple):
            kwargs["ns"] = (ns[0], ns[1] + 1)
        real_utime(path, *args, **kwargs)

    monkeypatch.setattr(restore_metadata.os, "utime", shifted_utime)
    with pytest.raises(UmzugError, match="mtime verification failed"):
        _apply(workspace, destination, candidate, target_users=[], target_groups=[])
