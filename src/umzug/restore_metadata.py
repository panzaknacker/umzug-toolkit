from __future__ import annotations

import grp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat
import time
from typing import Any, Iterable, Mapping

from .util import UmzugError, atomic_write, canonical_json, clean_relative, sha256_file


_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


def target_identities() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """read only public account databases; never consult shadow credentials."""

    users = [{"name": row.pw_name, "uid": row.pw_uid, "gid": row.pw_gid} for row in pwd.getpwall()]
    groups = [{"name": row.gr_name, "gid": row.gr_gid} for row in grp.getgrall()]
    return users, groups


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"{label} is missing or invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise UmzugError(f"{label} must be a JSON object")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise UmzugError(f"signed manifest has an invalid {label}")
    return value


def _candidate_manifest(
    workspace: Path,
    candidate: str,
    *,
    verified_manifest: Mapping[str, Any] | None = None,
    verified_manifest_sha256: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], PurePosixPath, list[dict[str, Any]]]:
    """reload the verified signed manifest and bind it to immutable ingest state."""

    ingest_path = workspace / "state" / "ingest.json"
    manifest_path = workspace / "state" / "bundle" / "verified-container" / "umzug" / "manifest.json"
    ingest = _load_object(ingest_path, "ingest state")
    workspace_manifest = _load_object(manifest_path, "verified signed manifest")
    expected = ingest.get("manifest_sha256")
    observed = sha256_file(manifest_path)
    if not isinstance(expected, str) or not _SHA256_RE.fullmatch(expected) or observed != expected:
        raise UmzugError("verified signed manifest no longer matches its ingest-state SHA-256 binding")
    if (verified_manifest is None) != (verified_manifest_sha256 is None):
        raise UmzugError("independently verified manifest and SHA-256 must be supplied together")
    if verified_manifest is not None:
        if (
            not isinstance(verified_manifest_sha256, str)
            or not _SHA256_RE.fullmatch(verified_manifest_sha256)
            or observed != verified_manifest_sha256
        ):
            raise UmzugError("workspace manifest differs from the independently re-verified signed manifest")
        manifest = dict(verified_manifest)
    else:
        manifest = workspace_manifest
    payload = manifest.get("payload")
    if not isinstance(payload, dict) or payload.get("sha256") != ingest.get("source_payload_sha256"):
        raise UmzugError("signed source payload is no longer bound to ingest state")
    if manifest.get("trust_statement") != "UNTRUSTED_SOURCE_DATA_REQUIRES_ANALYSIS_AND_EXPLICIT_APPROVAL":
        raise UmzugError("signed manifest has an unexpected trust statement")

    ingested_candidates = ingest.get("candidates")
    if (
        not isinstance(ingested_candidates, list)
        or sum(isinstance(row, dict) and row.get("id") == candidate for row in ingested_candidates) != 1
    ):
        raise UmzugError("candidate is not uniquely bound to ingest state")

    archive_root, entries = _selection_entries(manifest, candidate)
    return ingest, manifest, archive_root, entries


def _selection_entries(manifest: Mapping[str, Any], candidate: str) -> tuple[PurePosixPath, list[dict[str, Any]]]:
    selections = manifest.get("selections")
    if not isinstance(selections, list):
        raise UmzugError("signed manifest selections are invalid")
    matching = [row for row in selections if isinstance(row, dict) and row.get("id") == candidate]
    if len(matching) != 1 or not isinstance(matching[0].get("archive_root"), str):
        raise UmzugError("candidate has no unique selection mapping in the signed manifest")
    archive_path = clean_relative(matching[0]["archive_root"])
    archive_root = PurePosixPath(archive_path.as_posix())
    if len(archive_root.parts) < 3 or archive_root.parts[:2] != ("SOURCE", candidate):
        raise UmzugError("candidate archive root is inconsistent with its signed selection ID")

    all_entries = manifest.get("entries")
    if not isinstance(all_entries, list):
        raise UmzugError("signed manifest entries are invalid")
    entries: list[dict[str, Any]] = []
    seen: set[PurePosixPath] = set()
    for raw in all_entries:
        if not isinstance(raw, dict):
            raise UmzugError("signed manifest contains a non-object entry")
        if raw.get("source_selection") != candidate:
            continue
        raw_path = raw.get("path")
        if not isinstance(raw_path, str):
            raise UmzugError("candidate manifest entry has no valid path")
        path = PurePosixPath(clean_relative(raw_path).as_posix())
        try:
            relative = path.relative_to(archive_root)
        except ValueError as exc:
            raise UmzugError("candidate manifest entry escapes its signed selection root") from exc
        if relative in seen:
            raise UmzugError("candidate manifest contains a duplicate path")
        seen.add(relative)
        row = dict(raw)
        row["_relative"] = "." if relative == PurePosixPath(".") else relative.as_posix()
        entries.append(row)
    if not entries or "." not in {row["_relative"] for row in entries}:
        raise UmzugError("candidate manifest does not describe its selection root")
    return archive_root, entries


def verify_candidate_against_signed_manifest(
    manifest: Mapping[str, Any], candidate: str, candidate_root: Path
) -> dict[str, Any]:
    """bind an APPROVED/RESTORED candidate to signed source bytes and links."""

    if not _CANDIDATE_RE.fullmatch(candidate) or candidate in {".", ".."}:
        raise UmzugError("candidate ID must be a safe ASCII identifier")
    archive_root, entries = _selection_entries(manifest, candidate)
    _verify_tree(candidate_root.absolute(), entries)
    digest_rows = [{key: value for key, value in row.items() if key != "_relative"} for row in entries]
    selection_digest = hashlib.sha256(
        canonical_json(
            {
                "candidate": candidate,
                "archive_root": archive_root.as_posix(),
                "entries": digest_rows,
            }
        )
    ).hexdigest()
    return {
        "candidate": candidate,
        "archive_root": archive_root.as_posix(),
        "entry_count": len(entries),
        "signed_selection_sha256": selection_digest,
    }


def _identity_plan(
    source_rows: object,
    target_rows: Iterable[Mapping[str, Any]],
    *,
    id_key: str,
    kind: str,
) -> tuple[dict[int, int], dict[str, Any]]:
    if not isinstance(source_rows, list):
        source_rows = []
    source_by_id: dict[int, set[str]] = {}
    source_ids_by_name: dict[str, set[int]] = {}
    for raw in source_rows:
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            continue
        value = raw.get(id_key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            source_by_id.setdefault(value, set()).add(raw["name"])
            source_ids_by_name.setdefault(raw["name"], set()).add(value)

    target_by_name: dict[str, set[int]] = {}
    target_by_id: dict[int, set[str]] = {}
    for raw in target_rows:
        name, value = raw.get("name"), raw.get(id_key)
        if not isinstance(name, str) or isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise UmzugError(f"target {kind} database contains an invalid row")
        target_by_name.setdefault(name, set()).add(value)
        target_by_id.setdefault(value, set()).add(name)

    mapping: dict[int, int] = {}
    decisions: dict[str, Any] = {}
    for old_id, names in sorted(source_by_id.items()):
        key = str(old_id)
        if len(names) != 1:
            decisions[key] = {
                "status": "blocked_ambiguous_source_id",
                "source_names": sorted(names),
            }
            continue
        name = next(iter(names))
        source_ids = source_ids_by_name.get(name, set())
        if len(source_ids) != 1:
            decisions[key] = {
                "status": "blocked_ambiguous_source_name",
                "source_name": name,
                "source_ids": sorted(source_ids),
            }
            continue
        target_ids = target_by_name.get(name, set())
        if len(target_ids) != 1:
            occupants = sorted(target_by_id.get(old_id, set()))
            decisions[key] = {
                "status": "blocked_numeric_conflict"
                if occupants and name not in occupants
                else "skipped_name_missing_or_ambiguous",
                "source_name": name,
                "old_id": old_id,
                "target_old_id_names": occupants,
            }
            continue
        new_id = next(iter(target_ids))
        aliases = target_by_id.get(new_id, set())
        if aliases != {name}:
            decisions[key] = {
                "status": "blocked_ambiguous_target_id",
                "source_name": name,
                "target_id": new_id,
                "target_names": sorted(aliases),
            }
            continue
        mapping[old_id] = new_id
        old_occupants = target_by_id.get(old_id, set())
        decisions[key] = {
            "status": "mapped_by_identical_name",
            "source_name": name,
            "old_id": old_id,
            "target_id": new_id,
            "numeric_conflict_avoided": bool(old_occupants - {name}),
            "target_old_id_names": sorted(old_occupants),
        }
    return mapping, decisions


def _open_parent(root: Path, relative: str) -> tuple[int, str]:
    if relative == ".":
        parent = os.open(root.parent, os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW)
        return parent, root.name
    parts = PurePosixPath(relative).parts
    current = os.open(root, os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _open_final(parent_fd: int, name: str, expected_kind: str) -> tuple[int | None, os.stat_result]:
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if expected_kind == "directory":
        expected = stat.S_ISDIR(info.st_mode)
        flags = os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW
    elif expected_kind in {"file", "hardlink"}:
        expected = stat.S_ISREG(info.st_mode)
        flags = os.O_RDONLY | _CLOEXEC | _NOFOLLOW
    elif expected_kind == "symlink":
        expected = stat.S_ISLNK(info.st_mode)
        flags = 0
    else:
        raise UmzugError(f"unsupported signed entry type: {expected_kind!r}")
    if not expected:
        raise UmzugError(f"restored object type differs from signed manifest: {name}")
    if expected_kind == "symlink":
        return None, info
    fd = os.open(name, flags, dir_fd=parent_fd)
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode)) != (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
    ):
        os.close(fd)
        raise UmzugError(f"restored object changed while opening it: {name}")
    return fd, opened


def _hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while data := os.read(fd, 1024 * 1024):
        digest.update(data)
    return digest.hexdigest()


def _verify_tree(destination: Path, entries: list[dict[str, Any]]) -> dict[str, tuple[int, int]]:
    expected_paths = {str(row["_relative"]) for row in entries}
    observed_paths: set[str] = set()
    if destination.is_symlink() or not destination.is_dir():
        observed_paths.add(".")
    else:
        stack: list[tuple[Path, str]] = [(destination, ".")]
        while stack:
            path, relative = stack.pop()
            observed_paths.add(relative)
            if path.is_symlink() or not path.is_dir():
                continue
            with os.scandir(path) as iterator:
                children = sorted(iterator, key=lambda row: os.fsencode(row.name), reverse=True)
            for child in children:
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                child_path = path / child.name
                observed_paths.add(child_relative)
                if child.is_dir(follow_symlinks=False):
                    stack.append((child_path, child_relative))
    if observed_paths != expected_paths:
        missing = sorted(expected_paths - observed_paths)[:20]
        unexpected = sorted(observed_paths - expected_paths)[:20]
        raise UmzugError(
            f"restored tree differs from signed selection mapping; missing={missing}, unexpected={unexpected}"
        )

    inodes: dict[str, tuple[int, int]] = {}
    rows_by_archive_path = {str(row.get("path")): row for row in entries}
    for row in entries:
        relative = str(row["_relative"])
        kind = str(row.get("type"))
        parent_fd, name = _open_parent(destination, relative)
        fd: int | None = None
        try:
            fd, info = _open_final(parent_fd, name, kind)
            inodes[relative] = (info.st_dev, info.st_ino)
            if kind == "file":
                expected_size = _integer(row.get("size"), "file size")
                expected_hash = row.get("sha256")
                if not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash):
                    raise UmzugError("signed manifest has an invalid file SHA-256")
                assert fd is not None
                if info.st_size != expected_size or _hash_fd(fd) != expected_hash:
                    raise UmzugError(f"restored file bytes differ from signed manifest: {relative}")
            elif kind == "symlink":
                expected_target = row.get("link_target")
                if not isinstance(expected_target, str) or os.readlink(name, dir_fd=parent_fd) != expected_target:
                    raise UmzugError(f"restored symlink differs from signed manifest: {relative}")
            elif kind == "hardlink":
                target = row.get("link_target")
                target_row = rows_by_archive_path.get(str(target))
                if not isinstance(target, str) or not isinstance(target_row, dict):
                    raise UmzugError("signed hardlink target is missing")
                if target_row.get("type") != "file" or any(
                    row.get(field) != target_row.get(field) for field in ("mode", "uid", "gid", "mtime_ns")
                ):
                    raise UmzugError("signed hardlink metadata is inconsistent with its inode target")
                target_relative = str(target_row["_relative"])
                if target_relative not in inodes or inodes[target_relative] != inodes[relative]:
                    raise UmzugError(f"restored hardlink relation differs from signed manifest: {relative}")
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)
    return inodes


def _strip_extended_attributes(destination: Path, entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for row in entries:
        relative, kind = str(row["_relative"]), str(row.get("type"))
        parent_fd, name = _open_parent(destination, relative)
        fd: int | None = None
        try:
            fd, _ = _open_final(parent_fd, name, kind)
            if fd is None:
                # linux has no l*xattrat API. resolve the already-open parent
                # descriptor through procfs and still refuse to follow the
                # final symlink. this keeps every parent component anchored.
                proc_parent = Path(f"/proc/self/fd/{parent_fd}")
                if not proc_parent.exists():
                    raise UmzugError("/proc is required to verify symlink extended attributes safely")
                anchored = proc_parent / name
                removed: list[str] = []
                for attribute in os.listxattr(anchored, follow_symlinks=False):
                    os.removexattr(anchored, attribute, follow_symlinks=False)
                    removed.append(attribute)
                if os.listxattr(anchored, follow_symlinks=False):
                    raise UmzugError(f"restored symlink extended attributes could not be stripped: {relative}")
                results.append({"path": relative, "status": "stripped", "removed": sorted(removed)})
                continue
            removed: list[str] = []
            for attribute in os.listxattr(fd):
                os.removexattr(fd, attribute)
                removed.append(attribute)
            remaining = os.listxattr(fd)
            if remaining:
                raise UmzugError(f"extended attributes could not be stripped: {relative}")
            results.append({"path": relative, "status": "stripped", "removed": sorted(removed)})
        except (AttributeError, NotImplementedError) as exc:
            raise UmzugError("target cannot verify stripping ACLs, capabilities, and extended attributes") from exc
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)
    return results


def apply_safe_restore_metadata(
    *,
    workspace: Path,
    candidate: str,
    destination: Path,
    approval_manifest_sha256: str,
    approval_sha256: str,
    target_users: Iterable[Mapping[str, Any]] | None = None,
    target_groups: Iterable[Mapping[str, Any]] | None = None,
    require_root: bool = True,
    verified_manifest: Mapping[str, Any] | None = None,
    verified_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """apply only non-privileged, signed metadata to a newly restored tree.

    regular-file execute bits, SUID/SGID/sticky bits, acls, capabilities and
    every xattr remain absent. ownership is translated only through an exact
    account/group name found in both signed inventory and the target database.
    """

    workspace, destination = workspace.absolute(), destination.absolute()
    if not _CANDIDATE_RE.fullmatch(candidate) or candidate in {".", ".."}:
        raise UmzugError("candidate ID must be a safe ASCII identifier")
    if require_root and os.geteuid() != 0:
        raise UmzugError("safe ownership reconciliation requires root; no metadata was changed")
    if not _SHA256_RE.fullmatch(approval_manifest_sha256) or not _SHA256_RE.fullmatch(approval_sha256):
        raise UmzugError("approval hash binding is invalid")
    if not os.path.lexists(destination):
        raise UmzugError("restored destination is missing")
    receipt_path = workspace / "RESTORED" / f"{candidate}.metadata.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        raise UmzugError("metadata receipt already exists; refusing to overwrite restore evidence")

    ingest, manifest, archive_root, entries = _candidate_manifest(
        workspace,
        candidate,
        verified_manifest=verified_manifest,
        verified_manifest_sha256=verified_manifest_sha256,
    )
    _verify_tree(destination, entries)
    inventory = manifest.get("inventory")
    if not isinstance(inventory, dict):
        inventory = {}
    if target_users is None or target_groups is None:
        local_users, local_groups = target_identities()
        target_users = local_users if target_users is None else target_users
        target_groups = local_groups if target_groups is None else target_groups
    uid_map, uid_decisions = _identity_plan(inventory.get("users"), target_users, id_key="uid", kind="user")
    gid_map, gid_decisions = _identity_plan(inventory.get("groups"), target_groups, id_key="gid", kind="group")

    # inherited default acls/xattrs are removed before any ownership or mode
    # is accepted. failure is fatal and prevents a success receipt.
    xattr_results = _strip_extended_attributes(destination, entries)
    results: list[dict[str, Any]] = []
    # children first and directories last keep the tree reachable until all
    # anchored operations have completed, even when the signed mode is 000.
    ordered = sorted(
        entries,
        key=lambda row: (
            1 if str(row.get("type")) == "directory" else 0,
            -str(row["_relative"]).count("/"),
        ),
    )
    for row in ordered:
        relative, kind = str(row["_relative"]), str(row.get("type"))
        source_mode = _integer(row.get("mode"), "mode") & 0o7777
        source_uid = _integer(row.get("uid"), "UID")
        source_gid = _integer(row.get("gid"), "GID")
        mtime_ns = _integer(row.get("mtime_ns"), "mtime_ns")
        safe_mode = None if kind == "symlink" else source_mode & (0o777 if kind == "directory" else 0o666)
        target_uid, target_gid = uid_map.get(source_uid), gid_map.get(source_gid)
        parent_fd, name = _open_parent(destination, relative)
        fd: int | None = None
        entry_result: dict[str, Any] = {
            "path": relative,
            "type": kind,
            "source_mode": oct(source_mode),
            "safe_mode": oct(safe_mode) if safe_mode is not None else None,
            "mode_policy": "directory traversal bits retained; privileged bits stripped"
            if kind == "directory"
            else "all executable and privileged bits stripped",
            "uid": {
                "source": source_uid,
                "target": target_uid,
                "status": "mapped_by_name" if target_uid is not None else "kept_restore_operator",
            },
            "gid": {
                "source": source_gid,
                "target": target_gid,
                "status": "mapped_by_name" if target_gid is not None else "kept_restore_operator",
            },
            "mtime_ns": mtime_ns,
        }
        try:
            fd, before = _open_final(parent_fd, name, kind)
            entry_result["uid"]["expected"] = target_uid if target_uid is not None else before.st_uid
            entry_result["gid"]["expected"] = target_gid if target_gid is not None else before.st_gid
            if fd is not None:
                os.fchown(
                    fd, target_uid if target_uid is not None else -1, target_gid if target_gid is not None else -1
                )
                assert safe_mode is not None
                os.fchmod(fd, safe_mode)
                os.utime(fd, ns=(mtime_ns, mtime_ns))
            else:
                os.chown(
                    name,
                    target_uid if target_uid is not None else -1,
                    target_gid if target_gid is not None else -1,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                try:
                    os.utime(name, ns=(mtime_ns, mtime_ns), dir_fd=parent_fd, follow_symlinks=False)
                    entry_result["symlink_mtime_status"] = "applied"
                except (NotImplementedError, OSError) as exc:
                    entry_result["symlink_mtime_status"] = f"skipped_not_supported:{type(exc).__name__}"
            entry_result["status"] = "applied"
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)
        results.append(entry_result)

    # verify no operation or filesystem inheritance recreated privileged bits
    # or extended security metadata.
    _verify_tree(destination, entries)
    post_xattrs = _strip_extended_attributes(destination, entries)
    results_by_path = {str(row["path"]): row for row in results}
    for row in entries:
        relative, kind = str(row["_relative"]), str(row.get("type"))
        applied = results_by_path[relative]
        parent_fd, name = _open_parent(destination, relative)
        fd: int | None = None
        try:
            fd, info = _open_final(parent_fd, name, kind)
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o7000 or (kind in {"file", "hardlink"} and mode & 0o111):
                raise UmzugError(f"unsafe mode observed after metadata reconciliation: {relative}")
            if applied["safe_mode"] is not None and mode != int(str(applied["safe_mode"]), 8):
                raise UmzugError(f"safe mode verification failed after metadata reconciliation: {relative}")
            expected_uid = int(applied["uid"]["expected"])
            expected_gid = int(applied["gid"]["expected"])
            if info.st_uid != expected_uid or info.st_gid != expected_gid:
                raise UmzugError(f"ownership verification failed after metadata reconciliation: {relative}")
            verify_mtime = kind != "symlink" or applied.get("symlink_mtime_status") == "applied"
            if verify_mtime and info.st_mtime_ns != int(applied["mtime_ns"]):
                raise UmzugError(f"mtime verification failed after metadata reconciliation: {relative}")
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)

    report: dict[str, Any] = {
        "format": 1,
        "candidate": candidate,
        "destination": str(destination),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "safe-metadata-applied",
        "approval_manifest_sha256": approval_manifest_sha256,
        "approval_sha256": approval_sha256,
        "ingest_state_sha256": sha256_file(workspace / "state" / "ingest.json"),
        "signed_manifest_sha256": ingest["manifest_sha256"],
        "source_payload_sha256": ingest["source_payload_sha256"],
        "selection_archive_root": archive_root.as_posix(),
        "identity_mapping": {"uids": uid_decisions, "gids": gid_decisions},
        "xattrs_before_metadata": xattr_results,
        "xattrs_after_metadata": post_xattrs,
        "entries": sorted(results, key=lambda row: str(row["path"])),
        "policy": {
            "ownership": "exact signed-source name to exact target name only; raw numeric IDs are never replayed",
            "regular_modes": "signed rw bits only; execute, SUID, SGID, and sticky bits stripped",
            "directory_modes": "signed rwx traversal bits only; SUID, SGID, and sticky bits stripped",
            "symlink_modes": "never changed; symlinks are never followed",
            "extended_metadata": "ACLs, capabilities, and all xattrs stripped and absence verified",
            "timestamps": "signed mtime applied; symlink mtime may be explicitly skipped if unsupported",
        },
        "limitations": [
            "Names absent or ambiguous on the target retain the restore operator (normally root) as owner and are reported.",
            "Directory execute bits are traversal permissions, not permission to execute migrated file content.",
            "The ingest state and verified-container directory must remain protected by target filesystem permissions after signature verification.",
        ],
    }
    report["receipt_sha256"] = hashlib.sha256(canonical_json(report)).hexdigest()
    atomic_write(receipt_path, canonical_json(report), 0o600)
    return report
