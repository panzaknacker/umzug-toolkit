from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
from typing import Any

from .util import UmzugError, canonical_json, fsync_directory, sha256_file


PART_RE = re.compile(r"^[A-Za-z0-9._-]+\.part[0-9]{5}$")


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    fsync_directory(path.parent)


def split_file(source: Path, part_size: int) -> Path:
    if part_size < 1024 * 1024:
        raise UmzugError("part size must be at least 1 MiB")
    index_path = source.with_name(source.name + ".parts.json")
    if os.path.lexists(index_path):
        raise UmzugError(f"refusing to overwrite existing split index: {index_path}")
    expected_parts = math.ceil(source.stat().st_size / part_size)
    planned_paths = [source.with_name(f"{source.name}.part{number:05d}") for number in range(1, expected_parts + 1)]
    existing = [str(path) for path in planned_paths if os.path.lexists(path)]
    if existing:
        raise UmzugError(f"refusing to overwrite existing split part: {existing[0]}")
    parts: list[dict[str, Any]] = []
    created: list[Path] = []
    try:
        with source.open("rb") as input_file:
            number = 0
            while True:
                chunk = input_file.read(part_size)
                if not chunk:
                    break
                number += 1
                name = f"{source.name}.part{number:05d}"
                path = source.with_name(name)
                _write_exclusive(path, chunk, 0o600)
                created.append(path)
                parts.append({"name": name, "size": len(chunk), "sha256": sha256_file(path)})
        if not parts:
            raise UmzugError("cannot split an empty bundle")
        index = {
            "format": "umzug-split-v1",
            "source_name": source.name,
            "source_size": source.stat().st_size,
            "source_sha256": sha256_file(source),
            "part_size": part_size,
            "parts": parts,
        }
        _write_exclusive(index_path, canonical_json(index), 0o644)
        created.append(index_path)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return index_path


def reassemble(index_path: Path, destination: Path, *, max_bytes: int | None = None) -> None:
    if index_path.is_symlink() or not index_path.is_file():
        raise UmzugError("parts index must be a non-symlink regular file")
    if index_path.stat().st_size > 64 * 1024 * 1024:
        raise UmzugError("parts index exceeds the 64 MiB parser limit")
    try:
        value = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"invalid parts index: {exc}") from exc
    if value.get("format") != "umzug-split-v1" or not isinstance(value.get("parts"), list):
        raise UmzugError("unsupported parts index")
    source_name = value.get("source_name")
    if (
        not isinstance(source_name, str)
        or not source_name
        or Path(source_name).name != source_name
        or not re.fullmatch(r"[A-Za-z0-9._-]+", source_name)
    ):
        raise UmzugError("invalid source name in parts index")
    expected_size = value.get("source_size")
    if not isinstance(expected_size, int) or expected_size < 1:
        raise UmzugError("invalid source size in parts index")
    if max_bytes is not None and (max_bytes <= 0 or expected_size > max_bytes):
        raise UmzugError("split source exceeds configured reassembly limit")
    written = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            for position, row in enumerate(value["parts"], 1):
                if not isinstance(row, dict):
                    raise UmzugError("invalid part entry")
                name = row.get("name")
                if (
                    not isinstance(name, str)
                    or not PART_RE.fullmatch(name)
                    or name != f"{source_name}.part{position:05d}"
                ):
                    raise UmzugError("invalid or non-contiguous part name")
                part = index_path.parent / name
                if part.parent.resolve() != index_path.parent.resolve():
                    raise UmzugError("part path escapes index directory")
                if not part.is_file() or part.is_symlink():
                    raise UmzugError(f"missing or unsafe part: {name}")
                if part.stat().st_size != row.get("size") or sha256_file(part) != row.get("sha256"):
                    raise UmzugError(f"part integrity check failed: {name}")
                with part.open("rb") as input_file:
                    while chunk := input_file.read(1024 * 1024):
                        written += len(chunk)
                        if written > expected_size:
                            raise UmzugError("parts exceed declared total size")
                        output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    if written != expected_size or sha256_file(destination) != value.get("source_sha256"):
        destination.unlink(missing_ok=True)
        raise UmzugError("reassembled bundle integrity check failed")
