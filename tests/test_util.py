from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys

import pytest

from umzug.util import AuditLog, UmzugError, atomic_replace, run


def test_atomic_replace_closes_temporary_file_when_setting_mode_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "receipt.json"
    target.write_bytes(b"previous receipt\n")
    descriptors: list[int] = []

    def fail_chmod(descriptor: int, _mode: int) -> None:
        descriptors.append(descriptor)
        raise OSError("chmod failed")

    monkeypatch.setattr(os, "fchmod", fail_chmod)
    with pytest.raises(OSError, match="chmod failed"):
        atomic_replace(target, b"new receipt\n")

    assert target.read_bytes() == b"previous receipt\n"
    assert not list(tmp_path.glob(".receipt.json.*"))
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_audit_log_rejects_symlink_without_touching_target(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("unchanged\n", encoding="utf-8")
    link = tmp_path / "audit.jsonl"
    link.symlink_to(target.name)

    with pytest.raises(UmzugError, match="safely"):
        AuditLog(link).event("test")
    assert target.read_text(encoding="utf-8") == "unchanged\n"


def test_audit_log_tightens_mode_and_redacts_common_tokens(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    log.write_text("", encoding="utf-8")
    log.chmod(0o666)
    secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"

    AuditLog(log).event("test", message=f"token={secret}", aws="AKIAABCDEFGHIJKLMNOP")

    assert stat.S_IMODE(log.stat().st_mode) == 0o600
    row = json.loads(log.read_text(encoding="utf-8"))
    rendered = json.dumps(row)
    assert secret not in rendered
    assert "AKIAABCDEFGHIJKLMNOP" not in rendered
    assert "<redacted>" in rendered


def test_audit_log_rejects_symlinked_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)

    with pytest.raises((UmzugError, OSError)):
        AuditLog(alias / "audit.jsonl")
    assert not (real / "audit.jsonl").exists()


def test_run_passes_only_explicit_close_on_exec_descriptors(tmp_path: Path) -> None:
    inherited = tmp_path / "inherited"
    closed = tmp_path / "closed"
    inherited.mkdir()
    closed.mkdir()
    inherited_fd = os.open(inherited, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    closed_fd = os.open(closed, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        destination = f"/proc/self/fd/{inherited_fd}/child-observation"
        unlisted = f"/proc/self/fd/{closed_fd}"
        run(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                (
                    "import os,sys; "
                    "fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600); "
                    "os.write(fd, b'visible' if os.path.isdir(sys.argv[2]) else b'closed'); "
                    "os.close(fd)"
                ),
                destination,
                unlisted,
            ],
            pass_fds=(inherited_fd, inherited_fd),
        )
    finally:
        os.close(closed_fd)
        os.close(inherited_fd)

    assert (inherited / "child-observation").read_bytes() == b"closed"
    assert not any(closed.iterdir())


def test_run_rejects_inheritable_or_closed_pass_through_descriptor(tmp_path: Path) -> None:
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    os.set_inheritable(descriptor, True)
    try:
        with pytest.raises(UmzugError, match="close-on-exec"):
            run([sys.executable, "-c", "pass"], pass_fds=(descriptor,))
    finally:
        os.close(descriptor)

    with pytest.raises(UmzugError, match="not open"):
        run([sys.executable, "-c", "pass"], pass_fds=(descriptor,))


def test_run_supplies_bounded_standard_input() -> None:
    result = run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
        ],
        input_bytes=b"inert test input",
    )
    assert result.stdout == b"inert test input"
