from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import umzug.console as console_module
from umzug.console import (
    remote_session_evidence,
    require_not_known_remote,
    require_proven_local_console,
)
from umzug.util import UmzugError


def _process(proc: Path, pid: int, name: str, parent: int) -> None:
    root = proc / str(pid)
    root.mkdir(parents=True)
    (root / "comm").write_text(f"{name}\n", encoding="utf-8")
    (root / "status").write_text(
        f"Name:\t{name}\nPid:\t{pid}\nPPid:\t{parent}\n",
        encoding="utf-8",
    )


def test_wrapper_ssh_marker_is_remote_even_without_process_evidence(tmp_path: Path) -> None:
    result = remote_session_evidence(
        environ={"UMZUG_INVOCATION_REMOTE": "1"},
        proc_root=tmp_path,
        parent_pid=999,
    )

    assert result["remote_detected"] is True
    assert result["ancestor_scan_complete"] is False


def test_sshd_ancestor_is_detected(tmp_path: Path) -> None:
    _process(tmp_path, 300, "sudo", 200)
    _process(tmp_path, 200, "bash", 100)
    _process(tmp_path, 100, "sshd", 1)

    result = remote_session_evidence(environ={}, proc_root=tmp_path, parent_pid=300)

    assert result["remote_detected"] is True
    assert [row["name"] for row in result["ancestors"]] == ["sudo", "bash", "sshd"]


def test_local_process_tree_is_not_mislabeled_remote(tmp_path: Path) -> None:
    _process(tmp_path, 300, "sudo", 200)
    _process(tmp_path, 200, "zsh", 100)
    _process(tmp_path, 100, "foot", 1)

    result = remote_session_evidence(environ={}, proc_root=tmp_path, parent_pid=300)

    assert result["remote_detected"] is False
    assert result["ancestor_scan_complete"] is True


def test_known_remote_guard_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "umzug.console.remote_session_evidence",
        lambda: {
            "remote_detected": True,
            "reasons": ["remote test"],
        },
    )

    with pytest.raises(UmzugError, match="forbidden from a detected remote session"):
        require_not_known_remote("productive apply")


@pytest.mark.parametrize(
    "evidence",
    [
        {
            "local_console_proven": False,
            "local_console_blockers": ["process ancestry could not be inspected completely"],
        },
        {
            "local_console_proven": False,
            "local_console_blockers": ["stdin and stdout are not both attached to a TTY"],
        },
        {
            "local_console_proven": False,
            "local_console_blockers": ["TTY is not a permitted console"],
            "tty": "/dev/pts/7",
        },
    ],
)
def test_proven_local_console_guard_blocks_incomplete_or_pts_evidence(
    evidence: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("umzug.console.remote_session_evidence", lambda: evidence)

    with pytest.raises(UmzugError, match="requires a proven physical"):
        require_proven_local_console("productive apply")


def test_proven_local_console_guard_accepts_only_positive_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = {
        "remote_detected": False,
        "ancestor_scan_complete": True,
        "stdin_is_tty": True,
        "stdout_is_tty": True,
        "tty": "/dev/tty2",
        "local_console_proven": True,
        "local_console_blockers": [],
    }
    monkeypatch.setattr("umzug.console.remote_session_evidence", lambda: evidence)

    assert require_proven_local_console("productive apply") == evidence


@pytest.mark.parametrize(
    ("tty", "expected"),
    [("/dev/tty2", True), ("/dev/ttyS0", True), ("/dev/hvc0", True), ("/dev/pts/7", False)],
)
def test_remote_evidence_requires_exact_local_console_tty(
    tmp_path: Path,
    tty: str,
    expected: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _process(tmp_path, 300, "sudo", 200)
    _process(tmp_path, 200, "zsh", 100)
    _process(tmp_path, 100, "foot", 1)
    stream = SimpleNamespace(isatty=lambda: True, fileno=lambda: 0)
    monkeypatch.setattr(console_module.sys, "stdin", stream)
    monkeypatch.setattr(console_module.sys, "stdout", stream)
    monkeypatch.setattr(console_module.os, "ttyname", lambda _fd: tty)

    evidence = remote_session_evidence(environ={}, proc_root=tmp_path, parent_pid=300)

    assert evidence["ancestor_scan_complete"] is True
    assert evidence["local_console_proven"] is expected
