from __future__ import annotations

from pathlib import Path

import pytest

from umzug.state_storage import (
    observe_persistent_state_storage,
    require_matching_state_storage,
)
from umzug.util import UmzugError


def _mountinfo(path: Path, filesystem: str, *, source: str = "/dev/mapper/root") -> Path:
    path.write_text(
        f"36 25 253:0 / / rw,relatime - {filesystem} {source} rw\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    "filesystem",
    ["tmpfs", "ramfs", "overlay", "nfs4", "cifs", "9p", "fuse.sshfs"],
)
def test_volatile_remote_and_overlay_state_are_rejected(tmp_path: Path, filesystem: str) -> None:
    mountinfo = _mountinfo(tmp_path / "mountinfo", filesystem, source=filesystem)

    with pytest.raises(UmzugError, match="approved local persistent"):
        observe_persistent_state_storage(tmp_path / "future" / "state", mountinfo_path=mountinfo)


def test_local_persistent_state_is_observed_and_digest_bound(tmp_path: Path) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "36 25 253:0 / / rw,relatime - ext4 /dev/mapper/root rw\n"
        "372 27 0:5 net:[4026533133] /run/netns/test rw - nsfs nsfs rw\n",
        encoding="utf-8",
    )

    observed = observe_persistent_state_storage(tmp_path / "future" / "state", mountinfo_path=mountinfo)

    assert observed["filesystem"] == "ext4"
    assert observed["mount_point"] == "/"
    assert observed["persistent_local_storage_proven"] is True
    assert observed["created_or_modified"] is False
    require_matching_state_storage(observed, observed)


def test_selected_persistent_mount_requires_absolute_filesystem_root(
    tmp_path: Path,
) -> None:
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "36 25 253:0 dataset / rw - ext4 /dev/mapper/root rw\n",
        encoding="utf-8",
    )

    with pytest.raises(UmzugError, match="non-absolute filesystem root"):
        observe_persistent_state_storage(tmp_path / "state", mountinfo_path=mountinfo)


def test_state_storage_binding_detects_replacement(tmp_path: Path) -> None:
    first = observe_persistent_state_storage(
        tmp_path / "state",
        mountinfo_path=_mountinfo(tmp_path / "first", "ext4"),
    )
    second = observe_persistent_state_storage(
        tmp_path / "state",
        mountinfo_path=_mountinfo(tmp_path / "second", "xfs", source="/dev/sdb1"),
    )

    with pytest.raises(UmzugError, match="filesystem identity changed"):
        require_matching_state_storage(first, second)


def test_more_specific_volatile_mount_wins(tmp_path: Path) -> None:
    mount_root = tmp_path / "mounted"
    mount_root.mkdir()
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        f"36 25 253:0 / / rw - ext4 /dev/mapper/root rw\n40 36 0:44 / {mount_root} rw - tmpfs tmpfs rw\n",
        encoding="utf-8",
    )

    with pytest.raises(UmzugError, match="tmpfs"):
        observe_persistent_state_storage(mount_root / "hardware", mountinfo_path=mountinfo)


def test_malformed_or_ambiguous_mount_evidence_fails_closed(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed"
    malformed.write_text("not mountinfo\n", encoding="utf-8")
    with pytest.raises(UmzugError, match="malformed"):
        observe_persistent_state_storage(tmp_path / "state", mountinfo_path=malformed)

    ambiguous = tmp_path / "ambiguous"
    ambiguous.write_text(
        "36 25 253:0 / / rw - ext4 /dev/sda1 rw\n37 25 253:1 / / rw - xfs /dev/sdb1 rw\n",
        encoding="utf-8",
    )
    with pytest.raises(UmzugError, match="ambiguous"):
        observe_persistent_state_storage(tmp_path / "state", mountinfo_path=ambiguous)


def test_relative_state_path_is_rejected_before_mount_observation(
    tmp_path: Path,
) -> None:
    with pytest.raises(UmzugError, match="must be absolute"):
        observe_persistent_state_storage(Path("relative/state"), mountinfo_path=tmp_path / "unused")
