from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "offline-install.py"
sys.path.insert(0, str(ROOT / "build_backend"))
import umzug_build  # noqa: E402


def build_wheel(directory: Path) -> Path:
    directory.mkdir(mode=0o700)
    name = umzug_build.build_wheel(str(directory))
    return directory / name


def install(wheel: Path, test_root: Path, digest: str | None = None) -> subprocess.CompletedProcess[str]:
    os.chmod(test_root, 0o700)
    expected = digest or hashlib.sha256(wheel.read_bytes()).hexdigest()
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(INSTALLER),
            "--wheel",
            str(wheel),
            "--expected-sha256",
            expected,
            "--test-root",
            str(test_root),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=60,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(test_root),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )


def test_pip_free_install_and_no_overwrite(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path / "wheel")
    target = tmp_path / "target"
    target.mkdir(mode=0o700)

    first = install(wheel, target)
    assert first.returncode == 0, first.stderr
    runtime = target / "opt" / "umzug" / "runtime"
    assert (runtime / "bin" / "python").is_file()
    assert not (runtime / "bin" / "python").is_symlink()
    assert stat.S_IMODE((runtime / "bin" / "umzug-setup-root").stat().st_mode) == 0o755
    assert stat.S_IMODE((runtime / "bin" / "umzug-pack").stat().st_mode) == 0o755
    assert not any(path.is_symlink() for path in runtime.rglob("*"))
    smoke = subprocess.run(
        [str(runtime / "bin" / "python"), "-I", "-B", "-m", "umzug.setup_cli", "--help"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(target), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    assert smoke.returncode == 0, smoke.stderr
    source = (runtime / "bin" / "umzug-setup-root").read_text(encoding="utf-8")
    uid = os.geteuid()
    source = source.replace("RUNTIME=/opt/umzug/runtime", f"RUNTIME={shlex.quote(str(runtime))}")
    source = source.replace(
        'for directory in /opt /opt/umzug "$RUNTIME"',
        'for directory in "$RUNTIME"',
    )
    source = source.replace('[ "$owner" = 0 ]', f'[ "$owner" = {uid} ]')
    source = source.replace("! -uid 0", f"! -uid {uid}")
    wrapper = target / "umzug-setup-test-wrapper"
    wrapper.write_text(source, encoding="utf-8")
    wrapper.chmod(0o755)
    for _ in range(2):
        wrapped = subprocess.run(
            [str(wrapper), "--help"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=30,
        )
        assert wrapped.returncode == 0, wrapped.stderr
    assert not list(runtime.rglob("__pycache__"))

    second = install(wheel, target)
    assert second.returncode == 2
    assert "refusing overwrite" in second.stderr


def test_wrong_outer_digest_creates_no_runtime(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path / "wheel")
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    result = install(wheel, target, "0" * 64)
    assert result.returncode == 2
    assert "SHA-256 mismatch" in result.stderr
    assert not os.path.lexists(target / "opt" / "umzug" / "runtime")


def test_installer_requires_python_isolated_mode(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, str(INSTALLER), "--help"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 2
    assert "-I" in completed.stderr


def test_record_tamper_is_rejected_before_install(tmp_path: Path) -> None:
    original = build_wheel(tmp_path / "wheel")
    tampered = tmp_path / "tampered.whl"
    with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(tampered, "w") as destination:
        for info in source.infolist():
            payload = source.read(info)
            if info.filename == "umzug/__init__.py":
                payload += b"# changed without RECORD update\n"
            destination.writestr(info, payload)
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    result = install(tampered, target)
    assert result.returncode == 2
    assert "RECORD" in result.stderr
    assert not os.path.lexists(target / "opt" / "umzug" / "runtime")


def test_path_traversal_member_is_rejected(tmp_path: Path) -> None:
    original = build_wheel(tmp_path / "wheel")
    tampered = tmp_path / "traversal.whl"
    shutil.copyfile(original, tampered)
    with zipfile.ZipFile(tampered, "a") as archive:
        archive.writestr("../escape", b"never write me")
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    result = install(tampered, target)
    assert result.returncode == 2
    assert "escapes its root" in result.stderr
    assert not (tmp_path / "escape").exists()
    assert not os.path.lexists(target / "opt" / "umzug" / "runtime")


def test_wheel_source_must_be_single_link(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path / "wheel")
    alias = tmp_path / "wheel-hardlink.whl"
    os.link(wheel, alias)
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    result = install(wheel, target)
    assert result.returncode == 2
    assert "single-link" in result.stderr
    assert not os.path.lexists(target / "opt" / "umzug" / "runtime")
