from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import shlex
import subprocess
import stat
import sys
import tomllib
import venv
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
_BACKEND_SPEC = importlib.util.spec_from_file_location("umzug_build", ROOT / "build_backend/umzug_build.py")
assert _BACKEND_SPEC is not None and _BACKEND_SPEC.loader is not None
umzug_build = importlib.util.module_from_spec(_BACKEND_SPEC)
sys.modules[_BACKEND_SPEC.name] = umzug_build
_BACKEND_SPEC.loader.exec_module(umzug_build)


SHELL_ASSETS = (
    ROOT / "scripts/offline-build.sh",
    ROOT / "scripts/umzug-setup-root",
    ROOT / "scripts/make-hardware-test-kit.sh",
    ROOT / "scripts/static-checks.sh",
    ROOT / "container/offline-smoke.sh",
    ROOT / "vm/qemu-smoke.sh",
)


def _record_rows(wheel: zipfile.ZipFile) -> dict[str, tuple[str, str]]:
    record = f"{umzug_build.NAME}-{umzug_build.VERSION}.dist-info/RECORD"
    rows = list(csv.reader(io.StringIO(wheel.read(record).decode("utf-8"))))
    assert all(len(row) == 3 for row in rows)
    assert len({row[0] for row in rows}) == len(rows)
    return {name: (digest, size) for name, digest, size in rows}


def test_offline_backend_builds_reproducible_valid_wheel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_path = first / umzug_build.build_wheel(str(first))
    second_path = second / umzug_build.build_wheel(str(second))

    assert first_path.read_bytes() == second_path.read_bytes()
    with zipfile.ZipFile(first_path) as wheel:
        assert wheel.testzip() is None
        names = wheel.namelist()
        assert len(names) == len(set(names))
        assert all(not PurePosixPath(name).is_absolute() for name in names)
        assert all(".." not in PurePosixPath(name).parts for name in names)
        assert "umzug/pack_cli.py" in names
        assert "umzug/setup_cli.py" in names
        root_launcher = f"{umzug_build.NAME}-{umzug_build.VERSION}.data/scripts/umzug-setup-root"
        assert root_launcher in names
        launcher_mode = wheel.getinfo(root_launcher).external_attr >> 16
        assert stat.S_ISREG(launcher_mode)
        assert stat.S_IMODE(launcher_mode) == 0o755
        launcher = wheel.read(root_launcher).decode("utf-8")
        assert "/usr/bin/env -i" in launcher
        assert '"$PYTHON" -I -B -m umzug.setup_cli "$@"' in launcher
        assert 'find -P "$RUNTIME/lib"' in launcher
        assert "! -uid 0" in launcher
        assert "-perm /022" in launcher
        assert "UMZUG_INVOCATION_REMOTE" in launcher
        assert "SSH_CONNECTION" in launcher
        entry_points = wheel.read(f"{umzug_build.NAME}-{umzug_build.VERSION}.dist-info/entry_points.txt").decode(
            "utf-8"
        )
        assert "umzug-pack=umzug.pack_cli:main" in entry_points
        assert "umzug-setup=umzug.setup_cli:main" not in entry_points
        rows = _record_rows(wheel)
        assert set(rows) == set(names)
        record_name = f"{umzug_build.NAME}-{umzug_build.VERSION}.dist-info/RECORD"
        for name in names:
            digest, size = rows[name]
            if name == record_name:
                assert (digest, size) == ("", "")
                continue
            data = wheel.read(name)
            encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
            assert digest == f"sha256={encoded}"
            assert size == str(len(data))


def test_offline_build_script_runs_and_refuses_different_output(tmp_path: Path) -> None:
    output = tmp_path / "wheel-output"
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "1767225600"
    subprocess.run(
        [str(ROOT / "scripts/offline-build.sh"), str(output)],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel = output / "umzug_toolkit-0.2.0rc1-py3-none-any.whl"
    installer = output / "umzug-offline-install.py"
    assert wheel.is_file()
    assert installer.is_file()
    assert installer.read_bytes() == (ROOT / "scripts/offline-install.py").read_bytes()
    assert stat.S_IMODE(installer.stat().st_mode) == 0o644
    wheel.write_bytes(b"different pre-existing output")
    repeated = subprocess.run(
        [str(ROOT / "scripts/offline-build.sh"), str(output)],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert repeated.returncode == 2
    assert "refusing to overwrite" in repeated.stderr


def test_offline_build_refuses_different_existing_installer(tmp_path: Path) -> None:
    output = tmp_path / "wheel-output"
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "1767225600"
    subprocess.run(
        [str(ROOT / "scripts/offline-build.sh"), str(output)],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    (output / "umzug-offline-install.py").write_bytes(b"different pre-existing installer")
    repeated = subprocess.run(
        [str(ROOT / "scripts/offline-build.sh"), str(output)],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert repeated.returncode == 2
    assert "different existing installer" in repeated.stderr


def test_offline_build_preflights_stale_installer_before_copying_wheel(
    tmp_path: Path,
) -> None:
    output = tmp_path / "stale-output"
    output.mkdir()
    (output / "umzug-offline-install.py").write_bytes(b"stale installer")
    env = os.environ.copy()
    env["SOURCE_DATE_EPOCH"] = "1767225600"

    completed = subprocess.run(
        [str(ROOT / "scripts/offline-build.sh"), str(output)],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert "different existing installer" in completed.stderr
    assert not (output / "umzug_toolkit-0.2.0rc1-py3-none-any.whl").exists()


def test_shell_assets_are_executable_and_parse() -> None:
    for script in SHELL_ASSETS:
        assert script.stat().st_mode & 0o111
        subprocess.run(["sh", "-n", str(script)], check=True)


def test_root_setup_wrapper_ignores_malicious_pythonpath_before_import(
    tmp_path: Path,
) -> None:
    malicious = tmp_path / "malicious"
    package = malicious / "umzug"
    package.mkdir(parents=True)
    marker = tmp_path / "executed"
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "setup_cli.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    runtime = tmp_path / "test-runtime"
    venv.EnvBuilder(with_pip=False, symlinks=False).create(runtime)
    source = (ROOT / "scripts/umzug-setup-root").read_text(encoding="utf-8")
    uid = os.geteuid()
    source = source.replace(
        "RUNTIME=/opt/umzug/runtime",
        f"RUNTIME={shlex.quote(str(runtime))}",
    )
    source = source.replace(
        'for directory in /opt /opt/umzug "$RUNTIME"',
        'for directory in "$RUNTIME"',
    )
    source = source.replace('[ "$owner" = 0 ]', f'[ "$owner" = {uid} ]')
    source = source.replace("! -uid 0", f"! -uid {uid}")
    wrapper = tmp_path / "umzug-setup-root"
    wrapper.write_text(source, encoding="utf-8")
    wrapper.chmod(0o755)
    completed = subprocess.run(
        [str(wrapper), "--help"],
        cwd=malicious,
        env={"PYTHONPATH": str(malicious)},
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert not marker.exists()


def test_root_wrapper_forbids_bytecode_writes() -> None:
    wrapper = (ROOT / "scripts/umzug-setup-root").read_text(encoding="utf-8")
    assert '"$PYTHON" -I -B -m umzug.setup_cli "$@"' in wrapper


def test_root_wrapper_preserves_only_a_derived_remote_session_marker() -> None:
    wrapper = (ROOT / "scripts/umzug-setup-root").read_text(encoding="utf-8")
    assert 'UMZUG_INVOCATION_REMOTE="$UMZUG_INVOCATION_REMOTE"' in wrapper
    assert 'SSH_CLIENT="$SSH_CLIENT"' not in wrapper
    assert 'SSH_CONNECTION="$SSH_CONNECTION"' not in wrapper
    assert 'SSH_TTY="$SSH_TTY"' not in wrapper


def test_offline_wheel_install_places_executable_isolated_setup_wrapper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    wheel = wheels / umzug_build.build_wheel(str(wheels))
    runtime = tmp_path / "runtime"
    venv.EnvBuilder(with_pip=True, symlinks=False).create(runtime)
    python = runtime / "bin" / "python"

    def installation_umask() -> None:
        os.umask(0o022)

    subprocess.run(
        [
            str(python),
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--no-cache-dir",
            str(wheel),
        ],
        check=True,
        capture_output=True,
        preexec_fn=installation_umask,
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        },
    )
    launcher = runtime / "bin" / "umzug-setup-root"
    info = launcher.lstat()
    assert stat.S_ISREG(info.st_mode)
    assert stat.S_IMODE(info.st_mode) == 0o755
    assert not (runtime / "bin" / "umzug-setup").exists()


def test_container_harness_cannot_fetch_dependencies() -> None:
    dockerfile = (ROOT / "container/Dockerfile").read_text(encoding="utf-8")
    assert "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}" in dockerfile
    lowered = dockerfile.lower()
    assert "pip install" not in lowered
    assert "apt-get" not in lowered
    assert "curl " not in lowered
    runner = (ROOT / "container/offline-smoke.sh").read_text(encoding="utf-8")
    assert runner.count("--network=none") >= 2
    assert runner.count("--pull=never") >= 2
    assert "--cap-drop=all" in runner
    assert "--read-only" in runner


def test_container_context_excludes_private_key_and_secret_patterns() -> None:
    ignored = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert {
        "agentkey.pem",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        ".env*",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    } <= ignored


def test_vm_harness_is_networkless_disposable_and_hash_pinned() -> None:
    script = (ROOT / "vm/qemu-smoke.sh").read_text(encoding="utf-8")
    assert "-nic none" in script
    assert "snapshot=on" in script
    assert "EXPECTED_DISK" in script
    assert "EXPECTED_QEMU" in script
    assert "-net user" not in script
    assert "hostfwd" not in script


def test_hardware_test_kit_is_offline_no_overwrite_and_secret_excluding() -> None:
    script = (ROOT / "scripts/make-hardware-test-kit.sh").read_text(encoding="utf-8")
    lowered = script.lower()
    assert "scripts/static-checks.sh" in script
    assert "scripts/offline-build.sh" in script
    assert "PIP_NO_INDEX=1" in script
    assert "refusing to overwrite" in script
    assert "authenticate" in lowered
    assert '"SHA256SUMS"' in script
    assert "clamav" in lowered and "not bundled" in lowered
    assert "agentkey.pem" not in script
    assert "curl " not in lowered
    assert "wget " not in lowered


def test_pack_example_is_only_a_nonsecret_dry_run_profile() -> None:
    profile = tomllib.loads((ROOT / "profiles/pack.example.toml").read_text(encoding="utf-8"))["pack"]
    assert profile["include_sensitive"] is False
    assert profile["acknowledge_sensitive_risk"] is False
    assert "recipient" not in profile
    assert "signing_key" not in profile
    assert "generate_signing_key" not in profile
    assert "output" not in profile
    assert profile["include"] == [{"category": "projects", "path": "profiles"}]
    result = subprocess.run(
        [
            str(ROOT / "pack"),
            "--config",
            str(ROOT / "profiles/pack.example.toml"),
            "--non-interactive",
            "--dry-run",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "Dry-Run abgeschlossen" in result.stdout


def test_yara_rules_are_real_heuristics_not_fake_trust_pins(tmp_path: Path) -> None:
    rules = ROOT / "rules/umzug-core.yar"
    content = rules.read_text(encoding="utf-8")
    assert content.count("rule UMZUG_") >= 6
    assert "non-match is never evidence" in content
    assert not any(token in content.lower() for token in ("<64 hex>", "todo", "placeholder"))
    yarac = shutil.which("yarac")
    if yarac:
        subprocess.run([yarac, str(rules), str(tmp_path / "rules.yarc")], check=True)
