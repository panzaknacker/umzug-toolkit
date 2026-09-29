from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import tempfile
from typing import Any

from .util import UmzugError, atomic_write, canonical_json, minimal_bwrap_runtime, which


FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_OPENPGP_METADATA_BYTES = 16 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_VENDOR_TOOL_BYTES = 128 * 1024 * 1024
MAX_TOOL_ADDRESS_SPACE_BYTES = 1024 * 1024 * 1024
MAX_TOOL_CPU_SECONDS = 30
MAX_TOOL_PROCESSES = 32
MAX_TOOL_OPEN_FILES = 64


def _runtime_closure_limitation() -> dict[str, Any]:
    """describe exactly what the executable-file pins do not authenticate."""

    return {
        "schema": 1,
        "limitation_id": "dynamic-runtime-closure-not-bound",
        "status": "incomplete-unbound-host-runtime",
        "closure_cryptographically_bound": False,
        "pinned_executable_files": ["bwrap", "gpg", "gpgv"],
        "unbound_components": [
            "dynamic-loader",
            "shared-libraries",
            "locale-and-message-catalog-data",
            "magic-and-other-runtime-databases",
            "kernel-and-namespace-implementation",
        ],
        "decision": "reject-full-runtime-closure-claim",
    }


def _snapshot_pinned_tool(name: str, expected: str, destination: Path) -> Path:
    """pin one executable file, not its loader/library/kernel runtime closure."""

    path = which(name)
    if path is None:
        raise UmzugError(f"required vendor-verification tool missing: {name}")
    expected = expected.lower()
    if not SHA256_RE.fullmatch(expected):
        raise UmzugError(f"invalid pinned SHA-256 for {name}")
    try:
        original = path.resolve(strict=True)
    except OSError as exc:
        raise UmzugError(f"required vendor-verification tool cannot be resolved safely: {name}") from exc
    _snapshot_regular_file(
        original,
        destination,
        max_bytes=MAX_VENDOR_TOOL_BYTES,
        mode=0o500,
    )
    observed, _size = _snapshot_hash_and_size(destination, required_mode=0o500)
    if observed != expected:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
        raise UmzugError(f"{name} executable does not match its pinned SHA-256")
    return original


def _run_isolated(
    argv: list[str],
    *,
    home: Path,
    bwrap: Path,
    inputs: dict[str, Path],
    tools: dict[str, Path],
    timeout: int = 120,
) -> subprocess.CompletedProcess[bytes]:
    """run offline with isolation, but an explicitly unpinned host runtime closure."""

    if not argv or not all(isinstance(part, str) and "\x00" not in part for part in argv):
        raise UmzugError("invalid vendor signature command vector")
    if tools.get("bwrap") != bwrap:
        raise UmzugError("vendor sandbox must execute the private bwrap snapshot")
    executable_name = Path(argv[0]).name
    if argv[0] != f"/analysis/tools/{executable_name}" or executable_name not in tools:
        raise UmzugError("vendor sandbox must execute a bound private tool snapshot")
    sandbox = [
        str(bwrap),
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--cap-drop",
        "ALL",
        *minimal_bwrap_runtime(),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/analysis",
        "--bind",
        str(home),
        "/analysis/work",
        "--dir",
        "/analysis/tools",
    ]
    for name, path in sorted(inputs.items()):
        if not re.fullmatch(r"[a-z0-9-]+", name):
            raise UmzugError("invalid internal vendor input name")
        sandbox.extend(("--ro-bind", str(path), f"/analysis/{name}"))
    for name, path in sorted(tools.items()):
        if not re.fullmatch(r"[a-z0-9-]+", name):
            raise UmzugError("invalid internal vendor tool name")
        sandbox.extend(("--ro-bind", str(path), f"/analysis/tools/{name}"))
    sandbox.extend(
        (
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/home",
            "--tmpfs",
            "/root",
            "--chdir",
            "/analysis",
            "--clearenv",
            "--setenv",
            "PATH",
            "/analysis/tools",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "GNUPGHOME",
            "/analysis/work",
            "--",
            *argv,
        )
    )
    try:

        def restrict_vendor_parser() -> None:
            limits = (
                ("RLIMIT_FSIZE", MAX_TOOL_OUTPUT_BYTES + 1),
                ("RLIMIT_AS", MAX_TOOL_ADDRESS_SPACE_BYTES),
                ("RLIMIT_CPU", MAX_TOOL_CPU_SECONDS),
                ("RLIMIT_NPROC", MAX_TOOL_PROCESSES),
                ("RLIMIT_NOFILE", MAX_TOOL_OPEN_FILES),
                ("RLIMIT_CORE", 0),
            )
            for resource_name, requested in limits:
                resource_id = getattr(resource, resource_name, None)
                if resource_id is None:
                    raise OSError(f"required vendor resource limit is unavailable: {resource_name}")
                _soft, hard = resource.getrlimit(resource_id)
                effective = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
                if effective < 0:
                    raise OSError(f"invalid vendor resource limit: {resource_name}")
                resource.setrlimit(resource_id, (effective, effective))

        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            completed = subprocess.run(
                sandbox,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                check=False,
                timeout=timeout,
                env={"PATH": "/nonexistent", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                shell=False,
                close_fds=True,
                preexec_fn=restrict_vendor_parser,
            )
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(MAX_TOOL_OUTPUT_BYTES + 1)
            stderr = stderr_file.read(MAX_TOOL_OUTPUT_BYTES + 1)
            if len(stdout) > MAX_TOOL_OUTPUT_BYTES or len(stderr) > MAX_TOOL_OUTPUT_BYTES:
                raise UmzugError("vendor signature tool output exceeded the configured bound")
            return subprocess.CompletedProcess(sandbox, completed.returncode, stdout, stderr)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UmzugError(f"vendor signature tool failed safely: {type(exc).__name__}") from exc


def _snapshot_regular_file(
    path: Path,
    destination: Path,
    *,
    max_bytes: int | None = None,
    mode: int = 0o400,
) -> None:
    """copy one stable, nofollow-opened inode to a private snapshot."""

    if max_bytes is not None and max_bytes <= 0:
        raise UmzugError("vendor snapshot limit must be positive")
    if mode not in (0o400, 0o500):
        raise UmzugError("vendor snapshot mode must be private and immutable")
    if os.path.lexists(destination):
        raise UmzugError(f"vendor snapshot destination already exists: {destination}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UmzugError(f"vendor input cannot be opened safely: {path}") from exc
    output_fd = -1
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise UmzugError(f"vendor input is not a regular file: {path}")
        if max_bytes is not None and before.st_size > max_bytes:
            raise UmzugError(f"vendor input exceeds its bounded snapshot limit: {path}")
        output_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            mode,
        )
        os.fchmod(output_fd, mode)
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise UmzugError(f"vendor input was truncated while snapshotting: {path}")
            remaining -= len(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(output_fd, view) :]
        if os.read(fd, 1):
            raise UmzugError(f"vendor input grew while snapshotting: {path}")
        os.fsync(output_fd)
        after = os.fstat(fd)
        try:
            path_after = path.lstat()
        except OSError as exc:
            raise UmzugError(f"vendor input disappeared while snapshotting: {path}") from exc
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, name) != getattr(after, name) for name in stable_fields):
            raise UmzugError(f"vendor input changed while snapshotting: {path}")
        if any(getattr(after, name) != getattr(path_after, name) for name in stable_fields):
            raise UmzugError(f"vendor input was replaced while snapshotting: {path}")
        snapshot = os.fstat(output_fd)
        if (
            not stat.S_ISREG(snapshot.st_mode)
            or stat.S_IMODE(snapshot.st_mode) != mode
            or snapshot.st_size != before.st_size
        ):
            raise UmzugError(f"vendor snapshot is not a private {mode:04o} regular file")
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
        raise
    finally:
        os.close(fd)
        if output_fd >= 0:
            os.close(output_fd)


def _snapshot_hash_and_size(path: Path, *, required_mode: int = 0o400) -> tuple[str, int]:
    """hash only a completed private snapshot, never a mutable source path."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UmzugError(f"vendor snapshot cannot be opened safely: {path}") from exc
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != required_mode:
            raise UmzugError(f"vendor snapshot is not a private {required_mode:04o} regular file: {path}")
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(fd)
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, name) != getattr(after, name) for name in stable_fields):
            raise UmzugError(f"vendor snapshot changed while hashing: {path}")
        return digest.hexdigest(), before.st_size
    finally:
        os.close(fd)


def _verification_payload(
    *,
    artifact: Path,
    signature: Path,
    signing_key: Path,
    expected_artifact_sha256: str,
    expected_fingerprint: str,
    expected_gpg_sha256: str,
    expected_gpgv_sha256: str,
    expected_bwrap_sha256: str,
) -> dict[str, Any]:
    expected_artifact_sha256 = expected_artifact_sha256.strip().lower()
    if not SHA256_RE.fullmatch(expected_artifact_sha256):
        raise UmzugError("expected vendor artifact SHA-256 must be exactly 64 lowercase hexadecimal digits")
    fingerprint = expected_fingerprint.replace(" ", "").replace(":", "").upper()
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise UmzugError("expected signing-key fingerprint must be exactly 40 hexadecimal digits")
    original_paths = {
        "artifact": artifact.expanduser().absolute(),
        "signature": signature.expanduser().absolute(),
        "signing_key": signing_key.expanduser().absolute(),
    }
    with tempfile.TemporaryDirectory(prefix="umzug-vendor-verification-") as tmp_name:
        private_root = Path(tmp_name)
        os.chmod(private_root, 0o700)
        snapshot_root = private_root / "inputs"
        snapshot_root.mkdir(mode=0o700)
        tool_root = private_root / "tools"
        tool_root.mkdir(mode=0o700)
        tools = {
            "gpg": tool_root / "gpg",
            "gpgv": tool_root / "gpgv",
            "bwrap": tool_root / "bwrap",
        }
        original_tool_paths = {
            "gpg": _snapshot_pinned_tool("gpg", expected_gpg_sha256, tools["gpg"]),
            "gpgv": _snapshot_pinned_tool("gpgv", expected_gpgv_sha256, tools["gpgv"]),
            "bwrap": _snapshot_pinned_tool("bwrap", expected_bwrap_sha256, tools["bwrap"]),
        }
        inputs = {
            "artifact": snapshot_root / "artifact",
            "signature": snapshot_root / "signature",
            "signing-key": snapshot_root / "signing-key",
        }
        _snapshot_regular_file(artifact, inputs["artifact"])
        _snapshot_regular_file(
            signature,
            inputs["signature"],
            max_bytes=MAX_OPENPGP_METADATA_BYTES,
        )
        _snapshot_regular_file(
            signing_key,
            inputs["signing-key"],
            max_bytes=MAX_OPENPGP_METADATA_BYTES,
        )
        captured = {
            "artifact": _snapshot_hash_and_size(inputs["artifact"]),
            "signature": _snapshot_hash_and_size(inputs["signature"]),
            "signing_key": _snapshot_hash_and_size(inputs["signing-key"]),
        }
        if captured["artifact"][0] != expected_artifact_sha256:
            raise UmzugError("vendor artifact differs from the independently obtained release SHA-256")
        home = private_root / "gnupg"
        home.mkdir(mode=0o700)
        os.chmod(home, 0o700)
        show = _run_isolated(
            [
                "/analysis/tools/gpg",
                "--no-options",
                "--batch",
                "--no-auto-key-retrieve",
                "--with-colons",
                "--show-keys",
                "/analysis/signing-key",
            ],
            home=home,
            bwrap=tools["bwrap"],
            inputs=inputs,
            tools=tools,
        )
        if show.returncode != 0:
            raise UmzugError("could not parse the pinned vendor signing key in the offline sandbox")
        primary_fingerprints: list[str] = []
        expect_primary_fpr = False
        for line in show.stdout.decode("utf-8", errors="replace").splitlines():
            fields = line.split(":")
            if fields[0] == "pub":
                expect_primary_fpr = True
            elif fields[0] == "sub":
                expect_primary_fpr = False
            elif fields[0] == "fpr" and expect_primary_fpr and len(fields) > 9:
                primary_fingerprints.append(fields[9].upper())
                expect_primary_fpr = False
        if primary_fingerprints != [fingerprint]:
            raise UmzugError("vendor key file must contain exactly the independently pinned primary key")
        keyring = home / "vendor-keyring.gpg"
        dearmor = _run_isolated(
            [
                "/analysis/tools/gpg",
                "--no-options",
                "--batch",
                "--yes",
                "--dearmor",
                "--output",
                "/analysis/work/vendor-keyring.gpg",
                "/analysis/signing-key",
            ],
            home=home,
            bwrap=tools["bwrap"],
            inputs=inputs,
            tools=tools,
        )
        if dearmor.returncode != 0 or not keyring.is_file():
            raise UmzugError("could not construct isolated vendor keyring")
        verify = _run_isolated(
            [
                "/analysis/tools/gpgv",
                "--keyring",
                "/analysis/work/vendor-keyring.gpg",
                "--",
                "/analysis/signature",
                "/analysis/artifact",
            ],
            home=home,
            bwrap=tools["bwrap"],
            inputs=inputs,
            tools=tools,
        )
        if verify.returncode != 0:
            raise UmzugError("detached vendor signature is invalid")
    return {
        "format": "umzug-vendor-verification-v4",
        "artifact": str(original_paths["artifact"]),
        "artifact_sha256": captured["artifact"][0],
        "expected_artifact_sha256": expected_artifact_sha256,
        "artifact_size": captured["artifact"][1],
        "signature": str(original_paths["signature"]),
        "signature_sha256": captured["signature"][0],
        "signing_key": str(original_paths["signing_key"]),
        "signing_key_sha256": captured["signing_key"][0],
        "signing_key_fingerprint": fingerprint,
        "gpg_path": str(original_tool_paths["gpg"]),
        "gpg_sha256": expected_gpg_sha256.lower(),
        "gpgv_path": str(original_tool_paths["gpgv"]),
        "gpgv_sha256": expected_gpgv_sha256.lower(),
        "bwrap_path": str(original_tool_paths["bwrap"]),
        "bwrap_sha256": expected_bwrap_sha256.lower(),
        "signature_verified": True,
        "isolation": (
            "bubblewrap: user,pid,net,ipc,uts,cgroup; cap-drop ALL; read-only host "
            "runtime mounts that are not cryptographically pinned; private 0400 input "
            "and 0500 executable-file snapshots; hard resource limits"
        ),
        "runtime_closure": _runtime_closure_limitation(),
        "statement": (
            "The artifact matched an independently supplied SHA-256 and its detached "
            "signature verified with the pinned executable files. This does not bind "
            "the dynamic runtime closure and does not establish malware-free contents."
        ),
    }


def verify_detached_openpgp(
    *,
    artifact: Path,
    signature: Path,
    signing_key: Path,
    expected_artifact_sha256: str,
    expected_fingerprint: str,
    expected_gpg_sha256: str,
    expected_gpgv_sha256: str,
    expected_bwrap_sha256: str,
    receipt_path: Path,
) -> dict[str, Any]:
    """verify an offline detached signature with a single fingerprint-pinned key.

    no keyserver, web-of-trust database, network, shell, or filename-derived
    trust is used. the three executable files are pinned by SHA-256; their
    dynamic loader, libraries, runtime data, kernel, and namespace
    implementation are explicitly not authenticated by those file hashes.
    """
    if os.path.lexists(receipt_path):
        raise UmzugError(f"refusing to overwrite vendor receipt: {receipt_path}")
    payload = _verification_payload(
        artifact=artifact,
        signature=signature,
        signing_key=signing_key,
        expected_artifact_sha256=expected_artifact_sha256,
        expected_fingerprint=expected_fingerprint,
        expected_gpg_sha256=expected_gpg_sha256,
        expected_gpgv_sha256=expected_gpgv_sha256,
        expected_bwrap_sha256=expected_bwrap_sha256,
    )
    payload["receipt_sha256"] = hashlib.sha256(canonical_json(payload)).hexdigest()
    atomic_write(receipt_path, canonical_json(payload), 0o600)
    return payload


def load_vendor_receipt(
    receipt_path: Path,
    artifact: Path,
    *,
    expected_artifact_sha256: str,
    expected_fingerprint: str,
    expected_gpg_sha256: str,
    expected_gpgv_sha256: str,
    expected_bwrap_sha256: str,
) -> dict[str, Any]:
    """re-run the proof while preserving its explicit unbound-runtime limitation."""
    try:
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UmzugError(f"invalid vendor receipt: {exc}") from exc
    if not isinstance(value, dict):
        raise UmzugError("invalid vendor receipt root")
    unsigned = dict(value)
    supplied = unsigned.pop("receipt_sha256", None)
    observed = hashlib.sha256(canonical_json(unsigned)).hexdigest()
    if supplied != observed:
        raise UmzugError("vendor receipt integrity hash mismatch")
    if unsigned.get("format") != "umzug-vendor-verification-v4" or unsigned.get("signature_verified") is not True:
        raise UmzugError("vendor receipt does not establish detached-signature verification")
    if unsigned.get("runtime_closure") != _runtime_closure_limitation():
        raise UmzugError("vendor receipt omits or alters the mandatory runtime-closure limitation")
    if Path(str(unsigned.get("artifact"))).resolve() != artifact.resolve():
        raise UmzugError("vendor receipt belongs to another artifact path")
    if (
        str(unsigned.get("signing_key_fingerprint", "")).upper()
        != expected_fingerprint.replace(" ", "").replace(":", "").upper()
    ):
        raise UmzugError("vendor receipt fingerprint differs from the independent plan-time anchor")
    signature = Path(str(unsigned.get("signature", "")))
    signing_key = Path(str(unsigned.get("signing_key", "")))
    current = _verification_payload(
        artifact=artifact,
        signature=signature,
        signing_key=signing_key,
        expected_artifact_sha256=expected_artifact_sha256,
        expected_fingerprint=expected_fingerprint,
        expected_gpg_sha256=expected_gpg_sha256,
        expected_gpgv_sha256=expected_gpgv_sha256,
        expected_bwrap_sha256=expected_bwrap_sha256,
    )
    for key in (
        "artifact_sha256",
        "expected_artifact_sha256",
        "artifact_size",
        "signature_sha256",
        "signing_key_sha256",
        "signing_key_fingerprint",
        "gpg_sha256",
        "gpgv_sha256",
        "bwrap_sha256",
        "runtime_closure",
    ):
        if unsigned.get(key) != current.get(key):
            raise UmzugError(f"vendor receipt changed or is stale: {key}")
    current["receipt_sha256"] = supplied
    return current
