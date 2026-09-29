from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

import umzug.vendor as vendor
from umzug.util import UmzugError, canonical_json


FINGERPRINT = "A" * 40
GPG_HASH = "1" * 64
GPGV_HASH = "2" * 64
BWRAP_HASH = "3" * 64


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    artifact = tmp_path / "vendor.deb"
    signature = tmp_path / "vendor.deb.asc"
    key = tmp_path / "vendor.asc"
    artifact.write_bytes(b"package bytes")
    signature.write_bytes(b"detached signature")
    key.write_bytes(b"public key")
    return artifact, signature, key


def _fake_snapshot_pinned_tool(name: str, expected: str, destination: Path) -> Path:
    del expected
    destination.write_bytes(f"private {name} executable".encode())
    destination.chmod(0o500)
    return Path(f"/usr/bin/{name}")


def _fake_tools_and_runs(monkeypatch: pytest.MonkeyPatch, *, signature_valid: bool = True) -> list[list[str]]:
    monkeypatch.setattr(vendor, "_snapshot_pinned_tool", _fake_snapshot_pinned_tool)
    calls: list[list[str]] = []

    def fake_run(
        argv: list[str],
        *,
        home: Path,
        bwrap: Path,
        inputs: dict[str, Path],
        tools: dict[str, Path],
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[bytes]:
        del bwrap, inputs, tools, timeout
        calls.append(argv)
        if "--show-keys" in argv:
            output = f"pub:-:255:22:KEY::::::\nfpr:::::::::{FINGERPRINT}:\n".encode()
            return subprocess.CompletedProcess(argv, 0, output, b"")
        if "--dearmor" in argv:
            (home / "vendor-keyring.gpg").write_bytes(b"keyring")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        return subprocess.CompletedProcess(argv, 0 if signature_valid else 1, b"", b"invalid")

    monkeypatch.setattr(vendor, "_run_isolated", fake_run)
    return calls


def test_receipt_is_reverified_with_independent_plan_time_anchors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact, signature, key = _inputs(tmp_path)
    receipt = tmp_path / "receipt.json"
    calls = _fake_tools_and_runs(monkeypatch)
    created = vendor.verify_detached_openpgp(
        artifact=artifact,
        signature=signature,
        signing_key=key,
        expected_artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        expected_fingerprint=FINGERPRINT,
        expected_gpg_sha256=GPG_HASH,
        expected_gpgv_sha256=GPGV_HASH,
        expected_bwrap_sha256=BWRAP_HASH,
        receipt_path=receipt,
    )
    assert created["format"] == "umzug-vendor-verification-v4"
    closure = created["runtime_closure"]
    assert closure["closure_cryptographically_bound"] is False
    assert closure["decision"] == "reject-full-runtime-closure-claim"
    assert set(closure["unbound_components"]) == {
        "dynamic-loader",
        "shared-libraries",
        "locale-and-message-catalog-data",
        "magic-and-other-runtime-databases",
        "kernel-and-namespace-implementation",
    }
    assert "not cryptographically pinned" in created["isolation"]
    assert "does not bind the dynamic runtime closure" in created["statement"]
    assert len(calls) == 3

    loaded = vendor.load_vendor_receipt(
        receipt,
        artifact,
        expected_artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        expected_fingerprint=FINGERPRINT,
        expected_gpg_sha256=GPG_HASH,
        expected_gpgv_sha256=GPGV_HASH,
        expected_bwrap_sha256=BWRAP_HASH,
    )
    assert loaded["artifact_sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert len(calls) == 6  # show/dearmor/gpgv really ran again; JSON was not trusted.


def test_independent_artifact_hash_mismatch_fails_before_signature_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact, signature, key = _inputs(tmp_path)
    receipt = tmp_path / "receipt.json"
    calls = _fake_tools_and_runs(monkeypatch)

    with pytest.raises(UmzugError, match="independently obtained release SHA-256"):
        vendor.verify_detached_openpgp(
            artifact=artifact,
            signature=signature,
            signing_key=key,
            expected_artifact_sha256="0" * 64,
            expected_fingerprint=FINGERPRINT,
            expected_gpg_sha256=GPG_HASH,
            expected_gpgv_sha256=GPGV_HASH,
            expected_bwrap_sha256=BWRAP_HASH,
            receipt_path=receipt,
        )

    assert calls == []
    assert not receipt.exists()


def test_recomputed_unkeyed_receipt_cannot_replace_independent_fingerprint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact, signature, key = _inputs(tmp_path)
    receipt = tmp_path / "receipt.json"
    _fake_tools_and_runs(monkeypatch)
    vendor.verify_detached_openpgp(
        artifact=artifact,
        signature=signature,
        signing_key=key,
        expected_artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        expected_fingerprint=FINGERPRINT,
        expected_gpg_sha256=GPG_HASH,
        expected_gpgv_sha256=GPGV_HASH,
        expected_bwrap_sha256=BWRAP_HASH,
        receipt_path=receipt,
    )
    forged = json.loads(receipt.read_text(encoding="utf-8"))
    forged.pop("receipt_sha256")
    forged["signing_key_fingerprint"] = "B" * 40
    forged["receipt_sha256"] = hashlib.sha256(canonical_json(forged)).hexdigest()
    receipt.write_bytes(canonical_json(forged))

    with pytest.raises(UmzugError, match="independent plan-time anchor"):
        vendor.load_vendor_receipt(
            receipt,
            artifact,
            expected_artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            expected_fingerprint=FINGERPRINT,
            expected_gpg_sha256=GPG_HASH,
            expected_gpgv_sha256=GPGV_HASH,
            expected_bwrap_sha256=BWRAP_HASH,
        )


def test_recomputed_unkeyed_receipt_cannot_hide_runtime_closure_limitation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact, signature, key = _inputs(tmp_path)
    receipt = tmp_path / "receipt.json"
    _fake_tools_and_runs(monkeypatch)
    vendor.verify_detached_openpgp(
        artifact=artifact,
        signature=signature,
        signing_key=key,
        expected_artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        expected_fingerprint=FINGERPRINT,
        expected_gpg_sha256=GPG_HASH,
        expected_gpgv_sha256=GPGV_HASH,
        expected_bwrap_sha256=BWRAP_HASH,
        receipt_path=receipt,
    )
    forged = json.loads(receipt.read_text(encoding="utf-8"))
    forged.pop("receipt_sha256")
    forged.pop("runtime_closure")
    forged["receipt_sha256"] = hashlib.sha256(canonical_json(forged)).hexdigest()
    receipt.write_bytes(canonical_json(forged))

    with pytest.raises(UmzugError, match="runtime-closure limitation"):
        vendor.load_vendor_receipt(
            receipt,
            artifact,
            expected_artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            expected_fingerprint=FINGERPRINT,
            expected_gpg_sha256=GPG_HASH,
            expected_gpgv_sha256=GPGV_HASH,
            expected_bwrap_sha256=BWRAP_HASH,
        )


def test_vendor_parser_wrapper_unshares_network_and_mounts_inputs_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact, _, _ = _inputs(tmp_path)
    captured: list[str] = []
    gpg = tmp_path / "gpg.snapshot"
    bwrap = tmp_path / "bwrap.snapshot"
    gpg.write_bytes(b"gpg")
    bwrap.write_bytes(b"bwrap")
    gpg.chmod(0o500)
    bwrap.chmod(0o500)

    def fake_subprocess_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured.extend(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(vendor.subprocess, "run", fake_subprocess_run)
    result = vendor._run_isolated(
        ["/analysis/tools/gpg", "--version"],
        home=tmp_path,
        bwrap=bwrap,
        inputs={"artifact": artifact},
        tools={"gpg": gpg, "bwrap": bwrap},
    )

    assert result.returncode == 0
    assert captured[0] == str(bwrap)
    assert "--unshare-net" in captured
    assert captured[captured.index("--cap-drop") + 1] == "ALL"
    assert not any(captured[index : index + 3] == ["--ro-bind", "/", "/"] for index in range(len(captured) - 2))
    assert "/usr" in captured
    binding = captured.index(str(artifact.resolve()))
    assert captured[binding - 1] == "--ro-bind"
    assert captured[binding + 1] == "/analysis/artifact"
    tool_binding = captured.index(str(gpg))
    assert captured[tool_binding - 1] == "--ro-bind"
    assert captured[tool_binding + 1] == "/analysis/tools/gpg"


def test_vendor_gpg_runs_use_private_snapshots_during_source_a_b_a_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact, signature, key = _inputs(tmp_path)
    originals = {
        "artifact": artifact.read_bytes(),
        "signature": signature.read_bytes(),
        "signing-key": key.read_bytes(),
    }
    original_paths = {artifact.resolve(), signature.resolve(), key.resolve()}
    observed_inputs: list[dict[str, Path]] = []
    monkeypatch.setattr(vendor, "_snapshot_pinned_tool", _fake_snapshot_pinned_tool)

    def isolated(
        argv: list[str],
        *,
        home: Path,
        bwrap: Path,
        inputs: dict[str, Path],
        tools: dict[str, Path],
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[bytes]:
        del bwrap, tools, timeout
        observed_inputs.append(dict(inputs))
        for name, snapshot in inputs.items():
            assert snapshot.resolve() not in original_paths
            assert snapshot.read_bytes() == originals[name]
            assert stat.S_IMODE(snapshot.stat().st_mode) == 0o400
            assert stat.S_IMODE(snapshot.parent.stat().st_mode) == 0o700
        if len(observed_inputs) == 1:
            artifact.write_bytes(b"transient replacement")
            signature.write_bytes(b"transient signature")
            key.write_bytes(b"transient key")
            artifact.write_bytes(originals["artifact"])
            signature.write_bytes(originals["signature"])
            key.write_bytes(originals["signing-key"])
        if "--show-keys" in argv:
            output = f"pub:-:255:22:KEY::::::\nfpr:::::::::{FINGERPRINT}:\n".encode()
            return subprocess.CompletedProcess(argv, 0, output, b"")
        if "--dearmor" in argv:
            (home / "vendor-keyring.gpg").write_bytes(b"keyring")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(vendor, "_run_isolated", isolated)
    receipt = vendor.verify_detached_openpgp(
        artifact=artifact,
        signature=signature,
        signing_key=key,
        expected_artifact_sha256=hashlib.sha256(originals["artifact"]).hexdigest(),
        expected_fingerprint=FINGERPRINT,
        expected_gpg_sha256=GPG_HASH,
        expected_gpgv_sha256=GPGV_HASH,
        expected_bwrap_sha256=BWRAP_HASH,
        receipt_path=tmp_path / "receipt.json",
    )

    assert receipt["artifact_sha256"] == hashlib.sha256(originals["artifact"]).hexdigest()
    assert len(observed_inputs) == 3
    first = observed_inputs[0]
    assert all(row == first for row in observed_inputs)
    assert all(not os.path.lexists(path) for path in first.values())


def test_vendor_tool_runs_use_private_snapshots_during_source_a_b_a_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact, signature, key = _inputs(tmp_path)
    tool_root = tmp_path / "original-tools"
    tool_root.mkdir()
    original_tools = {name: tool_root / name for name in ("gpg", "gpgv", "bwrap")}
    original_bytes = {name: f"trusted executable {name}".encode() for name in original_tools}
    for name, path in original_tools.items():
        path.write_bytes(original_bytes[name])
        path.chmod(0o755)
    expected_hashes = {name: hashlib.sha256(contents).hexdigest() for name, contents in original_bytes.items()}
    monkeypatch.setattr(vendor, "which", lambda name: original_tools.get(name))
    observed_tools: list[dict[str, Path]] = []

    def isolated(
        argv: list[str],
        *,
        home: Path,
        bwrap: Path,
        inputs: dict[str, Path],
        tools: dict[str, Path],
        timeout: int = 120,
    ) -> subprocess.CompletedProcess[bytes]:
        del inputs, timeout
        observed_tools.append(dict(tools))
        assert bwrap == tools["bwrap"]
        for name, snapshot in tools.items():
            assert snapshot.resolve() != original_tools[name].resolve()
            assert snapshot.read_bytes() == original_bytes[name]
            assert stat.S_IMODE(snapshot.stat().st_mode) == 0o500
            assert stat.S_IMODE(snapshot.parent.stat().st_mode) == 0o700
            assert str(original_tools[name]) not in argv
        if len(observed_tools) == 1:
            for name, path in original_tools.items():
                path.write_bytes(f"attacker replacement {name}".encode())
                path.write_bytes(original_bytes[name])
                path.chmod(0o755)
        if "--show-keys" in argv:
            output = f"pub:-:255:22:KEY::::::\nfpr:::::::::{FINGERPRINT}:\n".encode()
            return subprocess.CompletedProcess(argv, 0, output, b"")
        if "--dearmor" in argv:
            (home / "vendor-keyring.gpg").write_bytes(b"keyring")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(vendor, "_run_isolated", isolated)
    receipt = vendor.verify_detached_openpgp(
        artifact=artifact,
        signature=signature,
        signing_key=key,
        expected_artifact_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        expected_fingerprint=FINGERPRINT,
        expected_gpg_sha256=expected_hashes["gpg"],
        expected_gpgv_sha256=expected_hashes["gpgv"],
        expected_bwrap_sha256=expected_hashes["bwrap"],
        receipt_path=tmp_path / "receipt.json",
    )

    assert receipt["gpg_sha256"] == expected_hashes["gpg"]
    assert receipt["gpgv_sha256"] == expected_hashes["gpgv"]
    assert receipt["bwrap_sha256"] == expected_hashes["bwrap"]
    assert len(observed_tools) == 3
    first = observed_tools[0]
    assert all(row == first for row in observed_tools)
    assert all(not os.path.lexists(path) for path in first.values())


def test_vendor_parser_applies_all_hard_resource_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact, _, _ = _inputs(tmp_path)
    gpg = tmp_path / "gpg.snapshot"
    bwrap = tmp_path / "bwrap.snapshot"
    gpg.write_bytes(b"gpg")
    bwrap.write_bytes(b"bwrap")
    gpg.chmod(0o500)
    bwrap.chmod(0o500)
    applied: dict[int, tuple[int, int]] = {}

    monkeypatch.setattr(
        vendor.resource,
        "getrlimit",
        lambda resource_id: (vendor.resource.RLIM_INFINITY, vendor.resource.RLIM_INFINITY),
    )
    monkeypatch.setattr(
        vendor.resource,
        "setrlimit",
        lambda resource_id, limits: applied.__setitem__(resource_id, limits),
    )

    def fake_subprocess_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        preexec_fn = kwargs["preexec_fn"]
        assert callable(preexec_fn)
        preexec_fn()
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(vendor.subprocess, "run", fake_subprocess_run)
    result = vendor._run_isolated(
        ["/analysis/tools/gpg", "--version"],
        home=tmp_path,
        bwrap=bwrap,
        inputs={"artifact": artifact},
        tools={"gpg": gpg, "bwrap": bwrap},
    )

    assert result.returncode == 0
    assert applied == {
        vendor.resource.RLIMIT_FSIZE: (vendor.MAX_TOOL_OUTPUT_BYTES + 1,) * 2,
        vendor.resource.RLIMIT_AS: (vendor.MAX_TOOL_ADDRESS_SPACE_BYTES,) * 2,
        vendor.resource.RLIMIT_CPU: (vendor.MAX_TOOL_CPU_SECONDS,) * 2,
        vendor.resource.RLIMIT_NPROC: (vendor.MAX_TOOL_PROCESSES,) * 2,
        vendor.resource.RLIMIT_NOFILE: (vendor.MAX_TOOL_OPEN_FILES,) * 2,
        vendor.resource.RLIMIT_CORE: (0, 0),
    }
