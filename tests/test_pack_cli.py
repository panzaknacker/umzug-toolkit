from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
from typing import Any

import pytest

import umzug.manifest as manifest_module
import umzug.pack_cli as pack_cli
from umzug.manifest import safe_extract_bundle, verify_manifest, verify_source_tar_manifest
from umzug.util import UmzugError, run, sha256_file


def _supply_openssl_test_passphrase(monkeypatch: pytest.MonkeyPatch, directory: Path) -> None:
    passphrase_file = directory / "openssl-test-passphrase"
    descriptor = os.open(
        passphrase_file,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        os.write(descriptor, os.urandom(32).hex().encode("ascii") + b"\n")
    finally:
        os.close(descriptor)
    original_run = manifest_module.run

    def run_with_passphrase(argv: list[str], **kwargs: Any) -> Any:
        command = list(argv)
        needs_passphrase = False
        if command[:2] == ["openssl", "genpkey"]:
            command.extend(("-pass", f"file:{passphrase_file}"))
            needs_passphrase = True
        elif command[:2] == ["openssl", "pkey"] and "-pubin" not in command:
            command.extend(("-passin", f"file:{passphrase_file}"))
            needs_passphrase = True
        elif command[:2] == ["openssl", "pkeyutl"] and "-sign" in command:
            command.extend(("-passin", f"file:{passphrase_file}"))
            needs_passphrase = True
        if needs_passphrase:
            assert "input_bytes" not in kwargs
        return original_run(command, **kwargs)

    monkeypatch.setattr(manifest_module, "run", run_with_passphrase)


def test_unknown_noninteractive_config_key_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "pack.toml"
    config.write_text(
        "[pack]\nunknown_security_switch = true\n[[pack.include]]\npath = '/tmp/source'\n",
        encoding="utf-8",
    )
    args = pack_cli._parser().parse_args(["--config", str(config), "--non-interactive", "--dry-run"])
    with pytest.raises(UmzugError, match="unknown pack configuration"):
        pack_cli.execute(args)


def test_incomplete_secret_preview_blocks_plain_default_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    preview = {
        "files": 1,
        "directories": 1,
        "symlinks": 0,
        "bytes": 20_000_000,
        "excluded": [],
        "special": [],
        "unreadable": [],
        "sensitive_candidates": [],
        "content_scan_incomplete": [str(source / "large.bin")],
        "selections": [{"id": "item-0000", "path": str(source), "category": "projects"}],
    }
    monkeypatch.setattr(pack_cli, "preview_selections", lambda *args, **kwargs: preview)
    args = pack_cli._parser().parse_args(["--include", f"projects={source}", "--non-interactive", "--dry-run"])
    with pytest.raises(UmzugError, match="secret preview was incomplete"):
        pack_cli.execute(args)


def test_json_dry_run_emits_one_complete_document(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "notes.txt").write_text("inert notes\n", encoding="utf-8")

    result = pack_cli.main(["--include", f"projects={source}", "--non-interactive", "--dry-run", "--json"])

    assert result == 0
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "dry-run"
    assert document["preview"]["files"] == 1


def test_signing_key_snapshot_rejects_symlink_and_insecure_mode(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    private_key.write_text("private material", encoding="utf-8")
    private_key.chmod(0o600)
    symlink = tmp_path / "key-link.pem"
    symlink.symlink_to(private_key.name)

    with pytest.raises(UmzugError, match="safely snapshot"):
        pack_cli._snapshot_signing_key(symlink, tmp_path / "snapshot-one.pem")

    private_key.chmod(0o640)
    with pytest.raises(UmzugError, match="0600"):
        pack_cli._snapshot_signing_key(private_key, tmp_path / "snapshot-two.pem")


def test_final_publish_never_replaces_target_created_after_precheck(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    destination = tmp_path / "destination"
    staging.mkdir()
    destination.mkdir()
    artifact = staging / "bundle.tar"
    artifact.write_bytes(b"new signed package")
    target = destination / "migration.umzug"
    # this represents a competing file created after pack's early precheck.
    target.write_bytes(b"existing transport data")
    parent_fd = pack_cli.open_directory_chain(destination)
    try:
        with pytest.raises(UmzugError, match="refusing to overwrite"):
            pack_cli._publish_output(artifact, parent_fd, target.name)
    finally:
        pack_cli.os.close(parent_fd)

    assert target.read_bytes() == b"existing transport data"
    assert artifact.read_bytes() == b"new signed package"


@pytest.mark.parametrize(
    "body, message",
    [
        ("[pack]\ninclude = 'wrong'\n", "pack.include"),
        ("[pack]\nexclude = [1]\n", "entries must be strings"),
        ("[pack]\nencrypt = 'invented'\n", "invalid pack encryption mode"),
        ("[pack]\nsplit_size = 42\n", "at least 1 MiB"),
    ],
)
def test_noninteractive_config_types_and_ranges_are_fail_closed(tmp_path: Path, body: str, message: str) -> None:
    config = tmp_path / "pack.toml"
    config.write_text(body, encoding="utf-8")
    args = pack_cli._parser().parse_args(["--config", str(config), "--non-interactive", "--dry-run"])
    with pytest.raises(UmzugError, match=message):
        pack_cli.execute(args)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is not installed")
@pytest.mark.parametrize("generated_key", [False, True], ids=("external-key", "generated-key"))
def test_real_pack_keeps_openssl_fd_anchored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    generated_key: bool,
) -> None:
    source = tmp_path / "synthetic-source"
    source.mkdir()
    (source / "notes.txt").write_text("inert offline fixture\n", encoding="utf-8")
    (source / "current-notes").symlink_to("notes.txt")

    key_directory = tmp_path / "keys"
    key_directory.mkdir(mode=0o700)
    private_key = key_directory / "signing-private.pem"
    trusted_public_key = private_key.with_suffix(".pem.pub")
    if generated_key:
        _supply_openssl_test_passphrase(monkeypatch, tmp_path)
        key_option = "--generate-signing-key"
    else:
        run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)])
        private_key.chmod(0o600)
        manifest_module.public_key_for(private_key, trusted_public_key)
        key_option = "--signing-key"

    bundle = tmp_path / "transport" / "migration.bundle.tar"
    args = pack_cli._parser().parse_args(
        [
            "--output",
            str(bundle),
            "--include",
            f"projects={source}",
            "--non-interactive",
            key_option,
            str(private_key),
            "--encrypt",
            "none",
            "--source-date-epoch",
            "1767225600",
        ]
    )

    result = pack_cli.execute(args)

    assert result["status"] == "created"
    assert result["sha256"] == sha256_file(bundle)
    assert result["signing_key_fingerprint"] == manifest_module.public_key_fingerprint(trusted_public_key)
    assert result["preview"]["files"] == 1
    assert result["preview"]["symlinks"] == 1
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o600
    assert stat.S_IMODE(private_key.stat().st_mode) == 0o600
    assert trusted_public_key.is_file()
    if generated_key:
        with private_key.open("rb") as handle:
            assert handle.readline() == b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    assert [path.name for path in bundle.parent.iterdir()] == [bundle.name]

    extracted = safe_extract_bundle(bundle, tmp_path / "verified-bundle")
    verify_manifest(
        extracted["umzug/manifest.json"],
        extracted["umzug/manifest.sig"],
        trusted_public_key,
    )
    manifest = json.loads(extracted["umzug/manifest.json"].read_text(encoding="utf-8"))
    verify_source_tar_manifest(extracted["umzug/SOURCE.tar"], manifest)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="OpenSSL is not installed")
def test_real_pack_is_byte_reproducible_with_source_date_epoch(tmp_path: Path) -> None:
    source = tmp_path / "synthetic-source"
    source.mkdir()
    (source / "notes.txt").write_text("inert offline fixture\n", encoding="utf-8")
    (source / "current-notes").symlink_to("notes.txt")

    key_directory = tmp_path / "keys"
    key_directory.mkdir(mode=0o700)
    private_key = key_directory / "signing-private.pem"
    run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)])
    private_key.chmod(0o600)

    epoch = 1_767_225_600
    bundles = [tmp_path / "first.bundle.tar", tmp_path / "second.bundle.tar"]
    results = []
    for bundle in bundles:
        args = pack_cli._parser().parse_args(
            [
                "--output",
                str(bundle),
                "--include",
                f"projects={source}",
                "--non-interactive",
                "--signing-key",
                str(private_key),
                "--encrypt",
                "none",
                "--source-date-epoch",
                str(epoch),
            ]
        )
        results.append(pack_cli.execute(args))

    assert results[0]["sha256"] == results[1]["sha256"]
    assert bundles[0].read_bytes() == bundles[1].read_bytes()
    extracted = safe_extract_bundle(bundles[0], tmp_path / "verified-reproducible-bundle")
    manifest = json.loads(extracted["umzug/manifest.json"].read_text(encoding="utf-8"))
    assert manifest["created_at"] == "2026-01-01T00:00:00Z"
