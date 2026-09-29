#!/usr/bin/env python3
"""Pack and verify synthetic files with the real CLI and OpenSSL."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60)


def main() -> None:
    if not sys.platform.startswith("linux") or os.geteuid() == 0:
        raise SystemExit("Run this smoke check on Linux as a normal user, without sudo.")
    if shutil.which("openssl") is None:
        raise SystemExit("OpenSSL is required in PATH.")

    sys.path.insert(0, str(ROOT / "src"))
    from umzug.manifest import (
        load_and_verify_manifest,
        safe_extract_bundle,
        safe_extract_source,
        verify_source_tar_manifest,
    )
    from umzug.util import UmzugError

    with tempfile.TemporaryDirectory(prefix="umzug-transport-smoke-") as temporary:
        directory = Path(temporary)
        source = directory / "source"
        source.mkdir(mode=0o700)
        content = b"Synthetic offline transport example.\n"
        (source / "notes.txt").write_bytes(content)
        private_key = directory / "signing.pem"
        trusted_key = directory / "trusted.pem"
        # The unencrypted throwaway key never leaves this private test directory.
        run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)])
        private_key.chmod(0o600)
        run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(trusted_key)])
        bundle = directory / "transport.bundle.tar"
        command = [
            sys.executable,
            str(ROOT / "pack"),
            "--non-interactive",
            "--json",
            "--include",
            f"projects={source}",
            "--signing-key",
            str(private_key),
            "--encrypt",
            "none",
            "--output",
            str(bundle),
            "--source-date-epoch",
            "1767225600",
        ]
        result = json.loads(run(command).stdout)
        if result["status"] != "created":
            raise RuntimeError("Pack CLI did not create the transport bundle.")
        original_bundle = bundle.read_bytes()
        repeated = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if repeated.returncode != 2 or bundle.read_bytes() != original_bundle:
            raise RuntimeError("Pack CLI did not preserve the existing transport target.")
        extracted = safe_extract_bundle(bundle, directory / "bundle")
        manifest, _ = load_and_verify_manifest(extracted, trusted_public_key=trusted_key, expected_fingerprint=None)
        payload = extracted["umzug/SOURCE.tar"]
        verify_source_tar_manifest(payload, manifest)
        restored = directory / "extracted-source"
        if safe_extract_source(payload, restored):
            raise RuntimeError("Source extraction reported errors.")
        target = restored / manifest["selections"][0]["archive_root"] / "notes.txt"
        if target.read_bytes() != content:
            raise RuntimeError("Extracted bytes differ from the selected source.")
        print("PASS: real Pack CLI, independent public key, signature, manifest and exact extracted bytes.")
        print("PASS: existing transport target preserved.")
        changed = bytearray(payload.read_bytes())
        changed[len(changed) // 2] ^= 1
        payload.write_bytes(changed)
        try:
            load_and_verify_manifest(extracted, trusted_public_key=trusted_key, expected_fingerprint=None)
        except UmzugError as error:
            if "checksum mismatch" not in str(error):
                raise
        else:
            raise RuntimeError("Changed payload was accepted.")
        print("PASS: changed payload rejected.")
    print("Temporary data and keys removed. Transport only; no scanner, approval or privileged restore claim.")


if __name__ == "__main__":
    main()
