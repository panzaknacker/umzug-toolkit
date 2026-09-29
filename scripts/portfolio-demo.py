#!/usr/bin/env python3
"""Run the local file and rollback regressions."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    (
        "Signiertes Transportpaket prüfen; manipulierten Inhalt ablehnen",
        "tests/test_manifest.py::test_signed_bundle_roundtrip_and_payload_tamper_detection",
        1,
    ),
    (
        "SOURCE → QUARANTINE → SANITIZED → APPROVED → RESTORED; Inhalt vergleichen",
        "tests/test_scanner.py::test_complete_pipeline_moves_only_forward_through_all_trust_zones",
        1,
    ),
    (
        "Unabhängigen Schlüssel und Freigabebeleg vor Restore prüfen",
        "tests/test_restore_trust.py::test_restore_reverification_accepts_independent_key_and_fingerprint",
        1,
    ),
    (
        "Nach Freigabe veränderte Bytes vor Restore ablehnen",
        "tests/test_restore_trust.py::test_restore_reverification_rejects_changed_approved_bytes",
        1,
    ),
    (
        "Restore ohne unabhängigen Vertrauensanker ablehnen",
        "tests/test_restore_trust.py::test_restore_reverification_requires_external_source_anchor",
        1,
    ),
    (
        "Bestehende Zieldatei und Zielverzeichnis unverändert erhalten",
        "tests/test_scanner.py::test_restore_preserves_existing_destination",
        2,
    ),
    (
        "Änderung und neue Datei in einer temporären Systemwurzel zurücksetzen",
        "tests/test_executor.py::test_rollback_restores_backup_and_removes_created_file_under_injected_root",
        1,
    ),
    (
        "Manipuliertes Backup ablehnen, bevor die aktuelle Datei gelöscht wird",
        "tests/test_executor.py::test_rollback_verifies_every_backup_before_deleting_live_target",
        1,
    ),
)


def main() -> int:
    if not sys.platform.startswith("linux") or sys.version_info < (3, 11):
        print("Benötigt Linux und Python 3.11 oder neuer.", file=sys.stderr)
        return 2
    if os.geteuid() == 0:
        print("Diese Komponenten-Demo als normaler Nutzer ausführen, ohne sudo.", file=sys.stderr)
        return 2
    if importlib.util.find_spec("pytest") is None or shutil.which("openssl") is None:
        print("Voraussetzungen fehlen: pytest im verwendeten Python und OpenSSL im PATH.", file=sys.stderr)
        return 2
    print("umzug-toolkit · lokale Komponenten-Demo", flush=True)
    print(f"Python {platform.python_version()} · {platform.system()} {platform.machine()}", flush=True)
    print("Synthetische Daten und temporäre Schlüssel; keine Systemänderungen.", flush=True)
    print("Externe Scanner/Quellmounts sind Test-Fixtures, kein produktiver Clean-Nachweis.\n", flush=True)
    env = dict(os.environ)
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    env.pop("PYTEST_ADDOPTS", None)
    # --basetemp must never name an existing directory supplied by the caller.
    with tempfile.TemporaryDirectory(prefix="umzug-portfolio-") as temporary:
        directory = Path(temporary)
        report = directory / "results.xml"
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--no-header",
            "--tb=short",
            "--color=no",
            "-p",
            "no:cacheprovider",
            "-o",
            "addopts=",
            f"--basetemp={directory / 'cases'}",
            f"--junitxml={report}",
        ]
        command.extend(node for _, node, _ in SCENARIOS)
        try:
            result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            print("Demo nach 180 Sekunden abgebrochen; kein vollständiger Erfolgsnachweis.", file=sys.stderr)
            return 1
        if result.returncode != 0:
            print(result.stdout, end="")
            print(result.stderr, end="", file=sys.stderr)
            print("Demo fehlgeschlagen; kein vollständiger Erfolgsnachweis.", file=sys.stderr)
            return 1
        try:
            cases = list(ET.parse(report).getroot().iter("testcase"))
        except (OSError, ET.ParseError):
            print("Prüfbericht fehlt oder ist ungültig; Demo nicht bestätigt.", file=sys.stderr)
            return 1
        if len(cases) != sum(count for _, _, count in SCENARIOS):
            print("Unerwartete Anzahl Prüffälle; Demo nicht vollständig.", file=sys.stderr)
            return 1
        for title, node, count in SCENARIOS:
            name = node.split("::", 1)[1]
            matched = [case for case in cases if case.get("name", "").split("[", 1)[0] == name]
            if len(matched) != count or any(
                child.tag in {"failure", "error", "skipped"} for case in matched for child in case
            ):
                print(f"FEHLER/ÜBERSPRUNGEN: {title}", file=sys.stderr)
                return 1
            print(f"PASS · {title}")
    print("\n9 Prüffälle bestanden. Temporäre Demo-Daten entfernt.")
    print("Belegt Komponentenverhalten; keine Hardware-, Scanner- oder Produktionsabnahme.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
