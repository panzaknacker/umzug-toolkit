# Projektstatus

- Stand: Release Candidate 0.2.0rc1
- Umfang: Offline-Migration, Quarantäne, Freigabe, Restore und Linux-Härtung
- Vorgesehene Nutzung: kontrollierte Evaluierung und die dokumentierte H0-Hardware-Baseline
- Produktionssupport: keiner
- Lizenz: GPL-3.0-or-later

## Lokale Prüfung: 21.09.2026

Unter Arch Linux mit Python 3.14.7 und pytest 9.1.1:

- Komponenten-Demo: neun Fälle bestanden, keiner übersprungen.
- Vollständige lokale Suite: 508 Tests und drei Subtests bestanden.
- Syntax, YARA-Kompilierung und byteidentischer doppelter Offline-Build
  bestanden.
- Eine Nachprüfung mit der ältesten unterstützten Python-Linie (3.11.15)
  bestand dieselbe vollständige Suite, Demo, YARA und den reproduzierbaren Build,
  jetzt einschließlich ShellCheck 0.11.0.
- Ein echter Transport-Smoketest mit der Pack-CLI bestand unter Python 3.11.15
  und 3.14.7: Signatur, exakte extrahierte Bytes, Ablehnung von Manipulation und
  Erhalt eines bestehenden Ziels.

[Befehle und Protokolle](docs/VALIDATION.md).

Der Fedora-/SELinux-Lauf vom 19. September hatte 500 bestandene und acht
fehlgeschlagene Tests. Die aktuellen Testdateien hatten kein
`security.selinux`-Label; das neue Ergebnis löst diese
[Kompatibilitätsgrenze](docs/KNOWN-ISSUES.md) nicht.

## Offene Arbeit

- Gehostete CI beobachten; GitHub Actions bleiben deaktiviert.
- Die verbleibende [H0-Hardwarequalifikation](docs/HARDWARE-TEST.md)
  abschließen.
- Privilegierten CLI-Restore, echte Scanner und unterstützte Zielumgebungen
  qualifizieren.
- Migrationspakete, Signaturschlüssel und Betreiberzustand außerhalb von Git
  halten.

## Lokale Qualitätsprüfung

```sh
./scripts/static-checks.sh
gitleaks dir --config .gitleaks.toml .
```

Der Snapshot vom 4. September hielt 506 Tests und drei Subtests fest. Zwei
Regressionsfälle für Restore-Ziele kamen während der Portfolio-Vorbereitung
hinzu; produktive Schutzfunktionen wurden nicht geändert.
