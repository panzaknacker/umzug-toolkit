# umzug-toolkit

Kontrollierte Linux-Datenübernahme beim Wechsel von Hardware oder Distribution.
Die Python-Werkzeuge trennen signierten Transport, Quarantäne, Prüfung,
ausdrückliche Freigabe und Restore. Checkpoints und Rollback begleiten Systemänderungen.

Entstanden aus dem Bedarf, eigene Daten und Einstellungen zwischen Laptops
und PCs zu übernehmen. [Hintergrund und Entscheidungen](docs/PORTFOLIO.md).

**Release Candidate `v0.2.0rc1`.** Die Evaluierung beschränkt sich auf die
dokumentierte H0-Offline-Baseline mit entbehrlicher Debian-/Ubuntu-Hardware
und systemd. Die Hardwarequalifikation ist offen. Andere Plattformen,
`strict`/`maximal`, Mullvad/H2 und Produktivbetrieb sind nicht qualifiziert.
[Projektstatus](PROJECT_STATUS.md) · [Hardwareumfang](docs/HARDWARE-TEST.md).

## Lokal ausprobieren

Voraussetzungen: Linux, Python 3.11+, pytest und OpenSSL. Die Beispiele laufen
mit temporären Dateien und Schlüsseln, ohne Root und ohne Systemänderungen.

```sh
python scripts/portfolio-demo.py
python scripts/transport-smoke.py
```

Die Komponenten-Demo prüft neun Fälle zu Signaturen, Freigaben, Restore und
Rollback. Der Transporttest verwendet die echte Pack-CLI und prüft signierten
Transport, exakte extrahierte Bytes, Manipulationsabwehr und Erhalt eines
vorhandenen Ziels. Scanner und privilegierter Restore gehören nicht zu diesem Test.
[Einrichtung und erwartete Ausgabe](docs/DEMO.md).

Für die vollständigen lokalen Prüfungen:

```sh
./scripts/static-checks.sh
```

Der Lauf umfasst Syntax, Tests und einen byteidentischen doppelten Offline-Wheel-Build.
ShellCheck und YARA werden bei vorhandenen Werkzeugen verwendet; übersprungene
Prüfungen müssen genannt werden. [Befehle und Protokolle](docs/VALIDATION.md).

## Ablauf der Datenübernahme

```mermaid
flowchart LR
    source[Quelle] --> quarantine[Quarantäne]
    quarantine --> sanitized[Bereinigt]
    sanitized --> approved[Freigegeben]
    approved --> restored[Wiederhergestellt]
```

Manifeste und Hashes binden die Übergänge an konkrete Daten. Quellmounts brauchen
`ro,noexec,nodev,nosuid`. Scanner laufen mit Limits und festgelegten Werkzeugen
in einer netzlosen Bubblewrap-Umgebung. Unanalysierbare Inhalte werden blockiert;
Restore verlangt eine ausdrückliche Freigabe.

Vorhandene Ziele bleiben erhalten. Execute-, SUID-/SGID-Bits, ACLs, xattrs und
Capabilities werden nicht übernommen. Das Quellsystem bleibt untrusted;
Signaturen und Scannerergebnisse garantieren keine Malwarefreiheit.
[Threat Model](docs/THREAT-MODEL.md).

## Nachweise und bekannte Grenzen

Die September-Läufe auf Arch Linux bestanden 508 Tests und drei Subtests,
Demo und reproduzierbaren Build, einschließlich einer Nachprüfung mit Python 3.11.15.
Der frühere Fedora-/SELinux-Lauf hatte acht fehlerhafte Metadaten-Restore-Tests.
Das grüne Arch-Ergebnis behebt diese SELinux-Grenze nicht.
[Umgebungsspezifische Ergebnisse](docs/VALIDATION.md) ·
[SELinux-Befund](docs/KNOWN-ISSUES.md) ·
[Aktuelle lokale Nachprüfung](docs/LOCAL-REVIEW-2026-10-01.md).

Der Planer zeigt Diffs und verlangt Bestätigung. Backups und Checkpoints
ermöglichen Fortsetzung und Rollback. Systemd- und Firewall-Guards können bei
Fehlern Boot oder Netzwerk bewusst sperren. Automatische Partitionierung,
vollständige Benutzer-/Gruppenmigration, FDE, Secure-Boot-Key-Enrollment und
allgemeines CDR fehlen. Mullvad ist ein separater letzter Netzschritt.
[Handbuch](docs/USER-GUIDE.md) · [Einschränkungen](docs/LIMITATIONS.md).

Die [GitHub-Workflows](https://github.com/panzaknacker/umzug-toolkit/actions)
sind von lokalen Ergebnissen getrennt. Der [CI-Startfehler](docs/HOSTED-CI.md) ist dokumentiert.

## Dokumentation

- [Demo](docs/DEMO.md) · [Prüfstand](docs/VALIDATION.md) · [Projektstatus](PROJECT_STATUS.md)
- [Architektur](docs/ARCHITECTURE.md) · [Betriebsbeispiel](docs/EXAMPLE-WORKFLOW.md)
- [Recovery](docs/RECOVERY.md) · [Offline-Build](docs/OFFLINE-BUILD.md)
- [Tests](docs/TESTING.md) · [Hardwarequalifikation](docs/HARDWARE-TEST.md)
- [Beiträge](CONTRIBUTING.md) · [Sicherheitsmeldungen](SECURITY.md)

## Lizenz

[GPL-3.0-or-later](LICENSE).
