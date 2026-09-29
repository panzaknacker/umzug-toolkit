# umzug-toolkit

umzug-toolkit hilft dabei, Daten bei Hardware- und Distributionswechseln
kontrolliert auf ein neues Linux-System zu übernehmen. Entstanden ist es aus
meinen eigenen Wechseln zwischen Laptops und PCs; gedacht ist es für technisch
versierte Linux-Nutzer.

`umzug-pack` erstellt ein signiertes, optional verschlüsseltes Transportpaket.
`umzug-setup` prüft es offline auf dem Ziel und führt geplante Änderungen erst
nach ausdrücklicher Freigabe aus.

**Release Candidate `v0.2.0rc1`.** Der vorgesehene Hardwareumfang ist der
reversible H0-Offline-Basislauf auf entbehrlicher Debian-/Ubuntu-Hardware mit
systemd. Weitere Plattformen, `strict`/`maximal`, Mullvad/H2 und Produktivbetrieb
sind nicht qualifiziert. [Status](PROJECT_STATUS.md),
[Hardwaretest](docs/HARDWARE-TEST.md).

## Lokal ausprobieren

```sh
python scripts/portfolio-demo.py
```

Benötigt werden Linux, Python 3.11+, pytest und OpenSSL. Die Demo läuft ohne
Root mit temporären Dateien und Schlüsseln. Sie prüft Signaturen, Freigaben,
Restore und Rollback anhand vorhandener Regressionstests.
[Einrichtung und Ablauf](docs/DEMO.md).

Für die vollständigen lokalen Prüfungen:

```sh
./scripts/static-checks.sh
```

[Prüfergebnisse](docs/VALIDATION.md) und
[offene SELinux-Kompatibilitätsgrenze](docs/KNOWN-ISSUES.md).

## Daten übernehmen

`SOURCE` → `QUARANTINE` → `SANITIZED` → `APPROVED` → `RESTORED`

Manifeste und Hashes binden die Schritte an konkrete Daten. Quellmounts müssen
`ro,noexec,nodev,nosuid` sein. Scanner laufen mit Limits und festgelegten
Werkzeugen in einer netzlosen Bubblewrap-Umgebung. Unanalysierbare Inhalte
werden blockiert; nur freigegebene Daten dürfen in den Restore.

Restore überschreibt keine vorhandenen Ziele und übernimmt keine Execute-,
SUID-/SGID-Bits, ACLs, xattrs oder Capabilities. Das alte System bleibt untrusted;
auch gültige Signaturen und Scannerergebnisse garantieren keine Malwarefreiheit.
[Bedrohungsmodell](docs/THREAT-MODEL.md).

## Systemänderungen

Der Planer zeigt Diffs und verlangt Bestätigung. Backups und Checkpoints
ermöglichen Fortsetzung und Rollback. Systemd-Offline-Guard und Firewall bilden
Boot-Schranken; ein Ladefehler kann nach `emergency.target` isolieren.

Automatische Partitionierung, vollständige Benutzer-/Gruppenmigration, FDE,
Secure-Boot-Key-Enrollment und allgemeines CDR fehlen. Mullvad ist ein separat
ausgelöster letzter Netzschritt. Details stehen im
[Handbuch](docs/USER-GUIDE.md) und unter [Einschränkungen](docs/LIMITATIONS.md).

## Dokumentation

- [Projekt und Entscheidungen](docs/PORTFOLIO.md)
- [Betriebsbeispiel](docs/EXAMPLE-WORKFLOW.md) und [Architektur](docs/ARCHITECTURE.md)
- [Recovery](docs/RECOVERY.md) und [Offline-Build](docs/OFFLINE-BUILD.md)
- [Tests](docs/TESTING.md) und [historische VM-Abnahme](docs/LIVE-VM-TEST-2026-07-15.md)
- [Beiträge](CONTRIBUTING.md) und [Sicherheitsmeldungen](SECURITY.md)

GPL-3.0-or-later, siehe [LICENSE](LICENSE).
