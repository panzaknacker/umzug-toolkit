# Beiträge

Mit [Testleitfaden](docs/TESTING.md) und [PROJECT_STATUS.md](PROJECT_STATUS.md) beginnen.
Änderungen fokussiert halten und Problem, Verhalten sowie betroffene
Vertrauensgrenzen erläutern.

## Lokale Prüfung

Linux, Python 3.11+, OpenSSL, Git und pytest in einer isolierten Umgebung
bereitstellen.

```sh
./scripts/static-checks.sh
python scripts/portfolio-demo.py
python scripts/transport-smoke.py
```

Der Gesamtlauf umfasst Syntax, Tests und einen doppelten Offline-Wheel-Build.
Nennen, ob die optionalen ShellCheck-/YARA-Prüfungen liefen. Die
[SELinux-Grenze](docs/KNOWN-ISSUES.md) bei Ergebnissen sichtbar halten.

Tatsächlich ausgeführte Befehle, Umgebung, Ergebnisse und übersprungene Checks
festhalten. Geänderte Go-Dateien mit `gofmt` formatieren. Verhaltensänderungen
brauchen gezielte Regressionen für Fehlerfälle und abgelehnte Eingaben.

## Anforderungen an Beiträge

Ausdrückliche Freigaben, geprüftes Vertrauen, Fehlerbehandlung und Recovery-Grenzen
erhalten. Ändert sich eine Fähigkeit oder ihre Abnahme, den Projektstatus anpassen.
Lokale, simulierte und echte Betriebsnachweise getrennt benennen.

Synthetische Fixtures verwenden. Keine Binaries, privaten Zustände, Zugangsdaten,
echten Inventare oder Fremdquellen ohne Lizenzhinweise committen.
Sensible Befunde über [SECURITY.md](SECURITY.md) melden.

## Quellbedingungen

Für Beiträge gilt die bestehende [GPL-3.0-or-later-Lizenz](LICENSE).
