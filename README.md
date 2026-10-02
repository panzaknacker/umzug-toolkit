# umzug-toolkit

Python-Werkzeuge für kontrollierte Linux-Datenübernahme: signierter Transport,
Quarantäne, Prüfung, ausdrückliche Freigabe und Restore. Systemänderungen nutzen
Pläne, Checkpoints und Rollback.

Release Candidate `v0.2.0rc1`. Zur Evaluierung vorgesehen sind entbehrliche
Debian-/Ubuntu-Systeme mit systemd und H0-Offline-Baseline. Die Hardwareabnahme
ist offen. Andere Plattformen, `strict`/`maximal` und Mullvad/H2 sind nicht qualifiziert.

## Ausprobieren

Linux, Git, Python 3.11+ mit `venv`/pip und OpenSSL bereitstellen.
Das Repository klonen und pytest in einer separaten Python-Umgebung installieren:

```sh
git clone https://github.com/panzaknacker/umzug-toolkit.git
cd umzug-toolkit
python3 -m venv .venv
. .venv/bin/activate
python -m pip install pytest
```

Die pytest-Installation benötigt Zugriff auf einen Paketindex. Die folgenden
Aufrufe laufen aus dem Repository-Wurzelverzeichnis mit aktivierter Umgebung;
die statischen Checks installieren selbst keine Abhängigkeiten:

```sh
python scripts/portfolio-demo.py
python scripts/transport-smoke.py
./scripts/static-checks.sh
```

Die Demos verwenden temporäre Dateien ohne Root oder Systemänderungen.
Der Transporttest verwendet die echte Pack-CLI; Scanner und privilegierter
Restore gehören nicht dazu. Die statischen Checks umfassen Syntax, Tests und
einen reproduzierbaren Offline-Wheel-Build. ShellCheck und YARA sind optional.

Ein Offline-Testpaket lässt sich mit
`./scripts/make-hardware-test-kit.sh /absoluter/neuer/pfad` bauen. Es enthält
Wheel, Installer, Profile, Regeln und Prüfsummen und überschreibt kein Ziel.

## Code

- [Plan und Validierung](src/umzug/model.py), [Aktionen](src/umzug/actions.py)
- [Hardening-Policy](src/umzug/hardening_policy.py) und [Planer](src/umzug/hardening.py)
- [Scanner](src/umzug/scanner.py) und [Formatprüfung](src/umzug/scan_formats.py)
- [Ausführung und Recovery](src/umzug/executor.py), [Transport](src/umzug/pack_cli.py)

Bekannte Grenze: Unter Fedora/SELinux scheitern acht Metadaten-Restore-Fälle am
Entfernen von `security.selinux`. Ein grüner Lauf auf einer anderen Distribution
behebt das nicht. GitHub Actions sind derzeit deaktiviert; die bisherigen
Starts endeten vor einem Job.

## Sicherheit

Nur eigene, entbehrliche Systeme verwenden und Backups sowie lokale Konsole vor
Systemänderungen bereitstellen. Quellmounts benötigen `ro,noexec,nodev,nosuid`.
Der externe Scanner verlangt Isolation und feste Werkzeuge; unanalysierbare
Inhalte werden blockiert. Signaturen und Scanner garantieren keine Malwarefreiheit.
Vorhandene Restore-Ziele bleiben erhalten. Boot- und Netzwerk-Guards können
bei Fehlern bewusst sperren; Checkpoints und gesicherter Zustand sind für Recovery
nötig. Sensible Befunde über die private Meldung im GitHub-Security-Tab teilen.

[GPL-3.0-or-later](LICENSE).
