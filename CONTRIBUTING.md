# Entwicklung

`umzug-toolkit` ist ein release candidate für den dokumentierten H0-testumfang.
bitte änderungen klein halten und auswirkungen auf vertrauenszonen, freigaben,
rollback und offline-betrieb in der beschreibung nennen.

## Lokale prüfung

voraussetzungen: linux, python 3.11+, OpenSSL, git und pytest. eine isolierte
entwicklungsumgebung kann online vorbereitet werden:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install pytest==9.0.3
./scripts/static-checks.sh
```

der eigentliche prüflauf lädt keine abhängigkeiten nach. er prüft python- und
shell-syntax, tests und einen reproduzierbaren doppelten offline-wheel-build.
ShellCheck und `yarac` werden zusätzlich verwendet, wenn sie installiert sind;
übersprungene prüfungen müssen bei einer ergebnisangabe genannt werden.
details: [TESTING.md](docs/TESTING.md), [OFFLINE-BUILD.md](docs/OFFLINE-BUILD.md).

## Unvollständige funktionen

nicht implementierte oder noch nicht qualifizierte bestandteile bleiben als
`in development` mit ihren grenzen in [PROJECT_STATUS.md](PROJECT_STATUS.md)
und [LIMITATIONS.md](docs/LIMITATIONS.md) sichtbar. ein grüner unit-testlauf
ändert die hardwarequalifikation nicht. neue sicherheitsrelevante funktionen
benötigen tests für erfolg, abbruch und wiederaufnahme; ein stub darf keinen
erfolg melden.

vor einem beitrag lokale pfade, migrationspakete, schlüssel und operatorzustand
entfernen. mit installiertem gitleaks:

```sh
gitleaks dir --config .gitleaks.toml .
```

sicherheitsmeldungen: [SECURITY.md](SECURITY.md). für beiträge gilt die
vorhandene [GPL-3.0-or-later-lizenz](LICENSE).
