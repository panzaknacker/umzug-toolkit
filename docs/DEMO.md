# Lokale Komponenten-Demo

Die Demo führt neun vorhandene Regressionstests mit synthetischen Dateien aus.
Sie prüft Transport, Freigabe, Restore und Rollback ohne Änderungen an Diensten,
Firewall oder bestehenden Benutzerdaten.

## Einrichtung

Benötigt werden Linux, Python 3.11+, OpenSSL im `PATH` und pytest. Als normaler
Nutzer ausführen. Die einmalige Einrichtung lädt pytest; die Demo selbst
benötigt kein Netzwerk:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install pytest==9.1.1
python scripts/portfolio-demo.py
```

## Prüffälle

| Fall | Erwartung |
| --- | --- |
| Signierter Transport | Gültiges Paket akzeptieren, veränderten Payload ablehnen. |
| Zustandsfolge | Alle fünf Zustände durchlaufen und den ursprünglichen Inhalt herstellen. |
| Vertrauensanker | Unabhängigen Schlüssel und Freigabebeleg vor Restore prüfen. |
| Änderung nach Freigabe | Veränderte Bytes ablehnen. |
| Fehlender Anker | Ohne externen Vertrauensanker abbrechen. |
| Bestehendes Ziel | Dateiinhalt, Inode, Modus und Änderungszeit sowie Verzeichniseinträge unverändert erhalten. |
| Rollback | Gesicherten Inhalt zurückspielen und eine neu erstellte Datei entfernen. |
| Beschädigtes Backup | Abbrechen, bevor die aktuelle Datei gelöscht wird. |

Der [Runner](../scripts/portfolio-demo.py) nennt die konkreten Tests.
Bei Erfolg erscheinen acht `PASS`-Zeilen für neun Fälle; das bestehende Ziel
wird als Datei und Verzeichnis geprüft. Fehler oder übersprungene Fälle lassen
die Demo scheitern. Temporäre Daten und Schlüssel werden am Ende entfernt.

## Umfang

Dateioperationen, Signaturen, Hashes, Zustandswechsel und Rollback werden
wirklich ausgeführt. Scanner und geschützte Quellmounts sind Test-Fixtures.
Die Demo prüft daher Komponentenlogik, nicht Malwarefreiheit oder den
vollständigen privilegierten CLI-Betrieb. Dafür gilt der
[VM-/Betriebsablauf](EXAMPLE-WORKFLOW.md).

## Vollständige lokale Prüfung

Ein zusätzlicher [Transport-Smoketest](../scripts/transport-smoke.py) ruft den
echten Pack-CLI auf: synthetische Datei auswählen, mit einem temporären
Ed25519-Schlüssel signieren, über einen separat gehaltenen Public Key prüfen,
extrahierte Bytes vergleichen und nachträgliche Manipulation ablehnen. Er
prüft außerdem, dass ein vorhandenes Transportziel nicht überschrieben wird.

```sh
python scripts/transport-smoke.py
```

Dafür reichen Python 3.11+ und OpenSSL; pytest, Netzwerk und root sind nicht
nötig. Unverschlüsseltes Paket und unverschlüsselter Wegwerf-Testschlüssel
bleiben im privaten temporären Verzeichnis und werden entfernt. Das ist ein
realer Transport-Rundlauf, kein vollständiger Scanner-/Freigabe-/Restore-Betrieb.

In der aktivierten Testumgebung:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  PYTHON_BIN="$VIRTUAL_ENV/bin/python" ./scripts/static-checks.sh
```

Dieser Lauf prüft Syntax, alle Tests und den reproduzierbaren Offline-Build.
ShellCheck und YARA werden bei vorhandenen Werkzeugen ergänzt; fehlende
Werkzeuge erscheinen ausdrücklich als übersprungen.
[Ergebnisse je Umgebung](VALIDATION.md), [SELinux-Grenze](KNOWN-ISSUES.md).
