# Lokaler Prüfstand

## 21.09.2026: Arch Linux

Linux x86_64, Kernel 7.2.5-hardened1-1-hardened, Python 3.14.7 und pytest 9.1.1.
Die Prüfung lief mit synthetischen Daten in einer temporären Quellkopie.
[Geprüfte Code- und Builddateien](evidence/2026-09-21-inputs.sha256).
Die beiden Eingabelisten wurden am 29.09.2026 nachträglich um den Eintrag
einer leeren, inzwischen entfernten Datei gekürzt; alle übrigen Einträge sind
unverändert.

| Prüfung | Ergebnis | Protokoll |
| --- | --- | --- |
| Komponenten-Demo | Neun Fälle bestanden, keiner übersprungen | [Demo](evidence/2026-09-21-demo.txt) |
| `scripts/static-checks.sh` | 508 Tests und drei Subtests bestanden; Exit 0 | [Gesamtlauf](evidence/2026-09-21-full-check.txt) |
| Syntax, YARA-Regelkompilierung | Bestanden | Im Gesamtlauf |
| Doppelter Offline-Build | Byteidentisch | Im Gesamtlauf |
| ShellCheck | Nicht installiert, ausdrücklich übersprungen | Im Gesamtlauf |

Die Testdateien hatten kein `security.selinux`-Attribut. Der Lauf bestätigt die
lokalen Komponenten in dieser Umgebung, keine SELinux-Unterstützung oder
Hardware-/Produktionsabnahme. GitHub Actions bleiben deaktiviert.

## Nachprüfung: Python-Mindestversion und ShellCheck

Auf demselben Arch-System bestand Python 3.11.15 mit pytest 9.1.1 den gesamten
lokalen Check: 508 Tests, drei Subtests, ShellCheck 0.11.0, YARA und der
byteidentische Doppelbuild. Die neun Demo-Fälle bestanden ebenfalls.
[Gesamtlauf](evidence/2026-09-21-followup-python311.txt),
[Demo](evidence/2026-09-21-followup-python311-demo.txt),
[Code-/Builddateien](evidence/2026-09-21-followup-inputs.sha256).

Der neue echte Pack-CLI-Transportcheck bestand mit Python
[3.11.15](evidence/2026-09-21-followup-transport-python311.txt) und
[3.14.7](evidence/2026-09-21-followup-transport-python314.txt).
Er prüft Signatur, separat gelieferten Test-Public-Key, exakte extrahierte Bytes,
Manipulationsabwehr und Erhalt eines bestehenden Transportziels ohne Mocks.
Scanner, Freigabe und privilegierter Restore bleiben außerhalb dieses Checks.
[Aufruf und Umfang](DEMO.md).

Python und Prüfwerkzeuge wurden separat im temporären Verzeichnis vorbereitet;
die Läufe selbst nutzten keinen Paketindex. Für ShellCheck wurden nur fünf
leere `CDPATH`-Zuweisungen als `CDPATH=''` ausgeschrieben. Die bisherigen
Prüfprotokolle bleiben unverändert. Der SELinux-Befund unten bleibt offen.

## 19.09.2026: Fedora 44 mit SELinux

Die damalige Arbeitskopie bestand die [neun Demo-Fälle](evidence/2026-09-19-demo.txt).
Der [vollständige Lauf](evidence/2026-09-19-full-check.txt) endete mit
500 bestandenen und acht fehlgeschlagenen Tests sowie drei bestandenen Subtests.
Ursache war das Entfernen geschützter SELinux-Attribute beim Metadaten-Restore.
[Reproduktion und offene Abnahme](KNOWN-ISSUES.md).

Syntax und Doppelbuild bestanden; ShellCheck und YARA waren damals nicht verfügbar.
Der [Secret-Scan](evidence/2026-09-19-secret-scan.txt) meldete keine Funde.

## Änderungen

Der neue Restore-Test prüft vorhandene Dateien und Verzeichnisse auf unveränderten
Inhalt und Metadaten sowie einen fehlenden Erfolgsbeleg. Zwei bestehende Tests
binden ihre synthetischen Review-Findings ausdrücklich an die Freigabe.
Produktive Schutzfunktionen und Scannerpflichten bleiben unverändert.
Die spätere Stilbearbeitung verändert nur Layout und Kommentare/Docstrings.

## Wiederholen

In der eingerichteten Testumgebung aus der Repository-Wurzel:

```sh
python scripts/portfolio-demo.py
python scripts/transport-smoke.py
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  PYTHON_BIN="$VIRTUAL_ENV/bin/python" ./scripts/static-checks.sh
```

Die Protokolle normalisieren lokale Pfade, nicht Ergebnisse oder Fehler.
Der ursprüngliche Entwicklungsverlauf war nicht Teil der ZIP-Quelle; die neuen
Review-Änderungen werden in der privaten Git-Historie getrennt festgehalten.

## Quellprüfung

Der saubere Quell-Export bestand die Link- und Dateihygieneprüfung. Gitleaks
8.30.1 meldete am 21.09.2026 keine Funde.
[Scanner-Ausgabe](evidence/2026-09-21-source-scan.txt). Die Git-Historie wird
getrennt geprüft.
