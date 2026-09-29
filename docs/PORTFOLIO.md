# Warum umzug-toolkit

Ausgangspunkt waren Hardware- und Distributionswechsel zwischen meinen
eigenen Laptops und PCs. Ich wollte Daten einfacher auf das nächste Linux-System
mitnehmen können, statt die Übernahme jedes Mal neu vorzubereiten.

Dabei sollte das alte System nicht automatisch als vertrauenswürdig gelten –
auch für eine Neuinstallation nach einer möglichen Infektion. Das Python-Werkzeug
trennt deshalb Quarantäne, Prüfung, Freigabe und Wiederherstellung. Im Mittelpunkt
steht die kontrollierte Datenübernahme, nicht das Klonen einer kompletten Installation.

## Entscheidungen im Code

**Signatur und Freigabe erfüllen verschiedene Aufgaben.** Eine Signatur bindet
Daten an einen Schlüssel. Ob die geprüften Daten übernommen werden dürfen,
entscheidet eine separate, an Inhalt und Befunde gebundene Freigabe.
[Manifest](../src/umzug/manifest.py), [Zustandsübergänge](../src/umzug/scanner.py).

**Vor Restore wird erneut geprüft.** Inhalt und Belege könnten sich seit der
Freigabe verändert haben. Der Restore prüft deshalb Hashes und Vertrauensanker
noch einmal.
[Restore-Prüfung](../src/umzug/restore_trust.py).

**Vorhandene Ziele bleiben erhalten.** Restore ersetzt weder bestehende Dateien
noch Verzeichnisse. Der Regressionstest prüft Inhalt, Inode, Modus und Änderungszeit
der vorhandenen Datei, bei einem Zielverzeichnis außerdem dessen unveränderte
Einträge. In beiden Fällen darf kein Erfolgsbeleg entstehen.
[Scanner-Tests](../tests/test_scanner.py).

**Rollback prüft das Backup zuerst.** Ein beschädigtes Backup darf nicht dazu
führen, dass die aktuelle Datei vorzeitig gelöscht wird.
[Executor](../src/umzug/executor.py).

## Ausprobieren

Die [Demo](DEMO.md) führt neun Prüffälle mit synthetischen Daten aus, darunter
Manipulation nach Freigabe und der Schutz bestehender Ziele. Scanner und
Systemumgebung sind dabei Test-Fixtures.

[VALIDATION.md](VALIDATION.md) enthält die Ergebnisse je Umgebung.
Hardware, privilegierter CLI-Restore und echte Scanner haben eigene
[Abnahmeschritte](HARDWARE-TEST.md). Die
[SELinux-Metadaten-Grenze](KNOWN-ISSUES.md) bleibt separat dokumentiert.
