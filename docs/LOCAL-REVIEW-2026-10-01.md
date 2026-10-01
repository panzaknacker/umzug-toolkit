# Lokale Nachprüfung · 01.10.2026

Die [Komponenten-Demo](evidence/2026-10-01-demo.txt) bestand alle neun Fälle.
Der [echte Transporttest](evidence/2026-10-01-transport.txt) bestand Signatur-
und Manifestprüfung, exakte extrahierte Bytes, Erhalt eines vorhandenen Ziels
und Manipulationsabwehr.

Keine neue vollständige Metadaten-Restore-, Scanner- oder Hardwareabnahme.
Die [SELinux-Kompatibilitätsgrenze](KNOWN-ISSUES.md) bleibt offen.

## Umgebung und Quellstand

Fedora 44 x86_64, Kernel 7.2.5-200.fc44; Go 1.26.8, soweit verwendet,
und Python 3.14.7. Vorbereitete Werkzeuge und Modulcaches wurden wiederverwendet.
Go-Proxy und Prüfsummenabrufe waren deaktiviert. Daten und Schlüssel waren
synthetisch und temporär.

[Kontext](evidence/2026-10-01-context.json) ·
[Geprüfte Code-/Build-Eingaben](evidence/2026-10-01-inputs.sha256)

Lokale Checkout-/Werkzeugpfade und zufällige öffentliche Demo-Key-IDs wurden
normalisiert; Ergebnisse und Fehler blieben erhalten. Gitleaks 8.30.1 meldete
bei der Prüfung aller vorhandenen Git-Refs keine Geheimnisse. Nicht mitgelieferte
ursprüngliche Entwicklungshistorie und Produktionsreife sind davon nicht erfasst.

[Gehostete CI-Startfehler](HOSTED-CI.md) sind von diesen lokalen Ergebnissen getrennt.
