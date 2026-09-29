# Restore-Metadaten unter SELinux

Offene Kompatibilitätsgrenze, beobachtet am 19.09.2026 auf Fedora 44 mit
Python 3.14.7. Der spätere grüne Arch-Lauf ohne entsprechende Dateilabels
ändert diesen Befund nicht. [Prüfungen je Umgebung](VALIDATION.md).

## Reproduktion

```sh
python -m pytest -q -p no:cacheprovider \
  tests/test_restore_metadata.py::test_safe_restore_metadata_maps_names_but_never_reactivates_privilege
```

Auf dem Fedora-Host erhält bereits eine neue Datei `security.selinux`.
`_strip_extended_attributes` verlangt die Entfernung aller erweiterten
Attribute; der Kernel verweigert das Entfernen dieses Labels durch den
unprivilegierten Prozess. Der Restore endet mit `PermissionError`, ohne
Metadaten-Erfolgsbeleg.

Betroffen waren sieben Fälle in `tests/test_restore_metadata.py` und der
Private-Snapshot-/Metadatenfall in `tests/test_restore_trust.py`. Ein
Debian-Container auf demselben Kernel beseitigte diese Eigenschaft nicht.

## Sicherheitsentscheidung

Eine pauschale Ausnahme für `security.selinux` würde das aktuelle Versprechen
ändern, alle erweiterten Attribute zu entfernen. Der Code unterscheidet noch
nicht zuverlässig zwischen neu erzeugten Zielpolicy-Labels und fremden Labels.
Deshalb wurden weder die Prüfung gelockert noch Tests übersprungen oder
SELinux abgeschaltet.

## Abnahme einer Lösung

- Den bestehenden Umfang auf einer dokumentierten Referenzumgebung ohne diese
  Attributgrenze vollständig abnehmen und die Unterstützung entsprechend benennen;
- oder SELinux-Zielkontexte ausdrücklich unterstützen: Herkunft und Zielpolicy
  prüfen, Änderungen erkennen, fremde Source-Labels ablehnen und Belege sowie
  Bedrohungsmodell anpassen. Tests müssen erlaubte, unerwartete, manipulierte
  und nicht entfernbare fremde Attribute unterscheiden.

Die Komponenten-Demo prüft diesen vollständigen Metadaten-Restore nicht.
