# Offline-Build und vertrauenswürdiger Bootstrap

Der Python-Kern hat keine PyPI-Laufzeitabhängigkeiten und verwendet ein
kleines PEP-517-Build-Backend aus `build_backend/umzug_build.py`. Für den Build
genügt Python 3.11 oder neuer. Das reduziert die Bootstrap-Fläche, macht den
Python-Interpreter und das Quellarchiv aber nicht automatisch vertrauenswürdig.

## Vertrauenskette vorbereiten

Auf einem separaten, aktuellen und vertrauenswürdigen Online-System:

1. Toolkit-Quellrelease beziehen und dessen Signatur/Hash über einen zweiten
   Kanal prüfen.
2. Herstellerpakete für Python, OpenSSL, `age` oder GnuPG sowie optional
   Bubblewrap, `zstd`, `file`, ClamAV und YARA beziehen. Nur
   distributionsnative signierte Repositorys oder signierte Upstream-Releases
   verwenden.
3. YARA-Regeln und ClamAV-Signaturen mit festem Versionsstand beziehen,
   Herstellersignaturen prüfen und exakte SHA-256-Werte erfassen.
4. Alle Pakete einschließlich transitiver Abhängigkeiten für Architektur und
   Zielrelease in einen Offline-Repository-/Paketcache übernehmen.
5. Mullvad ausschließlich aus offiziellen Quellen beziehen und gemäß der
   [offiziellen Signaturanleitung](https://mullvad.net/en/help/verifying-signatures)
   verifizieren. Paket und Detached Signature gemeinsam übernehmen;
   Code-Signing-Public-Key und dessen primären Fingerprint über einen zweiten
   Kanal verankern. Setup lädt die App nicht selbst herunter.
6. Artefakte auf ein frisch formatiertes Transfermedium kopieren, dieses danach
   physisch schreibschützen oder auf der Analyseseite nur lesbar einbinden.

Hashlisten müssen signiert sein oder über einen unabhängigen Kanal kommen. Eine
`SHA256SUMS` auf demselben nicht vertrauenswürdigen Medium ist allein kein
Vertrauensanker.

## Wheel ohne Netzwerk bauen

Aus der geprüften Quellwurzel mit dem mitgelieferten No-Overwrite-Doppelbuild:

```sh
SOURCE_DATE_EPOCH=1767225600 \
  ./scripts/offline-build.sh /tmp/umzug-build-0.2.0rc1-001
sha256sum \
  /tmp/umzug-build-0.2.0rc1-001/umzug_toolkit-0.2.0rc1-py3-none-any.whl \
  /tmp/umzug-build-0.2.0rc1-001/umzug-offline-install.py
```

Das Skript baut zweimal in getrennten temporären Verzeichnissen, prüft beide
ZIPs und verlangt Bytegleichheit. Ein abweichendes vorhandenes Ziel-Wheel wird
nicht überschrieben; die vollständige Wheel-/Installer-Paarung wird vor der
ersten Veröffentlichung geprüft. Für Release-Artefakte trotzdem immer einen
neuen, noch nicht vorhandenen Ausgabepfad verwenden und ein historisches
`dist/` nie weiterreichen. Dieser Pfad verwendet ausschließlich Shell und die
Python-Standardbibliothek. Er wurde für Version 0.2.0rc1 praktisch geprüft.
Alternativ kann ein bereits vorhandenes PEP-517-Frontend offline verwendet
werden:

```sh
python3 -m pip wheel --no-index --no-deps --no-build-isolation -w dist .
```

Der zweite Befehl setzt ein lokal installiertes, bereits vertrautes `pip`
voraus. Es darf nichts aus dem Netz nachinstallieren.

`SOURCE_DATE_EPOCH` fixiert ZIP-Zeitstempel. Bei identischem Quellbaum,
Interpreter-/Backendverhalten und Epoch ist das reine Wheel deterministisch.
Das beweist keine Source-Reproducibility über unterschiedliche Python-/zlib-
Versionen; zwei unabhängig erzeugte Wheels müssen byteweise beziehungsweise per
SHA-256 verglichen werden.

## Offline installieren: auch ohne ensurepip

Minimale Debian-/Ubuntu-Images enthalten häufig weder pip noch ensurepip. Der
Build liefert deshalb `umzug-offline-install.py`: einen eng begrenzten
Standardbibliothek-Installer nur für das reine Toolkit-Wheel. Hashwerte von
Wheel **und** Installer müssen unabhängig authentifiziert sein. Auf dem Ziel
beide empfangenen Dateien zunächst in einen root-eigenen, privaten Baum
kopieren und die Kopien erneut prüfen; so kann ein unprivilegierter Prozess sie
zwischen Prüfung und Root-Ausführung nicht austauschen:

```sh
sudo /usr/bin/install -d -o root -g root -m 0700 /root/umzug-bootstrap
sudo /usr/bin/install -o root -g root -m 0600 \
  /pfad/zum/umzug-offline-install.py /root/umzug-bootstrap/
sudo /usr/bin/install -o root -g root -m 0600 \
  /pfad/zum/umzug_toolkit-0.2.0rc1-py3-none-any.whl /root/umzug-bootstrap/
sudo /usr/bin/sha256sum \
  /root/umzug-bootstrap/umzug-offline-install.py \
  /root/umzug-bootstrap/umzug_toolkit-0.2.0rc1-py3-none-any.whl
sudo /usr/bin/python3 -I /root/umzug-bootstrap/umzug-offline-install.py \
  --wheel /root/umzug-bootstrap/umzug_toolkit-0.2.0rc1-py3-none-any.whl \
  --expected-sha256 '<UNABHÄNGIG-AUTHENTIFIZIERTER-WHEEL-SHA256>'
sudo /usr/bin/install -o root -g root -m 0755 \
  /opt/umzug/runtime/bin/umzug-setup-root /usr/local/sbin/umzug-setup
sudo /usr/bin/install -o root -g root -m 0755 \
  /opt/umzug/runtime/bin/umzug-pack /usr/local/bin/umzug-pack
```

`/pfad/zum/...` und der Hash sind durch die geprüften realen Werte zu
ersetzen. Der Installer verlangt Python 3.11+, öffnet Wheel und eigenes
Staging nofollow/root-eigen, prüft äußeren Hash, ZIP-Kanonizität, reguläre
Dateitypen, Modi, Größen-/Expansionslimits, exakte Metadaten sowie die
vollständige SHA-256-/Größenbindung in `RECORD`. Er erzeugt eine venv ohne pip,
entfernt Symlinks, normalisiert Eigentum/Modi, prüft Module ohne Ausführung als
UTF-8/Python-Syntax und veröffentlicht `/opt/umzug/runtime` atomar mit
`RENAME_NOREPLACE`. Eine vorhandene Runtime wird niemals aktualisiert oder
überschrieben; Updates benötigen eine separat geplante, geprüfte Ablösung.

Das Wheel deklariert absichtlich keinen normalen `umzug-setup`-Python-
Entry-Point. Die Wheel-Scriptdatei `umzug-setup-root` wird nach der
Installation genau wie oben als root-eigener Launcher kopiert; sie startet über
`/usr/bin/env -i` eine feste Minimalumgebung und exakt
`/opt/umzug/runtime/bin/python -I -B -m umzug.setup_cli`. `-B` verhindert
privilegierte Bytecode-Caches in der Runtime; wiederholte Root- und
unprivilegierte Read-only-Aufrufe sehen dadurch denselben traversierbaren Baum.
Setup kontrolliert bei Root-Ausführung Interpreter, Paketverzeichnis,
Python-Dateien und Elternpfade auf Root-Eigentum, regulären Typ und fehlende
Gruppen-/Weltschreibbarkeit. Der Quellbaum-Launcher `./setup` verweigert root;
`sudo ./setup`, ein vom Benutzer beschreibbarer `PYTHONPATH` und eine
benutzerkontrollierte venv sind keine produktiven Bootstrap-Pfade. Der
Shell-Wrapper prüft vor dem Python-Start `/opt`, Runtime-, `bin`-/`lib`-Komponenten,
Interpreter und `pyvenv.cfg` linkfrei auf Root-Eigentum und fehlende Gruppen-/
Weltschreibbarkeit. `find -P` lehnt im gesamten `runtime/lib` Symlinks,
Nicht-Root-Eigentum, Gruppen-/Weltschreibbarkeit und Spezialbits ab. Die
anwendungsseitige Revalidierung nach dem Import bildet eine zweite Schranke.
Beide sind lokale Prüfungen, keine kryptografische Runtime-Attestierung gegen
kompromittiertes root oder privilegierte TOCTOU-Manipulation.

Ohne Installation kann aus dem verifizierten Quellbaum ausschließlich
unprivilegiert entwickelt oder schreibgeschützt geprüft werden:

```sh
PYTHONPATH=src python3 -m umzug.pack_cli --help
PYTHONPATH=src python3 -m umzug.setup_cli --help
```

Die Wheel-Installation erzeugt den Python-Entry-Point `umzug-pack` und die
Wheel-Scriptdatei `umzug-setup-root`, aber bewusst keinen normalen
`umzug-setup`-Entry-Point. Dokumentation und externe Profile bleiben im
Quellpaket.

Der Offline-Workspace ist erst vollständig, wenn je Kandidat SOURCE- und
Ingest-QUARANTINE-Report, selbstgehashter SOURCE→QUARANTINE-Provenienzbeleg,
exakter Promotion-QUARANTINE- und SANITIZED-Report, selbstgehashter
QUARANTINE→SANITIZED-Promotion-Beleg sowie Approval vorhanden sind. Diese
Dateien gemeinsam offline sichern; der Restore snapshottet sie fd-/nofollow
und lehnt alte oder unvollständige Schemas fail-closed ab. Ihre Hashverkettung
belegt Integrität und Ableitung, nicht Malwarefreiheit.

## Laufzeitwerkzeuge

| Funktion | Erforderlich |
|---|---|
| Manifest signieren/prüfen | OpenSSL mit Ed25519 und `pkeyutl -rawin` |
| age-Verschlüsselung | `age` |
| Symmetrische GPG-Verschlüsselung | GnuPG |
| Strikte Zero-Trust-Freigabe | Bubblewrap, `file`, `clamscan`, `yara` plus gepinntes Material; bei zstd zusätzlich gepinntes `zstd` |
| Vendor-Receipt | SHA-256-gepinnte `gpg`-, `gpgv`- und Bubblewrap-Binärdateien, Hersteller-Key/Fingerprint |
| Hardening auf aktuellem Backend | nftables, `sysctl`, systemd oder eingeschränkt OpenRC, distributionsabhängige Werkzeuge |
| Offline-Paketaktionen | Jeweiliger Paketmanager, lokaler geprüfter Cache/Artefakte, `unshare` |
| Mullvad-Finalisierung | Über Vendor-Receipt offline installierte offizielle Mullvad-App |

Fehlt ein optionales Verschlüsselungsprogramm, bricht nur der gewählte Modus
ab. Fehlt ein erforderlicher externer Scanner oder dessen Hashbindung, ist eine
strikte Freigabe absichtlich nicht möglich.

## Scanner-Policy

Beispiel mit einer YARA-Datei und genau einem ClamAV-Datenbankverzeichnis:

```toml
[scanner]
required_external_scanners = ["file", "clamscan", "yara"]
yara_rule_paths = ["/opt/umzug-analysis/yara/main.yar"]
clam_signature_paths = ["/opt/umzug-analysis/clamdb"]
external_isolation_backend = "bubblewrap"

[scanner.trusted_tool_hashes]
bwrap = "<64 hex>"
file = "<64 hex>"
clamscan = "<64 hex>"
yara = "<64 hex>"
zstd = "<64 hex>"

[scanner.trusted_yara_rule_hashes]
"/opt/umzug-analysis/yara/main.yar" = "<64 hex>"

[scanner.trusted_clam_signature_hashes]
"/opt/umzug-analysis/clamdb" = "<KANONISCHER-BAUMHASH>"
```

`<64 hex>` ist durch den unabhängig geprüften echten SHA-256-Wert zu ersetzen;
es ist kein lauffähiger Platzhalter. Beispielwerte werden absichtlich nicht
mitgeliefert, weil sie ohne konkreten Release-/Signaturstand gefährlich wären.
Bei einer einzelnen Datei entspricht der Policy-Wert `sha256sum DATEI`. Bei
einem Verzeichnis verwendet der Scanner einen kanonischen Baumhash über
relative Namen, Verzeichnismodi und Datei-SHA-256, nicht den Hash eines
Tarballs. Nach unabhängiger Signatur-/Herkunftsprüfung lässt er sich mit exakt
derselben geprüften Toolkit-Version auf dem vertrauenswürdigen Buildsystem
ermitteln:

```sh
PYTHONPATH=src python3 -c \
  'from pathlib import Path; from umzug.scanner import _hash_path_or_tree; print(_hash_path_or_tree(Path("/opt/umzug-analysis/clamdb")))'
```

`_hash_path_or_tree` ist eine interne, versionsgebundene Hilfsfunktion; den Wert
bei Toolkit-Upgrades neu erzeugen und prüfen. Der strikte Scanner akzeptiert
genau einen Datenbankpfad und übergibt ihn ausdrücklich als
`clamscan --database=DATEI_ODER_VERZEICHNIS`. Mehrere Pfade oder die implizite
systemweite ClamAV-Datenbank führen fail-closed zu einem Blocker.

`zstd` gehört nicht zur Liste der drei externen Scanner, wird aber beim ersten
zstd-Stream zwingend aus `trusted_tool_hashes` geprüft. Dekompression läuft mit
dem ebenfalls gepinnten Bubblewrap ohne Netzwerk, `zstd -M128`, Timeout und den
konfigurierten Input-/Output-/Expansionslimits. Ohne vollständigen Erfolg kann
weder ein generischer zstd-Stream noch ein zstd-RPM-Payload freigegeben werden.

Die TOML-Datei kann Limits verschärfen, aber nicht über die eingebauten
Migrationsobergrenzen anheben. Ebenso lassen sich Bubblewrap, sichere
Quellmountoptionen, die drei Pflichtscanner, verifiziertes Material und das
Blockieren unbekannter Binärdateien produktiv nicht deaktivieren. Unbekannte
Felder oder falsche Typen brechen den Lauf ab, statt still ignoriert zu werden.

Für reguläre Dateien beträgt die Default-Obergrenze eines unveränderlichen
Scan-Snapshots 256 MiB; alle Dateisnapshots eines Kandidaten teilen sich mit der
rekursiven Archivexpansion das harte Gesamtbudget von 1 GiB
`max_archive_expanded_bytes`. Jeder Snapshot wird nofollow in einem privaten
0700-Temporärbaum als 0400-Datei angelegt, nach der externen Analyse erneut
gehasht und regulär gelöscht. `TMPDIR` für produktive Scans auf ausreichend
großen, verschlüsselten Analysestorage setzen und nach einem Absturz auf Reste
prüfen.

Bubblewrap bindet **nicht** `/` als Hostwurzel ein. Sichtbar sind nur `/usr`
und erforderliche `/bin`-/`sbin`-/Library-Bäume schreibgeschützt, leere
`/etc`/`var`, private `proc`/`dev`/`tmp`/`run`/Home-Bäume, der Snapshot unter
`/input` und die explizit hashgebundenen Regeln beziehungsweise
ClamAV-Signaturen.

Diese Runtime ist nicht vollständig als kryptografischer Closure-Baum
gepinnt. Die ausgeführten Werkzeugdateien werden privat gesnapshottet und
hashgeprüft; dynamischer Loader, Shared Libraries, NSS-/Locale-Daten, Kernel und
weitere schreibgeschützte Runtimebestandteile aber nicht lückenlos einzeln.
Read-only im Namespace bedeutet zudem nicht „vertrauenswürdig auf dem Host“.
Ein Angreifer mit derselben UID kann Prozess und private Snapshots angreifen,
root/Kernel/Hypervisor ohnehin. Deshalb auch bei korrekten Hashes nur in einer
frisch aufgebauten netzlosen VM aus unabhängig verifizierten Basisartefakten
scannen.

## Offline-Paketbestände

Das Toolkit erstellt keinen universellen Paketspiegel. Geeignete Verfahren sind:

- Debian/Ubuntu: signierte `InRelease`/`Release.gpg`-Metadaten und alle Debs
  offline sichern. Der heutige generische Capability-Plan führt jedoch bewusst
  **kein** `apt-get` aus, weil ein signatur-/SHA-256-gebundener `APPROVED`-
  Repository-Snapshot samt exaktem Closure-Receipt noch fehlt. Er erzeugt nur
  einen blockierenden manuellen Nicht-Ausführungs-Checkpoint.
- Arch: signierte Repository-Datenbank plus explizit unter `APPROVED` liegende
  Paketdateien; der Adapter akzeptiert offline nur konkrete absolute Pfade.
- NixOS: vollständig vorgefüllter, verifizierter Nix-Store und manuell geprüfte
  Einbindung von `umzug-packages.nix`.
- Gentoo: signierter Snapshot/Manifest plus passende Binärpakete; der Plan nutzt
  `--usepkgonly --getbinpkg=n` und darf keine Downloads auslösen.
- LFS: eigenes signiertes Source-/Patch-/Buildbook-Set; keine automatische
  Paketmanagerannahme.

Für Mullvad ist die native Repository-Prüfung allein nicht der Toolkit-Receipt.
Nach der `APPROVED`-Freigabe prüft `umzug-setup verify-vendor` die Detached
OpenPGP-Signatur erneut mit einem einzelnen fingerprintgebundenen Schlüssel und
gepinnten `gpg`-/`gpgv`-/Bubblewrap-Binärdateien in einer netzlosen Sandbox.
Zusätzlich ist `--artifact-sha256` mit dem unabhängig authentifizierten Hash
des exakten Hersteller-Releases Pflicht; ein Hash aus dem Workspace zählt nicht.
`plan --mullvad-artifact ... --mullvad-vendor-receipt ...` verlangt den
Artefakthash, Fingerprint sowie alle drei Toolhashes nochmals über
`--mullvad-artifact-sha256`,
`--mullvad-package-version`, `--mullvad-package-architecture`,
`--mullvad-fingerprint`, `--mullvad-gpg-sha256`,
`--mullvad-gpgv-sha256` und `--mullvad-bwrap-sha256`. Es führt den Receipt im
Format `umzug-vendor-verification-v4` erneut kryptografisch aus und akzeptiert
danach ausschließlich das unveränderte receiptgebundene `.deb`/`.rpm` auf einer
offiziell gegateten Zielplattform. Der Receipt ist kein Malwarefreiheits- oder
Reproducible-Build-Nachweis.

Version und Architektur müssen für genau das Artefakt aus unabhängig
authentifizierten Paket-/Repository-Metadaten kommen, nicht aus Paket oder
Workspace. Die Vendor-Action installiert Debian mit
`apt-get install --yes --reinstall --no-download --no-install-recommends --
ARTEFAKT` und Fedora mit `rpm --upgrade --replacepkgs -- ARTEFAKT`, nie mit
DNF. Der DEB-Receipt beweist keine transitive APT-Closure. Auf systemd müssen
Managementgruppe und Drop-in vor dem Paket liegen; dieselbe Install-Action
bindet `mullvad`, führt receiptgebunden daemon-reload/restart aus und schließt
erst nach Paket- und Live-Prüfung von Gruppe/Environment/Umask/UDS.

Paketaktionen laufen im Executor mit `unshare --net` in einem neuen
Netzwerk-Namespace. Wenn der Kernel oder die lokale Policy den Namespace nicht
erlaubt, wird nicht auf Onlinebetrieb zurückgefallen; die Aktion bricht ab.

## Reproduzierbarkeit des Migrationspakets

`umzug-pack --source-date-epoch EPOCH` normalisiert Tar-Zeitstempel und setzt
auch `created_at` im Manifest auf exakt diesen UTC-Zeitpunkt. Bei identischen
Quelldaten und Metadaten, identischer Auswahl/Inventarisierung, demselben
bereits vorhandenen Ed25519-Schlüssel und `--encrypt none` entstehen damit
byteidentische Bundles; dies wird in einem realen Doppel-Pack-Test geprüft.

Nicht bitidentisch bleiben Läufe, wenn Quellinventar, Pakete, Benutzer,
Services oder Dateimetadaten variieren. `age` und GnuPG verwenden frischen
Zufall, und auch eine neu erzeugte passwortgeschützte Ed25519-Schlüsseldatei
ist zufällig. Für forensische Wiederholung Manifest, Toolversionen, Policy,
Signaturmaterial und `SOURCE_DATE_EPOCH` archivieren.

## Offline-Nachweis

Build und Setup in einer netzlosen VM durchführen und vor der Mullvad-
Finalisierung kontrollieren:

```sh
ip link
ip route
ss -tpn
```

Zusätzlich auf Hypervisor-Ebene sicherstellen, dass kein virtuelles NIC
verbunden ist. Der erste absichtlich netzfähige Toolkit-Schritt ist
`umzug-setup vpn-finalize --expected-plan-sha256 HASH`; er ist nur nach
vollständig abgeschlossenem Plan und positiv erkannter verschlüsselter
Mount-Abdeckung für `/etc/mullvad-vpn` sowie mit procfs auf `/proc` unter
`hidepid=2`/`hidepid=invisible` ohne `gid=`-Ausnahme zulässig. Zusätzlich müssen
`kernel.core_pattern` exakt leer, `kernel.core_uses_pid=0` und alle
Swap-Einträge inaktiv sein. `strict` und `maximal` rendern die Core-Dump-Werte
samt `fs.suid_dumpable=0` deklarativ; Nicht-NixOS-Pläne laden sie über eine
bestätigte Action, NixOS erst nach manuellem Modulimport und lokalem Test.
Procfs und Swap müssen distributionsgerecht außerhalb des Toolkits eingerichtet
werden. Alle wirksamen Voraussetzungen werden vor Prompt und CLI-Login erneut
geprüft. Finalizer und CLI-Kind setzen zudem `RLIMIT_CORE` soft/hard auf `0`
und `PR_SET_DUMPABLE=0`. Ein `systemd-coredump`-Pipehandler wird trotzdem
abgewiesen, weil `RLIMIT_CORE` über Pipes geleitete Core-Dumps nicht
hinreichend sperrt.

Vor dem hostnamebasierten Online-Check und erneut nach Reconnect laufen pro
gebundener Ethernet-NIC rohe UDP/53- und TCP/53-Proben zu `1.1.1.1`,
`8.8.8.8` und `9.9.9.9`. Geschütztes `resolv.conf` und optional bereits
receiptgebundenes `resolvectl status` liefern Resolver-Evidenz; literale
Nicht-Loopback-Resolver müssen receiptgebunden über eine von `wg show
interfaces` ausgewiesene WireGuard-NIC routen. Ein Loopback-Stub ohne
sichtbaren Upstream scheitert. Diese endlichen Proben und
`finite_connected_dns_containment_checks_passed=true` decken DoH/DoT,
beliebige Resolver, Namespaces, Prozessmarken und Races nicht ab.

Der Online-Check und der kontrollierte Disconnect-Test über mit
`SO_BINDTODEVICE` gebundene rohe Literal-IP-Sockets für TCP/80, TCP/443 und
UDP/53 sind im produktiven Pfad verpflichtend. TCP-Erfolg, Refusal oder Reset
und jedes empfangene UDP-Datagramm gelten als Leak; nur definierte Policy-/
Down-/Unreachable-/Timeout-Fehler gelten als blockiert, andere Socketfehler
brechen unbestimmt fail-closed ab. Zusätzlich muss die
Mullvad-OUTPUT-Basiskette Policy `drop` besitzen und darf keine indirekten
Verdictpfade enthalten. Die Proben und das anschließende Reconnect liefern
endliche Evidenz, aber keinen formalen Nachweis gegen alle möglichen Leaks oder
privilegierten Bypässe.

Der Finalizer darf nur aus exakt geprüftem Offline-Guard, Bootstrap-Guard oder
Mullvad-Lockdown plus geprüfter Mullvad-nftables-Policy starten. Vor jedem
Daemon-Restart installiert und prüft er den Bootstrap-Guard erneut; das
Offline-Guard-Retirement darunter ist idempotent. Bei einem gefangenen Fehler
reaktiviert er `umzug-offline-guard.service` per `enable --now` rebootfest
und verifiziert Offline- und Bootstrap-Guard. Scheitert dies, ist keine
geschlossene Grenze bewiesen und lokale Emergency-Recovery Pflicht.

Das generierte systemd-Drop-in beginnt mit leerem `Environment=` und enthält
danach ausschließlich Managementgruppe sowie `UMask=0077`. Der Finalizer
verlangt die exakten Bytes über eine geschützte root-eigene, linkfreie
Elternkette in einer regulären root-eigenen Single-Link-Datei mit Modus 0644
oder strenger; maßgeblich bleibt anschließend die reale Daemon-Umgebung.

Ein separates `/etc`-, `/etc/mullvad-vpn`- oder exaktes Datei-Mount auf
`account-history.json` beziehungsweise `device.json` kann die heutige
Erkennung nicht auf eigene Verschlüsselung zurückführen und blockiert deshalb
fail-closed. Vor Prompt und nach Login werden `account-history.json` und
`device.json` linkfrei auf Root-Eigentum, regulären Typ, `nlink=1`, höchstens
1 MiB und Modus 0600 oder strenger geprüft; nach Login müssen beide existieren.
Die Prüfung schützt keine bereits unverschlüsselt gespeicherten Bytes
nachträglich.
