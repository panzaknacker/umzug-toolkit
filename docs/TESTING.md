# Tests und Abnahme

Die Tests prüfen Sicherheitsinvarianten des MVP, nicht die Malwarefreiheit
eines Datenbestands und nicht die Wirksamkeit auf jeder Kernel-,
Firmware- oder Distributionskombination. Firewall-, Initramfs-, Secure-Boot-,
GPU- und VPN-Abnahmen benötigen eine wegwerfbare VM mit lokaler Konsole.
Für v0.2.0rc1 ist darüber hinaus ausschließlich der begrenzte H0-Basislauf auf
dedizierter Debian-/Ubuntu-systemd-Hardware als Hardware-Testkandidat
freigegeben; H1/H2 und Arch/NixOS/Gentoo/LFS sind nicht hardwareabgenommen.

## Schneller lokaler Testlauf

Entwicklungsabhängigkeit ist `pytest`; sie gehört nicht zur
Laufzeitinstallation. Aus der Projektwurzel:

```sh
./scripts/static-checks.sh
```

Das Skript arbeitet lokal/offline, parst alle Python-Dateien, prüft die
Shellsyntax, kompiliert `rules/umzug-core.yar`, wenn `yarac` vorhanden ist,
baut das Wheel zweimal byteidentisch und führt pytest ohne Cache aus.
`shellcheck`/`yarac` werden nicht nachinstalliert; fehlen sie, wird der jeweilige
Zusatzcheck offen als übersprungen gemeldet. Die aktuelle Zahl und das Ergebnis
stets aus dem abschließenden `pytest -q` dieses konkreten Quellbaums übernehmen,
nicht aus einer statischen Dokumentationsangabe.

Einzelne Bereiche:

```sh
python3 -m pytest -q tests/test_detection.py
python3 -m pytest -q tests/test_manifest.py
python3 -m pytest -q tests/test_scanner.py
python3 -m pytest -q tests/test_git_safety.py
python3 -m pytest -q tests/test_executor.py
python3 -m pytest -q tests/test_hardening.py
python3 -m pytest -q tests/test_network.py
python3 -m pytest -q tests/test_pack_cli.py
python3 -m pytest -q tests/test_setup_cli.py
python3 -m pytest -q tests/test_console.py
python3 -m pytest -q tests/test_hardware_preflight.py
python3 -m pytest -q tests/test_state_storage.py
python3 -m pytest -q tests/test_util.py
python3 -m pytest -q tests/test_vendor.py
python3 -m pytest -q tests/test_vpn.py
python3 -m pytest -q tests/test_restore_trust.py
python3 -m pytest -q tests/test_restore_metadata.py
python3 -m pytest -q tests/test_assets.py
```

Mit deaktiviertem Cache und Bytecode schreiben die Tests nur in
pytest-Temporärverzeichnisse und verwenden für Systembäume injizierte Wurzeln.
Ohne `-p no:cacheprovider` kann pytest zusätzlich `.pytest_cache` anlegen.
Kein Test darf die produktive Firewall, Services, Mounts oder Paketverwaltung
verändern.

## Abgedeckte Invarianten

| Datei | Geprüfte Schwerpunkte |
|---|---|
| `test_detection.py` | Debian/Arch/NixOS/Gentoo/LFS, Firmware und Secure Boot, GPU/Netz/Funk, Storage/LUKS, Symlinkbegrenzung, Adapterauswahl und Capability-Grenzen |
| `test_manifest.py` | Eindeutige Selection-IDs/Archivwurzeln und ihre Bindung, Größenobergrenze vor Payload-Lesen, PAX-Metadaten, Datei- und Payloadhashes, Ed25519-Roundtrip, TOCTOU-/Secret-Snapshot-Bindung, Tar-Ende/Polyglot, Traversal, Duplikate, Spezialdateien, sichere Extraktion und Split-Reassembly |
| `test_scanner.py` | Archivbomben, Traversal/Link-Fluchten, verschlüsselte Archive, Polyglots, Secrets, Hardlinks/Spezialdateien, DEB/RPM- und gepinnte zstd-Analyse, Review-Bindung, Trust-Zonen, Manipulation nach Scan, symlinkfreie fd-verankerte No-Replace-Restore-Ziele, striktes Fail-closed, Bubblewrap-Isolation und gebundene ClamAV-Datenbank |
| `test_git_safety.py` | Verbot von Git-Ausführung/Remote-Helpern, enge Allowlist lokaler Repository-Konfiguration sowie Fail-closed-Behandlung doppelter und irreführender Sections |
| `test_executor.py` | Dry-Run ohne vergifteten Checkpoint, unlesbare Root-Diffs, fehlende Werkzeuge vor Mutation, absolute hash-/metadatengebundene Executable-Receipts und Austauschabwehr, idempotentes Apply, Backups, Plan-Digest, typisierte Registry, Reboot/Resume, Rollback und Root-Begrenzung |
| `test_hardening.py` | Stabiler Ziel-Fingerprint, regenerierter Ziel-Intent, Ablehnung leerer/gekürzter Pläne, fremder Adapteraktionen, nichtkanonischer Preflights und umsortierter systemd-/LFS-/NixOS-Abhängigkeiten, feste Profil-Untergrenzen, sichere Core-Dump-Werte und absoluter NixOS-Recoverypfad |
| `test_network.py` | INPUT/FORWARD Default-Drop, keine SSH-Freigabe, systemd-Offline-Guard/-Firewall als `RequiredBy`-Boot-Gates mit Emergency-Isolation, exakter manueller WireGuard-Egress, Mullvad-OUTPUT-Policy `drop` ohne indirekte/userspace-kontrollierte Verdicts oder bedingungsloses Accept, kein implizites DNS/LAN, Parameterinjektion und sichere Quellmount-Auswertung |
| `test_pack_cli.py` | Fail-closed Pack-Konfiguration, Secret-Preview-Grenzen und Typ-/Wertevalidierung |
| `test_setup_cli.py` | Exakte Plan-SHA-256-Bestätigung, private/symlinkfreie Resume-Pläne, State-Bindung, Debian-Paketorder nach Netzwerk-Gates/vor rfkill samt exaktem Werkzeugpräfix, Scanner-Floor, Shadow-Mount-Ablehnung und root-pflichtiger Restore nur in inertes Staging |
| `test_console.py` | Remote-Marker und SSH-Prozessahnen, unvollständige Prozessketten, `/dev/pts`-Ablehnung und positive Bindung an eine echte lokale beziehungsweise serielle Konsole |
| `test_hardware_preflight.py` | Strikt schreibgeschützter Hardware-Preflight, automatische Blocker versus manuelle Attestierungen, Plan-/Toolkit-/Zielbindung, lokale Konsole, Offline-Grenze, Backup-/Recovery-/Strom-Gates, kein State-Schreibzugriff, erlaubte Funkgeräteabwesenheit nur nach Reboot und unveränderte Ethernetbindung |
| `test_state_storage.py` | Ablehnung flüchtiger, entfernter, Overlay- und mehrdeutiger State-Speicher; Bindung eines persistenten lokalen Mounts und Erkennung seines Austauschs |
| `test_util.py` | Auditlog-No-Follow für Datei und Elternpfad, Modus 0600 sowie Redaction typischer Tokenmuster |
| `test_vendor.py` | Receipt `umzug-vendor-verification-v4`, unabhängiger Artefakthash und Planzeit-Anker, echte erneute Signaturprüfung, Runtime-Closure-Hinweis, private Tool-Snapshots, Ressourcenlimits und netzlose schreibgeschützte Bubblewrap-Eingaben |
| `test_vpn.py` | Zulässige Finalizer-Anfangsgrenzen, idempotentes Offline-Retirement, rebootfeste Offline-/Bootstrap-Guard-Reaktivierung im Fehlerpfad, exakte geschützte Drop-in-Datei, Kill-Switch-/Lockdown-Einstellungen vor Kontoeingabe, Account-/Device-Dateiprüfung, procfs-/Core-Dump-/Swap-Gates, `RLIMIT_CORE=0`/`PR_SET_DUMPABLE=0`, Parser und Allowlist der realen Daemon-Umgebung, kontrollierter Disconnect mit interfacegebundenen TCP/80-, TCP/443- und UDP/53-Proben, Leak-Abbruch und Managementgruppen-Grenze |
| `test_restore_trust.py` | Unabhängige Schlüssel-/Fingerprint- und Approval-Hash-Anker, erneute Bundle-/Signatur-/Payloadprüfung, fd-/nofollow-Snapshots aller vier Reports und beider Ableitungsbelege, vollständige Provenienz-/Promotion-/Approval-Bindung, exakte Promotion-Akzeptanzen, Ablehnung alter/unvollständiger Records und unveränderter APPROVED-Baum |
| `test_restore_metadata.py` | Bijektive namensbasierte UID/GID-Zuordnung ohne rohe IDs, Entfernung von Privileged-/Execute-Bits und xattrs, Manifestbindung, Symlink-Nofollow, exakte Postprüfung von Mode/Eigentümer/mtime und No-Overwrite-Receipt |
| `test_offline_installer.py` | pip-/ensurepip-freie venv, vollständige ZIP-/RECORD-Prüfung, falscher äußerer Hash, manipulierte Nutzdaten, Traversal, Hardlinks, Cleanup und No-Overwrite-Publikation |
| `test_assets.py` | Reproduzierbares Wheel/RECORD ohne normalen Setup-Entry-Point, ausführbarer isolierender `umzug-setup-root`-Wrapper samt Pre-Import-Ownership-/Symlink-/Mode-Prüfung, doppelter Wheel-Build plus unveränderlicher Installer-Ausgabe, Shell-/Container-/VM-Invarianten, Pack-Beispiel und echte YARA-Regeln |

Ein erfolgreicher String-/Planner-Test beweist nicht, dass der laufende Kernel
die Regel geladen hat. Ein Virenscanner-Test beweist nicht, dass unbekannte
Malware fehlt.

## CLI- und Build-Smoke-Test

```sh
./pack --help
./setup --help
./setup detect --root / --proc /proc --sys /sys --no-commands --json

SOURCE_DATE_EPOCH=1767225600 \
  ./scripts/offline-build.sh /tmp/umzug-wheel-test
python3 -m zipfile -l \
  /tmp/umzug-wheel-test/umzug_toolkit-0.2.0rc1-py3-none-any.whl
sha256sum \
  /tmp/umzug-wheel-test/umzug_toolkit-0.2.0rc1-py3-none-any.whl \
  /tmp/umzug-wheel-test/umzug-offline-install.py
```

Das vollständige H0-Testkit nur in einen neuen, noch nicht existierenden Pfad
bauen. Der Befehl führt zuerst den gesamten lokalen statischen Testlauf aus und
erzeugt danach das Kit ohne Netzwerkzugriff:

```sh
SOURCE_DATE_EPOCH=1767225600 \
  ./scripts/make-hardware-test-kit.sh \
  /tmp/umzug-hardware-kit-0.2.0rc1-h0-smoke-001

cd /tmp/umzug-hardware-kit-0.2.0rc1-h0-smoke-001
sha256sum -c SHA256SUMS
```

Ein vorhandener Pfad muss absichtlich scheitern; für einen erneuten Smoke-Test
einen neuen Namen verwenden, nicht das alte Kit verändern. Der erfolgreiche
`sha256sum -c`-Lauf prüft die interne Transportintegrität. Vor einem echten
Hardwaretest die vom Build ausgegebenen drei Hashes für `SHA256SUMS`, Wheel und
Installer über einen unabhängigen Kanal authentifizieren. Das Kit bündelt
keine ClamAV-Datenbank, externen YARA-Regeln, Scannerprogramme,
distributionsspezifischen Offline-Pakete oder deren Trust-Anker.

`detect --no-commands` ist schreibgeschützt, liest aber im obigen Aufruf den
echten Host. Für reproduzierbare Detection-Tests ausschließlich die
pytest-Fixtures oder vollständig kontrollierte `--root`-, `--proc`- und
`--sys`-Bäume verwenden.

Diese drei Quellbaum-Aufrufe sind ausschließlich unprivilegierte Smoke-Tests.
Der Quellbaum-Launcher muss EUID 0 verweigern. Produktive Root-Tests
installieren das unabhängig hashgeprüfte Wheel zuerst in die root-eigene
Runtime aus [OFFLINE-BUILD.md](OFFLINE-BUILD.md) und verwenden nur
`/usr/local/sbin/umzug-setup`, das aus
`/opt/umzug/runtime/bin/umzug-setup-root` installiert wurde; `sudo ./setup`,
ein direkter nicht vorhandener `runtime/bin/umzug-setup`-Entry-Point und ein vom
Benutzer beschreibbarer `PYTHONPATH` sind keine zulässigen Test- oder
Betriebswege.

Der Offline-Build darf keinen Download auslösen. Das Skript baut bereits
zweimal, vergleicht die Wheels byteweise und verweigert ein abweichendes
vorhandenes Ausgabewheel oder einen abweichenden vorhandenen Installer. Der
Installer benötigt weder pip noch ensurepip und wird in den Unit-Tests gegen
ein frisch gebautes echtes Wheel ausgeführt.

## Netzloser Container-Test

Container sind für Parser, Planner, CLI und Unit-Tests geeignet. Sie sind keine
realistische Testumgebung für UEFI, Secure Boot, TPM, Initramfs, Funkhardware
oder Host-Firewall-Hooks.

Ein vorher verifiziertes, lokal vorhandenes Image muss Python 3.11+ und pytest
bereits enthalten. Das mitgelieferte Harness verlangt die unabhängig
authentifizierte lokale Image-ID und baut/läuft ohne Pull oder Netzwerk:

```sh
./container/offline-smoke.sh \
  REGISTRY/IMAGE@sha256:MANIFEST_DIGEST \
  sha256:AUTHENTIFIZIERTE_LOKALE_IMAGE_ID
```

Die beiden Werte sind Metavariablen, keine mitgelieferten Pins. Das Skript
prüft die lokale Image-ID, nutzt Podman `--pull=never`/`--network=none`, einen
schreibgeschützten Container, keine Capabilities, `no-new-privileges`, Prozess-/
Speicherlimits und ein privates noexec-`/tmp`. Details:
[`container/README.md`](../container/README.md). Rootless-Container können
verschachtelte User-Network-Namespaces oder Bubblewrap blockieren. Die
Scanner-Tests prüfen deshalb sowohl Argumentvektoren als auch
Fail-closed-Verhalten. Ein produktiver strikter Scan muss die reale
Bubblewrap-Probe erfolgreich bestehen.

## Netzloser QEMU-Smoke-Test

Ein separat installiertes, unabhängig authentifiziertes Disk-Abbild kann ohne
virtuelle Netzwerkkarte und mit ausschließlich temporären Disk-Schreibvorgängen
gestartet werden. Abbild und tatsächlich ausgeführtes QEMU-Binary sind
SHA-256-gepinnt:

```sh
./vm/qemu-smoke.sh \
  /pfad/zum/debian-test.qcow2 \
  AUTHENTIFIZIERTER_DISK_SHA256 \
  AUTHENTIFIZIERTER_QEMU_SHA256 \
  qcow2
```

Das Skript verwendet `-nic none`, `-snapshot` und eine serielle lokale
Konsole. Optionaler UEFI-Firmware-Code muss ebenfalls separat gepinnt werden.
Dieser Lauf prüft Boot/CLI manuell, aber weder echte Netz-/Firewallwirkung noch
Hardware oder Mullvad. Siehe [`vm/README.md`](../vm/README.md).

## VM-Testmatrix

Mindestens folgende frische, netzlos installierte VMs mit serieller oder
grafischer Konsole verwenden:

| Ziel | Erwarteter Schwerpunkt |
|---|---|
| Debian 12 und 13 | APT-Offlineplan, `update-initramfs`, systemd/nftables, offiziell gegateter Mullvad-App-Pfad |
| Arch Linux | Explizite Paketartefakte unter `APPROVED`, `mkinitcpio`, systemd/nftables; App nicht als offiziell von Mullvad gepflegt behandeln |
| NixOS | Erzeugte native Nix-Module prüfen, `nixos-rebuild dry-build/test` manuell; keine imperative FHS-Annahme |
| Gentoo/OpenRC | USE-Flag-/Binärpaketplan, OpenRC-Service-/local.d-Pfade und distributionsnative Initramfs-Entscheidung |
| LFS/generic | Keine erfundene Paketverwaltung; manuelle Init-/Firewall-/Initramfs-Checkpoints müssen sichtbar blockieren |

Für jede VM:

1. Installationsmedium, Toolkit und Offline-Artefakte unabhängig prüfen; das
   Wheel für Root-Schritte in die dedizierte root-eigene Runtime installieren.
2. NIC trennen und Baseline-Snapshot erstellen.
3. `detect --json` mit tatsächlicher Hardware-/VM-Konfiguration vergleichen.
4. Alle drei Profile planen; Plan und Bericht gegen die erwartete Distribution
   prüfen.
5. Dry-Run in einem separaten State-Verzeichnis ausführen.
6. Vor produktivem Apply lokale Root-Anmeldung, Live-Medium, Snapshot und
   Recovery-Pfad testen.
7. Nur an der Konsole anwenden; jeden Reboot-Checkpoint ausführen und mit
   `resume` fortsetzen. Vor der Reboot-Postcondition muss absichtliche Drift an
   einer abgeschlossenen Test-Control die Fortsetzung geschlossen stoppen.
8. Nach Apply Listener, Services, Module, Funk, sysctl, nftables, Routing und
   DNS als unabhängige Evidenz erfassen.
9. Recovery und Rollback testen, danach zum Baseline-Snapshot zurückkehren.

## Firewall-Abnahme in einer VM

Vor Aktivierung:

```sh
sudo nft --check --file /etc/umzug/firewall.nft
sudo /usr/local/sbin/umzug-network-recovery
```

Nach erneutem, bewusst bestätigtem Apply:

```sh
sudo nft -a list table inet umzug_host
sudo systemctl status umzug-firewall.service
sudo systemctl status umzug-offline-guard.service
sudo systemctl is-enabled \
  umzug-firewall.service umzug-offline-guard.service
sudo systemctl cat \
  umzug-firewall.service umzug-offline-guard.service
sudo systemctl is-enabled ssh.service sshd.service
ss -lntup
```

Abnahmekriterien:

- INPUT und FORWARD haben Policy `drop`;
- kein `tcp dport 22 accept` und keine andere unerwartete eingehende
  Dienstfreigabe;
- kein SSH-Listener;
- Loopback, notwendige ICMP-Fehler und der erwartete DHCP-Pfad funktionieren;
- ein zweiter Testhost kann keinen nicht ausdrücklich freigegebenen Port
  erreichen;
- der Konsolen-Recovery-Befehl deaktiviert die drei Toolkit-Units und entfernt
  ausschließlich `inet umzug_host`, `inet umzug_vpn_lock`,
  `inet umzug_vpn_bootstrap_guard` und `inet umzug_offline_guard`; er öffnet
  keinen SSH-Port und lässt sich durch Rollback sauber nachbereiten;
- die beiden systemd-Netz-Units besitzen `RequiredBy=`/`Before=` für ihre
  Basic-/Network-/VPN-Ziele sowie `OnFailure=emergency.target` und
  `OnFailureJobMode=isolate`;
- in einer ausschließlich dafür vorgesehenen Snapshot-VM führt ein bewusst
  ungültiger Guard-/Firewall-Load beim Reboot in die lokale Emergency-Konsole,
  nicht in einen normalen netzfähigen Boot. Dort müssen `systemctl --failed`,
  die Unit-Journale und anschließend der Recovery-Befehl erreichbar sein.

Die Tests niemals ausschließlich über eine Remoteverbindung durchführen.

## Kill-Switch- und DNS-Abnahme

Die Unit-Tests für manuelles WireGuard verlangen einen wörtlichen Relay-IP-
Endpunkt und erlauben als Egress nur Loopback, Tunnel, diesen UDP-Endpunkt und
gegebenenfalls DHCPv4. Sie prüfen keine echte Mullvad-Sitzung.

Für die offizielle App ist ein separates, bewusst netzfähiges VM-Szenario mit
einem realen Konto nötig. Erst nach Offline-Hardening, vollständigem Apply,
Snapshot, **positiv erkannter verschlüsselter Mount-Abdeckung für
`/etc/mullvad-vpn`**, verifiziertem procfs auf `/proc` mit
`hidepid=2`/`hidepid=invisible` ohne `gid=`-Ausnahme, exakt leerem
`kernel.core_pattern`, `kernel.core_uses_pid=0` und vollständig leerem Swap.
Vor der Kontoabnahme lokal sichern:

```sh
findmnt -T /etc
findmnt -T /etc/mullvad-vpn
findmnt -no TARGET,FSTYPE,OPTIONS /proc
sysctl -n kernel.core_pattern
sysctl -n kernel.core_uses_pid
cat /proc/swaps
```

Die erste `sysctl`-Ausgabe muss leer, die zweite `0` und `/proc/swaps` auf die
Kopfzeile beschränkt sein. `strict`/`maximal` müssen die Core-Werte
einschließlich `fs.suid_dumpable=0` korrekt rendern und laden; Swap bleibt ein
ausdrücklich manueller, betriebsriskanter Schritt gemäß
[RECOVERY.md](RECOVERY.md). Vorhandene `account-history.json`/`device.json`
müssen bereits vor dem Prompt und nach dem Login – dann müssen beide Dateien
zwingend vorhanden sein – erneut als mit `O_NOFOLLOW` geöffnete, reguläre,
root-eigene Single-Link-Dateien von höchstens 1 MiB und Modus 0600 oder
strenger akzeptiert werden. Symlink, Hardlink, Gruppen-/Welt-Schreibbit,
falscher Eigentümer, Spezialdatei oder Übergröße muss fail-closed abbrechen.

1. Am lokalen TTY ausführen:

   ```sh
   sudo /usr/local/sbin/umzug-setup vpn-finalize \
     --state-dir /var/lib/umzug \
     --expected-plan-sha256 SHA256
   ```

   `SHA256` ist der zuvor separat geprüfte Digest des vollständig
   abgeschlossenen Plans.
2. Den vom Befehl verpflichtend ausgeführten Online-Nachweis und seine
   kontrollierte Disconnect-Probe prüfen: Lockdown-/Blocking-Zustand und genau
   eine Mullvad-OUTPUT-Basiskette mit Policy `drop` sind Pflicht; indirekte oder
   userspace-kontrollierte Verdictpfade sowie bedingungsloses Accept müssen
   scheitern. Mit `SO_BINDTODEVICE` gebundene rohe Literal-IP-Proben über
   TCP/80, TCP/443 und UDP/53 müssen auf jedem plangebundenen Ethernet-
   Interface fail-closed sein. TCP-Erfolg, `ECONNREFUSED` oder
   `ECONNRESET` und jedes empfangene UDP-Datagramm müssen als Leak gelten;
   nur definierte Policy-/Down-/Unreachable-/Timeout-Fehler als blockiert und
   jeder andere Socketfehler als unbestimmter Abbruch. Danach muss Reconnect
   wieder `connected` erreichen. Jeder direkte Erfolg muss den Schritt
   abbrechen, den Loopback-only-Bootstrap-Guard exakt verifizieren und
   `umzug-offline-guard.service` per `enable --now` rebootfest reaktivieren.
   Vor dem Test müssen Wiederholungen aus exakt Offline-, Bootstrap- oder
   Mullvad-Lockdown-Grenze starten; ein fehlender Guard muss vor
   Daemon-Restart abbrechen. Ein bereits fehlender Offline-Tabellenzustand muss
   unter Bootstrap-Guard idempotent fortsetzbar sein. Das Audit darf nur nach
   vollständigem Erfolg
   `finite_fail_closed_disconnect_checks_passed=true` enthalten.
3. `mullvad status -v`, `wg show`, `nft -a list ruleset` und
   `ip route show table all` unabhängig sichern. Wenn `resolvectl` bereits
   receiptgebunden vorhanden ist, zusätzlich `resolvectl status` erfassen;
   ein statischer, stabil gelesener `resolv.conf`-Pfad bleibt zulässig.
4. Optional die Trennung mit einem anderen harmlosen Literal-IP-Ziel und einem
   Hypervisor-Paketmitschnitt wiederholen. Das erweitert nur die endliche
   Stichprobe; es ist kein formaler Leak-Freiheitsbeweis.
5. Virtuelles Ethernet kurz trennen und wieder verbinden; während Ausfall und
   Reconnect darf kein normaler Egress außerhalb des Tunnels sichtbar sein.
6. Mit einer zweiten VM bestätigen, dass weiterhin kein eingehender Dienst
   veröffentlicht ist.

Mullvads dokumentierte API-/Root-/DHCP-Ausnahmen bedeuten, dass „kein einziges
Paket außerhalb des Tunnels“ kein korrektes absolutes Testkriterium ist. Ein
Paketmitschnitt am Hypervisor kann Bootstrap-Ausnahmen und Relayverkehr
beobachten; Anwendungsverkehr und DNS dürfen nicht am Tunnel vorbeigehen.

## Negative Zero-Trust-Abnahme

In einer ausschließlich dafür vorgesehenen VM mit harmlosen Testfixtures
prüfen:

- ZIP mit `../`, absolutem Pfad, Duplikat oder Link-Flucht;
- verschlüsseltes oder beschädigtes Archiv;
- hochkomprimiertes Bombenfixture unter kleinen Testlimits;
- Symlink/Hardlink außerhalb des Kandidaten;
- FIFO oder andere Spezialdatei;
- private Testschlüssel-/Tokenmarker;
- ausführbare Datei, Git-Hook und aktive lokale Git-Konfiguration;
- fehlende, manipulierte oder ungepinnte YARA-/ClamAV-/Bubblewrap-Artefakte;
- zstd/RPM-zstd mit fehlendem oder falschem `zstd`-/Bubblewrap-Pin sowie
  Überschreitung von `-M128`, Timeout oder Outputlimit;
- Manipulation zwischen Scan und Approval;
- fehlender, veralteter oder manipulierter Provenienz-/Promotion-Beleg;
- ausgetauschter SOURCE-, Ingest-QUARANTINE-, Promotion-QUARANTINE- oder
  SANITIZED-Report, abweichende Policy-/Toolbindung oder nicht exakt gebundene
  Promotion-Review-IDs;
- beschreibbarer Quellmount.

Jeder Fall muss einen nicht quittierbaren Blocker oder einen vollständigen
Abbruch erzeugen. Testfixtures dürfen keine echte Malware und keine echten
Zugangsdaten enthalten.

Die Vendor-Kette zusätzlich mit harmlosen, eigens erzeugten OpenPGP-Testkeys
prüfen: Eine korrekte Detached Signature muss einen Receipt erzeugen; falscher
Fingerprint, falscher `gpg`-/`gpgv`-/Bubblewrap-Hash, ausgetauschtes Artefakt,
ausgetauschte Signatur, Symlink/Traversal, zweiter primärer Schlüssel,
geänderter Receipt und vorhandener Ausgabepfad müssen scheitern. Anschließend
muss `plan --mullvad-artifact ... --mullvad-vendor-receipt ...
--mullvad-artifact-sha256 ... --mullvad-package-version ...
--mullvad-package-architecture ...` mit unabhängig erneut angegebenen
Fingerprint-/`gpg`-/`gpgv`-/Bubblewrap-Ankern sowie exakter Paketidentität den
gesamten Signaturnachweis noch einmal ausführen und einen Artefaktaustausch
erkennen. Testkeys dürfen niemals produktiv verwendet werden.

## Zielkriterien für einen späteren vollständigen MVP-Release

Diese Liste ist eine Zielmatrix, kein behaupteter Status von v0.2.0rc1. Der RC
ist nur für den in [HARDWARE-TEST.md](HARDWARE-TEST.md) beschriebenen
dedizierten H0-Lauf vorgesehen; insbesondere H1/H2, Arch/NixOS/Gentoo/LFS und
die folgenden VPN-/Boot-Nachweise sind damit noch nicht hardwareabgenommen.

- Kompletter pytest-Lauf erfolgreich;
- Offline-Wheel ohne Netz gebaut und dessen Hash dokumentiert;
- Hilfetexte und Dokumentation stimmen mit dem `umzug-pack`-Entry-Point und
  dem separat installierten isolierenden `umzug-setup-root`-Wrapper überein;
- produktive Root-Ausführung akzeptiert nur die root-eigene Runtime, und der
  Quellbaum-Launcher verweigert EUID 0;
- mindestens Debian- und Arch-Plan in frischen VMs geprüft;
- Firewall-Default-Drop, kein SSH, Recovery und Rollback praktisch bestätigt;
- systemd-Boot-Gates führen bei simuliertem Ladefehler nach `emergency.target`
  und lassen sich ausschließlich lokal wiederherstellen;
- Reboot/Resume nach realem Initramfs-Neubau einschließlich Re-Verifikation
  abgeschlossener verwalteter Dateien und effektiver Controls geprüft;
- Scanner fällt bei fehlender Isolation oder Analysekomponente geschlossen aus;
- Vendor-Receipt und Planbindung lehnen manipulierte Schlüssel, Tools,
  Signaturen, unabhängige Artefakthashes, Artefakte und Receipts ab;
- die typisierte Action-Registry lehnt unbekannte beziehungsweise manipulierte
  privilegierte Operationen, Pfade, Argumente, Safety-Flags und Verifier ab;
- produktives Apply lehnt fehlende beziehungsweise abweichende unabhängige
  Plan-SHA-256-Bestätigung ab;
- keine Kontonummer, privaten Schlüssel oder Tokens in Logs/Reports;
- `vpn-finalize` verweigert die Kontoeingabe ohne positiv erkannte
  verschlüsselte Mount-Abdeckung für `/etc/mullvad-vpn`, sichere
  Account-/Device-Dateien, sichere procfs-`hidepid`-Policy, exakt deaktivierte
  globale Core-Dumps, vollständig inaktiven Swap oder nicht-dumpbaren Prozess
  mit `RLIMIT_CORE=0`; die reale TCP/80-, TCP/443- und
  UDP/53-Disconnect-/Reconnect-Probe fällt bei jedem direkten Ethernet-Egress
  geschlossen aus, und die Mullvad-OUTPUT-Kette verlangt Policy `drop` ohne
  indirekte Verdictpfade;
- alle nicht automatisierten Distributions- und Hardwaregrenzen im
  Abschlussprotokoll festgehalten.
