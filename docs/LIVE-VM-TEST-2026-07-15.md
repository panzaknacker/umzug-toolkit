# Live-VM-Abnahme vom 15. Juli 2026

Dieses Protokoll dokumentiert einen begrenzten, **historischen Lauf des
v0.1.0-Stands vor v0.2.0rc1** auf zwei ausdrücklich bereitgestellten,
kurzlebigen Cloud-VMs. Es ist weder eine Abnahme des aktuellen
v0.2.0rc1-Hardware-Testkandidaten noch ein Produktionszertifikat und
insbesondere kein Nachweis, dass Inhalte malwarefrei sind. Die nachstehenden
Hashes, Testzahlen, Plandigests und Aktionszahlen bleiben historische Werte
dieses damaligen Laufs und dürfen nicht auf einen aktuellen Build übertragen
werden.

## Vertrauensgrenze und Artefakte

Die SSH-Hostschlüssel wurden vor dem Test per TOFU lokal fest gepinnt, aber
nicht über einen zweiten, vom VM-Zugriff unabhängigen Kanal bestätigt. Die
Ergebnisse belegen deshalb das Verhalten auf den erreichten Endpunkten, nicht
deren externe Provenienz.

Der damals lokal netzlos gebaute v0.1.0-Stand hatte:

- Wheel:
  `41d7ee530430a10eeff1e38c517504d9e673b38f59c5e55c97e12238fc355304`
- Pip-freier Installer:
  `cb9dac3cfe713ddc834dd07ea9e5d97419571226de069d7f55bb0a02654f9696`
- Lokale Prüfung: 428 Tests und 3 Untertests bestanden;
  Python-/Shell-Syntax sowie YARA-Regelkompilierung bestanden
- Lokal nicht verfügbar: `shellcheck`; dieser optionale Lint-Lauf wurde
  daher nicht behauptet

Beide Artefakte wurden auf beiden VMs nach dem Upload root-eigen gestagt,
erneut gehasht und vom isoliert gestarteten Offline-Installer erfolgreich nach
`/opt/umzug/runtime` installiert. Ältere Test-Runtimes wurden dabei erhalten,
nicht überschrieben.

## Erkannte Ziele

| Merkmal | Debian-VM | Ubuntu-VM |
|---|---|---|
| Distribution | Debian 13 (trixie) | Ubuntu 24.04.4 LTS |
| Kernel | 6.12.63+deb13-cloud-amd64 | 6.17.0-1010-aws |
| Architektur / Init / Pakete | x86_64 / systemd / apt | x86_64 / systemd / apt |
| Firmware | BIOS gemeldet, Secure Boot nicht unterstützt | UEFI, Secure-Boot-Variable im Setup-Zustand |
| Ethernet | ein physisches `ens5`, Treiber `ena` | ein physisches `ens5`, Treiber `ena` |
| Funkgeräte | keine erkannt | keine erkannt |
| TPM / IOMMU | nicht erkannt / nicht aktiv | nicht erkannt / nicht aktiv |
| Root-Verschlüsselung | nicht vorhanden | unklar |
| Relevante fehlende Werkzeuge | `nft`, `rfkill` | `rfkill` |

Die Erkennung lief auf beiden Systemen mit Exit 0. Hardware- und
Secure-Boot-Aussagen bleiben Best-Effort-Befunde aus Cloud und Firmware.

## Planung und mutationsfreie Ausführung

Das Profil `strict` wurde mit den Capabilities Firewall, WireGuard, Audit,
Integritätsprüfung, SSH-Client und Funkkontrolle sowie ohne unvorbereitetes
Mullvad-Vendorpaket geplant. Beide Pläne banden exakt das erkannte physische
Ethernet-Interface und enthielten 36 Aktionen:

- Debian-Plan:
  `87627a4315cffe3f23c34823bfc42ef4321090d2a0cb806ec09416af07ac717c`
- Ubuntu-Plan:
  `104bd3c9fdddc105b7283fb66958582b5dd6508249d66f98976eb64334e399af`

Beide Dry-Runs wurden nach der Installation des finalen Wheels erneut
ausgeführt und endeten mit Exit 0 und `completed: []`. Der generische
Debian-/Ubuntu-Offline-Adapter erzeugte keinen `apt-get`-Installationsbefehl.
Die produktiven Preflight-Negativtests liefen mit dem unmittelbar
vorausgehenden Build; der dabei geprüfte Plan-/Executorpfad änderte sich bis
zum finalen Wheel nicht. Ohne `--expected-plan-sha256` brach Debian vor der
State-Erzeugung und vor jeder Systemänderung ab. Mit dem korrekten Digest
stoppte Debian am fehlenden `nft`-Preflight. Ubuntu band das vorhandene `nft`
nach expliziter Bestätigung an sein Executable-Receipt und stoppte anschließend
am fehlenden `rfkill`. In beiden Fällen existierte die erste geplante
Systemdatei danach nicht; `ssh.service` blieb aktiv.

Produktive Firewall-, SSH-Deaktivierungs-, Initramfs-, Boot- und
Reboot-Aktionen wurden nicht remote angewendet. Ohne unabhängig getestete
serielle/Hypervisor-Konsole wäre ein absichtlicher SSH-Lockout nicht
verifizierbar oder sicher wiederherstellbar gewesen.

## Reale Pack- und Zero-Trust-Pipeline

Auf Ubuntu wurde eine synthetische Quelle mit einer 400-Byte-Textdatei und
einem relativen internen Symlink gepackt. Es wurden keine Inventare,
Zugangsdaten oder privaten Nutzerdaten aufgenommen. Das unverschlüsselte
Testbundle hatte:

- Bundle-SHA-256:
  `3846854ec18183559848f5982d2c240d4e936b9a57fc4d25f63f7dddfaa5e745`
- Ed25519-Public-Key-Fingerprint:
  `1954a5a97238ea5211c819796ef524357f109efc74f2609bf001e75af159da05`
- Größe: 20.480 Byte

Zwei Pack-Läufe mit unveränderter Quelle, demselben vorhandenen Schlüssel und
demselben `SOURCE_DATE_EPOCH` erzeugten byteidentische Bundles (`cmp` Exit 0).
Damit wurde die reproduzierbare Manifest-Erstellzeit auch im Live-Lauf
nachgewiesen. Verschlüsselte Bundles und neu erzeugte Schlüssel bleiben
absichtlich nicht bitidentisch.

`--generate-signing-key` verlangte in der nichtinteraktiven SSH-Sitzung wie
von OpenSSL vorgesehen eine Passphrase und erzeugte nach dem Abbruch weder
Schlüssel noch Bundle. Für diesen ausschließlich synthetischen Wegwerftest
wurde danach separat ein unverschlüsselter Ed25519-Testschlüssel mit Modus
0600 erzeugt. Er blieb auf der Ubuntu-VM und wurde nie transportiert. Das ist
kein empfohlenes Produktionsverfahren; produktive Schlüssel sind
passwortgeschützt an einem lokalen TTY zu erzeugen.

Der Bundle-Hash war auf Ubuntu, dem Controller, nach dem Upload auf Debian und
im simulierten Medium identisch. Auf Debian wurde ein 64-MiB-ext4-Abbild als
schreibgeschütztes Loop-Blockgerät angebunden. `setup mount-source` bestätigte
exakt `ro,nodev,noexec,nosuid`; ein Root-Schreibversuch scheiterte mit
`Read-only file system`.

`setup ingest` des finalen Wheels validierte Transporthash, Bundle, Manifest,
Ed25519-Signatur und den getrennt notierten Fingerprint. Der Ingest-Beleg
enthielt exakt `unsafe_source_mount_tainted: false`. Der Kandidat `item-0000`
gelangte nur nach `SOURCE` und `QUARANTINE`. Ein zweiter finaler Ingest mit
einem absichtlich falschen Fingerprint brach mit
`signing key fingerprint mismatch` ab und erzeugte keinen
Quarantäne-Kandidaten.

Der strikte Scan des echten Quarantänebaums endete erwartungsgemäß mit Exit 3:

- 3 untersuchte Objekte
- 8 Blocker
- 1 Review-Fund
- Blocker unter anderem für fehlende bzw. nicht gepinnt konfigurierte ClamAV-
  und YARA-Evidenz, fehlendes Bubblewrap und unvollständigen Tool-Snapshot

Die Promotion mit dem korrekt gebundenen Quarantäne-Manifest scheiterte wegen
9 ungelöster Funde. `SANITIZED`, `APPROVED` und `RESTORED` blieben leer. Das
relative Symlinkziel blieb in Quarantäne erhalten; Dateimodi und Eigentümer
wurden dort absichtlich auf root/0600 verschärft.

Ein separater Negativtest las dasselbe Bundle absichtlich über
`--allow-unsafe-source-mount-for-testing` von einem normalen Home-Dateisystem
ein. Der Ingest-Beleg enthielt exakt `unsafe_source_mount_tainted: true`.
Selbst mit dem korrekten Manifest verweigerte die Paket-Schranke die Promotion
mit Exit 2; `SANITIZED` blieb leer. Der Test-Override kann damit keine
Freigabekette begründen.

Das Loop-Medium wurde nach den Mount-/Ingest-Tests ausgehängt und das
Loop-Gerät getrennt. Eine abschließende Zustandsprüfung meldete auf beiden VMs
den weiterhin aktiven SSH-Server; weder der geplante lokale Recovery-Befehl
noch die Offline-Firewalldatei existierten. Der Sicherheitsbericht meldete
wahrheitsgemäß die fehlende Host-Firewall, fehlende beziehungsweise unklare
Root-Verschlüsselung und keinerlei Approval oder Restore.

## Nicht durch diesen Lauf bewiesen

- Kein produktiver Hardening-/Firewall-/Rollback-/Reboot-/Resume-Lauf ohne
  lokale Recovery-Konsole
- Kein echter Mullvad-Login, Tunnel oder Kill-Switch-Livetest: Es lagen weder
  ein unabhängig verifiziertes Vendor-Artefakt noch eine Kontonummer vor;
  zudem würde die erkannte fehlende beziehungsweise unklare
  Root-Verschlüsselung den Account-Schritt fail-closed blockieren
- Kein verschlüsselter Realtransport; das Bundle enthielt ausschließlich
  synthetische öffentliche Testdaten
- Kein Restore, weil die strikte Scannerpolicy eine Freigabe richtigerweise
  verhinderte
- Keine Live-Abnahme von Arch Linux, NixOS, Gentoo oder LFS; diese Adapter sind
  in lokalen Tests und Fixtures abgedeckt, nicht durch diesen Zwei-VM-Lauf
- Kein vollständiger Beweis der APT-Dependency-Closure des engen
  Mullvad-DEB-Pfads; der generische Offline-APT-Pfad bleibt deshalb ohne
  signatur- und hashgebundenen Repository-Snapshot ein manueller
  Nicht-Ausführungs-Checkpoint
- Keine Garantie von Malwarefreiheit, Leakfreiheit oder zukünftiger
  Systemsicherheit
