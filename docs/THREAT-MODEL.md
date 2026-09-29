# Bedrohungsmodell

Stand: 15.07.2026. Dieses Dokument beschreibt den MVP, nicht ein Versprechen
über zukünftige Funktionen.

## Zentrale Aussage

**Das Toolkit kann keine Malwarefreiheit garantieren.** Kein Scanner, keine
Signatur und keine noch so strenge statische Pipeline kann beweisen, dass ein
beliebiger Datenbestand frei von Trojanern, Backdoors, Logikbomben,
Supply-Chain-Manipulationen oder bisher unbekannten Exploits ist. Das Ziel ist
Risikoreduktion durch Isolation, mehrere unabhängige Kontrollen,
nachvollziehbare Freigaben und Fail-closed-Entscheidungen.

## Schutzgüter

- Integrität und Bootfähigkeit des frisch installierten Zielsystems;
- Geheimnisse, insbesondere private Schlüssel, Tokens, Passwörter und die
  Mullvad-Kontonummer;
- Vertraulichkeit und Integrität des Migrationspakets;
- Firewall-, Routing- und DNS-Zustand;
- Nachvollziehbarkeit von Auswahl, Scan, Freigabe, Änderung und Rollback;
- Trennung zwischen analysierten und tatsächlich installierten Daten.

## Angreifermodell

Als potenziell kompromittiert gelten:

- altes Betriebssystem einschließlich Kernel, Benutzerland und `pack`-Laufzeit;
- alle Projekte, Git-Repositories, Dotfiles, Archive, Dokumente und Medien;
- USB-/SD-/externe Datenträger und deren Dateisystem-Metadaten;
- Paketlisten, Service-Definitionen, Hooks, Buildsysteme und Abhängigkeiten;
- Dateinamen, Symlinks, Hardlinks, ACLs, xattrs und Capabilities;
- lokale Malware-Signaturen oder Analyseprogramme, solange ihre Herkunft und
  Hashes nicht unabhängig verifiziert wurden.

Angriffe umfassen bekannte und unbekannte Malware, Parser-Exploits,
Archivbomben, Pfad-Traversal, TOCTOU-Austausch, irreführende Unicode-Namen,
Secrets in Dateien, Git-Hooks/-Filter/-Submodule, Build- und Editor-Hooks,
Boot-/Kernel-/Firmware-Persistenz sowie manipulierte Paketquellen.

Nicht abgedeckt sind ein bereits kompromittierter Zielkernel, bösartige
Firmware, CPU-/TPM-/UEFI-Implantate, ein kompromittierter Hypervisor, physische
Angriffe während der Analyse und ein Angreifer mit dauerhaftem Root-Zugriff auf
das Ziel. Gegen diese Gegner kann lokale Software keine belastbare
Sicherheitsgrenze herstellen.

## Vertraute Basis

Die belastbare Basis muss außerhalb des alten Systems aufgebaut werden:

1. frisch installiertes, verifiziertes Ziel- beziehungsweise Analysemedium;
2. Firmware-/Secure-Boot-Vertrauensanker, soweit vorhanden und geprüft;
3. Offline-Kopie des Toolkit-Quellcodes oder Wheels mit unabhängig geprüftem
   Release-Hash beziehungsweise Signatur;
4. separat verankerte OpenSSL-/`age`-/GnuPG-, Bubblewrap-, `zstd`-, Scanner-,
   YARA- und ClamAV-Artefakte;
5. aus unabhängiger Quelle geprüfter Ed25519-Public-Key oder Fingerprint des
   Migrationsmanifests;
6. vertrauenswürdige lokale Paket-Repositories samt Hersteller-Schlüsseln;
7. für Vendor-Pakete: separat geprüfter OpenPGP-Schlüssel, dessen 40-stelliger
   primärer Fingerprint sowie Hashes der verwendeten `gpg`-/`gpgv`- und
   Bubblewrap-Binärdateien.

SHA-256-Pinning beweist nur Gleichheit mit einem erwarteten Artefakt. Die
Erwartungswerte dürfen nicht ausschließlich vom gleichen nicht
vertrauenswürdigen Datenträger stammen. Für Releases sind Herstellersignaturen
und Schlüssel-Fingerprints über einen zweiten Kanal zu prüfen.

## Pflichtumgebung für Quellmedien

Das Quellmedium ist standardmäßig in einer wegwerfbaren, netzlosen VM oder einer
vergleichbar starken Isolation zu untersuchen. Automount, Desktop-Vorschau,
Indexer, udev-Helfer und Autorun müssen deaktiviert sein. Es wird nur lesbar mit
folgenden Optionen eingebunden:

```text
ro,noexec,nodev,nosuid
```

`noexec` verhindert nicht, dass ein Interpreter eine gelesene Datei ausführt.
Darum darf nichts geöffnet, importiert, kompiliert, getestet oder mit einem
Editor mit Plugins geladen werden. Die Optionen sind zusätzliche
Schadensbegrenzung, keine Sandbox. `mount-source` kann das explizite
Blockdevice mit allen vier Optionen mounten, und `ingest` prüft sie erneut. VM,
Desktop-/udev-Automount-Sperren und die übergeordnete Isolation erzeugt der MVP
nicht; der Betreiber muss den Zustand zusätzlich mit `findmnt` kontrollieren.

## Trust-Zonen und Freigabe

Nur die Richtung `SOURCE → QUARANTINE → SANITIZED → APPROVED → RESTORED` ist
zulässig. Keine Datei darf eine Zone überspringen. Nur `APPROVED` darf in das
Ziel gelangen.

- `SOURCE`: unveränderbarer Snapshot der nicht vertrauenswürdigen Bytes;
  niemals ausführen. Ein selbstgehashter Provenienzbeleg bindet SOURCE- und
  Ingest-QUARANTINE-Scan/-Report/-Manifest sowie das unveränderliche
  SOURCE-Snapshot-Manifest.
- `QUARANTINE`: inerte Arbeitskopie ohne Spezialdateien, SUID/SGID oder
  ausführbare Bits.
- `SANITIZED`: Kandidat nach vollständiger Analyse. Ein selbstgehashter
  Promotion-Beleg bindet Provenienz, den exakten strikten blockerfreien
  Promotion-QUARANTINE-Report, seine exakt akzeptierten Review-IDs und den
  SANITIZED-Scan/-Report/-Manifest. Im MVP bedeutet dies keine automatische
  semantische Bereinigung.
- `APPROVED`: exakte Bytes mit hashgebundener menschlicher Freigabe; Blocker
  bleiben unüberstimmbar. Der ausgegebene Approval-Hash muss anschließend auf
  einem vom Workspace unabhängigen, geschützten Kanal festgehalten werden.
- `RESTORED`: bestätigte, nicht überschreibende Kopie samt Content- und
  Metadaten-Receipt. Vor der Kopie werden das ursprüngliche Bundle, Signatur
  und `SOURCE.tar` sowie SOURCE-, Ingest-QUARANTINE-, Promotion-QUARANTINE-
  und SANITIZED-Report, beide selbstgehashten Ableitungsbelege, Approval und
  APPROVED-Baum fd-/nofollow gesnapshottet und vollständig gegen unabhängigen
  Schlüssel/Fingerprint und erwarteten Approval-Hash geprüft. Alte oder
  unvollständige Belege schlagen fail-closed fehl. UID/GID werden nur über
  identische signierte Namen abgebildet; rohe IDs, Execute-/Privileged-Bits,
  ACLs, Capabilities und xattrs werden nicht übernommen.

Review-Funde dürfen nur einzeln über ihre stabilen IDs akzeptiert werden.
Unlesbare, veränderliche, beschädigte, verschlüsselte oder durch Limits nur
teilweise untersuchte Dateien erzeugen Blocker.

## Analyseverfahren

Der eingebaute Scanner führt, ohne Eingaben zu extrahieren oder auszuführen,
unter anderem folgende unabhängige Klassen von Prüfungen durch:

- SHA-256 und Metadatenbindung mit `O_NOFOLLOW` und Austauschprüfung;
- Inhaltssignaturen für ELF, PE, Archive, PDF, Bilder, Medien und Skripte statt
  blindem Vertrauen in Dateiendungen;
- rekursive, limitierte ZIP-/tar-/gzip-/bzip2-/xz-Inspektion;
- vollständige zstd-Dekompression ausschließlich mit SHA-256-gepinntem `zstd`
  und Bubblewrap, ohne Netzwerk, mit `-M128` und harten Zeit-/Input-/Output-/
  Expansionslimits; Scheitern oder fehlende Pins blockieren;
- Member-, Größen-, Tiefen- und Expansionslimits gegen Archivbomben;
- absolute Pfade, `..`, Windows-Laufwerke, Duplikate und Link-Escapes;
- verschlüsselte, beschädigte und nicht unterstützte Archive;
- SUID/SGID, ausführbare Bits, Spezialdateien, Link-Fluchten und Hardlinks mit
  Zielen außerhalb des Kandidaten;
- Extended Attributes, Linux Capabilities und POSIX-ACL-Indizien;
- unsichtbare/Control-/Bidi-Zeichen, Normalisierung und gemischte Schriften;
- versteckte Namen, auf Alternate Streams verdächtige Doppelpunkte und
  Widersprüche zwischen Typ und Endung;
- Secrets, private Schlüssel, Token-/Passwortmuster, Netzwerk-Endpunkte,
  Download-and-Execute, Shell-/Loader-/Persistenzmuster und verschleierte Blobs;
- aktive PDF-/RTF-Inhalte, Makro-Endungen und eingebettete Payload-Signaturen in
  Bildern;
- Git-Hooks, aktive Git-Filter/`sshCommand`/URL-Rewrites sowie Boot-,
  Initramfs-, Kernelmodul- und Firmwarepfade;
- begrenzte strukturelle DEB-/RPM-Prüfung; native Payloads und
  Maintainer-Skripte bleiben reviewpflichtig;
- externes `file`, ClamAV und YARA unter festen Limits und ohne Shell in einer
  Bubblewrap-Isolation ohne Hostnetz und ohne sichtbare Hostwurzel. Nur minimale
  schreibgeschützte Runtime-Bäume, private Runtime-Mounts, der unveränderliche
  Dateisnapshot und explizit gepinntes Analysematerial werden eingebunden.

Im strikten Standardmodus sind Bubblewrap, externe Tools, YARA-Regeln und genau
eine explizit an `clamscan --database=…` gebundene ClamAV-Datenbankdatei oder
ein Datenbankbaum nur dann akzeptabel, wenn ihr exakter SHA-256-Wert in der
Policy vorab verankert ist. Ein Virenscanner allein reicht ausdrücklich nicht.

## Grenzen der Analyse

- Heuristiken erzeugen False Positives und False Negatives.
- Der Scanner führt keine dynamische Malwareanalyse, Emulation oder
  Speicherforensik durch.
- 7z und RAR werden erkannt, aber in der eingebauten Engine nicht vollständig
  analysiert und deshalb blockiert.
- Office- und PDF-Parser sind bewusst keine vollständigen Formatinterpreter.
  Komplexe Dokumente sollten in einer separaten CDR-Strecke in passive Formate
  konvertiert werden.
- Ein harmlos wirkender Quelltext kann erst durch Compiler, Dependency
  Resolver, Editor, Language Server oder Tests schädlich werden. Eine Freigabe
  erlaubt daher noch keinen Build auf dem produktiven Ziel.
- Unbekannte native Binärdateien sind im Standard blockiert. Eine
  Neuübersetzung aus geprüftem Quellcode ist besser, aber ebenfalls kein
  Malwarefreiheitsbeweis.
- DEB/RPM-Parsing beweist weder Paketherkunft noch Harmlosigkeit. Der separate
  Vendor-Receipt im Format `umzug-vendor-verification-v4` beweist nur, dass
  exakt diese Bytes in der gepinnten, netzlosen Sandbox von einem Schlüssel mit
  dem erwarteten Fingerprint verifiziert wurden. Die Planung führt den Beweis
  mit unabhängig neu angegebenen Fingerprint-/Toolhash-Ankern nochmals aus; das
  schützt nicht vor Schlüsselkompromittierung, bösartigen signierten Paketen,
  Widerruf, Ablauf oder kompromittierten Hersteller-Buildsystemen.
- Das Kopieren in eine Trust-Zone erzeugt keine echte Read-only-Mount-Garantie;
  Dateirechte sind nur eine zusätzliche Kontrolle. VM-/Dateisystem-Isolation
  bleibt erforderlich.
- Für jeden Scan werden reguläre Dateien nofollow in einen privaten
  0700-Temporärbaum mit 0400-Snapshots kopiert. Der Scanner analysiert diese
  stabilen Bytes, prüft den Originalbaum danach erneut und löscht den
  Temporärbaum regulär. Standardobergrenzen sind 256 MiB pro Datei und 1 GiB
  insgesamt; Überschreitungen blockieren. Ein Prozessabbruch kann temporäre
  Kopien zurücklassen, und privilegiertes root kann sie lesen. `TMPDIR` deshalb
  auf verschlüsseltem, isoliertem Storage bereitstellen und nach Abbruch prüfen.
- Die hashgeprüften Werkzeug-Snapshots schließen die ausgeführte Runtime nicht
  vollständig kryptografisch: Dynamischer Loader, Shared Libraries, NSS-/
  Locale-Daten, Kernel und weitere schreibgeschützt eingebundene Laufzeitteile
  sind nicht lückenlos einzeln gepinnt. Read-only im Namespace bedeutet nicht,
  dass die Bytes auf dem Host vertrauenswürdig sind.
- Ein bereits aktiver Angreifer mit derselben UID kann Scannerprozess und
  private Snapshots angreifen. Privilegiertes root, Kernel und Hypervisor liegen
  ebenfalls außerhalb der Schutzgrenze. Die Abwehr von Pfad-/Symlink-Races ist
  keine MAC-Isolation gegen diesen Angreifer auf demselben Host. Produktive
  Analyse gehört deshalb in eine frische, netzlose VM aus unabhängig
  verifizierten Basisbytes.

## Projekte und Git-Repositories

Eigene Repositories genießen keinen Vertrauensbonus. Vor einer Freigabe sind
mindestens zu prüfen beziehungsweise neu zu erzeugen:

- `.git/hooks`, lokale Git-Konfiguration, Includes, Filter, `sshCommand`,
  Credential Helper und URL-Rewrites;
- Submodules, LFS-Pointer, Alternates, Worktrees und objektbezogene Integrität;
- Makefiles, Nix-Flakes, `shell.nix`, `flake.nix`, Dockerfiles, Devcontainer,
  CI-Workflows und Lifecycle-Skripte von Paketmanagern;
- Editor-/IDE-Konfiguration, Tasks, Debugger, Language Server und Autostart;
- Lockfiles, Vendoring, Checksums, Signaturen und Herkunft jeder Abhängigkeit;
- generierte Dateien, Compiler-Artefakte und Binärblobs.

Im MVP existiert kein vollständiger Verifier für Git-Objekte und
Commit-Signaturen und kein sicherer automatischer Build. Repositories erst in
einer neuen, wegwerfbaren, netzlosen Build-VM öffnen; Hooks deaktivieren und
Abhängigkeiten nur aus einem separat geprüften Offline-Store beziehen.

## Geheimnisse

`pack` schließt bekannte Secret-Pfade und Namensmuster standardmäßig aus.
`--include-sensitive` ist nur zusammen mit Vollpaketverschlüsselung zulässig und
verlangt eine zusätzliche Risikoquittierung. Das ist keine vollständige
Secret-Erkennung. Der Scanner blockiert weitere Muster, kann aber beliebig
kodierte Geheimnisse übersehen.

Audit-Logs werden rekursiv anhand von Schlüsseln und Werten redigiert, darunter
16-stellige Mullvad-Kontonummern. Das Log ist lokal Modus 0600, aber nicht
kryptografisch verkettet oder signiert. Elternkomponenten und Logdatei werden
nofollow geöffnet; das Log muss eine reguläre, einfach verlinkte Datei im
Eigentum des aufrufenden Benutzers sein. Unsichere Symlink-/Hardlinkziele werden
abgewiesen. Kommandoausgaben anderer Programme können unbekannte
Geheimnisformate enthalten und müssen vor der Weitergabe geprüft werden.

Eine explizite `--age-identity` bleibt ein hochsensibler lokaler
Entschlüsselungsschlüssel. Das Toolkit akzeptiert sie nur als reguläre
Nicht-Symlink-Datei mit Modus 0600 oder strenger, kopiert und protokolliert sie
nicht. Ein kompromittierter Ziel-Root oder die ausgeführte `age`-Binärdatei
liegt dennoch innerhalb der vertrauten Basis.

## Manifest-Signatur: Aussage und Nichtaussage

Der gebündelte Public Key ist allein nicht vertrauenswürdig. Ein Angreifer kann
Paket, Manifest, Signatur und Schlüssel gemeinsam ersetzen. Deshalb muss
mindestens `--trusted-key` oder der erwartete Fingerprint aus einem unabhängigen
Kanal kommen. Selbst dann bedeutet eine korrekte Signatur nur: „Diese Bytes
wurden von jemandem mit diesem privaten Schlüssel signiert und danach nicht
verändert.“ Sie bedeutet nicht „sicher“, „geprüft“ oder „malwarefrei“.

## Risiken der Systemhärtung

`maximal` kann User Namespaces, `kexec`, Dateisystem- und Funkmodule sperren und
IPv6 vollständig deaktivieren. Das kann Container, Desktop-Sandboxes,
Dateisysteme, Recovery, Hardware und Bootfähigkeit beeinträchtigen. Modprobe-
und Initramfs-Änderungen werden oft erst nach einem Neustart vollständig
wirksam. Ein Firewall-Lockdown kann den Netzwerkzugang absichtlich verlieren
lassen.

Auf systemd sind Offline-Guard und Host-Firewall absichtlich harte frühe
Boot-Abhängigkeiten. Fehlende Werkzeuge, beschädigte Regeln oder ein
nftables-Ladefehler isolieren nach `emergency.target`, statt mit möglicherweise
offenem Netz weiterzubooten. Das schützt die Netzgrenze, erhöht aber das Risiko
eines lokalen Boot-/Verfügbarkeitsausfalls und setzt eine funktionierende
Konsolenanmeldung voraus. Deshalb:

- ausschließlich an lokaler Konsole arbeiten;
- jeden Diff und jede Action-ID prüfen;
- Recovery-Befehl und Live-Medium vorher testen;
- wichtige Dateisystem-/VM-Snapshots außerhalb des Toolkits anlegen;
- Secure Boot, FDE, Partitionierung und Bootloader nicht als vom MVP
  automatisch abgesichert betrachten.

## Mullvad-Vertrauens- und Grenzmodell

Stand 15.07.2026 ist Mullvad WireGuard-only; OpenVPN wurde server- und
clientseitig am 15.01.2026 entfernt. Das Toolkit bietet OpenVPN deshalb nicht
an. Offizielle Quellen: [OpenVPN-Entfernung](https://mullvad.net/en/blog/final-reminder-for-openvpn-removal),
[Mullvad-Protokollbeschreibung](https://mullvad.net/en/why-mullvad-vpn).

Die konservative, im Toolkit festgeschriebene Matrix vom 15.07.2026 umfasst
Debian 12/13, Ubuntu 24.04/25.10/26.04 und Fedora 43/44 auf x86-64 oder ARM64.
Vor späterer Nutzung ist sie gegen die
[offizielle Plattformmatrix](https://github.com/mullvad/mullvadvpn-app/blob/main/docs/supported-platforms.md)
und die [Linux-Installationsanleitung](https://mullvad.net/en/help/install-mullvad-app-linux)
neu zu prüfen. Archs Repository-Paket wird nicht von Mullvad gepflegt; NixOS,
Gentoo und LFS sind für die App Best-Effort. Dort ist eine separat geprüfte
manuelle WireGuard-Konfiguration die konservative Alternative.

Die offizielle App hat einen nicht abschaltbaren Kill-Switch während Verbindung
und Fehlerzuständen. Nur Lockdown blockiert zusätzlich nach bewusstem
Disconnect/Quit. Das Toolkit setzt daher Auto-Connect und Lockdown, leert
Split-Tunneling und blockiert LAN.

Der Offline-Hardening-Plan selbst aktiviert diesen App-Kill-Switch nicht. Bei
`strict` und `maximal` weist sein Bericht die Anforderung bis zum expliziten
TTY-Schritt `vpn-finalize` offen aus. Auf nicht offiziell unterstützten Zielen
bleibt sie offen, bis eine separat geprüfte Vanilla-WireGuard-/nftables-Policy
implementiert ist; der vorhandene Regelgenerator allein ist keine angewendete
Policy.

Das reduziert Leaks, beseitigt aber folgende offiziell dokumentierte Grenzen
nicht:

- Auf Linux nutzt die App nftables. Ein Ausfall des Root-Daemons oder ein
  kompromittierter Root-Prozess liegt außerhalb der Schutzgrenze.
- In Blocking-Zuständen darf der Daemon die Mullvad-API erreichen; auf Linux
  können laut [Security-Dokument](https://github.com/mullvad/mullvadvpn-app/blob/main/docs/security.md)
  auch andere Root-Prozesse diese API-Ausnahme nutzen. API-Traffic verwendet
  TLS 1.3 mit Certificate Pinning, ist aber eine bewusste Bootstrap-Ausnahme.
- Die Management-UDS ist laut [Mullvad-README](https://github.com/mullvad/mullvadvpn-app/blob/main/README.md)
  standardmäßig für lokale Benutzer erreichbar. `MULLVAD_MANAGEMENT_SOCKET_GROUP`
  kann den CLI/GUI-Zugriff auf eine dedizierte Gruppe begrenzen. Auf einer vom
  Toolkit offiziell akzeptierten systemd-Plattform nimmt der Standardplan die
  leere dedizierte Gruppe und den Override auf; beide Aktionen bleiben einzeln
  bestätigungspflichtig. `vpn-finalize` verweigert den Login bei expliziten oder
  Primary-GID-Mitgliedern außer root. Das generierte Drop-in beginnt mit
  leerem `Environment=`, das frühere Environment-Zuweisungen löscht, und
  enthält danach nur Managementgruppe und `UMask=0077`. Der Finalizer öffnet
  seine root-eigene Elternkette linkfrei und verlangt exakte Bytes, regulären
  Typ, Root-Eigentum, `nlink=1` und Modus 0644 oder strenger. Er startet den
  Daemon neu und liest neben der systemd-Property dessen reale
  `/proc/<MainPID>/environ` nofollow, root-eigen, größenbegrenzt und bei
  stabiler PID. Exakt die erwartete `MULLVAD_MANAGEMENT_SOCKET_GROUP` muss
  gelten. Weitere Mullvad-/talpid-, Loader-, Proxy-, CA- und
  Shell-Start-Overrides werden abgewiesen. Danach verbietet er einen fremden
  RPC-Socketpfad und prüft Typ, Root-/Gruppeneigentum und Other-Rechte des
  realen UDS. Das ist keine Integritätsattestierung des Daemonprozesses;
  kompromittiertes root kann die Beobachtung manipulieren.
- `vpn-finalize` beginnt nur an einer bewiesenen Grenze: exaktem Offline-Guard,
  exaktem Bootstrap-Guard oder Mullvad-Lockdown plus strukturell geprüfter
  Mullvad-nftables-Policy; die Host-Firewall prüft es separat. Vor jedem
  Daemon-Restart setzt und verifiziert es die Tabelle
  `umzug_vpn_bootstrap_guard` mit OUTPUT-Drop und alleiniger Loopback-Ausnahme.
  Das Offline-Guard-Retirement darunter ist bei bereits fehlender Tabelle
  idempotent. Erst nach nachgewiesenem Lockdown wird der Bootstrap-Guard
  entfernt. Jeder gefangene Fehler installiert ihn erneut, reaktiviert
  `umzug-offline-guard.service` per `enable --now` rebootfest und verifiziert
  beide Grenzen. Misslingt diese Notfall-Reaktivierung, wird keine geschlossene
  Netzgrenze behauptet, und lokale Emergency-Recovery ist Pflicht. Nach der
  erfolgreichen Entfernung gelten weiterhin Mullvads dokumentierte API-/
  Bootstrap-Ausnahmen unter Lockdown.
- Split-Tunneling kann selbst bei Lockdown Anwendungen außerhalb des Tunnels
  lassen. Darum wird es geleert und darf nicht wieder aktiviert werden.
- DNS wird im Connected-Zustand in den Tunnel gezwungen; private oder
  Loopback-Adressen als Custom-DNS haben Sonderregeln. Browser-DoH und
  konkurrierende Resolver können das Systemmodell durchbrechen. Siehe
  [DNS-Leaks](https://mullvad.net/en/help/dns-leaks).
- Die App benötigt mindestens einen API-Zugriffsweg. „Direct“ kann automatisch
  aktiv bleiben. Bootstrap-Ausnahmen dürfen nicht pauschal als „sämtlicher
  Verkehr ausschließlich im Tunnel“ beschrieben werden.
- `/etc/mullvad-vpn/account-history.json` enthält die Kontonummer im Klartext,
  wenn auch root-eigen und mit Modus 0600 oder strenger. Quelle:
  [account_history.rs](https://github.com/mullvad/mullvadvpn-app/blob/main/mullvad-daemon/src/account_history.rs).
  `device.json` enthält darüber hinaus kontobezogenen Gerätezustand und privates
  WireGuard-Schlüsselmaterial. `vpn-finalize` erlaubt die Kontoeingabe
  ausschließlich, wenn die lokale Erkennung die wirksame Mount-Abdeckung von
  `/etc/mullvad-vpn` eindeutig als verschlüsselt nachweist. Ein separates
  `/etc`-, `/etc/mullvad-vpn`- oder exaktes Datei-Mount auf
  `account-history.json` beziehungsweise `device.json` wird nicht aus dem
  Root-FDE-Indiz abgeleitet und deshalb fail-closed abgewiesen; FDE richtet der
  MVP nicht ein.
- Vor dem Prompt prüft der Finalizer vorhandene `account-history.json` und
  `device.json`, nach dem Login beide dann zwingend vorhandenen Dateien. Jede
  wird relativ zu einer linkfrei geöffneten, root-eigenen und nicht gruppen-/
  weltbeschreibbaren Elternkette mit `O_NOFOLLOW` geöffnet und muss regulär,
  root-eigen, `nlink=1`, höchstens 1 MiB sowie Modus 0600 oder strenger sein.
  Das begrenzt Link-/Rechteangriffe, validiert aber weder JSON-Inhalt noch
  Schlüsselherkunft und schützt nicht gegen kompromittiertes root.
- Der offizielle CLI-Login akzeptiert die Kontonummer als Prozessargument. Das
  Toolkit fragt sie TTY-only mit verdeckter Eingabe ab, schreibt sie nicht in
  Log, Config oder Shell-History und überschreibt sein `bytearray` best effort.
  Vor der Abfrage und nochmals unmittelbar vor dem CLI-Start prüft es
  fail-closed, dass genau ein wirksamer `/proc`-Mount wirklich procfs ist und
  mit `hidepid=2` oder `hidepid=invisible` ohne `gid=`-Ausnahme gemountet wurde.
  Damit sollen normale lokale Benutzer die kurzlebigen Root-argv nicht über
  procfs lesen können. Die Prüfung konfiguriert die Mountpolicy nicht und
  schützt nicht gegen root, Kernel, privilegierte eBPF-/Audit-Mechanismen,
  Prozessspeicherzugriff oder andere privilegierte Beobachtung; Python kann die
  Speicherlöschung zudem nicht garantieren.
- Vor dem Prompt und erneut direkt vor dem CLI-Login muss die globale
  Core-Dump-Policy ebenfalls fail-closed sein: `kernel.core_pattern` ist exakt
  leer und `kernel.core_uses_pid=0`. Ein Pipehandler wie `systemd-coredump` wird
  bewusst abgewiesen, weil der Kernel `RLIMIT_CORE` bei über Pipes geleiteten
  Core-Dumps nicht als ausreichende Barriere behandelt. Gleichzeitig darf
  `/proc/swaps` keinen aktiven Eintrag enthalten; der MVP versucht nicht, aus
  Namen oder Konfiguration eine sichere Swap-Verschlüsselung abzuleiten.
- Der Finalizer sperrt sein softes und hartes `RLIMIT_CORE` auf `0`, setzt
  `PR_SET_DUMPABLE=0` und wiederholt dies im offiziellen CLI-Kind. Das
  reduziert gewöhnliche Core-/ptrace-Angriffe, verhindert aber weder
  Root-/Kernel-/DMA-/Hypervisor-Zugriff noch garantiert es die Löschung aller
  Python- oder Fremdprozess-Speicherkopien. Später reaktivierter Swap oder
  Core-Dumping liegt ebenfalls außerhalb dieses endlichen Nachweises.

Shadowsocks, UDP-over-TCP, QUIC und LWO sind 2026 offiziell unterstützte
Anti-Zensurmodi **innerhalb der Mullvad-App**. Sie sind keine OpenVPN-Bridges
und werden bei manuellem WireGuard nicht angeboten. Quellen:
[CLI WireGuard](https://mullvad.net/en/help/cli-command-wg) und
[restriktive Netze](https://mullvad.net/en/help/connecting-to-mullvad-vpn-from-restrictive-locations).

Downloads müssen vor dem Offline-Transfer gemäß Mullvads
[Signaturanleitung](https://mullvad.net/en/help/verifying-signatures) geprüft
werden. Der Toolkit-Pfad verlangt zusätzlich, dass Paket und Detached Signature
die vollständige `APPROVED`-Pipeline durchlaufen und `verify-vendor` sie an
den unabhängig geprüften Mullvad-Schlüssel bindet. Der finale Login/Connect,
der verpflichtende Online-Nachweis und der kontrollierte Disconnect-/Reconnect-
Test sind die einzigen vorgesehenen Netzschritte im Setup-Ablauf. Der
Disconnect-Test prüft Lockdown und verlangt für die aktive Mullvad-OUTPUT-
Basiskette Policy `drop`; indirekte beziehungsweise userspace-kontrollierte
Verdictpfade und bedingungsloses Accept werden abgewiesen. Dieser Strukturcheck
beweist nicht die Tunnelbindung jeder bedingten Accept-Regel. Pro
plangebundenem Ethernet-Interface folgen zeitbegrenzte, mit
`SO_BINDTODEVICE` gebundene rohe Literal-IP-Proben über TCP/80, TCP/443 und
UDP/53. TCP-Erfolg, Refusal/Reset und jedes empfangene UDP-Datagramm gelten
unabhängig von DNS-Format oder Transaktions-ID als Leak. Nur definierte Policy-/
Down-/Unreachable-/Timeout-Fehler gelten als blockiert; andere Socketfehler
brechen als unbestimmt fail-closed ab. Das ist eine endliche Momentaufnahme,
kein formaler Beweis gegen jeden möglichen Leak. Nur bei vollständigem Erfolg
erscheint `finite_fail_closed_disconnect_checks_passed=true` im Audit. Bei
Fehlschlag werden der Loopback-only-Bootstrap-Guard und per `enable --now` der
rebootfeste Offline-Guard erneut installiert und exakt geprüft. Scheitert diese
Notfallgrenze selbst, ist lokale Emergency-Recovery Pflicht.
