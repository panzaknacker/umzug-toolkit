# Architektur

## Ziel und status

`umzug-toolkit` 0.2.0rc1 ist ein abhängigkeitsarmer hardware-test-release-
kandidat für eine offline-first,
zero-trust-orientierte linux-migration. die architektur trennt erfassen,
erkennen, planen, ausführen und verifizieren. nicht jede geplante schnittstelle
ist bereits vollständig über die kommandozeile verdrahtet. maßgeblich ist die
funktionsmatrix in [LIMITATIONS.md](LIMITATIONS.md).

das toolkit besteht aus zwei installierten programmen:

- `umzug-pack` erfasst ausgewählte quellen, erstellt `SOURCE.tar`, ein
  kanonisches manifest und eine Ed25519-signatur und verpackt alles optional
  verschlüsselt.
- `umzug-setup` prüft und importiert das paket, erkennt das zielsystem, führt die
  zero-trust-pipeline, erzeugt hardening-pläne, führt bestätigte aktionen aus
  und verwaltet checkpoints beziehungsweise recovery.

die programmnamen in `argparse`-hilfetexten können verkürzt als `pack` und
`setup` erscheinen. das wheel installiert `umzug-pack` als python-entry-
point. `/usr/local/sbin/umzug-setup` ist dagegen die root-owned kopie der
isolierenden wheel-scriptdatei `umzug-setup-root`, kein python-console-entry-
point.

## Komponenten

| modul | verantwortung | darf systemzustand ändern? |
|---|---|---:|
| `pack_cli.py` | auswahl, vorschau, paketbau, verschlüsselung, splitten | nur ausgabedateien und optional schlüssel |
| `inventory.py` | lokales, geheimnisarmes quellinventar | nein |
| `manifest.py` | tar-format, hashes, Ed25519, sichere extraktion, verschlüsselungsadapter | nur explizite zielpfade |
| `transport.py` | dateisystemneutrale teile und wiederzusammenbau mit hashprüfung | nur explizite zielpfade |
| `detection.py` | distribution, paketmanager, init, CPU, kernel, firmware, geräte und storage | nein |
| `adapters.py` | endliche capability-zuordnung und distributionsspezifische paketpläne | nein; erzeugt nur intents |
| `package_actions.py` | typisierte, erneut regenerierbare übersetzung von paketplänen in actions | nein |
| `scanner.py` | statische mehrfachanalyse und hashgebundene trust-zonen | nur pipeline-arbeitsbereich |
| `restore_trust.py` | unabhängige erneute prüfung von bundle, signatur, payload, ingest, approval und APPROVED-baum | nein; temporäre, private prüfsnapshots |
| `restore_metadata.py` | erneute manifest-/baumprüfung und konservative metadaten-/identitätszuordnung | ja, nur im neuen restore-ziel |
| `vendor.py` | fingerprint- und toolhashgebundene OpenPGP-prüfung unveränderter APPROVED-artefakte | nur expliziter receipt |
| `hardening.py` | deklarative hardening-pläne | nein |
| `network.py` | nftables-regeln, kill-switch-regeln, recovery und zustandsnachweise | recovery-funktion ja |
| `vpn.py` | abschließende mullvad-app-konfiguration und verifikation | ja, nur expliziter finaler schritt |
| `model.py` | validierte plan- und aktionsmodelle | nein |
| `executor.py` | diff, bestätigung, backup, checkpoint, ausführung, verifikation, rollback | ja |
| `util.py` | nofollow-dateizugriffe, redigiertes auditlog, atomare writes und sichere prozessaufrufe | nur explizite ausgabe-/logpfade |
| `setup_cli.py` | orchestrierung der zielseite | abhängig vom unterbefehl |

externe programme werden ohne shell als feste argumentvektoren gestartet.
privilegierte planbefehle sind zusätzlich auf eine allowlist begrenzt.

## Paketformat

das unverschlüsselte äußere paket ist ein POSIX-PAX-tar mit genau vier regulären
dateien:

```text
umzug/manifest.json
umzug/manifest.sig
umzug/signing-public.pem
umzug/SOURCE.tar
```

`SOURCE.tar` enthält jede auswahl unter einer künstlichen wurzel
`SOURCE/item-NNNN/<ursprünglicher-Basisname>`. dadurch werden keine absoluten
pfade transportiert. das manifest bindet payload-größe und SHA-256 sowie für
jeden eintrag typ, modus, UID, GID, zeitstempel, größe, linkziel, SHA-256 bei
regulären dateien sowie name, SHA-256 und größe gelesener extended Attributes.
spezialdateien werden nicht archiviert. symlinks werden nicht verfolgt;
hardlinks werden als solche abgebildet.

nach verifizierter signatur und JSON-dekodierung validiert setup die
manifeststruktur **vor** jeder SOURCE-extraktion: ids und archivwurzeln müssen
eindeutig sein, wurzeln dürfen sich nicht überlappen, jeder eintrag muss eine
existierende auswahl nennen und exakt unter deren kanonischer wurzel liegen.
deklarierte und tatsächliche `SOURCE.tar`-größe werden aneinander gebunden; für
bundle-aufnahme, verifikation und extraktion gilt dieselbe harte 8-TiB-
obergrenze. nichtkanonisches tar-ende, angehängte polyglot-daten, duplikate und
überzählige member werden abgewiesen.

vor der manifesterzeugung und signatur liest `pack` das fertige `SOURCE.tar`
selbst erneut ein und vergleicht typen, pfade, metadaten und datei-hashes mit
den erfassten einträgen. eine während des packens erkannte quelländerung oder
tar-/manifest-abweichung verhindert damit die signatur. das macht eine
kompromittierte quelle nicht vertrauenswürdig, verhindert aber, dass ein lokal
bereits inkonsistenter snapshot als erfolgreiches paket ausgegeben wird.

die äußere datei kann mit `age` für einen empfänger, mit einer `age`-passphrase
oder symmetrisch mit GnuPG/AES-256 verschlüsselt werden. die verschlüsselung ist
nicht bestandteil des python-codes; das toolkit ruft das lokal vorhandene,
separat zu vertrauende programm auf. für transportmedien mit dateigrößenlimit
kann die fertige datei in nummerierte teile mit SHA-256-index zerlegt werden.

## Signatur- und fingerprint-vertrauensmodell

das manifest wird mit Ed25519 über OpenSSL signiert. die öffentliche schlüsseldatei liegt
aus portabilitätsgründen im paket, ist dort aber **kein vertrauensanker**. setup
muss entweder einen unabhängig beschafften öffentlichen schlüssel oder dessen
SHA-256-fingerprint erhalten. es prüft:

1. optional, dass gebündelter und separat vertrauter schlüssel identisch sind;
2. den erwarteten fingerprint;
3. die Ed25519-signatur des exakten manifests;
4. formatversion und verpflichtende kennzeichnung als nicht vertrauenswürdig;
5. SHA-256 und größe von `SOURCE.tar`.

der fingerprint muss auf einem vom transportdatenträger unabhängigen kanal
übermittelt werden. eine gültige signatur beweist nur herkunft beziehungsweise
unverändertheit relativ zu diesem schlüssel. sie beweist weder, dass das alte
system sauber war, noch dass eine datei harmlos ist. ist das alte system
kompromittiert, kann auch `pack` beziehungsweise der dort verwendete private
schlüssel angegriffen werden. deshalb folgt nach der signaturprüfung zwingend
die zero-trust-analyse.

## Zero-trust-datenfluss

```text
externes Medium
      |
      | ro,noexec,nodev,nosuid; keine Autoruns; netzlose Analyse-VM
      v
   SOURCE  --Scan + inerte Kopie-->  QUARANTINE
                                        |
                                        | keine Blocker, Reviews einzeln akzeptiert
                                        v
                                    SANITIZED
                                        |
                                        | erneuter Scan + hashgebundene Freigabe
                                        v
                                     APPROVED
                                        |
                                        | explizit bestätigt, kein Überschreiben
                                        v
                                     RESTORED
```

- `SOURCE` ist ein unveränderbarer snapshot. das physische quellmedium muss
  bereits vom betreiber nur lesbar und mit `noexec,nodev,nosuid` eingebunden
  worden sein. `mount-source` übernimmt diesen schritt für ein explizites
  blockdevice und prüft die wirksamen optionen; `ingest` verweigert
  standardmäßig jeden anderen quellmount. VM, desktop-/udev-automount-sperren
  und den übergeordneten mount-namespace richtet der MVP nicht selbst ein.
- `QUARANTINE` ist eine inerte kopie. spezialdateien und unsichere eingaben
  werden abgewiesen; SUID, SGID und ausführbare bits werden nicht übertragen.
  ingest schreibt `state/reports/CANDIDATE.source.json`,
  `CANDIDATE.quarantine.ingest.json` und den selbstgehashten beleg
  `state/CANDIDATE.provenance.json`. dieser bindet SOURCE-scan-ID/-reporthash,
  SOURCE- und unveränderlichen snapshot-manifest-hash sowie
  ingest-QUARANTINE-scan-ID/-reporthash/-manifest.
- `SANITIZED` ist im MVP eine erneut geprüfte kandidatenkopie. promotion prüft
  den SOURCE-snapshot erneut, verlangt einen strikten, blockerfreien
  QUARANTINE-report und genau dessen review-ids. sie persistiert den exakten
  promotion-report als `CANDIDATE.quarantine.json`, den SANITIZED-report als
  `CANDIDATE.sanitized.json` und
  `state/promotions/CANDIDATE.json`. dieser selbstgehashte beleg bindet den
  provenienzbeleg, SOURCE-snapshot, QUARANTINE-scan/-report/-manifest, exakt
  akzeptierte funde sowie SANITIZED-scan/-report/-manifest. automatische
  content-disarm-and-reconstruction für dokumente oder quellcode ist nicht
  implementiert.
- `APPROVED` entsteht nur aus `SANITIZED`. die entscheidung enthält akteur,
  grund, akzeptierte SANITIZED-review-funde und den exakten manifest-hash.
  zusätzlich bindet der approval-record `ingest_provenance_sha256`,
  `promotion_sha256`, `source_manifest_sha256`,
  `source_snapshot_manifest_sha256`, `quarantine_manifest_sha256`,
  `sanitized_manifest_sha256`, `quarantine_report_scan_id`,
  `quarantine_report_sha256` und `promotion_accepted_findings`. blocker
  können nicht quittiert werden. der ausgegebene
  `approval_sha256` muss unmittelbar auf einem vom workspace unabhängigen,
  geschützten kanal notiert werden.
  selbsthashes sind SHA-256 über kanonisches UTF-8-JSON mit sortierten
  schlüsseln, kompakten trennern und ASCII-escapes; das jeweilige hashfeld ist
  beim hashen entfernt.
- `RESTORED` wird ausschließlich aus unverändertem `APPROVED` erzeugt. das ziel
  darf nicht existieren. zuvor erstellt das trust-gate einen stabilen
  nofollow-snapshot des ursprünglichen bundle, extrahiert nur die vier erlaubten
  member und prüft Ed25519-signatur sowie komplettes `SOURCE.tar` erneut. es
  kopiert SOURCE-, ingest-QUARANTINE-, promotion-QUARANTINE- und SANITIZED-
  report, provenienz- und promotion-beleg sowie approval und `APPROVED` über
  fd-verankerte, linkfreie snapshots. die re-verifikation verlangt vollständige
  aktuelle schemas, prüft beide QUARANTINE-reports strikt und blockerfrei,
  identische policy-/toolbindungen, exakte promotion-review-ids und die gesamte
  hash-/manifestkette. alte belege ohne pflichtfelder werden nicht migriert,
  sondern fail-closed abgewiesen. erst danach bindet sie alles an den unabhängig
  übergebenen public key/fingerprint und `approval_sha256` und kopiert
  fd-verankert in das neue ziel. veröffentlichung erfolgt ausschließlich über
  atomisches `renameat2(RENAME_NOREPLACE)`; alle elternkomponenten müssen echte
  verzeichnisse sein und linux-`/proc` muss verfügbar sein. ein root-pflichtiger
  metadatenabgleich prüft das verifizierte signierte manifest, auswahlwurzel
  sowie alle bytes, typen und links erneut.
  UID/GID werden nur über eine eindeutige bijektive
  bindung exakt gleicher signierter quell- und lokaler zielnamen abgebildet;
  rohe nummern werden nie übernommen.
  reguläre dateien erhalten höchstens signierte rw-bits und mtime,
  verzeichnisse signierte rwx-traversalbits. privileged-/execute-bits, acls,
  capabilities und alle xattrs bleiben entfernt. mode, ziel-UID/-GID und mtime
  werden anschließend exakt gegen diese sichere policy nachgeprüft. getrennte,
  nicht überschreibbare content- und metadaten-receipts binden das ergebnis.

der eingebaute scanner führt inhalts- und metadatenheuristiken aus und bindet
bei strikter policy die binärdateien von bubblewrap, `file`, ClamAV und YARA
sowie deren regel-/signaturmaterial an vorab konfigurierte SHA-256-werte.
jede reguläre datei wird über `O_NOFOLLOW` als stabiler read-only snapshot in
einem privaten 0700-temporärbaum mit 0400-dateien erfasst. interne byteanalyse
und externe scanner verwenden genau diese snapshots; danach wird der
originalkandidat nochmals gegen das scanmanifest geprüft und der temporärbaum
gelöscht. standardmäßig sind 256 MiB pro datei und 1 GiB für alle snapshots und
die globale archivexpansion erlaubt; produktive policies dürfen diese grenzen
nur absenken.

externe scanner laufen in einem neuen user-, PID-, netzwerk-, IPC-, UTS- und
best-effort cgroup-namespace. bubblewrap sieht keine hostwurzel, sondern nur
read-only `/usr` und notwendige library-/executable-bäume, leere runtime-
verzeichnisse, private `proc`/`dev`/`tmp`, den snapshot unter `/input` sowie
explizit gepinnte regeln und signaturen.
fehlt isolation, eine erforderliche unabhängige analyse oder geprüftes
material, entsteht ein blocker. details und grenzen stehen im
[bedrohungsmodell](THREAT-MODEL.md).

die werkzeug-snapshots schließen die dynamische runtime nicht vollständig:
loader, shared libraries, teile der read-only eingebundenen `/usr`-/library-
bäume, kernel und bubblewrap-implementierung bilden weiterhin eine vertraute
basis und sind nicht als vollständiger closure-baum einzeln gepinnt. ein
angreifer mit derselben UID kann außerdem private snapshotdateien oder den
scannerprozess angreifen; root/kernel/hypervisor erst recht. die snapshot-
bindung schützt gegen normale pfad-/symlink-rennen, ist aber keine MAC-domain
gegen einen bereits aktiven same-host-angreifer. produktive scans gehören daher
in eine frische, netzlose analyse-VM aus unabhängig verifizierten basisbytes.

zstd-daten, einschließlich zstd-komprimierter RPM-payloads, werden nur dann
analysiert, wenn `zstd` **und** bubblewrap unabhängig per SHA-256 gepinnt sind.
die vollständige dekompression läuft ohne netzwerk mit `zstd -M128` und
zeit-/input-/output-/expansionslimits; der entstandene stream wird rekursiv
untersucht. fehlt eine voraussetzung oder endet die dekompression nicht
vollständig innerhalb der limits, ist das ergebnis ein nicht quittierbarer
blocker.

## Zielerkennung

`SystemDetector` liest primär `/etc`, `/proc` und `/sys`. diese wurzeln sind
injizierbar, damit tests und die untersuchung eines gemounteten zielsystems
nicht versehentlich daten des hosts verwenden. ein eigener symlink-resolver
begrenzt auch absolute links auf den injizierten baum. nur beim live-root darf
optional ein fester, read-only `lsblk`-aufruf erfolgen.

erkannt werden unter anderem:

- distribution, version, paketmanager und init-system;
- normalisierte architektur und kernel;
- UEFI/BIOS und secure-boot-variable;
- DRM-gpus, vendor, treiber und konservative treiberempfehlungen;
- ethernet, WLAN, virtuelle interfaces, bluetooth und rfkill-geräte;
- TPM, IOMMU, kernel-lockdown und ausgewählte CPU-sicherheitsflags;
- mounts, blockgeräte, device-mapper/LUKS-indizien und `/etc/crypttab`.

ein unbekannter wert bleibt `unknown`; er wird nicht optimistisch interpretiert.

## Distributionsadapter

ein paketwunsch ist keine native paketzeichenkette, sondern eine endliche
capability wie `git`, `build-tools`, `firewall` oder `wireguard`. unbekannte oder
syntaktisch verdächtige werte bleiben ungelöst. dadurch kann ein manipuliertes
quellmanifest keine optionen in einen privilegierten paketmanager einschleusen.

- debian-/ubuntu-familie: generische capabilities erzeugen derzeit nur einen
  blockierenden manuellen nicht-ausführungs-checkpoint. eine privilegierte
  offline-APT-aktion bleibt aus, bis ein signatur-/SHA-256-gebundener
  `APPROVED`-repository-snapshot samt exaktem closure-receipt implementiert ist.
- arch-familie: offline-installation nur aus explizit zugeordneten,
  vorverifizierten paketdateien.
- NixOS: erzeugt ein separates deklaratives nix-modul zur manuellen einbindung;
  kein blindes `nixos-rebuild`.
- gentoo: plant binär-only portage-aufrufe und eine getrennte datei für relevante
  USE-flags.
- LFS: erzeugt keine erfundene paketmanageraktion, sondern manuelle hinweise.
- generic: unbekannte distributionen bleiben vollständig manuell.

native repository-metadaten und paketsignaturen müssen vor jeder ausführung
gegen einen außerhalb der migration verankerten schlüssel geprüft werden. die
adapter erzeugen pläne; sie sind kein repository-spiegel und kein
signaturprüfer.

für die offizielle mullvad-app existiert zusätzlich ein enger vendor-pfad:
`verify-vendor` akzeptiert nur artefakt und detached signature unter demselben
unveränderten `APPROVED`-kandidaten, einen separat bereitgestellten public key
mit exakt erwartetem primären fingerprint sowie SHA-256-gepinnte `gpg`-,
`gpgv`- und bubblewrap-binärdateien. der receipt im format
`umzug-vendor-verification-v4` entsteht ohne keyserver und web
of trust in einer netzlosen bubblewrap-sandbox mit temporärem keyring. `plan`
akzeptiert den receipt nur unter `WORKSPACE/state/vendor`, verlangt fingerprint
und alle drei toolhashes erneut als unabhängige CLI-anker und führt parsen,
keyringaufbau sowie detached-signature-prüfung nochmals aus. zusätzlich bindet
der plan die über `--mullvad-package-version` und
`--mullvad-package-architecture` gelieferten exakten paketwerte. sie müssen
für genau das artefakt aus unabhängig authentifizierten paket-/repository-
metadaten stammen und werden nicht aus dem untrusted paket gelesen. erst danach
erlaubt der plan `.deb` auf debian/ubuntu beziehungsweise `.rpm` auf fedora.
plan, jeder dry-run/apply, `resume` und `vpn-finalize` führen die
vendor-intent-prüfung vor nutzung erneut aus; ein receipt-JSON allein genügt
nie.

für den vorgesehenen frisch installierten zielzustand ist die systemd-reihenfolge
`mullvad-management-group` → `mullvad-management-socket` →
`mullvad-offline-install`. gruppe und drop-in werden vor dem paket geschrieben,
damit schon dessen erster unit-load die einschränkung sieht. bei einem bereits
installierten oder laufenden daemon gilt diese first-load-invariante nicht; bis
zum receiptgebundenen neustart kann noch die alte unit-umgebung wirksam sein.
dieser nicht-frischsystem-fall erfordert vorheriges manuelles stoppen und einen
separaten review an der lokalen konsole. ein
`daemon-reload` vor einer noch fehlenden main-unit ist bewusst nicht teil des
plans. die atomare vendor-aktion installiert im netzlosen namespace, bindet
den neu installierten `mullvad`-executable-receipt und führt unmittelbar
receiptgebunden `systemctl daemon-reload` sowie
`systemctl restart mullvad-daemon.service` aus. erst exakte
paketidentität/-integrität und die live-prüfung von leerer managementgruppe,
drop-in, effektiver environment/umask und UDS schließen die action ab. debian
nutzt `apt-get install --yes --reinstall --no-download
--no-install-recommends -- ARTEFAKT`; dessen transitive APT-abhängigkeiten
beweist das toolkit nicht. fedora nutzt ohne DNF
`rpm --upgrade --replacepkgs -- ARTEFAKT`.

## Plan, ausführung und checkpoints

ein `Plan` bindet zusätzlich zu validierten, eindeutig benannten
`Action`-objekten einen deklarativen ziel-intent: distribution/`ID_LIKE`,
paketmanager, init-system, vollständige profilwerte, ethernet-interfaces,
funkmodule, ausgewählten adapter und angeforderte capabilities. jede aktion
enthält begründung, risiko, operation, parameter, backup-pfade,
verifikation, bestätigungspflicht, destruktiv-markierung und gegebenenfalls
neustartgrund. der executor:

1. validiert den plan; **jedes** produktive apply verlangt
   `--expected-plan-sha256` mit dem unabhängig von der planerstellung
   notierten digest. es gibt keine interaktive ersatzabfrage; nur dry-run darf
   die option weglassen und zeigt den digest;
2. vergleicht den stabilen ziel-fingerprint und bindet den checkpoint an genau
   diesen plan-SHA-256-digest;
3. zeigt bei verwalteten dateien einen unified diff;
4. verlangt pro aktion eine zustimmung, bei destruktiven aktionen exakt die
   action-ID;
5. sichert deklarierte zielpfade;
6. führt nur implementierte operationen und erlaubte befehle aus;
7. verifiziert definierte postconditions;
8. re-verifiziert bei jeder produktiven fortsetzung alle bereits
   abgeschlossenen verwalteten dateien byte-/modusgenau und jede abgeschlossene
   action mit typisiertem verifier gegen den effektiven zustand;
9. schreibt den checkpoint atomar und setzt nach einer neustartaktion aus.

### Zero-trust-ableitung und typisierte action-registry

signierte inventare, `APPROVED`-dateien und vendor-receipts sind weiterhin
untrusted daten und dürfen weder `operation`, zielpfad noch einen
kommandoargumentvektor liefern. ein plan entsteht nur aus:

1. lokaler zielerkennung;
2. einem eng typisierten profil und explizit gewählten capabilities;
3. endlichen distributionsspezifischen capability-mappings;
4. separat hash-/signaturgebundenen lokalen paketartefakten.

`Plan.from_dict()` behandelt auch einen gespeicherten plan als potenziell
manipuliert. die action-ID ist der registry-schlüssel. für jede produktive ID
werden operation, exakte feldmenge, risiko, bestätigungs- und
destruktiv-markierung, höchstens ein exakter backup-pfad sowie ein typisierter
verifier neu abgeleitet. `write_file` ist auf feste ziele und modi begrenzt;
sicherheitskritische inhalte werden bytegenau aus vertrauenswürdigen renderern
rekonstruiert beziehungsweise gegen eine endliche grammatik geprüft.
`run_command` akzeptiert nur feste `argv`-templates oder eng gebundene
offline-paketformen mit `network_policy=forbidden` und artefakthash.
service-actions dürfen nur die festgelegten SSH-/legacy-/funkdienste
deaktivieren oder toolkit-eigene units aktivieren. freie command-verifier,
unbekannte ids, zusätzliche felder, `backup_paths=["/"]`, eingehendes SSH und
abweichende safety-flags scheitern geschlossen.

der validator regeneriert aus dem gebundenen intent den vollständigen
hardening-body und paketplan. pflichtaktionen dürfen nicht zusammen mit ihren
preflights gelöscht werden; ziel- oder capability-fremde adapteraktionen
scheitern. beim apply werden distribution, `ID_LIKE`, paketmanager, init und
physische ethernet-geräte erneut mit der lokalen erkennung verglichen.

ein kanonischer prefix prüft alle vor der ersten mutation benötigten programme.
produktiv bindet der private checkpoint je programm exakt `path`, `sha256`,
`device`, `inode`, `size`, `mtime_ns` und `ctime_ns`. jede spätere auflösung
beobachtet alle felder erneut und startet nur den absoluten pfad; ein austausch
stoppt. erst an einer typisierten paketgrenze bereitgestellte werkzeuge wie
`rfkill` oder `wg` und der vendor-client `mullvad` werden unmittelbar nach
installation gebunden. der finalizer rekonstruiert seine bound-executables nur
aus abgeschlossenen plan-receipts; ein fehlender oder driftender receipt
scheitert geschlossen.

zusätzlich validiert ein ordnungsgraph recovery → persistenter offline-guard →
host-firewall → offline-paketaktionen → SSH-/funk-containment sowie die
einzelkanten datei → syntax/apply/persistenz und auf NixOS
recovery → modul → testgeneration → paketmodul. der SHA-256-digest bindet die bereits
semantisch validierten bytes und verhindert austausch; er macht einen
inhaltlich unzulässigen plan nicht zulässig.

produktive root-ausführung ist nur aus einer root-owned, nicht
gruppen-/weltbeschreibbaren python-runtime erlaubt. der veränderliche
quellbaum-launcher verweigert EUID 0; `sudo ./setup` und ein user-writable
`PYTHONPATH` sind keine unterstützten betriebswege. der isolierende wrapper
leert die umgebung und nutzt festen interpreter plus `-I -B`. bereits **vor**
dem interpreterstart verlangt er für `/opt`, runtime-, `bin`-/`lib`-
komponenten, interpreter und `pyvenv.cfg` echten nicht-symlink-typ,
root-eigentum und fehlende gruppen-/weltschreibbarkeit. ein `find -P` über
`runtime/lib` lehnt symlinks, nicht-root-eigentum, schreibbits für
gruppe/welt und SUID-/SGID-/sticky-bits ab. nach dem import revalidiert setup
interpreter, paketdateien und elternpfade als zweite schranke. die gebundenen
executable-receipts schließen den normalen prüfungs-/nutzungswechsel, sind aber
keine TPM-/secure-boot-attestierung und schützen nicht gegen kompromittiertes
root.

jede action mit neustartgrund muss eine explizite post-reboot-prüfung besitzen.
unmittelbar bevor der executor den reboot-checkpoint speichert, re-verifiziert
er den gesamten bereits abgeschlossenen action-prefix einschließlich
effektiver controls. damit darf etwa ein paket- oder initramfs-hook firewall
oder guard nicht unbemerkt verändern und direkt in den neustart übergehen.
erst danach werden action-abschluss, kanonische boot-ID und offener
reboot-checkpoint atomar gespeichert. noch **vor** annahme der neuen boot-ID
re-verifiziert `resume` alle zuvor
abgeschlossenen `write_file`-actions gegen exakte bytes und modi sowie alle
abgeschlossenen actions mit verifier, darunter effektive offline-guard-/host-
firewall-regeln, service-deaktivierung, funk- und paketstatus. drift stoppt die
fortsetzung, lässt den reboot-checkpoint offen und führt keine folgeaktion aus.
danach prüft `resume` je nach reboot-action einen erlaubten befehl samt
erwarteter ausgabe, dass gesperrte module nicht mehr in `/proc/modules` stehen,
oder eine bewusst manuelle konsolenattestierung. auch
normale manuelle `checkpoint`-actions sind keine no-ops: sie zeigen die konkrete
voraussetzung, verlangen am lokalen TTY exakt `VERIFIED:ACTION-ID` und speichern
die attestierung im gebundenen state.

NixOS verwendet für den generation-checkpoint `nixos-rebuild dry-build`,
`nixos-rebuild test` und `nixos-rebuild boot`. am lokalen TTY ist der exakte
getestete kanonische `/nix/store/...-system`-pfad einzugeben. executor und
checkpoint binden getestete sowie vorherige generation und verlangen, dass
`/nix/var/nix/profiles/system` auf genau den neuen, root-owned und nicht
gruppen-/weltbeschreibbaren storepfad zeigt. nach dem reboot akzeptiert
`resume` nur, wenn `/run/current-system` exakt diesen getesteten pfad auflöst
und von der vorigen generation abweicht; eine generische manuelle
`POST-REBOOT-VERIFIED`-phrase ersetzt dies nicht.

ein abweichender plan darf einen begonnenen checkpoint nicht übernehmen.
rollback arbeitet die gespeicherten backups rückwärts ab und entfernt nur
protokollierte, neu erzeugte pfade. das ist kein transaktionales dateisystem und
kein ersatz für ein system-snapshot.

der ziel-fingerprint bindet stabile distributions-, architektur-, firmware-,
CPU-, board-, storage- und interfaceidentitäten, blendet erwartete
laufzeitänderungen wie kernel- und treiberstand aber aus. er verhindert
versehentliches apply/resume auf einer anderen maschine; er ist keine
kryptografische geräteattestierung.

ein dry-run führt keine aktionen aus und trägt keine action-ID in `completed`
ein. er kann daher einen späteren produktiven lauf nicht durch vorgetäuschte
erledigung überspringen. nicht lesbare root-ziele werden ausdrücklich als
`not inspectable` markiert; der produktive root-lauf muss den echten diff erneut
erzeugen. fehlende preflight-werkzeuge bleiben sichtbar, ohne ausgeführt zu
werden. ein separates state-verzeichnis bleibt für die klare trennung von
vorschau und produktionsnachweisen empfohlen.

## Hardening- und netzwerkarchitektur

die profile `compatible`, `strict` und `maximal` steuern deklarative werte.
eigene TOML-profile akzeptieren ausschließlich `name`, `disable_ipv6`,
`disable_radios`, `blacklist_radio_modules`, `firewall`, `vpn_killswitch` und
`sudo_timestamp_minutes`; unbekannte oder nur vorgetäuschte optionen werden
abgewiesen. MAC-/PAM-/mount-policy wird dadurch nicht behauptet.
aktuell erzeugt der plan insbesondere sysctl- und modprobe-dateien,
SSH/legacy-service-deaktivierung, eine systemd- oder eingeschränkt
OpenRC-gebundene nftables-host-firewall, sudoers- und bei systemd
journald-fragmente sowie einen lokalen recovery-befehl. der recovery-befehl
steht im plan vor jeder firewall-aktivierung. kritische aktionen sind explizit
zu bestätigen.

nach einer modprobe-policy plant debian/ubuntu `update-initramfs`, arch
`mkinitcpio` und fedora/RHEL-artige systeme `dracut`. auf anderen zielen wird
statt eines geratenen befehls ein kritischer manueller checkpoint erzeugt; erst
danach darf der rebootgebundene plan fortgesetzt werden.

die host-firewall verwendet für INPUT und FORWARD default-drop, erlaubt keinen
eingehenden dienst und wird statisch auf versehentliche SSH-freigaben geprüft.
vor der aktivierung validiert `nft --check` die datei. die service-/OpenRC-
lader löschen eine bereits aktive `umzug_host`-tabelle niemals vorab: ein
reload mit kollidierender tabelle scheitert und lässt die alte policy wirksam,
statt kurzzeitig offen zu werden. das ist kein automatischer live-regel-merge;
aktive regeln müssen nach jedem versuch geprüft werden.

auf systemd sind sowohl `umzug-offline-guard.service` als auch
`umzug-firewall.service` frühe **boot-hartschranken**: `DefaultDependencies=no`,
`After=local-fs.target`, `Before=` den relevanten basic-/network-/VPN-zielen und
`RequiredBy=` denselben zielen. die firewall bindet zusätzlich
`wg-quick.target`. beide units setzen `OnFailure=emergency.target` und
`OnFailureJobMode=isolate`. scheitert der nftables-load, darf der normale boot
nicht mit offenem netz fortfahren, sondern fällt absichtlich auf lokale
emergency-/konsolen-recovery zurück. OpenRC-`local.d` besitzt keine
gleichwertige systemd-isolationssemantik und bleibt ein dokumentierter
best-effort-pfad.

`vpn-finalize` akzeptiert auch bei einem wiederholungs-/fortsetzungslauf nur
eine bereits bewiesene anfangsgrenze: exakten offline-guard, exakten bootstrap-
guard oder mullvad-lockdown zusammen mit der strukturell geprüften mullvad-
nftables-policy. fehlt jede dieser drei grenzen, bricht es vor daemon-restart
ab; die host-firewall wird unabhängig zusätzlich geprüft. danach installiert
und verifiziert jeder lauf die temporäre OUTPUT-drop-tabelle
`umzug_vpn_bootstrap_guard`, die nur loopback erlaubt, erneut **vor**
daemon-restart und UDS-prüfung.

beim handoff bleibt der bootstrap-guard wirksam, während der offline-guard mit
`disable --now` beendet wird. der finalizer verifiziert enabled/active-
abwesenheit, prüft eine noch vorhandene offline-tabelle vor dem löschen und
akzeptiert eine bereits fehlende tabelle als idempotente fortsetzung. erst nach
effektivem mullvad-lockdown/-nftables wird der bootstrap-guard entfernt und die
mullvad-grenze sofort erneut geprüft.

das generierte drop-in beginnt mit leerem `Environment=`, das frühere
environment-zuweisungen löscht, und enthält danach nur managementgruppe sowie
`UMask=0077`. der finalizer öffnet die datei und ihre elternkette root-owned
und linkfrei und verlangt exakte bytes, regulären typ, UID 0, `nlink=1` und
modus 0644 oder strenger. die unitdatei und
`systemctl show ... Environment` sind dabei trotzdem nur vorprüfungen.
nach dem neustart ermittelt der finalizer `MainPID`, öffnet `/proc`, das
root-owned prozessverzeichnis und `environ` jeweils nofollow, liest höchstens
1 MiB, prüft stabile metadaten und verlangt danach dieselbe positive `MainPID`.
der NUL-parser lehnt unvollständige, doppelte oder syntaktisch ungültige
variablen ab. in der realen daemon-umgebung muss exakt
`MULLVAD_MANAGEMENT_SOCKET_GROUP=<erwartete Gruppe>` stehen. jede weitere
`MULLVAD_*`-variable, alle `TALPID_*`, `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`,
groß-/kleinschreibungsvarianten von HTTP(s)/ALL-proxy und
`SSL_CERT_FILE`/`SSL_CERT_DIR` werden fail-closed abgewiesen. andere
umgebungsvariablen sind nicht allgemein sicherheitsbewertet; kompromittiertes
root kann auch diese prüfung manipulieren.

im connected-zustand liest der finalizer `/etc/resolv.conf` über eine
größenbegrenzte, ersetzungsgeprüfte nofollow-kette; nur die eng erlaubte
`systemd-resolved`-runtime-symlinkkette ist eine ausnahme. ist `resolvectl`
bereits durch einen abgeschlossenen executable-receipt gebunden, ergänzt
`resolvectl status` die evidenz. es wird dafür weder installiert noch
vorausgesetzt. ohne receipt ist ein geschütztes statisches `resolv.conf` nur
mit literaler nicht-loopback-resolveradresse zulässig. für jeden ermittelten
resolver muss receiptgebundenes `ip -j -4/-6 route get ... uid 0` eine route
über eine von `wg show interfaces` ausgewiesene WireGuard-NIC ergeben;
loopback darf nur über `lo` laufen. ein allein sichtbarer loopback-stub ohne
upstream, physische NIC-zuordnung, driftende oder mehrdeutige evidenz bricht
fail-closed ab.

vor der hostname-basierten onlinebestätigung und erneut nach kontrolliertem
disconnect/reconnect sendet der finalizer auf jeder plan-gebundenen physischen
ethernet-NIC raw UDP/53- und TCP/53-proben zu `1.1.1.1`, `8.8.8.8` und
`9.9.9.9`. beobachtbare antwort, TCP-refusal oder -reset ist ein leak; nur
definierte policy-/down-/unreachable-/timeout-ergebnisse gelten als negative
endliche beobachtung. die firewallstruktur darf zudem keine erkennbare
DNS-acceptregel auf der physischen NIC enthalten. erst beide durchläufe setzen
`finite_connected_dns_containment_checks_passed=true`. das beweist weder, dass
bei einem timeout kein paket gesendet wurde, noch alle resolver, DoH/DoT,
namespaces, prozessmarken oder zeitabhängigen regeln.

der bibliotheksgenerator für eine separat zu prüfende manuelle WireGuard-regel
erlaubt ausgehend nur loopback, das tunnelinterface, DHCPv4 und genau einen
freigegebenen relay-endpunkt; der heutige setup-plan verdrahtet diesen pfad aber
nicht automatisch. bei `strict` und `maximal` bleibt der egress-kill-switch im
offline-bericht daher ausdrücklich offen. auf offiziell unterstützten zielen
wird erst in `vpn-finalize` der mullvad-app-kill-switch samt lockdown aktiviert
und verifiziert; auf anderen zielen bleibt die anforderung ungelöst, bis eine
separat reviewte vanilla-WireGuard-/nftables-lösung vorliegt. die host-firewall
bleibt notwendig, weil mullvads VPN-regeln keine allgemeine host-hardening-
policy ersetzen.

noch vor der TTY-abfrage der kontonummer muss `vpn-finalize` lokale
geheimnisschutz-gates positiv beweisen:

- die wirksame mount-abdeckung des klartextzustands unter
  `/etc/mullvad-vpn` ist eindeutig als verschlüsselt erkannt. ein eigenes
  `/etc`-, `/etc/mullvad-vpn`- oder exaktes datei-mount auf account-history
  beziehungsweise device-state überschattet das
  erkannte verschlüsselte root-dateisystem; da der MVP dessen verschlüsselung
  nicht separat beweisen kann, wird es fail-closed abgewiesen.
- genau ein wirksamer echter procfs-mount liegt auf `/proc`; er verwendet
  `hidepid=2` oder `hidepid=invisible`, aber keine `gid=`-ausnahme.
- `kernel.core_pattern` ist exakt leer und `kernel.core_uses_pid` exakt `0`.
  insbesondere ein pipehandler wie `|.../systemd-coredump` wird abgewiesen,
  denn bei über pipes geleiteten core-dumps schützt selbst `RLIMIT_CORE=0`
  nicht hinreichend.
- `/proc/swaps` enthält ausschließlich die kopfzeile, also weder disk-swap noch
  zram. eine vermutete swap-verschlüsselung genügt nicht.
- der geheimnistragende prozess konnte sein softes und hartes `RLIMIT_CORE`
  auf `0` sperren und sich mit `PR_SET_DUMPABLE=0` als nicht dumpbar markieren.

vor dem prompt prüft der finalizer vorhandene
`/etc/mullvad-vpn/account-history.json` und `device.json`, nach dem login prüft
er beide erneut und verlangt dann ihre existenz. `account-history.json` enthält
die kontonummer im klartext; `device.json` enthält kontobezogenen gerätezustand
und privates WireGuard-schlüsselmaterial. jede datei wird relativ zu einer
linkfrei geöffneten, root-owned und nicht gruppen-/weltbeschreibbaren
elternkette mit `O_NOFOLLOW` geöffnet. zulässig sind nur reguläre root-owned
dateien mit `nlink=1`, höchstens 1 MiB und modus 0600 oder strenger. ein fehler
tritt vor connect fail-closed ein; weder die prüfung noch FDE-erkennung
verschlüsselt die dateien nachträglich.

procfs-, globale core-dump- und swap-zustände werden unmittelbar vor dem
offiziellen CLI-start erneut gelesen; das CLI-kind erhält dieselben
`RLIMIT_CORE`-/dumpable-beschränkungen. ein uneindeutiger oder wechselnder
zustand führt fail-closed zum abbruch. das schützt normale lokale benutzer vor
der technisch unvermeidlichen mullvad-CLI-argv und reduziert weitere lokale
persistenzpfade. `strict` und `maximal` rendern `fs.suid_dumpable=0`, ein leeres
`kernel.core_pattern` und `kernel.core_uses_pid=0` in die deklarative sysctl-
konfiguration. nicht-NixOS-pläne laden sie über eine bestätigte
`sysctl --system`-action; NixOS erhält die entsprechenden werte im generierten,
erst manuell zu importierenden und zu testenden modul. diese planwerte ersetzen
die erneute effektivprüfung nicht. der MVP richtet FDE, procfs-mountpolicy und swap
nicht selbst ein. root, kernel, privilegierte eBPF-/audit- oder
vergleichbare beobachter und garantierte speicherlöschung bleiben außerhalb
dieser schutzgrenze. weil `hidepid`, abgeschaltete core-dumps und deaktivierter
swap monitoring, debugging, hibernation und betriebssicherheit beeinflussen
können, bleibt ihre persistente distributionsspezifische einrichtung ein
lokaler, recoverybewusster administrationsschritt.

nach der ersten erfolgreichen verbindung führt `vpn-finalize` einen
kontrollierten fail-closed-test aus: es trennt über die offizielle CLI, wartet
auf `disconnected`/`blocked` und prüft lockdown sowie die effektive mullvad-
nftables-tabelle. genau eine OUTPUT-basiskette mit terminaler policy `drop` ist
pflicht; indirekte oder userspace-kontrollierte verdictpfade (`jump`, `goto`,
`return`, `continue`, `queue`, `vmap`) und bedingungsloses accept werden
abgewiesen. dieser strukturcheck beweist nicht, dass jede bedingte accept-regel
tunnelgebunden ist. deshalb versucht der finalizer je gebundenem physischen
ethernet-interface zusätzlich zeitbegrenzt rohe, mit `SO_BINDTODEVICE`
gebundene TCP-connects zu `1.1.1.1:80` und `:443` sowie eine UDP/53-probe.
TCP-erfolg, `ECONNREFUSED` oder `ECONNRESET` beweist beobachtbaren verkehr;
jedes UDP-datagramm gilt unabhängig von DNS-format oder transaktions-ID als
leak. nur definierte policy-/down-/unreachable-/timeout-fehler gelten als
blockiert; alle anderen socketfehler sind unbestimmt und brechen fail-closed
ab. im `finally`-pfad wird reconnect versucht und
der verbundene zustand erneut geprüft. nur der vollständig erfolgreiche ablauf
schreibt im audit `finite_fail_closed_disconnect_checks_passed=true`.
jeder im finalizer gefangene fehler installiert und verifiziert zuerst wieder
den loopback-only bootstrap-guard, führt anschließend
`systemctl enable --now umzug-offline-guard.service` aus und verlangt enabled,
active sowie die exakte offline-regel; abschließend wird auch der bootstrap-
guard erneut geprüft. damit überlebt der fehlerzustand einen neustart und ein
erneuter finalizer-lauf kann aus einer bewiesenen grenze fortsetzen. scheitert
diese guard-reaktivierung selbst, wird der fehlschlag separat auditiert; eine
geschlossene grenze ist dann nicht bewiesen und lokale emergency-recovery ist
pflicht. die endlichen ziel-/protokollproben belegen nicht alle möglichen
namespaces, protokolle, ziele oder privilegierten bypässe.

## Erweiterungspunkte

- neue distribution: `DistributionAdapter` ableiten, nur feste capability-
  mappings definieren, einen deterministischen plan zurückgeben und auswahltests
  ergänzen.
- neuer init-/firewall-backend: eigene reine planerzeugung plus separaten,
  allowlist-basierten executor implementieren. das heutige firewallbackend setzt
  nftables voraus; systemd ist vollständig verdrahtet, OpenRC nur für
  service-deaktivierung sowie `local.d`-firewall-/rfkill-persistenz. andere
  init-systeme erhalten manuelle checkpoints.
- neue scanner: tool-binärdatei, regeln und signaturen kryptografisch außerhalb
  des quellpakets verankern; ausfall und unvollständige analyse müssen
  fail-closed bleiben.
- neue aktion: modell-allowlist, executor, diff/backup und postcondition gemeinsam
  ergänzen. eine nur modellierte, aber nicht ausführbare aktion ist kein feature.
