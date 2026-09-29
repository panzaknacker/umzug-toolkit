# Begrenzter H0-hardwaretest für v0.2.0rc1

diese anleitung beschreibt einen echten, aber kontrolliert rückbaubaren test
des toolkits auf einem physischen linux-rechner. sie ist kein
produktionszertifikat, kein malwarefreiheitsnachweis und kein ersatz für ein
vollständiges, praktisch wiederhergestelltes backup. der erste lauf bleibt
offline und verwendet das profil `compatible`.

> **verbindlicher RC-umfang:** v0.2.0rc1 ist nur ein hardware-testkandidat für
> H0 auf dedizierter, entbehrlicher debian-/ubuntu-hardware mit systemd. die
> H1-/H2-abschnitte beschreiben spätere, getrennte abnahmeziele, autorisieren
> mit diesem RC aber keinen `strict`-/`maximal`- oder mullvad-hardwarelauf.
> arch, NixOS, gentoo und LFS sind ebenfalls nicht rc1-hardwareabgenommen. ein
> NixOS-firewall-merge mit bestehender konfiguration ist insbesondere offen.

das testgerät darf nicht das einzige funktionsfähige arbeitsgerät sein. alle
produktiven schritte erfolgen an tastatur und bildschirm beziehungsweise einer
unabhängig getesteten seriellen konsole. eine SSH-sitzung ist weder konsole
noch recovery-pfad.

toolkit-rollback stellt kein vollständiges systemabbild wieder her. ein extern
getestetes voll-/blockbackup einschließlich bootbereich und EFI-systempartition
ist daher eine harte voraussetzung, nicht nur eine empfehlung. der produktive
state muss auf lokalem, persistentem und geschütztem speicher liegen, damit
reboot und `resume` dieselbe gebundene evidenz sehen; tmpfs, overlay- oder
entfernter speicher sind dafür unzulässig.

## Abnahmestufen

die ergebnisse getrennt bewerten:

- **H0, reversibler offline-basislauf:** `compatible`, kein mullvad-paket,
  keine partitionierungs-, verschlüsselungs-, secure-boot- oder
  bootloaderänderung; detect, plan, dry-run, apply, gegebenenfalls reboot und
  resume, verifikation, netzwerk-recovery und rollback müssen funktionieren.
- **H1, strikter offline-lauf:** erst nach wiederherstellung der H0-baseline;
  `strict` mit den tatsächlich unterstützten offline-artefakten. zusätzliche
  funk-, IPv6-, initramfs- und bootfolgen werden einzeln bewertet.
- **H2, mullvad-finalisierung:** optional und zuletzt. sie setzt einen
  vollständig abgeschlossenen, dafür vorbereiteten offline-plan, ein
  unabhängig verifiziertes vendor-artefakt, die vorgeschriebene
  speicherverschlüsselung und alle lokalen geheimnisschutz-gates voraus.

ein bestandener H0-lauf darf nicht als bestandenes H1- oder H2-hardening
ausgegeben werden. auf LFS, generic, nicht unterstützten paket-/init-systemen
oder hardware mit manuellen checkpoints kann ein korrektes ergebnis auch ein
begründeter fail-closed-stopp sein; es ist dann keine vollständige
hardwareabnahme.

## 1. voraussetzungen und vertrauensanker

vor dem termin müssen alle folgenden punkte erfüllt sein:

1. **dediziertes testziel:** keine ungesicherten produktiven daten, keine
   laufenden dienste oder nutzer, die vom ausfall betroffen wären, stabile
   stromversorgung und mindestens ein vollständiges wartungsfenster.
2. **vollständiges backup:** ein unabhängiges vollbackup oder blockabbild aller
   relevanten datenträger einschließlich bootbereich und EFI-systempartition.
   mindestens eine stichprobe muss auf einem anderen datenträger erfolgreich
   wiederhergestellt und gelesen worden sein. ein btrfs-/ZFS-/LVM-snapshot ist
   ein zusätzlicher schneller rückweg, aber kein ersatz für dieses backup.
3. **baseline-snapshot:** unmittelbar vor H0, sofern das dateisystem dies
   unterstützt. snapshot-ID, zeitpunkt und zugehörige bootgeneration getrennt
   notieren. das toolkit-rollback ist kein system-snapshot.
4. **lokale recovery:** signaturgeprüftes, bootfähiges live-/installationsmedium,
   lokale root-/sudo-anmeldung, firmwarezugang sowie vorhandene LUKS-recovery-
   schlüssel offline testen. auf systemd auch eine lokale anmeldung in
   `emergency.target` praktisch erproben.
5. **zweites vertrauenswürdiges gerät:** dort wheel- und installer-hash,
   signer-fingerprint, scanner-/regelhashes, plan-digest und
   hersteller-fingerprint getrennt speichern. das gerät darf diese werte nicht
   vom zu prüfenden ziel oder demselben untrusted transportmedium übernehmen.
6. **netztrennung:** ethernet abziehen; WLAN, bluetooth und mobilfunk am gerät
   beziehungsweise in der firmware abschalten. bis H2 darf kein toolkit-schritt
   internetzugriff erhalten. desktop-automount, autorun, thumbnailer und
   indexer für transportmedien deaktivieren.
7. **verifizierte offline-runtime:** wheel und pip-freien installer nach
   [OFFLINE-BUILD.md](OFFLINE-BUILD.md) bauen, beide hashes unabhängig
   authentifizieren und die produktive root-eigene runtime installieren. für
   root-schritte ausschließlich `/usr/local/sbin/umzug-setup` verwenden,
   niemals `sudo ./setup` aus dem veränderlichen quellbaum.
8. **scanner-snapshot:** bubblewrap, `file`, `clamscan`, `yara`, lokale
   YARA-regeln, genau ein ClamAV-signaturbaum und bei zstd-inhalten `zstd`
   offline aus signaturgeprüften quellen bereitstellen. binär-, regel- und
   kanonischen datenbankbaumhash in einer produktiven `scanner.toml` binden.
   fehlende oder nicht gepinnte evidenz ist ein abbruch, keine warnung zum
   überstimmen.
9. **offline-pakete:** jedes distributionsspezifisch benötigte paket samt
   vollständiger signatur- und SHA-256-closure vorher bereitstellen. der
   generische debian-/ubuntu-pfad installiert im MVP bewusst keine beliebigen
   pakete. fehlt beispielsweise `nft`, wird nicht online nachinstalliert.
10. **keine geheimnisse im H0/H1-material:** keine mullvad-kontonummer, keine
    produktiven privaten Schlüssel und keine unverschlüsselten Tokens. Logs,
    Reports und State enthalten Systemdetails und werden verschlüsselt
    aufbewahrt.
11. **persistenter lokaler state:** `/var/lib/umzug-hardware-h0` liegt auf
    lokalem, rebootfestem Speicher, ist kein tmpfs/Overlay/Netz-Dateisystem und
    gegen normale Benutzer geschützt. Seine Mount-Identität darf sich bis zum
    Abschluss von Apply, Reboot, Resume und Rollback nicht ändern.

für den ersten physischen lauf werden **keine** partitionen verändert, keine
FDE eingerichtet oder umgeschlüsselt, keine secure-boot-schlüssel eingeschrieben
und weder firmware noch bootloader geändert. das toolkit implementiert diese
änderungen im MVP ohnehin nicht. entdeckt ein plan entgegen dieser erwartung
eine solche aktion, ist das ein sofortiger abbruch und ein defektbefund.

## 2. beweisakte vorbereiten

für jeden lauf neue, nicht vorhandene ausgabe- und state-pfade verwenden, zum
beispiel:

- `/var/tmp/umzug-hardware-h0-plan.json` und dessen tatsächlicher bericht
  `/var/tmp/umzug-hardware-h0-plan.json.report.json`;
- `/var/tmp/umzug-hardware-h0-dry-state` nur für den dry-run;
- `/var/lib/umzug-hardware-h0` nur für den produktiven lauf;
- `/var/log/umzug-hardware-h0-audit.jsonl` für das lokale auditlog;
- `/var/tmp/umzug-hardware-h0-security-report.json` für den abschlussbericht.

vorher und nachher getrennt sichern:

- authentifizierte hashwerte und versionen von toolkit, scannerwerkzeugen,
  regeln, signaturen und offline-paketen;
- terminalausgabe von detect, plan und dry-run sowie den außerhalb der
  planerstellung notierten plan-digest;
- plan, `PLAN.report.json`, `state.json`, gespeicherten `state/plan.json`,
  checkpoints, backups und audit-JSONL;
- boot-/unit-journale, nftables-, routing-, DNS-, listener- und funkstatus;
- abschlussbericht sowie ergebnis von recovery, rollback und
  baselinevergleich.

die zweite maschine verifiziert die übertragenen hashes erneut und signiert
oder protokolliert die beweisakte mit einem vom testziel unabhängigen schlüssel.
auditlogs sind selbst nicht manipulationssicher signiert. private schlüssel,
mullvad-kontonummer, accountdateien, speicherabbilder und vollständige
prozessumgebungen gehören nicht in die akte. reports und hardwarekennungen vor
einer weitergabe redigieren; die unveränderten originale verschlüsselt
aufbewahren.

## Gate 0: backup und lokale recovery

H0 beginnt erst, wenn:

- der wiederherstellungstest des vollbackups dokumentiert ist;
- snapshot oder baseline-backup unveränderlich referenziert ist;
- das live-medium bis zu einer lokalen root-shell gebootet wurde;
- root-/sudo- und gegebenenfalls LUKS-recovery lokal funktionieren;
- das zweite gerät die hashanker anzeigt, während das ziel offline ist;
- der bediener weiß, wie das testgerät im firmware-menü vom live-medium startet.

der vorhandene CLI-recovery-pfad kann vor jeder änderung nur als vorschau
aufgerufen werden:

```sh
/usr/local/sbin/umzug-setup recover-network \
  --confirm-recovery \
  --dry-run
```

das später durch den plan installierte skript
`/usr/local/sbin/umzug-network-recovery` muss zusätzlich vor aktivierung der
firewall im plan sichtbar sein. vor seiner installation darf seine existenz
nicht behauptet werden.

**abbruch:** kein getestetes backup, keine lokale konsole, fehlender
firmwarezugang, unklarer recovery-key, ausschließlich remotezugriff oder
abweichende artefakthashes.

## Gate 1: ausschließlich lesende erkennung

das ziel bleibt physisch netzlos. zuerst die unveränderte hardware erkennen:

```sh
umzug-setup --log /var/tmp/umzug-hardware-h0-detect.jsonl detect --json
```

die ausgabe gegen firmware- und installationsbestand prüfen, insbesondere:

- distribution, version, architektur, kernel, paketmanager und init-system;
- UEFI/BIOS und secure-boot-status, ohne ihn zu verändern;
- GPU und treiberhinweise;
- jedes physische ethernet-interface samt treiber;
- WLAN-, bluetooth- und mobilfunkgeräte sowie erkannte module;
- TPM/IOMMU und andere gemeldete hardware-sicherheitsfunktionen;
- root-dateisystem, mount-abdeckung, partitionierung und
  verschlüsselungsstatus.

erkennung ist best-effort. eine leere geräteliste beweist nicht, dass keine
funkhardware existiert. firmwareansicht, gehäuse-/boarddokumentation und
`detect` müssen gemeinsam bewertet werden.

**abbruch:** falsche distribution oder zielplatte, unerklärte physische NIC,
falsches ethernet-interface, für den gewählten plan sicherheitsrelevante
hardware als `unknown`, unerwartete funkgeräte oder eine diskrepanz zwischen
firmware und erkennung. für den eintritt in H2 ist außerdem jede unklare
verschlüsselungsabdeckung ein harter stopp.

## Gate 2: pläne erzeugen und vergleichen

für H0 das konkrete beispielinterface durch das in gate 1 bestätigte physische
ethernet ersetzen. das beispiel erzeugt nur einen plan und bereitet mullvad
ausdrücklich nicht vor:

```sh
umzug-setup plan \
  --profile compatible \
  --output /var/tmp/umzug-hardware-h0-plan.json \
  --ethernet enp0s31f6 \
  --no-mullvad-app-preparation
```

optional `strict` und `maximal` jetzt nur zum vergleich in jeweils neue
ausgabepfade planen. im ersten physischen lauf wird ausschließlich der
vollständig geprüfte `compatible`-plan angewendet. für H1 nach der
baseline-wiederherstellung einen frischen `strict`-plan aus einer neuen
erkennung erzeugen; einen alten H0-plan nie umschreiben oder wiederverwenden.
H0/H1 fordern absichtlich keine optionale `ssh-client`-capability an. die
profilgebundene deaktivierung eines vorhandenen eingehenden SSH-servers bleibt
dagegen teil von apply und darf nicht aus dem plan verschoben werden. ein
optionaler ausgehender SSH-client-test folgt erst nach H2.

plan und `PLAN.report.json` vollständig lesen. prüfpunkte:

- system-fingerprint und adapter entsprechen genau gate 1;
- exakt die bestätigten physischen ethernet-interfaces sind gebunden;
- `executable_preflight` enthält keine ungeklärten `MISSING/UNSAFE`-einträge;
- alle diffs, zielpfade, modi, backups, verifier, rebootgründe und manuellen
  checkpoints sind verständlich;
- keine eingehende SSH-accept-regel und keine installation/aktivierung eines
  SSH-servers;
- netzwerk-recovery wird vor dem firewall-lockdown installiert;
- kein freier paketname aus migrationsdaten und kein online-paketbefehl;
- H0 enthält keine mullvad-, partitionierungs-, FDE-, secure-boot-, firmware-
  oder bootloaderänderung;
- offene punkte wie MAC-policy, FDE oder VPN-kill-switch bleiben ehrlich als
  offen ausgewiesen.

den von der planerzeugung angezeigten SHA-256-digest exakt auf dem zweiten gerät
notieren. plan und report dürfen danach nicht mehr verändert werden.

**abbruch:** unbekannte action-ID, unerwarteter zielpfad, falsches interface,
fehlendes werkzeug, unverständlicher destruktiver schritt, generisches
`apt-get`, ein geplanter netzwerkzugriff oder eine als erfüllt dargestellte,
tatsächlich nur manuelle anforderung.

## Gate 3: mutationsfreier dry-run

der dry-run verwendet ein eigenes state-verzeichnis und benötigt keinen
erwarteten planhash:

```sh
umzug-setup --log /var/tmp/umzug-hardware-h0-dry-run.jsonl apply \
  /var/tmp/umzug-hardware-h0-plan.json \
  --dry-run \
  --state-dir /var/tmp/umzug-hardware-h0-dry-state
```

er muss alle änderungen, diffs, risiken und bestätigungs-ids zeigen, darf aber
keine action als produktiv abgeschlossen markieren. `not inspectable by this
unprivileged dry-run` ist kein erfolgsnachweis; genau dieser pfad muss vor dem
root-lauf separat geprüft werden. `MISSING/UNSAFE` blockiert produktives apply.

die dry-run-ausgabe gegen plan und report abgleichen und auf dem zweiten gerät
den plan-digest nochmals vergleichen.

**abbruch:** unerwartete abweichung vom plan, mutation, abgeschlossene
action-ID, nicht erklärbarer root-only-bestand, fehlende/unsichere werkzeuge,
plan-digest-abweichung oder ein nicht leerer alter dry-run-state.

## Gate 4: verpflichtender, schreibgeschützter hardware-preflight

den preflight als root an derselben echten lokalen systemkonsole ausführen, an
der später apply läuft. `/dev/pts`, SSH, eine unvollständig prüfbare
prozesskette und ein nicht interaktives stdin werden fail-closed abgewiesen.
der befehl liest nur lokale evidenz, sendet keine netzwerkproben, legt den
state-pfad nicht an und führt keine planaktion aus:

```sh
sudo /usr/local/sbin/umzug-setup hardware-preflight \
  /var/tmp/umzug-hardware-h0-plan.json \
  --expected-plan-sha256 '<SHA256-AUS-DER-PLAN-AUSGABE>' \
  --state-dir /var/lib/umzug-hardware-h0 \
  --recovery-medium /mnt/umzug-recovery
```

der erste lauf soll noch keine ungeprüfte aussage attestieren. er zeigt alle
automatischen blocker und genau die für diesen plan noch erforderlichen
manuellen attestierungs-ids. exitstatus `3` bedeutet dabei bewusst
`blocked` oder `manual-attestation-required`, nicht einen bestandenen
preflight. erst die verlangten lokalen prüfungen tatsächlich durchführen und
danach denselben befehl mit jeder angezeigten ID einzeln wiederholen, zum
beispiel:

```sh
sudo /usr/local/sbin/umzug-setup hardware-preflight \
  /var/tmp/umzug-hardware-h0-plan.json \
  --expected-plan-sha256 '<SHA256-AUS-DER-PLAN-AUSGABE>' \
  --state-dir /var/lib/umzug-hardware-h0 \
  --recovery-medium /mnt/umzug-recovery \
  --attest full-backup-restore-tested \
  --attest network-physically-disconnected \
  --attest recovery-medium-boot-tested
```

`backup-and-rollback-reviewed`, `destructive-actions-reviewed`,
`reboot-path-tested` und `stable-power-confirmed` nur ergänzen, wenn der erste
bericht sie für den konkreten plan verlangt und die jeweilige aussage wirklich
erfüllt ist. für eine maschinenlesbare beweisakte darf `--json` verwendet und
stdout in einen **neuen**, root-geschützten pfad umgeleitet werden; stdin muss
weiter an der echten lokalen konsole hängen. `--log` ist absichtlich verboten,
damit der read-only preflight keinen auditpfad anlegt.

automatisch geprüft werden unter anderem planhash und toolkit-version,
ziel-fingerprint, vollständiger physischer ethernet-bestand,
funkmodul-intent, root-eigene produktive runtime, werkzeugauflösung,
state-/backup-speicher, recovery-reihenfolge und separates recovery-medium.
carrier, IPv4-/IPv6-default-routen und unvollständige lokale netzevidenz
blockieren. unmittelbar vor jeder produktiven apply-/resume-mutation wird die
offline-grenze erneut geprüft.

der einzige bestandene zustand ist `ready` mit exitstatus `0`. auch dann steht
im bericht `authorization_to_apply: false`: der preflight ersetzt weder den
erneuten diff noch den planhash oder die einzelbestätigung einer aktion.

zusätzlich unmittelbar vor apply bestätigen:

1. netzwerk weiterhin physisch getrennt; keine remote-sitzung ist geöffnet.
2. aktueller snapshot und vollbackup sind erreichbar, das live-medium steckt
   bereit, lokale root-anmeldung funktioniert.
3. produktiver state-pfad ist neu, lokal und gegen normale benutzer geschützt.
4. plan und report sind unverändert; der digest stimmt mit dem zweiten gerät
   überein.
5. alle ausführbaren preflights sind vorhanden, sicher aufgelöst und aus dem
   vorgesehenen offline-bestand. kein spontanes online-update durchführen.
6. freier speicher, stromversorgung und zeitfenster reichen für backup,
   initramfs und einen zusätzlichen recovery-reboot.
7. jede kritische/destruktive action-ID wurde einzeln notiert. es wird kein
   pauschales `--yes` verwendet.
8. der plan installiert den lokalen netzwerk-recovery-befehl vor den
   firewall-aktionen.
9. es gibt keine änderung an partitionierung, FDE, secure boot, firmware oder
   bootloader.
10. bei systemd ist der beabsichtigte fail-closed-boot nach einem firewall-
    Loadfehler verstanden; auf echter Hardware wird im ersten Lauf **kein**
    absichtlich beschädigter Regelsatz erzeugt. Dieser Negativtest gehört in
    eine Snapshot-VM.

**abbruch:** status ist nicht `ready`, irgendein kästchen bleibt offen, der
state-pfad liegt auf flüchtigem storage, oder automatische und manuelle
evidenz widersprechen einander. fehlende pakete oder scanner werden offline
nachbeschafft; anschließend beginnen detect und plan mit neuen ausgabepfaden
erneut. scanner-/bubblewrap-probe und vendor-revalidierung sind bewusst
separate gates und werden durch `hardware-preflight` nicht als erledigt
ausgegeben.

## Gate 5: produktives offline-apply

nur an der lokalen konsole und mit dem extern notierten digest:

```sh
sudo /usr/local/sbin/umzug-setup \
  --log /var/log/umzug-hardware-h0-audit.jsonl \
  apply /var/tmp/umzug-hardware-h0-plan.json \
  --expected-plan-sha256 '<SHA256-AUS-DER-PLAN-AUSGABE>' \
  --state-dir /var/lib/umzug-hardware-h0
```

jeden aktuellen diff neu lesen. normale fragen bewusst beantworten; bei
kritischen/destruktiven aktionen exakt die angezeigte action-ID eingeben. ein
planhash ersetzt diese einzelbestätigungen nicht. keine unbekannte manuelle
checkpoint-phrase bestätigen und nie eine fehlgeschlagene verifikation durch
dateiedits oder direktes manipulieren von `state.json` umgehen.

wenn apply einen reboot-checkpoint erreicht, vor dem neustart mindestens
auditlog, `state.json`, gespeicherten plan, rebootgrund und angezeigten
fortsetzungsbefehl sichern. noch nicht `resume` aufrufen.

**abbruch:** hash- oder ziel-fingerprintfehler, unvorhergesehener netzbedarf,
abweichender diff, fehlender backupbeleg, werkzeugdrift, unklare bestätigung,
verifierfehler, beschädigter state oder eine nicht im plan erklärte
boot-/netzwerkänderung. netzwerk getrennt lassen, evidenz sichern und nur den
dokumentierten recovery-/rollback-weg verwenden.

## Gate 6: reboot und resume

nur neu starten, wenn der gespeicherte checkpoint den neustart verlangt und
den grund erklärt:

```sh
sudo reboot
```

nach dem boot ausschließlich lokal anmelden. bei `emergency.target` zuerst
evidenz sammeln:

```sh
systemctl --failed
journalctl -b -u umzug-offline-guard.service -u umzug-firewall.service
nft -a list ruleset
```

ist die ursache nicht sofort eindeutig, nicht mit geöffnetem netz
weiterarbeiten, sondern die schritte aus [RECOVERY.md](RECOVERY.md) verwenden.
bei normalem boot fortsetzen:

```sh
sudo /usr/local/sbin/umzug-setup resume \
  --state-dir /var/lib/umzug-hardware-h0
```

`resume` muss eine neue boot-ID, den unveränderten abgeschlossenen
action-prefix und die plan-gebundene postcondition prüfen. jeder weitere
checkpoint wird auf dieselbe weise behandelt. manuelle attestierungen nur nach
tatsächlicher prüfung und exakt in der vom tool angezeigten form eingeben.

**abbruch:** gleiche boot-ID, drift, fehlende verwaltete datei, abweichender
guard, weiterhin geladenes gesperrtes modul, nicht erfüllte postcondition oder
ein unerwartet offenes netz. keinen neuen plan über einen offenen checkpoint
legen.

## Gate 7: lokale verifikation und bericht

nach vollständig abgeschlossenem apply/resume das ziel weiterhin offline
prüfen. auf systemd-/nftables-zielen gelten die dokumentierten befehle:

```sh
sudo nft -a list table inet umzug_host
sudo systemctl status umzug-firewall.service
sudo systemctl status umzug-offline-guard.service
sudo systemctl is-enabled \
  umzug-firewall.service umzug-offline-guard.service
sudo systemctl is-enabled ssh.service sshd.service
ss -lntup
rfkill list
ip -4 route show table all
ip -6 route show table all
```

`resolvectl status` nur verwenden, wenn `resolvectl` bereits vorhanden und
receiptgebunden ist. auf OpenRC, NixOS-sonderpfaden und manuellen adaptern die
im plan genannten distributionsnativen verifier verwenden; systemd-ausgaben
dort nicht als ersatz erfinden.

den toolkit-bericht in einen neuen pfad schreiben:

```sh
sudo /usr/local/sbin/umzug-setup report \
  --output /var/tmp/umzug-hardware-h0-security-report.json \
  --state-dir /var/lib/umzug-hardware-h0
```

dieser bericht ist nur ein lokaler **rohbeleg** der implementierten,
zeitpunktbezogenen prüfungen. er ist weder signiert noch eine unabhängige
attestierung, er autorisiert kein apply und beweist weder vollständigen
rollback noch bootfähigkeit, malware- oder leakfreiheit. die effektiven
firewall-, routing-, DNS-, listener-, funk- und bootbefunde müssen weiterhin
separat erhoben und mit der externen baseline verglichen werden.

für H0 müssen mindestens gelten:

- plan vollständig abgeschlossen, kein offener reboot-checkpoint und keine
  verifierdrift;
- INPUT und FORWARD der toolkit-host-firewall haben policy `drop`;
- keine eingehende SSH-accept-regel, kein listener auf TCP/22 und kein aktiver
  oder entgegen dem plan unmaskierter SSH-server; ein noch installiertes paket
  allein darf nicht als aktiver dienst fehlinterpretiert werden;
- keine unerwarteten listener oder veröffentlichte dienste;
- recovery-befehl vorhanden und sein dry-run erfolgreich;
- hardware-, funk-, routing- und DNS-befund stimmen mit plan und profil
  überein;
- bericht nennt FDE, MAC-policy und VPN weiterhin offen, sofern sie nicht
  tatsächlich verifiziert wurden.

ein zweites gerät darf erst jetzt als testhost an ein isoliertes lokales
testsegment angeschlossen werden, um zu bestätigen, dass kein ungeplanter
eingehender port erreichbar ist. es wird kein SSH-server aktiviert und kein
SSH-login als testweg verwendet. danach das kabel wieder trennen.

## Gate 8: netzwerk-recovery, rollback und baseline

recovery wird erst nach sicherung aller vorher-/nachher-belege getestet. zuerst
beide änderungen nur anzeigen:

```sh
/usr/local/sbin/umzug-setup recover-network \
  --confirm-recovery \
  --dry-run

sudo /usr/local/sbin/umzug-setup rollback \
  --state-dir /var/lib/umzug-hardware-h0 \
  --confirm-rollback \
  --dry-run
```

dann an der lokalen konsole die netzwerk-recovery wirklich ausführen:

```sh
sudo /usr/local/sbin/umzug-setup recover-network \
  --confirm-recovery
```

sie darf nur die dokumentierten toolkit-netztabellen/-hooks deaktivieren,
öffnet keinen SSH-port und kann normalen egress bewusst wieder zulassen. das
ethernet bleibt deshalb abgezogen. nftables, units und listener erneut sichern.

anschließend toolkit-rollback ausführen:

```sh
sudo /usr/local/sbin/umzug-setup rollback \
  --state-dir /var/lib/umzug-hardware-h0 \
  --confirm-rollback
```

neu starten, die baseline-befunde erneut erfassen und mit gate 1 vergleichen.
abweichungen an nicht vom toolkit gesicherten paket-, boot- oder
distributionszuständen müssen aus snapshot/vollbackup wiederhergestellt werden.
erst wenn diese wiederherstellung praktisch funktioniert und dokumentiert ist,
ist H0 bestanden.

**abbruch und wiederherstellung:** recovery entfernt nicht exakt nur die
toolkit-regeln, öffnet SSH, rollback scheitert, das system bootet nicht normal
oder baselinevergleich weicht unerklärt ab. in diesem fall H1/H2 nicht starten;
vom live-medium snapshot beziehungsweise vollbackup wiederherstellen und den
fehlerbericht sichern.

## 3. H1: strikter offline-lauf

**nicht teil der v0.2.0rc1-hardwarefreigabe.** dieser abschnitt bleibt als
zukünftiges abnahmeprotokoll erhalten. er darf erst mit einem dafür neu
freigegebenen build und nach bestandener, wiederhergestellter H0-baseline
verwendet werden.

nach erfolgreichem H0 und wiederhergestellter baseline gates 1 bis 8 mit neuen
pfaden und einem frisch erzeugten `strict`-plan wiederholen. keine H0-pläne,
digests oder state-verzeichnisse wiederverwenden.

```sh
umzug-setup plan \
  --profile strict \
  --output /var/tmp/umzug-hardware-h1-plan.json \
  --ethernet enp0s31f6 \
  --no-mullvad-app-preparation
```

auch hier das beispielinterface ersetzen. nur vollständig offline vorbereitete,
vom zieladapter akzeptierte capabilities hinzufügen; jede hinzugefügte
capability verlangt einen neuen plan- und dry-run-durchgang.

vor apply zusätzlich prüfen:

- IPv6-deaktivierung ist ausdrücklich gewollt und mit der lokalen umgebung
  vereinbar;
- alle funkgeräte und dienste sind korrekt erkannt; kernelmodule werden nur
  nach manueller treiberzuordnung gesperrt;
- distributionsrichtiger initramfs-befehl und rebootgrund sind nachvollziehbar;
- jedes physische ethernet-interface ist im plan gebunden;
- der offline-bericht bezeichnet den VPN-egress-kill-switch bis H2 weiterhin
  als offen.

im ersten physischen H1-lauf keine absichtliche guard-korruption, keine
ungetestete modul-blacklist und kein profil `maximal` verwenden. muss der plan
für die vorhandene hardware eine riskante blacklist oder einen manuellen
initramfs-schritt erzeugen, ist ein fail-closed-stopp das richtige ergebnis;
zuerst in einer möglichst hardwaregleichen testinstallation validieren.

H1 ist nur bestanden, wenn zusätzlich alle planmäßig zu deaktivierenden
funkgeräte blockiert, bestätigte IPv6-controls wirksam, die erwarteten module
nach reboot nicht geladen und alle strikten warnungen entweder maschinell
verifiziert oder ausdrücklich als nicht erfüllt ausgewiesen sind.

## 4. H2: mullvad und SSH zuletzt

**nicht teil der v0.2.0rc1-hardwarefreigabe.** insbesondere sind die reale
rebootfeste boot-übergabe vom offline-/bootstrap-guard zu mullvad-lockdown, die
DNS-eindämmung auf physischer hardware und die bereinigung beziehungsweise
lebensdauer temporärer konto-/secret-daten in erfolgs-, abbruch- und
crashpfaden noch offene hardware-nachweise. die folgenden schritte sind ein
späteres abnahmeprotokoll und dürfen nicht aus unit-tests oder einem
sicherheitsbericht als bereits bestanden abgeleitet werden.

H2 ist ein eigener, abschließender testlauf. der H1-recovery-weg muss bereits
praktisch bestanden sein. die offizielle mullvad-app, detached signature,
hersteller-key, fingerprint, exakte paketversion/-architektur und alle
prüfwerkzeuge werden vorher auf einem vertrauenswürdigen system beschafft,
unabhängig authentifiziert und durch `QUARANTINE` → `SANITIZED` → `APPROVED`
sowie `verify-vendor` geführt. der neue hardening-plan bindet artefakt, receipt
und alle unabhängigen hashanker exakt wie in [USER-GUIDE.md](USER-GUIDE.md)
beschrieben. gates 1 bis 7 mit H2-eigenen ausgabe- und state-pfaden wiederholen.
der produktive offline-apply dieses plans verwendet denselben state, den
`vpn-finalize` später übernimmt:

```sh
sudo /usr/local/sbin/umzug-setup \
  --log /var/log/umzug-hardware-h2-audit.jsonl \
  apply /var/tmp/umzug-hardware-h2-plan.json \
  --expected-plan-sha256 '<SHA256-AUS-DER-PLAN-AUSGABE>' \
  --state-dir /var/lib/umzug-hardware-h2
```

jeden verlangten reboot mit dem realen fortsetzungsbefehl abschließen:

```sh
sudo /usr/local/sbin/umzug-setup resume \
  --state-dir /var/lib/umzug-hardware-h2
```

erst ein vollständig abgeschlossener, unveränderter H2-plan darf in die
online-finalisierung gelangen.

kein mullvad-login ist zulässig, solange eine voraussetzung offen ist. lokal
prüfen:

```sh
findmnt -T /etc
findmnt -T /etc/mullvad-vpn
findmnt -no TARGET,FSTYPE,OPTIONS /proc
sysctl -n kernel.core_pattern
sysctl -n kernel.core_uses_pid
cat /proc/swaps
```

die mount-abdeckung von `/etc/mullvad-vpn` muss eindeutig als verschlüsselt
erkannt sein, `/proc` muss die dokumentierte `hidepid`-policy ohne
gruppenausnahme haben, `kernel.core_pattern` leer, `kernel.core_uses_pid` `0`
und `/proc/swaps` auf die kopfzeile beschränkt sein. das toolkit richtet FDE
nicht ein. ist das testsystem unverschlüsselt oder der befund unklar, endet H2
hier erwartungsgemäß fail-closed; FDE wird nicht als teil dieses ersten
hardwaretests nachgerüstet.

erst jetzt ethernet verbinden und am lokalen TTY ausführen:

```sh
sudo /usr/local/sbin/umzug-setup \
  --log /var/log/umzug-hardware-h2-audit.jsonl \
  vpn-finalize \
  --state-dir /var/lib/umzug-hardware-h2 \
  --expected-plan-sha256 '<SHA256-DES-VOLLSTAENDIG-ABGESCHLOSSENEN-PLANS>'
```

die kontonummer ausschließlich verdeckt am TTY eingeben, niemals über argv,
environment, datei, pipe, remote-sitzung oder testprotokoll. nach erfolg lokal
und über den toolkit-bericht prüfen:

```sh
mullvad status -v
wg show
nft -a list ruleset
ip route show table all
```

`vpn-finalize` muss seinen online-check, die kontrollierte trennung, die
endlichen TCP/80-, TCP/443- und UDP/53-proben auf jedem plan-gebundenen
ethernet-interface, den fail-closed-zustand und den anschließenden reconnect
selbst erfolgreich abschließen. das beweist nur die implementierte endliche
stichprobe, keine allgemeine leakfreiheit.

erst nach diesem nachweis darf optional eine ausgehende SSH-client-verbindung
als normale VPN-anwendung getestet werden. ein eingehender SSH-server bleibt
deaktiviert; kein port 22 darf lauschen und keine firewallregel darf ihn
freigeben. eine spätere serveraktivierung gehört nicht zu dieser abnahme.

bei jedem H2-fehler keine kontoeingabe wiederholen und keinen guard manuell
lockern. ethernet abziehen, die durch den finalizer reaktivierte offline-
beziehungsweise bootstrap-grenze verifizieren und ausschließlich lokale
recovery nach [RECOVERY.md](RECOVERY.md) durchführen.

## 5. klare abbruchkriterien

der lauf ist sofort zu stoppen, wenn mindestens eines gilt:

- backup oder snapshot ist nicht lesbar beziehungsweise restore wurde nicht
  bewiesen;
- lokale root-/emergency-konsole oder live-medium funktioniert nicht;
- ein hash/fingerprint stimmt nicht oder stammt nur vom untrusted zielmedium;
- das ziel war vor H2 unerwartet online;
- erkennung, plan, planreport und reale hardware widersprechen sich;
- falsche platte, NIC, distribution, init-system oder bootmodus ist gebunden;
- `MISSING/UNSAFE`, ungepinnte scannerregeln oder unvollständige paketclosure;
- planhash, system-fingerprint, datei-receipt oder verifier driftet;
- unerwartete partitionierungs-, FDE-, secure-boot-, firmware-, bootloader-
  oder online-paketaktion;
- ein diff, eine action-ID, ein manueller checkpoint oder rebootgrund ist nicht
  vollständig verstanden;
- apply/resume verlangt das überspringen einer postcondition oder das manuelle
  editieren des state;
- firewall/guard lädt nicht, SSH lauscht, ein ungeplanter dienst ist erreichbar
  oder ein funkgerät bleibt entgegen dem angewendeten profil aktiv;
- recovery öffnet SSH oder entfernt fremde firewallregeln;
- rollback/baseline-wiederherstellung ist unvollständig;
- vor H2 sind FDE-, procfs-, core-dump- oder swap-gates nicht eindeutig;
- der mullvad-disconnect-test meldet verkehr oder einen unbestimmten fehler.

nach einem abbruch nichts „reparieren“, um den test grün zu machen. netz
physisch trennen, logs und effektiven zustand sichern, recovery oder rollback
an der konsole ausführen und nötigenfalls das vollständige backup
wiederherstellen. danach mit neuer erkennung, neuen ausgabepfaden und neuem plan
beginnen.

## 6. akzeptanzkriterien

### H0 bestanden

- alle voraussetzungen und gates 0 bis 8 sind mit zeit, bediener und hashankern
  dokumentiert.
- detect entspricht der realen hardware; plan und report sind vollständig und
  unverändert.
- dry-run war mutationsfrei; produktives apply akzeptierte nur den extern
  notierten digest und die einzeln bestätigten aktionen.
- jeder verlangte reboot wurde über checkpoint und `resume` mit positiver
  postcondition abgeschlossen.
- host-firewall blockiert unerwarteten ingress; kein SSH-server/port 22 und
  keine unerwarteten listener sind aktiv.
- sicherheitsbericht nennt offene anforderungen ehrlich.
- netzwerk-recovery, rollback und wiederherstellung zur baseline wurden real
  ausgeführt und unabhängig verglichen.

### H1 bestanden

dieses kriterium ist ein späteres ziel und kann für v0.2.0rc1 nicht als
hardware-abnahmestatus vergeben werden.

- H0 war zuvor bestanden und die baseline wurde wiederhergestellt.
- frischer `strict`-plan und frischer state wurden verwendet.
- IPv6-, funk-, modul-, sysctl-, firewall- und reboot-ergebnis entsprechen
  exakt dem plan; jede nicht unterstützte kontrolle bleibt sichtbar offen.
- offline-guard und host-firewall sind rebootfest verifiziert; recovery und
  rollback funktionieren erneut.
- der noch nicht finalisierte VPN-kill-switch wird nicht als erfüllt behauptet.

### H2 bestanden oder korrekt blockiert

auch dieses kriterium liegt außerhalb der v0.2.0rc1-hardwarefreigabe. ein
fail-closed blocker ist wichtige evidenz, aber keine bestandene H2-abnahme.

- H2 darf als **bestanden** gelten, wenn vendor-kette, vollständiger offline-
  plan, verschlüsselte mount-abdeckung, procfs/core-/swap-gates,
  `vpn-finalize`, disconnect-/reconnect-proben und abschlussbericht positiv
  sind und weiterhin kein eingehendes SSH existiert.
- fehlt FDE oder eine andere zwingende voraussetzung, ist nur „H2 korrekt
  fail-closed blockiert“ zulässig, nicht „bestanden“.
- keine stufe darf eine garantie von malwarefreiheit, vollständiger
  leakfreiheit, boot-sicherheit oder zukünftiger kompromissfreiheit ausgeben.

die allgemeine testmatrix und die bewusst nur in vms auszuführenden
negativtests stehen in [TESTING.md](TESTING.md). ausführliche notfallverfahren
stehen in [RECOVERY.md](RECOVERY.md), bekannte grenzen in
[LIMITATIONS.md](LIMITATIONS.md).
