# Recovery und rollback

recovery ist vor jeder hardening-anwendung vorzubereiten und an einer lokalen
konsole zu testen. niemals eine firewall-, funk-, IPv6-, modul- oder
boot-änderung ausschließlich über eine remote-sitzung anwenden. das basissystem
installiert und öffnet bewusst keinen SSH-server.

## Vor dem anwenden

1. bootfähiges, signaturgeprüftes live-/installationsmedium bereithalten.
2. LUKS-recovery-key, secure-boot-/firmware-zugang und lokale root-/sudo-
   anmeldung offline testen.
3. wenn möglich einen dateisystem- oder VM-snapshot erstellen. das toolkit-
   rollback ist kein vollständiger system-snapshot.
4. den plan lesen, `umzug-setup apply PLAN --dry-run` ausführen und besonders
   alle als `DESTRUKTIV` markierten action-ids sowie die angezeigte plan-
   SHA-256 getrennt notieren. produktives apply verlangt exakt diesen digest
   zwingend über `--expected-plan-sha256`; eine TTY-eingabeaufforderung als
   ersatz existiert nicht.
5. ein eigenes state-verzeichnis auf verschlüsseltem lokalem storage wählen und
   sichern; standard ist `/var/lib/umzug`.
6. prüfen, dass `/usr/local/sbin/umzug-network-recovery` im plan enthalten ist,
   bevor die firewall aktiviert wird.
7. prüfen, dass produktive root-befehle tatsächlich den root-owned launcher
   `/usr/local/sbin/umzug-setup` aus der geschützten runtime verwenden. der
   quellbaum-launcher verweigert root; `sudo ./setup` ist kein recovery-pfad.
8. auf systemd-zielen lokale root-anmeldung im emergency mode praktisch testen.
   offline-guard und host-firewall sind harte boot-abhängigkeiten; ein
   nftables-loadfehler darf den normalen boot absichtlich stoppen.

## Kontoeingabe wegen storage, core-dump oder swap blockiert

der account-schritt hat keinen storage-risiko-override. er verlangt eine
eindeutig verschlüsselte mount-abdeckung für `/etc/mullvad-vpn`. ein separates
`/etc`-, `/etc/mullvad-vpn`- oder exaktes datei-mount auf
`account-history.json` beziehungsweise `device.json` wird von der heutigen
erkennung nicht aus dem root-FDE-indiz abgeleitet und blockiert fail-closed.
zuerst nur lesen:

```sh
findmnt -T /etc
findmnt -T /etc/mullvad-vpn
```

vor dem prompt müssen vorhandene `account-history.json` und `device.json`, nach
dem login beide zwingend vorhandenen dateien die linkfreie root-/mode-/typ-/
single-link-/1-MiB-prüfung bestehen. bei einem fehler dateien nicht blind mit
`chmod`, `chown`, kopieren oder link-ersetzung „reparieren“: sie enthalten die
kontonummer beziehungsweise kontobezogenen gerätezustand und privates
WireGuard-schlüsselmaterial. den daemon nicht weiterverwenden, mount- und
dateiherkunft lokal untersuchen und bei nicht beweisbarer verschlüsselung das
ziel außerhalb des toolkits sicher neu aufbauen. die prüfung verschlüsselt
vorhandene bytes nicht nachträglich.

`vpn-finalize` bricht vor der kontoeingabe und erneut unmittelbar vor dem
offiziellen CLI-login ab, wenn `kernel.core_pattern` nicht exakt leer,
`kernel.core_uses_pid` nicht `0` oder irgendein swap aktiv ist. das schließt
verschlüsselten swap und zram absichtlich ein. ein pipehandler wie
`|/usr/lib/systemd/systemd-coredump` ist kein zulässiger ersatz: der kernel
wendet `RLIMIT_CORE` bei über pipes geleiteten core-dumps nicht als
hinreichende sperre an.
der finalizer ändert diese wirksamen voraussetzungen nicht heimlich.

zuerst ausschließlich lesend an der lokalen konsole prüfen:

```sh
free -h
swapon --show --bytes
sysctl -n kernel.core_pattern
sysctl -n kernel.core_uses_pid
cat /proc/swaps
```

die `core_pattern`-ausgabe muss leer, `core_uses_pid` muss `0` und
`/proc/swaps` muss auf seine kopfzeile beschränkt sein. `strict` und `maximal`
schreiben die drei deklarativen werte `fs.suid_dumpable=0`, leeres
`kernel.core_pattern` und `kernel.core_uses_pid=0` nach
`/etc/sysctl.d/90-umzug-hardening.conf` und laden sie über die bestätigte
`sysctl --system`-action; auf NixOS werden sie im zu importierenden modul
gerendert. bei abweichung deshalb zuerst plan, backup, apply-/rebuild-ergebnis
und spätere drift untersuchen.

> **betriebs- und datenverlustwarnung:** `swapoff -a` kann belegte seiten in
> unzureichenden RAM zwingen, den OOM-killer auslösen, prozesse beenden oder das
> system festfahren. es kann hibernation/resume unbrauchbar machen. das
> abschalten globaler core-dumps entfernt wichtige crashanalyse. niemals über
> eine remote-sitzung ändern. erst workloads stoppen, freien RAM und
> swap-belegung prüfen, recovery-/neustartweg vorbereiten und die auswirkungen
> der ziel-distribution ausdrücklich akzeptieren.

nur wenn diese prüfung ausreichend RAM und einen sicheren lokalen recovery-weg
bestätigt und die änderung wirklich gewollt ist, kann der **laufende** zustand
konkret so korrigiert werden:

```sh
sudo sysctl -w 'kernel.core_pattern='
sudo sysctl -w 'kernel.core_uses_pid=0'
sudo swapoff -a
```

danach alle fünf lesenden befehle erneut ausführen. die beiden `sysctl -w`-
änderungen und `swapoff -a` allein sind nicht zwingend rebootfest. außerhalb
von `strict`/`maximal` muss die core-policy distributionsgerecht persistent
konfiguriert werden; swap kann aus `/etc/fstab`, systemd-units, zram-
generatoren oder resume-konfiguration wiederkehren. diese quellen nicht blind
editieren: hibernation und bootfähigkeit zuerst distributionsspezifisch
bewerten, anschließend neu starten und erneut prüfen. bleibt auch nur ein gate
uneindeutig, keine kontonummer eingeben. spätere reaktivierung von swap oder
core-dumps liegt außerhalb des dokumentierten geheimnisschutz-nachweises.

## Sofortige netzwerk-recovery

an der lokalen konsole als root:

```sh
/usr/local/sbin/umzug-network-recovery
```

der installierte befehl deaktiviert und stoppt die systemd-units
`umzug-firewall.service`, `umzug-radio-off.service` und
`umzug-offline-guard.service`, entfernt ausschließlich die nftables-tabellen
`inet umzug_vpn_bootstrap_guard`, `inet umzug_vpn_lock`, `inet umzug_host` und
`inet umzug_offline_guard`, hebt `rfkill`-sperren auf und benennt vorhandene
OpenRC-`local.d`-hooks mit dem suffix `.disabled-by-recovery` um. er startet
**keinen** SSH-server und öffnet keine eingehende portregel. er öffnet aber
bewusst den normalen egress und ist daher nur für lokale notfall-recovery
gedacht. das skript und die CLI verlangen root sowie eine nachgewiesene
`/dev/console`-, VT-, serielle oder hypervisor-konsole; SSH, `/dev/pts`,
unvollständig prüfbare prozessabstammung und nichtinteraktive ausführung werden
vor jeder änderung abgewiesen. kann eine unit, ein hook, `rfkill` oder der
endzustand der eigenen nftables-tabellen nicht eindeutig geprüft werden, endet
recovery ungleich null und darf nicht als erfolgreich gelten.

wenn das skript noch nicht installiert ist, bietet die CLI dieselbe aktion:

```sh
sudo /usr/local/sbin/umzug-setup recover-network --confirm-recovery
```

vorschau ohne änderung:

```sh
/usr/local/sbin/umzug-setup recover-network --confirm-recovery --dry-run
```

die recovery deaktiviert toolkit-systemd-units und OpenRC-hooks auch für den
nächsten boot, ist aber kein vollständiger konfigurationsrollback. die
`.disabled-by-recovery`-hooks (bei wiederholter wiederherstellung mit einem
zusätzlichen numerischen suffix) und gesicherten unitdateien bleiben bis zur
bewussten bereinigung erhalten. außerdem verwaltet die offizielle mullvad-app
eigene nftables-regeln. ist deren lockdown aktiv,
kann nach entfernung der umzug-tabellen weiterhin absichtlich kein internet
verfügbar sein. nur wenn klarer internetzugriff für recovery wirklich gewollt
ist, als root über die lokal eingeschränkte mullvad-CLI lockdown abschalten und
bewusst trennen:

```sh
mullvad lockdown-mode set off
mullvad disconnect
```

`vpn-finalize` führt selbst einen kontrollierten disconnect- und reconnect-test
aus. es verlangt in der effektiven mullvad-OUTPUT-basiskette policy `drop`,
weist indirekte/userspace-kontrollierte verdictpfade ab und versucht je
gebundenem ethernet-interface direkten literal-IP-egress über rohe
`SO_BINDTODEVICE`-sockets für TCP/80, TCP/443 und UDP/53. TCP-erfolg,
refusal/reset oder jedes empfangene UDP-datagramm ist ein leak. nur definierte
policy-/down-/unreachable-/timeout-fehler gelten als blockiert; unbekannte
fehler brechen fail-closed ab. schlägt eine probe, reconnect oder nachfolgende
evidenzprüfung
fehl, installiert und verifiziert der fehlerpfad zuerst
`inet umzug_vpn_bootstrap_guard` mit ausschließlich loopback-egress. danach
reaktiviert er `umzug-offline-guard.service` per `enable --now` rebootfest
und verlangt enabled, active sowie die exakte offline-regel; zuletzt prüft er
den bootstrap-guard erneut. ein dann vollständig blockiertes netz ist
erwartetes fail-closed-verhalten und bildet eine bewiesene grenze für einen
fortsetzungslauf. scheitert diese notfall-reaktivierung selbst, protokolliert
der finalizer dies, darf aber keine geschlossene netzgrenze behaupten: an der
lokalen konsole sofort aktive regeln sichern und emergency-recovery ausführen.
das auditfeld
`finite_fail_closed_disconnect_checks_passed=true` darf nur nach dem
vollständigen endlichen ablauf erscheinen und ist kein allgemeiner
leak-freiheitsbeweis. vor jeder recovery zuerst lokal `nft -a list ruleset`
sichern; der obige recovery-befehl entfernt den bootstrap- und offline-guard
bewusst zusammen mit den übrigen toolkit-tabellen.

danach das eigentliche konfigurations-rollback durchführen. die
mullvad-kontonummer dabei niemals auf die kommandozeile setzen.

## Boot landet absichtlich in `emergency.target`

auf systemd verwenden `umzug-offline-guard.service` und
`umzug-firewall.service` `RequiredBy=`/`Before=` für frühe basic-/network-/VPN-
ziele sowie `OnFailure=emergency.target` und `OnFailureJobMode=isolate`.
fehlendes `nft`, beschädigte regeln oder ein nicht unterstützter regelsatz
führen deshalb bewusst in die lokale emergency-konsole, statt mit offenem netz
weiterzubooten.

an der physischen/virtuellen konsole anmelden und zuerst evidenz sichern:

```sh
systemctl --failed
journalctl -b -u umzug-offline-guard.service -u umzug-firewall.service
nft -a list ruleset
```

wenn der normale boot zur diagnose bewusst ohne toolkit-netzschutz fortgesetzt
werden soll:

```sh
/usr/local/sbin/umzug-network-recovery
systemctl default
```

falls `systemctl default` nicht sauber fortsetzt, lokal neu starten. der
recovery-befehl entfernt die `RequiredBy`-enablement-links durch deaktivierung
der units und öffnet normalen egress bewusst, startet aber keinen SSH-server.
danach regeln/unitdateien gegen plan und backups prüfen und erst nach
ursachenbehebung erneut anwenden. OpenRC besitzt keine gleichwertige
emergency-isolation.

## Toolkit-rollback

zuerst anzeigen, was zurückgespielt würde:

```sh
sudo /usr/local/sbin/umzug-setup rollback \
  --state-dir /var/lib/umzug \
  --confirm-rollback \
  --dry-run
```

dann an der lokalen konsole ausführen:

```sh
sudo /usr/local/sbin/umzug-setup rollback \
  --state-dir /var/lib/umzug \
  --confirm-rollback
```

der produktive CLI-rollback erzwingt dieselbe lokale konsolenprüfung. vor dem
ersten rückspielen muss die verifizierte recovery der ausschließlich von
umzug verwalteten units, OpenRC-hooks und nftables-tabellen erfolgreich sein;
sonst beginnt der datei-rollback nicht. danach wird recovery erneut ausgeführt,
damit eine aus dem backup wiederhergestellte umzug-unit oder ein OpenRC-hook
nicht beim nächsten boot unbemerkt aktiv wird. fremde firewalltabellen werden
dabei weder geleert noch gelöscht.

der executor sichert jeden in einer action deklarierten `backup_paths`-eintrag
vor der ersten änderung unter `STATE/backups/<sha256-des-pfads>` und speichert
existenz und backup-pfad in `STATE/state.json`. rollback arbeitet diese einträge
rückwärts ab und entfernt protokollierte, neu erzeugte dateien beziehungsweise
leere verzeichnisse. reguläre backup-dateien und verzeichnisse werden vor dem
erfolgsreceipt rekursiv `fsync`-synchronisiert; schlägt dies fehl oder ändert
sich der backup-hash dabei, wird kein erfolgsreceipt geschrieben.

grenzen des rollbacks:

- diese dateibasierten aktionsbackups sind **kein** vollwertiges, externes
  blockgeräte-/dateisystem-snapshot-backup. sie versprechen insbesondere keine
  vollständige wiederherstellung aller eigentümer, acls, xattrs, capabilities,
  hardlinks, bootsektoren, partitionen oder nicht deklarierten dateien. vor dem
  hardwaretest bleibt ein getrennt gelagerter und getesteter vollbackup pflicht.
- paketinstallationen/-upgrades werden nicht deinstalliert.
- servicezustände und maskierungen werden derzeit nicht als eigener vorzustand
  gesichert. `ssh.service`/`sshd.service` bleiben nach datei-rollback gegebenenfalls
  maskiert. nur wenn eingehendes SSH bewusst über ein separates, späteres profil
  gewollt ist, lokal `systemctl unmask`/`enable` verwenden.
- die angelegte `mullvad-management`-gruppe wird nicht automatisch entfernt.
- live-sysctl-werte ändern sich durch rückspielen der datei nicht sofort.
- externe befehle können weiteren zustand verändert haben, der nicht in
  `backup_paths` lag.
- ein unterbrochenes rollback ist nicht atomar; danach state und dateisystem
  manuell vergleichen.

nach einem erfolgreichen rollback mindestens:

```sh
sudo sysctl --system
sudo systemctl daemon-reload
```

anschließend firewall, listener, routing, DNS und dienstzustand lokal prüfen.

## Abgebrochener restore oder metadatenabgleich

`restore` prüft und staged zuerst die bereits freigegebenen, weiterhin inerten
bytes und veröffentlicht sie atomar in einem neuen ziel. schlägt `/proc`-,
elternpfad- oder `RENAME_NOREPLACE`-prüfung vorher fehl, darf kein ziel
veröffentlicht werden. nach erfolgreicher veröffentlichung wendet es den
root-pflichtigen sicheren
metadatenabgleich an. das ist kein atomarer dateisystem-commit. bei einem fehler
können zielbaum, content-receipt und teilweise angewandte konservative modi/
eigentümer vorhanden sein, während der erfolgs-metadaten-receipt fehlt.

in diesem fall:

1. ziel nicht öffnen, ausführen, bauen oder in bestehende konfigurationen
   mischen.
2. auditlog, content-receipt, `state/ingest.json`, SOURCE-/ingest-
   QUARANTINE-/promotion-QUARANTINE-/SANITIZED-reports,
   `state/CANDIDATE.provenance.json`,
   `state/promotions/CANDIDATE.json`, approval und den zielbaum auf
   geschütztem storage sichern.
3. ursache prüfen, insbesondere geschütztes workspace-state, manifestbindung,
   zielmanipulation, linux-`/proc`, libc-/kernel-/dateisystemunterstützung für
   `renameat2(RENAME_NOREPLACE)`, symlinkfreie ziel-elternpfade und lokale
   accountdatenbank.
4. den fehlgeschlagenen zielbaum nur in der isolierten umgebung bewusst
   entfernen oder verwerfen; das toolkit überschreibt ihn und vorhandene
   receipts nicht.
5. für einen erneuten versuch einen frischen verifizierten workspace und einen
   neuen zielpfad verwenden. alte oder unvollständige provenienz-, promotion-
   oder approval-records nicht ergänzen: die vollständige pipeline ab ingest
   erneut durchlaufen. keine receipts editieren, um sperren zu umgehen.

## Neustart und fortsetzung

wenn eine action `reboot_reason` setzt, speichert der executor action, grund,
fortsetzungsbefehl und aktuelle linux-boot-ID und beendet den plan an diesem
checkpoint. vor dem neustart `STATE/state.json` und `STATE/plan.json` auf
verschlüsseltem lokalen storage prüfen.

nach dem neustart:

```sh
sudo /usr/local/sbin/umzug-setup resume --state-dir /var/lib/umzug
```

`resume` re-verifiziert zunächst sämtliche bereits abgeschlossenen
`write_file`-actions gegen exakte planbytes und modi sowie jede abgeschlossene
action mit typisiertem verifier gegen den effektiven zustand, insbesondere
offline-guard und host-firewall. drift bricht ab, bevor der reboot akzeptiert
oder eine folgeaktion ausgeführt wird. danach verweigert `resume` die
fortsetzung, wenn die boot-ID unverändert ist, und prüft die an die
reboot-action gebundene postcondition. je nach action ist das ein erlaubter
lokaler befehl samt erwarteter ausgabe, die
abwesenheit gesperrter module in `/proc/modules` oder eine exakte
`POST-REBOOT-VERIFIED:ACTION-ID`-attestierung am lokalen TTY. erst danach wird
der pending-checkpoint gelöscht; bereits abgeschlossene actions bleiben
übersprungen und folgende actions fragen ihre bestätigungen erneut ab. eine
neue boot-ID und auch eine manuelle attestierung beweisen allein nicht die
wirksamkeit jeder änderung. netzwerkgeräte, firewall, DNS, listener und
boot-logs zusätzlich prüfen.

wichtig: nach einer modprobe-blacklist plant der MVP auf debian/ubuntu
`update-initramfs -u -k all`, auf arch `mkinitcpio -P` und auf
fedora/RHEL-artigen systemen `dracut --regenerate-all --force`. diese aktion ist
kritisch, bestätigungspflichtig und setzt den neustart-checkpoint. auf NixOS,
gentoo, LFS und unbekannten distributionen wird kein befehl geraten, sondern ein
kritischer manueller initramfs-checkpoint erzeugt. ohne erfolgreichen neubau
können früh geladene module aktiv bleiben; ein falscher befehl kann das system
unbootbar machen. der manuelle checkpoint verlangt zunächst
`VERIFIED:hardening-initramfs-manual-checkpoint`; nach dem neustart prüft
`resume` zusätzlich automatisch, dass die im plan gesperrten module nicht mehr
geladen sind.

## Kein boot nach modul-/sysctl-änderungen

1. vom vertrauenswürdigen live-medium booten.
2. verschlüsseltes root-dateisystem entsperren und nur für recovery einhängen.
3. `etc/modprobe.d/90-umzug-deny.conf` entfernen oder aus dem state-backup
   zurückspielen.
4. `etc/sysctl.d/90-umzug-hardening.conf` prüfen/zurückspielen.
5. mit den werkzeugen **der ziel-distribution** initramfs neu erzeugen.
6. vor `chroot` oder ausführung von zielbinärdateien sicherstellen, dass das
   zielsystem selbst nicht als untrusted quelle untersucht wird; recovery eines
   kompromittierten ziels erfordert neuinstallation statt chroot.

das toolkit ändert im MVP weder partitionstabelle noch bootloader noch
secure-boot-keys. wenn ein bootproblem dort liegt, gelten die
distributionsspezifischen recovery-verfahren; umzug kann sie nicht automatisiert
rückgängig machen.

## Firewall manuell prüfen

nach recovery beziehungsweise erneutem apply:

```sh
nft -a list ruleset
ip -4 rule show
ip -4 route show table all
ip -6 rule show
ip -6 route show table all
ss -lntup
rfkill list
resolvectl status
mullvad status -v
wg show
```

`resolvectl status` nur ausführen, wenn `resolvectl` bereits vorhanden und
receiptgebunden ist; andernfalls die stabil gelesene statische
`/etc/resolv.conf`-evidenz des berichts verwenden.

`/usr/local/sbin/umzug-setup report --output security-report.json --state-dir /var/lib/umzug`
sammelt diese nachweise best effort. ein einzelner bericht ist nur eine
momentaufnahme. insbesondere muss `ss` keinen listener auf port 22 zeigen und
die nftables-regeln dürfen keine accept-regel für eingehendes SSH enthalten.

## Beschädigter checkpoint

`state.json` und `plan.json` werden atomar geschrieben, können aber durch
storagefehler unlesbar werden. dann keine neue planung über dasselbe
state-verzeichnis anwenden. das verzeichnis unverändert sichern, backups anhand
der pfadschlüssel in `state.json` auswerten und gegen den gespeicherten plan
vergleichen. ohne lesbares mapping ist ein automatisches rollback nicht sicher;
snapshot oder neuinstallation bevorzugen.
