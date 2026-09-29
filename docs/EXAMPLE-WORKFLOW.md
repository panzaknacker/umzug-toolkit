# Beispielablauf: altes system bis gehärtetes debian-ziel

dieses beispiel verwendet ein frisch installiertes debian 13 auf x86-64 in
einer wegwerfbaren VM mit lokaler konsole. es zeigt den tatsächlich
implementierten MVP-pfad. hardware-, hash-, fingerprint-, finding- und
interfacewerte müssen aus der eigenen umgebung übernommen werden; sie dürfen
niemals ungeprüft aus diesem beispiel kopiert werden.

der ablauf verspricht keine malwarefreiheit. das alte system, sein
migrationspaket, der USB-datenträger und selbst eigene repositories bleiben
untrusted. erst eine explizite, hashgebundene freigabe erzeugt `APPROVED`.

## 1. vertrauensmaterial getrennt vorbereiten

auf einem vertrauenswürdigen online-rechner:

1. debian-installationsabbild, toolkit-release, scanner, bubblewrap, `zstd`,
   YARA-regeln, ClamAV-datenbank, offline-pakete und mullvad-app beziehen.
2. hersteller- und repository-signaturen sowie schlüsselfingerprints über einen
   zweiten kanal prüfen.
3. SHA-256-werte der exakt verwendeten binärdateien und regelstände erfassen.
4. das toolkit-wheel und die analyseartefakte gemäß
   [OFFLINE-BUILD.md](OFFLINE-BUILD.md) bauen.
5. einen `age`-empfängerschlüssel auf einem vom alten system getrennten gerät
   erzeugen. nur der öffentliche empfänger darf zum alten system gelangen.

der private `age`-schlüssel, der erwartete Ed25519-fingerprint und die
vertrauenswürdigen scanner-hashes gehören nicht ausschließlich auf denselben
USB-stick wie das migrationspaket. für mullvad müssen zusätzlich offizielles
DEB, dessen detached signature und der separat verankerte code-signing-key samt
40-stelligem primärem fingerprint vorliegen.

## 2. auf dem alten system nur auswählen und packen

zuerst eine vorschau erstellen:

```sh
umzug-pack \
  --include projects=/home/alice/Projects \
  --include dotfiles=/home/alice/.config \
  --include git=/home/alice/.gitconfig \
  --include scripts=/home/alice/bin \
  --include vendor=/home/alice/offline-vendor/mullvad \
  --exclude '**/.cache/**' \
  --exclude '**/node_modules/**' \
  --dry-run
```

die ausgabe manuell prüfen. private SSH-schlüssel, `.env`, token-dateien,
WireGuard-konfigurationen, buildprodukte und paket-caches nicht durch breite
overrides wieder einschließen. benötigte zugangsdaten auf dem ziel neu
erzeugen.

dann einen neuen, passphrasengeschützten Ed25519-schlüssel außerhalb der
auswahl erzeugen und das paket verschlüsseln:

```sh
umzug-pack \
  --output /mnt/transport/alice-migration.bundle.age \
  --include projects=/home/alice/Projects \
  --include dotfiles=/home/alice/.config \
  --include git=/home/alice/.gitconfig \
  --include scripts=/home/alice/bin \
  --include vendor=/home/alice/offline-vendor/mullvad \
  --exclude '**/.cache/**' \
  --exclude '**/node_modules/**' \
  --generate-signing-key /secure/off-media/alice-migration-ed25519.pem \
  --encrypt age-recipient \
  --recipient 'age1EIGENER_OEFFENTLICHER_EMPFÄNGER' \
  --source-date-epoch 1784073600 \
  --log /secure/off-media/pack-audit.jsonl
```

`/secure/off-media/alice-migration-ed25519.pem.pub` und den ausgegebenen
fingerprint separat sichern. der gebündelte public key ist kein
vertrauensanker. bei einem medium mit dateigrößenlimit zusätzlich beispielsweise
`--split-size 2147483648` verwenden; auf dem ziel wird dann die
`.parts.json`-datei an `ingest` übergeben.

`umzug-pack` verifiziert das erzeugte `SOURCE.tar` vor der signatur selbst. ein
erfolgreicher lauf bestätigt damit snapshot-konsistenz, aber weder harmlosigkeit
noch vertrauenswürdigkeit der quelldaten.

das medium sauber aushängen und danach nicht wieder am alten system
beschreibbar verwenden.

der vendor-ordner durchläuft hier absichtlich das möglicherweise kompromittierte
alte system und bleibt untrusted. eine dortige manipulation muss später sowohl
an der unabhängigen hersteller-signatur als auch an der zero-trust-prüfung
scheitern; die alte manifestsignatur allein reicht dafür nicht.

## 3. frisches ziel vollständig offline starten

die debian-VM aus dem unabhängig geprüften installationsabbild installieren:

- virtuelles NIC trennen;
- keine shared folders, zwischenablage oder drag-and-drop-funktion;
- desktop-automount, thumbnailer und indexer deaktivieren;
- einen VM-snapshot vor dem ersten kontakt mit dem quellmedium erstellen;
- toolkit, scanner und regeln nur aus dem getrennt geprüften bootstrap
  installieren.

wheel und pip-freien installer unabhängig hashprüfen, root-eigen stagen und in
die dedizierte produktive runtime installieren; der quellbaum-launcher darf
niemals mit root laufen:

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
```

`/pfad/zum/...` und der hash sind durch die unabhängig geprüften realen werte
zu ersetzen. der standardbibliothek-installer validiert ZIP, metadaten und
`RECORD`, erzeugt die venv ohne ensurepip und überschreibt nie eine vorhandene
runtime. das wheel hat
keinen normalen setup-entry-point; der kopierte root-wrapper startet mit leerer,
fest neu aufgebauter umgebung
`/opt/umzug/runtime/bin/python -I -B -m umzug.setup_cli`. das bytecode-verbot
hält die runtime auch nach root-aufrufen unverändert traversierbar. `sudo ./setup`,
ein user-writable `PYTHONPATH` oder eine benutzerkontrollierte venv sind für
keinen produktiven root-schritt zulässig.

das quellmedium inert einbinden:

```sh
sudo /usr/local/sbin/umzug-setup mount-source \
  /dev/disk/by-id/usb-TRANSPORT-part1 \
  /mnt/umzug-source \
  --confirm
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /mnt/umzug-source
```

die ausgabe muss `ro,noexec,nodev,nosuid` enthalten. `noexec` verhindert
nicht, dass ein interpreter gelesene daten ausführt; deshalb nichts auf dem
medium öffnen oder starten.

## 4. signatur prüfen und in quarantäne importieren

die produktive `scanner.toml` enthält die unabhängig geprüften, realen hashes
aus [OFFLINE-BUILD.md](OFFLINE-BUILD.md). dann:

```sh
umzug-setup --log /var/tmp/umzug-ingest.jsonl ingest \
  /mnt/umzug-source/alice-migration.bundle.age \
  --workspace /var/tmp/umzug-work \
  --decrypt age \
  --age-identity /secure/off-media/alice-migration-age-identity.txt \
  --trusted-key /secure/off-media/alice-migration-ed25519.pem.pub \
  --scanner-config /opt/umzug-analysis/scanner.toml
```

alternativ kann statt `--trusted-key` der separat notierte
`--fingerprint` verwendet werden. niemals nur dem public key im paket
vertrauen.
die identity muss eine reguläre nicht-symlink-datei mit modus 0600 oder
strenger sein. entschlüsselung und extraktion sind durch
`--max-payload-bytes` begrenzt; vorhandene workspace-/ausgabepfade werden nicht
überschrieben.

kandidaten und ursprüngliche auswahlzuordnung ansehen:

```sh
jq '.candidates[] | {id, category, original_path, quarantine_blockers}' \
  /var/tmp/umzug-work/state/ingest.json
```

ingest prüft paket, signatur, manifest, payload und sichere extraktion. es
schreibt je kandidat SOURCE- und ingest-QUARANTINE-report sowie den
selbstgehashten beleg `state/item-NNNN.provenance.json`. dieser bindet beide
scan-ids/-reporthashes, SOURCE-, SOURCE-snapshot- und QUARANTINE-manifest. es
erzeugt trotzdem keine vertrauensfreigabe.

## 5. jeden kandidaten einzeln untersuchen

beispiel für `item-0000`:

```sh
umzug-setup scan \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --stage QUARANTINE \
  --scanner-config /opt/umzug-analysis/scanner.toml \
  --report /var/tmp/item-0000.quarantine.json
```

manifest-hash, blocker und reviews separat ausgeben:

```sh
jq -r '.manifest_sha256' /var/tmp/item-0000.quarantine.json
jq -r '.findings[] | [.severity, .id, .rule, .path] | @tsv' \
  /var/tmp/item-0000.quarantine.json
```

regeln für die entscheidung:

- ein `blocker` kann nicht quittiert werden.
- verschlüsselte, beschädigte oder nur teilweise analysierte inhalte bleiben in
  quarantäne.
- review-ids niemals pauschal aus dem report übernehmen. jede ID und ihre
  evidenz einzeln begründen.
- projektcode nicht bauen, testen, importieren oder in einer IDE öffnen.
- wenn passive rekonstruktion nötig ist, nur in einer weiteren wegwerfbaren,
  netzlosen umgebung arbeiten, die bereinigten bytes nach `QUARANTINE`
  zurückführen und einen vollständig neuen scan erstellen.

sind keine blocker vorhanden und alle review-funde einzeln akzeptiert, den
angezeigten quarantäne-hash und jede tatsächlich geprüfte review-ID explizit
übergeben:

```sh
umzug-setup promote \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --expected-manifest 'QUARANTAENE-MANIFEST-SHA256' \
  --accept-finding 'EINZELN-GEPRUEFTE-REVIEW-ID' \
  --scanner-config /opt/umzug-analysis/scanner.toml
```

ohne reviews wird `--accept-finding` weggelassen; bei mehreren wird die
option wiederholt. promotion verlangt exakt alle und nur die review-ids des
strikten, blockerfreien QUARANTINE-reports, prüft den SOURCE-snapshot und die
ingest-bindung erneut und persistiert diesen promotion-report. dann kopiert sie
nach `SANITIZED`, scannt erneut und schreibt den selbstgehashten beleg
`state/promotions/item-0000.json`. dieser bindet provenienz, SOURCE-snapshot,
QUARANTINE- und SANITIZED-scan/-report/-manifest sowie die exakten
promotion-akzeptanzen. danach einen eigenen SANITIZED-report schreiben und
vollständig prüfen:

```sh
umzug-setup scan \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --stage SANITIZED \
  --scanner-config /opt/umzug-analysis/scanner.toml \
  --report /var/tmp/item-0000.sanitized.json
```

erst dann genehmigen:

```sh
umzug-setup approve \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --expected-manifest 'SANITIZED-MANIFEST-SHA256' \
  --actor 'alice' \
  --reason 'Offline geprüft; dokumentierte Reviews einzeln bewertet' \
  --accept-finding 'EINZELN-GEPRUEFTE-SANITIZED-REVIEW-ID' \
  --confirm-approval item-0000 \
  --scanner-config /opt/umzug-analysis/scanner.toml
```

die JSON-ausgabe bindet den exakten strikten scan über `report_sha256` und
enthält `approval_sha256`. der approval-record bindet außerdem
`ingest_provenance_sha256`, `promotion_sha256`, SOURCE-, SOURCE-snapshot-,
QUARANTINE- und SANITIZED-manifeste, promotion-QUARANTINE-scan-ID/-reporthash
und exakt akzeptierte promotion-funde. den 64-stelligen approval-wert jetzt
auf einem vom workspace und transportmedium unabhängigen, geschützten kanal
festhalten. ihn beim restore nicht aus `state/approvals/item-0000.json`
zurücklesen, denn diese kopie gehört zur erneut zu prüfenden eingabekette.
die verkettung belegt integrität und ableitung, nicht malwarefreiheit.

für jedes weitere `item-NNNN` wird der gesamte ablauf wiederholt.

## 6. freigegebene daten ohne überschreiben wiederherstellen

ein projekt zunächst in einen neuen review-pfad kopieren:

```sh
umzug-setup project-report \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --output /var/tmp/item-0000.project-report.json

sudo /usr/local/sbin/umzug-setup restore \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --destination /var/lib/umzug/restored-staging/item-0000 \
  --confirm-restore item-0000 \
  --trusted-key /secure/off-media/alice-migration-ed25519.pem.pub \
  --fingerprint 'SEPARAT-NOTIERTER-64-HEX-SCHLUESSELFINGERPRINT' \
  --expected-approval-sha256 'SEPARAT-NOTIERTER-64-HEX-APPROVAL-SHA256' \
  --scanner-config /opt/umzug-analysis/scanner.toml
```

die 64-HEX-werte sind metavariablen und müssen durch die zuvor unabhängig
notierten realen werte ersetzt werden. das ziel muss fehlen. der root-restore
prüft zuerst das ursprüngliche bundle, signatur und komplettes `SOURCE.tar`
neu. dann snapshottet er SOURCE-, ingest-QUARANTINE-, promotion-QUARANTINE-
und SANITIZED-report, provenienz- und promotion-beleg, approval sowie
APPROVED fd-verankert und linkfrei. er verlangt aktuelle vollständige schemas,
beide QUARANTINE-reports strikt und blockerfrei, gleiche policy-/toolbindung,
exakte promotion-review-ids und die komplette hash-/manifestkette. alte oder
unvollständige belege werden fail-closed abgewiesen. erst nach diesen prüfungen
kopiert er fd-verankert und
veröffentlicht das neue ziel ausschließlich per
`renameat2(RENAME_NOREPLACE)`. dafür benötigt er linux-`/proc`; symlink-eltern
und plattformen ohne atomare no-replace-unterstützung werden abgewiesen. danach
ordnet er eigentümer nur über exakt gleiche eindeutige quell-/zielnamen zu und
verwendet nie rohe UID/GID-werte. nicht zuordenbare namen bleiben beim
restore-operator und werden im metadaten-receipt berichtet. reguläre dateien
erhalten nur signierte rw-bits; execute-/SUID-/SGID-/sticky-bits, acls, xattrs
und capabilities bleiben entfernt. bestehende konfigurationen per diff manuell
zusammenführen. `restore` akzeptiert absichtlich nur
`/var/lib/umzug/restored-staging/CANDIDATE`; erst den inerten staging-baum
reviewen und danach bewusst manuell in home-/systemziele übernehmen.

ein genehmigtes repository bleibt untrusted code. es erst in einer neuen,
netzlosen build-VM mit deaktivierten hooks und einem separat geprüften
offline-abhängigkeitsstore bauen.

angenommen, die kandidatenzuordnung weist `item-0004` als vendor-ordner aus
und paket sowie detached signature wurden beide vollständig bis `APPROVED`
freigegeben. dann die hersteller-signatur zusätzlich prüfen:

```sh
umzug-setup verify-vendor \
  --workspace /var/tmp/umzug-work \
  --candidate item-0004 \
  --artifact 'MullvadVPN-RELEASE_amd64.deb' \
  --artifact-sha256 '64-HEX-SHA256-DES-OFFIZIELLEN-RELEASES' \
  --signature 'MullvadVPN-RELEASE_amd64.deb.asc' \
  --signing-key /secure/off-media/mullvad-code-signing-key.asc \
  --fingerprint '40-HEX-ZEICHEN-AUS-UNABHAENGIGEM-KANAL' \
  --gpg-sha256 '64-HEX-SHA256-DER-VERIFIZIERTEN-GPG-BINAERDATEI' \
  --gpgv-sha256 '64-HEX-SHA256-DER-VERIFIZIERTEN-GPGV-BINAERDATEI' \
  --bwrap-sha256 '64-HEX-SHA256-DER-VERIFIZIERTEN-BWRAP-BINAERDATEI' \
  --receipt /var/tmp/umzug-work/state/vendor/mullvad.json
```

der receipt ist an pfad, größe und hash des unveränderten `APPROVED`-
artefakts gebunden. GnuPG läuft dabei netzlos in der gepinnten
bubblewrap-sandbox. der receipt ist ein herkunftsnachweis relativ zum
gepinnten herstellerschlüssel, keine malwarefreiheitsgarantie; die planung
führt diesen nachweis mit unabhängig erneut angegebenen ankern noch einmal aus.
der wert für `--artifact-sha256` beziehungsweise später
`--mullvad-artifact-sha256` muss aus demselben unabhängig authentifizierten
releasekanal stammen und darf nicht aus dem untrusted workspace abgeleitet
werden.

## 7. ziel erkennen und hardening-plan prüfen

```sh
umzug-setup detect --json

umzug-setup plan \
  --profile strict \
  --output /var/tmp/debian13-strict-plan.json \
  --ethernet enp1s0 \
  --workspace /var/tmp/umzug-work \
  --mullvad-artifact \
    /var/tmp/umzug-work/APPROVED/item-0004/MullvadVPN-RELEASE_amd64.deb \
  --mullvad-vendor-receipt \
    /var/tmp/umzug-work/state/vendor/mullvad.json \
  --mullvad-artifact-sha256 \
    '64-HEX-SHA256-DES-OFFIZIELLEN-RELEASES' \
  --mullvad-package-version \
    'AUTHENTIFIZIERTE-PAKETVERSION' \
  --mullvad-package-architecture \
    'AUTHENTIFIZIERTE-PAKETARCHITEKTUR' \
  --mullvad-fingerprint \
    '40-HEX-ZEICHEN-AUS-UNABHAENGIGEM-KANAL' \
  --mullvad-gpg-sha256 \
    '64-HEX-SHA256-DER-VERIFIZIERTEN-GPG-BINAERDATEI' \
  --mullvad-gpgv-sha256 \
    '64-HEX-SHA256-DER-VERIFIZIERTEN-GPGV-BINAERDATEI' \
  --mullvad-bwrap-sha256 \
    '64-HEX-SHA256-DER-VERIFIZIERTEN-BWRAP-BINAERDATEI' \
  --capability firewall \
  --capability wireguard \
  --capability audit \
  --capability integrity-checker \
  --capability ssh-client
```

`debian13-strict-plan.json` und
`debian13-strict-plan.json.report.json` vollständig lesen. insbesondere
distribution, architektur, ethernet-interface, paketauflösung, funkmodule,
mullvad-supportstatus, erneut verifizierten vendor-receipt, diffs, destruktive
aktionen und neustartgründe prüfen. `mullvad-offline-install` muss das erwartete
`.deb` über `apt-get install --yes --reinstall --no-download
--no-install-recommends -- ARTEFAKT` im netzlosen namespace installieren.
version und architektur müssen den unabhängig aus authentifizierten DEB/APT-
metadaten notierten werten entsprechen. der vendor-nachweis bindet keine
transitive APT-closure. vor der vendor-action müssen
`mullvad-management-group` und `mullvad-management-socket` liegen. dieselbe
`mullvad-offline-install`-action bindet den neuen client, führt receiptgebunden
`systemctl daemon-reload` und `restart mullvad-daemon.service` aus und wird
erst nach paketintegritäts- und live-gruppe/environment/umask/UDS-prüfung
abgeschlossen. ein reload vor dem paket ist bewusst nicht vorgesehen.
das beispiel setzt ein frisches ziel ohne bereits geladenen mullvad-daemon
voraus. bei einer vorinstallation könnte bis zum receiptgebundenen neustart
noch die alte unit-umgebung gelten; diesen fall vorher an der lokalen konsole
stoppen und separat prüfen.

der gespeicherte plan bleibt untrusted eingabe. beim dry-run und apply prüft die
typisierte action-registry jede ID gegen exakte operation, felder,
ziel/gerenderte bytes oder `argv`, risiko, bestätigung, backup, verifier und
reihenfolge. ein planhash bindet nur einen semantisch zulässigen plan; er kann
keine manipulierte freie datei-, service- oder command-action autorisieren.

dry-run:

```sh
umzug-setup apply /var/tmp/debian13-strict-plan.json \
  --dry-run \
  --state-dir /var/tmp/umzug-dry-run
```

der dry-run markiert nichts als produktiv abgeschlossen. vor dem echten apply
snapshot, live-medium, lokale root-anmeldung und den geplanten
`network-recovery-command` prüfen.
der planbericht muss den strikten egress-kill-switch bis zum späteren
`vpn-finalize` ausdrücklich als offen ausweisen.

## 8. offline anwenden, rebooten und fortsetzen

nur an der lokalen VM-konsole:

```sh
sudo /usr/local/sbin/umzug-setup --log /var/log/umzug-audit.jsonl apply \
  /var/tmp/debian13-strict-plan.json \
  --expected-plan-sha256 '<SHA256-AUS-DER-PLAN-AUSGABE>' \
  --state-dir /var/lib/umzug
```

der angegebene digest muss exakt dem zuvor separat geprüften plan entsprechen;
`--expected-plan-sha256` ist auch am interaktiven TTY pflicht; ohne option
bricht produktives apply vor jeder änderung ab. jeden diff lesen. bei
kritischen/destruktiven aktionen exakt die angezeigte
action-ID eingeben. niemals eine entfernte SSH-sitzung als einzige konsole
verwenden.

auf diesem systemd-ziel sind `umzug-offline-guard.service` und
`umzug-firewall.service` harte abhängigkeiten der frühen basic-/network-/VPN-
ziele. scheitert ihr nftables-load beim boot, isoliert systemd absichtlich nach
`emergency.target`. vor dem neustart daher unbedingt lokale root-anmeldung und
`/usr/local/sbin/umzug-network-recovery` testen.

debian baut nach der modprobe-policy mit `update-initramfs -u -k all` neu und
setzt einen reboot-checkpoint. unmittelbar vor dessen speicherung
re-verifiziert der executor den gesamten abgeschlossenen action-prefix samt
effektiver guards; paket- oder initramfs-hook-drift stoppt hier. nach dem
erklärten neustart:

```sh
sudo /usr/local/sbin/umzug-setup resume --state-dir /var/lib/umzug
```

`resume` re-verifiziert zuerst jede abgeschlossene verwaltete datei und jedes
abgeschlossene effektive control, insbesondere offline-guard und host-firewall.
erst ohne drift akzeptiert es die neue boot-ID und führt die plan-gebundene
post-reboot-prüfung aus. für die modulpolicy müssen die gesperrten module aus
`/proc/modules` verschwunden sein; eine erforderliche manuelle konsolenprüfung
ist exakt mit `POST-REBOOT-VERIFIED:ACTION-ID` zu attestieren. bei fehlschlag
bleibt der checkpoint offen und keine folgeaktion läuft.

auf NixOS ersetzt keine generische manuelle phrase den generationsnachweis:
`nixos-rebuild dry-build`, `test` und `boot` binden den am lokalen TTY
eingegebenen exakten getesteten `/nix/store/...-system`-pfad. nach dem reboot
muss `/run/current-system` genau darauf zeigen und von der vorherigen generation
abweichen.

nach jeder etappe lokal prüfen:

```sh
systemctl is-enabled ssh.service sshd.service
ss -lntup
rfkill list
nft -a list ruleset
ip -4 route show table all
ip -6 route show table all
# falls receiptgebunden vorhanden: resolvectl status
```

es darf keine eingehende SSH-accept-regel und keinen unerwarteten listener auf
port 22 geben. bei netzwerkfehlern an der konsole:

```sh
sudo /usr/local/sbin/umzug-network-recovery
```

danach ursache untersuchen und den dokumentierten rollback aus
[RECOVERY.md](RECOVERY.md) verwenden.

## 9. mullvad wirklich als letzten schritt finalisieren

dieser pfad gilt nur, wenn die offizielle app für das erkannte release und die
architektur unterstützt wird. mit stand 2026-07-15 akzeptiert das toolkit
debian 12/13, ubuntu 24.04/25.10/26.04 und fedora 43/44 auf x86-64/ARM64.
upstream-matrix und paketsignatur vor verwendung neu prüfen.

das offizielle paket muss aus einer getrennt verifizierten lieferkette stammen,
offline untersucht, ausdrücklich freigegeben, per `verify-vendor` gebunden und
durch die bestätigte `mullvad-offline-install`-planaktion installiert worden
sein. native paketcontainer und maintainer-skripte erfordern zusätzlich die
distributionsnative hersteller-/repository-signaturprüfung; statische
inhaltsanalyse und receipt ersetzen diese nicht.

der angewendete plan muss außerdem die leere `mullvad-management`-gruppe und
den systemd-override installiert haben. die erkennung muss die tatsächliche
mount-abdeckung von `/etc/mullvad-vpn` eindeutig als verschlüsselt melden; bei
`unknown`, `false` oder einem separaten, nicht separat beweisbaren `/etc`-,
`/etc/mullvad-vpn`- oder exakten datei-mount auf `account-history.json`
beziehungsweise `device.json` verweigert das toolkit die kontoeingabe
ausnahmslos.
lokal zusätzlich prüfen:

```sh
findmnt -T /etc
findmnt -T /etc/mullvad-vpn
```

der finalizer akzeptiert als anfangsgrenze nur den exakt geprüften offline-
guard, bootstrap-guard oder bereits mullvad-lockdown zusammen mit strukturell
geprüfter mullvad-nftables-policy; die host-firewall prüft er separat. vor
jedem daemon-restart installiert und verifiziert er den bootstrap-guard erneut.
das offline-guard-retirement darunter ist auch bei bereits fehlender tabelle
idempotent. das generierte drop-in muss über eine geschützte root-owned,
linkfreie elternkette als reguläre single-link-datei mit UID 0 und modus 0644
oder strenger exakt vorliegen: leeres `Environment=`, dann nur
managementgruppe und `UMask=0077`. erst danach startet der finalizer den
daemon neu und prüft nicht nur unit-metadaten, sondern dessen reale, linkfrei
gelesene
`/proc/<MainPID>/environ`. die `MainPID` muss stabil und root-owned sein, die
erwartete managementgruppe exakt gelten. zusätzliche mullvad-/talpid-,
loader-, proxy-, CA- oder shell-start-overrides brechen fail-closed ab. solche
werte niemals zur diagnose in ein geteiltes log kopieren; unit-drop-ins und
daemon-herkunft ausschließlich lokal als root prüfen.

plan, dry-run/apply, `resume` und `vpn-finalize` führen den kryptografischen
vendor-intent-nachweis vor nutzung erneut aus. ein unverändert aussehendes
receipt-JSON allein genügt nicht.

außerdem muss `/proc` distributionsgerecht
als procfs mit `hidepid=2` oder `hidepid=invisible` und ohne `gid=`-ausnahme
gemountet sein. globale core-dumps müssen vollständig abgeschaltet sein und
kein swap darf aktiv sein; auch verschlüsselter swap und zram werden
konservativ abgewiesen. `strict` und `maximal` rendern die core-dump-werte
`fs.suid_dumpable=0`, ein leeres `kernel.core_pattern` und
`kernel.core_uses_pid=0`; nicht-NixOS-pläne laden sie bestätigt, während NixOS
das modul erst nach manuellem import und test aktiviert. die effektive prüfung
bleibt trotzdem pflicht. FDE, procfs und swap konfiguriert das toolkit nicht.
vorher lokal prüfen:

```sh
findmnt -no TARGET,FSTYPE,OPTIONS /proc
sysctl -n kernel.core_pattern
sysctl -n kernel.core_uses_pid
cat /proc/swaps
```

die erste `sysctl`-ausgabe muss exakt leer, die zweite `0` und `/proc/swaps`
muss auf seine kopfzeile beschränkt sein. ein `core_pattern`-pipehandler wie
`systemd-coredump` ist nicht zulässig: `RLIMIT_CORE=0` verhindert solche pipes
nicht zuverlässig. falls eine änderung erforderlich ist, ausschließlich an der
lokalen konsole und mit den betriebswarnungen aus
[RECOVERY.md](RECOVERY.md) vorgehen; insbesondere kann `swapoff -a` bei
speicherdruck prozesse beenden oder das system festfahren und hibernation
brechen.

erst dann das virtuelle ethernet verbinden und als root am lokalen TTY
ausführen:

```sh
sudo /usr/local/sbin/umzug-setup \
  --log /var/log/umzug-audit.jsonl \
  vpn-finalize \
  --state-dir /var/lib/umzug \
  --expected-plan-sha256 '<SHA256-DES-VOLLSTAENDIG-ABGESCHLOSSENEN-PLANS>'
```

die kontonummer wird jetzt erstmals verdeckt abgefragt. sie erscheint nicht in
toolkit-log, config oder shell-history, wird von der offiziellen CLI technisch
aber kurzzeitig in argv verarbeitet. die vorab geprüfte `hidepid`-policy sperrt
die normale lokale procfs-sicht darauf; root, kernel und privilegierte
beobachter bleiben außerhalb der schutzgrenze. vor prompt und CLI-start werden
procfs-, core-dump- und swap-gates erneut geprüft; finalizer und CLI-kind setzen
`RLIMIT_CORE` soft/hard auf `0` und `PR_SET_DUMPABLE=0`. das reduziert
exposition, garantiert aber weder speicherlöschung noch schutz gegen
privilegierte. mullvads root-only `account-history.json` enthält die
kontonummer im klartext; `device.json` enthält kontobezogenen gerätezustand und
privates WireGuard-schlüsselmaterial. vor dem prompt werden vorhandene dateien,
nach dem login beide zwingend vorhandenen dateien per `O_NOFOLLOW` auf regulären
typ, root-eigentum, `nlink=1`, höchstens 1 MiB und modus 0600 oder strenger
geprüft. auch die elternkette muss root-owned und für gruppe/welt nicht
beschreibbar sein. FDE wird vom toolkit nur erkannt, nicht eingerichtet; ohne
mountgenauen positiven nachweis muss das ziel außerhalb dieses ablaufs
verschlüsselt oder neu installiert werden.

`vpn-finalize` leert split-tunneling, blockiert LAN, aktiviert auto-connect
und lockdown, verbindet und prüft online den mullvad-status. danach trennt es
kontrolliert, prüft den blocking-/lockdown-zustand und die effektive mullvad-
nftables-tabelle. deren OUTPUT-basiskette muss policy `drop` besitzen;
indirekte oder userspace-kontrollierte verdictpfade werden abgewiesen. über
jedes plan-gebundene ethernet-interface folgen mit `SO_BINDTODEVICE`
gebundene rohe TCP-connects zu `1.1.1.1:80` und `:443` sowie eine UDP/53-
probe. TCP-erfolg, `ECONNREFUSED` oder `ECONNRESET` und jedes empfangene
UDP-datagramm sind unabhängig vom DNS-inhalt ein leak. nur definierte policy-/
down-/unreachable-/timeout-fehler gelten als blockiert; andere fehler brechen
als unbestimmt fail-closed ab. anschließend wird reconnect versucht und der
connected-zustand
erneut geprüft. nur dann enthält das audit
`finite_fail_closed_disconnect_checks_passed=true`. bei jedem gefangenen
fehler installiert und verifiziert der finalizer zuerst den loopback-only
bootstrap-guard, reaktiviert dann `umzug-offline-guard.service` per
`enable --now` rebootfest und verlangt dessen enabled-/active-zustand sowie
die exakte offline-regel. scheitert diese notfall-reaktivierung selbst, ist
keine geschlossene grenze bewiesen und lokale emergency-recovery pflicht. die
endlichen proben sind kein beweis für alle denkbaren ziele, protokolle,
namespaces oder root-bypässe.
erst nach diesem erfolgreich verifizierten schritt ist die vorher offen
ausgewiesene
strikte kill-switch-anforderung erfüllt. OpenVPN wird nicht angeboten.

## 10. abschlussbericht sichern

```sh
sudo /usr/local/sbin/umzug-setup report \
  --output /var/tmp/umzug-security-report.json \
  --state-dir /var/lib/umzug \
  --workspace /var/tmp/umzug-work
```

bericht, plan, planbericht, scanreports, approval-records und auditlogs auf
verschlüsseltem, lokal kontrolliertem storage sichern. der bericht ist eine
momentaufnahme und kein beweis für malwarefreiheit oder zukünftige
regelwirksamkeit.
