# Installations- und benutzerhandbuch

## Sicherheitswarnung

das toolkit reduziert migrationsrisiken, kann aber **keine malwarefreiheit
garantieren**. behandle das alte system, das paket, alle projekte und das
transportmedium als kompromittiert. analysiere nur in einer wegwerfbaren VM
ohne netz und binde das quellmedium ausschließlich mit
`ro,noexec,nodev,nosuid` ein. eine gültige manifestsignatur ersetzt keine
inhaltsanalyse.

hashgebundene werkzeug-snapshots sind keine abwehr gegen einen bereits aktiven
angreifer mit derselben UID oder gegen root, kernel und hypervisor. auch
dynamischer loader und shared libraries der analyse-runtime sind nicht als
vollständiger kryptografischer closure-baum gepinnt. eine frische, netzlose VM
aus unabhängig geprüften basisartefakten ist deshalb teil des betriebsmodells,
nicht nur eine komfortempfehlung.

vor produktiver nutzung [bedrohungsmodell](THREAT-MODEL.md),
[grenzen](LIMITATIONS.md) und [recovery](RECOVERY.md) vollständig lesen.

## Voraussetzungen und installation

- linux und python 3.11 oder neuer;
- OpenSSL mit Ed25519-unterstützung;
- optional `age` oder GnuPG für vollpaketverschlüsselung;
- für freigabefähige strikte scans: verifizierte bubblewrap-, `file`-,
  ClamAV- und YARA-binärdateien sowie gepinnte offline-regeln/-signaturen;
  für zstd-inhalte zusätzlich ein SHA-256-gepinntes `zstd`;
- für das aktuelle hardening-backend: nftables, root-rechte und systemd oder
  der eingeschränkte OpenRC-pfad;
- für mullvad: offizielles paket samt detached signature, separat verankerter
  hersteller-public-key/fingerprint und gepinnte `gpg`-/`gpgv`-/bubblewrap-
  binärdateien.

wheel offline als unprivilegierter build-schritt erzeugen:

```sh
SOURCE_DATE_EPOCH=1767225600 \
  ./scripts/offline-build.sh /tmp/umzug-build-0.2.0rc1-001
sha256sum \
  /tmp/umzug-build-0.2.0rc1-001/umzug_toolkit-0.2.0rc1-py3-none-any.whl \
  /tmp/umzug-build-0.2.0rc1-001/umzug-offline-install.py
```

für einen release immer einen neuen, noch nicht vorhandenen ausgabepfad
verwenden; ein altes `dist/` und ein abgebrochener ausgabebaum sind keine
zulässige artefaktquelle.

ausführliche vertrauenskette und reproduzierbarer zeitstempel:
[OFFLINE-BUILD.md](OFFLINE-BUILD.md).

auf dem ziel wheel und installer gegen unabhängig authentifizierte hashes
prüfen. beide dateien zunächst root-eigen und nicht durch normale benutzer
veränderbar stagen; erst diese kopien ausführen beziehungsweise öffnen:

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

`/pfad/zum/...` und der hash sind metavariablen. der installer verwendet nur
die standardbibliothek, `venv --without-pip` mit kopiertem interpreter und
eine atomare no-replace-publikation. vorher validiert er den äußeren hash,
kanonische ZIP-pfade, typen/modi/quoten, exakte wheel-metadaten sowie jeden
`RECORD`-hash und jede größe. bestehende runtimes oder teilüberschreibungen
werden verweigert; ein fehler räumt den privaten staging-baum auf.

das wheel enthält absichtlich keinen
normalen `umzug-setup`-python-entry-point. sein `umzug-setup-root`-wrapper
startet mit leerer, fest neu aufgebauter umgebung exakt
`/opt/umzug/runtime/bin/python -I -B -m umzug.setup_cli`. `-B` verhindert
bytecode-schreibzugriffe und damit root-private cacheverzeichnisse in der
unveränderlichen, auch unprivilegiert prüfbaren runtime.
die runtime, jedes python-modul und alle
elternpfade müssen root gehören und dürfen nicht gruppen-/weltbeschreibbar
sein; setup prüft dies bei EUID 0. die installierten programme heißen:

```sh
umzug-pack --help
umzug-setup --help
```

ohne installation sind ausschließlich unprivilegierte entwicklungs-/read-only-
aufrufe vorgesehen:

```sh
PYTHONPATH=src python3 -m umzug.pack_cli --help
PYTHONPATH=src python3 -m umzug.setup_cli --help
```

der mitgelieferte `./setup`-launcher verweigert root absichtlich. niemals
`sudo ./setup`, `sudo PYTHONPATH=...` oder eine user-writable venv für
produktives `restore`, `apply`, `resume`, recovery oder `vpn-finalize`
verwenden.

## Teil 1: paket auf dem alten system erstellen

### Auswahl nur als vorschau

ohne `--include` und ohne `--non-interactive` fragt `umzug-pack` erkannte
kandidaten kategorieweise ab. für eine explizite vorschau:

```sh
umzug-pack \
  --include projects=/home/alice/Projects \
  --include dotfiles=/home/alice/.config \
  --include git=/home/alice/.gitconfig \
  --exclude '**/.local/share/Trash/**' \
  --dry-run
```

die vorschau meldet dateien, verzeichnisse, symlinks, byteumfang,
ausgeschlossene/unlesbare pfade und spezialdateien. fehlende oder unlesbare
auswahlen verhindern den echten paketbau. symlinks werden nicht verfolgt.

standardmäßig ausgeschlossen sind unter anderem caches, virtuelle umgebungen,
`node_modules`, buildverzeichnisse und bekannte secret-pfade wie private SSH-/
GnuPG-schlüssel, `.env`, cloud-/kubernetes-credentials, token-/secret-namen und
WireGuard-konfigurationen. die muster sind keine vollständige secret-erkennung;
vorschau manuell prüfen.

`--expert` zeigt in der pack-vorschau vollständige ausschluss- und fundlisten
statt gekürzter zusammenfassungen. es lockert keine sicherheitsprüfung und ist
kein globaler setup-schalter.

### Signiertes, verschlüsseltes paket

die signatur ist verpflichtend. einen neuen passphrasengeschützten Ed25519-
schlüssel außerhalb der auswahl erzeugen und für den transport mit `age`
verschlüsseln:

```sh
umzug-pack \
  --output /mnt/transport/migration.bundle.age \
  --include projects=/home/alice/Projects \
  --include dotfiles=/home/alice/.config \
  --include ssh-client=/home/alice/.ssh/config \
  --generate-signing-key /secure/off-media/migration-ed25519.pem \
  --encrypt age-recipient \
  --recipient 'age1…' \
  --source-date-epoch 1767225600 \
  --log /secure/off-media/pack-audit.jsonl
```

alternativen:

- `--encrypt age-passphrase`: `age` fragt die passphrase am TTY ab;
- `--encrypt gpg-symmetric`: GnuPG/AES-256 fragt interaktiv ab;
- `--encrypt none`: unverschlüsselt, nicht für sensible daten.

der empfänger ist öffentlich und darf in einer konfiguration stehen.
passphrasen und private schlüssel niemals als kommandozeilenargument angeben.
der output wird mode 0600 erzeugt und eine vorhandene datei nie überschrieben.
vor der signatur prüft `umzug-pack` außerdem das erzeugte `SOURCE.tar` selbst
gegen alle erfassten einträge. quelländerungen oder tar-/manifest-abweichungen
brechen den build ohne signiertes ergebnis ab.

nach erfolg zeigt `umzug-pack` SHA-256 und den SHA-256-fingerprint des
öffentlichen Ed25519-schlüssels. fingerprint beziehungsweise public key getrennt
vom transportmedium aufbewahren und am ziel unabhängig prüfen. der im paket
liegende schlüssel ist allein nicht vertrauenswürdig.

### Große pakete teilen

`--split-size BYTES` erzeugt nummerierte `partNNNNN`-dateien und einen
`.parts.json`-index. mindestgröße ist 1 MiB. beispiel für etwa 2 GiB:

```sh
umzug-pack ... --split-size 2147483648
```

`umzug-setup ingest` akzeptiert den index direkt, prüft jeden teil und setzt die
datei lokal zusammen. die manifestsignatur muss danach trotzdem geprüft werden.

### Sensible daten bewusst einschließen

nur wenn unvermeidbar:

```sh
umzug-pack ... \
  --encrypt age-recipient \
  --include-sensitive \
  --acknowledge-sensitive-risk
```

ohne vollpaketverschlüsselung bricht der befehl ab. interaktiv ist zusätzlich
der exakte warnsatz einzugeben. dieser override kann geheimnisse in die
quarantäne bringen und ist kein sicherer credential-migrationsmechanismus.
neue schlüssel und tokens auf dem ziel sind vorzuziehen.

### Nichtinteraktive pack-konfiguration

`pack.toml`:

```toml
[pack]
output = "/mnt/transport/migration.bundle.age"
signing_key = "/secure/off-media/migration-ed25519.pem"
encrypt = "age-recipient"
recipient = "age1…"
source_date_epoch = 1767225600
split_size = 2147483648
include_sensitive = false
exclude = ["**/.local/share/Trash/**"]

[[pack.include]]
category = "projects"
path = "/home/alice/Projects"

[[pack.include]]
category = "dotfiles"
path = "/home/alice/.config"
```

ausführen:

```sh
umzug-pack --config pack.toml --non-interactive
```

CLI-angaben haben für bereits gesetzte skalare vorrang. nichtinteraktives
einbeziehen sensibler daten benötigt sowohl verschlüsselung als auch
`acknowledge_sensitive_risk = true`. unbekannte `[pack]`-felder, falsche typen
und ungültige werte werden abgewiesen; sie werden nicht still ignoriert.

## Teil 2: isolierte zielanalyse vorbereiten

1. wegwerfbare VM aus verifiziertem installationsmedium starten.
2. virtuelles NIC trennen; keine shared folders, clipboard-, drag-and-drop- oder
   USB-autorun-integration aktivieren.
3. desktop-automount, vorschau/thumbnailer und indexer deaktivieren.
4. verifizierte toolkit-, scanner-, regel- und signaturartefakte bereitstellen.
5. quellmedium über die toolkit-CLI inert mounten:

```sh
sudo /usr/local/sbin/umzug-setup mount-source \
  /dev/disk/by-id/usb-TRANSPORT-part1 \
  /mnt/umzug-source \
  --confirm
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /mnt/umzug-source
```

`mount-source` akzeptiert nur ein blockdevice, ein leeres nicht-symlink-ziel und
prüft nach dem mount, dass `ro,noexec,nodev,nosuid` tatsächlich aktiv sind. es
gibt im MVP keinen unmount-unterbefehl; anschließend lokal `umount` verwenden.

## Teil 3: signaturprüfung und ingest

eine produktive scanner-policy wie in [OFFLINE-BUILD.md](OFFLINE-BUILD.md)
vorbereiten. dann das paket **direkt vom sicheren read-only-mount** importieren:

```sh
umzug-setup --log /var/tmp/umzug-ingest.jsonl ingest \
  /mnt/umzug-source/migration.bundle.age \
  --workspace /var/tmp/umzug-work \
  --decrypt auto \
  --fingerprint 'ERWARTETER-64-HEX-FINGERPRINT' \
  --scanner-config /opt/umzug-analysis/scanner.toml
```

bei empfängerverschlüsselung kann die lokale identity ausdrücklich angegeben
werden:

```sh
--age-identity /secure/local/migration-age-identity.txt
```

sie muss eine reguläre nicht-symlink-datei mit modus 0600 oder strenger sein.
ohne diese option übergibt das toolkit keine identity-datei; ein
empfängerverschlüsseltes paket wird dann nur entschlüsselt, wenn `age` selbst
über einen ausdrücklich unterstützten mechanismus an die passende identity
gelangt, andernfalls bricht ingest ab.
`--max-payload-bytes BYTES` begrenzt transport, entschlüsseltes paket und
extraktion; die entschlüsselung selbst erhält zusätzlich ein hartes
dateigrößenlimit. vorhandene decrypt-/workspace-ziele werden nicht ersetzt.

alternativ zu `--fingerprint`:

```sh
--trusted-key /secure/off-media/migration-ed25519.pem.pub
```

diese optionen schließen einander aus und eine ist pflicht. `--decrypt auto`
erkennt `.age`, `.gpg` und `.pgp` am namen; sonst wird ein unverschlüsseltes tar
angenommen. das workspace muss fehlen oder leer sein.

ingest:

1. verweigert standardmäßig unsichere mountoptionen;
2. kopiert den transport lokal, bevor ein parser ihn liest;
3. entschlüsselt lokal;
4. akzeptiert im äußeren tar nur die vier definierten regulären member;
5. prüft schlüssel/fingerprint, Ed25519-signatur, manifest und payloadhash;
6. verifiziert jedes `SOURCE.tar`-member gegen das signierte manifest;
7. extrahiert ohne privilegien/spezialknoten und mit größenlimits;
8. erzeugt je ursprünglicher auswahl `item-NNNN` in `SOURCE` und `QUARANTINE`;
9. scannt beide zonen und schreibt
   `state/reports/item-NNNN.source.json` sowie
   `item-NNNN.quarantine.ingest.json`;
10. schreibt `state/item-NNNN.provenance.json` als selbstgehashten
    SOURCE→QUARANTINE-Beleg. Er bindet beide Scan-IDs/-Reporthashes, SOURCE-,
    unveränderlichen SOURCE-Snapshot- und QUARANTINE-Manifest-Hash.

manifest-warnungen, extraktionsfehler oder nicht lesbare xattrs sind
paketweite, nicht überstimmbare blocker für promotion/approval. das paket muss
dann an der quelle enger ausgewählt und neu erstellt werden.

`--allow-unsafe-source-mount-for-testing` existiert ausschließlich für tests.
es darf bei einer echten migration nicht verwendet werden. ein damit erzeugtes
`ingest.json` wird explizit als unsicher markiert; promotion, approval und
produktiver restore bleiben dauerhaft gesperrt. auch alte belege ohne dieses
eindeutige `false`-feld werden fail-closed abgewiesen und müssen durch einen
frischen sicheren ingest ersetzt werden.

trifft der scanner auf zstd, auch in einem RPM-payload, verlangt er sowohl
den unabhängigen `zstd`- als auch den bubblewrap-hash. er dekomprimiert den
stream vollständig in einer sandbox ohne netzwerk mit `zstd -M128`, timeout
und input-/output-/expansionslimits und scannt das ergebnis rekursiv. fehlende
pins, ein fehler oder ein limitüberlauf erzeugen einen blocker. unbekannte
felder und falsche typen in `scanner.toml` werden ebenfalls abgewiesen. eine
produktive policy darf externe scanner, hashbindung, bubblewrap, sichere
quellmounts oder unknown-binary-blocking nicht abschalten, keine
unisolierte/executable-/cross-filesystem-ausnahme aktivieren und die
eingebauten ressourcenlimits nicht erhöhen. `--relaxed-test-mode` bleibt der
einzige bewusst nicht freigabefähige testpfad.

## Teil 4: scannen, bereinigen, freigeben

kandidaten separat scannen:

```sh
umzug-setup scan \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --stage QUARANTINE \
  --scanner-config /opt/umzug-analysis/scanner.toml \
  --report /var/tmp/item-0000.quarantine.json
```

exitcode 3 bedeutet blocker; exitcode 2 einen bedien-/verifikationsfehler.
`--relaxed-test-mode` deaktiviert externe scanner und ist niemals
freigabefähig.

blocker können nicht akzeptiert werden. die datei muss in der isolierten,
netzlosen quarantäne entfernt oder durch eine separat erzeugte passive fassung
ersetzt und danach vollständig neu gescannt werden. keine untrusted datei mit
editorplugins, interpreter, buildtool, office-anwendung oder medienplayer
öffnen. der MVP enthält keine automatische CDR-strecke.

wenn keine blocker verbleiben, den exakten manifest-hash aus dem neuen report
verwenden. review-funde werden nur einzeln über ihre ids quittiert:

```sh
umzug-setup promote \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --expected-manifest '<SHA256-AUS-DEM-REPORT>' \
  --accept-finding '<REVIEW-ID>' \
  --scanner-config /opt/umzug-analysis/scanner.toml
```

promotion prüft den unveränderten SOURCE-snapshot und den ingest-beleg erneut.
der übergebene QUARANTINE-report muss strikt, blockerfrei und an das ingest-
manifest gebunden sein; `--accept-finding` muss exakt alle und nur seine
review-ids nennen. danach schreibt promotion den exakten report als
`state/reports/item-NNNN.quarantine.json`, erzeugt und scannt `SANITIZED`
und schreibt `state/promotions/item-NNNN.json`. dieser selbstgehashte
QUARANTINE→SANITIZED-beleg bindet provenienz, SOURCE-snapshot, beide
manifeststufen, scan-ids, reporthashes und die exakten promotion-akzeptanzen.
das ist noch keine freigabe. den SANITIZED-report erneut prüfen und dann
hashgebunden genehmigen:

```sh
umzug-setup approve \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --expected-manifest '<SANITIZED-SHA256>' \
  --actor 'alice' \
  --reason 'Manuelle Prüfung und passive Rekonstruktion abgeschlossen' \
  --accept-finding '<REVIEW-ID>' \
  --confirm-approval item-0000 \
  --scanner-config /opt/umzug-analysis/scanner.toml
```

nur eine strikte policy darf genehmigen. approval kopiert die unveränderten
bytes nach `APPROVED` und schreibt einen hashgebundenen record. die JSON-ausgabe
bindet über `report_sha256` auch den exakten strikten SANITIZED-report und
enthält `approval_sha256`. der record bindet außerdem
`ingest_provenance_sha256`, `promotion_sha256`, SOURCE-, SOURCE-snapshot-,
QUARANTINE- und SANITIZED-manifest, promotion-QUARANTINE-scan-ID/-reporthash
sowie die exakt akzeptierten promotion-funde. `approval_sha256` deckt alle
diese felder ab. diesen 64-stelligen wert unmittelbar auf einem vom workspace
und transportmedium unabhängigen, geschützten kanal notieren; nicht später aus
der workspace-datei für den restore kopieren. diese hashkette belegt integrität
und ableitung, nicht malwarefreiheit.

### Native vendor-pakete zusätzlich signaturprüfen

ein strukturell untersuchtes DEB/RPM bleibt reviewpflichtig. statische analyse
ist kein herkunftsnachweis. für die mullvad-app müssen paket und offizielle
detached signature unter demselben unveränderten `APPROVED`-kandidaten liegen.
der hersteller-public-key und dessen erwarteter 40-stelliger primärer
fingerprint müssen dagegen aus einem unabhängigen kanal kommen.

nach approval, hier beispielhaft `item-0004`:

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

`--artifact-sha256` muss aus einem unabhängigen, authentifizierten release-
kanal stammen; ein hash aus demselben untrusted kandidaten ist kein anker. die
relativen artefaktpfade dürfen den kandidaten nicht verlassen und keine
symlinks sein. der befehl verwendet keinen keyserver, kein web of trust, keine
shell und keine implizite schlüsseldatei. GnuPG-parsing, keyringaufbau und
`gpgv` laufen in der SHA-256-gepinnten bubblewrap-sandbox ohne netzwerk. der
befehl verweigert vorhandene receipts und bindet in den receipt im format
`umzug-vendor-verification-v4`
artefaktgröße/-hash, signaturhash, schlüsselhash/-fingerprint sowie alle drei
toolpfade/-hashes. ein gültiger receipt beweist signaturherkunft, nicht
malwarefreiheit oder einen vertrauenswürdigen hersteller-build.

restore überschreibt nie:

```sh
sudo /usr/local/sbin/umzug-setup restore \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --destination /var/lib/umzug/restored-staging/item-0000 \
  --confirm-restore item-0000 \
  --trusted-key /secure/off-media/migration-ed25519.pem.pub \
  --fingerprint 'ERWARTETER-64-HEX-FINGERPRINT' \
  --expected-approval-sha256 '<UNABHAENGIG-NOTIERTER-64-HEX-APPROVAL-SHA256>' \
  --scanner-config /opt/umzug-analysis/scanner.toml
```

die werte in spitzen klammern sind metavariablen und müssen durch separat
aufbewahrte reale werte ersetzt werden. mindestens `--trusted-key` oder
`--fingerprint` ist pflicht; beide zusammen prüfen sowohl schlüsselbytes als
auch den unabhängig notierten fingerprint. der trusted key muss außerhalb des
workspace liegen. `--expected-approval-sha256` ist immer pflicht.
approval-, provenienz- oder promotion-records älterer versionen ohne alle
pflichtfelder der aktuellen ableitungskette werden abgewiesen. den kandidaten
aus einem frischen ingest erneut durch QUARANTINE und SANITIZED führen und
freigeben; JSON-records niemals manuell ergänzen.

`restore` verlangt root und genau den inerten, neuen pfad
`/var/lib/umzug/restored-staging/CANDIDATE`; aktive home-, dotfile- oder
systemziele werden abgewiesen. erst nach separatem review dürfen inhalte
manuell in ihr endgültiges ziel übernommen werden. vor jeder zielkopie erstellt
es einen stabilen
nofollow-snapshot des ursprünglichen bundle, prüft dessen vier member,
Ed25519-signatur und vollständiges `SOURCE.tar` neu und kopiert zusätzlich
SOURCE-, ingest-QUARANTINE-, promotion-QUARANTINE- und SANITIZED-report, beide
ableitungsbelege, approval und APPROVED über fd-verankerte, linkfreie
snapshots. es verlangt aktuelle vollständige schemas, beide QUARANTINE-reports
strikt und blockerfrei, identische policy-/toolbindungen, exakte promotion-
review-ids und eine lückenlose hash-/manifestkette bis zum unabhängigen
approval-hash. die kopie ist über offene verzeichnisdeskriptoren
verankert, folgt keiner elternpfad-symlinkkomponente und wird nur atomar mit
`renameat2(RENAME_NOREPLACE)` veröffentlicht. dafür müssen linux-`/proc`, libc,
kernel und zielfilesystem diese operationen unterstützen; es gibt keinen
unsicheren fallback. erst danach prüft der metadatenpfad sämtliche zielbytes,
typen und links. eine
quell-UID/-GID wird nur dann auf das ziel übertragen, wenn derselbe eindeutige
benutzer- beziehungsweise gruppenname sowohl im signierten inventar als auch
lokal bijektiv und eindeutig genau einer ID zugeordnet ist. rohe numerische ids
werden nie übernommen; fehlende oder mehrdeutige namen bleiben beim
restore-operator (normalerweise root) und werden
im receipt ausgewiesen. numerische kollisionen unter anderem namen werden nicht
blind verwendet. namensgleichheit ist dennoch keine kryptografische identität;
zuordnungen auf privilegierte zielkonten im receipt besonders prüfen.

reguläre dateien erhalten nur die signierten rw-bits und mtime, verzeichnisse
die signierten rwx-traversalbits. execute-, SUID-, SGID- und sticky-bits,
capabilities, acls und sämtliche xattrs bleiben entfernt; symlinks werden nie
für chmod verfolgt. mode, ziel-UID/-GID und mtime werden nach der anwendung
nochmals exakt verifiziert. der nicht überschreibbare metadaten-receipt liegt unter
`WORKSPACE/RESTORED/CANDIDATE.metadata.json`. bestehende ziele und receipts
müssen manuell verglichen/zusammengeführt werden. die funktion legt keine
benutzer oder gruppen an und aktiviert absichtlich keine ausführbaren inhalte.

für ein genehmigtes projekt gibt es einen rein statischen zusatzbericht:

```sh
umzug-setup project-report \
  --workspace /var/tmp/umzug-work \
  --candidate item-0000 \
  --output /var/tmp/project-report.json
```

er listet erkannte ökosysteme, deklarierte abhängigkeiten, build-/CI-metadaten,
git-hooks, aktive lokale git-konfiguration und submodule, ohne code, git oder
paketmanager auszuführen.

## Teil 5: ziel erkennen und plan erzeugen

read-only-erkennung:

```sh
umzug-setup detect
umzug-setup detect --json
```

für einen gemounteten testbaum können `--root`, `--proc`, `--sys` und
`--no-commands` gesetzt werden.

interaktiver einstieg:

```sh
umzug-setup wizard --output /var/tmp/umzug-plan.json
```

der wizard erkennt das system, fragt profil und ethernet-interfaces ab und
schreibt nur einen plan. er wendet nichts an.

expliziter plan:

```sh
umzug-setup plan \
  --profile strict \
  --output /var/tmp/umzug-plan.json \
  --ethernet enp0s31f6 \
  --capability firewall \
  --capability wireguard \
  --capability audit \
  --capability integrity-checker \
  --capability ssh-client
```

ohne `--ethernet` werden physische erkannte ethernet-interfaces verwendet.
WLAN/virtuelle interfaces werden nicht als ersatz gewählt. `--radio-module`
kann nach manueller treiberprüfung wiederholt werden. das ziel ist ein
kabelgebundenes profil; fehlendes ethernet stoppt die planung.

akzeptierte capabilities sind eine endliche liste im adapter, unter anderem
`archive-tools`, `audit`, `build-tools`, `ca-certificates`, `curl`, `firewall`,
`git`, `gnupg`, `integrity-checker`, `mac-apparmor`, `mac-selinux`,
`malware-scanner`, `python`, `rsync`, `sandbox`, `ssh-client`, `sudo`,
`tpm-tools`, `usb-control`, `wireguard`, `yara` und ausgewählte editoren/shells.
nicht jede capability existiert auf jeder distribution; ungelöste werte bleiben
im adapterbericht manuell. `mac-apparmor`/`mac-selinux` sind nur
paket-/service-capabilities; sie erzeugen keine vollständige MAC-policy und
beweisen keine aktive erzwingung.

arch-offline-artefakte müssen reguläre dateien unter `APPROVED` sein:

```sh
umzug-setup plan ... \
  --workspace /var/tmp/umzug-work \
  --offline-artifact \
  'git=/var/tmp/umzug-work/APPROVED/item-0003/git.pkg.tar.zst'
```

für ein offizielles mullvad-paket muss der zuvor erzeugte vendor-receipt
zusammen mit dem unveränderten absoluten artefaktpfad in den plan:

```sh
umzug-setup plan \
  --profile strict \
  --output /var/tmp/umzug-plan.json \
  --ethernet enp0s31f6 \
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
  --capability wireguard
```

artefakt und receipt sind nur gemeinsam erlaubt; artefakthash, fingerprint,
die drei toolhashes sowie exakte paketversion und -architektur sind pflicht.
version und architektur müssen für exakt dieses artefakt unabhängig aus
authentifizierten paket-/repository-metadaten stammen: auf debian aus
authentifizierten DEB/APT-metadaten, auf fedora aus authentifizierten
RPM-/repository-metadaten. werte aus paket oder workspace sind kein
unabhängiger anker. der receipt muss unter `WORKSPACE/state/vendor` liegen.
der plan prüft approval und führt den isolierten signaturnachweis mit den neu
angegebenen ankern wirklich erneut aus. er akzeptiert `.deb` nur auf
unterstütztem debian/ubuntu und `.rpm` nur auf unterstütztem fedora und erzeugt
eine kritisch zu bestätigende offline-installation mit
`apt-get install --yes --reinstall --no-download --no-install-recommends --
ARTEFAKT` beziehungsweise auf fedora ausdrücklich
`rpm --upgrade --replacepkgs -- ARTEFAKT` im netzwerk-namespace. DNF wird dafür
nicht verwendet. transitive APT-abhängigkeiten müssen vorher im
vertrauenswürdigen systembestand vorhanden sein; ihre vollständige
signatur-/closure-bindung beweist der vendor-receipt nicht. weil
der nachweis wirklich wiederholt wird, müssen auch die im receipt gebundene
detached signature und schlüsseldatei bis zur planung unverändert und lokal
verfügbar bleiben.

auf dem vorgesehenen frisch installierten systemd-ziel erzwingt der plan
`mullvad-management-group` → `mullvad-management-socket` →
`mullvad-offline-install`. gruppe und drop-in entstehen vor dem paket. die
vendor-action bindet danach `mullvad`, führt receiptgebunden
`systemctl daemon-reload` und `restart mullvad-daemon.service` aus und gilt
erst nach paketidentitäts/-integritäts- sowie live-gruppe/environment/umask/UDS-
prüfung als abgeschlossen. ein reload vor der noch fehlenden main-unit ist
bewusst nicht vorgesehen. `--no-mullvad-app-preparation` kann nicht mit einem
vendor-artefakt kombiniert werden. ist mullvad bereits installiert oder läuft
der daemon schon, gilt die first-load-invariante nicht: bis zum verifizierten
neustart könnte die alte unit-umgebung weiterwirken. diesen nicht-frischsystem-
fall vorher an der lokalen konsole stoppen und separat prüfen.

neben dem plan entsteht `PLAN.report.json` mit erkennung, adapterauflösung,
mullvad-plattformstatus, `executable_preflight` und warnungen. beide vollständig
prüfen. `missing-blocks-productive-apply-before-mutation` bedeutet: der dry-run
bleibt möglich, aber produktives apply stoppt im führenden werkzeug-prefix,
bevor eine systemdatei geändert wird. der plan ist
nicht separat signiert. `apply` und `resume` vergleichen den stabilisierten
`system_fingerprint` erneut mit dem aktuellen ziel und brechen bei einem
anderen system ab. der fingerprint ist nur eine fehlziel-sperre, keine
kryptografische hostidentität; planhash und zielbezug trotzdem manuell prüfen.
der bericht markiert bei `strict` und `maximal` den egress-kill-switch als
`deferred-to-explicit-vpn-finalize`. ein erfolgreicher offline-apply erfüllt
diese anforderung daher noch nicht.

plan und report sind selbst keine vertrauensanker. quelldaten und manifest
liefern niemals freie paketnamen, pfade oder befehle: die ableitung verwendet
nur lokale erkennung, explizite capabilities, das enge profil und endliche
adaptermappings. beim laden prüft die typisierte action-registry jede action-ID
erneut gegen exakte felder, ziel/mode/gerenderte bytes oder `argv`, risiko,
bestätigungs-/destruktivstatus, backup, verifier und sichere reihenfolge.
unbekannte ids, ein freier command-verifier, ein abweichender safety-flag oder
eine manipulierte service-/dateiaktion werden trotz passenden planhashes
abgewiesen.
zusätzlich regeneriert der validator aus dem ziel-intent den vollständigen
hardening- und paketaktionssatz. leere/gekürzte produktive pläne, fremde
adaptermodule und ein apply vor seiner konfigurationsdatei werden abgewiesen,
auch wenn zugehörige preflights gemeinsam entfernt wurden.

### Profile

| effekt | compatible | strict | maximal |
|---|---:|---:|---:|
| IPv6 sysctl/modprobe deaktivieren | nein | ja | ja |
| funkmodule in blacklist | nein | nein | ja, erkannte/angegebene |
| INPUT/FORWARD default-drop | ja | ja | ja |
| VPN-egress-kill-switch nach offline-plan | nicht beansprucht | offen bis `vpn-finalize` | offen bis `vpn-finalize` |
| sudo timestamp | 5 min | 0 | 0 |
| zusätzliche dateisystemmodule/user-namespaces/`kexec` sperren | nein | nein | ja |

eigene profile werden mit `--profile-file DATEI` geladen. zulässig sind nur
`name`, `disable_ipv6`, `disable_radios`, `blacklist_radio_modules`, `firewall`,
`vpn_killswitch` und `sudo_timestamp_minutes`; unbekannte felder werden
abgewiesen. insbesondere existiert kein profil-schalter, der MAC, PAM,
mount-hardening, FDE, secure boot oder bootloaderänderungen nur dem namen nach
als erledigt markieren könnte.
`strict` und `maximal` haben feste untergrenzen: IPv6-/funkdeaktivierung,
VPN-kill-switch-anforderung und sudo-timestamp 0 dürfen nicht abgeschwächt
werden; `maximal` muss erkannte funkmodule zusätzlich blacklisten.

alle profile deaktivieren/maskieren im systemd-backend eingehendes SSH, telnet
und rsh; OpenRC deaktiviert die bekannten entsprechenden services ohne
systemd-maskierung. kein backend erzeugt eine SSH-accept-regel. ausgehender
`ssh`-client ist als optionale capability verfügbar. `disable_radios` plant
`rfkill block all`
sowie das abschalten bekannter WLAN-/bluetooth-/mobilfunkdienste. `maximal`
blacklisted zusätzlich erkannte oder mit `--radio-module` angegebene module.
unbekannte dienste, firmware-radios und aktive geräte nach apply trotzdem
separat verifizieren.

folgende ziele werden durch keines der drei profile automatisch abgeschlossen:

| ziel | tatsächlicher MVP-status |
|---|---|
| AppArmor/selinux/anderes LSM | höchstens capability-/paketplanung; keine vollständige policy, aktivierung oder enforcing-verifikation |
| PAM/account-lockout/passwortpolicy | inventar und einzelne sudo-einstellung; kein sicherer vollständiger PAM-stack |
| full-disk-encryption | erkennung von indizien; keine partitionierung, schlüsselerzeugung oder verschlüsselung |
| secure boot | statushinweis; kein key-enrollment, signieren oder bootkettennachweis |
| LFS/generic | dokumentierte manuelle checkpoints; kein erfundener paket-, initramfs-, init- oder firewallmanager |
| offiziell nicht unterstützte mullvad-plattform | `vpn-finalize` verweigert; strikter kill-switch bleibt offen bis zu einer separat reviewten lösung |

diese punkte im abschlussbericht als offen kennzeichnen; eine manuelle
attestierung macht daraus keinen kryptografischen wirksamkeitsbeweis.

auf systemd sind offline-guard und host-firewall als frühe harte boot-gates
installiert. sie stehen vor basic-/network-/VPN-zielen, werden von diesen über
`RequiredBy=` zwingend eingezogen und isolieren bei einem ladefehler mit
`OnFailure=emergency.target`/`OnFailureJobMode=isolate`. ein boot in den
emergency mode ist daher beabsichtigtes fail-closed-verhalten, kein anlass,
die regeln blind zu löschen. lokale root-anmeldung und den recovery-befehl vor
dem apply praktisch testen. OpenRC besitzt diese harte systemd-semantik nicht.

## Teil 6: dry-run, apply, neustart, rollback

dry-run ohne root in einem eigenen state-verzeichnis:

```sh
umzug-setup apply /var/tmp/umzug-plan.json \
  --dry-run \
  --state-dir /var/tmp/umzug-dry-run-state
```

der dry-run führt keine aktion aus und trägt keine action-ID als abgeschlossen
ein. kann der benutzer etwa `/etc/sudoers.d` nicht lesen, erscheint ausdrücklich
`not inspectable by this unprivileged dry-run`; die vorschau erfindet keinen
bestand. fehlende programme erscheinen als `MISSING/UNSAFE`. der produktive
root-lauf prüft ziel und echten diff erneut. ein getrenntes state-verzeichnis
bleibt empfohlen, damit vorschau und produktionsnachweise getrennt bleiben.

produktiv an der lokalen konsole:

```sh
sudo /usr/local/sbin/umzug-setup --log /var/log/umzug-audit.jsonl apply \
  /var/tmp/umzug-plan.json \
  --expected-plan-sha256 '<SHA256-AUS-DER-PLAN-AUSGABE>' \
  --state-dir /var/lib/umzug
```

`--expected-plan-sha256` ist bei **jedem** produktiven apply pflicht, auch am
interaktiven TTY. es gibt keine eingabeaufforderung als ersatz. der wert muss
außerhalb der planerstellung separat notiert worden sein; fehlen oder
abweichung bricht vor zielprüfung und state-speicherung ab. nur der dry-run
darf die option weglassen und zeigt den getrennt zu notierenden digest.

für dateien erscheint ein diff. normale aktionen fragen `y/N`; destruktive
aktionen erfordern exakt ihre action-ID. `--yes` genehmigt nur actions, die
ohnehin keine explizite bestätigung verlangen. nichtinteraktiv müssen alle
bestätigungspflichtigen ids einzeln mit `--approve ACTION_ID` angegeben werden.
eine pauschale freigabe kritischer aktionen existiert absichtlich nicht.

privilegierte offline-paketbefehle laufen, sofern ein adapter sie sicher
unterstützt, mit `unshare --net`. generische debian-/ubuntu-capabilities führen
derzeit **kein** `apt-get` aus, sondern enden in einem blockierenden manuellen
nicht-ausführungs-checkpoint. es fehlt noch ein signatur-/SHA-256-gebundener
`APPROVED`-APT-repository-snapshot mit exaktem closure-receipt. der enge
mullvad-DEB-pfad bleibt separat artefakt-/vendorreceiptgebunden, beweist aber
keine transitiven APT-abhängigkeiten. auf frischem debian ohne `nft` kann
`nftables` nicht hinter seinem eigenen noch fehlenden guard bootstrapen:
`nft` muss aus einer separat verifizierten offline-basisinstallation stammen,
sonst stoppt apply vor der ersten systemänderung. `wireguard-tools`/`wg` sind
ohne eine solche sichere bereitstellung nicht automatisch verfügbar; auch der
manuelle regelgenerator ist im setup-plan nicht angewendet.

preflight-programme werden im privaten state exakt mit `path`, `sha256`,
`device`, `inode`, `size`, `mtime_ns` und `ctime_ns` gebunden. jede spätere
auflösung, ausführung und verifikation prüft alle felder erneut und nutzt den
absoluten pfad. neu installierte werkzeuge dürfen nur unmittelbar an ihrer
typisierten paketgrenze gebunden werden. ein update oder austausch bricht ab
und verlangt einen neu geprüften plan.

bei einem neustart-checkpoint:

```sh
sudo reboot
sudo /usr/local/sbin/umzug-setup resume --state-dir /var/lib/umzug
```

noch unmittelbar vor speicherung des reboot-checkpoints re-verifiziert der
executor den gesamten abgeschlossenen action-prefix und seine effektiven
controls; drift durch paket-/initramfs-hooks stoppt vor dem neustartzustand.
die boot-ID muss danach gewechselt haben. `resume` führt die im plan gebundene
post-reboot-prüfung aus. zuvor verifiziert es alle abgeschlossenen verwalteten
dateien erneut gegen exakte planbytes/modi und alle abgeschlossenen typisierten
controls gegen den effektiven zustand, darunter offline-guard und host-
firewall. jede drift stoppt vor anerkennung des reboots und vor folgeaktionen.
anschließend dürfen beispielsweise gesperrte module nicht mehr in
`/proc/modules` stehen oder ein paketadapter kann eine erwartete lokale
versionsausgabe verlangen. NixOS ist strenger: nach `nixos-rebuild dry-build`,
`test` und `boot` wird am lokalen TTY der exakte getestete kanonische
`/nix/store/...-system`-pfad gebunden. nach dem neustart muss
`/run/current-system` exakt darauf zeigen und von der vorigen generation
abweichen. nur andere manuelle fälle verwenden
`POST-REBOOT-VERIFIED:ACTION-ID`. bei fehlschlag bleibt der
checkpoint offen und keine folgeaktion läuft.

auch eine normale `checkpoint`-action führt keine automatische änderung aus,
ist aber nicht still erfolgreich: nach eigener prüfung der angezeigten
voraussetzung muss am lokalen TTY exakt `VERIFIED:ACTION-ID` eingegeben werden;
die attestierung wird mit zeit und anforderung im plan-gebundenen state erfasst.
eine manuelle aussage ist kein maschineller wirksamkeitsbeweis. details und
rollback:
[RECOVERY.md](RECOVERY.md).

## Teil 7: mullvad als letzter netzschritt

stand 2026-07-15 ist mullvad WireGuard-only; OpenVPN wurde am 15.01.2026
vollständig entfernt. `vpn-finalize` akzeptiert konservativ nur debian 12/13,
ubuntu 24.04/25.10/26.04 und fedora 43/44 auf x86-64/ARM64. die offizielle
matrix ist zeitabhängig und vor späterer nutzung erneut zu prüfen. archs paket
ist nicht mullvad-maintained; NixOS/gentoo/LFS werden von diesem app-pfad
abgewiesen und bleiben nur dokumentierter best-effort für manuelles WireGuard.

vorher:

1. offizielle app und detached signature online auf einem vertrauenswürdigen
   system beziehen; hersteller-key/fingerprint unabhängig prüfen;
2. paket und signatur durch die gleiche zero-trust- und `APPROVED`-strecke
   bringen;
3. mit `verify-vendor` einen hashgebundenen receipt erzeugen;
4. paket plus receipt über `--mullvad-artifact` und
   `--mullvad-vendor-receipt` sowie den unabhängigen artefakthash, fingerprint,
   die drei toolhashes und aus authentifizierten paket-/repo-metadaten
   stammende exakte version/architektur in den hardening-plan aufnehmen und ihn
   offline anwenden; damit werden auch `mullvad-management`-gruppe und
   systemd-override bestätigt eingerichtet;
5. sicherstellen, dass die erkennung die tatsächliche mount-abdeckung von
   `/etc/mullvad-vpn` eindeutig als verschlüsselt meldet. ein nur
   verschlüsseltes root-dateisystem reicht nicht, wenn ein separates `/etc`-
   oder `/etc/mullvad-vpn`-mount es überschattet. die heutige erkennung kann ein
   solches unter-mount nicht separat als verschlüsselt beweisen und blockiert
   es ausnahmslos. vorher lokal prüfen:

   ```sh
   findmnt -T /etc
   findmnt -T /etc/mullvad-vpn
   ```

   auch ein separates `/etc`-, `/etc/mullvad-vpn`- oder exaktes datei-mount
   auf `account-history.json` beziehungsweise `device.json` wird konservativ
   abgewiesen. `unknown`, `false` oder uneindeutige mount-herkunft blockiert
   die finalisierung; es gibt keinen risiko-override;
6. `/proc` distributionsgerecht als procfs mit `hidepid=2` oder
   `hidepid=invisible` und **ohne** `gid=`-ausnahme persistent konfigurieren und
   lokal prüfen:

   ```sh
   findmnt -no TARGET,FSTYPE,OPTIONS /proc
   ```

   das toolkit nimmt die mountänderung nicht selbst vor. fehlendes procfs, eine
   andere `hidepid`-stufe oder jede ausgenommene gruppe blockiert die
   kontoeingabe. `hidepid` kann monitoring-, debugging- und desktop-werkzeuge
   einschränken; die distributionsspezifische persistente konfiguration deshalb
   an der lokalen konsole setzen, nach einem neustart erneut prüfen und einen
   recovery-weg bereithalten;
7. globale core-dumps vollständig deaktivieren und jeden aktiven swap beenden.
   der finalizer verlangt exakt diese lokale sicht:

   ```sh
   sysctl -n kernel.core_pattern
   sysctl -n kernel.core_uses_pid
   cat /proc/swaps
   ```

   der erste befehl darf keinen inhalt ausgeben, der zweite muss `0` liefern
   und `/proc/swaps` darf nur die kopfzeile enthalten. ein pipehandler wie
   `|/usr/lib/systemd/systemd-coredump` wird abgewiesen, weil `RLIMIT_CORE=0`
   über pipes geleitete core-dumps nicht hinreichend verhindert. auch
   verschlüsselter swap
   und zram werden nicht als ausnahme akzeptiert. `strict` und `maximal`
   rendern `fs.suid_dumpable=0`, ein leeres `kernel.core_pattern` und
   `kernel.core_uses_pid=0`. nicht-NixOS-pläne laden die sysctl-datei als
   bestätigte action; auf NixOS sind manueller modulimport und lokaler
   generationstest pflicht. die effektivprüfung bleibt trotzdem notwendig.
   swap wird nicht automatisch
   deaktiviert. core-dump-abschaltung beeinträchtigt crashanalyse; `swapoff -a`
   kann unter speicherdruck prozesse beenden oder das system festfahren und
   hibernation brechen. änderungen nur an der lokalen konsole nach
   kapazitätsprüfung und mit dem verfahren in
   [RECOVERY.md](RECOVERY.md) vornehmen.

erst jetzt netzwerk verbinden und als root am TTY:

```sh
sudo /usr/local/sbin/umzug-setup \
  --log /var/log/umzug-audit.jsonl \
  vpn-finalize \
  --state-dir /var/lib/umzug \
  --expected-plan-sha256 '<SHA256-DES-VOLLSTAENDIG-ABGESCHLOSSENEN-PLANS>'
```

die kontonummer wird verdeckt interaktiv abgefragt; config, stdin-pipe,
environment und argv werden nicht akzeptiert. der übergebene planhash muss
außerhalb des state-verzeichnisses festgehalten worden sein. setup verlangt,
dass exakt dieser plan vollständig abgeschlossen, nicht zurückgerollt und ohne
offenen reboot-checkpoint ist. der schritt:

- akzeptiert als anfangsgrenze ausschließlich den exakt verifizierten offline-
  guard, den exakt verifizierten bootstrap-guard oder bereits wirksamen
  mullvad-lockdown zusammen mit der strukturell geprüften mullvad-nftables-
  policy; die host-firewall wird unabhängig zusätzlich geprüft;
- verlangt die installierte UDS-gruppenbeschränkung;
- öffnet das generierte systemd-drop-in samt elternkette root-owned und
  linkfrei, verlangt eine reguläre single-link-datei mit UID 0 und modus 0644
  oder strenger sowie exakte bytes: zuerst leeres `Environment=`, danach nur
  die managementgruppe und `UMask=0077`;
- installiert und verifiziert vor jedem daemon-restart erneut den
  loopback-only-bootstrap-guard; das abschalten des offline-guards geschieht
  darunter und ist bei bereits fehlender offline-tabelle idempotent;
- startet den daemon unter dem bootstrap-guard neu, liest seine reale
  `/proc/<MainPID>/environ` bei stabiler root-owned PID nofollow und
  größenbegrenzt und verlangt exakt die erwartete managementgruppe; weitere
  mullvad-/talpid-, loader-, proxy-, CA- und shell-start-overrides werden
  fail-closed abgewiesen;
- beweist vor der kontoeingabe die verschlüsselte mount-abdeckung für
  `/etc/mullvad-vpn`, sichere procfs-mountpolicy, global abgeschaltete
  core-dumps und vollständig inaktiven swap;
  procfs-, core-dump- und swap-zustand werden direkt vor dem CLI-start erneut
  geprüft;
- prüft vor dem prompt vorhandene `account-history.json` und `device.json`,
  nach dem login beide zwingend vorhandenen dateien per `O_NOFOLLOW` auf
  regulären typ, root-eigentum, `nlink=1`, höchstens 1 MiB und modus 0600 oder
  strenger unter einer geschützten root-owned elternkette;
- sperrt im finalizer und CLI-kind `RLIMIT_CORE` soft/hard auf `0` und setzt
  `PR_SET_DUMPABLE=0`;
- loggt die kontonummer nicht;
- leert split-tunneling;
- blockiert LAN;
- aktiviert auto-connect und lockdown;
- setzt den gewählten offiziellen app-anti-zensurmodus;
- verbindet und wartet fail-closed auf `connected`;
- revalidiert den vollständigen vendor-intent samt kryptografischem receipt-
  und signaturnachweis bereits vor jeder nutzung; plan, apply/dry-run, `resume`
  und finalizer vertrauen nicht nur dem receipt-JSON;
- liest die effektive DNS-konfiguration geschützt. receiptgebundenes
  `resolvectl status` ist optional; ohne `resolvectl` ist ein statisches
  `resolv.conf` nur mit literaler nicht-loopback-adresse und nachgewiesener
  root-route über eine von `wg show interfaces` ausgewiesene WireGuard-NIC
  zulässig. ein bloßer loopback-stub ohne sichtbaren upstream wird abgewiesen;
- prüft vor der hostname-basierten onlineabfrage und erneut nach
  disconnect/reconnect auf jeder plan-gebundenen ethernet-NIC raw UDP/53 und
  TCP/53 zu `1.1.1.1`, `8.8.8.8` und `9.9.9.9`. empfang, TCP-refusal oder
  -reset ist ein leak; nur definierte negative fehler/timeouts bestehen;
- trennt kontrolliert und verlangt lockdown sowie eine effektive mullvad-
  OUTPUT-basiskette mit policy `drop` ohne indirekte/userspace-kontrollierte
  verdictpfade oder bedingungsloses accept;
- versucht pro plan-gebundenem ethernet-interface direkte, zeitbegrenzte,
  mit `SO_BINDTODEVICE` gebundene TCP-connects zu `1.1.1.1:80` und `:443`
  sowie eine UDP/53-probe. TCP-erfolg, `ECONNREFUSED` oder `ECONNRESET` und
  jedes empfangene UDP-datagramm gelten als leak; nur definierte policy-/
  down-/unreachable-/timeout-fehler gelten als blockiert, andere fehler
  brechen als unbestimmt fail-closed ab;
- verbindet auch nach der probe wieder und prüft den finalen connected-zustand;
- sammelt firewall-, routing-, DNS-, listener- und VPN-nachweise;
- prüft standardmäßig online über `https://am.i.mullvad.net/connected`.

erst der erfolgreiche abschluss dieses schritts schließt auf unterstützten
zielen die im `strict`-/`maximal`-offline-bericht offen ausgewiesene
kill-switch-anforderung. bricht der schritt vorher ab, darf der offline-plan
nicht als vollständiges VPN-egress-hardening bewertet werden.

`finite_connected_dns_containment_checks_passed=true` besagt nur, dass diese
endlichen DNS-proben bestanden. ein timeout beweist nicht, dass kein paket
gesendet wurde; drei ziele und eine sequenzielle root-routenansicht decken
weder DoH/DoT, beliebige resolver, prozess-uids/-marken, namespaces noch races
ab.

offizielle app-modi:

```sh
--anti-censorship auto
--anti-censorship udp2tcp
--anti-censorship shadowsocks
--anti-censorship quic
--anti-censorship lwo
```

diese modi gelten nur innerhalb der offiziellen app. bei manuellem WireGuard
sind sie laut mullvad nicht verfügbar. der online-connection-check ist in
diesem produktiven pfad nicht abschaltbar. fehlende oder nicht eindeutig bis
`/etc/mullvad-vpn` wirksame speicherverschlüsselung blockiert die kontoeingabe
ausnahmslos: `account-history.json` speichert die kontonummer im klartext und
`device.json` privaten kontobezogenen gerätezustand. das toolkit richtet FDE
nicht selbst ein; bei `unknown`/`false` oder einem nicht beweisbaren unter-mount
muss die zielinstallation außerhalb des toolkits sicher verschlüsselt und
anschließend neu erkannt werden.

der disconnect-test bindet pro physischem ethernet-interface rohe TCP- und
UDP-sockets mit `SO_BINDTODEVICE`. ein erfolgreicher TCP-connect sowie
`ECONNREFUSED`/`ECONNRESET` zeigen verkehr; jedes empfangene UDP-datagramm
zeigt verkehr, unabhängig von DNS-format oder transaktions-ID. nur die
definierten policy-/down-/unreachable-/timeout-fehler gelten als blockierung;
ein anderer socketfehler bricht als unbestimmt fail-closed ab. das verhindert,
dass protokoll- oder parserfehler als kill-switch-nachweis gelten, bleibt aber
endlich und ist
kein mathematischer beweis für alle ziele, protokolle, netzwerk-namespaces
oder privilegierten mullvad-API-ausnahmen. das auditfeld
`finite_fail_closed_disconnect_checks_passed=true` bezeichnet genau diese
begrenzten checks. jeder im finalizer gefangene fehler installiert und
verifiziert zuerst den unabhängigen loopback-only-bootstrap-guard, reaktiviert
danach `umzug-offline-guard.service` per `enable --now` rebootfest und
verlangt dessen enabled-/active-zustand sowie die exakte offline-regel. ein
fortsetzungslauf beginnt damit wieder an einer bewiesenen grenze. scheitert
diese notfall-reaktivierung selbst, wird der fehler auditiert; eine geschlossene
netzgrenze ist dann nicht bewiesen und recovery ist ausschließlich an der
lokalen konsole nach [RECOVERY.md](RECOVERY.md) zulässig.

die offizielle CLI erhält die kontonummer technisch kurz als argv.
root-/kernel-/eBPF-/audit-beobachtung kann sie daher weiterhin sehen; die
`hidepid`-pflicht schließt nur die normale lokale procfs-sicht ohne
gruppenausnahme. global leeres `core_pattern`, `core_uses_pid=0`, kein swap,
`RLIMIT_CORE=0` und `PR_SET_DUMPABLE=0` reduzieren zusätzliche lokale
offenlegung, garantieren aber weder speicherlöschung noch schutz gegen
privilegierte. die strikten datei- und mountprüfungen beweisen weder
schlüsselherkunft noch schutz gegen root. root-/API-, UDS-, DNS-, account-
history- und device-state-grenzen stehen im [bedrohungsmodell](THREAT-MODEL.md).

## Abschlussbericht

```sh
sudo /usr/local/sbin/umzug-setup report \
  --output /var/tmp/umzug-security-report.json \
  --state-dir /var/lib/umzug \
  --workspace /var/tmp/umzug-work
```

der bericht enthält zielerkennung, checkpoint, ingest/approval-receipts,
nftables, routing, DNS, listener, rfkill, WireGuard/mullvad und einfache
assertions wie „kein SSH-listener beobachtet“. er enthält keinen online-test und
ist eine momentaufnahme, kein malwarefreiheits- oder zukunftsnachweis.

## Exitcodes und logging

- `0`: unterbefehl erfolgreich;
- `2`: erwarteter bedien-, sicherheits- oder verifikationsfehler;
- `3`: ingest/scan/promotion abgeschlossen, aber blocker vorhanden.

`--log PFAD` steht als globale `umzug-setup`-option **vor** dem unterbefehl.
logs sind JSONL, mode 0600 und redigieren bekannte secret-schlüssel/-muster.
sie sind nicht manipulationssicher signiert. reports können pfade,
paketinformationen, geräte und netzdetails enthalten und sind vertraulich zu
behandeln. plan-, wizard-, scan-, projekt-, vendor-, restore- und
sicherheitsbericht-ausgaben verweigern vorhandene zielpfade beziehungsweise
receipts; für einen neuen lauf einen neuen pfad wählen, statt evidenz zu
überschreiben.
