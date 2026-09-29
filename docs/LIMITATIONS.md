# Grenzen und nicht implementierte anforderungen

diese liste ist bestandteil des sicherheitsmodells. sie verhindert, dass ein
MVP versehentlich als vollständig automatisiertes migrations- oder
malware-abwehrsystem eingesetzt wird. stand: 2026-07-15, version 0.2.0rc1.

## Kurzfassung

implementiert sind ein signiertes und optional verschlüsseltes transportformat,
lokale zielerkennung, sichere extraktionsprimitive, eine strikte statische
zero-trust-pipeline, distributionsspezifische paketplaner, drei
hardening-profile, ein bestätigender/backupfähiger executor, nftables-regeln,
recovery-grundlagen und eine abschließende mullvad-app-konfiguration.

nicht implementiert ist eine universelle, vollautomatische ende-zu-ende-
migration für alle genannten distributionen. insbesondere sind partitionierung,
bootloader, secure-boot-key-enrollment, full-disk-encryption, vollständige
benutzer-/gruppenanlage oder umnummerierung, semantische konfigurations-merges
und eine malwarefreiheitsgarantie nicht vorhanden.

explizit **nicht automatisch abgeschlossen** werden LSM-aktivierung und
policy-rollout (AppArmor/selinux), ein distributionsspezifisch sicherer
PAM-umbau, FDE/partitionierung, secure-boot-schlüsselverwaltung oder
bootloaderänderungen. LFS erhält nur dokumentierte manuelle checkpoints. auf
arch, NixOS, gentoo, LFS und anderen nicht offiziell akzeptierten plattformen
verweigert `vpn-finalize` den automatischen mullvad-app-pfad; ein manuell
reviewter WireGuard-/firewall-aufbau liegt außerhalb des MVP.

## Umfang des hardware-testkandidaten v0.2.0rc1

- v0.2.0rc1 ist nur ein kandidat für den reversiblen H0-offline-basislauf mit
  profil `compatible` auf **dedizierter, entbehrlicher debian-/ubuntu-hardware
  mit systemd**. auch ein bestandener H0-lauf ist keine produktionsfreigabe.
- H1 (`strict`), H2/mullvad, `maximal`, arch, NixOS, gentoo und LFS sind mit
  diesem RC nicht auf hardware abgenommen. vorhandene adapter, unit-tests und
  VM-befunde ersetzen diese abnahme nicht.
- produktives `apply`, `resume` und `vpn-finalize` benötigen eine positiv
  nachgewiesene echte lokale beziehungsweise serielle konsole. SSH,
  pseudoterminals (`/dev/pts/*`), unvollständig prüfbare prozessahnen und
  nichtinteraktive eingabe werden abgewiesen. planung und unprivilegierter
  dry-run bleiben davon getrennt.
- produktiver state muss auf einem persistenten, lokalen, geschützten
  dateisystem liegen und reboots unverändert überstehen. tmpfs, flüchtiger oder
  entfernter speicher, overlay-dateisysteme und unklare mount-evidenz sind kein
  zulässiger fortsetzungspfad.
- toolkit-rollback ist **kein vollständiger systemrollback**. es behandelt nur
  deklarierte und gesicherte pfade; paket-, initramfs-, boot-, firmware- und
  sonstige externe seiteneffekte können außerhalb seiner reichweite liegen.
  vor jedem hardwarelauf ist daher ein unabhängig geprüftes und praktisch
  wiederhergestelltes voll-/blockbackup einschließlich bootbereich und
  EFI-systempartition pflicht.
- der abschlussbericht ist ein lokaler rohbeleg der modellierten beobachtungen,
  keine signatur, attestierung oder autorisierung und kein beweis für
  malwarefreiheit, bootfähigkeit, vollständige regelwirkung oder leakfreiheit.
- für NixOS fehlt insbesondere ein sicherer automatischer merge einer
  bestehenden nativen firewallkonfiguration mit den erzeugten regeln. das
  generierte modul verlangt manuellen merge, `nixos-rebuild`-test und
  unabhängige prüfung; es gehört nicht zum rc1-hardwarelauf.
- für H2 sind die reale rebootfeste übergabe vom offline-/bootstrap-guard an
  mullvad-lockdown, die DNS-eindämmung auf echter hardware und die bereinigung
  beziehungsweise lebensdauer temporärer konto-/secret-daten nach erfolgs- und
  fehlerpfaden noch nicht hardwareabgenommen. diese offenen nachweise dürfen
  nicht aus unit-tests oder berichtsfeldern abgeleitet werden.

## Zero trust und malwareanalyse

- es gibt keine technische möglichkeit, „100 % malwarefrei“ zu garantieren.
- VM-erzeugung, hypervisor-härtung sowie automount-/udev-/desktop-abschaltung
  werden nicht automatisiert. `mount-source` kann ein explizites blockdevice
  mit `ro,noexec,nodev,nosuid` mounten und `ingest` prüft diese optionen; die
  übergeordnete isolation bleibt zwingende betriebliche voraussetzung.
- die trust-zonen sind verzeichnisse mit restriktiven rechten, keine eigenen
  kernel-mounts oder MAC-domains.
- die eingebaute analyse ist statisch. externe scanner werden in bubblewrap
  isoliert, untrusted kandidaten aber niemals zur dynamischen analyse
  ausgeführt. emulation, memory-forensik und verhaltensanalyse fehlen.
- 7z/RAR, verschlüsselte, beschädigte, übergroße und unvollständig lesbare
  dateien werden fail-closed blockiert, nicht „repariert“.
- es gibt kein vollständiges content disarm and reconstruction. `SANITIZED`
  bedeutet im MVP: erneut untersuchter, inerter kandidat; keine garantierte
  semantische säuberung.
- office-, PDF-, bild- und medienprüfungen sind heuristiken, keine vollständigen
  parser für alle aktiven oder polyglotten formate.
- ClamAV, YARA und `file` sind nur unabhängige indizien. die standardpolicy
  blockiert bei fehlenden oder nicht SHA-256-gepinnten tools/regeln/signaturen.
- die dateibytes für interne und externe analyse stammen aus privaten,
  nofollow erzeugten 0400-snapshots und werden danach gegen den originalbaum
  rückgebunden. die produktive standardobergrenze beträgt 256 MiB je datei und
  1 GiB insgesamt; größere kandidaten müssen aufgeteilt werden. temporärkopien
  benötigen entsprechend freien, vorzugsweise verschlüsselten storage und
  können nach einem harten prozess-/systemabbruch manuelle bereinigung erfordern.
- werkzeugdateien werden privat gesnapshottet und hashgeprüft, die dynamische
  runtime-closure aus loader, shared libraries, NSS-/locale-daten, kernel und
  weiteren read-only bäumen aber nicht lückenlos einzeln gepinnt. ein angreifer
  mit derselben UID kann prozess oder snapshots angreifen; root, kernel und
  hypervisor liegen außerhalb der schutzgrenze. die isolation ersetzt deshalb
  keine frisch aufgebaute, netzlose analyse-VM aus unabhängig geprüften
  basisartefakten.
- der setup-wrapper leert die umgebung, nutzt einen festen interpreter und
  `-I`. vor dem python-start prüft er feste runtime-komponenten linkfrei auf
  root-eigentum und fehlende gruppen-/weltschreibbarkeit; `find -P` lehnt im
  gesamten `runtime/lib` zusätzlich symlinks, nicht-root-eigentum,
  gruppen-/weltschreibbarkeit und spezialbits ab. setup revalidiert geladene
  paketdateien und eltern danach als zweite schranke. dies ist keine
  kryptografische attestierung und kann kompromittiertes root oder einen
  privilegierten TOCTOU-austausch nicht stoppen.
- alle fünf trust-zonen und ihre vorwärtsübergänge sind über die CLI erreichbar;
  semantische bereinigung zwischen `QUARANTINE` und `SANITIZED` bleibt ein
  manueller, isolierter arbeitsschritt.

## Paket und metadaten

- reguläre dateien, verzeichnisse, symlinks, hardlinks, UID/GID, modus und
  zeitstempel werden im quell-tar beziehungsweise manifest erfasst.
- spezialdateien werden absichtlich ausgelassen. das ist sicherer, aber keine
  vollständige dateisystemkopie.
- extended Attributes werden im manifest mit name, SHA-256 und größe
  dokumentiert. die zero-trust-kopien übertragen sie absichtlich nicht;
  capabilities, acls, SUID, SGID, sticky- und reguläre execute-bits werden auch
  beim restore nicht reaktiviert.
- der root-pflichtige restore ordnet eigentümer nur über exakt gleiche,
  bijektiv eindeutige name/ID-bindungen im signierten quellinventar und in der
  lokalen accountdatenbank zu. rohe ids und numerische kollisionen unter
  anderem namen werden nie übernommen; fehlende/mehrdeutige namen bleiben beim
  restore-operator. das ist eine konservative zuordnung, keine vollständige
  benutzer-/gruppenmigration. ein gleicher name ist keine kryptografische
  identität; insbesondere eine zuordnung auf privilegierte zielkonten muss im
  receipt vor jeder weiteren verwendung ausdrücklich geprüft werden.
- der metadatenabgleich prüft manifestbindung, bytes, typen und links erneut und
  entfernt acls/capabilities/xattrs; mode, ziel-UID/-GID und mtime werden nach
  anwendung exakt geprüft. für sichere nofollow-behandlung von
  symlink-xattrs ist unter linux ein funktionsfähiges `/proc` erforderlich;
  fehlt es, schlägt der abgleich geschlossen fehl.
- vor dem restore wird die paket-zu-approval-kette aus dem ursprünglichen
  workspace-bundle erneut aufgebaut. dazu werden beide selbstgehashten
  ableitungsbelege, SOURCE-, ingest-QUARANTINE-, promotion-QUARANTINE- und
  SANITIZED-report, approval und APPROVED fd-/nofollow gesnapshottet und
  vollständig neu gebunden. beide QUARANTINE-reports müssen strikt,
  blockerfrei und policy-/toolidentisch sein; promotion-akzeptanzen müssen
  exakt den review-ids entsprechen. dafür müssen mindestens ein unabhängiger
  public key oder sein 64-stelliger SHA-256-fingerprint und zusätzlich der beim
  approval unabhängig notierte `approval_sha256` vorliegen. diese anker schützen
  nicht gegen einen bereits vor ihrer erfassung kompromittierten pack-/
  freigabeprozess und beweisen weiterhin keine malwarefreiheit.
- der content-restore ist bewusst linux-spezifisch fd-verankert. er benötigt
  ein eingehängtes `/proc`, eine libc mit `renameat2` sowie kernel- und
  dateisystemunterstützung für `RENAME_NOREPLACE`. fehlt eine voraussetzung,
  wird nicht auf eine racy copy-/rename-variante zurückgefallen. symlinkte oder
  nicht stabile elternpfade werden ebenfalls fail-closed abgewiesen.
- approval-records binden neben dem exakten strikten SANITIZED-report
  provenienz- und promotion-selbsthash, SOURCE-, SOURCE-snapshot-, QUARANTINE-
  und SANITIZED-manifeste, promotion-QUARANTINE-scan-ID/-reporthash und exakte
  promotion-akzeptanzen. records oder ableitungsbelege aus älteren schemas ohne
  jedes pflichtfeld sind nicht wiederherstellbar; der kandidat muss einen
  frischen ingest und die vollständige pipeline durchlaufen. belege dürfen
  nicht von hand ergänzt werden. die hashkette beweist weiterhin keine
  malwarefreiheit.
- byte-restore und anschließender metadatenabgleich sind kein atomarer
  dateisystem-commit. scheitert der zweite schritt, können ein neuer zielbaum,
  ein content-receipt und teilweise angewandte sichere metadaten verbleiben,
  aber kein erfolgs-metadaten-receipt. dann nicht weiterarbeiten: evidenz
  sichern, ziel isoliert prüfen und manuell entfernen beziehungsweise aus einem
  frischen workspace neu beginnen.
- `SOURCE_DATE_EPOCH` normalisiert tar-/wheel-zeitstempel und die
  manifest-erstellzeit. bei stabilen quelldaten, metadaten und inventaren,
  demselben bereits vorhandenen Ed25519-schlüssel und `--encrypt none` ist das
  bundle byteidentisch reproduzierbar. geänderte inventare oder metadaten,
  age-/GPG-verschlüsselung und neu erzeugte schlüssel bleiben absichtlich
  nicht bitidentisch.
- ausschlussmuster und secret-heuristiken sind nicht vollständig. eine manuelle
  vorschau bleibt notwendig.
- das split-format erhält datei- und teilhashes, aber der index ist nicht separat
  signiert. nach dem zusammensetzen muss weiterhin die paketsignatur geprüft
  werden.

## Migration und konflikte

- vorhandene paket-ausgaben und pipeline-restore-ziele werden nicht
  überschrieben. verwaltete hardening-dateien erhalten diffs und backups.
- es gibt noch keinen allgemeinen drei-wege-merge für dotfiles oder
  systemkonfigurationen und keinen vollständigen konfliktresolver für jeden
  dateityp.
- benutzer, gruppen, UID/GID-kollisionen, home-verzeichnisse, shells, acls und
  sudo/PAM-beziehungen werden inventarisiert, aber nicht vollautomatisch sicher
  angelegt oder umnummeriert. die restore-zuordnung gleicher namen ersetzt
  diese provisionierung nicht.
- projekt-build-abhängigkeiten werden nicht vollständig aus beliebigen
  buildsystemen abgeleitet. es existiert kein sicherer automatischer build.
- git-objektintegrität, signierte commits/tags, submodule, LFS, alternates und
  dependency-lockfiles werden nicht als vollständige repository-attestierung
  validiert.
- cronjobs und systemd-units können als dateien ausgewählt und gescannt werden,
  werden aber nicht automatisch als vertrauenswürdig aktiviert.
- rollback sichert nur deklarierte pfade und neu erzeugte einträge. externe
  kommandos können zustand außerhalb dieser pfade ändern; dafür ist ein
  dateisystem-/VM-snapshot notwendig.
- ein gespeicherter plan bleibt untrusted. die typisierte action-registry
  erlaubt nur bekannte ids und leitet operation, exakte felder, ziel/bytes oder
  `argv`, risiko, bestätigungs-/destruktivstatus, backup, verifier und sichere
  reihenfolge neu ab. diese endliche registry begrenzt den MVP zugleich: neue
  adapteraktionen müssen im code ergänzt und getestet werden; der planhash
  allein autorisiert keine unbekannte aktion.
- produktive pläne binden einen lokalen ziel-intent und regenerieren daraus den
  vollständigen hardening- und adapteraktionssatz. das verhindert gelöschte
  pflichtaktionen und ziel-/capability-fremde adapterdateien. planhash und
  einzelbestätigungen bleiben für bewusst gewählte capabilities nötig.
- automatische post-reboot-prüfungen sind auf explizit modellierte evidenz
  begrenzt, derzeit insbesondere befehlsausgabe und abwesenheit gesperrter
  module in `/proc/modules`. manuelle checkpoints und NixOS-/unbekannte
  plattformprüfungen verlangen eine exakte lokale TTY-attestierung und speichern
  sie, können aber keine falsche bedieneraussage kryptografisch erkennen.
- bei jeder produktiven fortsetzung re-verifiziert der executor abgeschlossene
  verwaltete dateien sowie actions mit typisiertem verifier. er beweist damit
  weder beliebige seiteneffekte externer kommandos noch zustand ohne
  modellierten verifier; dafür bleiben VM-/dateisystem-snapshot und unabhängige
  systemprüfung erforderlich.
- DEB und RPM werden begrenzt strukturell geprüft. zstd-streams und
  zstd-komprimierte RPM-payloads werden nur mit SHA-256-gepinntem `zstd` **und**
  bubblewrap vollständig netzlos mit `-M128` sowie zeit-/input-/output-/
  expansionslimits dekomprimiert; fehlt diese vollständige analyse, entsteht ein
  blocker statt einer freigabe. ein vendor-receipt ersetzt keine vollständige
  maintainer-skript-, dependency- oder repositoriesicherheitsanalyse.

## Distributionen und paketmanager

| ziel | implementierungsgrad | wesentliche grenze |
|---|---|---|
| debian/ubuntu-familie | capability-mapping und blockierender manueller offline-checkpoint | kein generischer `apt-get`-befehl im MVP; erforderlich ist ein `APPROVED`, extern signaturverankerter repository-snapshot mit vollständiger SHA-256-closure |
| arch-familie | capability-mapping und blockierende manuelle offline-artefakt-checkpoints | kein privilegierter pacman-befehl im MVP; artefakt und policy-receipt bleiben manuell |
| NixOS | deklaratives paketmodul | manuelle einbindung/review; kein sicherer automatischer merge mit einer bestehenden nativen firewallkonfiguration; allgemeiner hardening-executor ist systemd-/FHS-orientiert und kein vollständiges NixOS-modul |
| gentoo | mapping und deklarative USE-flag-datei | kein automatischer `emerge`; binärpakete, signaturpolicy, profile und ABI bleiben manuell |
| LFS | erkennung und dokumentierter manueller plan | kein paketmanager wird erfunden; build-, update- und integritätsverantwortung bleibt manuell |
| andere | generic-adapter | unbekannte pakete und privilegierte befehle werden nicht geraten |

adapter laden offline keine abhängigkeiten. die generischen offline-adapter
erzeugen ohne eine bis zur ausführung gebundene repository-/vendor-
signaturkette, paketidentität und vollständige transitive SHA-256-closure
absichtlich keinen privilegierten installationsbefehl. ein APT-cache und
`--no-download` allein sind kein integritätsnachweis. der enge, separat
vendorreceiptgebundene mullvad-DEB-pfad beweist ebenfalls keine transitive
APT-closure; seine voraussetzungen müssen bereits vertrauenswürdig installiert
sein. paketpläne bleiben insoweit blockierende manuelle checkpoints.

## Hardware, boot und verschlüsselung

- hardwareerkennung ist best effort und basiert auf lokal sichtbaren `/sys`-,
  `/proc`- und `/etc`-daten. virtuelle geräte, exotische busse, proprietäre
  treiber oder gesperrte firmware können unvollständig erscheinen.
- GPU-treiberempfehlungen sind konservative hinweise, keine automatische
  kompatibilitäts- oder signaturgarantie.
- secure-boot-status kann fehlen oder durch firmware/VM unzuverlässig gemeldet
  werden. das toolkit enrolt keine schlüssel und signiert keine kernelmodule.
- TPM/IOMMU/kernel-lockdown-erkennung beweist nicht, dass die funktion korrekt
  provisioniert oder gegen physische angriffe wirksam ist.
- full-disk-encryption, partitionierung, LUKS-key-management, bootloader- und
  firmwareupdates sind nicht implementiert. sie werden niemals stillschweigend
  vorgenommen.
- debian/ubuntu-, arch- und fedora/RHEL-artige pläne bauen das initramfs nach
  modul-blacklists mit `update-initramfs`, `mkinitcpio` beziehungsweise `dracut`
  neu. andere distributionen erhalten einen kritischen manuellen checkpoint.
  BIOS-/UEFI-/initramfs- und kernelmoduländerungen können das system trotzdem
  unbootbar machen; der MVP kann dies nicht vollständig vorab simulieren.

## Hardening

- die profile erzeugen aktuell ausgewählte sysctl-, modprobe-, sudoers-,
  journald-, service- und nftables-aktionen. sie sind keine vollständige CIS-,
  ANSSI- oder BSI-konformitätsimplementierung.
- profile weisen unbekannte felder ab. die einzige erlaubte feldmenge ist im
  benutzerhandbuch dokumentiert; es existieren insbesondere keine
  `lock_kernel_modules`-/AppArmor-scheinoptionen, die nicht umgesetzte wirkung
  vortäuschen.
- mountoptionen für jedes dateisystem, PAM-stack, passwortqualität,
  account-lockout, usbguard, AIDE, audit-regeln, sichere paketquellen und
  automatische updates werden nicht vollständig konfiguriert.
- AppArmor/selinux wird in paket-capabilities berücksichtigt, aber nicht
  universell installiert, aktiviert, mit policies versehen und verifiziert.
- systemd-sandboxing für beliebige bestehende dienste ist nicht automatisch
  generierbar und im MVP nicht allgemein umgesetzt.
- systemd ist für services, firewall, rfkill und journald verdrahtet. OpenRC
  unterstützt service-deaktivierung und `local.d`-hooks für firewall/rfkill,
  aber weder eine universelle logging- noch sandbox-policy. runit, s6 und
  selbstgebaute LFS-init-systeme benötigen neue executor-adapter und erhalten
  manuelle checkpoints.
- `disable_radios` plant `rfkill block all` und deaktiviert bekannte WLAN-,
  bluetooth- und mobilfunkdienste. `maximal` sperrt zusätzlich erkannte oder
  explizit angegebene funkmodule. firmware-radios, unbekannte dienste und
  hardwareabhängige treiber müssen weiterhin separat geprüft werden.
- IPv6-deaktivierung und modul-blacklists können boot, container, discovery,
  VPN und recovery beeinträchtigen. `maximal` deaktiviert außerdem user
  namespaces und kann browser-/desktop-sandboxes sowie spätere strikte
  bubblewrap-scans brechen. scans deshalb vor diesem apply abschließen oder die
  isolation nach dem reboot ausdrücklich neu bewerten.
- `sshd`, `ssh.service`, telnet und rsh werden im systemd-plan deaktiviert und
  maskiert; ein fremdes init-system, socket-aktivierung unter anderem namen,
  container oder ein später manuell gestarteter prozess muss separat geprüft
  werden. es wird keine eingehende SSH-firewallregel erzeugt.

## Firewall und mullvad

- das vorhandene firewallbackend ist nftables. systeme mit ausschließlich
  iptables, pf, firewalld-abstraktion oder eigener policy benötigen anpassung.
- `nft` ist bootstrap-voraussetzung und wird vor jeder produktiven mutation
  geprüft. frisches debian ohne `nft` kann `nftables` nicht erst hinter seinem
  eigenen fehlenden guard installieren; nötig ist eine separat verifizierte
  offline-basisinstallation.
- ein syntaxcheck verhindert nicht jede logische fehlkonfiguration. vor
  aktivierung sind lokale konsole und getesteter recovery-befehl pflicht.
- auf systemd sind offline-guard und host-firewall über `RequiredBy=` harte
  abhängigkeiten früher basic-/network-/VPN-ziele und isolieren bei ladefehlern
  bewusst nach `emergency.target`. fehlendes `nft`, beschädigte regeln oder
  inkompatible kernelunterstützung können das system deshalb in der lokalen
  emergency-konsole halten. das ist fail-closed, aber keine
  verfügbarkeitsgarantie. OpenRC-`local.d` hat keine gleichwertige harte
  isolationssemantik.
- die firewall-lader löschen eine aktive `inet umzug_host`-tabelle nicht vor
  einem reload. kollidiert eine neue datei mit der vorhandenen tabelle, schlägt
  der reload geschlossen fehl und die alte tabelle bleibt aktiv. die neue
  policy ist dann gerade **nicht** angewendet; aktive handles/regeln prüfen und
  keinen unkontrollierten delete-and-reload über eine remoteverbindung versuchen.
- die host-firewall blockiert INPUT/FORWARD standardmäßig, ist aber kein
  vollständiges egress-policy-system. `strict`/`maximal` markieren die
  kill-switch-anforderung im offline-plan ausdrücklich als offen. auf
  unterstützten zielen schließt erst `vpn-finalize` diese lücke mit der
  verifizierten app-/lockdown-konfiguration; auf anderen zielen bleibt sie bis
  zu einer separat reviewten manuellen WireGuard-/nftables-lösung ungelöst.
- der bibliotheksgenerator für manuelles WireGuard benötigt für eine
  fail-closed regel einen konkreten aktuellen relay-IP-endpunkt. der setup-plan
  verdrahtet und aktiviert diese regel derzeit nicht. relaywechsel würde eine
  neue geprüfte regel verlangen; obfuscation ist in diesem modus nicht
  verfügbar.
- das toolkit akzeptiert mit stand 2026-07-15 ausschließlich debian 12/13,
  ubuntu 24.04/25.10/26.04 und fedora 43/44 auf x86-64/ARM64 für die offizielle
  mullvad-app. die upstream-matrix ist zeitabhängig und vor späterer nutzung
  neu zu prüfen. arch ist nicht mullvad-maintained; NixOS/gentoo/LFS bleiben
  best-effort und werden von `vpn-finalize` abgewiesen.
- ein H2-lauf ist in v0.2.0rc1 nicht auf physischer hardware abgenommen. die
  rebootfeste boot-übergabe zwischen offline-/bootstrap-guard und mullvad-
  lockdown, reale DNS-eindämmung sowie secret-cleanup nach erfolg, abbruch und
  hartem prozessende bleiben offene hardware-nachweise. die nachfolgenden
  endlichen prüfungen sind sicherheitsgrenzen, aber keine vorweggenommene
  abnahme dieser punkte.
- die automatisierte vendor-installation akzeptiert nur ein receiptgebundenes
  `.deb` auf debian/ubuntu oder `.rpm` auf fedora. `verify-vendor` prüft eine
  detached OpenPGP-signatur mit einem einzelnen gepinnten schlüssel in einer
  gepinnten bubblewrap-sandbox. der receipt im format
  `umzug-vendor-verification-v4` wird bei `plan` mit unabhängig neu
  angegebenem fingerprint und `gpg`-/`gpgv`-/bubblewrap-hashes erneut
  kryptografisch bewiesen; das prüft trotzdem keine key-transparenz,
  widerrufsaktualität, reproducible builds oder vollständige native
  repository-metadaten.
- OpenVPN ist seit 15.01.2026 entfernt und wird nicht unterstützt.
- lockdown hat dokumentierte ausnahmen: mullvad-API-bootstrap, auf linux
  API-zugriff für root-prozesse, DHCP/NDP und optional LAN. „ausschließlich
  tunnelverkehr“ gilt daher nicht absolut für system-/bootstrap-verkehr.
- die management-UDS ist upstream standardmäßig nicht auf eine dedizierte
  gruppe begrenzt. auf akzeptierten systemd-zielen nimmt der toolkit-plan eine
  leere managementgruppe und den override als bestätigungspflichtige aktionen
  auf. ohne erfolgreich angewendeten override verweigert `vpn-finalize` den
  login; nicht-systemd-ziele erhalten diese automation nicht. das generierte
  drop-in leert mit einem ersten `Environment=` frühere environment-
  zuweisungen und setzt danach nur managementgruppe und `UMask=0077`. der
  finalizer verlangt über eine root-owned, linkfreie elternkette exakt diese
  bytes in einer regulären root-owned single-link-datei mit modus 0644 oder
  strenger. die prüfung
  umfasst effektive systemd-werte und die reale, nofollow/root-owned und auf
  1 MiB begrenzte `/proc/<MainPID>/environ` bei stabiler PID. exakt die
  erwartete `MULLVAD_MANAGEMENT_SOCKET_GROUP` ist zulässig; weitere
  `MULLVAD_*`, alle `TALPID_*`/`LD_*`/`DYLD_*` sowie proxy-, CA- und
  shell-start-overrides werden abgewiesen. dazu kommen unerwünschte RPC-socket-
  overrides, gruppenmitgliedschaft und der tatsächlich erzeugte unix-socket.
  die liste bewertet nicht jede beliebige umgebungsvariable und bleibt gegen
  kompromittiertes root oder einen kompromittierten daemon wirkungslos.
- die reihenfolge „gruppe und drop-in vor paket“ schließt den ersten unit-load
  nur auf einem frischen ziel. bei einem bereits installierten oder laufenden
  mullvad-daemon kann bis zum receiptgebundenen neustart noch die alte
  unit-umgebung gelten. das toolkit automatisiert das vorherige sichere
  stoppen/entfernen dieses nicht-frischsystem-falls nicht; er erfordert lokalen
  konsolen-review.
- `vpn-finalize` akzeptiert am anfang nur den exakt geprüften offline-guard,
  bootstrap-guard oder bereits mullvad-lockdown plus strukturell geprüfte
  mullvad-nftables-policy; die host-firewall wird separat verifiziert. vor
  jedem daemon-restart installiert und prüft es
  `inet umzug_vpn_bootstrap_guard`, der allen egress außer loopback blockiert.
  das offline-guard-retirement darunter ist bei bereits fehlender tabelle
  idempotent. bei jedem gefangenen fehler werden bootstrap-guard und
  `umzug-offline-guard.service` per `enable --now` rebootfest reaktiviert
  und exakt verifiziert. scheitert auch das, ist eine geschlossene grenze nicht
  bewiesen; lokale emergency-recovery ist pflicht.
- mullvads `account-history.json` ist root-only, aber im klartext;
  `device.json` enthält kontobezogenen gerätezustand und privates WireGuard-
  schlüsselmaterial. der MVP verlangt vor jeder kontoeingabe den eindeutig
  positiven nachweis, dass der wirksame mount für `/etc/mullvad-vpn` durch die
  erkannte verschlüsselung abgedeckt ist. ein separates `/etc`-,
  `/etc/mullvad-vpn`- oder exaktes datei-mount auf `account-history.json`
  beziehungsweise `device.json` kann die heutige erkennung nicht separat
  beweisen und wird daher auch dann konservativ abgewiesen, wenn der betreiber
  es für verschlüsselt hält. FDE wird vom toolkit nicht eingerichtet.
- vor dem prompt werden vorhandene `account-history.json` und `device.json`,
  nach dem login beide dann zwingend vorhandenen dateien per `O_NOFOLLOW`
  geprüft. nur reguläre, root-owned dateien mit `nlink=1`, höchstens 1 MiB und
  modus 0600 oder strenger unter einer root-owned, nicht gruppen-/
  weltbeschreibbaren elternkette sind zulässig. das prüft typ und
  zugriffsschutz, weder inhalt noch nachträgliche verschlüsselung; ein bereits
  kompromittierter root-prozess kann die dateien weiterhin lesen oder ersetzen.
- die kontonummer gelangt wegen der offiziellen CLI kurzzeitig in deren argv.
  vor der TTY-abfrage verlangt der MVP deshalb einen echten procfs-mount auf
  `/proc` mit `hidepid=2` oder `hidepid=invisible` und ohne `gid=`-ausnahme.
  fehlendes oder uneindeutiges procfs wird fail-closed abgewiesen; die
  mountpolicy wird nicht automatisch eingerichtet. das schließt die normale
  lokale `/proc`-sicht, schützt aber nicht gegen root, kernel, privilegierte
  eBPF-/audit-beobachtung, speicherauslesung oder andere privilegierte kanäle.
  `hidepid` kann monitoring, debugger und einzelne desktop-/systemwerkzeuge
  beeinträchtigen und muss distributionsspezifisch nach jedem reboot geprüft
  werden.
- vor prompt und unmittelbar vor CLI-login verlangt der finalizer außerdem ein
  exakt leeres `kernel.core_pattern`, `kernel.core_uses_pid=0` und keinerlei
  aktiven eintrag in `/proc/swaps`. damit werden auch verschlüsselter swap und
  zram konservativ abgewiesen. ein systemd-coredump-pipehandler ist unzulässig,
  weil `RLIMIT_CORE=0` bei über pipes geleiteten core-dumps nicht
  hinreichend wirkt.
  `strict` und `maximal` rendern `fs.suid_dumpable=0`, ein leeres
  `kernel.core_pattern` und `kernel.core_uses_pid=0`; nicht-NixOS-pläne laden
  die sysctl-konfiguration bestätigt, NixOS verlangt modulimport und lokalen
  generationstest. der effektive zustand kann dennoch driften und wird deshalb
  erneut geprüft. swap wird nicht automatisch deaktiviert. abschaltung kann
  debugging, crashanalyse, hibernation und stabilität bei speicherdruck
  beeinträchtigen.
- der finalizer und sein offizielles CLI-kind setzen `RLIMIT_CORE` soft/hard
  auf `0` und `PR_SET_DUMPABLE=0`. das reduziert gewöhnliche dump-/ptrace-
  exposition, ist aber keine garantierte speicherlöschung und schützt nicht
  gegen root, kernel, privilegierte audit-/eBPF-mechanismen, DMA oder den
  hypervisor. python kann immutable zwischenkopien der kontonummer nicht
  nachweisbar überschreiben.
- der DNS-nachweis liest `/etc/resolv.conf` über einen größenbegrenzten,
  ersetzungsgeprüften FD aus einer geschützten root- oder exakt zugelassenen
  `systemd-resolved`-laufzeitkette. ist `resolvectl` bereits durch einen
  plan-receipt gebunden, ergänzt `resolvectl status` link- und
  upstream-evidenz; das programm installiert oder verlangt systemd-resolved
  hierfür nicht. es ermittelt jeden daraus ableitbaren literalen resolver und
  fragt dessen effektive
  root-route receiptgebunden mit `ip -j ... route get ... uid 0` ab. eine
  nicht-loopback-route darf nur über eine tatsächlich von `wg show interfaces`
  ausgewiesene WireGuard-NIC laufen; linkgebundene resolver auf geplantem
  ethernet, funk- oder anderen nicht-WireGuard-interfaces sowie unlesbare,
  nichtliterale, mehrdeutige oder während der sammlung wechselnde angaben
  brechen fail-closed ab. das ist eine sequenzielle momentaufnahme, keine
  atomare kernel-/resolved-transaktion: UID-/mark-/namespace-spezifische wege
  anderer prozesse, browser-DoH, eigene resolver und spätere races bleiben
  separat zu auditieren.
  ein statischer `resolv.conf`-pfad ohne `resolvectl` ist zulässig, wenn er
  einen nicht-loopback-resolver mit WireGuard-route ausweist. enthält die
  verfügbare evidenz ausschließlich einen loopback-stub, dessen upstream nicht
  sichtbar ist, bricht der finalizer statt einer unbelegten freigabe ab.
- vor der hostname-basierten mullvad-onlinebestätigung und erneut nach dem
  kontrollierten disconnect/reconnect versucht `vpn-finalize` auf **jeder**
  plan-gebundenen ethernet-NIC per `SO_BINDTODEVICE` UDP- und TCP-DNS zu den
  drei literalen externen resolvern `1.1.1.1`, `8.8.8.8` und `9.9.9.9`.
  beobachtbarer verkehr ist ein leak. zusätzlich wird eine strukturell
  erkennbare nftables-acceptregel für DNS auf einer solchen physischen NIC
  abgewiesen. die onlineabfrage darf erst nach diesen lokalen checks laufen.
  ein timeout ist lediglich eine negative endliche beobachtung und kein
  nachweis, dass kein paket gesendet wurde; auch drei ziele beweisen weder alle
  resolver noch DoT/DoH, andere protokolle, namespaces oder zeitabhängige
  regeländerungen. das auditfeld
  `finite_connected_dns_containment_checks_passed=true` behauptet ausdrücklich
  nicht mehr als diese begrenzte prüfung.
- `vpn-finalize` trennt nach dem ersten connect kontrolliert, prüft lockdown und
  verlangt für die effektive mullvad-OUTPUT-basiskette policy `drop`; indirekte
  beziehungsweise userspace-kontrollierte verdictpfade und bedingungsloses
  accept werden abgewiesen. das beweist nicht die tunnelbindung jeder bedingten
  accept-regel. über jedes plan-gebundene ethernet-interface folgen endliche
  mit `SO_BINDTODEVICE` gebundene rohe literal-IP-proben für TCP/80, TCP/443
  und UDP/53. TCP-refusal/-reset und jedes empfangene UDP-datagramm gelten
  bewusst als leak; unklassifizierte socketfehler brechen fail-closed ab. die
  proben können unbekannte
  protokolle, ziele, namespaces oder zeitabhängige leaks nicht formal
  ausschließen. ein gefangener fehler stellt bootstrap-guard und rebootfesten
  offline-guard wieder her und prüft beide exakt; misslingt dies, ist keine
  geschlossene grenze bewiesen und lokale emergency-recovery pflicht. das
  auditfeld
  `finite_fail_closed_disconnect_checks_passed=true` besagt ausschließlich,
  dass diese begrenzten prüfungen bestanden wurden.

## Bedienung und tests

- die oberfläche ist eine textbasierte argparse-/prompt-CLI, keine
  vollbildfähige TUI.
- `pack --expert` erweitert ausschließlich vorschau-/fundlisten. ein globaler
  expertenmodus und eine eigene fortschrittsanzeige über die schrittweisen
  CLI-ausgaben hinaus existieren nicht.
- pack unterstützt TOML für nichtinteraktive auswahl; hardening unterstützt
  ein eng validiertes TOML-profil. setup besitzt keine einzige vollständige
  ende-zu-ende-konfigurationsdatei: nichtinteraktives apply benötigt explizite
  action-ids und `--expected-plan-sha256`; mullvad-kontoeingabe bleibt bewusst
  TTY-only.
- actions mit manueller voraussetzung oder manueller post-reboot-prüfung können
  nicht nichtinteraktiv abgeschlossen werden. sie verlangen die angezeigte
  exakte attestierungsphrase am lokalen TTY; es gibt keinen config-bypass.
- tests decken nur die in [TESTING.md](TESTING.md) genannten module ab. ein
  erfolgreicher unit-test ist kein nachweis für die firewallwirkung auf jeder
  kernel-/distribution-kombination.
- container eignen sich für parser, planner und statische regeln, nicht für
  realistische UEFI-, secure-boot-, TPM-, GPU-, initramfs- oder firewalltests.
  dafür sind wegwerfbare vms mit konsole erforderlich.
