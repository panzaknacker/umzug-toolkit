# Wegwerfbarer QEMU-Smoke-Test

`qemu-smoke.sh` startet ein bereits installiertes Abbild ohne virtuelle
Netzwerkkarte und mit temporären Disk-Schreibvorgängen. Das Basisabbild bleibt
unverändert. Es werden keine Host-Verzeichnisse, USB-Geräte, Zwischenablagen
oder Guest-Agent-Sockets eingebunden.

Sowohl Abbild als auch das tatsächlich ausgeführte QEMU-Binary müssen mit einem
extern authentifizierten SHA-256 gepinnt werden:

```sh
sha256sum /pfad/zum/debian-test.qcow2 "$(command -v qemu-system-x86_64)"
./vm/qemu-smoke.sh \
  /pfad/zum/debian-test.qcow2 \
  DISK_SHA256 \
  QEMU_BINARY_SHA256 \
  qcow2
```

`DISK_SHA256` und `QEMU_BINARY_SHA256` sind Metavariablen und keine
Vertrauenswerte. Ein Hash beweist nur Bytegleichheit; seine erwartete Version
muss über eine geprüfte Signatur oder einen unabhängigen Kanal stammen.

Standardmäßig wird BIOS verwendet. Für UEFI muss eine schreibgeschützte
Firmware-Code-Datei ebenfalls gepinnt werden:

```sh
UMZUG_UEFI_CODE=/usr/share/OVMF/OVMF_CODE.fd \
UMZUG_UEFI_CODE_SHA256=AUTHENTIFIZIERTER_SHA256 \
./vm/qemu-smoke.sh IMAGE IMAGE_SHA256 QEMU_SHA256 qcow2
```

Der Lauf hat `-nic none`, `-snapshot`, keine grafische Anzeige und eine
serielle Konsole. Im Gast werden anschließend manuell ausgeführt:

```sh
./setup detect --json
./setup plan --profile strict --ethernet testeth0 \
  --output /tmp/umzug-plan.json
./setup apply /tmp/umzug-plan.json --state-dir /tmp/umzug-state --dry-run
./setup report --state-dir /tmp/umzug-state --output /tmp/umzug-report.json
```

`testeth0` ist in diesem ausdrücklich NIC-losen Harness nur ein synthetischer
Planner-/CLI-Testwert; den Plan niemals produktiv anwenden. Ohne explizites
`--ethernet` muss `plan` wegen des fehlenden physischen Ethernet-Interfaces
fail-closed abbrechen. Für eine reale Netzwerk-/Firewall-Abnahme eine zweite VM
mit zunächst getrenntem virtuellem Ethernet und dem tatsächlich geprüften
Interfacenamen verwenden. Die exakten Planparameter zeigt
`./setup plan --help`; Profile und Workspace müssen aus einem zuvor
verifizierten, schreibgeschützt eingebundenen Medium stammen.

Für eine schreibende Firewall-/Initramfs-Abnahme zuerst einen Hypervisor-
Snapshot und eine lokale Recovery-Konsole bereitstellen. Ein erfolgreicher
QEMU-Boot beweist weder Malwarefreiheit des Abbilds noch die Wirksamkeit auf
physischer Hardware. Die endgültige Mullvad-Verbindung wird in diesem
netzlosen Test bewusst nicht aufgebaut.
