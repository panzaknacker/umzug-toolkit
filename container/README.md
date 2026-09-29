# Netzloser container-smoke-test

der container prüft python-parser, planer, das wheel-backend und unit-tests. er
ist **kein** nachweis für hardwareerkennung, secure boot, TPM, initramfs,
host-`nftables` oder einen realen VPN-kill-switch. container teilen sich
wesentliche teile des host-kernels.

es gibt bewusst kein standard-basisimage und keinen installationsschritt im
dockerfile. das basisimage muss python 3.11 oder neuer und `pytest` bereits
enthalten, lokal vorhanden und über einen unabhängigen kanal authentifiziert
sein. ein tag allein ist kein vertrauensanker.

lokale image-ID ermitteln und gegen den zuvor authentifizierten wert prüfen:

```sh
podman image inspect --format '{{.Id}}' REGISTRY/IMAGE@sha256:MANIFEST_DIGEST
```

dann ohne pull und ohne netzwerk bauen und testen:

```sh
./container/offline-smoke.sh \
  REGISTRY/IMAGE@sha256:MANIFEST_DIGEST \
  sha256:LOKALE_IMAGE_ID
```

`MANIFEST_DIGEST` und `LOKALE_IMAGE_ID` sind in der befehlsdarstellung
absichtlich metavariablen, keine mitgelieferten oder vertrauenswürdigen werte.
das skript akzeptiert die image-ID nur als exakt 64-stelligen hexwert und
bricht bei abweichung ab. podman wird verwendet, weil `--pull=never` für build
und run explizit unterstützt wird. der test läuft read-only, ohne capabilities,
mit `no-new-privileges`, begrenzten prozessen und einem privaten `noexec`-`/tmp`.

eine kompromittierte container-engine oder ein kompromittierter host kann
diese isolation umgehen. für firewall-, reboot- und hardwaretests eine
wegwerfbare VM mit lokaler konsole verwenden.
