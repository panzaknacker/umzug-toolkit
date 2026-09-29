#!/bin/sh
# boot an authenticated local VM image in a disposable, networkless QEMU run.
set -eu

usage() {
    echo "Usage: $0 DISK_IMAGE DISK_SHA256 QEMU_BINARY_SHA256 [raw|qcow2]" >&2
    echo "QEMU_BIN defaults to qemu-system-x86_64; every digest must be authenticated independently." >&2
    exit 2
}

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || usage
DISK=$1
EXPECTED_DISK=$2
EXPECTED_QEMU=$3
DISK_FORMAT=${4:-qcow2}
QEMU_BIN=${QEMU_BIN:-qemu-system-x86_64}
MACHINE=${UMZUG_QEMU_MACHINE:-q35,accel=kvm:tcg}
MEMORY_MB=${UMZUG_QEMU_MEMORY_MB:-4096}
CPUS=${UMZUG_QEMU_CPUS:-2}

case "$DISK_FORMAT" in raw | qcow2) ;; *) usage ;; esac
case "$MEMORY_MB:$CPUS" in *[!0-9:]* | :*) usage ;; esac
EXPECTED_DISK=${EXPECTED_DISK#sha256:}
EXPECTED_QEMU=${EXPECTED_QEMU#sha256:}
case "$EXPECTED_DISK:$EXPECTED_QEMU" in *[!0-9a-fA-F:]* | :) usage ;; esac
[ "${#EXPECTED_DISK}" -eq 64 ] || usage
[ "${#EXPECTED_QEMU}" -eq 64 ] || usage
EXPECTED_DISK=$(printf '%s' "$EXPECTED_DISK" | tr 'A-F' 'a-f')
EXPECTED_QEMU=$(printf '%s' "$EXPECTED_QEMU" | tr 'A-F' 'a-f')

case "$DISK" in
*','* | *'
'*)
    echo "qemu-smoke: commas and newlines are not allowed in disk paths" >&2
    exit 2
    ;;
esac
if [ -L "$DISK" ] || [ ! -f "$DISK" ]; then
    echo "qemu-smoke: disk must be a regular, non-symlink file" >&2
    exit 2
fi
QEMU_PATH=$(command -v "$QEMU_BIN" 2>/dev/null) || {
    echo "qemu-smoke: QEMU executable not found: $QEMU_BIN" >&2
    exit 2
}
if [ -L "$QEMU_PATH" ]; then
    QEMU_PATH=$(readlink -f -- "$QEMU_PATH")
fi
if [ ! -f "$QEMU_PATH" ]; then
    echo "qemu-smoke: QEMU path is not a regular file: $QEMU_PATH" >&2
    exit 2
fi

hash_file() {
    python3 -I -c \
        'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
        "$1"
}

OBSERVED_DISK=$(hash_file "$DISK")
OBSERVED_QEMU=$(hash_file "$QEMU_PATH")
if [ "$OBSERVED_DISK" != "$EXPECTED_DISK" ]; then
    echo "qemu-smoke: disk image hash mismatch" >&2
    exit 1
fi
if [ "$OBSERVED_QEMU" != "$EXPECTED_QEMU" ]; then
    echo "qemu-smoke: QEMU binary hash mismatch" >&2
    exit 1
fi

set -- \
    "$QEMU_PATH" \
    -name umzug-offline-smoke \
    -machine "$MACHINE" \
    -m "$MEMORY_MB" \
    -smp "$CPUS" \
    -drive "file=$DISK,format=$DISK_FORMAT,if=virtio,snapshot=on,cache=none" \
    -nic none \
    -snapshot \
    -no-reboot \
    -display none \
    -serial mon:stdio

if [ -n "${UMZUG_UEFI_CODE:-}" ]; then
    [ -n "${UMZUG_UEFI_CODE_SHA256:-}" ] || {
        echo "qemu-smoke: UMZUG_UEFI_CODE_SHA256 is mandatory when UEFI code is supplied" >&2
        exit 2
    }
    if [ -L "$UMZUG_UEFI_CODE" ] || [ ! -f "$UMZUG_UEFI_CODE" ]; then
        echo "qemu-smoke: UEFI code must be a regular, non-symlink file" >&2
        exit 2
    fi
    case "$UMZUG_UEFI_CODE" in
    *','* | *'
'*)
        echo "qemu-smoke: commas and newlines are not allowed in UEFI paths" >&2
        exit 2
        ;;
    esac
    UEFI_EXPECTED=${UMZUG_UEFI_CODE_SHA256#sha256:}
    UEFI_EXPECTED=$(printf '%s' "$UEFI_EXPECTED" | tr 'A-F' 'a-f')
    case "$UEFI_EXPECTED" in '' | *[!0-9a-f]*) usage ;; esac
    [ "${#UEFI_EXPECTED}" -eq 64 ] || usage
    [ "$(hash_file "$UMZUG_UEFI_CODE")" = "$UEFI_EXPECTED" ] || {
        echo "qemu-smoke: UEFI firmware hash mismatch" >&2
        exit 1
    }
    set -- "$@" -drive "if=pflash,format=raw,readonly=on,file=$UMZUG_UEFI_CODE"
fi

echo "qemu-smoke: verified image and QEMU; starting with no virtual NIC and temporary disk writes"
echo "qemu-smoke: quit from the QEMU monitor with Ctrl-a c, then 'quit'"
exec "$@"
