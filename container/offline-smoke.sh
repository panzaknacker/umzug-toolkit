#!/bin/sh
# build and run the smoke image with podman's network disabled.
set -eu

usage() {
    echo "Usage: $0 LOCAL_BASE_IMAGE EXPECTED_IMAGE_ID_SHA256" >&2
    echo "Both values must come from a separately authenticated local image; no image is pulled." >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
BASE_IMAGE=$1
EXPECTED_ID=$2
PODMAN_BIN=${PODMAN_BIN:-podman}
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
TEST_IMAGE=${UMZUG_TEST_IMAGE:-localhost/umzug-toolkit-smoke:offline}

case "$BASE_IMAGE" in
'' | -* | *[!a-zA-Z0-9._:/@-]*) usage ;;
esac
case "$EXPECTED_ID" in
sha256:*) EXPECTED_HEX=${EXPECTED_ID#sha256:} ;;
*) EXPECTED_HEX=$EXPECTED_ID ;;
esac
case "$EXPECTED_HEX" in
'' | *[!0-9a-fA-F]*) usage ;;
esac
[ "${#EXPECTED_HEX}" -eq 64 ] || usage
EXPECTED_HEX=$(printf '%s' "$EXPECTED_HEX" | tr 'A-F' 'a-f')

if ! command -v "$PODMAN_BIN" >/dev/null 2>&1; then
    echo "container-smoke: Podman is required for --pull=never semantics" >&2
    exit 2
fi

OBSERVED=$(
    "$PODMAN_BIN" image inspect --format '{{.Id}}' "$BASE_IMAGE" 2>/dev/null
) || {
    echo "container-smoke: base image is not present locally; refusing to pull: $BASE_IMAGE" >&2
    exit 2
}
OBSERVED_HEX=${OBSERVED#sha256:}
OBSERVED_HEX=$(printf '%s' "$OBSERVED_HEX" | tr 'A-F' 'a-f')
if [ "$OBSERVED_HEX" != "$EXPECTED_HEX" ]; then
    echo "container-smoke: local base-image ID does not match the authenticated pin" >&2
    echo "expected: sha256:$EXPECTED_HEX" >&2
    echo "observed: sha256:$OBSERVED_HEX" >&2
    exit 1
fi

"$PODMAN_BIN" build \
    --pull=never \
    --network=none \
    --no-cache \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    --file "$ROOT/container/Dockerfile" \
    --tag "$TEST_IMAGE" \
    "$ROOT"

"$PODMAN_BIN" run \
    --rm \
    --pull=never \
    --network=none \
    --read-only \
    --cap-drop=all \
    --security-opt=no-new-privileges \
    --pids-limit=512 \
    --memory=2g \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=1g \
    "$TEST_IMAGE"

echo "container-smoke: unit tests passed without a container network"
echo "container-smoke: this does not validate UEFI, hardware, host nftables, initramfs, or a real VPN"
