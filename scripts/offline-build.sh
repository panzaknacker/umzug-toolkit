#!/bin/sh
# build the pure-python wheel twice without a package index and compare bytes.
set -eu

umask 077
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
OUTPUT_DIR=${1:-"$ROOT/dist"}
PYTHON_BIN=${PYTHON_BIN:-python3}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1767225600}

case "$SOURCE_DATE_EPOCH" in
'' | *[!0-9]*)
    echo "offline-build: SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 2
    ;;
esac

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "offline-build: Python interpreter not found: $PYTHON_BIN" >&2
    exit 2
fi
if [ -L "$OUTPUT_DIR" ]; then
    echo "offline-build: refusing a symlink output directory: $OUTPUT_DIR" >&2
    exit 2
fi

TMP_BASE=${TMPDIR:-/tmp}
BUILD_TMP=$(mktemp -d "$TMP_BASE/umzug-offline-build.XXXXXX")
cleanup() {
    chmod -R u+w "$BUILD_TMP" 2>/dev/null || true
    rm -rf -- "$BUILD_TMP"
}
trap cleanup EXIT HUP INT TERM

mkdir -p -- "$OUTPUT_DIR" "$BUILD_TMP/one" "$BUILD_TMP/two"

build_one() {
    destination=$1
    SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
        PIP_NO_INDEX=1 \
        PIP_DISABLE_PIP_VERSION_CHECK=1 \
        "$PYTHON_BIN" -I -c \
        'import sys; sys.path.insert(0, sys.argv[1]); import umzug_build; print(umzug_build.build_wheel(sys.argv[2]))' \
        "$ROOT/build_backend" "$destination"
}

build_one "$BUILD_TMP/one"
build_one "$BUILD_TMP/two"

WHEEL_NAME=umzug_toolkit-0.2.0rc1-py3-none-any.whl
INSTALLER_NAME=umzug-offline-install.py
FIRST="$BUILD_TMP/one/$WHEEL_NAME"
SECOND="$BUILD_TMP/two/$WHEEL_NAME"

"$PYTHON_BIN" -I -m zipfile -t "$FIRST" >/dev/null
"$PYTHON_BIN" -I -m zipfile -t "$SECOND" >/dev/null
if ! cmp -s -- "$FIRST" "$SECOND"; then
    echo "offline-build: two builds with the same epoch differ; refusing output" >&2
    exit 1
fi

FINAL="$OUTPUT_DIR/$WHEEL_NAME"
INSTALLER_SOURCE="$ROOT/scripts/offline-install.py"
INSTALLER_FINAL="$OUTPUT_DIR/$INSTALLER_NAME"

# validate the complete two-file publication set before writing either file.
# this prevents a stale installer from leaving a newly copied wheel beside an
# incompatible old artifact when the build correctly refuses the installer.
if [ -L "$FINAL" ]; then
    echo "offline-build: refusing to replace symlink: $FINAL" >&2
    exit 2
fi
if [ -e "$FINAL" ]; then
    if ! cmp -s -- "$FIRST" "$FINAL"; then
        echo "offline-build: refusing to overwrite a different existing wheel: $FINAL" >&2
        exit 2
    fi
fi
if [ -L "$INSTALLER_FINAL" ]; then
    echo "offline-build: refusing to replace symlink: $INSTALLER_FINAL" >&2
    exit 2
fi
if [ -e "$INSTALLER_FINAL" ]; then
    if ! cmp -s -- "$INSTALLER_SOURCE" "$INSTALLER_FINAL"; then
        echo "offline-build: refusing to overwrite a different existing installer: $INSTALLER_FINAL" >&2
        exit 2
    fi
fi

if [ ! -e "$FINAL" ]; then
    cp -- "$FIRST" "$FINAL"
    chmod 0644 "$FINAL"
fi
if [ ! -e "$INSTALLER_FINAL" ]; then
    cp -- "$INSTALLER_SOURCE" "$INSTALLER_FINAL"
    chmod 0644 "$INSTALLER_FINAL"
fi

DIGEST=$("$PYTHON_BIN" -I -c \
    'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
    "$FINAL")
printf '%s  %s\n' "$DIGEST" "$FINAL"
INSTALLER_DIGEST=$("$PYTHON_BIN" -I -c \
    'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
    "$INSTALLER_FINAL")
printf '%s  %s\n' "$INSTALLER_DIGEST" "$INSTALLER_FINAL"
echo "offline-build: byte-identical double build completed; authenticate both digests independently"
