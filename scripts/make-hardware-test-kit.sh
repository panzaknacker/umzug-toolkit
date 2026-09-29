#!/bin/sh
# build a reviewed offline toolkit kit for a console-backed hardware test.
set -eu

umask 077
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
PYTHON_BIN=${PYTHON_BIN:-python3}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-1767225600}

usage() {
    echo "Usage: $0 NEW_OUTPUT_DIRECTORY" >&2
    echo "The output must not exist. No network access or dependency installation is performed." >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
OUTPUT=$1
case "$OUTPUT" in
'' | / | . | .. | */. | */..) usage ;;
esac
if [ -e "$OUTPUT" ] || [ -L "$OUTPUT" ]; then
    echo "hardware-test-kit: refusing to overwrite an existing path: $OUTPUT" >&2
    exit 2
fi
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "hardware-test-kit: Python interpreter not found: $PYTHON_BIN" >&2
    exit 2
fi

OUTPUT_PARENT=$(dirname -- "$OUTPUT")
OUTPUT_NAME=$(basename -- "$OUTPUT")
mkdir -p -- "$OUTPUT_PARENT"
OUTPUT_PARENT=$(CDPATH='' cd -- "$OUTPUT_PARENT" && pwd -P)
OUTPUT=$OUTPUT_PARENT/$OUTPUT_NAME
if [ -e "$OUTPUT" ] || [ -L "$OUTPUT" ]; then
    echo "hardware-test-kit: canonical output already exists: $OUTPUT" >&2
    exit 2
fi

STAGE=$(mktemp -d "$OUTPUT_PARENT/.umzug-hardware-test-kit.XXXXXX")
cleanup() {
    chmod -R u+w "$STAGE" 2>/dev/null || true
    rm -rf -- "$STAGE"
}
trap cleanup EXIT HUP INT TERM

export PIP_NO_INDEX=1
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PYTHONDONTWRITEBYTECODE=1
export SOURCE_DATE_EPOCH

"$ROOT/scripts/static-checks.sh"
mkdir -p -- "$STAGE/artifacts" "$STAGE/docs" "$STAGE/profiles" "$STAGE/rules"
"$ROOT/scripts/offline-build.sh" "$STAGE/artifacts"

for document in \
    README.md \
    LICENSE \
    docs/HARDWARE-TEST.md \
    docs/RECOVERY.md \
    docs/OFFLINE-BUILD.md \
    docs/USER-GUIDE.md \
    docs/THREAT-MODEL.md \
    docs/LIMITATIONS.md \
    docs/TESTING.md; do
    if [ -L "$ROOT/$document" ] || [ ! -f "$ROOT/$document" ]; then
        echo "hardware-test-kit: required regular source file is missing: $document" >&2
        exit 2
    fi
    case "$document" in
    docs/*) destination="$STAGE/docs/${document#docs/}" ;;
    *) destination="$STAGE/$document" ;;
    esac
    install -m 0644 -- "$ROOT/$document" "$destination"
done

for profile in compatible strict maximal; do
    source=$ROOT/profiles/$profile.toml
    if [ -L "$source" ] || [ ! -f "$source" ]; then
        echo "hardware-test-kit: required profile is missing: $source" >&2
        exit 2
    fi
    install -m 0644 -- "$source" "$STAGE/profiles/$profile.toml"
done
if [ -L "$ROOT/rules/umzug-core.yar" ] || [ ! -f "$ROOT/rules/umzug-core.yar" ]; then
    echo "hardware-test-kit: core YARA rules are unavailable" >&2
    exit 2
fi
install -m 0644 -- "$ROOT/rules/umzug-core.yar" "$STAGE/rules/umzug-core.yar"

"$PYTHON_BIN" -I -c '
import hashlib
import json
import os
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve(strict=True)
epoch = int(sys.argv[2])
rows = []
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if path.is_symlink():
        raise SystemExit(f"hardware-test-kit: symlink in staged kit: {path}")
    if not path.is_file():
        continue
    relative = path.relative_to(root).as_posix()
    if relative in {"MANIFEST.json", "SHA256SUMS"}:
        continue
    data = path.read_bytes()
    rows.append({"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
manifest = {
    "format": 1,
    "kind": "umzug-hardware-test-kit",
    "source_date_epoch": epoch,
    "files": rows,
    "authenticity_notice": (
        "This manifest and SHA256SUMS detect transport corruption only. "
        "Authenticate the SHA256SUMS digest plus the wheel and installer digests through an independent channel."
    ),
    "scanner_notice": (
        "ClamAV databases, external YARA packages, scanner binaries and their trust anchors are not bundled. "
        "A strict migration scan must remain blocked until independently authenticated offline material is configured."
    ),
}
encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
(root / "MANIFEST.json").write_bytes(encoded)

lines = []
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if path.is_file() and path.name != "SHA256SUMS":
        relative = path.relative_to(root).as_posix()
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n")
(root / "SHA256SUMS").write_text("".join(lines), encoding="ascii")
' "$STAGE" "$SOURCE_DATE_EPOCH"

chmod -R a-w,go-rwx "$STAGE"
chmod 0755 "$STAGE" "$STAGE/artifacts" "$STAGE/docs" "$STAGE/profiles" "$STAGE/rules"
chmod 0644 "$STAGE"/README.md "$STAGE"/LICENSE "$STAGE"/MANIFEST.json "$STAGE"/SHA256SUMS
chmod 0644 "$STAGE"/artifacts/* "$STAGE"/docs/* "$STAGE"/profiles/* "$STAGE"/rules/*
mv -- "$STAGE" "$OUTPUT"
trap - EXIT HUP INT TERM

echo "hardware-test-kit: created offline kit: $OUTPUT"
echo "hardware-test-kit: authenticate these three digests through an independent channel:"
"$PYTHON_BIN" -I -c '
import hashlib
from pathlib import Path
import sys
root = Path(sys.argv[1])
for relative in (
    "SHA256SUMS",
    "artifacts/umzug_toolkit-0.2.0rc1-py3-none-any.whl",
    "artifacts/umzug-offline-install.py",
):
    path = root / relative
    print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
' "$OUTPUT"
