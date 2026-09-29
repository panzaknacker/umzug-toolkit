#!/bin/sh
# local checks only.  this script contains no dependency installation step.
set -eu

umask 077
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
PYTHON_BIN=${PYTHON_BIN:-python3}
TMP_BASE=${TMPDIR:-/tmp}
CHECK_TMP=$(mktemp -d "$TMP_BASE/umzug-static-checks.XXXXXX")
cleanup() {
    chmod -R u+w "$CHECK_TMP" 2>/dev/null || true
    rm -rf -- "$CHECK_TMP"
}
trap cleanup EXIT HUP INT TERM

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "static-checks: Python interpreter not found: $PYTHON_BIN" >&2
    exit 2
fi

export PIP_NO_INDEX=1
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PYTHONDONTWRITEBYTECODE=1

"$PYTHON_BIN" -I -c '
import ast
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for path in sorted((*root.joinpath("src").rglob("*.py"), *root.joinpath("build_backend").rglob("*.py"), *root.joinpath("tests").rglob("*.py"), root / "scripts/offline-install.py")):
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
' "$ROOT"

for script in \
    "$ROOT/scripts/offline-build.sh" \
    "$ROOT/scripts/umzug-setup-root" \
    "$ROOT/scripts/make-hardware-test-kit.sh" \
    "$ROOT/scripts/static-checks.sh" \
    "$ROOT/container/offline-smoke.sh" \
    "$ROOT/vm/qemu-smoke.sh"; do
    sh -n "$script"
done

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck \
        "$ROOT/scripts/offline-build.sh" \
        "$ROOT/scripts/umzug-setup-root" \
        "$ROOT/scripts/make-hardware-test-kit.sh" \
        "$ROOT/scripts/static-checks.sh" \
        "$ROOT/container/offline-smoke.sh" \
        "$ROOT/vm/qemu-smoke.sh"
else
    echo "static-checks: shellcheck not installed; syntax was still checked with sh -n" >&2
fi

if command -v yarac >/dev/null 2>&1; then
    yarac "$ROOT/rules/umzug-core.yar" "$CHECK_TMP/umzug-core.yarc"
else
    echo "static-checks: yarac not installed; YARA compilation check skipped" >&2
fi

SOURCE_DATE_EPOCH=1767225600 \
    "$ROOT/scripts/offline-build.sh" "$CHECK_TMP/wheels"

cd -- "$ROOT"
"$PYTHON_BIN" -m pytest -q -p no:cacheprovider

if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$ROOT" diff --check
fi

echo "static-checks: all available offline checks passed"
