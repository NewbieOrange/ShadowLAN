#!/usr/bin/env bash
# Build the linux + windows release packages from the working tree.
# The two version stamps (common.VERSION + SHADOWLAN_VERSION) must be
# set to the new rc number and the binaries rebuilt BEFORE running
# (see the version policy in AGENTS.md). Every artifact is listed
# explicitly and a leakage guard runs last, so platform files can
# never cross between packages.
set -euo pipefail
cd "$(dirname "$0")"
V="$(python3 -c 'import common; print(common.VERSION)')"
STAMP="$(strings hook/lan_hook64.dll | grep -m1 -- "$V" || true)"
[ "$STAMP" = "$V" ] || {
    echo "hook binaries not stamped $V - stamp + rebuild first"; exit 1; }

PY="common.py wclient.py server.py"
DOC="README.md LICENSE AGENTS.md game.example.json"

rm -rf build/pkg_lnx build/pkg_win
mkdir -p build/pkg_lnx build/pkg_win

cp $DOC $PY build/pkg_lnx/
cp hook/README.md build/pkg_lnx/HOOK_README.md
cp hook/lan_hook.so build/pkg_lnx/

cp $DOC $PY build/pkg_win/
cp hook/README.md build/pkg_win/HOOK_README.md
cp hook/lan_hook64.dll hook/lan_hook32.dll hook/injector.exe build/pkg_win/

DIST="$(cd "${DIST_DIR:-dist}" && pwd)"
OUT="${DIST}/shadowlan-v${V}"
rm -f "${OUT}-linux-amd64.tar.gz" "${OUT}-windows-amd64.zip"
tar czf "${OUT}-linux-amd64.tar.gz" -C build/pkg_lnx .
(cd build/pkg_win && zip -q "${OUT}-windows-amd64.zip" *)

if unzip -l "${OUT}-windows-amd64.zip" | grep -q lan_hook.so; then
    echo "GUARD: windows package contains lan_hook.so"; exit 1; fi
if tar tzf "${OUT}-linux-amd64.tar.gz" | grep -qE '\.dll|injector\.exe'; then
    echo "GUARD: linux package contains windows binaries"; exit 1; fi
echo "packed v$V"
ls -la --time-style=+%H:%M "${OUT}-linux-amd64.tar.gz" "${OUT}-windows-amd64.zip"
