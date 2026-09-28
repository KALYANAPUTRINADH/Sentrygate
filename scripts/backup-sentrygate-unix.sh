#!/bin/sh
set -eu
data_root=${SENTRYGATE_DATA_DIR:-$HOME/.local/share/SentryGate}
if [ "$(uname -s)" = Darwin ]; then data_root=${SENTRYGATE_DATA_DIR:-$HOME/.local/share/SentryGate}; fi
install_root=/opt/sentrygate
node="$install_root/runtime/sentrygate-node"
out=${1:?Usage: sh scripts/backup-sentrygate-unix.sh <backup-file>}
mkdir -p "$(dirname -- "$out")"
SENTRYGATE_STANDALONE=true SENTRYGATE_DATA_DIR="$data_root" SENTRYGATE_DB_PATH="$data_root/sentrygate.db" "$node" "$install_root/apps/api/scripts/backup-db.js" --out "$out"
printf 'Local backup created: %s\n' "$out"
