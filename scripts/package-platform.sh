#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out=${1:?Usage: sh scripts/package-platform.sh <new-output-directory>}
case "$(uname -s)" in Darwin) platform=macos ;; Linux) platform=linux ;; *) echo "Run this packager on macOS or Linux; it packages the current OS only." >&2; exit 2 ;; esac
node_cmd=$(command -v node)
node_bin=$($node_cmd -p 'process.execPath')
node_version=$($node_bin --version | sed 's/^v//')
major=${node_version%%.*}
[ "$major" -ge 24 ] || { echo 'Packaging requires Node.js 24+.' >&2; exit 2; }
[ ! -e "$out" ] || { echo 'Output path exists; choose a new directory.' >&2; exit 2; }
mkdir -p "$out"
for item in apps/api/src apps/api/scripts apps/web apps/agent/src apps/agent/scripts packages/shared scripts docs; do
  mkdir -p "$out/$(dirname "$item")"
  cp -R "$root/$item" "$out/$(dirname "$item")/"
done
cp "$root/package.json" "$root/README.md" "$root/.env.example" "$root/INSTALL-UNIX.md" "$out/"
mkdir -p "$out/runtime"
cp "$node_bin" "$out/runtime/sentrygate-node"
chmod 700 "$out/runtime/sentrygate-node"
archive="${out%/}.tar.gz"
tar -czf "$archive" -C "$out" .
printf 'Packaged %s build: %s\nArchive: %s\n' "$platform" "$out" "$archive"
