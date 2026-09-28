#!/bin/sh
set -eu
[ "$(uname -s)" = Darwin ] || { echo 'Run this installer on macOS.' >&2; exit 2; }
exec "$(dirname -- "$0")/install-sentrygate-unix.sh" "$@"
