#!/bin/sh
set -eu
[ "$(uname -s)" = Linux ] || { echo 'Run this installer on Linux.' >&2; exit 2; }
exec "$(dirname -- "$0")/install-sentrygate-unix.sh" "$@"
