#!/bin/sh
set -eu
bundle=$(CDPATH= cd -- "${1:?Usage: sh scripts/update-sentrygate-unix.sh <extracted-new-bundle>}" && pwd)
case "$(uname -s)" in Darwin) platform=macos ;; Linux) platform=linux ;; *) echo 'Only macOS and Linux update packages are supported here.' >&2; exit 2 ;; esac
[ -x "$bundle/runtime/sentrygate-node" ] || { echo 'Bundle must have been built on the same OS and include its runtime.' >&2; exit 2; }
install_root=/opt/sentrygate
data_root="$HOME/.local/share/SentryGate"
if [ "$platform" = macos ]; then data_root="$HOME/.local/share/SentryGate"; fi
stamp=$(date +%Y%m%d-%H%M%S)
backup="$HOME/SentryGate-backup-$stamp.db"
"$(dirname -- "$0")/backup-sentrygate-unix.sh" "$backup"
if [ "$platform" = linux ]; then
  systemctl --user stop sentrygate.service || true
  sudo systemctl stop sentrygate-agent.service || true
else
  sudo launchctl bootout system/local.sentrygate.dashboard 2>/dev/null || true
  sudo launchctl bootout system/local.sentrygate.agent 2>/dev/null || true
fi
stage="${install_root}.new-$stamp"
old="${install_root}.old-$stamp"
sudo mkdir -p "$stage"
for item in apps packages scripts docs; do sudo cp -R "$bundle/$item" "$stage/"; done
sudo cp "$bundle/package.json" "$stage/"
sudo mkdir -p "$stage/runtime"
sudo cp "$bundle/runtime/sentrygate-node" "$stage/runtime/"
sudo chmod 755 "$stage/runtime/sentrygate-node"
sudo mv "$install_root" "$old"
if ! sudo mv "$stage" "$install_root"; then sudo mv "$old" "$install_root"; echo 'Update failed; old installation restored.' >&2; exit 1; fi
if [ "$platform" = linux ]; then
  systemctl --user daemon-reload
  systemctl --user start sentrygate.service
  sudo systemctl start sentrygate-agent.service
else
  sudo launchctl bootstrap system /Library/LaunchDaemons/local.sentrygate.dashboard.plist
  sudo launchctl bootstrap system /Library/LaunchDaemons/local.sentrygate.agent.plist
fi
printf 'Updated offline. Previous files: %s; database backup: %s\n' "$old" "$backup"
