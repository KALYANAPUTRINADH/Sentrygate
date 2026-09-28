#!/bin/sh
set -eu
case "$(uname -s)" in Darwin) platform=macos ;; Linux) platform=linux ;; *) echo 'Only macOS and Linux are supported here.' >&2; exit 2 ;; esac
if [ "$platform" = linux ]; then
  systemctl --user disable --now sentrygate.service || true
  sudo systemctl disable --now sentrygate-agent.service || true
  sudo rm -f /etc/systemd/system/sentrygate-agent.service
  systemctl --user daemon-reload
  if [ -f "$HOME/.local/share/SentryGate/runtime/linger-enabled-by-sentrygate" ]; then sudo loginctl disable-linger "$(id -un)"; rm -f "$HOME/.local/share/SentryGate/runtime/linger-enabled-by-sentrygate"; fi
  if command -v nft >/dev/null 2>&1 && table=$(sudo nft list table inet sentrygate 2>/dev/null); then
    printf '%s\n' "$table" | grep -q 'comment "SentryGate:owned"' || { echo 'Refusing to remove an nftables table without the SentryGate ownership marker.' >&2; exit 1; }
    printf '%s\n' "$table" | awk '/^[[:space:]]*chain / && $2 != "input" { exit 1 } /# handle/ && $0 !~ /SentryGate:/ { exit 1 }' || { echo 'Refusing to remove an nftables table containing unowned chains or rules.' >&2; exit 1; }
    sudo nft delete table inet sentrygate
  fi
else
  sudo launchctl bootout system/local.sentrygate.dashboard 2>/dev/null || true
  sudo launchctl bootout system/local.sentrygate.agent 2>/dev/null || true
  sudo rm -f /Library/LaunchDaemons/local.sentrygate.dashboard.plist
  sudo rm -f /Library/LaunchDaemons/local.sentrygate.agent.plist
fi
printf 'Remove application files under /opt/sentrygate? [y/N] '
read answer
if [ "$answer" = y ] || [ "$answer" = Y ]; then sudo rm -rf /opt/sentrygate; fi
printf 'Delete this computer\047s local settings, database, reports, and credentials? Type DELETE DATA: '
read answer
if [ "$answer" = 'DELETE DATA' ]; then
  rm -rf "$HOME/.local/share/SentryGate" "$HOME/Library/Application Support/SentryGate"
  sudo rm -rf /var/lib/sentrygate-agent
else
  printf 'Data preserved in the local SentryGate directories.\n'
fi
