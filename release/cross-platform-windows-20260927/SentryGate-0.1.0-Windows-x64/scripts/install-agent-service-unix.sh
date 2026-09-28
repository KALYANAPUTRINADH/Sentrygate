#!/bin/sh
set -eu
case "$(uname -s)" in Darwin) platform=macos ;; Linux) platform=linux ;; *) echo 'Only macOS and Linux are supported by this script.' >&2; exit 2 ;; esac
install_root=/opt/sentrygate
node="$install_root/runtime/sentrygate-node"
[ -x "$node" ] || { echo 'Install the local SentryGate bundle first.' >&2; exit 2; }
data_root=/var/lib/sentrygate-agent
sudo mkdir -p "$data_root"
sudo chmod 700 "$data_root"
printf 'Enroll this computer in its local dashboard at http://127.0.0.1:4300 first.\n'
printf 'Paste the device ID and one-time credential only from this computer.\n'
sudo env SENTRYGATE_AGENT_DATA="$data_root" "$node" "$install_root/apps/agent/scripts/configure-agent-unix.mjs" "${1:?Usage: sh scripts/install-agent-service-unix.sh <local-device-guid>}"
if [ "$platform" = linux ]; then
  sudo mkdir -p /etc/systemd/system
  sudo tee /etc/systemd/system/sentrygate-agent.service >/dev/null <<EOF
[Unit]
Description=SentryGate Local Windows-compatible Host Metadata Agent
After=network.target

[Service]
Type=simple
Environment=SENTRYGATE_AGENT_CONFIG=$data_root/config.json
ExecStart=$node $install_root/apps/agent/src/agent.js
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=$data_root

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now sentrygate-agent.service
else
  sudo tee /Library/LaunchDaemons/local.sentrygate.agent.plist >/dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.sentrygate.agent</string>
<key>ProgramArguments</key><array><string>$node</string><string>$install_root/apps/agent/src/agent.js</string></array>
<key>EnvironmentVariables</key><dict><key>SENTRYGATE_AGENT_CONFIG</key><string>$data_root/config.json</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>$data_root/agent.log</string><key>StandardErrorPath</key><string>$data_root/agent.log</string>
</dict></plist>
EOF
  sudo chmod 644 /Library/LaunchDaemons/local.sentrygate.agent.plist
  sudo launchctl bootstrap system /Library/LaunchDaemons/local.sentrygate.agent.plist
fi
printf 'SentryGate agent service is installed. Firewall policy remains preview-only by default.\n'
