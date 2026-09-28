#!/bin/sh
set -eu
source_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uname -s)" in Darwin) platform=macos ;; Linux) platform=linux ;; *) echo 'This installer supports macOS or Linux only.' >&2; exit 2 ;; esac
node_src="$source_root/runtime/sentrygate-node"
[ -x "$node_src" ] || { echo 'Bundled runtime is missing; use a package built on this target OS.' >&2; exit 2; }
node_version=$($node_src --version | sed 's/^v//')
[ "${node_version%%.*}" -ge 24 ] || { echo 'This SentryGate bundle requires its included Node.js 24+ runtime.' >&2; exit 2; }
install_root=/opt/sentrygate
data_root="$HOME/.local/share/SentryGate"
runtime_root="$data_root/Runtime"
if [ "$platform" = linux ]; then runtime_root="$data_root/runtime"; else runtime_root="$data_root/Runtime"; fi
if [ -e "$install_root" ]; then echo "$install_root already exists; use the documented offline update process." >&2; exit 2; fi
sudo mkdir -p "$install_root"
sudo cp -R "$source_root/apps" "$source_root/packages" "$source_root/scripts" "$source_root/docs" "$install_root/"
sudo cp "$source_root/package.json" "$install_root/"
sudo mkdir -p "$install_root/runtime"
sudo cp "$node_src" "$install_root/runtime/sentrygate-node"
sudo chmod 755 "$install_root/runtime/sentrygate-node"
mkdir -p "$data_root" "$runtime_root"
chmod 700 "$data_root" "$runtime_root"
if [ "$platform" = linux ]; then
  unit_dir="$HOME/.config/systemd/user"
  mkdir -p "$unit_dir"
  cat > "$unit_dir/sentrygate.service" <<EOF
[Unit]
Description=SentryGate Local Dashboard and Backend
After=network.target

[Service]
Type=simple
Environment=SENTRYGATE_STANDALONE=true
Environment=SENTRYGATE_DATA_DIR=$data_root
Environment=SENTRYGATE_RUNTIME_DIR=$runtime_root
ExecStart=$install_root/runtime/sentrygate-node $install_root/scripts/local-server.mjs
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$data_root

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now sentrygate.service
  if command -v loginctl >/dev/null 2>&1 && ! loginctl show-user "$(id -un)" -p Linger | grep -q 'Linger=yes'; then
    sudo loginctl enable-linger "$(id -un)"
    : > "$runtime_root/linger-enabled-by-sentrygate"
  fi
else
  cat <<EOF | sudo tee /Library/LaunchDaemons/local.sentrygate.dashboard.plist >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.sentrygate.dashboard</string>
<key>UserName</key><string>$(id -un)</string>
<key>ProgramArguments</key><array><string>$install_root/runtime/sentrygate-node</string><string>$install_root/scripts/local-server.mjs</string></array>
<key>EnvironmentVariables</key><dict><key>SENTRYGATE_STANDALONE</key><string>true</string><key>SENTRYGATE_DATA_DIR</key><string>$data_root</string><key>SENTRYGATE_RUNTIME_DIR</key><string>$runtime_root</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>$runtime_root/dashboard.log</string><key>StandardErrorPath</key><string>$runtime_root/dashboard.log</string>
</dict></plist>
EOF
  sudo chmod 644 /Library/LaunchDaemons/local.sentrygate.dashboard.plist
  sudo launchctl bootstrap system /Library/LaunchDaemons/local.sentrygate.dashboard.plist
fi
printf 'SentryGate dashboard service installed (%s). Open http://127.0.0.1:4300 and create this computer\047s administrator.\n' "$platform"
printf 'Data: %s\nInstaller: %s\n' "$data_root" "$install_root"
