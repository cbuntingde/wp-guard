#!/bin/bash
# systemd service installer for wp-guard

set -e

echo "Installing wp-guard systemd service..."

if [ "$EUID" -ne 0 ]; then
  echo "Run as root"
  exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/wp-guard"
CONFIG="$SCRIPT_DIR/wp-guard.yaml"

if [ ! -f "$BINARY" ]; then
  echo "Binary not found at $BINARY"
  exit 1
fi

# Copy binary
cp "$BINARY" /usr/local/bin/wp-guard
chmod +x /usr/local/bin/wp-guard

# Create user if not exists
id -u wp-guard &>/dev/null || useradd --system --no-create-home --disabled-login wp-guard

# Create directories
mkdir -p /etc/wp-guard
mkdir -p /var/log/wp-guard
mkdir -p /var/www/wp-guard-quarantine

# Copy config if it doesn't exist
if [ ! -f /etc/wp-guard/wp-guard.yaml ]; then
  if [ -f "$CONFIG" ]; then
    cp "$CONFIG" /etc/wp-guard/wp-guard.yaml
  fi
fi

# Create systemd unit
cat > /etc/systemd/system/wp-guard.service << EOF
[Unit]
Description=wp-guard WordPress file integrity monitor
After=network.target

[Service]
Type=simple
User=wp-guard
Group=www-data
ExecStart=/usr/local/bin/wp-guard run --config /etc/wp-guard/wp-guard.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/wp-guard /var/www/html
ReadWritePaths=/var/log/wp-guard /var/www/wp-guard-quarantine

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable
systemctl daemon-reload
systemctl enable wp-guard
echo "Done. Run 'systemctl start wp-guard' to start."