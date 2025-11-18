#!/usr/bin/env bash
# Simple deploy helper to install a systemd service for the backend.
# Usage: sudo ./deploy.sh /path/to/project [--venv /path/to/venv]

set -euo pipefail

PROJECT_DIR=${1:-$(pwd)}
VENV_DIR="${2:-}"

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
  echo "Usage: sudo $0 /absolute/path/to/project [path_to_python_venv]"
  exit 0
fi

if [ ! -d "$PROJECT_DIR" ]; then
  echo "Project dir not found: $PROJECT_DIR"
  exit 1
fi

SERVICE_NAME=network-monitor.service
UNIT_PATH="/etc/systemd/system/$SERVICE_NAME"

PYTHON_CMD="python3"
if [ -n "$VENV_DIR" ]; then
  PYTHON_CMD="$VENV_DIR/bin/python"
fi

# If there's a backend env file, use it in the systemd unit
if [ -f "$PROJECT_DIR/backend/backend.env" ]; then
  ENV_FILE="$PROJECT_DIR/backend/backend.env"
else
  ENV_FILE=""
fi

cat > "$UNIT_PATH" <<EOF
[Unit]
Description=Network Monitor Backend
After=network.target

[Service]
Type=simple
WorkingDirectory=$PROJECT_DIR/backend
EOF

if [ -n "$ENV_FILE" ]; then
  echo "EnvironmentFile=$ENV_FILE" >> "$UNIT_PATH"
fi

cat >> "$UNIT_PATH" <<EOF
ExecStart=$PYTHON_CMD -m uvicorn backend.app:app --host 0.0.0.0 --port 3000
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now $SERVICE_NAME

echo "Service $SERVICE_NAME installed and started."
echo "Check status: systemctl status $SERVICE_NAME"
