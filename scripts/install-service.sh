#!/usr/bin/env bash
set -euo pipefail

BIN_SOURCE="target/release/honeypot"
CONFIG_SOURCE=""
START_SERVICE=0

usage() {
  cat <<'EOF'
Usage: sudo scripts/install-service.sh [options]

Options:
  --bin PATH       Path to compiled honeypot binary. Default: target/release/honeypot
  --config PATH    Config file to install as /etc/honeypot/config.toml.
                   If omitted, config.example.toml is installed when no config exists yet.
  --start          Start or restart honeypot.service after installation.
  -h, --help       Show this help.

Examples:
  cargo build --release
  sudo scripts/install-service.sh --config config.toml
  sudo scripts/install-service.sh --config config.toml --start
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)
      BIN_SOURCE="${2:?missing value for --bin}"
      shift 2
      ;;
    --config)
      CONFIG_SOURCE="${2:?missing value for --config}"
      shift 2
      ;;
    --start)
      START_SERVICE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "This installer must run as root because it writes /usr/local/bin, /etc, and systemd units." >&2
  exit 1
fi

if [[ ! -f "${BIN_SOURCE}" ]]; then
  echo "Binary not found: ${BIN_SOURCE}" >&2
  echo "Run: cargo build --release" >&2
  exit 1
fi

install -d -m 0755 /usr/local/bin
install -d -m 0700 /etc/honeypot
install -d -m 0750 /var/lib/honeypot
install -d -m 0750 /var/log/honeypot

install -m 0755 "${BIN_SOURCE}" /usr/local/bin/honeypot
install -m 0644 packaging/honeypot.service /etc/systemd/system/honeypot.service
install -m 0644 README.md /etc/honeypot/README.md

if [[ -n "${CONFIG_SOURCE}" ]]; then
  if [[ ! -f "${CONFIG_SOURCE}" ]]; then
    echo "Config not found: ${CONFIG_SOURCE}" >&2
    exit 1
  fi
  install -m 0600 "${CONFIG_SOURCE}" /etc/honeypot/config.toml
elif [[ ! -f /etc/honeypot/config.toml ]]; then
  install -m 0600 config.example.toml /etc/honeypot/config.toml
  echo "Installed config.example.toml to /etc/honeypot/config.toml."
  echo "Edit admin.password and deployment paths before starting the service."
fi

systemctl daemon-reload
systemctl enable honeypot.service

if [[ "${START_SERVICE}" -eq 1 ]]; then
  systemctl restart honeypot.service
  systemctl --no-pager --full status honeypot.service
else
  echo "Installed and enabled honeypot.service."
  echo "Edit /etc/honeypot/config.toml, then run: sudo systemctl start honeypot.service"
fi
