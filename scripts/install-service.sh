#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
if [[ -f "${PROJECT_ROOT}/honeypot" ]]; then
  BIN_SOURCE="${PROJECT_ROOT}/honeypot"
else
  BIN_SOURCE="${PROJECT_ROOT}/target/release/honeypot"
fi
CONFIG_SOURCE=""
DEFAULT_CONFIG="${PROJECT_ROOT}/packaging/config.toml"
UNIT_SOURCE="${PROJECT_ROOT}/packaging/honeypot.service"
README_SOURCE="${PROJECT_ROOT}/README.md"
START_SERVICE=0

usage() {
  cat <<'EOF'
Usage: sudo scripts/install-service.sh [options]

Options:
  --bin PATH       Path to compiled honeypot binary. Default: target/release/honeypot
  --config PATH    Config file to install as /etc/honeypot/config.toml.
                   If omitted, the existing config is preserved or a production template is installed.
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
BIN_SOURCE="$(realpath "${BIN_SOURCE}")"

if [[ -n "${CONFIG_SOURCE}" ]]; then
  if [[ ! -f "${CONFIG_SOURCE}" ]]; then
    echo "Config not found: ${CONFIG_SOURCE}" >&2
    exit 1
  fi
  CONFIG_SOURCE="$(realpath "${CONFIG_SOURCE}")"
fi

for required_source in "${UNIT_SOURCE}" "${README_SOURCE}"; do
  if [[ ! -f "${required_source}" ]]; then
    echo "Required installation file not found: ${required_source}" >&2
    exit 1
  fi
done
if [[ -z "${CONFIG_SOURCE}" && ! -f /etc/honeypot/config.toml && ! -f "${DEFAULT_CONFIG}" ]]; then
  echo "Production config template not found: ${DEFAULT_CONFIG}" >&2
  exit 1
fi

CONFIG_TO_VALIDATE="${CONFIG_SOURCE}"
if [[ -z "${CONFIG_TO_VALIDATE}" && -f /etc/honeypot/config.toml ]]; then
  CONFIG_TO_VALIDATE=/etc/honeypot/config.toml
fi
if [[ -n "${CONFIG_TO_VALIDATE}" ]]; then
  "${BIN_SOURCE}" --config "${CONFIG_TO_VALIDATE}" --check-config
elif [[ "${START_SERVICE}" -eq 1 ]]; then
  echo "Refusing to start with the placeholder password in the production template." >&2
  echo "Provide a validated config with --config PATH." >&2
  exit 1
fi

BACKUP_DIR="$(mktemp -d)"
INSTALLATION_STARTED=0
INSTALLATION_COMMITTED=0
WAS_ENABLED=0
WAS_ACTIVE=0
if systemctl is-enabled --quiet honeypot.service 2>/dev/null; then
  WAS_ENABLED=1
fi
if systemctl is-active --quiet honeypot.service 2>/dev/null; then
  WAS_ACTIVE=1
fi

backup_path() {
  local path="$1"
  local name="$2"
  if [[ -e "${path}" ]]; then
    cp -a -- "${path}" "${BACKUP_DIR}/${name}"
  else
    touch "${BACKUP_DIR}/${name}.absent"
  fi
}

restore_path() {
  local path="$1"
  local name="$2"
  if [[ -f "${BACKUP_DIR}/${name}.absent" ]]; then
    rm -f -- "${path}"
  else
    cp -a -- "${BACKUP_DIR}/${name}" "${path}"
  fi
}

rollback_installation() {
  echo "Restoring the previous honeypot installation." >&2
  systemctl stop honeypot.service >/dev/null 2>&1 || true
  restore_path /usr/local/bin/honeypot honeypot
  restore_path /etc/systemd/system/honeypot.service honeypot.service
  restore_path /etc/honeypot/config.toml config.toml
  restore_path /etc/honeypot/README.md README.md
  systemctl daemon-reload || true
  if [[ "${WAS_ENABLED}" -eq 1 ]]; then
    systemctl enable honeypot.service || true
  else
    systemctl disable honeypot.service >/dev/null 2>&1 || true
  fi
  if [[ "${WAS_ACTIVE}" -eq 1 ]]; then
    systemctl restart honeypot.service || true
  fi
}

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "${INSTALLATION_STARTED}" -eq 1 && "${INSTALLATION_COMMITTED}" -eq 0 ]]; then
    set +e
    rollback_installation
  fi
  rm -rf -- "${BACKUP_DIR:?}"
  exit "${status}"
}
trap cleanup EXIT

backup_path /usr/local/bin/honeypot honeypot
backup_path /etc/systemd/system/honeypot.service honeypot.service
backup_path /etc/honeypot/config.toml config.toml
backup_path /etc/honeypot/README.md README.md

INSTALLATION_STARTED=1
install -d -m 0755 /usr/local/bin
install -d -m 0700 /etc/honeypot
install -d -m 0750 /var/lib/honeypot
install -d -m 0750 /var/log/honeypot

install -m 0755 "${BIN_SOURCE}" /usr/local/bin/honeypot
install -m 0644 "${UNIT_SOURCE}" /etc/systemd/system/honeypot.service
install -m 0644 "${README_SOURCE}" /etc/honeypot/README.md

if [[ -n "${CONFIG_SOURCE}" ]]; then
  install -m 0600 "${CONFIG_SOURCE}" /etc/honeypot/config.toml
elif [[ ! -f /etc/honeypot/config.toml ]]; then
  install -m 0600 "${DEFAULT_CONFIG}" /etc/honeypot/config.toml
  echo "Installed the systemd configuration template to /etc/honeypot/config.toml."
  echo "Set admin.password before starting the service."
fi

systemctl daemon-reload
systemctl enable honeypot.service

if [[ "${START_SERVICE}" -eq 1 ]]; then
  if ! systemctl restart honeypot.service; then
    echo "The new service failed to start." >&2
    exit 1
  fi
  systemctl --no-pager --full status honeypot.service
else
  echo "Installed and enabled honeypot.service."
  echo "Validate and edit /etc/honeypot/config.toml, then run: sudo systemctl start honeypot.service"
fi
INSTALLATION_COMMITTED=1
