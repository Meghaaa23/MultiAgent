#!/usr/bin/env bash
# =============================================================================
# SURFACE-40 Ubuntu sandbox
# =============================================================================
# Run this ON the Ubuntu machine that will host the 40 apps.
# Docker Compose on the host is enough — no VirtualBox, Vagrant, or nested VM.
#
#   sudo bash sandbox-setup.sh                 # install Docker if needed, hosts, start all
#   sudo bash sandbox-setup.sh --profile ai    # one group
#   sudo bash sandbox-setup.sh --install-only  # Docker + /etc/hosts, do not start apps
#
# Tested target: Ubuntu 22.04 / 24.04 x86_64.
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

TESTBED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="all"
INSTALL_ONLY=0
SKIP_DOCKER_INSTALL=0

usage() {
  cat <<EOF
Usage: sudo bash $0 [options]

  --profile NAME    conventional | ai | chatbot | fake-ai | all | infra
                    default: all
  --install-only    install Docker Engine + host aliases; do not start containers
  --skip-docker     assume Docker is already installed
  -h, --help        this help

This script is for a native Ubuntu host. Do not run it inside a VM unless that
Ubuntu install is itself the machine you want to scan.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --install-only) INSTALL_ONLY=1; shift ;;
    --skip-docker) SKIP_DOCKER_INSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) error "unknown argument: $1" ;;
  esac
done

case "$PROFILE" in
  conventional|ai|chatbot|fake-ai|all|infra) ;;
  *) error "invalid --profile $PROFILE" ;;
esac

preflight() {
  [[ $EUID -eq 0 ]] || error "Re-run as root: sudo bash $0"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
  fi
  [[ "${ID:-}" == "ubuntu" ]] || warn "This script is written for Ubuntu (detected ID=${ID:-unknown}). Continuing anyway."
  ARCH="$(uname -m)"
  if [[ "$ARCH" != "x86_64" && "$ARCH" != "amd64" ]]; then
    warn "Arch is $ARCH. Mutillidae, Hackazon, NextChat, and Botpress v12 are amd64-only and may fail."
  fi
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    success "Docker Engine + Compose already installed ($(docker compose version --short 2>/dev/null || echo present))"
    return
  fi
  [[ $SKIP_DOCKER_INSTALL -eq 1 ]] && error "Docker/Compose missing and --skip-docker was set"
  info "Installing Docker Engine + Compose plugin via get.docker.com"
  command -v curl >/dev/null 2>&1 || {
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates
  }
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker.service 2>/dev/null || true
  if ! docker info >/dev/null 2>&1; then
    error "dockerd is not running. Start it with: sudo systemctl start docker"
  fi
  success "Docker installed"
}

add_docker_group() {
  local user="${SUDO_USER:-}"
  [[ -n "$user" && "$user" != "root" ]] || return 0
  if getent group docker >/dev/null; then
    usermod -aG docker "$user"
    info "Added $user to the docker group. Log out/in (or: newgrp docker) to use docker without sudo."
  fi
}

install_hosts() {
  bash "$TESTBED_DIR/scripts/install-hosts.sh"
}

bring_up() {
  cd "$TESTBED_DIR"
  if [[ "$PROFILE" == "infra" ]]; then
    info "Starting shared infra (postgres, mysql, mongo, redis, ollama)"
    docker compose up -d
  else
    info "Starting profile: $PROFILE"
    docker compose --profile "$PROFILE" up -d
  fi
  echo
  docker compose ps
  echo
  success "Compose is up. First-boot inits (Chatwoot, Rasa, Zammad, Ollama pull) can take several minutes."
  echo "Status:     bash scripts/healthcheck.sh"
  echo "Widget URL: http://store.testbed.local:3029"
  echo "Labels:     $TESTBED_DIR/ground_truth/targets.json"
}

preflight
if [[ $SKIP_DOCKER_INSTALL -eq 0 ]]; then
  install_docker
fi
add_docker_group
install_hosts

if [[ $INSTALL_ONLY -eq 1 ]]; then
  success "Install-only done. Start later with: cd $TESTBED_DIR && sudo docker compose --profile $PROFILE up -d"
  exit 0
fi

bring_up
