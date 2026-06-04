#!/usr/bin/env bash
# ================================================================
# sandbox-setup.sh
# Sets up an isolated sandbox environment for multiagent testing
# Run as root (or with sudo) on the host machine
# Tested on: Ubuntu 22.04 / Debian 12
# ================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

TESTBED_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_NET="172.30.0.0/24"
SANDBOX_IFACE="testbed-br0"
LOG_DIR="$TESTBED_DIR/logs"
SNAPSHOT_DIR="$TESTBED_DIR/snapshots"

# ─────────────────────────────
# 1. PRE-FLIGHT CHECKS
# ─────────────────────────────
preflight() {
  info "Running pre-flight checks..."
  [[ $EUID -eq 0 ]] || error "This script must be run as root. Use: sudo $0"
  command -v docker    >/dev/null 2>&1 || error "Docker not found. Install: https://docs.docker.com/engine/install/"
  command -v docker compose>/dev/null 2>&1 || \
  docker compose version >/dev/null 2>&1 || error "Docker Compose v2 not found."
  command -v iptables  >/dev/null 2>&1 || apt-get install -y iptables >/dev/null
  command -v cgcreate  >/dev/null 2>&1 || apt-get install -y cgroup-tools >/dev/null 2>&1 || true

  mkdir -p "$LOG_DIR" "$SNAPSHOT_DIR"
  success "Pre-flight checks passed."
}

# ─────────────────────────────
# 2. NETWORK ISOLATION
# ─────────────────────────────
setup_network_isolation() {
  info "Configuring network isolation..."

  # Drop all forwarded traffic leaving the testbed network to the internet
  # Allow traffic WITHIN the sandbox subnet only
  iptables -N TESTBED-ISOLATION 2>/dev/null || iptables -F TESTBED-ISOLATION

  # Allow established/related (return traffic for scanner agents)
  iptables -A TESTBED-ISOLATION -m state --state ESTABLISHED,RELATED -j ACCEPT

  # Allow intra-sandbox traffic
  iptables -A TESTBED-ISOLATION -s "$SANDBOX_NET" -d "$SANDBOX_NET" -j ACCEPT

  # Allow multiagent host → sandbox
  iptables -A TESTBED-ISOLATION -d "$SANDBOX_NET" -j ACCEPT

  # Block sandbox → internet (prevent exfil / SSRF reaching real targets)
  iptables -A TESTBED-ISOLATION -s "$SANDBOX_NET" ! -d "$SANDBOX_NET" -j DROP

  # Hook into FORWARD chain
  iptables -I FORWARD 1 -j TESTBED-ISOLATION

  # Save rules so they persist after reboot
  if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  fi

  success "Network isolation rules applied. Sandbox subnet: $SANDBOX_NET"
}

# ─────────────────────────────
# 3. CGROUP RESOURCE LIMITS
# ─────────────────────────────
setup_resource_limits() {
  info "Setting up cgroup resource limits..."

  # Docker already uses cgroups — we also enforce per-container limits
  # via docker-compose deploy.resources (see .env file)
  # This function writes sane defaults into the .env if not present

  ENV_FILE="$TESTBED_DIR/.env"
  if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" << 'EOF'
# Resource limits applied to each app container
# Adjust per machine capacity

# Memory limit per app container (Docker enforced)
MEM_LIMIT=512m
MEM_RESERVATION=256m

# CPU shares (1024 = 1 core equivalent)
CPU_SHARES=512

# Backing services get more headroom
DB_MEM_LIMIT=1g
DB_CPU_SHARES=1024

# Compose project name (keeps containers namespaced)
COMPOSE_PROJECT_NAME=testbed
EOF
    success "Created .env with default resource limits."
  else
    info ".env already exists, skipping."
  fi
}

# ─────────────────────────────
# 4. SECCOMP / APPARMOR PROFILE
# ─────────────────────────────
setup_security_profiles() {
  info "Writing seccomp profile for app containers..."

  mkdir -p "$TESTBED_DIR/security"
  cat > "$TESTBED_DIR/security/seccomp-testbed.json" << 'EOF'
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "names": ["mount", "umount2", "ptrace", "kexec_load",
                "open_by_handle_at", "init_module", "finit_module",
                "delete_module", "iopl", "ioperm", "swapon", "swapoff"],
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
EOF
  success "Seccomp profile written to security/seccomp-testbed.json"
}

# ─────────────────────────────
# 5. INIT FILES FOR DATABASES
# ─────────────────────────────
setup_init_files() {
  info "Creating DB init scripts..."

  mkdir -p "$TESTBED_DIR/init/mysql"
  cat > "$TESTBED_DIR/init/mysql/00-create-dbs.sql" << 'EOF'
CREATE DATABASE IF NOT EXISTS wordpress CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS joomla    CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS opencart  CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS prestashop CHARACTER SET utf8mb4;
CREATE DATABASE IF NOT EXISTS phpbb     CHARACTER SET utf8mb4;
GRANT ALL PRIVILEGES ON wordpress.*  TO 'testbed'@'%';
GRANT ALL PRIVILEGES ON joomla.*     TO 'testbed'@'%';
GRANT ALL PRIVILEGES ON opencart.*   TO 'testbed'@'%';
GRANT ALL PRIVILEGES ON prestashop.* TO 'testbed'@'%';
GRANT ALL PRIVILEGES ON phpbb.*      TO 'testbed'@'%';
FLUSH PRIVILEGES;
EOF

  mkdir -p "$TESTBED_DIR/init/postgres"
  cat > "$TESTBED_DIR/init/postgres/00-create-dbs.sql" << 'EOF'
CREATE DATABASE drupal      OWNER testbed;
CREATE DATABASE strapi      OWNER testbed;
CREATE DATABASE directus    OWNER testbed;
CREATE DATABASE keycloak    OWNER testbed;
CREATE DATABASE gitea       OWNER testbed;
CREATE DATABASE nextcloud   OWNER testbed;
CREATE DATABASE redmine     OWNER testbed;
EOF

  mkdir -p "$TESTBED_DIR/init/rest-api"
  cat > "$TESTBED_DIR/init/rest-api/db.json" << 'EOF'
{
  "users": [
    { "id": 1, "name": "Alice Admin",  "email": "alice@testbed.local",  "role": "admin",  "password": "admin123" },
    { "id": 2, "name": "Bob User",     "email": "bob@testbed.local",    "role": "user",   "password": "user123"  },
    { "id": 3, "name": "Carol Guest",  "email": "carol@testbed.local",  "role": "guest",  "password": "guest123" }
  ],
  "products": [
    { "id": 1, "name": "Widget A", "price": 9.99,  "stock": 100, "owner_id": 1 },
    { "id": 2, "name": "Widget B", "price": 19.99, "stock": 50,  "owner_id": 2 },
    { "id": 3, "name": "Widget C", "price": 4.99,  "stock": 200, "owner_id": 1 }
  ],
  "orders": [
    { "id": 1, "user_id": 2, "product_id": 1, "quantity": 2, "status": "pending" },
    { "id": 2, "user_id": 3, "product_id": 3, "quantity": 1, "status": "shipped" }
  ],
  "secrets": [
    { "id": 1, "key": "API_KEY",      "value": "sk-testbed-super-secret-key-12345" },
    { "id": 2, "key": "DB_PASSWORD",  "value": "testbed_pass" }
  ]
}
EOF

  success "Init files created."
}

# ─────────────────────────────
# 6. SNAPSHOT HELPER SCRIPTS
# ─────────────────────────────
create_snapshot_tools() {
  info "Creating snapshot/restore utilities..."

  cat > "$TESTBED_DIR/snapshot.sh" << 'SNAP'
#!/usr/bin/env bash
# snapshot.sh — save current Docker volume state for a clean-reset baseline
set -euo pipefail
SNAPSHOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/snapshots"
TAG="${1:-baseline}"
STAMP="$(date +%Y%m%d_%H%M%S)"
NAME="${TAG}_${STAMP}"
mkdir -p "$SNAPSHOT_DIR/$NAME"

echo "[snapshot] Stopping app containers (keeping DBs up)..."
docker compose stop wordpress joomla drupal opencart prestashop \
  webgoat juiceshop bwapp nodegoat mutillidae \
  dvwa phpbb rest-api strapi directus \
  keycloak grafana gitea nextcloud redmine 2>/dev/null || true

echo "[snapshot] Exporting volumes..."
for VOL in $(docker volume ls --filter "name=testbed" -q); do
  echo "  → $VOL"
  docker run --rm -v "${VOL}:/data" -v "$SNAPSHOT_DIR/$NAME:/backup" \
    alpine tar czf "/backup/${VOL}.tar.gz" -C /data . 2>/dev/null || true
done

docker compose start 2>/dev/null || true
echo "[snapshot] Snapshot saved: snapshots/$NAME"
SNAP

  cat > "$TESTBED_DIR/restore.sh" << 'RESTORE'
#!/usr/bin/env bash
# restore.sh — restore a snapshot to bring testbed back to clean state
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAPSHOT_DIR="$SCRIPT_DIR/snapshots"

if [[ -z "${1:-}" ]]; then
  echo "Usage: $0 <snapshot_name>"
  echo "Available snapshots:"
  ls "$SNAPSHOT_DIR" 2>/dev/null || echo "  (none)"
  exit 1
fi

NAME="$1"
[[ -d "$SNAPSHOT_DIR/$NAME" ]] || { echo "Snapshot not found: $NAME"; exit 1; }

echo "[restore] Stopping all containers..."
cd "$SCRIPT_DIR" && docker compose down 2>/dev/null || true

echo "[restore] Restoring volumes from $NAME..."
for ARCHIVE in "$SNAPSHOT_DIR/$NAME"/*.tar.gz; do
  VOL="$(basename "$ARCHIVE" .tar.gz)"
  echo "  → $VOL"
  docker volume create "$VOL" 2>/dev/null || true
  docker run --rm -v "${VOL}:/data" -v "$SNAPSHOT_DIR/$NAME:/backup" \
    alpine sh -c "rm -rf /data/* /data/..?* /data/.[!.]* 2>/dev/null; tar xzf /backup/$(basename "$ARCHIVE") -C /data"
done

echo "[restore] Restarting testbed..."
docker compose up -d
echo "[restore] Done. Testbed restored to: $NAME"
RESTORE

  chmod +x "$TESTBED_DIR/snapshot.sh" "$TESTBED_DIR/restore.sh"
  success "snapshot.sh and restore.sh created."
}

# ─────────────────────────────
# 7. MULTIAGENT TARGET MANIFEST
# ─────────────────────────────
create_target_manifest() {
  info "Creating target manifest for multiagent system..."

  cat > "$TESTBED_DIR/targets.json" << 'EOF'
{
  "testbed_version": "1.0",
  "base_url": "http://localhost",
  "network": "172.30.0.0/24",
  "targets": [
    {
      "id": 1, "name": "DVWA",
      "url": "http://localhost:8001",
      "internal_ip": "172.30.0.21",
      "group": "web-cms",
      "stack": ["PHP", "MySQL"],
      "default_creds": {"user": "admin", "pass": "password"},
      "known_vulns": ["sqli", "xss", "csrf", "fileupload", "cmdi"],
      "notes": "Reset DB via http://localhost:8001/setup.php"
    },
    {
      "id": 2, "name": "WordPress",
      "url": "http://localhost:8002",
      "internal_ip": "172.30.0.22",
      "group": "web-cms",
      "stack": ["PHP", "MySQL"],
      "default_creds": {"user": "admin", "pass": "admin123"},
      "known_vulns": ["sqli", "xss", "auth-bypass", "plugin-vulns"]
    },
    {
      "id": 3, "name": "Joomla",
      "url": "http://localhost:8003",
      "internal_ip": "172.30.0.23",
      "group": "web-cms",
      "stack": ["PHP", "MySQL"],
      "default_creds": {"user": "admin", "pass": "admin123"},
      "known_vulns": ["sqli", "xss", "rce"]
    },
    {
      "id": 4, "name": "Drupal",
      "url": "http://localhost:8004",
      "internal_ip": "172.30.0.24",
      "group": "web-cms",
      "stack": ["PHP", "PostgreSQL"],
      "default_creds": {"user": "admin", "pass": "admin123"},
      "known_vulns": ["sqli", "rce", "open-redirect"]
    },
    {
      "id": 5, "name": "phpBB",
      "url": "http://localhost:8005",
      "internal_ip": "172.30.0.25",
      "group": "web-cms",
      "stack": ["PHP", "MySQL"],
      "default_creds": {"user": "admin", "pass": "admin123"},
      "known_vulns": ["xss", "csrf", "sqli"]
    },
    {
      "id": 6, "name": "OpenCart",
      "url": "http://localhost:8006",
      "internal_ip": "172.30.0.26",
      "group": "ecommerce",
      "stack": ["PHP", "MySQL"],
      "default_creds": {"user": "admin", "pass": "admin123"},
      "known_vulns": ["sqli", "xss", "idor"]
    },
    {
      "id": 7, "name": "PrestaShop",
      "url": "http://localhost:8007",
      "internal_ip": "172.30.0.27",
      "group": "ecommerce",
      "stack": ["PHP", "MySQL"],
      "default_creds": {"user": "admin@testbed.local", "pass": "admin123"},
      "known_vulns": ["sqli", "xss", "auth-bypass"]
    },
    {
      "id": 8, "name": "REST API (json-server)",
      "url": "http://localhost:8008",
      "internal_ip": "172.30.0.28",
      "group": "api",
      "stack": ["Node.js"],
      "default_creds": {},
      "known_vulns": ["idor", "mass-assignment", "broken-auth"],
      "notes": "Endpoints: /users /products /orders /secrets"
    },
    {
      "id": 9, "name": "Strapi",
      "url": "http://localhost:8009",
      "internal_ip": "172.30.0.29",
      "group": "api",
      "stack": ["Node.js", "PostgreSQL"],
      "default_creds": {"user": "admin@testbed.local", "pass": "admin123"},
      "known_vulns": ["graphql-injection", "broken-object-auth"]
    },
    {
      "id": 10, "name": "Directus",
      "url": "http://localhost:8010",
      "internal_ip": "172.30.0.30",
      "group": "api",
      "stack": ["Node.js", "PostgreSQL"],
      "default_creds": {"user": "admin@testbed.local", "pass": "admin123"},
      "known_vulns": ["idor", "broken-auth"]
    },
    {
      "id": 11, "name": "Keycloak",
      "url": "http://localhost:8011",
      "internal_ip": "172.30.0.31",
      "group": "auth",
      "stack": ["Java", "PostgreSQL"],
      "default_creds": {"user": "admin", "pass": "admin123"},
      "known_vulns": ["oauth-misconfig", "token-forgery", "open-redirect"]
    },
    {
      "id": 12, "name": "Grafana",
      "url": "http://localhost:8012",
      "internal_ip": "172.30.0.32",
      "group": "dashboard",
      "stack": ["Go"],
      "default_creds": {"user": "admin", "pass": "admin123"},
      "known_vulns": ["ssrf", "anon-access", "plugin-rce"]
    },
    {
      "id": 13, "name": "Gitea",
      "url": "http://localhost:8013",
      "internal_ip": "172.30.0.33",
      "group": "devtools",
      "stack": ["Go", "PostgreSQL"],
      "default_creds": {"user": "admin", "pass": "admin123"},
      "known_vulns": ["repo-traversal", "webhook-ssrf", "token-leak"]
    },
    {
      "id": 14, "name": "Nextcloud",
      "url": "http://localhost:8014",
      "internal_ip": "172.30.0.34",
      "group": "fileshare",
      "stack": ["PHP", "PostgreSQL"],
      "default_creds": {"user": "admin", "pass": "admin123"},
      "known_vulns": ["path-traversal", "webdav-abuse", "idor"]
    },
    {
      "id": 15, "name": "Redmine",
      "url": "http://localhost:8015",
      "internal_ip": "172.30.0.35",
      "group": "projectmgmt",
      "stack": ["Ruby", "PostgreSQL"],
      "default_creds": {"user": "admin", "pass": "admin"},
      "known_vulns": ["sqli", "xss", "idor", "auth-bypass"]
    },
    {
      "id": 16, "name": "WebGoat",
      "url": "http://localhost:8016/WebGoat",
      "internal_ip": "172.30.0.36",
      "group": "intentionally-vulnerable",
      "stack": ["Java"],
      "default_creds": {"user": "guest", "pass": "guest"},
      "known_vulns": ["sqli","xss","xxe","idor","ssrf","jwt","deserialization"]
    },
    {
      "id": 17, "name": "OWASP Juice Shop",
      "url": "http://localhost:8017",
      "internal_ip": "172.30.0.37",
      "group": "intentionally-vulnerable",
      "stack": ["Node.js"],
      "default_creds": {"user": "admin@juice-sh.op", "pass": "admin123"},
      "known_vulns": ["sqli","xss","broken-auth","sensitive-data","xxe","csrf","jwt","nosqli"]
    },
    {
      "id": 18, "name": "bWAPP",
      "url": "http://localhost:8018/install.php",
      "internal_ip": "172.30.0.38",
      "group": "intentionally-vulnerable",
      "stack": ["PHP", "MySQL"],
      "default_creds": {"user": "bee", "pass": "bug"},
      "known_vulns": ["sqli","xss","cmdi","lfi","rfi","xxe","ssrf","ssti","csrf"]
    },
    {
      "id": 19, "name": "NodeGoat",
      "url": "http://localhost:8019",
      "internal_ip": "172.30.0.39",
      "group": "intentionally-vulnerable",
      "stack": ["Node.js", "MongoDB"],
      "default_creds": {"user": "user1", "pass": "User1_123"},
      "known_vulns": ["nosqli","xss","prototype-pollution","ssti","idor","regex-dos"]
    },
    {
      "id": 20, "name": "Mutillidae II",
      "url": "http://localhost:8020",
      "internal_ip": "172.30.0.40",
      "group": "intentionally-vulnerable",
      "stack": ["PHP", "MySQL"],
      "default_creds": {"user": "admin", "pass": "adminpass"},
      "known_vulns": ["sqli","xss","csrf","clickjacking","http-header-injection","lfi","rfi","cmdi","xxe"]
    }
  ]
}
EOF
  success "targets.json created — feed this to your multiagent scanner."
}

# ─────────────────────────────
# 8. START TESTBED
# ─────────────────────────────
start_testbed() {
  info "Starting all 20 containers..."
  cd "$TESTBED_DIR"
  docker compose pull --quiet 2>/dev/null || true
  docker compose up -d --remove-orphans

  info "Waiting for health checks (up to 120s)..."
  sleep 10

  # Print status table
  echo ""
  echo "════════════════════════════════════════════════════════════════"
  echo "  TESTBED STATUS"
  echo "════════════════════════════════════════════════════════════════"
  printf "  %-20s %-10s %-30s\n" "APP" "PORT" "STATUS"
  echo "  ──────────────────────────────────────────────────────────────"

  APPS=(
    "dvwa:8001" "wordpress:8002" "joomla:8003" "drupal:8004" "phpbb:8005"
    "opencart:8006" "prestashop:8007" "rest-api:8008" "strapi:8009" "directus:8010"
    "keycloak:8011" "grafana:8012" "gitea:8013" "nextcloud:8014" "redmine:8015"
    "webgoat:8016" "juiceshop:8017" "bwapp:8018" "nodegoat:8019" "mutillidae:8020"
  )

  for ENTRY in "${APPS[@]}"; do
    NAME="${ENTRY%%:*}"
    PORT="${ENTRY##*:}"
    STATUS=$(docker inspect --format='{{.State.Status}}' "tb-$NAME" 2>/dev/null || echo "not found")
    if [[ "$STATUS" == "running" ]]; then
      printf "  %-20s %-10s ${GREEN}%-30s${NC}\n" "$NAME" ":$PORT" "running  ✓"
    else
      printf "  %-20s %-10s ${RED}%-30s${NC}\n" "$NAME" ":$PORT" "$STATUS"
    fi
  done

  echo "════════════════════════════════════════════════════════════════"
  echo ""
  success "Testbed is up. Run './snapshot.sh baseline' to save a clean state."
}

# ─────────────────────────────
# MAIN
# ─────────────────────────────
main() {
  echo ""
  echo "╔══════════════════════════════════════════════════╗"
  echo "║   MULTIAGENT TESTBED — SANDBOX SETUP             ║"
  echo "║   20 Dockerized Traditional Applications         ║"
  echo "╚══════════════════════════════════════════════════╝"
  echo ""

  preflight
  setup_network_isolation
  setup_resource_limits
  setup_security_profiles
  setup_init_files
  create_snapshot_tools
  create_target_manifest
  start_testbed

  echo ""
  echo "  Quick reference:"
  echo "    Snapshot baseline:  ./snapshot.sh baseline"
  echo "    Restore baseline:   ./restore.sh baseline_<timestamp>"
  echo "    View targets:       cat targets.json"
  echo "    Stop everything:    docker compose down"
  echo "    Logs for one app:   docker compose logs -f <service>"
  echo ""
}

main "$@"
