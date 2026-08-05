# Multiagent Testing Testbed
## 20 Dockerized Traditional Applications + Sandbox Environment

---

## What's included

| File | Purpose |
|---|---|
| `docker-compose.yml` | All 20 app containers + shared DBs |
| `sandbox-setup.sh` | One-shot: network isolation, cgroups, iptables, start all containers |
| `snapshot.sh` | Save volume state for clean-reset baseline |
| `restore.sh` | Restore a saved snapshot between test runs |
| `targets.json` | Machine-readable manifest — feed to your multiagent scanner |
| `test_harness.py` | Python runner: iterate over targets, collect results, write reports |
| `ground_truth/` | Per-target labels: expected findings + **must_not_report** |
| `fixtures/golden/` | Scan JSONs that must PASS regression |
| `fixtures/negative/` | Known FP scans that must FAIL regression |
| `regression_eval.py` | Precision-first TP/FP/FN harness (offline + live) |

### Regression harness (run after every commit)

```bash
cd multiagent-testbed
# Golden corpus must pass
python3 regression_eval.py --fixtures-dir fixtures/golden --strict
# Negative FP corpus must fail (proves must_not_report still bites)
python3 regression_eval.py --fixtures-dir fixtures/negative --expect-fail
# Or via pytest
PYTHONPATH=../..:.. pytest ../../tests/test_regression_harness.py -q
```

Operating point: **precision-first, black-box unauthenticated**. Auth-gated
surfaces are `not_assessed`, not false negatives. See `ground_truth/SCHEMA.md`.

---

## Quick Start (Docker only, no VM)

```bash
# 1. Clone / copy this folder to your machine
cd multiagent-testbed

# 2. Start everything (no root needed for this step)
docker compose up -d

# 3. Check status
docker compose ps

# 4. Save a clean baseline snapshot
bash snapshot.sh baseline

# 5. Run your multiagent scanner via the harness
python test_harness.py --list           # see all 20 targets
python test_harness.py --health-check   # confirm all are reachable
python test_harness.py --all            # run full suite
```

---

## The 20 Applications

### Group 1 — Web / CMS
| # | App | Port | Default Creds | Key Vulns |
|---|-----|------|---------------|-----------|
| 1 | DVWA | 8001 | admin / password | SQLi, XSS, CSRF, file upload, CMDi |
| 2 | WordPress | 8002 | admin / admin123 | SQLi, XSS, plugin vulns |
| 3 | Joomla | 8003 | admin / admin123 | SQLi, XSS, RCE |
| 4 | Drupal | 8004 | admin / admin123 | SQLi, RCE, open redirect |
| 5 | phpBB | 8005 | admin / admin123 | XSS, CSRF, SQLi |

### Group 2 — E-commerce / APIs
| # | App | Port | Default Creds | Key Vulns |
|---|-----|------|---------------|-----------|
| 6 | OpenCart | 8006 | admin / admin123 | SQLi, XSS, IDOR |
| 7 | PrestaShop | 8007 | admin@testbed.local / admin123 | SQLi, auth bypass |
| 8 | REST API (json-server) | 8008 | none | IDOR, mass-assignment |
| 9 | Strapi | 8009 | admin@testbed.local / admin123 | GraphQL injection |
| 10 | Directus | 8010 | admin@testbed.local / admin123 | IDOR, broken auth |

### Group 3 — Auth / Dashboards
| # | App | Port | Default Creds | Key Vulns |
|---|-----|------|---------------|-----------|
| 11 | Keycloak | 8011 | admin / admin123 | OAuth misconfiguration, token forgery |
| 12 | Grafana | 8012 | admin / admin123 | SSRF, anonymous access |
| 13 | Gitea | 8013 | admin / admin123 | Repo traversal, webhook SSRF |
| 14 | Nextcloud | 8014 | admin / admin123 | Path traversal, WebDAV abuse |
| 15 | Redmine | 8015 | admin / admin | SQLi, XSS, IDOR |

### Group 4 — Intentionally Vulnerable
| # | App | Port | Default Creds | Key Vulns |
|---|-----|------|---------------|-----------|
| 16 | WebGoat | 8016 | guest / guest | SQLi, XSS, XXE, IDOR, SSRF, JWT, deserialization |
| 17 | OWASP Juice Shop | 8017 | admin@juice-sh.op / admin123 | Full OWASP Top 10 |
| 18 | bWAPP | 8018 | bee / bug | SQLi, XSS, CMDi, LFI, RFI, XXE, SSRF |
| 19 | NodeGoat | 8019 | user1 / User1_123 | NoSQLi, XSS, prototype pollution |
| 20 | Mutillidae II | 8020 | admin / adminpass | SQLi, XSS, CSRF, clickjacking, LFI, RFI |

---

## Sandbox Virtual Environment Options

Choose the isolation level that matches your threat model:

### Option A — Docker only (lightest, good for dev/testing)
```
Your machine
└── Docker Desktop / Docker Engine
    └── testbed-net (172.30.0.0/24 bridge)
        ├── 20 app containers
        └── 4 backing service containers
```
- Pros: trivial to set up, fast restart
- Cons: shares host kernel, limited blast-radius containment

### Option B — Linux VM + Docker (recommended for security research)
```
Host OS
└── VirtualBox / VMware / QEMU VM  ← isolated VM
    ├── Ubuntu 22.04
    ├── Docker Engine
    ├── iptables isolation rules  (sandbox-setup.sh handles this)
    └── testbed-net bridge
        └── 20 containers
```
Setup:
```bash
# On the VM (after installing Docker):
sudo bash sandbox-setup.sh
```
The script will:
- Apply iptables rules blocking container traffic from leaving the VM
- Create seccomp profiles for each container
- Write cgroup resource limits
- Start all 20 containers and print a status table

### Option C — Dedicated bare-metal / cloud VM (production-grade testbed)
Use an AWS EC2 `t3.2xlarge` or GCP `n2-standard-8` for adequate RAM (16 GB+ recommended for all 20 containers simultaneously).

Minimum specs:
- CPU: 4 vCPUs
- RAM: 16 GB (8 GB will work with only groups 3–4 running)
- Disk: 80 GB SSD
- OS: Ubuntu 22.04

### Option D — Vagrant (automated VM provisioning)
```bash
# Vagrantfile is included, just run:
vagrant up
vagrant ssh
# testbed is already running inside the VM
```

---

## Snapshot & Reset Workflow

```
                ┌─────────────────────────────────────┐
                │         Test Run Lifecycle           │
                └─────────────────────────────────────┘

  1. First time:    bash snapshot.sh baseline
                         │
  2. Run agents:    python test_harness.py --all
                         │
  3. After run:     bash restore.sh baseline_<timestamp>
                         │
  4. Repeat step 2 ──────┘
```

The snapshot saves Docker volumes to `./snapshots/<name>/`. Restore unpacks them and restarts containers. Each restore takes ~30–60 seconds.

For per-target reset (reset after every single scan):
```bash
python test_harness.py --all --reset-after
```

---

## Wiring in Your Multiagent Scanner

Edit the `run_scan()` function in `test_harness.py`:

```python
# Line ~72 in test_harness.py
agent_cmd = [
    "python", "-m", "yurarag.scanner",   # ← your scanner module
    "--url", target["url"],
    "--creds-user", target["default_creds"].get("user", ""),
    "--creds-pass", target["default_creds"].get("pass", ""),
    "--output", str(RESULTS_DIR / f"{target['name']}_raw.json"),
]
```

Your scanner should output JSON to stdout or to the `--output` file. The harness will pick up a `findings` or `vulnerabilities` key from the JSON.

---

## Useful Commands

```bash
# Start / stop specific groups
docker compose up -d webgoat juiceshop bwapp nodegoat mutillidae

# Tail logs for one app
docker compose logs -f juiceshop

# Reset just one container (without full snapshot restore)
docker compose restart wordpress

# Shell into a container
docker exec -it tb-juiceshop sh

# See all container IPs
docker network inspect testbed_testbed-net | grep -A4 '"Name"'

# Stop everything and remove volumes (full wipe)
docker compose down -v
```

---

## Network Map

```
Host (your machine / VM)
│
├── localhost:8001-8020  ──► 20 app containers
├── localhost:3306        ──► MySQL
├── localhost:5432        ──► PostgreSQL
├── localhost:6379        ──► Redis
└── localhost:27017       ──► MongoDB

All containers: 172.30.0.0/24 (testbed-net bridge)
Backing services: 172.30.0.10–13
App containers:   172.30.0.21–40

iptables rule (sandbox-setup.sh):
  FORWARD: 172.30.0.0/24 → !172.30.0.0/24 → DROP
  (blocks containers from reaching the real internet)
```
