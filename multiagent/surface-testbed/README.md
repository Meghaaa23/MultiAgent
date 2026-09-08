# SURFACE-40 evaluation testbed

All sandboxing lives in **`multiagent/surface-testbed`**. Run it **on Ubuntu** (22.04/24.04 x86_64) with Docker Engine. Containers are processes on that host. **No VM, Vagrant, or nested hypervisor** is required.

```bash
cd multiagent/surface-testbed
sudo bash sandbox-setup.sh                 # install Docker if needed, /etc/hosts, start all 40
# or one group:
sudo bash sandbox-setup.sh --profile conventional
sudo bash sandbox-setup.sh --install-only  # Docker + host aliases only; start later yourself
bash scripts/healthcheck.sh
```

If Docker is already installed and your user is in the `docker` group:

```bash
sudo bash scripts/install-hosts.sh
bash scripts/up.sh all          # or: conventional | ai | chatbot | fake-ai | infra
```

Four groups of ten apps for SURFACE scoring:

| Group | Profile | Ports | What it measures |
| --- | --- | --- | --- |
| 1 Conventional web | `conventional` | 3001–3010 | AI-negative vuln targets → conventional detection + AI-surface **precision** (true negatives) |
| 2 AI apps | `ai` | 3011–3020 | LLM/model-backed → AI-surface **recall** + application-owned chat |
| 3 Chatbot apps | `chatbot` | 3021–3030 | Ownership taxonomy: app-owned bot vs third-party widget vs human-operated |
| 4 Fake-AI | `fake-ai` | 3031–3040 | Hard negatives: AI branding / canned routes / “smart” products with no live model |

Requires **Docker Compose v2.24+** (`include`). Compose is split so you can bring up one group without booting all 40:

```
sandbox-setup.sh            # Ubuntu host: install Docker if needed, /etc/hosts, compose up
docker-compose.yml          # includes the four group files + infra
compose/00-infra.yml        # postgres, mysql, mongo (rs0), redis, ollama
compose/10-conventional.yml
compose/20-ai.yml
compose/30-chatbot.yml
compose/40-fake-ai.yml
```

NodeGoat is **not** in this stack: `owasp/nodegoat` has no published image. Slot 9 is **DVNA** (`appsecco/dvna`) plus the shared MySQL.

## Ubuntu host requirements

| | |
| --- | --- |
| OS | Ubuntu 22.04 or 24.04 |
| Arch | x86_64 (four old images are amd64-only) |
| Disk | ~80 GB free for images + volumes |
| RAM | 16 GB can run groups one at a time; **32 GB+** for `--profile all` |
| Software | Docker Engine + Compose v2.24+ (`sandbox-setup.sh` will install these) |

Do **not** wrap this in VirtualBox/VMware/QEMU. `sandbox-setup.sh` talks to the Ubuntu Docker daemon on the same machine you will point SURFACE at (`http://localhost:30xx` and the `*.testbed.local` aliases).

## Quick start (Docker already installed)

```bash
cd multiagent/surface-testbed

# 1. Host aliases so widget eTLD+1 differs (required for apps 29–30)
sudo bash scripts/install-hosts.sh

# 2. Shared infra only (DBs + Ollama, no apps)
docker compose up -d

# 3. One group at a time (fits a 16 GB Ubuntu box)
docker compose --profile conventional up -d
docker compose --profile ai up -d          # also pulls qwen2.5:0.5b
docker compose --profile chatbot up -d
docker compose --profile fake-ai up -d

# Or everything (32 GB RAM is a realistic floor; 64 GB is comfortable)
docker compose --profile all up -d
```

Wrappers: `bash scripts/up.sh conventional` (or `ai` / `chatbot` / `fake-ai` / `all` / `infra`). Probe: `bash scripts/healthcheck.sh`.

## If four apps stay DOWN after first boot

`listening=36 down=4` is the usual first-boot shape. Recreate only the flaky services (do not `down -v`):

```bash
cd multiagent/surface-testbed
sudo docker compose --profile all up -d --force-recreate bodgeit flowise chaskiq-init chaskiq chaskiq-worker rocketchat
# wait ~2 minutes for Rocket.Chat / Chaskiq migrate, then:
bash scripts/healthcheck.sh
```

| App | Typical cause | What the compose file now does |
| --- | --- | --- |
| BodgeIt (3010) | `psiinon/bodgeit` exits 255 unless given a TTY | `stdin_open: true` and `tty: true` (same as Hub's `docker run -i -t`) |
| Flowise (3018) | latest image `mkdir ''` when path env vars are empty; also runs as uid 1000 | explicit `/root/.flowise` paths, `user: "0"`, mkdir then `flowise start` |
| Chaskiq (3026) | `chaskiq-init` crash-loops so the web container never starts | override entrypoint, `db:migrate` or `db:setup`, `DISABLE_DATABASE_ENVIRONMENT_CHECK=1` |
| Rocket.Chat (3028) | Meteor `ConnectionResetError` while Mongo rs0 is reached via topology discovery | `directConnection=true`, `BIND_IP=0.0.0.0`, fixed `TCP_PORT=42000` |

Rocket.Chat can take 1–2 minutes after recreate before HTTP 200. If Chaskiq is still DOWN:

```bash
sudo docker compose logs --tail=80 chaskiq-init
sudo docker compose logs --tail=80 chaskiq
```

Labels for scoring: [`ground_truth/targets.json`](ground_truth/targets.json).

## Hostname aliases (third-party widgets)

SURFACE decides “third-party” by **eTLD+1**. `localhost:3029` embedding `localhost:3130` looks same-site. The store page is therefore served as `store.testbed.local` and the widget as `vendor.chat.local`.

`scripts/install-hosts.sh` appends:

```
127.0.0.1 store.testbed.local
127.0.0.1 vendor.chat.local
127.0.0.1 hubspot-embed.testbed.local
```

Scan:

- App 29: `http://store.testbed.local:3029` (widget origin `http://vendor.chat.local:3130`)
- App 30: `http://hubspot-embed.testbed.local:3030`

Real HubSpot/Tawk/Crisp also work as third-party widgets but need an account and internet egress. App 30 is an offline lookalike.

## Shared LLM backend

One Ollama (`localhost:3019`) backs Group 2. `ollama-pull` (profile `ai`/`all`) pulls `qwen2.5:0.5b` (override `OLLAMA_MODEL` in `.env`).

Open WebUI, LibreChat, AnythingLLM, Lobe Chat, NextChat, and SillyTavern are pointed at `http://ollama:11434`. Web-surface discovery still works if the model pull fails; prompt-injection confirmation does not.

LocalAI (3020) is a separate OpenAI-compatible API. Drop a GGUF into the `localai-models` volume if you want completions from it.

## First-boot steps

| App | Extra step |
| --- | --- |
| DVWA (3001) | Open `/setup.php` and create/reset the DB |
| bWAPP (3004) | Open `/install.php` |
| Chatwoot | `chatwoot-init` runs `rails db:chatwoot_prepare` |
| Papercups | entrypoint `db createdb` + `db migrate` |
| Chaskiq | `chaskiq-init` runs `rails db:migrate` (falls back to `db:setup`) |
| Rasa | `rasa-train` trains a tiny NLU model, then the API starts |
| Zammad | `zammad-init` then nginx on 3027 (Elasticsearch **off**) |
| Typebot | builder 3022 + viewer 3122 share Postgres |

## Group catalog

### Group 1 — Conventional web (no AI / chatbot)

| # | App | Image | Port | Notes |
| --- | --- | --- | --- | --- |
| 1 | DVWA | `vulnerables/web-dvwa` | 3001 | reset DB on first visit |
| 2 | WebGoat | `webgoat/webgoat` | 3002 | H2 embedded |
| 3 | Damn Vulnerable GraphQL | `dolevf/dvga` | 3003 | self-contained |
| 4 | bWAPP | `raesene/bwapp` | 3004 | `/install.php` first |
| 5 | Mutillidae II | `citizenstig/nowasp` | 3005 | old, amd64-only |
| 6 | VAmPI | `erev0s/vampi` | 3006 | SQLite |
| 7 | WrongSecrets | `jeroenwillemsen/wrongsecrets:latest-no-vault` | 3007 | self-contained |
| 8 | Hackazon | `ianwijaya/hackazon` | 3008 | unofficial — verify pull; amd64 |
| 9 | DVNA | `appsecco/dvna` | 3009 | NodeGoat replacement; MySQL |
| 10 | BodgeIt Store | `psiinon/bodgeit` | 3010 | Java; image needs a TTY (`stdin_open` + `tty`) |

### Group 2 — AI apps (LLM / model-backed)

| # | App | Image | Port | Needs |
| --- | --- | --- | --- | --- |
| 11 | Open WebUI | `ghcr.io/open-webui/open-webui:main` | 3011 | Ollama |
| 12 | LibreChat | `ghcr.io/danny-avila/librechat` | 3012 | Mongo rs0 + Ollama |
| 13 | AnythingLLM | `mintplexlabs/anythingllm` | 3013 | Ollama |
| 14 | Lobe Chat | `lobehub/lobe-chat` | 3014 | Ollama |
| 15 | NextChat | `yidadaa/chatgpt-next-web` | 3015 | Ollama; amd64 |
| 16 | SillyTavern | `ghcr.io/sillytavern/sillytavern` | 3016 | Ollama |
| 17 | Langflow | `langflowai/langflow` | 3017 | builder + `/api/v1/run` |
| 18 | Flowise | `flowiseai/flowise` | 3018 | builder + `/api/v1/prediction` |
| 19 | Ollama | `ollama/ollama` | 3019 | small model pull |
| 20 | LocalAI | `localai/localai:latest-cpu` | 3020 | CPU; optional GGUF |

### Group 3 — Chatbot apps (platforms / support / widgets)

| # | App | Image | Port | Ownership class |
| --- | --- | --- | --- | --- |
| 21 | Botpress v12 | `botpress/server:v12_31_10` | 3021 | app-owned bot (NLU); amd64 |
| 22 | Typebot | `baptistearno/typebot-builder` | 3022 | app-owned conversational bot (viewer `:3122`) |
| 23 | Rasa | `rasa/rasa:3.6.21` | 3023 | app-owned bot (trained in-compose) |
| 24 | Chatwoot | `chatwoot/chatwoot` | 3024 | human-operated support (+ AI copilot) |
| 25 | Papercups | `papercups/papercups` | 3025 | human-operated (OSS Intercom) |
| 26 | Chaskiq | `chaskiq/chaskiq` | 3026 | human + bots |
| 27 | Zammad | `ghcr.io/zammad/zammad` | 3027 | human helpdesk chat |
| 28 | Rocket.Chat | `registry.rocket.chat/rocketchat/rocket.chat` | 3028 | team chat + bot; Mongo rs0 |
| 29 | Third-party widget site | nginx + snippet | 3029 | `third_party_widget` |
| 30 | HubSpot-style embed | nginx static | 3030 | third-party widget lookalike |

### Group 4 — Pretending to be AI (hard negatives)

| # | App | Port | Should classify as |
| --- | --- | --- | --- |
| 31 | NeuraSaaS AI landing | 3031 | AI-negative (brand only) |
| 32 | Scripted SmartBot widget | 3032 | chatbot present but not AI |
| 33 | Human “we'll reply” support | 3033 | human, no bot |
| 34 | Fake LLM SDK site | 3034 | AI-negative (passive hint only) |
| 35 | Canned `/api/chat` | 3035 | AI-negative (route, not live model) |
| 36 | AI-branded docs site | 3036 | AI-negative |
| 37 | n8n | 3037 | markets “AI workflows”; not a model surface |
| 38 | Metabase | 3038 | “smart”/X-ray analytics, no chatbot |
| 39 | Uptime Kuma | 3039 | dashboard, zero AI |
| 40 | Excalidraw | 3040 | cloud markets “AI diagram”; OSS build has none |

Decoys 31–36 are one nginx with six listen ports (`decoys/sites/`).

## Architecture notes

- **Postgres** is `pgvector/pgvector:pg16` so Chatwoot can `CREATE EXTENSION vector`. Extra DBs are created in `init/postgres/00-create-dbs.sql`. Host port **5433** (avoids clashing with a local 5432).
- **MySQL** is only required by DVNA. Host port **3307**.
- **Mongo** is a single-node replica set `rs0` (Rocket.Chat oplog + LibreChat). Host port **27019**.
- **Redis** is shared; Chatwoot uses DB 1, Chaskiq DB 2. Zammad gets its own Redis.
- **Zammad** is a multi-container subset of the official stack with `ELASTICSEARCH_ENABLED=false`.
- Profiles: infra has no profile (always starts). Apps use `conventional` / `ai` / `chatbot` / `fake-ai` plus `all`.

## Arch / image caveats

These are old or unofficial and are effectively **amd64-only** (qemu on ARM, or run the testbed on x86_64):

- `citizenstig/nowasp` (Mutillidae, ~2015)
- `ianwijaya/hackazon` (unofficial)
- `yidadaa/chatgpt-next-web` (rebranded NextChat; stale)
- `botpress/server:v12_31_10` (last OSS release, 2023)

“Image exists” ≠ “guaranteed to run.” Pin digests after a one-time `bash scripts/pull-images.sh` smoke test if you need a frozen paper snapshot.

## Resource sketch

| Slice | Rough RAM |
| --- | --- |
| Infra (DBs + Ollama without a big model) | 2–4 GB |
| Group 1 | 2–4 GB |
| Group 2 (with 0.5B model) | 6–12 GB |
| Group 3 (Chatwoot + Zammad + Rocket.Chat) | 10–16 GB |
| Group 4 | 2–4 GB |
| `--profile all` | 32 GB+ recommended |

## Tear down

```bash
docker compose --profile all down
# add -v to wipe databases and the Ollama model
```
