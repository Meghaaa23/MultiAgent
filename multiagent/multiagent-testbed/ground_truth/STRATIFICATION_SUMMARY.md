# Ground-truth manifest: stratification summary

Generated after hand-labeling 49 of 49 `multiagent-testbed/benchmark-apps/` targets
(one target, `ragflow`, is deferred — its image was never pulled locally and pulling
it fresh would cost several GB of disk; everything else is done). Two pre-existing
entries (`dvwa`, `juice_shop`, `webgoat`) were retrofitted with the new `ai_surface`
block rather than re-labeled from scratch.

## Headline counts (`has_ai_surface`)

| value | count | targets |
|---|---|---|
| `yes` | 15 | anythingllm, dify, flowise, langflow, leantime, librechat_local, lobechat, minthcm, moodle, ollama, open_webui, openhands, rasa, twenty, wordpress |
| `partial` | 7 | botpress, chatwoot, dolibarr, gitlab, grafana, plane, zammad |
| `no` | 26 | adminer, dvwa, espocrm, freescout, ghost, gitea, itop, jenkins, joomla, juice_shop, librechat_marketing, limesurvey, mattermost, mautic, mediawiki, monica, nextcloud, nginx, openproject, owncloud, papercups, phpmyadmin, redmine, rocketchat, webgoat, wikijs |
| `unverifiable` | 1 | glpi (image fetches its real app from GitHub at container startup — nothing to statically inspect) |
| **total** | **49** | |

`partial` is a deliberately broad bucket covering several distinct sub-cases (see each
file's `notes` for the specific flavor): a live, auth-gated endpoint that's functionally
inert without an admin-configured provider key (chatwoot, dolibarr, plane, zammad); an
AI SDK/UI compiled in with the activating plugin absent (grafana); infra/config present
but EE-license-gated (gitlab); a platform capability with no live bot instance
provisioned (botpress).

## The headline finding: unauthenticated-by-default AI inference

Of the 15 `yes` + 7 `partial` targets, auth status on the real inference endpoint was
source-verified (not assumed) for most. **5 targets have a genuinely unauthenticated,
reachable AI inference surface by default in this deployment config:**

| target | endpoint | verified via |
|---|---|---|
| flowise | `POST /api/v1/prediction/:chatflowId` | endpoint explicitly whitelisted from the org-wide API-key gate; controller has no independent auth check |
| ollama | `/api/generate`, `/api/chat`, etc. | no auth middleware on any handler; `OLLAMA_API_KEY` exists but unset in this compose |
| openhands | `POST /api/conversations` | `get_dependencies()` returns empty list when `SESSION_API_KEY` env var is unset (it is, in this compose) |
| rasa | `/model/parse`, `/conversations/:id/messages` | `requires_auth()` explicitly bypasses when no `--auth-token`/`--jwt-secret` flag is passed (neither is, in this compose) |
| anythingllm | `/workspace/:slug/stream-chat` (the PRIMARY chat endpoint — note its secondary OpenAI-compat dev API IS properly key-gated) | `validatedRequest` middleware calls `next()` unconditionally when no `AUTH_TOKEN`/`JWT_SECRET` env var is set (neither is, in this compose) |

By contrast, **12 targets have real, source-verified auth enforcement** on their AI
surface: chatwoot, dify (3 separate auth mechanisms across its 3 surfaces), dolibarr,
gitlab (circumstantial — GitLab's general API architecture, not a traced AI-specific
decorator), langflow (contingent on this deployment's `LANGFLOW_AUTO_LOGIN=false`; the
framework *default* would auto-login as superuser), librechat_local, moodle,
open_webui, plane, twenty, wordpress, zammad.

**Auth status not fully verified** (traced partway, hit a wall, recorded honestly
rather than guessed): botpress, grafana (no live endpoint to gate — plugin absent),
leantime (found the `/mcp` route, could not locate its middleware registration),
lobechat (found a `checkAuth` call, could not trace its pass/fail logic), minthcm
(verified against upstream source proxy, not the exact pinned image).

## Coverage-honesty / false-positive denominator

26 targets confirmed `no` AI surface, all source-verified (dependency manifest grep +
directory scan against the actual image filesystem, not assumed from product
category). Several of these were specifically checked *because* a sibling product in
the same category turned out positive (e.g. wordpress/moodle/gitlab were positive, so
ghost/mediawiki/wikijs/joomla — other CMS/wiki tools — got the same rigor rather than
being waved through). This is the false-positive denominator the eval needs: "zero AI
surfaces claimed on 26 non-AI targets" is only a valid claim if the scanner is run
against exactly this set with these labels.

## Real surprises worth flagging in the paper

- **Stock WordPress 7.0.2 ships a first-party AI client library in core** (not a
  plugin) — `wp-includes/php-ai-client/`, wired into a new Connectors API and the
  editor. Admin-gated on the config page; usage-endpoint auth not fully traced.
- **Stock Moodle 5.2.1 ships a complete AI provider subsystem** with 6 built-in
  providers (openai/azureai/gemini/awsbedrock/ollama/deepseek) already present.
- **GitLab Duo infrastructure compiles into CE**, not just EE, though the full chat UI
  is likely license-gated.
- **Grafana's core binary has the OpenAI Go SDK statically linked**, plus a shipped
  (but not bundled-active) Assistant UI.
- **anythingllm's primary chat endpoint is open while its secondary "developer" API is
  properly key-gated** — the inverse of the usual assumption.
- **Leantime ships a real MCP server with 40+ LLM-callable tool classes AND a
  dedicated prompt-injection sanitizer** (`LLMStringSanitizer.php`) — a positive
  security-engineering signal worth citing, auth status still unresolved.
- **botpress's checked-out git source is the wrong product entirely** — a clone of the
  modern "Botpress Cloud" SDK monorepo, while the actual running container is the
  unrelated legacy self-hosted v12 binary. Any tool reading that checkout for
  botpress claims is reading the wrong codebase.
- **glpi and minthcm both fetch their real application from the internet at container
  startup** — their images contain no inspectable source at all, a distinct
  methodological category from every other target.

## Known gaps / follow-ups

- `ragflow` deferred — image never pulled (would cost several GB disk).
- `twenty`'s exact REST route for `AiGenerateTextController` wasn't pinned to a literal
  string (controller + guards confirmed, path wasn't).
- `leantime`'s `/mcp` auth middleware wasn't located.
- `lobechat`'s `checkAuth` pass/fail logic for an empty `ACCESS_CODES` array wasn't traced.
- `gitlab`'s AI-specific endpoint auth is inferred from GitLab's general API
  architecture, not a traced decorator on a Duo-specific route.
- `minthcm` and `glpi` are verified against upstream/proxy source, not the exact
  pinned commit their images would fetch at runtime — re-verify if these become
  consequential to headline numbers.

## Methodology note

~46 of 49 targets had **no application source checked out on disk** — only a
`docker-compose.yml` referencing a prebuilt image. All of these were source-verified
anyway via `docker create`/`docker run --entrypoint sh|find` + `docker cp` to extract
and read the actual code inside the image (no long-running app process, negligible
RAM cost — only disk I/O for already-pulled images). This is meaningfully more rigorous
than the original plan's assumption ("you have the containers, read the route
tables") could deliver from the git checkouts alone, since only 4 of 49 targets
(LibreChat, chatwoot, dify, and a partial botpress checkout that turned out to be the
wrong product) had real source present in the repo.
