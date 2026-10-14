# Ground truth for scanner evaluation

Four benchmark targets, with the vulnerabilities each is known to contain, so a
scan can be scored for precision, recall and accuracy. Endpoints marked
`"source": "confirmed_live"` were verified reachable on the running containers
on 2026-09-24; `"documented"` entries come from each app's published design and
should be confirmed against your instance before counting them.

| Target | File | URL | Server (observed) |
|---|---|---|---|
| DVWA | `dvwa.json` | http://localhost:3001 | Apache/2.4.25 (Debian) |
| WebGoat | `webgoat.json` | http://localhost:3002/WebGoat | Spring/embedded (no Server header) |
| Hackazon | `hackazon.json` | http://localhost:3008 | Apache/2.4.7 (Ubuntu) |
| WrongSecrets | `wrongsecrets.json` | http://localhost:3007 | `WrongSecrets - Star us!` (no version) |

## Per-finding fields

| field | meaning |
|---|---|
| `id` | stable identifier for this expected finding |
| `type` | canonical class: `sqli`, `sqli-blind`, `xss-reflected`, `xss-stored`, `xss-dom`, `cmdi`, `lfi`, `rfi`, `file-upload`, `csrf`, `open-redirect`, `ssrf`, `idor`, `xxe`, `insecure-deserialization`, `jwt`, `path-traversal`, `weak-auth`, `weak-session`, `default-credentials`, `hardcoded-secret`, `sensitive-exposure`, `missing_header`, `server_header` |
| `name` | human label |
| `path` | URL path of the injection point (relative to the target URL) |
| `parameter` | vulnerable parameter, when applicable |
| `method` | HTTP method |
| `severity` | `critical` / `high` / `medium` / `low` |
| `cwe`, `owasp` | references |
| `auth_required` | true when a valid session is needed to reach it |
| `blackbox_detectable` | true when a DAST scanner can confirm it without login and without multi-step, human-guided interaction |
| `required` | true = counts toward recall; false = optional/credit-only |
| `source` | `confirmed_live` or `documented` |

Each file also carries `must_not_report`: findings a precise scanner must NOT
raise on that target. Reporting one is a false positive.

## Scoring

Match a scanner finding to an expected finding when the canonical `type` agrees
and the `path` matches (host + path, ignoring query and trailing slash). Then:

- **TP** — a scanner finding that matches a `required` expected finding.
- **FP** — a scanner finding that matches no expected finding, or matches a
  `must_not_report` entry.
- **FN** — a `required` expected finding with no matching scanner finding.

```
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * precision * recall / (precision + recall)
```

Report recall against two denominators, because most DVWA and WebGoat
vulnerabilities are post-login and multi-step:

- **recall_all** — over every `required` finding.
- **recall_blackbox** — over `required` findings with `blackbox_detectable: true`.
  This is the fair denominator for an unauthenticated DAST run.

### Accuracy

Accuracy needs true negatives, which are undefined for open-ended scanning: the
number of vulnerabilities an app does *not* have is unbounded. Compute accuracy
only over a fixed decision grid you define, e.g. every (tested endpoint × the
vulnerability classes above). For each cell the scan either reports the class or
not, and the ground truth says whether it should:

```
accuracy = (TP + TN) / (TP + TN + FP + FN)
```

Without such a grid, report precision, recall and F1 and omit accuracy.

## Notes on the targets

- **DVWA** — every `/vulnerabilities/*` module is behind login (`admin` /
  `password`) and needs the database created at `/setup.php`. Unauthenticated,
  only the missing headers and the Apache version banner are detectable.
- **WebGoat** — a teaching app. Almost every lesson needs a registered session
  and specific, guided multi-step input, so `blackbox_detectable` is false for
  nearly all of it. A low unauthenticated recall here reflects the target, not
  the scanner.
- **Hackazon** — a realistic shop with genuine unauthenticated injection points
  (`/category/view?id=`, `/product/view?id=`, `/search?q=`). This is the best
  recall target of the four for a black-box scan.
- **WrongSecrets** — a secrets-management CTF, not a classic web-vuln app. It
  has no SQLi/XSS/CSRF by design, so those are false-positive traps. Its real
  exposures are the unauthenticated Spring Boot Actuator endpoints and its
  many hardcoded secrets. Treat WrongSecrets mainly as a precision test.
