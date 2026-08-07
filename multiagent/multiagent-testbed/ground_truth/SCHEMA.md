# Ground-truth schema (black-box unauthenticated)

Operating point: **precision-first**. Recall is reported honestly; auth-gated
surfaces are `not_assessed`, not false negatives.

## File shape

```json
{
  "target": "dvwa",
  "scope": "blackbox_unauth",
  "url_aliases": ["http://localhost:3142", "http://localhost:8001"],
  "endpoints_true": ["/login.php", "/setup.php"],
  "endpoints_auth_gated": ["/index.php", "/security.php"],
  "ai_surface": {
    "has_ai_surface": "no",
    "ai_endpoints_true": [],
    "ai_auth_gated": null,
    "chat_ui_present": false,
    "injection_authorized": true,
    "soft_404_behavior": "proper_404",
    "stack_true": {"framework": "PHP/DVWA", "language": "PHP"}
  },
  "expected_findings": [
    {
      "id": "dvwa-csp",
      "type": "missing_header",
      "name": "Content-Security-Policy",
      "severity": "Medium",
      "required": true,
      "category": "missing_check"
    }
  ],
  "out_of_scope_types": ["sqli", "xss", "csrf", "fileupload", "cmdi"],
  "must_not_report": [
    {
      "type": "sql injection (time-based blind)",
      "match": "evidence_status_0",
      "reason": "HTTP 0 timeout is not SLEEP confirmation",
      "category": "logic_bug"
    }
  ]
}
```

## Categories

| category | Meaning |
|---|---|
| `logic_bug` | Finite detector bug; every closed instance becomes a `must_not_report` regression |
| `missing_check` | Scope gap / not yet implemented; optional `required: false` |
| `irreducible` | Black-box cannot decide; counted as `not_assessed` |

## Matching

- Findings matched by normalised `type` (+ optional `name` / `path` / severity caps)
- `must_not_report` hits are hard false positives
- Auth-gated endpoints → `not_assessed` count (never FN)
- `out_of_scope_types` found unauthenticated are ignored for precision (bonus), not required for recall

## `ai_surface` fields (AI attack-surface ground truth)

Hand-labeled from the target's own source (these are containerized clones — read the
route tables directly, don't infer from the product name).

| field | type | meaning |
|---|---|---|
| `has_ai_surface` | `"yes"` / `"no"` / `"partial"` / `"unverifiable"` | Does the app expose a live chat/inference surface at all? `"partial"` covers several distinct sub-cases (a live, auth-gated, but provider-key-inert endpoint; an AI SDK/UI compiled in with the activating plugin absent; a platform capability with no live instance provisioned) — the exact flavor is always spelled out in `notes`, not encoded further here. `"unverifiable"` = the target's own image contains no application source to inspect at all (e.g. it fetches its real app from the internet at container startup) — use this instead of guessing `"no"`. |
| `ai_endpoints_true` | `string[]` | The actual chat/completion/inference route paths, from source (e.g. `/api/messages`, `/api/ask`, `/v1/chat/completions`). Empty if `has_ai_surface: "no"`. |
| `ai_auth_gated` | `bool \| null` | Whether the AI endpoints require auth. `null` if `has_ai_surface: "no"` (not applicable). |
| `chat_ui_present` | `bool` | Is there an on-page chat widget/UI (first-party or embedded third-party)? Independent of `has_ai_surface` — a vendor widget can be present without a first-party inference endpoint. |
| `injection_authorized` | `bool` | Whether prompt-injection testing against this target is authorized. Always `true` for this testbed (own containers) — recorded explicitly per target so the field is never silently assumed. |
| `soft_404_behavior` | `"catch_all_spa"` / `"proper_404"` | Whether unknown paths return a same-shape 200 (SPA catch-all) or a real 404. Ground truth for the soft-404 filter, independent of AI surface. |
| `stack_true` | `{"framework": string, "language": string}` | Actual framework/language from source (package.json, Dockerfile, etc.), not inferred from headers. |

Recall/precision against `ai_endpoints_true` and `has_ai_surface` are computed the same
precision-first way as `endpoints_true`: auth-gated AI surfaces the scanner correctly
declares (not silently omits or falsely clears) count toward coverage honesty, not
against recall.
