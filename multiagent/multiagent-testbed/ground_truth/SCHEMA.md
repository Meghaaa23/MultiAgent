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
  "ai_surface": null,
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
