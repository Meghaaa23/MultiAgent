#!/usr/bin/env bash
# Probe every SURFACE-40 target URL from ground_truth/targets.json.
# Run on the Ubuntu host after compose is up. No VM involved.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'PY'
import json, sys, time, urllib.error, urllib.request
from pathlib import Path

targets = json.loads(Path("ground_truth/targets.json").read_text())["targets"]
ok = fail = 0
width = max(len(t["name"]) for t in targets)
print(f"{'#':>3}  {'app':<{width}}  {'code':<6}  url")
for t in targets:
    url = t["url"]
    code = "ERR"
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "surface-testbed-healthcheck"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                code = str(resp.status)
            break
        except urllib.error.HTTPError as e:
            code = str(e.code)  # 401/403/404 still means the app is listening
            break
        except Exception as e:
            code = type(e).__name__
            if attempt < 2:
                time.sleep(2)
    listening = code.isdigit()
    flag = "OK" if listening else "DOWN"
    if listening:
        ok += 1
    else:
        fail += 1
    print(f"{t['id']:3d}  {t['name']:<{width}}  {code:<6}  {url}  {flag}")
print(f"\nlistening={ok}  down={fail}  total={len(targets)}")
sys.exit(1 if fail else 0)
PY
