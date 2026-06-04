#!/usr/bin/env python3
import argparse, json, time, urllib.request, urllib.error
from datetime import datetime
from pathlib import Path
import subprocess, sys

SCANNER_BASE_URL = "http://localhost:8000"
SCANNER_TIMEOUT  = 300

SCRIPT_DIR   = Path(__file__).parent
TARGETS_FILE = SCRIPT_DIR / "targets.json"
RESULTS_DIR  = SCRIPT_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def load_targets(group=None, target_id=None):
    with open(TARGETS_FILE) as f:
        manifest = json.load(f)
    targets = manifest["targets"]
    if target_id:
        targets = [t for t in targets if t["id"] == target_id]
    if group:
        targets = [t for t in targets if t["group"] == group]
    return targets


def is_reachable(url, timeout=5):
    try:
        req = urllib.request.urlopen(url, timeout=timeout)
        return req.status < 500
    except Exception:
        return False


def snapshot(tag="pre-test"):
    result = subprocess.run(["bash", str(SCRIPT_DIR / "snapshot.sh"), tag],
                            capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "snapshots/" in line:
            return line.split("snapshots/")[-1].strip()
    return tag


def restore(snapshot_name):
    result = subprocess.run(["bash", str(SCRIPT_DIR / "restore.sh"), snapshot_name],
                            capture_output=True, text=True)
    return result.returncode == 0


def run_scan(target, agent_cmd=None):
    tid  = target["id"]
    name = target["name"]
    url  = target["url"]
    print("\n  ┌─ [" + str(tid).zfill(2) + "] " + name + " @ " + url)

    if not is_reachable(url):
        print("  │  ⚠  Target not reachable, skipping.")
        return {"target_id": tid, "status": "unreachable", "findings": []}

    try:
        urllib.request.urlopen(SCANNER_BASE_URL + "/health", timeout=5)
    except Exception:
        print("  │  ✗  Scanner not running at " + SCANNER_BASE_URL)
        print("  │     Start: uvicorn main:app --host 0.0.0.0 --port 8080")
        return {"target_id": tid, "status": "scanner_offline", "findings": []}

    session_id = "testbed-" + str(tid) + "-" + str(int(time.time()))
    payload    = json.dumps({"target_url": url, "session_id": session_id}).encode()
    start      = time.time()

    try:
        req = urllib.request.Request(
            SCANNER_BASE_URL + "/scan/",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=SCANNER_TIMEOUT) as resp:
            elapsed   = round(time.time() - start, 1)
            scan_resp = json.loads(resp.read().decode())

        print("  │  ✓  Scan done in " + str(elapsed) + "s")

        # /scan/ returns vulnerabilities at the top level
        findings = scan_resp.get("vulnerabilities") or []
        if not findings:
            # fallback: nested scan_results structure
            scan_data = scan_resp.get("scan_results") or scan_resp.get("data") or {}
            if isinstance(scan_data, dict):
                findings = (scan_data.get("vulnerabilities") or
                            scan_data.get("findings") or
                            scan_data.get("issues") or [])
            elif isinstance(scan_data, list):
                findings = scan_data

        raw_path = RESULTS_DIR / (name.lower().replace(" ", "_") + "_" + session_id + ".json")
        open(raw_path, "w").write(json.dumps(scan_resp, indent=2))

        result = {
            "target_id": tid, "target_name": name, "url": url,
            "group": target["group"], "known_vulns": target.get("known_vulns", []),
            "session_id": session_id, "scan_time_s": elapsed,
            "status": "done", "findings": findings,
        }

    except urllib.error.HTTPError as e:
        elapsed = round(time.time() - start, 1)
        body    = e.read().decode("utf-8", errors="replace")[:300]
        print("  │  ✗  HTTP " + str(e.code) + " — " + body)
        result  = {"target_id": tid, "status": "http_" + str(e.code), "findings": [], "error": body}
    except Exception as e:
        elapsed = round(time.time() - start, 1)
        print("  │  ✗  Error: " + str(e))
        result  = {"target_id": tid, "status": "error", "findings": [], "error": str(e)}

    print("  └─ findings: " + str(len(result.get("findings", []))))
    return result


def run_suite(targets, reset_after=False):
    suite_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    print("\n" + "="*60)
    print("  MULTIAGENT TESTBED RUN  [" + suite_id + "]")
    print("  Targets: " + str(len(targets)))
    print("="*60)

    snap_name = None
    if reset_after:
        print("\n  Taking pre-suite snapshot...")
        snap_name = snapshot("pre-suite")

    all_results = []
    for target in targets:
        result = run_scan(target)
        result["suite_id"]  = suite_id
        result["timestamp"] = datetime.now().isoformat()
        all_results.append(result)
        if reset_after and snap_name:
            print("  Restoring " + snap_name + "...")
            restore(snap_name)
            time.sleep(5)

    done     = [r for r in all_results if r["status"] == "done"]
    skipped  = [r for r in all_results if r["status"] != "done"]
    total_f  = sum(len(r.get("findings", [])) for r in done)

    print("\n" + "="*60)
    print("  SUITE COMPLETE")
    print("  Scanned:   " + str(len(done)) + "/" + str(len(all_results)))
    print("  Findings:  " + str(total_f))
    print("  Skipped:   " + str(len(skipped)))
    print("="*60 + "\n")

    report      = {"suite_id": suite_id, "run_at": datetime.now().isoformat(),
                   "total_targets": len(all_results), "successful_scans": len(done),
                   "total_findings": total_f, "results": all_results}
    report_path = RESULTS_DIR / ("suite_" + suite_id + ".json")
    open(report_path, "w").write(json.dumps(report, indent=2))
    print("  Report saved: " + str(report_path))
    return report


def main():
    parser = argparse.ArgumentParser(description="Multiagent testbed harness")
    parser.add_argument("--all",          action="store_true")
    parser.add_argument("--target",       type=int, metavar="ID")
    parser.add_argument("--group",        type=str)
    parser.add_argument("--reset-after",  action="store_true")
    parser.add_argument("--list",         action="store_true")
    parser.add_argument("--health-check", action="store_true")
    args = parser.parse_args()

    if args.list:
        targets = load_targets()
        print("\n  " + "ID".ljust(4) + "NAME".ljust(22) + "GROUP")
        for t in targets:
            print("  " + str(t["id"]).ljust(4) + t["name"].ljust(22) + t["group"])
        return

    if args.health_check:
        targets = load_targets()
        print("\n  Health checking all targets...")
        for t in targets:
            ok     = is_reachable(t["url"])
            status = "✓ up  " if ok else "✗ down"
            color  = "\033[32m" if ok else "\033[31m"
            print("  " + color + status + "\033[0m [" + str(t["id"]).zfill(2) + "] " + t["name"] + " — " + t["url"])
        return

    if args.all:
        targets = load_targets()
    elif args.target:
        targets = load_targets(target_id=args.target)
        if not targets:
            print("No target with ID " + str(args.target)); sys.exit(1)
    elif args.group:
        targets = load_targets(group=args.group)
        if not targets:
            print("No targets in group " + args.group); sys.exit(1)
    else:
        parser.print_help(); sys.exit(0)

    run_suite(targets, reset_after=args.reset_after)


if __name__ == "__main__":
    main()
