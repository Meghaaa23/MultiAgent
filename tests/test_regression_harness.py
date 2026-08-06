"""
Offline regression harness tests — ground truth must stay durable.

Run:
  PYTHONPATH=/workspace:/workspace/multiagent \\
    python3 -m pytest tests/test_regression_harness.py -q
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "multiagent" / "multiagent-testbed"))

from regression_eval import (  # noqa: E402
    load_truth,
    score_scan,
    FIXTURES_DIR,
    TRUTH_DIR,
)


def _load_fixture(name: str) -> dict:
    for sub in ("golden", "negative", ""):
        path = FIXTURES_DIR / sub / name if sub else FIXTURES_DIR / name
        if path.exists():
            return json.loads(path.read_text())
    raise FileNotFoundError(name)


class TestGroundTruthFilesExist:
    def test_core_labels_present(self):
        for name in (
            "dvwa.json",
            "juice_shop.json",
            "librechat_marketing.json",
            "webgoat.json",
        ):
            assert (TRUTH_DIR / name).exists()


class TestWebgoatUnauthHeadersPass:
    def test_webgoat_golden_passes(self):
        truth = load_truth("webgoat")
        scan = _load_fixture("webgoat_unauth_headers_only.json")
        score = score_scan(truth, scan)
        assert score["must_not_violations"] == []
        assert score["fn"] == 0
        assert score["tp"] >= 3  # CSP, XCTO, clickjacking
        assert score["not_assessed_count"] >= 1
        assert score["pass"] is True
        tp_types = " ".join(t.get("type", "") for t in score.get("tp_detail") or []).lower()
        assert "clickjacking" in tp_types


class TestDvwaUnauthHeadersPass:
    def test_current_honest_dvwa_report_passes(self):
        truth = load_truth("dvwa")
        scan = _load_fixture("dvwa_unauth_headers_only.json")
        score = score_scan(truth, scan)
        assert score["must_not_violations"] == []
        assert score["fn"] == 0  # required headers present
        assert score["tp"] >= 3
        assert score["not_assessed_count"] >= 4
        assert score["pass"] is True
        assert score["precision"] >= 0.9


class TestMustNotReportRegression:
    def test_timing_http0_is_hard_fp(self):
        truth = load_truth("dvwa")
        scan = _load_fixture("dvwa_timing_sqli_http0_fp.json")
        score = score_scan(truth, scan)
        assert score["must_not_violations"], "HTTP 0 timing SQLi must violate must_not"
        assert score["pass"] is False

    def test_juice_cors_high_csrf_login_and_fake_cve_fail(self):
        truth = load_truth("juice_shop")
        scan = _load_fixture("juice_shop_cors_csrf_fp.json")
        score = score_scan(truth, scan)
        reasons = " ".join(
            (v.get("reason") or "") + " " + (v.get("type") or "")
            for v in score["must_not_violations"]
        ).lower()
        assert "csrf" in reasons or any(
            "csrf" in (v.get("type") or "").lower()
            for v in score["must_not_violations"]
        )
        assert any(
            "cors" in (v.get("type") or "").lower()
            or "credentials" in (v.get("reason") or "").lower()
            for v in score["must_not_violations"]
        )
        assert any(
            "cve" in (v.get("type") or "").lower()
            for v in score["must_not_violations"]
        )
        assert score["pass"] is False


class TestLibrechatMarketingClean:
    def test_empty_findings_pass(self):
        truth = load_truth("librechat_marketing")
        scan = _load_fixture("librechat_marketing_clean.json")
        score = score_scan(truth, scan)
        assert score["fp"] == 0
        assert score["must_not_violations"] == []
        assert score["pass"] is True


class TestAuthGatedNotCountedAsFn:
    def test_missing_sqli_behind_login_is_not_required_fn(self):
        """Black-box unauth: classic DVWA SQLi is out of scope, not FN."""
        truth = load_truth("dvwa")
        scan = _load_fixture("dvwa_unauth_headers_only.json")
        score = score_scan(truth, scan)
        assert "sqli" not in score["fn_required"]
        assert score["not_assessed_count"] >= 1
