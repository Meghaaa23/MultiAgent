"""
Offline regression harness tests — ground truth must stay durable.

Run:
  PYTHONPATH=/workspace:/workspace/multiagent \\
    python3 -m pytest tests/test_regression_harness.py -q
"""
import json
import pytest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "multiagent" / "multiagent-testbed"))

from regression_eval import (
    load_truth,
    score_scan,
    finding_matches_expected,
    resolve_truth_for_fixture,
    FIXTURES_DIR,
    TRUTH_DIR,
)

def _load_fixture(name: str) -> dict:
    for sub in ("golden", "negative", ""):
        path = FIXTURES_DIR / sub / name if sub else FIXTURES_DIR / name
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    raise FileNotFoundError(name)

class TestGroundTruthFilesExist:
    def test_core_labels_present(self):
        for name in (
            "dvwa.json",
            "juice_shop.json",
            "librechat_marketing.json",
            "librechat_local.json",
            "webgoat.json",
        ):
            assert (TRUTH_DIR / name).exists()

class TestLibrechatLocalGoldenPass:
    def test_librechat_local_passes(self):
        truth = load_truth("librechat_local")
        scan = _load_fixture("librechat_local_unauth.json")
        score = score_scan(truth, scan)
        assert score["must_not_violations"] == []
        assert score["pass"] is True
        assert score["fp"] == 0

class TestWebgoatUnauthHeadersPass:
    def test_webgoat_golden_passes(self):
        truth = load_truth("webgoat")
        scan = _load_fixture("webgoat_unauth_headers_only.json")
        score = score_scan(truth, scan)
        assert score["must_not_violations"] == []
        assert score["fn"] == 0
        assert score["tp"] >= 3
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
        assert score["fn"] == 0
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


class TestTruthResolution:
    """Fixtures must be graded against their own ground truth. Raw string
    prefix matching let `http://localhost` (freescout) claim every localhost
    fixture and `http://localhost:80` (dify) claim :8001/:8017/:8080."""

    @pytest.mark.parametrize("fixture,expected", [
        ("golden/dvwa_unauth_headers_only.json", "dvwa"),
        ("golden/librechat_local_unauth.json", "librechat_local"),
        ("golden/librechat_marketing_clean.json", "librechat_marketing"),
        ("golden/webgoat_unauth_headers_only.json", "webgoat"),
        ("negative/dvwa_timing_sqli_http0_fp.json", "dvwa"),
        ("negative/juice_shop_cors_csrf_fp.json", "juice_shop"),
    ])
    def test_every_fixture_resolves_to_its_own_truth(self, fixture, expected):
        path = FIXTURES_DIR / fixture
        scan = json.loads(path.read_text(encoding="utf-8"))
        scan = scan.get("scan", scan) if "vulnerabilities" not in scan else scan
        truth = resolve_truth_for_fixture(path, scan)
        assert truth is not None and truth["target"] == expected

    @pytest.mark.parametrize("url,expected", [
        ("http://localhost:3141", "juice_shop"),
        ("http://localhost:8001", "dvwa"),
        ("http://localhost:8080/WebGoat/login", "webgoat"),
        ("http://localhost/", "freescout"),
        ("http://localhost:80", "freescout"),
    ])
    def test_url_alias_matches_by_origin_not_prefix(self, url, expected):
        truth = resolve_truth_for_fixture(Path("unnamed_scan.json"), {"target_url": url})
        assert truth is not None and truth["target"] == expected

    def test_unknown_url_resolves_to_nothing(self):
        assert resolve_truth_for_fixture(
            Path("unnamed_scan.json"), {"target_url": "http://localhost:59999"}) is None


class TestHeaderSpecMatching:
    SPEC = {"type": "missing_header", "name": "Content-Security-Policy"}

    def test_header_finding_matches(self):
        f = {"type": "Missing Security Header: Content-Security-Policy"}
        assert finding_matches_expected(f, self.SPEC)

    def test_xss_mentioning_csp_does_not_match_header_spec(self):
        f = {"type": "Reflected XSS",
             "details": "No Content-Security-Policy mitigates this XSS."}
        assert not finding_matches_expected(f, self.SPEC)

    def test_other_header_does_not_match(self):
        f = {"type": "Missing Security Header: X-Content-Type-Options"}
        assert not finding_matches_expected(f, self.SPEC)


def test_score_reports_optional_fn_count_and_list():
    truth = {"target": "t", "expected_findings": [
        {"type": "xss", "required": False, "id": "opt-xss"}]}
    s = score_scan(truth, {"vulnerabilities": []})
    assert s["fn_optional_count"] == 1
    assert s["fn_optional"] == ["opt-xss"]
