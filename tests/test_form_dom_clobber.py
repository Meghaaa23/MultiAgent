"""Regression: DOM clobbering (a form control named "action") makes the browser
hand back a non-string form action. It must never crash form dedup or the
task loop's string handling.
"""
import sys, os
ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "multiagent"))

from multiagent.agents.webappscanner.web_scanner_agent import _dedup_forms


def test_dedup_forms_survives_dict_action():
    forms = [
        {"action": {"clobbered": "input-element"}, "method": "post"},  # dict action
        {"action": "http://h/submit", "method": "post"},
        {"action": "http://h/submit", "method": "post"},  # dup
    ]
    out = _dedup_forms(forms)          # must not raise TypeError: unhashable
    assert any(f["action"] == "http://h/submit" for f in out)
    assert len(out) == 2               # dict-action form + one real, dup removed


def test_dedup_forms_ignores_non_dupes_and_bad_entries():
    forms = [{"action": "/a"}, {"action": "/b"}, "not-a-dict", {"action": "/a"}]
    out = _dedup_forms(forms)
    assert [f["action"] for f in out] == ["/a", "/b"]


def _controller():
    import agents.webappscanner.browser_controller as bc
    Ctrl = [v for v in vars(bc).values() if isinstance(v, type)
            and v.__name__.endswith("Controller")][0]
    try:
        return Ctrl(None)
    except TypeError:
        return Ctrl.__new__(Ctrl)


def test_normalize_form_coerces_dict_action_to_string():
    c = _controller()
    out = c._normalize_form({"action": {"x": 1}, "method": {"y": 2},
                             "id": {"z": 3}, "inputs": [{"name": "q"}]})
    assert out["action"] == "" and isinstance(out["action"], str)
    assert out["method"] == "get" and isinstance(out["method"], str)
    assert isinstance(out["id"], str)
    assert out["fields"] == [{"name": "q"}]


def test_normalize_form_keeps_real_string_action():
    c = _controller()
    out = c._normalize_form({"action": "http://h/x", "method": "post",
                             "inputs": []})
    assert out["action"] == "http://h/x" and out["method"] == "post"
