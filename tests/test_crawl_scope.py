"""The crawl must stay on the target host (general, not app-specific), so it
never wanders onto third-party sites a page links to — which were a false-
positive source (open redirect / CSRF on google.com links)."""
import pytest
from multiagent.agents.webappscanner import browser_controller as bc

Ctrl = [v for v in vars(bc).values() if isinstance(v, type)
        and v.__name__.endswith("Controller")][0]


def _c(base="http://localhost:3008"):
    c = Ctrl.__new__(Ctrl)
    c._session_base = base
    return c


@pytest.mark.parametrize("url,inscope", [
    ("/category/view?id=1", True),
    ("http://localhost:3008/x", True),
    ("http://localhost:3008", True),
    ("page.php?q=1", True),
    ("#section", True),
    ("https://www.google.com/maps/answer/1", False),
    ("https://support.google.com/", False),
    ("//google.com/sorry/index", False),           # scheme-relative external
    ("http://localhost:9999/", False),             # different port = different host
    ("", False),
])
def test_in_scope(url, inscope):
    assert _c()._in_scope(url) is inscope


def test_no_base_means_permissive():
    assert _c(base="")._in_scope("https://anything.example.com/") is True
