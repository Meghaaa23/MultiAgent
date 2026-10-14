"""Open redirect confirms only when the Location points at the attacker host —
not when a same-site redirect merely echoes the payload in a query parameter,
which caused a false-positive cluster on external links during a live scan."""
import pytest
from multiagent.agents.webappscanner.attack_verification_agent import _redirect_goes_to_host


@pytest.mark.parametrize("loc,goes", [
    ("https://evil.com", True),
    ("//evil.com", True),
    ("https://evil.com/path", True),
    ("http://sub.evil.com/", True),
    ("https://trusted.example.com@evil.com/", True),  # userinfo trick
    ("/maps/answer?next=https://evil.com", False),     # same-site echo
    ("/search?url=//evil.com", False),
    ("https://www.google.com/maps/answer/123", False), # external, not evil
    ("/account", False),
    ("", False),
])
def test_redirect_goes_to_host(loc, goes):
    assert _redirect_goes_to_host(loc, "evil.com") is goes
