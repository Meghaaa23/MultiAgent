"""Zero false-positive gates for open redirect and XSS confirmation."""
from multiagent.agents.webappscanner.vulnerability_tester import (
    _open_redirect_to_attacker,
)


def test_open_redirect_rejects_same_origin_echo():
    # Zapier-style: Location stays on same site, evil URL only in query.
    assert not _open_redirect_to_attacker(
        "/google-sso/start/?scopes=basic&next=https%3A%2F%2Fevil-test-redirect.example.com",
        "https://evil-test-redirect.example.com",
    )
    assert not _open_redirect_to_attacker(
        "/app/home?next=https://evil-test-redirect.example.com",
        "https://evil-test-redirect.example.com",
    )


def test_open_redirect_accepts_external_host():
    assert _open_redirect_to_attacker(
        "https://evil-test-redirect.example.com/phish",
        "https://evil-test-redirect.example.com",
    )
    assert _open_redirect_to_attacker(
        "//evil-test-redirect.example.com/x",
        "//evil-test-redirect.example.com",
    )


def test_open_redirect_rejects_unrelated_host():
    assert not _open_redirect_to_attacker(
        "https://accounts.google.com/o/oauth",
        "https://evil-test-redirect.example.com",
    )
