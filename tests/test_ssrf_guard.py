"""
Security tests for the SSRF egress guard (audit finding F1).

These tests prove the core property: a caller cannot use the scanner as a
network pivot to reach non-public destinations unless the operator has
explicitly authorized that destination via SSRF_INTERNAL_ALLOWLIST.

All DNS is simulated (offline): named test hosts are mapped to fixed IPs, while
IP literals and numeric/alternate representations go through the real local
resolver (which needs no network).
"""
import ipaddress
import socket

import pytest

from multiagent.agents.webappscanner import ssrf_guard
from multiagent.agents.webappscanner.ssrf_guard import (
    EgressPolicy, SSRFBlocked, validate_url, load_policy_from_env, guarded_egress,
)

# Named hosts -> resolved IPs (everything else falls through to the real resolver)
_FAKE_DNS = {
    "public.example.com":   ["93.184.216.34"],
    "attacker.example.com": ["93.184.216.34"],
    "rebind.evil.com":      ["127.0.0.1"],          # public name -> loopback
    "private.example.com":  ["10.0.0.5"],           # public name -> RFC1918
    "dual.example.com":     ["93.184.216.34", "127.0.0.1"],  # mixed answer set
    "host.docker.internal": ["172.17.0.1"],
    "testbed.internal":     ["192.168.50.10"],
}

_REAL_GAI = ssrf_guard._ORIG_GETADDRINFO


def _fake_getaddrinfo(host, *args, **kwargs):
    if host in _FAKE_DNS:
        out = []
        for ip in _FAKE_DNS[host]:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            out.append((fam, socket.SOCK_STREAM, 6, "", (ip, 0)))
        return out
    return _REAL_GAI(host, *args, **kwargs)


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    monkeypatch.setattr(ssrf_guard, "_ORIG_GETADDRINFO", _fake_getaddrinfo)
    yield


@pytest.fixture
def public_policy():
    # No allowlist -> public-only.
    return EgressPolicy(allow_internal=False)


@pytest.fixture
def internal_policy():
    # Operator explicitly authorizes one testbed host and one /24.
    return EgressPolicy(
        allow_internal=True,
        internal_hosts={"testbed.internal"},
        internal_networks=[ipaddress.ip_network("192.168.50.0/24")],
    )


# ---------------------------------------------------------------------------
# MUST REJECT (public-only policy)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/x",
    "http://localhost/",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",     # cloud metadata
    "http://10.0.0.1/",                              # RFC1918
    "http://172.16.0.1/",                            # RFC1918
    "http://192.168.0.1/",                           # RFC1918
    "http://[fc00::1]/",                             # IPv6 ULA
    "http://[fe80::1]/",                             # IPv6 link-local
    "http://0.0.0.0/",                               # unspecified v4
    "http://[::]/",                                  # unspecified v6
    "http://172.17.0.1/",                            # docker bridge gateway
    "http://host.docker.internal/",                  # docker host alias
    "http://rebind.evil.com/",                       # public name -> loopback
    "http://private.example.com/",                   # public name -> RFC1918
    "http://dual.example.com/",                      # mixed set, one private
    "http://2130706433/",                            # decimal form of 127.0.0.1
    "http://[::ffff:127.0.0.1]/",                    # IPv4-mapped loopback
    "http://100.64.0.1/",                            # CGNAT (not globally routable)
])
def test_rejects_non_public(url, public_policy):
    with pytest.raises(SSRFBlocked):
        validate_url(url, public_policy)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "ftp://example.com/",
    "ssh://host/",
    "data:text/plain,hi",
    "",
    "not-a-url",
    "http://",
    "http:///only-path",
    "http://user:pass@127.0.0.1/",       # userinfo + loopback
    "http://expected@attacker.example.com/",  # userinfo trick to a public host
    "http://exa mple.com/",              # space in host
])
def test_rejects_malformed_or_scheme_or_userinfo(url, public_policy):
    with pytest.raises(SSRFBlocked):
        validate_url(url, public_policy)


# ---------------------------------------------------------------------------
# MUST ALLOW (public targets)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("url", [
    "http://public.example.com/",
    "https://public.example.com/path?q=1",
])
def test_allows_public(url, public_policy):
    target = validate_url(url, public_policy)
    assert target.host == "public.example.com"
    assert target.ips == ["93.184.216.34"]


# ---------------------------------------------------------------------------
# INTERNAL scanning only via explicit allowlist
# ---------------------------------------------------------------------------
def test_internal_blocked_without_allowlist(public_policy):
    with pytest.raises(SSRFBlocked):
        validate_url("http://testbed.internal/", public_policy)


def test_internal_allowed_by_host(internal_policy):
    target = validate_url("http://testbed.internal/login", internal_policy)
    assert target.ips == ["192.168.50.10"]


def test_internal_allowed_by_network(internal_policy):
    # Same /24, different host literal resolving into it.
    assert validate_url("http://192.168.50.77/", internal_policy)


def test_internal_allowlist_does_not_permit_other_private(internal_policy):
    # Allowlisting the testbed must NOT open other private ranges or metadata.
    with pytest.raises(SSRFBlocked):
        validate_url("http://10.0.0.1/", internal_policy)
    with pytest.raises(SSRFBlocked):
        validate_url("http://169.254.169.254/", internal_policy)
    with pytest.raises(SSRFBlocked):
        validate_url("http://127.0.0.1/", internal_policy)


# ---------------------------------------------------------------------------
# Redirect public -> private: the redirect *target* must be rejected.
# ---------------------------------------------------------------------------
def test_redirect_target_to_private_is_rejected(public_policy):
    # A 302 from public.example.com to any of these is re-validated per hop.
    for redirect_location in ("http://127.0.0.1/", "http://169.254.169.254/",
                              "http://10.0.0.1/"):
        with pytest.raises(SSRFBlocked):
            validate_url(redirect_location, public_policy)


# ---------------------------------------------------------------------------
# Connect-time enforcement (covers urllib/httpx/requests, rebinding, redirects)
# ---------------------------------------------------------------------------
def test_getaddrinfo_guard_inert_without_policy():
    # Outside a guarded scan the patched resolver must behave normally.
    assert ssrf_guard.current_policy() is None
    infos = socket.getaddrinfo("127.0.0.1", 80)
    assert infos  # no exception


def test_getaddrinfo_guard_blocks_private_during_scan(public_policy):
    with guarded_egress(public_policy):
        with pytest.raises(SSRFBlocked):
            socket.getaddrinfo("127.0.0.1", 80)
        with pytest.raises(SSRFBlocked):
            socket.getaddrinfo("169.254.169.254", 80)
        # public still resolves fine
        assert socket.getaddrinfo("public.example.com", 443)
    # policy cleared after the context exits
    assert ssrf_guard.current_policy() is None


def test_getaddrinfo_guard_allows_internal_only_when_configured(internal_policy, public_policy):
    with guarded_egress(public_policy):
        with pytest.raises(SSRFBlocked):
            socket.getaddrinfo("testbed.internal", 80)
    with guarded_egress(internal_policy):
        assert socket.getaddrinfo("testbed.internal", 80)


# ---------------------------------------------------------------------------
# Config-driven policy (the "authenticated-operator internal scanning" switch)
# ---------------------------------------------------------------------------
def test_policy_public_only_when_allowlist_unset(monkeypatch):
    monkeypatch.delenv("SSRF_INTERNAL_ALLOWLIST", raising=False)
    monkeypatch.delenv("ACTIVE_MODEL_PROVIDER", raising=False)
    pol = load_policy_from_env()
    assert pol.allow_internal is False
    with pytest.raises(SSRFBlocked):
        validate_url("http://testbed.internal/", pol)


def test_policy_parses_hosts_and_cidrs(monkeypatch):
    monkeypatch.setenv("SSRF_INTERNAL_ALLOWLIST", "testbed.internal, 192.168.50.0/24, 10.1.2.3")
    pol = load_policy_from_env()
    assert pol.allow_internal is True
    assert "testbed.internal" in pol.internal_hosts
    assert any(str(n) == "192.168.50.0/24" for n in pol.internal_networks)
    # host form of a bare IP is accepted either as a host or /32 network
    assert validate_url("http://testbed.internal/", pol)


def test_docker_url_resolution_gating():
    """_resolve_docker_url must NOT translate localhost unless authorized."""
    from multiagent.agents.webappscanner.web_scanner_agent import _resolve_docker_url

    # No active policy -> no translation.
    assert _resolve_docker_url("http://localhost:3000/x") == "http://localhost:3000/x"

    # Active public-only policy -> no translation (internal not authorized).
    with guarded_egress(EgressPolicy(allow_internal=False)):
        assert _resolve_docker_url("http://localhost:3000/x") == "http://localhost:3000/x"
        assert _resolve_docker_url("http://127.0.0.1/y") == "http://127.0.0.1/y"
