"""A server banner is a disclosure only when it reveals a software version
(what enables targeted CVE lookup). Bare names and free-form banners are not."""
import pytest
from multiagent.agents.webappscanner.vulnerability_tester import _server_header_is_leaky


@pytest.mark.parametrize("value,leaky", [
    ("Apache/2.4.25 (Debian)", True),
    ("Apache/2.4.7 (Ubuntu)", True),
    ("Microsoft-IIS/10.0", True),
    ("PHP/8.1", True),
    ("gunicorn/20.1.0", True),
    ("nginx/1.25.3", True),
    ("WrongSecrets - Star us!", False),   # free-form banner, no version
    ("nginx", False),                     # bare product name
    ("Apache", False),
    ("", False),
])
def test_server_header_leak(value, leaky):
    assert _server_header_is_leaky(value) is leaky
