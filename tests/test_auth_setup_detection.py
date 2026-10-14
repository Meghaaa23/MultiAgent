"""A login that lands on a setup/installation page has valid credentials but no
usable app session (the app is not initialized). It must be reported distinctly
and never counted as a successful login."""
import pytest
from multiagent.agents.webappscanner.auth_session import _looks_like_setup_or_install


@pytest.mark.parametrize("url,content,expected", [
    ("http://h/setup.php", "", True),
    ("http://h/install/", "", True),
    ("http://h/installer", "", True),
    ("http://h/configure.php", "", True),
    ("http://h/wizard", "", True),
    ("http://h/dashboard", "Create / Reset Database", True),
    ("http://h/x", "Installation wizard step 1", True),
    ("http://h/index.php", "Welcome to the app", False),
    ("http://h/account", "your orders and settings", False),
    ("http://h/products?category=setups", "catalog", False),  # not a setup path
])
def test_setup_page_detection(url, content, expected):
    assert _looks_like_setup_or_install(url, content) is expected
