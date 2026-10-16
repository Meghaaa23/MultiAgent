"""
Static configuration tests for container hardening (audit finding F7).

These assert the Dockerfile/Compose declare the hardening (non-root user,
no-new-privileges, all capabilities dropped, read-only root fs with a narrow
writable tmpfs, no privileged mode, no cap_add, no hardcoded secrets). Live
runtime verification (actual UID, browser launch) is done separately against
the built container.
"""
import os
import re

import pytest

yaml = pytest.importorskip("yaml")

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_COMPOSE = os.path.join(_ROOT, "multiagent", "docker-compose.yml")
_DOCKERFILE = os.path.join(_ROOT, "multiagent", "Dockerfile")


@pytest.fixture(scope="module")
def compose():
    with open(_COMPOSE) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def app_svc(compose):
    return compose["services"]["multiagent"]


@pytest.fixture(scope="module")
def dockerfile_text():
    with open(_DOCKERFILE) as f:
        return f.read()


# ---------------------------------------------------------------------------
# Non-root
# ---------------------------------------------------------------------------
def test_compose_runs_as_non_root(app_svc):
    user = str(app_svc.get("user", ""))
    assert user, "multiagent service must set a non-root user"
    uid = user.split(":")[0]
    assert uid not in ("", "0", "root"), f"service must not run as root (user={user!r})"


def test_dockerfile_switches_to_non_root_user(dockerfile_text):
    users = re.findall(r"^\s*USER\s+(\S+)", dockerfile_text, re.MULTILINE)
    assert users, "Dockerfile must set a USER"
    assert users[-1] not in ("root", "0"), f"final USER must be non-root, got {users[-1]!r}"
    # A dedicated unprivileged user is created.
    assert "useradd" in dockerfile_text and "app" in dockerfile_text


# ---------------------------------------------------------------------------
# Capabilities / privileges
# ---------------------------------------------------------------------------
def test_all_capabilities_dropped(app_svc):
    cap_drop = [str(c).upper() for c in app_svc.get("cap_drop", [])]
    assert "ALL" in cap_drop, "multiagent must cap_drop ALL"


def test_no_cap_add(app_svc):
    assert not app_svc.get("cap_add"), "no capabilities should be added back"


def test_not_privileged(app_svc):
    assert app_svc.get("privileged") in (None, False), "privileged mode must not be enabled"


def test_no_new_privileges(app_svc):
    opts = [str(o).replace(" ", "") for o in app_svc.get("security_opt", [])]
    assert any(o.startswith("no-new-privileges:true") for o in opts), \
        "no-new-privileges:true must be set"


# ---------------------------------------------------------------------------
# Filesystem
# ---------------------------------------------------------------------------
def test_read_only_root_fs(app_svc):
    assert app_svc.get("read_only") is True, "root filesystem must be read-only"


def test_writable_tmp_is_narrow_tmpfs(app_svc):
    tmpfs = app_svc.get("tmpfs", [])
    tmpfs = [tmpfs] if isinstance(tmpfs, str) else list(tmpfs)
    assert any(str(t).split(":")[0] == "/tmp" for t in tmpfs), \
        "a writable tmpfs at /tmp is required for the read-only root fs"


def test_no_host_bind_mounts_for_app(app_svc):
    # Named volumes are fine; host bind mounts (./ or /abs) are not expected.
    for v in app_svc.get("volumes", []) or []:
        src = str(v).split(":")[0] if isinstance(v, str) else v.get("source", "")
        assert not str(src).startswith((".", "/")), f"unexpected host bind mount: {v!r}"


# ---------------------------------------------------------------------------
# Networking note (F7 must not revert F2/Docker networking intent)
# ---------------------------------------------------------------------------
def test_host_binding_preserved(app_svc):
    env = app_svc.get("environment", {})
    env = env if isinstance(env, dict) else {
        kv.split("=", 1)[0]: kv.split("=", 1)[1] for kv in env if "=" in kv
    }
    assert env.get("HOST") == "0.0.0.0", "HOST=0.0.0.0 inside the container must be preserved"


# ---------------------------------------------------------------------------
# No hardcoded secrets in image/compose definition
# ---------------------------------------------------------------------------
_SECRET_KEYS = ("API_AUTH_TOKEN", "API_AUTH_TOKENS", "API_ADMIN_TOKEN",
                "AZURE_OPENAI_API_KEY", "NVD_API_KEY", "MONGODB_ATLAS_URI")


def test_no_hardcoded_secrets_in_compose():
    with open(_COMPOSE) as f:
        text = f.read()
    for key in _SECRET_KEYS:
        # A real assignment "KEY=value" must not appear (commented docs are OK).
        for m in re.finditer(rf"(?m)^\s*-?\s*{re.escape(key)}=(.*)$", text):
            line = m.group(0).strip()
            assert line.startswith("#"), f"{key} must not be hardcoded in compose: {line!r}"


def test_no_hardcoded_secrets_in_dockerfile(dockerfile_text):
    for key in _SECRET_KEYS:
        assert re.search(rf"(?m)^\s*ENV\s+{re.escape(key)}\b", dockerfile_text) is None, \
            f"{key} must not be baked into the image"
        assert not re.search(rf"{re.escape(key)}=\S", dockerfile_text), \
            f"{key} must not be assigned a value in the Dockerfile"
    # Secrets are supplied at runtime via env_file.
    with open(_COMPOSE) as f:
        assert "env_file" in f.read()
