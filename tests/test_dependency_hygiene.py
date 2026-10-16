"""
Supply-chain / dependency-hygiene regression tests (audit finding F8).

Guards against re-introducing the F8 issues: the ambiguous `autogen` (AG2)
dependency, unpinned direct dependencies, loss of the deterministic lock, or
re-declaring verified-unused heavy packages as direct production deps.
"""
import os
import re

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_REQ = os.path.join(_ROOT, "multiagent", "requirements.txt")
_LOCK = os.path.join(_ROOT, "multiagent", "requirements.lock.txt")
_DOCKERFILE = os.path.join(_ROOT, "multiagent", "Dockerfile")

# Packages removed in F8 as verified-unused; must not reappear as DIRECT deps.
_REMOVED_DIRECT = {
    "autogen", "ag2", "pyautogen", "transformers", "langchain",
    "langchain-community", "langchain-core", "langchain-text-splitters",
    "python-multipart", "pytesseract", "pymupdf", "speechrecognition",
}


def _direct_specs(path):
    specs = []
    with open(path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            specs.append(line.split("#", 1)[0].strip())
    return specs


def _name(spec):
    return re.split(r"[=<>!~ ]", spec, maxsplit=1)[0].strip().lower().replace("_", "-")


def test_all_direct_deps_are_exact_pinned():
    for spec in _direct_specs(_REQ):
        assert "==" in spec, f"direct dependency must be exact-pinned: {spec!r}"


def test_no_ambiguous_autogen_ag2():
    names = {_name(s) for s in _direct_specs(_REQ)}
    for bad in ("autogen", "ag2", "pyautogen"):
        assert bad not in names, (
            f"ambiguous AG2 package {bad!r} must not be a direct dependency; "
            f"the app uses autogen-agentchat / autogen-core"
        )
    # The Microsoft packages the app actually imports ARE present.
    assert "autogen-agentchat" in names
    assert "autogen-core" in names


def test_previously_unpinned_now_pinned():
    specs = {_name(s): s for s in _direct_specs(_REQ)}
    for pkg in ("autogen-agentchat", "ddgs", "requests"):
        assert pkg in specs and "==" in specs[pkg], f"{pkg} must be exact-pinned"


def test_removed_unused_packages_not_direct():
    names = {_name(s) for s in _direct_specs(_REQ)}
    offending = names & _REMOVED_DIRECT
    assert not offending, f"verified-unused packages re-added as direct deps: {offending}"


def test_lock_file_exists_and_fully_pinned():
    assert os.path.exists(_LOCK), "requirements.lock.txt must exist for reproducible builds"
    specs = _direct_specs(_LOCK)
    assert specs, "lock file must not be empty"
    for spec in specs:
        assert "==" in spec, f"lock entries must be exact-pinned: {spec!r}"


def test_dockerfile_installs_from_lock():
    with open(_DOCKERFILE) as f:
        text = f.read()
    assert "requirements.lock.txt" in text, "Dockerfile must install from the lock"


def test_hard_imports_are_declared():
    # Packages the app imports at import time must be declared directly.
    names = {_name(s) for s in _direct_specs(_REQ)}
    for pkg in ("fastapi", "uvicorn", "openai", "python-dotenv", "autogen-agentchat",
                "autogen-core", "playwright", "httpx", "sqlalchemy", "packaging",
                "pydantic", "redis", "beautifulsoup4", "ddgs"):
        assert pkg in names, f"hard import {pkg!r} must be a declared direct dependency"
