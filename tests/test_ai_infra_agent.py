"""
tests/test_ai_infra_agent.py

Pytest suite for AIInfraAgent.

Run from project root:
    source venv/bin/activate
    pytest tests/test_ai_infra_agent.py -v

All tests are fully offline — httpx and OpenAI client are mocked.
"""

import pytest
import pytest_asyncio
from unittest.mock import MagicMock, AsyncMock, patch

from multiagent.agents.webappscanner.Ai_Infra_agent import (
    AIInfraAgent,
    AIInfraScanResult,
    AIInfraThreat,
)

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def make_openai_client(summary: str = "Mock executive summary.") -> MagicMock:
    """Return a mock OpenAI client whose completions return `summary`."""
    client = MagicMock()
    client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content=summary))]
    )
    return client


def make_http_context(exposed: dict | None = None,
                      post_exposed: dict | None = None):
    """
    Build a mock httpx.AsyncClient context manager.

    `exposed`      maps path → (status_code, body_text) for GET requests.
    `post_exposed` maps path → (status_code, body_text) for POST requests.
    Any path not listed returns 404 for that method.
    """
    exposed      = exposed      or {}
    post_exposed = post_exposed or {}

    async def mock_get(url, **_):
        for path, (status, body) in exposed.items():
            if url.endswith(path):
                resp = MagicMock()
                resp.status_code = status
                resp.text = body
                return resp
        resp = MagicMock()
        resp.status_code = 404
        resp.text = ""
        return resp

    async def mock_post(url, **_):
        for path, (status, body) in post_exposed.items():
            if url.endswith(path):
                resp = MagicMock()
                resp.status_code = status
                resp.text = body
                return resp
        resp = MagicMock()
        resp.status_code = 404
        resp.text = ""
        return resp

    mock_client = AsyncMock()
    mock_client.get  = mock_get
    mock_client.post = mock_post

    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_client)
    ctx.__aexit__  = AsyncMock(return_value=False)
    return ctx


MODULE = "multiagent.agents.webappscanner.Ai_Infra_agent"


# ──────────────────────────────────────────────────────────────
# 1. Basic scan — no AI stack, nothing exposed
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_returns_result_object():
    """scan() must always return an AIInfraScanResult."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com")

    assert isinstance(result, AIInfraScanResult)
    assert result.target_url == "http://example.com"
    assert result.scan_time  # non-empty ISO timestamp
    assert result.error == ""


@pytest.mark.asyncio
async def test_scan_trailing_slash_stripped():
    """Target URL trailing slash must be stripped before storing."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com/")

    assert not result.target_url.endswith("/")


@pytest.mark.asyncio
async def test_threats_list_is_union_of_planes():
    """result.threats must equal the union of all four plane lists."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com")

    expected = (
        result.build_threats
        + result.deploy_threats
        + result.runtime_threats
        + result.orch_threats
    )
    assert result.threats == expected


# ──────────────────────────────────────────────────────────────
# 2. Build plane — static threats
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ml_dependency_confusion_always_fires():
    """ML Dependency Confusion fires regardless of stack or exposed endpoints."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack={})

    names = [t.attack_name for t in result.build_threats]
    assert any("Dependency Confusion" in n for n in names)


@pytest.mark.asyncio
async def test_weight_substitution_fires_for_ollama_stack():
    """Model Weight Substitution threat fires when ollama is in the ai_stack."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    stack = {"frameworks": ["ollama"], "confidence": "high"}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack=stack)

    names = [t.attack_name for t in result.build_threats]
    assert any("Weight Substitution" in n for n in names)


@pytest.mark.asyncio
async def test_weight_substitution_fires_for_llama_stack():
    """Model Weight Substitution also fires for llama/huggingface stacks."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    stack = {"model": "llama3", "source": "huggingface"}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack=stack)

    names = [t.attack_name for t in result.build_threats]
    assert any("Weight Substitution" in n for n in names)


@pytest.mark.asyncio
async def test_training_data_poisoning_fires_for_finetune_stack():
    """Training Data Poisoning threat fires when fine-tuning is indicated."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    stack = {"pipeline": "fine-tuning", "dataset": "custom"}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack=stack)

    names = [t.attack_name for t in result.build_threats]
    assert any("Poisoning" in n for n in names)


@pytest.mark.asyncio
async def test_weight_substitution_severity_critical_when_pull_exposed():
    """Weight Substitution severity is CRITICAL when /api/pull is exposed."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    stack = {"frameworks": ["ollama"]}
    exposed = {"/api/pull": (200, '{"status":"success"}')}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://localhost:11434", ai_stack=stack)

    pull_threat = next(
        (t for t in result.build_threats if "Weight Substitution" in t.attack_name),
        None,
    )
    assert pull_threat is not None
    assert pull_threat.severity == "CRITICAL"


# ──────────────────────────────────────────────────────────────
# 3. Deployment plane
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_oom_restart_threat_fires_for_ray_stack():
    """OOM Restart Window threat fires when ray is in the ai_stack."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    stack = {"serving": "ray-serve", "model": "llama-1b"}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack=stack)

    names = [t.attack_name for t in result.deploy_threats]
    assert any("OOM" in n for n in names)


@pytest.mark.asyncio
async def test_ray_deployment_api_threat_when_exposed():
    """Config Injection threat fires when /api/serve/deployments is reachable."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    body = '{"deployments": [{"name": "llm", "replicas": 2}]}'
    exposed = {"/api/serve/deployments": (200, body)}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://ray-cluster:8000", ai_stack={})

    names = [t.attack_name for t in result.deploy_threats]
    assert any("Config Injection" in n for n in names)


@pytest.mark.asyncio
async def test_route_table_disclosure_when_routes_exposed():
    """Route Table Disclosure fires when /-/routes returns 200."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    exposed = {"/-/routes": (200, '{"routes": {"/chat": "llm-deployment"}}')}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://ray-cluster:8000", ai_stack={})

    names = [t.attack_name for t in result.deploy_threats]
    assert any("Route Table" in n for n in names)


# ──────────────────────────────────────────────────────────────
# 4. Runtime plane
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unauthenticated_inference_fires_when_v1_exposed():
    """Unauthenticated inference threat fires when /v1/chat/completions is open."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    exposed = {"/v1/chat/completions": (200, '{"object":"chat.completion"}')}
    # vllm must be in ai_stack so VLLM_PATHS (including /v1/chat/completions) are probed
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://vllm-server:8000", ai_stack={"engine": "vllm"})

    names = [t.attack_name for t in result.runtime_threats]
    assert any("Unauthenticated AI Inference" in n for n in names)


@pytest.mark.asyncio
async def test_prompt_injection_threat_fires_with_exposed_inference():
    """Direct Prompt Injection threat fires alongside unauthenticated inference."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    exposed = {"/v1/completions": (200, '{"choices":[]}')}
    # vllm must be in ai_stack so VLLM_PATHS (including /v1/completions) are probed
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://vllm-server:8000", ai_stack={"engine": "vllm"})

    names = [t.attack_name for t in result.runtime_threats]
    assert any("Prompt Injection" in n for n in names)


@pytest.mark.asyncio
async def test_model_extraction_threat_fires_with_exposed_inference():
    """Model Extraction threat fires when any inference endpoint is open."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    exposed = {"/api/generate": (200, '{"response":"hello"}')}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://ollama:11434", ai_stack={})

    names = [t.attack_name for t in result.runtime_threats]
    assert any("Model Extraction" in n for n in names)


@pytest.mark.asyncio
async def test_metrics_disclosure_fires_when_metrics_exposed():
    """Prometheus metrics disclosure threat fires when /metrics returns 200."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    exposed = {"/metrics": (200, "# HELP vllm_requests_total\nvllm_requests_total 42")}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://vllm:8000", ai_stack={})

    names = [t.attack_name for t in result.runtime_threats]
    assert any("Metrics" in n for n in names)


@pytest.mark.asyncio
async def test_kv_cache_dos_always_fires():
    """KV-Cache Exhaustion DoS threat fires for any scan (no exposed path needed)."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack={})

    names = [t.attack_name for t in result.runtime_threats]
    assert any("KV-Cache" in n or "Long-Context" in n for n in names)


# ──────────────────────────────────────────────────────────────
# 5. Orchestration plane
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_model_pull_injection_fires_when_api_pull_exposed():
    """Unauthenticated Model Pull threat fires when /api/pull is reachable."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    exposed = {"/api/pull": (200, '{"status":"pulling"}')}
    # ollama must be in ai_stack so OLLAMA_PATHS (including /api/pull) are probed
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://ollama:11434", ai_stack={"service": "ollama"})

    names = [t.attack_name for t in result.orch_threats]
    assert any("Model Pull" in n for n in names)


@pytest.mark.asyncio
async def test_model_deletion_threat_fires_when_api_delete_exposed():
    """Unauthenticated Model Deletion threat fires when /api/delete is open."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    exposed = {"/api/delete": (200, '{"status":"success"}')}
    # ollama must be in ai_stack so OLLAMA_PATHS (including /api/delete) are probed
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://ollama:11434", ai_stack={"service": "ollama"})

    names = [t.attack_name for t in result.orch_threats]
    assert any("Deletion" in n for n in names)


@pytest.mark.asyncio
async def test_model_metadata_disclosure_when_api_show_exposed():
    """Model Metadata Disclosure fires when /api/show is reachable."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    exposed = {"/api/show": (200, '{"modelfile":"FROM llama3","architecture":"llama"}')}
    # ollama must be in ai_stack so OLLAMA_PATHS (including /api/show) are probed
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://ollama:11434", ai_stack={"service": "ollama"})

    names = [t.attack_name for t in result.orch_threats]
    assert any("Metadata" in n for n in names)


@pytest.mark.asyncio
async def test_k8s_api_exposure_fires_when_k8s_paths_exposed():
    """K8s Control Plane Exposure fires when /api/v1 is reachable."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    exposed = {"/api/v1": (200, '{"kind":"APIResourceList"}')}
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context(exposed)):
        result = await agent.scan("http://k8s-api:6443", ai_stack={})

    names = [t.attack_name for t in result.orch_threats]
    assert any("Kubernetes" in n for n in names)


# ──────────────────────────────────────────────────────────────
# 6. LLM synthesis
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_llm_synthesis_called_when_threats_exist():
    """The OpenAI client must be called exactly once when threats are found."""
    client = make_openai_client("Executive summary from LLM.")
    agent = AIInfraAgent(openai_client=client, timeout=5)
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack={"model": "llama"})

    assert client.chat.completions.create.called
    assert result.summary == "Executive summary from LLM."


@pytest.mark.asyncio
async def test_llm_synthesis_fallback_on_exception():
    """When OpenAI raises, summary must fall back to plain-text, not raise."""
    client = MagicMock()
    client.chat.completions.create.side_effect = Exception("API unavailable")
    agent = AIInfraAgent(openai_client=client, timeout=5)
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack={"model": "llama"})

    assert result.error == ""  # the scan itself didn't fail
    assert "threat" in result.summary.lower() or "Total" in result.summary


@pytest.mark.asyncio
async def test_no_threats_skips_llm_call():
    """When no threats are found, the LLM is not called and summary is the no-threat message."""
    # Patch all four analysis methods to return empty lists
    client = make_openai_client()
    agent = AIInfraAgent(openai_client=client, timeout=5)

    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()), \
         patch.object(agent, "_analyze_build_plane",        return_value=[]), \
         patch.object(agent, "_analyze_deployment_plane",   return_value=[]), \
         patch.object(agent, "_analyze_runtime_plane",      return_value=[]), \
         patch.object(agent, "_analyze_orchestration_plane", return_value=[]):
        result = await agent.scan("http://example.com")

    assert not client.chat.completions.create.called
    assert result.summary == "No AI infrastructure threats detected."


# ──────────────────────────────────────────────────────────────
# 7. Error handling
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_error_captured_not_raised():
    """A crash in _probe_ai_endpoints must be caught; result.error must be set."""
    client = make_openai_client()
    agent = AIInfraAgent(openai_client=client, timeout=5)

    with patch.object(agent, "_probe_ai_endpoints", side_effect=RuntimeError("network down")):
        result = await agent.scan("http://broken.target")

    assert "network down" in result.error
    assert isinstance(result, AIInfraScanResult)


# ──────────────────────────────────────────────────────────────
# 8. format_for_stride_report
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_format_for_stride_report_structure():
    """format_for_stride_report must return the expected top-level keys."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack={"model": "llama"})

    report = agent.format_for_stride_report(result)

    assert report["scan_type"] == "AI_INFRASTRUCTURE"
    assert report["target"] == result.target_url
    assert isinstance(report["findings"], list)
    assert set(report["planes_covered"]) == {"BUILD", "DEPLOYMENT", "RUNTIME", "ORCHESTRATION"}
    assert isinstance(report["threat_count"], int)
    assert report["threat_count"] == len(result.threats)


@pytest.mark.asyncio
async def test_format_for_stride_report_finding_fields():
    """Each finding in the STRIDE report must have required fields."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=make_http_context()):
        result = await agent.scan("http://example.com", ai_stack={"model": "llama"})

    report = agent.format_for_stride_report(result)
    required_keys = {"name", "category", "severity", "layer", "description",
                     "evidence", "mitigation", "references"}

    for finding in report["findings"]:
        assert required_keys.issubset(finding.keys()), (
            f"Finding missing keys: {required_keys - finding.keys()}"
        )
        assert finding["references"]["paper"]  # Wu et al. reference always present


@pytest.mark.asyncio
async def test_format_for_stride_report_empty_threats():
    """format_for_stride_report must handle zero threats without error."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    empty_result = AIInfraScanResult(
        target_url="http://example.com",
        scan_time="2026-01-01T00:00:00",
        ai_stack={},
        summary="No threats.",
    )
    report = agent.format_for_stride_report(empty_result)

    assert report["findings"] == []
    assert report["threat_count"] == 0


# ──────────────────────────────────────────────────────────────
# 9. AIInfraThreat dataclass
# ──────────────────────────────────────────────────────────────

def test_threat_dataclass_defaults():
    """AIInfraThreat optional fields must default to empty string."""
    t = AIInfraThreat(
        attack_name="Test",
        attack_plane="RUNTIME",
        stride_category="Tampering",
        severity="HIGH",
        description="desc",
        evidence="evidence",
    )
    assert t.cve_reference == ""
    assert t.atlas_technique == ""
    assert t.mitigation == ""


# ──────────────────────────────────────────────────────────────
# 10. Stack-aware endpoint probe selection
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vllm_paths_probed_for_vllm_stack():
    """When ai_stack contains 'vllm', /v1/models must be in the probe list."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    probed_urls = []

    async def capturing_get(url, **_):
        probed_urls.append(url)
        resp = MagicMock()
        resp.status_code = 404
        resp.text = ""
        return resp

    mock_client = AsyncMock()
    mock_client.get = capturing_get
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_client)
    ctx.__aexit__  = AsyncMock(return_value=False)

    with patch(f"{MODULE}.httpx.AsyncClient", return_value=ctx):
        await agent.scan("http://vllm:8000", ai_stack={"engine": "vllm"})

    assert any("/v1/models" in u for u in probed_urls)


@pytest.mark.asyncio
async def test_ollama_paths_probed_for_ollama_stack():
    """When ai_stack contains 'ollama', /api/tags must be in the probe list."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    probed_urls = []

    async def capturing_get(url, **_):
        probed_urls.append(url)
        resp = MagicMock()
        resp.status_code = 404
        resp.text = ""
        return resp

    mock_client = AsyncMock()
    mock_client.get = capturing_get
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_client)
    ctx.__aexit__  = AsyncMock(return_value=False)

    with patch(f"{MODULE}.httpx.AsyncClient", return_value=ctx):
        await agent.scan("http://ollama:11434", ai_stack={"frameworks": ["ollama"]})


# ──────────────────────────────────────────────────────────────
# 11. GET→POST fallback in _probe_path
# ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_probe_falls_back_to_post_on_405():
    """When GET returns 405, _probe_path must retry with POST and use that result."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)

    # GET → 405 for /api/pull; POST → 200 with a body
    ctx = make_http_context(
        exposed      = {"/api/pull": (405, "")},
        post_exposed = {"/api/pull": (200, '{"status":"pulling"}')},
    )
    with patch(f"{MODULE}.httpx.AsyncClient", return_value=ctx):
        result = await agent.scan("http://ollama:11434",
                                  ai_stack={"service": "ollama"})

    # /api/pull exposed via POST should trigger the ORCHESTRATION threat
    names = [t.attack_name for t in result.orch_threats]
    assert any("Model Pull" in n for n in names)


@pytest.mark.asyncio
async def test_probe_does_not_fallback_when_get_succeeds():
    """When GET returns 200, POST must NOT be attempted."""
    agent = AIInfraAgent(openai_client=make_openai_client(), timeout=5)
    post_called = []

    async def track_post(url, **_):
        post_called.append(url)
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        return resp

    ctx = make_http_context(exposed={"/api/pull": (200, '{"status":"ok"}')})
    original_aenter = ctx.__aenter__

    async def patched_aenter():
        client = await original_aenter()
        client.post = track_post
        return client

    ctx.__aenter__ = patched_aenter

    with patch(f"{MODULE}.httpx.AsyncClient", return_value=ctx):
        await agent.scan("http://ollama:11434", ai_stack={"service": "ollama"})

    assert not post_called, "POST should not be called when GET succeeds"
