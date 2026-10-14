"""Exposed Spring Boot Actuator detection.

Evidence-driven: probe the actuator index once, confirm it by its ``_links``
response shape, then follow only the sub-endpoints it advertises. No guessing,
no false positives on apps that have no actuator.
"""
import asyncio
import json

from multiagent.agents.webappscanner.vulnerability_tester import VulnerabilityTester


def _agent_with_responses(responses):
    """responses: {url: (status, headers, body)}. Unlisted urls -> 404."""
    t = VulnerabilityTester()

    def fake_fetch(url):
        return responses.get(url, (404, {}, ""))

    t._fetch_full = fake_fetch
    return t


def _run(t, base):
    return asyncio.new_event_loop().run_until_complete(
        t.test_management_exposure(base))


JSON_CT = {"Content-Type": "application/vnd.spring-boot.actuator.v3+json"}


def _index(links):
    return json.dumps({"_links": {k: {"href": f"http://h/actuator/{k}",
                                       "templated": False} for k in links}})


def test_actuator_index_exposure_is_flagged():
    t = _agent_with_responses({
        "http://h/actuator": (200, JSON_CT, _index(["self", "health", "info"])),
    })
    out = _run(t, "http://h")
    types = [f["type"] for f in out]
    assert any("Spring Boot Actuator Exposed" in x for x in types)
    idx = next(f for f in out if "Actuator Exposed" in f["type"])
    assert idx["severity"] == "Medium"
    assert idx["status"] == "Confirmed"


def test_sensitive_subendpoint_is_high():
    t = _agent_with_responses({
        "http://h/actuator": (200, JSON_CT, _index(["self", "env", "health"])),
        "http://h/actuator/env": (200, JSON_CT, '{"propertySources":[]}'),
    })
    out = _run(t, "http://h")
    env = [f for f in out if f["type"].endswith("env Exposed")]
    assert env and env[0]["severity"] == "High"


def test_health_alone_is_not_reported_as_sensitive():
    # /actuator/health is commonly public; only the index (Medium) is flagged.
    t = _agent_with_responses({
        "http://h/actuator": (200, JSON_CT, _index(["self", "health"])),
        "http://h/actuator/health": (200, JSON_CT, '{"status":"UP"}'),
    })
    out = _run(t, "http://h")
    assert not any("health" in f["type"].lower() for f in out)
    assert len(out) == 1  # index only


def test_no_actuator_yields_nothing():
    t = _agent_with_responses({
        "http://h/actuator": (404, {}, ""),
    })
    assert _run(t, "http://h") == []


def test_200_without_links_is_not_flagged():
    # A soft-404 / app shell returning 200 must not be mistaken for actuator.
    t = _agent_with_responses({
        "http://h/actuator": (200, {"Content-Type": "text/html"},
                              "<html><body>Not found</body></html>"),
    })
    assert _run(t, "http://h") == []


def test_subendpoint_not_followed_when_index_absent():
    # env only counts if the index advertises it AND it returns 200.
    t = _agent_with_responses({
        "http://h/actuator": (200, JSON_CT, _index(["self", "info"])),
    })
    out = _run(t, "http://h")
    assert not any("env" in f["type"].lower() for f in out)
