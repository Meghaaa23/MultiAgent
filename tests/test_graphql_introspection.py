"""GraphQL introspection exposure detection (a class neither Black Widow nor
YuraScanner reports). Confirmed only by a real __schema response."""
import asyncio
import json
from multiagent.agents.webappscanner.vulnerability_tester import VulnerabilityTester

SCHEMA = json.dumps({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [{"name": "Query"}, {"name": "User"}, {"name": "Product"}]}}})


def _agent(responses):
    t = VulnerabilityTester()
    async def fake(url, method="get", data=None, follow_redirects=True,
                   timeout=None, json_body=False):
        return responses.get(url, (404, {}, ""))
    t._http_request = fake
    return t


def _run(t, base, paths=None):
    return asyncio.new_event_loop().run_until_complete(
        t.test_graphql_introspection(base, paths))


def test_introspection_enabled_is_flagged():
    t = _agent({"http://h/graphql": (200, {"Content-Type": "application/json"}, SCHEMA)})
    out = _run(t, "http://h")
    assert len(out) == 1
    assert "GraphQL Introspection Enabled" in out[0]["type"]
    assert out[0]["status"] == "Confirmed" and out[0]["severity"] == "Medium"


def test_discovered_graphql_path_is_probed():
    t = _agent({"http://h/api/v2/graphql": (200, {}, SCHEMA)})
    out = _run(t, "http://h", ["http://h/api/v2/graphql"])
    assert len(out) == 1


def test_introspection_disabled_not_flagged():
    err = json.dumps({"errors": [{"message": "introspection is disabled"}]})
    t = _agent({"http://h/graphql": (200, {}, err)})
    assert _run(t, "http://h") == []


def test_non_graphql_200_not_flagged():
    t = _agent({"http://h/graphql": (200, {"Content-Type": "text/html"},
                                     "<html>not graphql</html>")})
    assert _run(t, "http://h") == []


def test_no_graphql_endpoint_yields_nothing():
    assert _run(_agent({}), "http://h") == []
