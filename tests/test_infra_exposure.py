"""Generic, signature-gated infra-exposure detection (metrics / directory
listing / Swagger-OpenAPI). Confirmed by response shape only — a bare HTTP 200
or a SPA catch-all shell must NOT trip it (keeps false positives ~0)."""
from multiagent.agents.webappscanner.vulnerability_tester import (
    _classify_infra_exposure, INFRA_EXPOSURE_PATHS,
)

HTML = {"Content-Type": "text/html"}
TEXT = {"Content-Type": "text/plain"}
JSON = {"Content-Type": "application/json"}


class TestMetrics:
    def test_prometheus_help_type_markers(self):
        body = ("# HELP app_requests_total Total requests\n"
                "# TYPE app_requests_total counter\napp_requests_total 5\n")
        hit = _classify_infra_exposure("/metrics", 200, TEXT, body)
        assert hit and hit[0] == "metrics"
        assert hit[2] == "Medium" and hit[3] == "CWE-200"

    def test_plain_text_without_markers_is_not_metrics(self):
        assert _classify_infra_exposure("/metrics", 200, TEXT, "hello world") is None


class TestDirectoryListing:
    def test_serve_index_listing_directory(self):
        body = "<!DOCTYPE html><html><head><title>listing directory /ftp</title></head>"
        hit = _classify_infra_exposure("/ftp", 200, HTML, body)
        assert hit and hit[0] == "directory_listing"
        assert hit[2] == "High" and hit[3] == "CWE-548"

    def test_apache_index_of(self):
        body = "<html><head><title>Index of /files</title></head><body>Index of /files"
        hit = _classify_infra_exposure("/files", 200, HTML, body)
        assert hit and hit[0] == "directory_listing"

    def test_ordinary_page_is_not_a_listing(self):
        body = "<html><head><title>Welcome</title></head><body>Our shop</body></html>"
        assert _classify_infra_exposure("/files", 200, HTML, body) is None


class TestSwaggerOpenAPI:
    def test_swagger_ui_page(self):
        body = ('<!DOCTYPE html><html><head><title>Swagger UI</title>'
                '<link href="./swagger-ui.css"></head><body>'
                '<script>SwaggerUIBundle({})</script></body></html>')
        hit = _classify_infra_exposure("/api-docs/", 200, HTML, body)
        assert hit and hit[0] == "swagger"
        assert hit[2] == "Low"

    def test_openapi_json_spec(self):
        body = '{"openapi":"3.0.0","info":{},"paths":{"/x":{}}}'
        hit = _classify_infra_exposure("/openapi.json", 200, JSON, body)
        assert hit and hit[0] == "swagger"

    def test_swagger_json_spec(self):
        body = '{"swagger":"2.0","paths":{"/a":{}}}'
        assert _classify_infra_exposure("/v2/api-docs", 200, JSON, body)[0] == "swagger"

    def test_unrelated_json_is_not_swagger(self):
        assert _classify_infra_exposure("/api/docs", 200, JSON, '{"data":[1,2,3]}') is None


class TestGatingAndCoverage:
    def test_non_200_never_fires(self):
        body = "# HELP x y\n# TYPE x counter\n"
        assert _classify_infra_exposure("/metrics", 404, TEXT, body) is None
        assert _classify_infra_exposure("/metrics", 401, TEXT, body) is None

    def test_empty_body_never_fires(self):
        assert _classify_infra_exposure("/metrics", 200, TEXT, "") is None

    def test_probe_set_covers_the_three_classes(self):
        assert "/metrics" in INFRA_EXPOSURE_PATHS
        assert "/ftp" in INFRA_EXPOSURE_PATHS
        assert any("api-docs" in p for p in INFRA_EXPOSURE_PATHS)
        assert any("openapi" in p for p in INFRA_EXPOSURE_PATHS)
