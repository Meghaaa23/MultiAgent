"""JSON login-API SQL-injection auth-bypass oracle. Many modern targets (SPA +
REST) leak no SQL error on a bad quote yet fully bypass auth on `' OR 1=1--`,
returning a JWT. The error-pattern check alone misses these; the oracle is
'an injection that must not match returns an authenticated session'."""
from multiagent.agents.webappscanner.vulnerability_tester import (
    _json_login_authenticated, _AUTH_BYPASS_SQLI_PAYLOADS,
)


class TestAuthenticatedResponseOracle:
    def test_jwt_bearing_response_is_authenticated(self):
        body = ('{"authentication":{"token":"eyJ0eXAiOiJKV1Qi.eyJkYXRhIjp7fX0.sig",'
                '"umail":"admin@x"}}')
        assert _json_login_authenticated(body) is True

    def test_token_field_with_real_value(self):
        assert _json_login_authenticated('{"token":"a1b2c3d4e5f6g7"}') is True
        assert _json_login_authenticated('{"access_token":"abcdef123456"}') is True

    def test_invalid_login_is_not_authenticated(self):
        assert _json_login_authenticated('{"error":"Invalid email or password."}') is False
        assert _json_login_authenticated('{"status":"fail"}') is False

    def test_success_word_alone_is_not_enough(self):
        # must not fire on a bare success envelope with no token
        assert _json_login_authenticated('{"status":"success","data":[]}') is False

    def test_empty_token_is_not_authenticated(self):
        # a short/empty token value must not trip the field regex
        assert _json_login_authenticated('{"token":""}') is False
        assert _json_login_authenticated('{"token":"short"}') is False

    def test_empty_body(self):
        assert _json_login_authenticated("") is False
        assert _json_login_authenticated(None) is False


class TestBypassPayloads:
    def test_classic_or_1eq1_is_probed(self):
        assert "' OR 1=1--" in _AUTH_BYPASS_SQLI_PAYLOADS
        assert any("'1'='1'" in p for p in _AUTH_BYPASS_SQLI_PAYLOADS)
