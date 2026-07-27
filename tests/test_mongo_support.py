# tests/test_mongo_support.py
from multiagent.agents.mongo_support import sanitize_retrieval_error, mongo_client_kwargs


def test_sanitize_tls_handshake_error():
    raw = (
        "SSL handshake failed: ac-nlznvxv-shard-00-00.r97ace3.mongodb.net:27017: "
        "[SSL: TLSV1_ALERT_INTERNAL_ERROR] tlsv1 alert internal error "
        "(_ssl.c:1032) (configured timeouts: socketTimeoutMS: 20000.0ms)"
    )
    out = sanitize_retrieval_error(raw)
    assert "TLS/SSL handshake failed" in out
    assert "configured timeouts" not in out
    assert "Knowledge base unavailable" in out


def test_sanitize_generic_error():
    out = sanitize_retrieval_error(ValueError("boom"))
    assert "boom" in out


def test_mongo_kwargs_fail_fast_defaults():
    kw = mongo_client_kwargs()
    assert kw["tls"] is True
    assert kw["serverSelectionTimeoutMS"] <= 10000
    assert "tlsCAFile" in kw
