"""
test_request_templates.py
Tests for REQUEST_TEMPLATES, _select_template, _template_name, _extract_by_path.
"""
import json
import pytest
from multiagent.agents.ai_agents.ai_vulnerability_test import (
    REQUEST_TEMPLATES, _select_template, _template_name, _extract_by_path,
)


# ---------------------------------------------------------------------------
# _select_template
# ---------------------------------------------------------------------------

class TestSelectTemplate:

    def test_openai_chat_path(self):
        tmpl = _select_template("/v1/chat/completions")
        assert _template_name(tmpl) == "openai_chat"

    def test_openai_chat_api_prefix(self):
        tmpl = _select_template("/api/chat/completions")
        assert _template_name(tmpl) == "openai_chat"

    def test_openai_completions_path(self):
        tmpl = _select_template("/v1/completions")
        assert _template_name(tmpl) == "openai_completions"

    def test_ollama_chat_path(self):
        tmpl = _select_template("/api/chat")
        assert _template_name(tmpl) == "ollama_chat"

    def test_ollama_generate_path(self):
        tmpl = _select_template("/api/generate")
        assert _template_name(tmpl) == "ollama_generate"

    def test_flowise_path(self):
        tmpl = _select_template("/api/v1/prediction")
        assert _template_name(tmpl) == "flowise"

    def test_tgi_path(self):
        tmpl = _select_template("/generate")
        assert _template_name(tmpl) == "tgi"

    def test_generic_predict_path(self):
        tmpl = _select_template("/predict")
        assert _template_name(tmpl) == "generic_prompt"

    def test_generic_inference_path(self):
        tmpl = _select_template("/inference")
        assert _template_name(tmpl) == "generic_prompt"

    def test_unknown_path_defaults_to_openai_chat(self):
        tmpl = _select_template("/some/unknown/endpoint")
        assert _template_name(tmpl) == "openai_chat"

    def test_case_insensitive_path_matching(self):
        tmpl = _select_template("/V1/Chat/Completions")
        assert _template_name(tmpl) == "openai_chat"

    def test_path_with_query_string(self):
        tmpl = _select_template("/v1/chat/completions?stream=false")
        assert _template_name(tmpl) == "openai_chat"


# ---------------------------------------------------------------------------
# Template body builders
# ---------------------------------------------------------------------------

class TestTemplateBodies:

    def test_openai_chat_body_structure(self):
        tmpl = REQUEST_TEMPLATES["openai_chat"]
        body = tmpl["body"]("Hello world", None)
        assert "model" in body
        assert "messages" in body
        assert body["messages"][0]["role"] == "user"
        assert body["messages"][0]["content"] == "Hello world"

    def test_openai_chat_body_custom_model(self):
        tmpl = REQUEST_TEMPLATES["openai_chat"]
        body = tmpl["body"]("Hi", "gpt-4o")
        assert body["model"] == "gpt-4o"

    def test_openai_completions_body(self):
        tmpl = REQUEST_TEMPLATES["openai_completions"]
        body = tmpl["body"]("Complete this:", None)
        assert "prompt" in body
        assert body["prompt"] == "Complete this:"

    def test_ollama_chat_no_stream(self):
        tmpl = REQUEST_TEMPLATES["ollama_chat"]
        body = tmpl["body"]("Test", None)
        assert body["stream"] is False

    def test_flowise_body_uses_question_key(self):
        tmpl = REQUEST_TEMPLATES["flowise"]
        body = tmpl["body"]("What is AI?", None)
        assert "question" in body
        assert body["question"] == "What is AI?"

    def test_tgi_body_has_parameters(self):
        tmpl = REQUEST_TEMPLATES["tgi"]
        body = tmpl["body"]("prompt text", None)
        assert "inputs" in body
        assert "parameters" in body
        assert body["parameters"]["max_new_tokens"] > 0

    def test_generic_body_has_multiple_keys(self):
        tmpl = REQUEST_TEMPLATES["generic_prompt"]
        body = tmpl["body"]("test", None)
        assert "prompt" in body
        assert "input" in body
        assert "query" in body


# ---------------------------------------------------------------------------
# _extract_by_path
# ---------------------------------------------------------------------------

class TestExtractByPath:

    def test_simple_key(self):
        data = {"text": "hello"}
        assert _extract_by_path(data, "text") == "hello"

    def test_nested_dotted_key(self):
        data = {"message": {"content": "world"}}
        assert _extract_by_path(data, "message.content") == "world"

    def test_array_index(self):
        data = {"choices": [{"text": "answer"}]}
        assert _extract_by_path(data, "choices[0].text") == "answer"

    def test_openai_chat_parse_path(self):
        data = {"choices": [{"message": {"content": "Hello!"}}]}
        result = _extract_by_path(data, "choices[0].message.content")
        assert result == "Hello!"

    def test_none_parse_key_returns_json_string(self):
        data = {"a": 1, "b": 2}
        result = _extract_by_path(data, None)
        parsed = json.loads(result)
        assert parsed == data

    def test_none_parse_key_on_string_returns_string(self):
        result = _extract_by_path("raw response text", None)
        assert result == "raw response text"

    def test_tgi_parse_path(self):
        data = {"generated_text": "output here"}
        assert _extract_by_path(data, "generated_text") == "output here"