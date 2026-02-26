"""Tests for runtime configuration."""

from skillshield.config import Config


def test_default_llm_models_are_sonnet_46(monkeypatch) -> None:
    """Defaults should use Sonnet 4.6 for both bulk and deep analysis."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SKILLSHIELD_LLM_API_KEY", raising=False)
    monkeypatch.delenv("SKILLSHIELD_LLM_MODEL_BULK", raising=False)
    monkeypatch.delenv("SKILLSHIELD_LLM_MODEL_DEEP", raising=False)
    monkeypatch.delenv("SKILLSHIELD_LLM_TIMEOUT_S", raising=False)
    monkeypatch.delenv("SKILLSHIELD_LLM_MAX_OUTPUT_TOKENS", raising=False)

    config = Config.load()

    assert config.llm_api_key is None
    assert config.llm_model_bulk == "claude-sonnet-4-6"
    assert config.llm_model_deep == "claude-sonnet-4-6"
    assert config.llm_timeout_s == 30
    assert config.llm_max_output_tokens == 1600


def test_llm_models_can_be_overridden(monkeypatch) -> None:
    """Environment overrides should be respected."""
    monkeypatch.setenv("SKILLSHIELD_LLM_API_KEY", "sk-test")
    monkeypatch.setenv("SKILLSHIELD_LLM_MODEL_BULK", "custom-model-bulk")
    monkeypatch.setenv("SKILLSHIELD_LLM_MODEL_DEEP", "custom-model-deep")
    monkeypatch.setenv("SKILLSHIELD_LLM_TIMEOUT_S", "45")
    monkeypatch.setenv("SKILLSHIELD_LLM_MAX_OUTPUT_TOKENS", "2200")

    config = Config.load()

    assert config.llm_api_key == "sk-test"
    assert config.llm_model_bulk == "custom-model-bulk"
    assert config.llm_model_deep == "custom-model-deep"
    assert config.llm_timeout_s == 45
    assert config.llm_max_output_tokens == 2200
