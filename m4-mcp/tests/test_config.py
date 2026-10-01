"""Unit tests for config parsing."""

import pytest

from tracehunt_mcp.config import Config


def test_defaults(monkeypatch):
    monkeypatch.delenv("TRACEHUNT_INDICES", raising=False)
    monkeypatch.delenv("TRACEHUNT_ES_URL", raising=False)
    monkeypatch.delenv("TRACEHUNT_RUN_ID", raising=False)
    cfg = Config.from_env()
    assert cfg.indices == ("windows-security", "sysmon", "zeek")
    assert cfg.es_url == "http://localhost:9200"
    assert cfg.default_size == 50
    assert cfg.max_size == 500
    assert cfg.run_id.startswith("run-")


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("TRACEHUNT_ES_URL", "https://es.example:9200/")
    monkeypatch.setenv("TRACEHUNT_INDICES", "alpha, beta")
    monkeypatch.setenv("TRACEHUNT_RUN_ID", "run-frozen-1")
    monkeypatch.setenv("TRACEHUNT_MAX_SIZE", "25")
    monkeypatch.setenv("TRACEHUNT_DEFAULT_SIZE", "40")
    cfg = Config.from_env()
    assert cfg.es_url == "https://es.example:9200"
    assert cfg.indices == ("alpha", "beta")
    assert cfg.run_id == "run-frozen-1"
    assert cfg.max_size == 25
    assert cfg.default_size == 25  # clamped to max


def test_invalid_index_name_rejected(monkeypatch):
    monkeypatch.setenv("TRACEHUNT_INDICES", "Good Index!")
    with pytest.raises(ValueError, match="invalid index name"):
        Config.from_env()


def test_empty_indices_rejected(monkeypatch):
    monkeypatch.setenv("TRACEHUNT_INDICES", " , ")
    with pytest.raises(ValueError, match="at least one index"):
        Config.from_env()


def test_non_integer_limit_rejected(monkeypatch):
    monkeypatch.setenv("TRACEHUNT_MAX_SIZE", "many")
    with pytest.raises(ValueError, match="must be an integer"):
        Config.from_env()
