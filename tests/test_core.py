"""Tests for core framework: config, models, results, plugins, logging."""

from __future__ import annotations

import json

import pytest

from metatrace.core import config as config_mod
from metatrace.core.config import AppConfig, ConfigError, load_config
from metatrace.core.logging import audit_log, utc_now_iso
from metatrace.core.models import Analysis, ExifData, FileIdentity
from metatrace.core.plugins import ModuleInfo, ModuleRegistry, get_registry
from metatrace.core.results import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    Finding,
    Result,
    exit_code_for,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_config_defaults():
    cfg = load_config()
    assert cfg["hash_algorithms"] == ["sha256"]
    assert cfg.profile == "default"
    assert cfg.source == "defaults"


def test_config_file_and_profile(tmp_path):
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(
        json.dumps(
            {
                "profiles": {
                    "default": {"hash_algorithms": ["sha256"]},
                    "thorough": {"hash_algorithms": ["sha256", "sha512"]},
                }
            }
        )
    )
    cfg = load_config(path=cfg_file, profile="thorough")
    assert cfg["hash_algorithms"] == ["sha256", "sha512"]
    assert cfg.source == str(cfg_file)


def test_config_missing_profile(tmp_path):
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({"profiles": {"default": {}}}))
    with pytest.raises(ConfigError, match="not defined"):
        load_config(path=cfg_file, profile="nope")


def test_config_unknown_setting(tmp_path):
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({"bogus_setting": 1}))
    with pytest.raises(ConfigError, match="unknown setting"):
        load_config(path=cfg_file)


def test_config_bad_algorithm(tmp_path):
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({"hash_algorithms": ["md5"]}))
    with pytest.raises(ConfigError, match="unsupported hash algorithm"):
        load_config(path=cfg_file)


def test_config_invalid_json(tmp_path):
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text("{not json")
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(path=cfg_file)


def test_config_overrides():
    cfg = load_config(overrides={"max_file_size_bytes": 10})
    assert cfg["max_file_size_bytes"] == 10
    with pytest.raises(ConfigError):
        load_config(overrides={"nope": 1})


def test_config_to_dict_and_getitem():
    cfg = AppConfig()
    assert cfg.get("hash_algorithms") == cfg["hash_algorithms"]
    d = cfg.to_dict()
    assert d["profile"] == "default"


def test_example_config_is_valid(tmp_path):
    cfg_file = tmp_path / "ex.json"
    cfg_file.write_text(config_mod.example_config())
    cfg = load_config(path=cfg_file, profile="thorough")
    assert cfg["hash_algorithms"] == ["sha256", "sha512"]


# ---------------------------------------------------------------------------
# Results / findings / exit codes
# ---------------------------------------------------------------------------


def test_result_exit_codes():
    r = Result(command="inspect")
    assert exit_code_for(r) == EXIT_OK
    r.add_finding(Finding(title="t", severity="low", reason="r"))
    assert r.status == "warning"
    assert exit_code_for(r) == EXIT_FINDINGS
    r.fail("boom")
    assert exit_code_for(r) == EXIT_ERROR


def test_result_to_dict_json_safe():
    r = Result(command="inspect", target="a.jpg", summary="ok")
    json.dumps(r.to_dict())


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def test_models_to_dict_json_safe():
    ident = FileIdentity(
        path="a.jpg", filename="a.jpg", size_bytes=10, format="JPEG", mime="image/jpeg"
    )
    exif = ExifData(present=True, make="M", raw_tags={0x010F: "M"})
    a = Analysis(
        evidence_id="MT-abc",
        tool_version="0.1.0",
        analyzed_at=utc_now_iso(),
        identity=ident,
        hashes={"sha256": "x"},
        exif=exif,
    )
    d = a.to_dict()
    json.dumps(d)
    assert d["exif"]["raw_tags"] == {"271": "M"}  # 0x010F == 271


def test_analysis_without_identity():
    a = Analysis(evidence_id="MT-x")
    assert a.to_dict()["identity"] is None


# ---------------------------------------------------------------------------
# Plugins
# ---------------------------------------------------------------------------


def test_builtin_modules_registered():
    registry = get_registry()
    assert "image" in registry.names()
    assert "parsers" in registry.names()
    assert registry.get("image").commands == ["inspect"]


def test_registry_rejects_duplicates_and_unknown():
    reg = ModuleRegistry()
    reg.register(ModuleInfo(name="x", description="d"))
    with pytest.raises(ValueError):
        reg.register(ModuleInfo(name="x", description="d2"))
    with pytest.raises(KeyError):
        reg.get("missing")


def test_discover_entry_points_is_best_effort():
    # Must not raise even with no entry points installed.
    ModuleRegistry().discover_entry_points()


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def test_audit_log_writes_json(tmp_path, monkeypatch):
    log_file = tmp_path / "audit.log"
    monkeypatch.setenv("METATRACE_AUDIT_LOG", str(log_file))
    audit_log({"command": "inspect", "exit_code": 0})
    entry = json.loads(log_file.read_text().strip())
    assert entry["command"] == "inspect"
    assert "timestamp" in entry


def test_audit_log_never_raises(monkeypatch):
    monkeypatch.setenv("METATRACE_AUDIT_LOG", "/no/such/dir/audit.log")
    audit_log({"command": "x"})  # must not raise


def test_utc_now_iso_format():
    assert utc_now_iso().endswith("Z")
