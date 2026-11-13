from pathlib import Path

from patchproof.config import load
from patchproof.sandbox.app_spec import detect_app_spec

FIXTURES = Path(__file__).parent / "fixtures"


def test_detect_fastapi_entry():
    spec = detect_app_spec(FIXTURES / "vuln-fastapi-sqli" / "app")
    assert spec.runtime == "python"
    assert spec.framework == "fastapi"
    assert spec.entry_file == "main.py"
    assert spec.app_var == "app"
    assert spec.asgi is True


def test_detect_flask_entry():
    spec = detect_app_spec(FIXTURES / "vuln-flask-pathtraversal" / "app")
    assert spec.framework == "flask"
    assert spec.port == 5000
    assert spec.asgi is False


def test_config_load(tmp_path):
    (tmp_path / "patchproof.toml").write_text(
        "[patch]\nmax_attempts = 7\nmodel = \"anthropic/claude-x\"\n[sandbox]\nrunner = \"local\"\n"
    )
    cfg = load(tmp_path)
    assert cfg["max_attempts"] == 7
    assert cfg["model"] == "anthropic/claude-x"
    assert cfg["runner"] == "local"


def test_config_absent(tmp_path):
    assert load(tmp_path) == {}
