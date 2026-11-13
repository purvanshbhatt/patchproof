from pathlib import Path

from patchproof.ingest.normalize import Oracle, load_poc


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "poc.txt"
    p.write_text(text)
    return p


def test_parse_curl_with_nested_quotes(tmp_path):
    poc = load_poc(_write(tmp_path, "curl \"http://h/?id=' OR '1'='1'\""))
    assert poc.kind == "curl"
    assert poc.payload["method"] == "GET"
    assert poc.payload["url"] == "http://h/?id=' OR '1'='1'"


def test_parse_curl_post_with_header_and_body(tmp_path):
    poc = load_poc(_write(tmp_path, "curl -X POST http://h/login -H 'Content-Type: application/json' -d '{\"a\":1}'"))
    assert poc.payload["method"] == "POST"
    assert poc.payload["headers"]["Content-Type"] == "application/json"
    assert poc.payload["body"] == '{"a":1}'


def test_parse_raw_http(tmp_path):
    poc = load_poc(_write(tmp_path, "GET /admin?debug=1 HTTP/1.1\nHost: x\n"))
    assert poc.kind == "http"
    assert poc.payload["url"] == "/admin?debug=1"


def test_oracle_signals():
    o = Oracle()
    assert o.judge(200, "nope EXPLOIT_LEAK here") is True
    assert o.judge(500, "server error") is True
    assert o.judge(200, "all good") is False


def test_directive_overrides_marker(tmp_path):
    poc = load_poc(_write(tmp_path, "#patchproof: marker=PWNED no-crash\ncurl http://h/?x=1"))
    assert poc.oracle.markers == ("PWNED",)
    assert poc.oracle.crash_is_success is False


def test_variants_generated_for_query():
    poc = load_poc_from_text("curl \"http://h/?id=' OR '1'='1'\"")
    labels = {v.label for v in poc.variants()}
    assert "url-encoded-quote" in labels
    assert "case-flip" in labels


def load_poc_from_text(text):
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(text)
        name = f.name
    return load_poc(Path(name))


def test_abs_url_rehost():
    poc = load_poc_from_text("curl http://example.com:9/path?x=1")
    assert poc._abs_url("http://127.0.0.1:5000") == "http://127.0.0.1:5000/path?x=1"
