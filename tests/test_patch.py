from patchproof.patch.apply import WorkCopy, apply_diff, diff_against_baseline, rollback


def _make_app(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text("x = 1\ny = 2\n")
    return src


DIFF = """--- a/main.py
+++ b/main.py
@@ -1,2 +1,2 @@
-x = 1
+x = 99
 y = 2
"""


def test_apply_and_rollback(tmp_path):
    src = _make_app(tmp_path)
    work = WorkCopy(src=src, dest=tmp_path / "work").setup()

    assert apply_diff(work, DIFF) is True
    assert "x = 99" in (work / "main.py").read_text()

    effective = diff_against_baseline(work)
    assert "x = 99" in effective

    rollback(work)
    assert "x = 1" in (work / "main.py").read_text()


def test_empty_diff_is_noop(tmp_path):
    src = _make_app(tmp_path)
    work = WorkCopy(src=src, dest=tmp_path / "work").setup()
    assert apply_diff(work, "   ") is False


def test_bad_diff_returns_false(tmp_path):
    src = _make_app(tmp_path)
    work = WorkCopy(src=src, dest=tmp_path / "work").setup()
    assert apply_diff(work, "--- a/nope.py\n+++ b/nope.py\n@@ -1 +1 @@\n-a\n+b\n") is False
    assert (work / "main.py").read_text() == "x = 1\ny = 2\n"
