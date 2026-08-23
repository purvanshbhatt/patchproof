"""Tests for the diff applier + rollback."""
from __future__ import annotations

from pathlib import Path

from patchproof.patch.apply import apply_diff, rollback, snapshot

DIFF = """--- a/main.py
+++ b/main.py
@@ -1,3 +1,3 @@
 def hello():
-    return "vuln"
+    return "safe"

 def world():
"""


def test_apply_and_rollback(tmp_path: Path) -> None:
    src = tmp_path / "main.py"
    src.write_text(
        'def hello():\n    return "vuln"\n\ndef world():\n    pass\n'
    )
    snap = snapshot(tmp_path)
    assert apply_diff(tmp_path, DIFF) is True
    assert "safe" in src.read_text()
    rollback(tmp_path, snap)
    assert "vuln" in src.read_text()


def test_apply_invalid_diff_returns_false(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("x = 1\n")
    assert apply_diff(tmp_path, "") is False
    assert apply_diff(tmp_path, "not a diff") is False


def test_snapshot_restores_unchanged_files(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("a\n")
    (tmp_path / "b.py").write_text("b\n")
    snap = snapshot(tmp_path)
    (tmp_path / "a.py").write_text("changed\n")
    (tmp_path / "c.py").write_text("new\n")
    rollback(tmp_path, snap)
    assert (tmp_path / "a.py").read_text() == "a\n"
    assert (tmp_path / "b.py").read_text() == "b\n"
