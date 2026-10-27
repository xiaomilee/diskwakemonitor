"""版本工具链的回归测试。

重点守住两件容易悄悄坏掉的事：
1. 产物文件名必须是 fnOS 规范 {appname}_{version}_{platform}.fpk
2. 文件名里的版本必须与唯一来源 __version__ 一致（不能各写各的）
"""

from __future__ import annotations

import importlib.util
import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "tools" / "sync_version.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("sync_version", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ArtifactNamingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()
        cls.version = cls.tool.read_version()
        cls.manifest_appname = cls.tool.read_manifest_field("appname")
        cls.manifest_platform = cls.tool.read_manifest_field("platform")

    def test_matches_fnos_convention(self):
        name = self.tool.artifact_name(self.version)
        self.assertEqual(
            name, f"{self.manifest_appname}_{self.version}_{self.manifest_platform}.fpk"
        )

    def test_extension_and_version_embedded(self):
        name = self.tool.artifact_name(self.version)
        self.assertTrue(name.endswith(".fpk"))
        # 版本号必须真的出现在文件名里，而不只是变量名里有
        self.assertIn(self.version, name)
        self.assertRegex(name, r"^[A-Za-z0-9._-]+\.fpk$")

    def test_manifest_version_matches_source(self):
        """manifest 的 version 是打包时被覆写的，这里保证仓库里也不漂移。"""
        self.assertEqual(self.tool.read_manifest_field("version"), self.version)

    def test_changelog_head_matches_source(self):
        title, items = self.tool.read_latest_changelog()
        self.assertEqual(self.tool.changelog_version(title), self.version)
        self.assertTrue(items, "最新一节应有 '- ' 条目")

    def test_platform_is_supported_value(self):
        self.assertIn(self.manifest_platform, {"x86", "arm", "all"})


class BumpChangelogTest(unittest.TestCase):
    """bump_version.py 的 CHANGELOG 插入必须锚定行首标题。

    文档说明行里含反引号包裹的 "## 版本号（日期）"，普通字符串 find
    会插进句子中间，把整份 CHANGELOG 截断（v1.2.0 发布时踩过）。
    """

    TRICKY = (
        "# 变更日志\n"
        "\n"
        "格式：最新版本在最上面；每节以 `## 版本号（日期）` 开头。\n"
        "\n"
        "## 1.1.0（2026-10-27）\n"
        "\n"
        "- 旧条目\n"
    )

    def _load_bump(self):
        path = ROOT / "tools" / "bump_version.py"
        spec = importlib.util.spec_from_file_location("bump_version", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module

    def test_insert_anchors_at_line_start(self):
        import tempfile

        bump = self._load_bump()
        with tempfile.NamedTemporaryFile(
            "w", suffix=".md", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(self.TRICKY)
            tmp_path = fh.name
        try:
            original = bump.CHANGELOG
            bump.CHANGELOG = Path(tmp_path)
            try:
                bump.prepend_changelog("1.2.0", "新条目")
            finally:
                bump.CHANGELOG = original
            text = Path(tmp_path).read_text(encoding="utf-8")
        finally:
            os.unlink(tmp_path)

        # 说明行原样保留，新小节插在第一个真实标题之前
        self.assertIn("格式：最新版本在最上面；每节以 `## 版本号（日期）` 开头。", text)
        self.assertLess(text.index("## 1.2.0"), text.index("## 1.1.0"))
        self.assertNotIn("## 1.2.0（", text.split("## 1.1.0")[0].split("格式：")[1].split("\n")[0])


if __name__ == "__main__":
    unittest.main()
