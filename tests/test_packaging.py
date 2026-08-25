import ast
import unittest
from pathlib import Path


class PackagingCompatibilityTest(unittest.TestCase):
    def test_legacy_setup_exists_and_declares_src_layout(self):
        path = Path("setup.py")
        self.assertTrue(path.is_file())
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        setup_calls = [node for node in calls if isinstance(node.func, ast.Name) and node.func.id == "setup"]
        self.assertEqual(len(setup_calls), 1)
        keywords = {item.arg: item.value for item in setup_calls[0].keywords}
        self.assertIn("package_dir", keywords)
        self.assertIn("entry_points", keywords)
        self.assertIn("python_requires", keywords)
