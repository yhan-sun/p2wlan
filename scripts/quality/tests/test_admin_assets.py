import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "check_admin_assets", Path(__file__).resolve().parents[1] / "check_admin_assets.py"
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class AdminAssetsTests(unittest.TestCase):
    def test_hashed_assets_exist_and_legacy_or_missing_entries_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app-abcdefgh.js").write_text("export {}", encoding="utf-8")
            (root / "app-12345678.css").write_text("body{}", encoding="utf-8")
            valid = '<script type="module" src="/admin/app-abcdefgh.js"></script><link rel="stylesheet" href="/admin/app-12345678.css">'
            (root / "index.html").write_text(valid, encoding="utf-8")
            checker.verify_assets(root)
            for reference in ["/admin/app.js", "/admin/app-missingx.js", "/admin/../app-abcdefgh.js", "https://example.test/admin/app-abcdefgh.js"]:
                (root / "index.html").write_text(valid.replace("/admin/app-abcdefgh.js", reference), encoding="utf-8")
                with self.subTest(reference=reference), self.assertRaises(ValueError):
                    checker.verify_assets(root)
            (root / "index.html").write_text('<script type="module" src="/admin/app-abcdefgh.js"></script>', encoding="utf-8")
            with self.assertRaises(ValueError):
                checker.verify_assets(root)


if __name__ == "__main__":
    unittest.main()
