"""The release bundle must work on its own, outside the repository, under
python3 -I, and carry provenance fields."""
import glob
import json
import os
import subprocess
import sys
import tempfile
import unittest

from tests.test_matcher import inventory, store

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp()
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_bundle.py"),
                               "--out", cls.out, "--source-commit", "deadbeef"],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        [cls.bundle] = glob.glob(os.path.join(cls.out, "amiaffected-check-*/"))
        cls.run_py = os.path.join(cls.bundle, "scripts", "run.py")

    def run_bundle(self, *args):
        # cwd is a directory that is not the repo and not the bundle
        return subprocess.run([sys.executable, "-I", self.run_py, *args], capture_output=True,
                              text=True, cwd=tempfile.gettempdir(), timeout=120)

    def test_layout(self):
        self.run_bundle("validate")  # a run must leave the bundle untouched
        for rel in ("SKILL.md", "TRUST.md", "scripts/run.py", "scripts/BUNDLE.json",
                    "scripts/amiaffected/__main__.py", "scripts/advisories"):
            self.assertTrue(os.path.exists(os.path.join(self.bundle, rel)), rel)
        self.assertFalse(glob.glob(os.path.join(self.bundle, "**", "__pycache__"), recursive=True))
        self.assertFalse(os.path.exists(os.path.join(self.bundle, "tools")))
        self.assertTrue(glob.glob(os.path.join(self.out, "amiaffected-check-*.tar.gz")))
        self.assertTrue(os.path.exists(os.path.join(self.out, "SHA256SUMS")))

    def test_bundle_json(self):
        with open(os.path.join(self.bundle, "scripts", "BUNDLE.json")) as fh:
            info = json.load(fh)
        self.assertEqual(info["source_commit"], "deadbeef")
        for k in ("version", "built_at", "data_revision", "advisories"):
            self.assertIn(k, info)
        self.assertGreaterEqual(info["advisories"], 1)

    def test_validate_outside_repo(self):
        proc = self.run_bundle("validate")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotIn("not started with python3 -I", proc.stderr)

    def test_check_reports_bundle_data(self):
        inv = inventory([store("affected-aaa-root.pem")])
        path = os.path.join(self.out, "inv.json")
        with open(path, "w") as fh:
            json.dump(inv, fh)
        proc = self.run_bundle("check", "--inventory", path)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["data"]["kind"], "bundle")
        self.assertEqual(doc["data"]["source_commit"], "deadbeef")
        self.assertFalse(doc["data"]["freshness"]["stale"])
        self.assertEqual(doc["runtime"]["network"], "none")


if __name__ == "__main__":
    unittest.main()
