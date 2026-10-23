import json
import os
import subprocess
import sys
import tempfile
import unittest

from amiaffected import schema
from tests.test_matcher import inventory, store

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run(*args, inv=None):
    cmd = [sys.executable, "-m", "amiaffected", *args]
    if inv is not None:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(inv, tmp)
        tmp.close()
        cmd += ["--inventory", tmp.name]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT, timeout=120)
    return proc.returncode, proc.stdout, proc.stderr


class CliTests(unittest.TestCase):
    def test_check_affected_exit_1(self):
        code, out, err = run("check", inv=inventory([store("affected-emsign-ecc-root-g3.pem")]))
        self.assertEqual(code, 1, err)
        doc = json.loads(out)
        self.assertEqual(doc["verdict"], "affected")
        self.assertEqual(doc["advisories_checked"], 1)
        self.assertEqual(schema.validate_result(doc["results"][0]), [])

    def test_check_not_affected_exit_0(self):
        code, out, err = run("check", inv=inventory([store("not-affected-isrg-only.pem")]))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["verdict"], "not_affected")

    def test_check_unknown_exit_2(self):
        code, out, err = run("check", inv=inventory([store("malformed.pem")]))
        self.assertEqual(code, 2, err)
        self.assertEqual(json.loads(out)["verdict"], "unknown")

    def test_invalid_inventory_exit_2(self):
        code, out, err = run("check", inv={"nonsense": True})
        self.assertEqual(code, 2)
        self.assertIn("inventory invalid", err)

    def test_validate(self):
        code, out, err = run("validate")
        self.assertEqual(code, 0, out + err)
        self.assertIn("ok   AIA-2026-0001", out)

    def test_live_inventory_is_valid(self):
        code, out, err = run("inventory", "--no-java")
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(schema.validate_inventory(doc), [])
        self.assertNotIn("BEGIN CERTIFICATE", out)


if __name__ == "__main__":
    unittest.main()
