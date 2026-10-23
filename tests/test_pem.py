import os
import tempfile
import unittest

from amiaffected import pem

FIX = os.path.join(os.path.dirname(__file__), "..", "advisories", "2026", "emudhra-ca-key-leak", "fixtures")
ISRG = "96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6"


class PemTests(unittest.TestCase):
    def test_parse_known_root(self):
        read = pem.read_pem_bundle(os.path.join(FIX, "not-affected-isrg-only.pem"))
        self.assertTrue(read["ok"])
        self.assertEqual(read["count"], 1)
        self.assertEqual(read["certs"][0]["sha256"], ISRG)

    def test_malformed_is_not_ok(self):
        read = pem.read_pem_bundle(os.path.join(FIX, "malformed.pem"))
        self.assertFalse(read["ok"])
        self.assertIn("does not decode", read["error"])

    def test_empty_is_not_ok(self):
        read = pem.read_pem_bundle(os.path.join(FIX, "empty.pem"))
        self.assertFalse(read["ok"])

    def test_missing_is_not_ok(self):
        read = pem.read_pem_bundle(os.path.join(FIX, "nope.pem"))
        self.assertFalse(read["ok"])
        self.assertIn("FileNotFoundError", read["error"])

    @unittest.skipIf(os.geteuid() == 0, "root can read anything")
    def test_unreadable_is_not_ok(self):
        with open(os.path.join(FIX, "not-affected-isrg-only.pem")) as src:
            content = src.read()
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(content)
            path = fh.name
        try:
            os.chmod(path, 0)
            read = pem.read_pem_bundle(path)
            self.assertFalse(read["ok"])
            self.assertIn("PermissionError", read["error"])
        finally:
            os.chmod(path, 0o600)
            os.unlink(path)

    def test_unsupported_type(self):
        read = pem.read_store("/dev/null", "nss")
        self.assertFalse(read["ok"])
        self.assertIn("unsupported", read["error"])

    def test_evidence_has_no_pem(self):
        read = pem.read_pem_bundle(os.path.join(FIX, "affected-aaa-root.pem"))
        self.assertNotIn("BEGIN CERTIFICATE", str(read))


if __name__ == "__main__":
    unittest.main()
