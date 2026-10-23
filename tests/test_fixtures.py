"""Every active advisory must pass schema validation and every fixture must
produce exactly the verdict its advisory declares."""
import unittest

from amiaffected import matcher, schema
from amiaffected.__main__ import run_fixtures


class AdvisoryFixtureTests(unittest.TestCase):
    def setUp(self):
        self.paths = matcher.find_advisories(matcher.advisory_root())
        self.assertTrue(self.paths, "no advisories found")

    def test_schema(self):
        for p in self.paths:
            with self.subTest(advisory=p):
                self.assertEqual(schema.validate_advisory(matcher.load_advisory(p)), [])

    def test_fixtures(self):
        for p in self.paths:
            adv = matcher.load_advisory(p)
            if adv.get("check_maturity") not in ("fixtured", "verified"):
                continue
            with self.subTest(advisory=adv["id"]):
                self.assertEqual(run_fixtures(adv), [])

    def test_ids_unique(self):
        ids = [matcher.load_advisory(p)["id"] for p in self.paths]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
