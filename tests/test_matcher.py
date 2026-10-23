import os
import unittest

from amiaffected import matcher, schema

FIX = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "advisories", "2026", "emudhra-ca-key-leak", "fixtures"))


def inventory(stores, gaps=()):
    return {
        "inventory_version": "0.1", "collected_at": "2026-10-23T12:00:00+00:00",
        "collector": {"name": "test", "version": "0"},
        "target": {"id": "test-host", "kind": "host", "os": {}},
        "scope": {"scan_roots": []},
        "facts": {"trust_stores": stores},
        "gaps": list(gaps),
    }


def store(name, store_type="pem_bundle", readable=True):
    return {"id": "fx:" + name, "kind": "fixture", "type": store_type, "path": os.path.join(FIX, name), "readable": readable}


class MatcherTests(unittest.TestCase):
    def setUp(self):
        [path] = [p for p in matcher.find_advisories(matcher.advisory_root()) if "emudhra" in p]
        self.adv = matcher.load_advisory(path)

    def test_affected_wins(self):
        res = matcher.check_advisory(self.adv, inventory([store("not-affected-isrg-only.pem"), store("affected-aaa-root.pem")]))
        self.assertEqual(res["verdict"], "affected")
        self.assertEqual(schema.validate_result(res), [])
        hit = [s for s in res["stores"] if s["verdict"] == "affected"][0]
        self.assertEqual(hit["evidence"][1]["name"], "AAA Certificate Services")

    def test_clean_store_with_no_gaps(self):
        res = matcher.check_advisory(self.adv, inventory([store("not-affected-isrg-only.pem")]))
        self.assertEqual(res["verdict"], "not_affected")

    def test_gap_makes_unknown(self):
        res = matcher.check_advisory(self.adv, inventory([store("not-affected-isrg-only.pem")],
                                                         gaps=[{"what": "java", "why": "keytool missing"}]))
        self.assertEqual(res["verdict"], "unknown")

    def test_unreadable_store_is_unknown(self):
        res = matcher.check_advisory(self.adv, inventory([store("not-affected-isrg-only.pem", readable=False)]))
        self.assertEqual(res["verdict"], "unknown")
        self.assertEqual(res["stores"][0]["reason"], "not readable by this user")

    def test_unsupported_store_is_unknown(self):
        res = matcher.check_advisory(self.adv, inventory([store("not-affected-isrg-only.pem", store_type="nss")]))
        self.assertEqual(res["verdict"], "unknown")

    def test_no_stores_is_unknown(self):
        res = matcher.check_advisory(self.adv, inventory([]))
        self.assertEqual(res["verdict"], "unknown")


if __name__ == "__main__":
    unittest.main()
