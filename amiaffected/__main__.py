"""amiaffected command line.

    amiaffected inventory [--scan-root DIR ...]
    amiaffected check     [--advisories DIR] [--advisory ID] [--inventory FILE] [--scan-root DIR ...]
    amiaffected validate  [--advisories DIR]

check exits 0 not_affected, 1 affected, 2 unknown (also on any internal error).
"""
import argparse
import json
import os
import sys

from . import EXIT_CODES, __version__
from . import inventory as inv
from . import matcher, schema
from .rules import certificate_trust


def _print(doc):
    json.dump(doc, sys.stdout, indent=2)
    sys.stdout.write("\n")


def cmd_inventory(args):
    doc = inv.collect(scan_roots=args.scan_root, include_node=not args.no_node, include_java=not args.no_java)
    _print(doc)
    return 0


def _load_inventory(args):
    if args.inventory:
        with open(args.inventory, encoding="utf-8") as fh:
            doc = json.load(fh)
        errs = schema.validate_inventory(doc)
        if errs:
            sys.stderr.write("amiaffected: inventory invalid:\n  " + "\n  ".join(errs) + "\n")
            raise SystemExit(EXIT_CODES["unknown"])
        return doc
    return inv.collect(scan_roots=args.scan_root, include_node=not args.no_node, include_java=not args.no_java)


def cmd_check(args):
    inventory = _load_inventory(args)
    root = args.advisories or matcher.advisory_root()
    paths = matcher.find_advisories(root)
    results = []
    for p in paths:
        adv = matcher.load_advisory(p)
        if args.advisory and args.advisory not in (adv.get("id"), adv.get("slug")):
            continue
        if adv.get("publication_state") not in ("active", "mitigated"):
            continue
        results.append(matcher.check_advisory(adv, inventory))
    overall = matcher._combine([r["verdict"] for r in results])
    _print({"result_version": matcher.RESULT_VERSION, "verdict": overall,
            "advisories_checked": len(results), "results": results})
    return EXIT_CODES[overall]


def run_fixtures(adv):
    """Evaluate each expected fixture with the advisory's own rules. Returns failures."""
    failures = []
    base = os.path.join(os.path.dirname(adv["_path"]), adv.get("fixtures", {}).get("directory", "fixtures"))
    rule_list = adv.get("affected", {}).get("rules", [])
    for exp in adv.get("fixtures", {}).get("expected", []):
        fact = {"id": "fixture:%s" % exp["file"], "type": exp.get("store_type", "pem_bundle"),
                "path": os.path.join(base, exp["file"]), "readable": True}
        got = matcher._combine([certificate_trust.evaluate(r, fact)["verdict"]
                                for r in rule_list if r.get("type") == "certificate_trust"])
        if got != exp["verdict"]:
            failures.append("%s [%s]: expected %s, got %s" % (exp["file"], fact["type"], exp["verdict"], got))
    return failures


def cmd_validate(args):
    root = args.advisories or matcher.advisory_root()
    paths = matcher.find_advisories(root)
    if not paths:
        print("no advisories under %s" % root)
        return 2
    bad = 0
    for p in paths:
        try:
            adv = matcher.load_advisory(p)
        except (OSError, ValueError) as exc:
            print("FAIL %s: %s" % (p, exc))
            bad += 1
            continue
        errs = schema.validate_advisory(adv)
        if adv.get("check_maturity") in ("fixtured", "verified"):
            errs += run_fixtures(adv)
        if errs:
            bad += 1
            print("FAIL %s" % p)
            for e in errs:
                print("  - " + e)
        else:
            print("ok   %s (%s rev %s, %d fixtures)" % (adv["id"], adv["slug"], adv["revision"],
                                                       len(adv.get("fixtures", {}).get("expected", []))))
    return 1 if bad else 0


def build_parser():
    p = argparse.ArgumentParser(prog="amiaffected", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version="amiaffected %s" % __version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--scan-root", action="append", default=[], metavar="DIR",
                        help="also look for certifi bundles under DIR (bounded depth); repeatable")
        sp.add_argument("--no-node", action="store_true", help="skip the node bundled store")
        sp.add_argument("--no-java", action="store_true", help="skip java keystores")

    sp = sub.add_parser("inventory", help="collect local facts as JSON; nothing leaves the machine")
    common(sp)
    sp.set_defaults(func=cmd_inventory)

    sp = sub.add_parser("check", help="match this host against advisories and run applicable rules")
    common(sp)
    sp.add_argument("--advisories", metavar="DIR", help="advisory root (default: bundled advisories/)")
    sp.add_argument("--advisory", metavar="ID_OR_SLUG", help="check only this advisory")
    sp.add_argument("--inventory", metavar="FILE", help="use a saved inventory instead of collecting")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("validate", help="validate advisory files and run their fixtures")
    sp.add_argument("--advisories", metavar="DIR")
    sp.set_defaults(func=cmd_validate)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SystemExit:
        raise
    except Exception as exc:  # any crash is "unknown", never silent success
        sys.stderr.write("amiaffected: %s: %s\n" % (exc.__class__.__name__, exc))
        return EXIT_CODES["unknown"]


if __name__ == "__main__":
    sys.exit(main())
