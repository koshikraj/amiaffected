"""amiaffected command line.

    amiaffected inventory [--scan-root DIR ...] [--node-bin PATH ...]
    amiaffected check     [--advisories DIR] [--advisory ID] [--inventory FILE]
                          [--scan-root DIR ...] [--node-bin PATH ...]
    amiaffected validate  [--advisories DIR]

check exits 0 not_affected, 1 affected, 2 unknown (also on any internal error).

The check never uses the network, never writes, never elevates, and only
executes the runtimes listed in the result's `runtime.executed`. Scope
defaults to known system locations; add --scan-root for directories where
project virtualenvs or caches live.
"""
import argparse
import datetime as _dt
import json
import os
import sys

from . import EXIT_CODES, MAX_DATA_AGE_DAYS, __version__
from . import inventory as inv
from . import matcher, pem, schema
from .rules import certificate_trust

SANDBOX_NOTE = ("not enforced by amiaffected; run under the host's sandbox (read-only filesystem, "
                "no network) where available")


def _print(doc):
    json.dump(doc, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _apply_node_bins(args):
    for p in getattr(args, "node_bin", None) or []:
        ap = os.path.abspath(p)
        if not os.path.isabs(p) or not os.path.isfile(ap):
            sys.stderr.write("amiaffected: --node-bin %s must be an absolute path to an existing file\n" % p)
            raise SystemExit(EXIT_CODES["unknown"])
        pem.EXTRA_EXECUTABLES.add(ap)


def _collect(args):
    return inv.collect(scan_roots=args.scan_root, include_node=not args.no_node, include_java=not args.no_java)


def cmd_inventory(args):
    _apply_node_bins(args)
    _print(_collect(args))
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
    return _collect(args)


def _freshness(info):
    """Stale bundle data must not reassure. Source trees are development
    mode and are reported as such rather than aged."""
    out = {"max_age_days": MAX_DATA_AGE_DAYS, "age_days": None, "stale": False, "note": None}
    if info.get("kind") != "bundle" or not info.get("built_at"):
        out["note"] = "running from a source tree; data age not enforced"
        return out
    try:
        built = _dt.datetime.fromisoformat(info["built_at"].replace("Z", "+00:00"))
    except ValueError:
        out["stale"] = True
        out["note"] = "BUNDLE.json built_at is unreadable; treating data as stale"
        return out
    age = (_dt.datetime.now(_dt.timezone.utc) - built).days
    out["age_days"] = age
    if age > MAX_DATA_AGE_DAYS:
        out["stale"] = True
        out["note"] = ("bundle data is %d days old (limit %d); not_affected is downgraded to unknown. "
                       "Install a newer verified release." % (age, MAX_DATA_AGE_DAYS))
    return out


def cmd_check(args):
    _apply_node_bins(args)
    inventory = _load_inventory(args)
    root = args.advisories or matcher.advisory_root()
    paths = matcher.find_advisories(root)
    if not paths:
        sys.stderr.write("amiaffected: no advisories under %s\n" % root)
    results = []
    for p in paths:
        adv = matcher.load_advisory(p)
        if args.advisory and args.advisory not in (adv.get("id"), adv.get("slug")):
            continue
        if adv.get("publication_state") not in ("active", "mitigated"):
            continue
        results.append(matcher.check_advisory(adv, inventory))
    overall = matcher._combine([r["verdict"] for r in results])

    info = matcher.bundle_info()
    fresh = _freshness(info)
    if fresh["stale"] and overall == "not_affected":
        overall = "unknown"
        for r in results:
            if r["verdict"] == "not_affected":
                r["verdict"] = "unknown"
                r["limitations"] = list(r.get("limitations", [])) + [fresh["note"]]

    _print({
        "result_version": matcher.RESULT_VERSION,
        "verdict": overall,
        "advisories_checked": len(results),
        "data": {
            "kind": info.get("kind"),
            "version": info.get("version", __version__),
            "source_commit": info.get("source_commit"),
            "built_at": info.get("built_at"),
            "revision": matcher.data_revision(paths) if paths else None,
            "freshness": fresh,
        },
        "runtime": {
            "network": "none",
            "writes": "none",
            "privileges": "current user, never elevated",
            "executed": sorted(set(pem.EXECUTED)),
            "sandbox": SANDBOX_NOTE,
        },
        "results": results,
    })
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
        sp.add_argument("--node-bin", action="append", default=[], metavar="PATH",
                        help="absolute path to a node binary you authorise this run to execute; repeatable")
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
