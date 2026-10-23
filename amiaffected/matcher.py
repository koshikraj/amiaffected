"""Match an inventory against advisories and produce per-advisory results.

Overall verdict for one advisory:
    affected      any inspected store is affected
    unknown       nothing affected but at least one store or gap is unknown
    not_affected  every applicable store parsed and nothing matched, and
                  the inventory reported no gaps the rule cares about
"""
import datetime as _dt
import hashlib
import json
import os

from . import __version__, rules

RESULT_VERSION = "0.1"


def _now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def advisory_root(start=None):
    """advisories/ next to the package, unless overridden."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(start or here, "advisories")


def find_advisories(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        if "advisory.json" in filenames:
            out.append(os.path.join(dirpath, "advisory.json"))
    return sorted(out)


def load_advisory(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    doc = json.loads(raw.decode("utf-8"))
    doc["_path"] = path
    doc["_digest"] = hashlib.sha256(raw).hexdigest()
    return doc


def _combine(verdicts):
    if "affected" in verdicts:
        return "affected"
    if "unknown" in verdicts or not verdicts:
        return "unknown"
    return "not_affected"


def check_advisory(advisory, inventory):
    stores_out = []
    verdicts = []
    for rule in advisory.get("affected", {}).get("rules", []):
        mod = rules.get(rule.get("type"))
        if mod is None:
            verdicts.append("unknown")
            stores_out.append({"id": "rule:%s" % rule.get("id"), "type": rule.get("type"), "path": None,
                               "verdict": "unknown", "reason": "rule type not implemented in this version",
                               "evidence": []})
            continue
        for fact in mod.applies_to(rule, inventory):
            if fact.get("readable") is False:
                res = {"verdict": "unknown", "reason": "not readable by this user", "evidence": []}
            else:
                res = mod.evaluate(rule, fact)
            verdicts.append(res["verdict"])
            stores_out.append({"id": fact.get("id"), "type": fact.get("type"), "path": fact.get("path"),
                               "rule": rule.get("id"), **res})
    gaps = list(inventory.get("gaps", []))
    if gaps:
        verdicts.append("unknown")
    return {
        "result_version": RESULT_VERSION,
        "advisory_id": advisory.get("id"),
        "advisory_revision": advisory.get("revision"),
        "advisory_digest": advisory.get("_digest"),
        "checked_at": _now(),
        "checker": {"name": "amiaffected", "version": __version__},
        "target": inventory.get("target", {}),
        "inventory_collected_at": inventory.get("collected_at"),
        "verdict": _combine(verdicts),
        "scope": inventory.get("scope", {}),
        "stores": stores_out,
        "gaps": gaps,
        "limitations": advisory.get("check", {}).get("limitations", []),
        "remediation": advisory.get("remediation", {}).get("summary"),
    }
