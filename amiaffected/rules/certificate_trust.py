"""certificate_trust: is a trust store still willing to anchor a chain that
passes through compromised certificates?

Rule shape (see docs/schema.md):
    anchors:     roots whose presence makes the store accept the bad chain
    compromised: the compromised certificates themselves (sha256 list each)
    distrust:    per store type, "none" if the store has no distrust
                 mechanism, otherwise "unsupported_in_v0"

Verdicts per store:
    affected      an anchor or a compromised certificate is present and the
                  store type has no distrust mechanism we need to consult
    not_affected  the store parsed completely and contains none of them
    unknown       unreadable, unparseable, empty, or a store type whose
                  distrust mechanism we cannot read yet
"""
from .. import pem

SUBJECT = "trust_stores"


def applies_to(rule, inventory):
    return list(inventory.get("facts", {}).get(SUBJECT, []))


def _index(rule):
    anchors = {a["sha256"].upper(): a for a in rule.get("anchors", [])}
    compromised = {}
    for c in rule.get("compromised", []):
        for h in c.get("sha256", []):
            compromised[h.upper()] = c
    return anchors, compromised


def evaluate(rule, store):
    store_type = store.get("type")
    path = store.get("path")
    distrust = rule.get("distrust", {}).get(store_type)
    if distrust is None or distrust == "unsupported_in_v0" or store_type not in pem.SUPPORTED_STORE_TYPES:
        return {"verdict": "unknown",
                "reason": "store type %r is not supported by this rule yet" % store_type,
                "evidence": []}
    read = pem.read_store(path, store_type)
    if not read["ok"]:
        return {"verdict": "unknown", "reason": read["error"], "evidence": []}

    anchors, compromised = _index(rule)
    hits = []
    for cert in read["certs"]:
        h = cert["sha256"]
        if h in anchors:
            hits.append({"role": "anchor", "name": anchors[h]["name"], "sha256": h})
        elif h in compromised:
            hits.append({"role": "compromised", "name": compromised[h]["name"], "sha256": h})
    evidence = [{"certificates_inspected": read["count"]}] + hits
    if hits:
        names = sorted({x["name"] for x in hits})
        return {"verdict": "affected",
                "reason": "store trusts: %s" % ", ".join(names),
                "evidence": evidence}
    return {"verdict": "not_affected",
            "reason": "none of %d anchors or %d compromised certificates present in %d inspected"
                      % (len(anchors), len(compromised), read["count"]),
            "evidence": evidence}
