"""Zero-dependency validators for advisory, inventory and result documents.
Each returns a list of error strings; empty means valid."""
import re

from . import VERDICTS
from .rules import RULE_TYPES

HEX64 = re.compile(r"^[0-9A-F]{64}$")
HEX40 = re.compile(r"^[0-9A-F]{40}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ADVISORY_ID = re.compile(r"^AIA-\d{4}-\d{4}$")
PUBLICATION_STATES = ("draft", "active", "mitigated", "superseded", "withdrawn")
CHECK_MATURITY = ("none", "draft", "fixtured", "verified")
SEVERITIES = ("low", "medium", "high", "critical")
STORE_TYPES = ("pem_bundle", "java_keystore", "node_bundled", "nss", "windows", "macos_keychain")


def _req(doc, key, typ, errors, ctx):
    if key not in doc:
        errors.append("%s: missing %r" % (ctx, key))
        return None
    if not isinstance(doc[key], typ):
        errors.append("%s: %r must be %s" % (ctx, key, getattr(typ, "__name__", typ)))
        return None
    return doc[key]


def _check_certificate_trust(rule, errors, ctx):
    anchors = _req(rule, "anchors", list, errors, ctx) or []
    for i, a in enumerate(anchors):
        c = "%s.anchors[%d]" % (ctx, i)
        _req(a, "name", str, errors, c)
        h = _req(a, "sha256", str, errors, c)
        if h and not HEX64.match(h):
            errors.append("%s: sha256 must be 64 uppercase hex chars" % c)
        if "ski" in a and not HEX40.match(a["ski"]):
            errors.append("%s: ski must be 40 uppercase hex chars" % c)
    comp = _req(rule, "compromised", list, errors, ctx) or []
    for i, item in enumerate(comp):
        c = "%s.compromised[%d]" % (ctx, i)
        _req(item, "name", str, errors, c)
        hs = _req(item, "sha256", list, errors, c) or []
        for h in hs:
            if not isinstance(h, str) or not HEX64.match(h):
                errors.append("%s: every sha256 must be 64 uppercase hex chars" % c)
    distrust = _req(rule, "distrust", dict, errors, ctx) or {}
    for k, v in distrust.items():
        if k not in STORE_TYPES:
            errors.append("%s.distrust: unknown store type %r" % (ctx, k))
        if v not in ("none", "unsupported_in_v0"):
            errors.append("%s.distrust[%s]: must be 'none' or 'unsupported_in_v0'" % (ctx, k))
    if not anchors and not comp:
        errors.append("%s: needs at least one anchor or compromised certificate" % ctx)


RULE_CHECKS = {"certificate_trust": _check_certificate_trust}


def validate_advisory(doc):
    errors = []
    ctx = "advisory"
    if _req(doc, "schema_version", str, errors, ctx) != "0.1":
        errors.append("advisory: schema_version must be '0.1'")
    aid = _req(doc, "id", str, errors, ctx)
    if aid and not ADVISORY_ID.match(aid):
        errors.append("advisory: id must look like AIA-YYYY-NNNN")
    _req(doc, "slug", str, errors, ctx)
    _req(doc, "title", str, errors, ctx)
    _req(doc, "summary", str, errors, ctx)
    rev = _req(doc, "revision", int, errors, ctx)
    if rev is not None and rev < 1:
        errors.append("advisory: revision must be >= 1")
    for key in ("published", "updated"):
        v = _req(doc, key, str, errors, ctx)
        if v and not DATE.match(v):
            errors.append("advisory: %s must be YYYY-MM-DD" % key)
    if _req(doc, "publication_state", str, errors, ctx) not in PUBLICATION_STATES:
        errors.append("advisory: publication_state must be one of %s" % (PUBLICATION_STATES,))
    if _req(doc, "check_maturity", str, errors, ctx) not in CHECK_MATURITY:
        errors.append("advisory: check_maturity must be one of %s" % (CHECK_MATURITY,))
    if _req(doc, "severity", str, errors, ctx) not in SEVERITIES:
        errors.append("advisory: severity must be one of %s" % (SEVERITIES,))
    sources = _req(doc, "sources", list, errors, ctx) or []
    if not sources:
        errors.append("advisory: at least one source is required")
    for i, s in enumerate(sources):
        _req(s, "id", str, errors, "sources[%d]" % i)
        _req(s, "url", str, errors, "sources[%d]" % i)
    affected = _req(doc, "affected", dict, errors, ctx) or {}
    rules = _req(affected, "rules", list, errors, "affected") or []
    if doc.get("publication_state") == "active" and not rules:
        errors.append("advisory: active advisories need at least one rule")
    for i, rule in enumerate(rules):
        c = "affected.rules[%d]" % i
        t = _req(rule, "type", str, errors, c)
        _req(rule, "id", str, errors, c)
        if t and t not in RULE_TYPES:
            errors.append("%s: unknown rule type %r (known: %s)" % (c, t, sorted(RULE_TYPES)))
        elif t:
            RULE_CHECKS[t](rule, errors, c)
    rem = _req(doc, "remediation", dict, errors, ctx) or {}
    _req(rem, "summary", str, errors, "remediation")
    check = _req(doc, "check", dict, errors, ctx) or {}
    req = _req(check, "requires", dict, errors, "check") or {}
    if "network" not in req or not isinstance(req["network"], list):
        errors.append("check.requires: 'network' must be an explicit list (empty means none)")
    fixtures = _req(doc, "fixtures", dict, errors, ctx) or {}
    expected = _req(fixtures, "expected", list, errors, "fixtures") or []
    if doc.get("check_maturity") in ("fixtured", "verified"):
        verdicts = {e.get("verdict") for e in expected}
        for needed in ("affected", "not_affected", "unknown"):
            if needed not in verdicts:
                errors.append("fixtures: check_maturity %r needs an expected %r fixture" % (doc.get("check_maturity"), needed))
    for i, e in enumerate(expected):
        c = "fixtures.expected[%d]" % i
        _req(e, "file", str, errors, c)
        _req(e, "why", str, errors, c)
        if _req(e, "verdict", str, errors, c) not in VERDICTS:
            errors.append("%s: verdict must be one of %s" % (c, VERDICTS))
    return errors


def validate_inventory(doc):
    errors = []
    if _req(doc, "inventory_version", str, errors, "inventory") != "0.1":
        errors.append("inventory: inventory_version must be '0.1'")
    _req(doc, "collected_at", str, errors, "inventory")
    target = _req(doc, "target", dict, errors, "inventory") or {}
    _req(target, "id", str, errors, "target")
    if _req(target, "kind", str, errors, "target") not in ("host", "container", "image", "project", None):
        errors.append("target.kind must be host|container|image|project")
    facts = _req(doc, "facts", dict, errors, "inventory") or {}
    stores = _req(facts, "trust_stores", list, errors, "facts") or []
    for i, s in enumerate(stores):
        c = "trust_stores[%d]" % i
        _req(s, "id", str, errors, c)
        _req(s, "path", str, errors, c)
        if _req(s, "type", str, errors, c) not in STORE_TYPES:
            errors.append("%s: type must be one of %s" % (c, STORE_TYPES))
    gaps = _req(doc, "gaps", list, errors, "inventory") or []
    for i, g in enumerate(gaps):
        _req(g, "what", str, errors, "gaps[%d]" % i)
        _req(g, "why", str, errors, "gaps[%d]" % i)
    return errors


def validate_result(doc):
    errors = []
    if _req(doc, "result_version", str, errors, "result") != "0.1":
        errors.append("result: result_version must be '0.1'")
    for key in ("advisory_id", "checked_at"):
        _req(doc, key, str, errors, "result")
    _req(doc, "advisory_revision", int, errors, "result")
    if _req(doc, "verdict", str, errors, "result") not in VERDICTS:
        errors.append("result: verdict must be one of %s" % (VERDICTS,))
    _req(doc, "target", dict, errors, "result")
    for key in ("stores", "gaps", "limitations"):
        _req(doc, key, list, errors, "result")
    return errors
