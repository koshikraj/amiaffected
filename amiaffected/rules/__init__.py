"""Typed detection rules. Each module exposes

    applies_to(rule, inventory) -> list of inventory facts the rule inspects
    evaluate(rule, fact) -> {"verdict", "reason", "evidence": [...]}

Verdict is one of amiaffected.VERDICTS. Anything a rule cannot read,
parse or support is "unknown", never "not_affected".
"""
from . import certificate_trust

RULE_TYPES = {
    "certificate_trust": certificate_trust,
}


def get(rule_type):
    return RULE_TYPES.get(rule_type)
