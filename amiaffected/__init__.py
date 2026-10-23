"""Am I Affected: local, read-only checks of this machine against curated
security incident advisories. Standard library only."""

__version__ = "0.1.0"

VERDICTS = ("not_affected", "affected", "unknown")
EXIT_CODES = {"not_affected": 0, "affected": 1, "unknown": 2}
