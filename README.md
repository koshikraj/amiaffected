# Am I Affected

A corpus of security incident advisories, each carrying a machine-checkable
"am I affected?" test and ordered remediation, so agents can check a user's
own systems in seconds and warn when something new applies to them.

Seed incidents:

- eMudhra intermediate CA key leak
- PHP2Shell (CVE-2026-109618, CVE-2026-109619)

Principles, in short:

- Checks are read-only, run locally under the user's own account, and return
  `affected`, `not_affected` or `unknown`. Never "clean".
- Raw inventory never leaves the machine.
- No fetch-and-exec. Execution is installed, reviewed code plus declarative
  advisory data.
- New incidents are triaged by humans. Feeds produce drafts, not checks.
