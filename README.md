# Am I Affected

Curated security incident advisories, each carrying a machine-checkable
"am I affected?" rule, offline fixtures and ordered remediation, so an agent
or a person can check their own machine in seconds and act on the answer.

Curated incidents, not coverage. Package-level CVE matching is already done
well by OSV, Trivy and Grype. This project spends its effort on the incidents
those tools cannot express: compromised certificate authorities, leaked
keys, configuration-level exposure, and remediation an agent can follow.

## Use

```
git clone https://github.com/koshikraj/amiaffected
cd amiaffected
python3 -m amiaffected check --scan-root ~/projects
```

No dependencies beyond Python 3.9+. The check reads trust stores and
runtimes at known locations, plus the scan roots you name, and prints one
JSON result per advisory. Exit codes: 0 not affected within the inspected
scope, 1 affected, 2 unknown. Read the `gaps` before trusting a 0.

```
python3 -m amiaffected inventory      # what would be inspected, as JSON
python3 -m amiaffected validate       # check advisory files and run fixtures
```

## Advisories

| ID | Incident | Rule | Maturity |
|---|---|---|---|
| [AIA-2026-0001](advisories/2026/emudhra-ca-key-leak/advisory.md) | eMudhra intermediate CA private keys recoverable from the certificates | `certificate_trust` | fixtured |

## Principles

- Checks are read-only, run locally under the user's own account, and return
  `affected`, `not_affected` or `unknown`. Never "clean".
- Anything unreadable, unparseable or unsupported is `unknown`, and any gap
  in the inventory makes the overall verdict `unknown`.
- Raw inventory never leaves the machine.
- Advisories are data. Detection rule types are implemented once in the
  matcher; no advisory ships code. No fetch-and-exec, ever.
- Every fixtured advisory has known-affected, known-clean and unknown
  fixtures whose expected verdicts were established independently of the
  matcher.
- New incidents are triaged by humans. Feeds produce drafts, not checks.

See [docs/schema.md](docs/schema.md) for the advisory, inventory and result
formats.

## Layout

```
advisories/<year>/<slug>/   advisory.json, advisory.md, fix.md, fixtures/
amiaffected/                stdlib Python: inventory, matcher, rules, CLI
docs/                       schema and user-facing documentation
tests/                      unittest suite; CI runs validate + tests
```
