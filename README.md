# Am I Affected

Curated security incident advisories, each carrying a machine-checkable
"am I affected?" rule, offline fixtures and ordered remediation, so an agent
or a person can check their own machine in seconds and act on the answer.

Curated incidents, not coverage. Package-level CVE matching is already done
well by OSV, Trivy and Grype. This project spends its effort on the incidents
those tools cannot express: compromised certificate authorities, leaked
keys, configuration-level exposure, and remediation an agent can follow.

## Install

Releases are single archives built by GitHub Actions from a tagged commit,
with build provenance you verify before extracting:

```
gh attestation verify amiaffected-check-<version>.tar.gz \
  --repo koshikraj/amiaffected \
  --signer-workflow koshikraj/amiaffected/.github/workflows/release.yml
sha256sum -c SHA256SUMS
tar -xzf amiaffected-check-<version>.tar.gz
```

That proves GitHub built these exact bytes from this repository at the
attested commit. It does not prove the code is harmless; the code is small
enough to read, and [docs/trust.md](docs/trust.md) lists what to look at.
No release has been published yet, so for now the honest check is to
review the commit you are about to run.

Nothing is fetched at run time. New advisories arrive only as a new
verified archive.

## Use

```
python3 -I amiaffected-check-<version>/scripts/run.py check
```

`-I` keeps the current directory and `PYTHONPATH` off the import path, so
only the bundled copy can load. The check reads trust stores at known
system locations, plus any `--scan-root` directories you name, and prints
one JSON result per advisory. Exit codes: 0 not affected within the
inspected scope, 1 affected, 2 unknown. Read `gaps`, `runtime.executed` and
`data.freshness` before trusting a 0.

```
python3 -I .../scripts/run.py inventory     # what would be inspected, as JSON
python3 -I .../scripts/run.py validate      # check advisory files and run fixtures
```

From a source checkout, developers run the same commands as
`python3 -m amiaffected ...`; `python3 tools/build_bundle.py` produces the
release layout under `dist/`.

## Use from an agent

The release archive is a skill: `SKILL.md` at its root, the tool under
`scripts/`. Verify the archive, extract it into your agent's skills
directory (for Claude Code, `~/.claude/skills/amiaffected-check/`), and ask
"am I affected by <incident>?". The skill runs only the copy beside it,
locally, unprivileged, with no network, and reports the verdict, the gaps,
what executed, and the ordered remediation.

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
  matcher; no advisory ships code. No fetch-and-exec, ever: nothing is
  cloned, pulled or downloaded at run time, and a path found in an inventory
  never selects an executable.
- Every fixtured advisory has known-affected, known-clean and unknown
  fixtures whose expected verdicts were established independently of the
  matcher.
- New incidents are triaged by humans. Feeds produce drafts, not checks.

See [docs/schema.md](docs/schema.md) for the advisory, inventory and result
formats, and [docs/trust.md](docs/trust.md) for what to verify before letting
an agent run this.

## Layout

```
advisories/<year>/<slug>/   advisory.json, advisory.md, fix.md, fixtures/
amiaffected/                stdlib Python: inventory, matcher, rules, CLI
docs/                       schema and user-facing documentation
skills/check/               agent skill text; tools/build_bundle.py adds the code beside it
tools/                      bundle builder and launcher used by the release workflow
tests/                      unittest suite; CI runs validate + tests
```
