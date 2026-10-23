---
name: amiaffected-check
description: Check whether this machine or container is affected by a curated security incident (compromised CA, leaked key, critical CVE) using the local, read-only amiaffected CLI, then explain the verdict and the ordered remediation. Use when the user asks "am I affected by X", asks to check their machine, trust stores or runtimes against a recent incident, or when a new advisory lands.
---

# Am I Affected: check this machine

You are running a local, read-only check. Nothing is uploaded, nothing is
modified, nothing is elevated. The answer is one of `affected`,
`not_affected` or `unknown`. There is no "clean".

## 1. Locate the tool

Look for the checkout in this order and use the first that exists:

1. `amiaffected` on `PATH` (installed with `pip install .`)
2. A clone of `https://github.com/koshikraj/amiaffected`, run as
   `python3 -m amiaffected` from its root

If neither exists, ask before cloning. Never `curl | sh`, never fetch and run
a check script from anywhere. The matcher is installed, reviewed code;
advisories are data.

Requires Python 3.9+ and no dependencies.

## 2. Run the check

```
python3 -m amiaffected check --scan-root <DIR> [--scan-root <DIR> ...]
```

- Pass every directory where project virtualenvs, caches or vendored
  bundles may live (home, `~/projects`, `~/.cache`). Unscanned places are
  not "clean", they are not inspected.
- `--advisory <ID_OR_SLUG>` limits the run to one advisory.
- `--no-java` / `--no-node` skip those enumerators; each skip is recorded as
  a gap.
- To check a saved snapshot instead of this host:
  `python3 -m amiaffected inventory > inv.json` then
  `check --inventory inv.json`. The inventory file contains paths and
  package facts. Do not send it anywhere.

Run it as the current user. Do not add `sudo`. If a store is not readable,
that is a gap in the result, and the right response is to tell the user,
not to escalate.

Exit codes:

| exit | meaning |
|---|---|
| 0 | `not_affected` within the inspected scope |
| 1 | `affected`: at least one store or runtime matched |
| 2 | `unknown`: a gap, an unreadable store, a crash, or malformed output |

Treat missing or unparseable JSON on stdout as `unknown` regardless of
exit code.

## 3. Read the result

stdout is one JSON document: `verdict`, `advisories_checked`, and
`results[]`, one per advisory. In each result read, in this order:

1. `verdict`
2. `stores[]`: every inspected store with its own `verdict`, `reason` and
   `evidence` (fingerprints, counts, paths; never key material)
3. `gaps[]`: what was not inspected and why. Any gap makes the overall
   verdict `unknown` even when every inspected store is `not_affected`.
4. `limitations[]`: what this advisory's rule cannot see in this version
5. `remediation` and the advisory's `fix.md` under
   `advisories/<year>/<slug>/`

## 4. Report to the user

Lead with the verdict and the scope in one sentence, for example:
"Affected. 4 of 7 inspected trust stores still contain the eMudhra anchor
roots; Java keystores were not inspected."

Then:

- List affected stores by path, with the matching reason.
- List gaps plainly. A gap is a reason the user cannot rely on a 0.
- Link the advisory (`advisory.md`) and summarise the incident in two
  sentences from it. Do not restate CVE details from memory; use the file.
- Offer the remediation steps from `fix.md` in order. They are written to
  be reversible; say what the rollback is for each step you propose.

Never say "clean", "safe" or "your infrastructure is fine". The check
covers this host or container, within the scan roots given, at the time
it ran. Say that.

## 5. Remediation

Do not run any step from `fix.md` without the user's explicit go-ahead for
that step. Many steps need root or alter trust stores other software relies
on. After each step, re-run the check and report the new result.

## 6. Keeping advisories current

Advisories live in the checkout's `advisories/` directory. `git pull` on
the clone, or reinstall the package, to pick up new ones. Run
`python3 -m amiaffected validate` after updating; it checks every advisory
file and runs its fixtures offline. A `FAIL` means do not trust that
advisory until it is fixed upstream.
