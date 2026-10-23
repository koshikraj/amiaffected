---
name: amiaffected-check
description: Check whether this machine or container is affected by a curated security incident (compromised CA, leaked key, critical CVE) using the local, read-only amiaffected tool bundled with this skill, then explain the verdict and the ordered remediation. Use when the user asks "am I affected by X", asks to check their machine, trust stores or runtimes against a recent incident, or when a new advisory lands.
---

# Am I Affected: check this machine

You are running a local, read-only check with code that is already
installed beside this file. Nothing is downloaded, nothing is uploaded,
nothing is modified, nothing is elevated. The answer is one of `affected`,
`not_affected` or `unknown`. There is no "clean".

## 1. Locate the tool: it is in this skill, nowhere else

The tool is `scripts/run.py` in the directory that contains this SKILL.md.
Resolve that directory to an absolute path and use only that copy:

```
SKILL_DIR=<absolute path of the directory containing this file>
python3 -I "$SKILL_DIR/scripts/run.py" --version
```

If `scripts/run.py` or `scripts/BUNDLE.json` is missing, you are reading an
unbuilt source tree, not a release. Stop and tell the user to install a
verified release:

```
gh attestation verify amiaffected-check-<version>.tar.gz \
  --repo koshikraj/amiaffected \
  --signer-workflow koshikraj/amiaffected/.github/workflows/release.yml
tar -xzf amiaffected-check-<version>.tar.gz
```

Never clone, `git pull`, `pip install`, `curl`, or run an `amiaffected`
found on `PATH`. Never fetch and run a check script from anywhere. If the
bundled copy is not there, the answer is "not installed", not "I found
another one".

Requires Python 3.9+. No dependencies. Always pass `-I` so nothing outside
the bundle can be imported.

## 2. Run the check

Default scope is the known system locations: the system CA bundle, bundles
named by `SSL_CERT_FILE` and similar variables, Java `cacerts` at standard
JVM paths, the running interpreter's certifi, and Node's compiled-in store
from an allowlisted location.

```
python3 -I "$SKILL_DIR/scripts/run.py" check
```

Widen the scope only where the user tells you projects, virtualenvs or
caches live. Do not scan the whole home directory by default; ask.

```
python3 -I "$SKILL_DIR/scripts/run.py" check --scan-root ~/projects --scan-root ~/.cache/uv
```

- `--advisory <ID_OR_SLUG>` limits the run to one advisory.
- `--no-java` / `--no-node` skip those enumerators; each skip is recorded as
  a gap.
- `--node-bin /abs/path/node` authorises this run to execute a Node binary
  that is not at a standard location (nvm, fnm, volta). Only pass a path the
  user has confirmed. Without it, such a Node is a gap, not a guess.
- To check a saved snapshot instead of this host:
  `inventory > inv.json` then `check --inventory inv.json`. The inventory
  contains paths. Do not send it anywhere. Paths in an inventory never
  cause anything to be executed.

Run it as the current user. Do not add `sudo`. If a store is not readable,
that is a gap in the result, and the right response is to tell the user,
not to escalate.

If the host offers a sandbox for commands (read-only filesystem, no
network), run the check inside it. The tool does not sandbox itself and
says so in `runtime.sandbox`. State in your report whether the run was
sandboxed by the host or not.

Exit codes:

| exit | meaning |
|---|---|
| 0 | `not_affected` within the inspected scope |
| 1 | `affected`: at least one store or runtime matched |
| 2 | `unknown`: a gap, an unreadable store, stale data, a crash, or malformed output |

Treat missing or unparseable JSON on stdout as `unknown` regardless of
exit code.

## 3. Read the result

stdout is one JSON document with `verdict`, `advisories_checked`, `data`,
`runtime` and `results[]`, one per advisory. Read, in this order:

1. `verdict`
2. `data.freshness`: if `stale` is true the bundle is older than the limit
   and a `not_affected` has already been downgraded to `unknown`. Tell the
   user to install a newer release.
3. `runtime.executed`: the absolute paths of every external program that
   ran (keytool, node). Report them; this is the whole trusted computing
   base beyond Python.
4. In each result: `verdict`, then `stores[]` with per-store `verdict`,
   `reason` and `evidence` (fingerprints, counts, paths; never key
   material), then `gaps[]` (what was not inspected and why; any gap makes
   the verdict `unknown`), then `limitations[]`, then `remediation` and the
   advisory's `fix.md` under `scripts/advisories/<year>/<slug>/`.

## 4. Report to the user

Lead with the verdict and the scope in one sentence, for example:
"Affected. 4 of 7 inspected trust stores still contain the eMudhra anchor
roots; Java keystores were not inspected."

Then:

- List affected stores by path, with the matching reason.
- List gaps plainly. A gap is a reason the user cannot rely on a 0.
- Say what executed (`runtime.executed`), whether the host sandboxed the
  run, and the bundle's `data.source_commit` and `data.built_at`.
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

Advisory data ships inside the bundle and is only updated by installing a
newer verified release; there is no in-place update, no `git pull`, no
fetch. `data.freshness` in every result reports the bundle's age, and a
bundle older than the limit stops reassuring on its own. When a new release
is out, the user verifies and installs it exactly as in step 1. After
installing, run `validate`:

```
python3 -I "$SKILL_DIR/scripts/run.py" validate
```

It checks every advisory file and runs its fixtures offline. A `FAIL` means
do not trust that advisory until it is fixed upstream.
