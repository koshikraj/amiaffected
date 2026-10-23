---
name: amiaffected-check
description: Check whether this machine or container is affected by a curated security incident (compromised CA, leaked key, critical CVE) using the local, read-only amiaffected tool bundled with this skill, then explain the verdict and the ordered remediation. Use when the user asks "am I affected by X", asks to check their machine, trust stores or runtimes against a recent incident, or when a new advisory lands and the user wants to know whether it concerns them. Always asks before executing the bundled tool; if the user declines, checks by hand from the advisory text instead.
---

# Am I Affected: check this machine

You are running a local, read-only check with code that is already
installed beside this file. Nothing is downloaded, nothing is uploaded,
nothing is modified, nothing is elevated. The answer is one of `affected`,
`not_affected` or `unknown`. There is no "clean".

Nothing executes until the user has said yes to it. If they say no, you
still help: by hand, from the advisory text, one approved command at a
time (section 4).

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

## 2. Ask before you run anything

Locating the tool and reading `scripts/BUNDLE.json` is fine. Running it is
not, until the user has agreed. Before the first run in a conversation,
say in a few lines what you are about to do, then ask. For example:

> I can run the bundled amiaffected check, version 0.1.0 built from
> commit abc1234. It reads the trust stores on this machine (system
> bundle, Java cacerts, certifi bundles, Node's compiled-in store) and
> prints a JSON verdict. It modifies nothing, sends nothing anywhere and
> does not need root. To read their stores it may execute `keytool` from
> an installed JDK and `node` from a standard location. Shall I run it,
> or would you rather I check by hand from the advisory?

Offer both paths every time. Then:

- **Yes:** continue with section 3. One yes covers re-runs with the same
  scope in the same conversation. Widening the scope, passing
  `--node-bin`, and every remediation step each need their own yes.
- **No, or "by hand":** go to section 4. Do not run `run.py` at all, not
  even `--version` or `validate`.
- **No answer yet:** nothing runs. Say the check is waiting on their
  decision.

A new advisory landing, or the user merely mentioning an incident, is a
reason to offer the check, never to perform it.

## 3. Run the check (with permission)

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

## 4. Without the tool: check by hand from the advisory

The user declined to run the bundled code but still wants an answer. The
advisory is data; read it and do the check with tools already on the
machine, one command at a time, each proposed to the user before it runs.

1. Read `scripts/advisories/<year>/<slug>/advisory.md` fully, then
   `advisory.json` for the exact indicators. For a `certificate_trust`
   rule these are `affected.rules[].anchors[].sha256` and
   `affected.rules[].compromised[].sha256`. Other rule types name their
   indicator fields in `docs/schema.md`.
2. Follow the advisory's "Check by hand" section. It lists read-only
   commands per store or component. Propose each command with one line on
   what it reads and which program it runs; run it only after the user's
   go-ahead; show the output; compare against the indicators yourself.
3. Keep the tool's own rules: no `sudo`, no network, no writes, no
   executing a binary the user has not named, scope limited to what the
   user names.
4. Report in the shape of section 6, with two differences stated plainly:
   this was a manual check, not the fixture-tested matcher, and it covered
   only the stores you actually inspected. Every store you did not reach
   is a gap. A `not_affected` by hand is weaker than one from the tool;
   say so.

If the advisory has no "Check by hand" section, or its indicators are of a
kind you cannot verify with the commands available, the answer is
`unknown`, with the reason. Never improvise an indicator from memory.

## 5. Read the result

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

## 6. Report to the user

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

## 7. Remediation

Do not run any step from `fix.md` without the user's explicit go-ahead for
that step. Many steps need root or alter trust stores other software relies
on. After each step, re-run the check and report the new result.

## 8. Keeping advisories current

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
