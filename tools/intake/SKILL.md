---
name: amiaffected-intake
description: Maintainer-only. Draft a new Am I Affected advisory folder (advisory.json, advisory.md, fix.md, eval cases) from vendor bulletins, CVE records and distribution security pages, as a branch for review. Runs no check commands, installs nothing and never publishes. Use only inside the amiaffected repository when a maintainer asks to draft, revise or triage an advisory.
---

# Am I Affected: intake

This skill drafts advisories. It lives under `tools/` so the Claude Code
plugin, which scans `skills/`, never installs it, and it is never
read during a check; `skills/check/SKILL.md` is the user-facing skill. The
output of this skill is a branch and a pull request that a second maintainer
reviews (CODEOWNERS), with `tools/validate.py` green. Nothing here publishes.

## What you are allowed to do

- Read: the sources the maintainer names, the vendor's advisory, the CVE
  records, the distribution security trackers and package pages, and the
  existing advisories in `advisories/` as the shape to match.
- Write: one new folder `advisories/<year>/<slug>/` with `advisory.json`,
  `advisory.md`, `fix.md` and `eval/`, plus the generated `index.json` and
  the README table row.
- Run: `python3 -I tools/validate.py --write` and the git commands for a
  branch off `main`. On this laptop you may exercise the check blocks you
  wrote, with the maintainer's one-batch approval, to capture real output
  for the "Exercised output" sections. Nothing else runs: no fix block,
  no exploit, no proof-of-concept, no network tool inside a check.

The draft is data about an incident. It must not become executable code:
the repository ships no scripts, and the linter rejects anything that
fetches, pipes into an interpreter, escalates or writes.

## Procedure

1. Triage before drafting. An advisory earns a folder when all hold: the
   incident is confirmed by the vendor or a primary source (not a single
   social post); a host can be checked for it with read-only local reads
   (a store, a package version, a config, a log line); and the fix is
   something the user can do. CVE rows alone are not advisories (D7 in the
   history: triage, not product). If any fails, write a one-paragraph
   triage note for the maintainer and stop.
2. Collect sources with dates. For each: id, title, https URL, role
   (vendor, primary, researcher, distribution, package-registry), and the
   retrieval date. The vendor fix announcement and the CVE/GHSA records
   are required where they exist. Record every version floor with the
   distribution page that states it; a floor you could not read is
   written as "to confirm" in `backport_note`, never guessed.
3. Pick the id and slug. The id is the next `AIA-<year>-<nnnn>` after the
   highest in `index.json`; the slug is the folder name, lowercase with
   hyphens, naming the incident not the vendor's marketing. `review_by` is
   30 days after `updated` for critical and high, 90 for the rest.
4. Write `advisory.json` against `docs/schema.md`. Indicators carry data
   only (version floors with their scheme and `as_of`, store locations,
   config settings with interpretation); no commands, patterns or scripts
   are allowed in JSON and the validator rejects the keys. Every indicator
   names its source. Coverage items say which stores are required for a
   negative; anything that cannot be read from the host goes in
   `uncheckable` with what the user should do instead.
5. Write `advisory.md` in the shape of the existing advisories: the
   preamble (one batch, read-only, no network, coverage, never "clean"),
   severity and revision line, sources, the exercised-on line, What
   happened, Who is affected, Checks (numbered `sh check` blocks, each
   ending `echo "-- block N done"`, each followed by exercised or expected
   output and a Reading paragraph that says what decides the item), the
   live check only if a vendor operates one, What cannot be checked from
   here, and Verdict rules. Say which comparator applies where: a
   distribution package with a backported fix is compared by package
   version, an upstream build by its own version string. Windows blocks
   are `powershell check`.
6. Write `fix.md`: upgrade first, then whatever the upgrade does not do
   (restart workers, rotate, redeploy images), one `sh fix <platform>`
   block per platform, each verified by re-running the check, mitigations
   last with the vendor's own statement of what they do not close.
7. Write `eval/README.md` and cases: at least one positive, one negative
   with every required item read, one unreadable, one stale, one
   incomplete_coverage, one declined, and whatever trap the comparator has
   (backported numbers, floating tags, present-but-unused). Each case is a
   transcript an agent could actually see, and `report_contains` quotes
   the lines the report must carry.
8. Run `python3 -I tools/validate.py --write` until it reports 0 errors,
   add the README row, and read the linter's reasons when it rejects a
   command rather than rewording around them: a rejected line usually is
   doing something a check must not.
9. Branch `feat/<slug>` off `main`, area-scoped commit
   (`feat(advisories): <title>`), no attribution lines. Open the PR only
   when the maintainer asks. The PR body lists the sources with dates, the
   floors you could not confirm, and which blocks were exercised on which
   platform.

## Revising an advisory

A revision bumps `revision`, sets `updated` and a new `review_by`, and
describes what changed in the PR body. Published advisories are not
rewritten in place for a different incident; a new incident gets a new id.
Expired `review_by` with nothing new to say is still a revision: re-check
every floor and source, then bump.

## What the intake skill never does

- Run a fix block, a proof-of-concept or any exploit material, on any host.
- Fetch and execute anything from a source. Sources are read as text.
- Add a live check host that the vendor does not operate.
- Vendor another project's artifact without a license on record.
- Commit to `main`, push, force-push, delete a branch or a tag.
