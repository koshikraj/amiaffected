# Trust

We distribute no executable code. Our text influences the commands an agent
proposes, and the user approves them before they run. That is the whole
claim, and it is also the whole risk: a security team will treat `RULES.md`
and the advisory markdown as software that influences a shell, and they are
right to.

## What gets installed

- `RULES.md`, the trusted part, and two files generated from it verbatim:
  `skills/check/SKILL.md` for Claude Code and `AGENTS.md` for agents that
  read that file. CI fails if either drifts from `RULES.md`.
- `index.json` and the `advisories/` tree: JSON that describes indicators and
  coverage, markdown with fenced check blocks, fix blocks and evaluation
  cases. No scripts, no binaries, no package of ours.
- `tools/validate.py` is maintainer tooling run in CI. The plugin copies the
  whole repository tree, so the file is present on disk, but no rule, skill
  or advisory ever invokes it; nothing in the plugin executes. The
  maintainer intake skill under `tools/intake/` is likewise present and
  never loaded: the plugin scans `skills/` only.

## Trusted computing base

The agent's host and its permission model, the commands the user approves,
and the rules as installed. Advisories are untrusted by design (rule 1): they
can only supply data. An advisory pull request is therefore the supply chain;
see the validator, the linter and `CODEOWNERS`.

## What a check does

- One batch of commands per advisory, shown in full and approved before
  anything runs (rule 3).
- Read-only and offline: no privilege escalation, no network, no writes, no
  piping into interpreters, no environment changes (rule 4). The linter
  rejects check blocks that do any of these; the agent reads them anyway.
- Negative conclusions require coverage: `not_affected` needs every required
  store read in full, no gaps, and a current advisory. Empty output, a missing
  tool or an error is a gap and the verdict is `unknown` (rule 6).
- The live check, when an advisory has one, is a separate opt-in step to the
  hosts listed in that advisory and nothing else, with the operator's privacy
  note quoted before the yes (rule 7).
- Inventory never leaves the machine (rule 8). Every report opens with a
  provenance header naming the agent, model, rules version, commit and
  advisory revisions (rule 9).

## What this is not

It is not a scanner, and no program of ours interprets the output; the agent
does, under the rules. The agents on which the reports have been checked are
listed in the README; anything not listed is unsupported. A routine may only
notify that a new advisory matches a saved platform profile; it runs no
commands.

## Verifying origin

Until the index is signed, origin is the git commit: the provenance header
names the commit the advisories were read from, and the files can be compared
against `https://github.com/koshikraj/amiaffected` at that commit. The
Claude Code plugin is the repository root at a released version: its
`version` in `.claude-plugin/plugin.json` is bumped for every advisory
release and tagged, so an installed copy is one tag's tree, and
`claude plugin update` moves to the next tag. `RULES.md` changes only with
its own `Rules version` bump; review it at the tag you installed.

## License

Apache-2.0, see `LICENSE`. Advisory data is derived from the sources credited
in each `advisory.json`.
