# Am I Affected

A corpus of security-incident advisories written for agents. Each advisory
tells an agent what to look for on a user's own machine, exactly how to read
each store with read-only commands, what the output means, and how to fix
what it finds. The agent proposes the commands, the user approves them, and
the report says `affected`, `not_affected` or `unknown`, never "clean".

We distribute no executable code: our text influences the commands an agent
proposes, and the user approves them before they run. See `docs/trust.md`.

## Advisories

| Id | Title | Severity | Revision |
|----|-------|----------|----------|
| AIA-2026-0001 | eMudhra intermediate CA private keys recoverable from the certificates | critical | 2 |
| AIA-2026-0002 | PHP2Shell: unauthenticated remote code execution in every PHP web SAPI (CVE-2026-109618, CVE-2026-109619) | critical | 1 |

`index.json` is the machine-readable list.

## Using it with an agent

1. Install or clone this repository where the agent can read it. For Claude
   Code the skill is `skills/check/SKILL.md`; agents that read `AGENTS.md`
   find the same rules there. Both are generated from `RULES.md`.
2. Ask: "Am I affected by the eMudhra CA leak?" The agent reads `index.json`,
   picks the advisories that apply, shows one batch of read-only commands per
   advisory, and runs it only after you say yes.
3. Read the report: per store, the quoted evidence line and the finding; then
   the gaps; then the verdict. Remediation is in each advisory's `fix.md` and
   is presented for you to run, never run for you.

## Supported agents

An agent is supported when the ship gate (`.github/` CI plus a manual run of
every advisory on a real machine with that agent and model) has passed. No
agent has been through the gate yet; this table is filled in when one has.

| Agent | Model | Gate date | Platform |
|-------|-------|-----------|----------|

## Layout

- `RULES.md`: the rules agents follow; versioned (`Rules version: N`).
- `skills/check/SKILL.md`, `AGENTS.md`: generated from `RULES.md`.
- `advisories/<year>/<slug>/`: `advisory.json` (indicators, coverage,
  applicability, live hosts), `advisory.md` (what happened, check blocks,
  expected output), `fix.md` (fix blocks per platform), `eval/` (cases used
  to grade an agent's reading, never installed).
- `docs/schema.md`: field reference. `docs/trust.md`: what is installed and
  what the trusted computing base is.
- `tools/validate.py`: validator, command linter and generator; CI runs it.

## Contributing an advisory

Copy an existing advisory directory, keep the schema (`docs/schema.md`), and
run `python3 -I tools/validate.py --write` before opening a pull request. Check
blocks are linted: no sudo, no network, no writes, no pipes into interpreters;
every check prints what it parsed next to what it matched. Advisory pull
requests are the supply chain and are reviewed as such.

## License

Apache-2.0.
