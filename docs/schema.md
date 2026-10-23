# advisory.json field reference (schema 1.0)

Every advisory lives in `advisories/<year>/<slug>/` and has four parts:

| File | Purpose | Read by |
|---|---|---|
| `advisory.json` | descriptive data: what the incident is, exact indicators, what must be covered before a negative verdict | agents, `tools/validate.py` |
| `advisory.md` | the write-up and the "How to check" blocks | agents, people |
| `fix.md` | remediation per platform, with the source's warnings kept | agents (read and quoted, never executed), people |
| `eval/` | evaluation cases for maintainers | maintainers only; never installed |

`advisory.json` is descriptive only. It carries no executable expression,
no command template with substituted input and no generic condition
language. Example commands live in `advisory.md`, labelled as examples. An
agent may pick a platform-appropriate reader for an indicator, but it must
preserve the comparison semantics written here; if it cannot show that its
method is equivalent, that store is a gap. Agents never invent detection
criteria.

`tools/validate.py` enforces everything marked **required** below and the
cross-references. It is a floor, not the review.

## Top level

| Field | Required | Meaning |
|---|---|---|
| `schema_version` | yes | `"1.0"` |
| `rules_version` | yes | the minimum `RULES.md` version this advisory was written for (integer) |
| `id` | yes | `AIA-<year>-<4 digits>`, unique across the corpus |
| `slug` | yes | equals the directory name; lowercase, digits and hyphens |
| `title` | yes | one line |
| `summary` | yes | one paragraph a reader can act on without the write-up |
| `aliases` | yes | other names and CVE ids; may be empty |
| `revision` | yes | integer, bumped on every published change |
| `published`, `updated` | yes | ISO dates |
| `review_by` | yes | ISO date after `updated`; after it, the advisory is stale (see verdict rules) |
| `publication_state` | yes | `draft`, `active`, `superseded` or `withdrawn` |
| `severity` | yes | `low`, `medium`, `high` or `critical` |
| `sources` | yes | list; see below. At least one |
| `credits` | no | list of `{name, url, for}` |
| `products` | yes | list of `{name, ecosystem, scope}`: what is in scope and what is not, in words |
| `applicability` | yes | `{summary, conditions[]}`. `summary` is the one line `index.json` shows; an agent opens the advisory only when it matches the machine. `conditions` are plain sentences |
| `indicators` | yes | list; see below. At least one |
| `coverage` | yes | list; see below. At least one |
| `limitations` | yes | list of sentences: what no method in this advisory can establish |
| `uncheckable` | no | list of `{what, why, user_should}`: things no agent can check from this machine |
| `remediation` | yes | `{summary, file}`; `file` is `fix.md` and must exist |
| `live_check` | no | see below |

## sources[]

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | short token, unique within the advisory; indicators cite it |
| `title` | yes | |
| `url` | yes | |
| `role` | yes | free text: `reference_implementation`, `vendor_advisory`, `artifacts`, `osv`, ... |
| `retrieved` | yes | ISO date the maintainer last read it |

## indicators[]

Common fields: `id` (unique within the advisory), `type`, `meaning` (what a
match establishes, in words, and nothing more), `source` (a `sources[].id`).

### type `certificate`

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | subject common name |
| `operator` | no | |
| `role` | yes | `anchor` (a root whose presence lets the compromised chains validate) or `compromised` (the leaked certificate itself) |
| `sha256` | yes | list of uppercase hex SHA-256 fingerprints of the DER certificate; cross-signs give one certificate several |
| `ski` | no | uppercase hex subject key identifier |
| `comparison` | yes | always `"sha256 of the DER certificate, case-insensitive; SKI is a secondary key for stores that expose it"` or an equivalent sentence |

Presence of an anchor in a store means the store would validate chains to
the compromised intermediates **if that store has no distrust record for
them**. Present and actively-trusted are separate findings and the
`meaning` must say which one a match establishes.

### type `version_floor`

| Field | Required | Meaning |
|---|---|---|
| `product` | yes | |
| `ecosystem` | yes | `os-package`, `pypi`, `npm`, `cargo`, `runtime`, `application`, ... |
| `version_scheme` | yes | `semver`, `pep440`, `debian`, `rpm`, `apk`, `date`, `freebsd`, `opaque` |
| `affected` | yes | list of `{introduced, fixed}` ranges in the product's own scheme; `introduced` may be `"0"` |
| `fixed_in` | yes | list of the first fixed version per branch, as strings |
| `backport_note` | no | where distributions backport fixes under the old upstream number; the agent keys on the package version, not the tool's own banner |
| `as_of` | yes | ISO date the floors were taken from the source |

A version at or above the floor establishes "installed version is at or
above the floor" and nothing about any store the product bundles. Where a
store can be read, read it; version is the fallback.

### type `file_hash`

`algorithm`, `target` (description of the file), `hashes` (list), `meaning`.

### type `config`

`component`, `setting`, `interpretation` (what each value means).

## coverage[]

Each entry is a store or component type that must be reached and read
successfully before `not_affected` is allowed.

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | unique within the advisory; check blocks in `advisory.md` name it |
| `store` | yes | human name |
| `indicators` | yes | list of `indicators[].id` this store is checked against |
| `platforms` | yes | list of `{os, locations[], note}`; `os` is `linux`, `macos`, `windows`, `freebsd`, `netbsd`, `any` |
| `required` | yes | `true` if a negative verdict needs it; `false` for stores that are optional (a store that is not installed is not a gap when `required` is false and the check block says how absence is established) |

## live_check (optional)

| Field | Required | Meaning |
|---|---|---|
| `hosts` | yes | list of `{host, proves, negative_means}` |
| `privacy` | yes | one sentence on what the remote host records (quoted from the source) |
| `operator` | yes | who runs the hosts |

Only hosts listed here may appear in a live block (`sh live`) in
`advisory.md`. The linter rejects any other host.

## Fenced blocks in advisory.md and fix.md

The info string on every fenced shell block declares its mode, and the
linter applies the mode's rules:

| Info string | Allowed in | Rules |
|---|---|---|
| `sh check` | `advisory.md` | read-only, no sudo/doas/su, no network, no writes or redirects (except to `/dev/null`), no pipes into an interpreter or shell, no env-assignment prefixes or `export`, no `$()` or backticks around a network tool, no package-manager or trust-store mutation verbs |
| `sh live` | `advisory.md` | same as `check`, except `curl`, `wget -q -O /dev/null` and `openssl s_client` may reach the hosts in `live_check.hosts` and nothing else |
| `sh fix <platform>` or `powershell fix windows` | `fix.md` | may write and use sudo; no pipes into an interpreter or shell, no fetch that is executed (`curl ... \| sh`, `$(curl ...)`). `<platform>` is required and must be one of `any linux debian ubuntu alpine fedora rhel suse arch nixos macos windows freebsd netbsd android` |
| `text` | anywhere | never linted: output excerpts, file contents |
| other languages (`json`, `nix`, `yaml`, ...) | anywhere | never linted |

A shell block without a mode fails validation. A `check` or `live` block in
`fix.md`, or a `fix` block in `advisory.md`, fails validation.

Every `advisory.md` must open with the five-line preamble (ask before
running, read-only, no network, no negative without full coverage, never
"clean" or "safe"), and the linter checks that the words "clean" and
"safe" do not appear as verdict words anywhere in the advisory.

## eval/

Each case is `eval/<name>.json`:

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | |
| `kind` | yes | `positive`, `negative`, `unreadable`, `stale`, `incomplete_coverage`, `present_unused`, `backported`, `declined` |
| `advisory_revision` | yes | the revision the case was written for |
| `coverage` | yes | the `coverage[].id` it exercises, or `"all"` |
| `input` | yes | `{file}` pointing at a file under `eval/`, or `{captured_output}` with the text the command produced |
| `expected` | yes | `{verdict, report_contains[]}`; `verdict` is `affected`, `not_affected` or `unknown` |

CI validates the shape and that referenced files exist. Running an agent
against the cases and grading the report is manual.

## index.json

Generated by `tools/validate.py --write` from every `advisory.json` and
committed. Fields per entry: `id`, `slug`, `path`, `title`, `severity`,
`revision`, `published`, `updated`, `review_by`, `publication_state`,
`rules_version`, `applicability` (the one-line summary), `products`,
`indicator_types`, `live_check` (boolean). Top level: `schema_version`,
`updated` (the newest `updated` across advisories), `count`, `advisories`.
CI fails if the committed file differs from a regeneration.
