# Schema v0.1

Three documents. All JSON, all validated by `python3 -m amiaffected validate`
with no third-party dependency.

## advisory.json

One per incident, at `advisories/<year>/<slug>/advisory.json`.

| Field | Meaning |
|---|---|
| `schema_version` | `"0.1"` |
| `id` | stable, `AIA-YYYY-NNNN` |
| `slug`, `title`, `summary` | human identifiers |
| `aliases` | CVE IDs and other names |
| `revision` | integer, bump on any change to rules or fixtures |
| `published`, `updated` | `YYYY-MM-DD` |
| `publication_state` | `draft`, `active`, `mitigated`, `superseded`, `withdrawn`. Describes the incident write-up, not your systems. |
| `check_maturity` | `none`, `draft`, `fixtured`, `verified`. Independent of publication state. `fixtured` requires an expected `affected`, `not_affected` and `unknown` fixture. |
| `severity` | `low`, `medium`, `high`, `critical` |
| `sources[]` | `{id, title, url, role}`; claims in the advisory cite a source id |
| `credits[]` | people whose work the advisory builds on |
| `affected.rules[]` | typed detection rules, see below |
| `remediation.summary`, `remediation.steps_file` | short text plus pointer to `fix.md` |
| `check.requires` | `read_paths`, `binaries`, `network` (explicit list, empty means none), `scratch`, `timeout_seconds` |
| `check.limitations[]` | what the check cannot see; copied into every result |
| `fixtures.expected[]` | `{file, store_type, verdict, why}`; the fixture suite |

### Rule types

Rules are data. The matcher in `amiaffected/rules/` implements each type
once; advisories never ship code.

**`certificate_trust`**: `anchors[]` (roots whose presence makes a store
accept the bad chain: `name`, `sha256`, optional `ski`), `compromised[]`
(the bad certificates: `name`, `ski`, `sha256[]`), `distrust` (per store
type, `none` when the store has no distrust mechanism, otherwise
`unsupported_in_v0`). Verdict per store: `affected` if any anchor or
compromised certificate is present in a store type without a distrust
mechanism; `not_affected` if the store parsed fully and contains none;
`unknown` otherwise.

Planned, not yet implemented: `package_version` (distro package versions,
with per-ecosystem comparison), `osv` (query OSV for ecosystem, package,
version; network declared), `file_hash`.

## inventory (output of `amiaffected inventory`)

`inventory_version`, `collected_at`, `collector`, `target` (`id`, `kind`
host|container|image|project, `os`), `scope` (what was selected),
`facts.trust_stores[]` (`id`, `kind`, `type`, `path`, `readable`), `gaps[]`
(`what`, `why`).

Gaps are first-class. Anything the collector could not read, could not
find, or does not support becomes a gap, and any gap makes the overall
verdict `unknown`. Raw inventory never leaves the machine.

## result (output of `amiaffected check`)

Per advisory: `result_version`, `advisory_id`, `advisory_revision`,
`advisory_digest`, `checked_at`, `target`, `verdict`, `scope`, `stores[]`
(`id`, `type`, `path`, `rule`, `verdict`, `reason`, `evidence[]`), `gaps[]`,
`limitations[]`, `remediation`.

Evidence is fingerprints, counts, paths and versions. Never PEM bodies,
environment variables or secrets.

### Top-level check document

`amiaffected check` wraps the per-advisory results in one document:

| field | meaning |
|---|---|
| `verdict` | combined verdict across advisories, after the freshness rule |
| `data.kind` | `bundle` when running from a release bundle (BUNDLE.json present), else `source-tree` |
| `data.source_commit`, `data.built_at` | from BUNDLE.json; null for a source tree |
| `data.revision` | SHA-256 over the digests of every advisory file, sorted |
| `data.freshness` | `max_age_days`, `age_days`, `stale`, `note`. A stale bundle downgrades `not_affected` to `unknown`; positive findings stand |
| `runtime.executed` | absolute paths of every external program that ran (keytool, node) |
| `runtime.network`, `runtime.writes`, `runtime.privileges` | always `none`, `none`, current user |
| `runtime.sandbox` | states that the tool does not sandbox itself; the host must |

## Exit codes

| Code | Verdict |
|---|---|
| 0 | `not_affected` within the inspected scope, no gaps |
| 1 | `affected` |
| 2 | `unknown`: a gap, an unreadable store, an unsupported store type, bad input, or a crash |

Never infer safety from anything but exit 0 with a valid result document.
