# Why trust this

This page is for the person who has to decide whether an agent may run
amiaffected on a machine they are responsible for. Everything below is
checkable; nothing asks to be taken on faith.

## What you install

One release archive, `amiaffected-check-<version>.tar.gz`, built by GitHub
Actions from a tagged commit of `koshikraj/amiaffected`. It contains the
skill text, the Python package, the advisory data and a `BUNDLE.json`
recording the version, source commit, build time and a digest over the
advisory set. The archive is a copy of the repository's package and data,
not a second implementation.

Verify it before extracting it or letting an agent read `SKILL.md`:

```
gh attestation verify amiaffected-check-<version>.tar.gz \
  --repo koshikraj/amiaffected \
  --signer-workflow koshikraj/amiaffected/.github/workflows/release.yml
sha256sum -c SHA256SUMS
```

The first command proves origin: GitHub built exactly these bytes from this
repository, with this workflow, at the commit named in the attestation. It
does not prove the code is benign. The second command only detects
corruption. Until the first release exists, the honest statement is
"review this commit", not "verified".

Nothing is ever cloned, pulled or fetched at run time. Updates are a new
verified archive replacing the old one.

## What runs

- Python 3.9 or newer, standard library only. No third-party Python code.
- Started as `python3 -I <bundle>/scripts/run.py`, so the current directory,
  `PYTHONPATH` and user site packages are off the import path. The only
  non-stdlib code that can load is the copy inside the bundle.
- Two optional external runtimes, each only from an allowlisted absolute
  path or a path you pass with `--node-bin`:
  - `keytool`, taken from the JVM that owns the `cacerts` being read, and
    only when that JVM sits at a standard location or `JAVA_HOME`.
  - `node`, from `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin` or
    `/snap/bin`, asked to print its compiled-in root store.
  Both run with a minimal environment (`PATH`, `LANG`, `LC_ALL` only), so
  `NODE_OPTIONS` and `JAVA_TOOL_OPTIONS` cannot inject code. The result
  lists every executable that actually ran under `runtime.executed`.
- A saved inventory passed with `--inventory` is untrusted input. A path in
  it never selects an executable; an unlisted path is reported as `unknown`.
- The collector never imports the packages it inspects. certifi bundles are
  located as files on disk.

## What it does not do

- No network. The advisory data is in the bundle. The result says
  `"network": "none"` and the code has no socket or HTTP use beyond
  `gethostname()` for the target id.
- No writes. It reads trust stores and prints JSON to stdout. The launcher
  disables bytecode caching, so not even `.pyc` files land in the bundle.
- No elevation. Run as the current user. Unreadable stores are gaps, and
  gaps make the verdict `unknown`.
- No scanning of your home directory unless you name it. Default scope is
  known system locations; `--scan-root` adds directories you choose.

## What the answer means

`affected`, `not_affected` or `unknown`, for this host, within the inspected
scope, at the time it ran. Any gap, any unreadable or unparseable store, any
unsupported store type, and any bundle older than 30 days downgrade a
`not_affected` to `unknown`. Positive findings always stand. There is no
"clean".

## Sandbox

amiaffected does not sandbox itself and does not claim to. The result's
`runtime.sandbox` field says so. Run it under the host's sandbox where one
exists: read-only filesystem, no network, no access to credential or agent
sockets. The skill asks the agent to do this and to say in its report
whether it did.

## Fixtures and CI

Every fixtured advisory ships known-affected, known-clean and unknown
fixtures whose expected verdicts were set independently of the matcher,
with `openssl verify` against captured chains. CI runs `validate` and the
unit tests on Python 3.9 and 3.12 on every change, and the release workflow
additionally runs the extracted bundle outside the repository before
attesting it.

## Not yet

- No release has been published, so the attestation command above has
  nothing to verify yet.
- NSS databases, Windows and macOS keychains, and container images are not
  read in v0 and are reported as gaps.
