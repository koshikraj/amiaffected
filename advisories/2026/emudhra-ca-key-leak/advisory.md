# AIA-2026-0001: eMudhra intermediate CA private keys recoverable from the certificates

Severity: critical. Kind: CA compromise. Published 2026-10-23, revision 1.

## What happened

Eight intermediate CAs operated by eMudhra (the emSign brand) were issued
with keys that can be recovered from the certificates themselves. Sixteen
certificates carry those keys: each intermediate is signed once by an
eMudhra root and once, as a cross-sign, by Sectigo's "AAA Certificate
Services" root. Six intermediates issue TLS certificates (DV, OV and EV, in
G3B and G3C generations) and two issue code-signing certificates.

Anyone holding a recovered key can issue a certificate for any hostname or
software publisher that chains through that intermediate. eMudhra revoked
all sixteen certificates on 2026-10-18. Revocation only helps clients that
check it, and most TLS clients, package managers and language runtimes do
not.

The reference write-up, signed proofs that the keys really are recoverable,
and live test hosts are maintained by Dennis Jackson at
https://emudhra.we-have-a-problem.com/. This advisory does not reproduce
that material; it adds the local, inventory-wide check.

## Who is affected

A trust store is affected if it still contains any of these roots and has no
distrust record for the compromised intermediates:

| Root | Operator | Why it matters |
|---|---|---|
| emSign Root TLS CA - G3 | eMudhra | direct issuer of the six TLS intermediates |
| emSign Root CS CA - G3 | eMudhra | direct issuer of the two code-signing intermediates |
| AAA Certificate Services | Sectigo | cross-signs all eight intermediates |
| emSign ECC Root CA - G3 | eMudhra | cross-signs emSign Root TLS CA - G3, so chains anchored here also validate |

A store is also affected if it contains one of the compromised intermediates
directly as a trusted certificate. Fingerprints are in `advisory.json`.

Root store status at the time of writing, per the reference site: Mozilla
and Chrome have removed AAA Certificate Services; Microsoft includes all
four roots; Apple includes AAA and emSign ECC Root CA - G3; emSign ECC Root
CA - G3 is included by every major root program. Operating system packages,
language runtimes and tools each bundle their own copy of one of those
programs' stores, and each copy is patched on its own schedule.

That is the gap this advisory covers. A browser check or a `curl` against
the test hosts tests exactly one store. This check inspects every store the
inventory can find on the host: the system bundle, Java `cacerts`, every
`certifi` bundle in scope, Node's compiled-in store, and anything pointed at
by `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` or
`NODE_EXTRA_CA_CERTS`.

Observed on 2026-10-23 on an up-to-date Ubuntu 24.04 laptop: the system
bundle was not affected, but four of five cached `certifi` bundles and the
Node 24 compiled-in store still contained emSign ECC Root CA - G3, and
`openssl verify` accepted the captured eMudhra chain against them.

## How to check

```
python3 -m amiaffected check --advisory emudhra-ca-key-leak --scan-root ~/projects
```

Exit 1 means at least one store trusts an anchor. Exit 2 means something
could not be inspected; read the `gaps` and `stores` arrays before
concluding anything. Exit 0 means no inspected store trusts an anchor and
nothing was skipped.

Stores with a distrust mechanism of their own (NSS databases used by Firefox
and by Chrome on Linux, the Windows certificate stores, the macOS keychain)
are reported as `unknown` in this version. Use the browser checker on the
reference site for those.

## What to do

See [fix.md](fix.md). In short: remove the four roots from every store you
control, or add explicit distrust where the store supports it, then re-run
the check. Upgrading the package that ships the store is the durable fix
once that package has removed the roots.

## Sources

- https://emudhra.we-have-a-problem.com/ (Dennis Jackson): write-up, proofs,
  captured chains, test hosts, patch status table.
- https://github.com/galadran/we-have-a-problem.com: `impacted-intermediates.json`
  and `roots.json`, against which every fingerprint in `advisory.json` was
  cross-checked. The intermediate fingerprints were also recomputed from the
  certificates in that repository's `proof/` directory.
