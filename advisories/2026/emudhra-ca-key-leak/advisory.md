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

With the bundled tool, which makes no network call and writes nothing:

```
python3 -I <skill_dir>/scripts/run.py check --advisory emudhra-ca-key-leak
```

Exit 1 means at least one store trusts an anchor. Exit 2 means something
could not be inspected; read the `gaps` and `stores` arrays before
concluding anything. Exit 0 means no inspected store trusts an anchor and
nothing was skipped.

Stores with a distrust mechanism of their own (NSS databases used by Firefox
and by Chrome on Linux, the Windows certificate stores, the macOS keychain)
are reported as `unknown` in this version. Use the browser checker on the
reference site for those.

### Check by hand

For readers, or agents, who would rather not run the tool. Every command
below is read-only, runs as the current user, needs no network, and prints
SHA-256 fingerprints. A store is affected if any of the four anchor roots
appears in it, or any of the 17 compromised intermediate fingerprints
listed in `advisory.json`:

| sha256 | Root |
|---|---|
| `7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D` | emSign Root TLS CA - G3 (eMudhra) |
| `F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5` | emSign Root CS CA - G3 (eMudhra) |
| `D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4` | AAA Certificate Services (Sectigo (Comodo)) |
| `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` | emSign ECC Root CA - G3 (eMudhra) |

Put the full indicator list in a shell variable once; it covers the roots
and the intermediates:

```
AIA_FPS='7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D|F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5|D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4|86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B|42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493|45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE|5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699|98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B|579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512|E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838|0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19|62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72|7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489|CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F|432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3|FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F|9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4|A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8|4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1|84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD|3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD'
```

**Any PEM bundle**: the system bundle (`/etc/ssl/certs/ca-certificates.crt`
on Debian and Ubuntu, `/etc/pki/tls/certs/ca-bundle.crt` on RHEL and
Fedora, `/etc/ssl/cert.pem` on Alpine and macOS), anything named by
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` or
`NODE_EXTRA_CA_CERTS`, and every certifi `cacert.pem`. Uses `openssl`.

```
BUNDLE=/etc/ssl/certs/ca-certificates.crt
while openssl x509 -noout -fingerprint -sha256 2>/dev/null; do :; done < "$BUNDLE" \
  | tr -d ':' | grep -i -c -E "$AIA_FPS"
```

A count above 0 is affected. Find certifi bundles without importing the
package: `find <venv or project dir> -path '*certifi*' -name cacert.pem`.

**Java cacerts**: one per JDK. Uses that JDK's `keytool`; the default
store password is `changeit`.

```
"$JAVA_HOME/bin/keytool" -list -v -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit \
  | grep 'SHA256:' | tr -d ': ' | grep -i -c -E "$AIA_FPS"
```

**Node's compiled-in store**: executes the `node` you name.

```
/usr/bin/node -p "require('tls').rootCertificates.join('\n')" \
  | while openssl x509 -noout -fingerprint -sha256 2>/dev/null; do :; done \
  | tr -d ':' | grep -i -c -E "$AIA_FPS"
```

A bundle you read completely with a count of 0 is not affected. A store
you did not read is a gap, not a 0. NSS, Windows and macOS keychains have
no command here; use the reference site's browser check for them.

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
