# AIA-2026-0001: eMudhra intermediate CA private keys recoverable from the certificates

Rules: before anything runs, ask the user once for the whole batch below. Every
check block is read-only: no sudo, no network, no writes, no installs. The live
block is separate, opt-in, and the only part that touches the network. Report per
coverage item with the quoted output line that decided it. A store is never
"clean": the verdicts are affected, not_affected and unknown, and empty output,
exit 1, a missing tool or a permission error is a gap, not a negative.

Severity: critical. Revision 2, updated 2026-10-23, review by 2026-11-23.
Source: Dennis Jackson's write-up at emudhra.we-have-a-problem.com (retrieved
2026-10-23; the page carries no revision date of its own).

The commands were exercised on Ubuntu 24.04 on 2026-10-23. macOS, Windows, BSD
and the other distributions are written from documentation and the reference
page; expected output for those is described, not quoted.

## What happened

Eight intermediate CAs operated by eMudhra under the emSign brand were issued
with private keys that can be recovered from the certificates alone. Sixteen
certificates are involved: each intermediate has an eMudhra-issued certificate
chaining to emSign Root TLS CA - G3 or emSign Root CS CA - G3, and a Sectigo
cross-sign chaining to AAA Certificate Services. emSign ECC Root CA - G3 in turn
cross-signs emSign Root TLS CA - G3, which is how most Linux bundles and certifi
reached the chain. Anyone holding a recovered key can issue a TLS certificate
for any hostname, or a code-signing certificate for any publisher, that
validates in every client still trusting one of the four roots without a
distrust record for the intermediates.

Browsers are protected through their revocation lists (Firefox OneCRL and
CRLite, Chrome CRLSets, Microsoft's and Apple's lists, rolled out between
17 and 22 October 2026). Almost nothing else checks revocation: curl, wget,
package managers, pip, Node, Java, Go, Rust, Electron apps, mail clients and
most mobile apps validate against a local bundle and stop there. For those, the
only fix is a bundle that no longer carries the roots, or a distrust record for
the intermediates.

## Who is affected

Any machine, container image or runtime that carries its own trust store and
makes TLS connections or verifies signatures with a client that does not check
revocation. That is almost every server, laptop and CI runner. The question the
checks answer is narrower: which stores on this host still contain an anchor
root, and whether a distrust record exists next to it. See applicability and
coverage in advisory.json. Container images, VMs and remote hosts have their
own stores; they are a gap unless the same checks run inside them.

## Checks

Run the blocks in one shell session on Linux, macOS or BSD; block 0 defines the
fingerprint list and the scan function the others use. Windows uses block 7
instead. Each block prints, per store, `parsed N certificates, M matched` and a
`MATCH <sha256>` line for every hit. The agent must compare N with the number of
`BEGIN CERTIFICATE` markers printed as `markers`: if they differ, or N is 0, the
store was not fully read and is a gap. Each block ends with a `-- block N done`
line; a block that stops before it is a gap for the stores it did not reach. The fingerprints are the sixteen
compromised certificates, the cross-sign and the four roots, so a MATCH line is
read against the indicator list in advisory.json: a root means the store would
validate forged chains; a compromised intermediate means the store trusts it
directly.

```sh check
# 0. Fingerprints (SHA-256 of the DER, no colons) and the scan function. Nothing runs yet.
AIA_FPS='7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D|F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5|D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4|86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B|42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493|45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE|5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699|98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B|579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512|E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838|0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19|62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72|7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489|CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F|432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3|FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F|9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4|A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8|4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1|84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD|3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD'
# Reads PEM certificates on stdin; prints one MATCH line per hit and a parsed/matched summary.
aia_scan() {
  while openssl x509 -noout -fingerprint -sha256 2>/dev/null; do :; done | tr -d ':' | awk -v fps="$AIA_FPS" 'BEGIN{n=split(fps,a,"|"); for(i in a) want[toupper(a[i])]=1} {sub(/.*=/,""); total++; if (toupper($0) in want) {hit++; print "MATCH " $0}} END{print "parsed " total+0 " certificates, " hit+0 " matched"}'
}
# Scans a PEM file and prints the marker count to compare against parsed N.
aia_file() {
  echo "== $1"
  aia_scan < "$1"
  echo "markers $(grep -c 'BEGIN CERTIFICATE' "$1")"
}
openssl version
echo "-- block 0 done"
```

Expected on Ubuntu 24.04: `OpenSSL 3.0.13 30 Jan 2024`. No openssl at all is a
gap for every PEM store below.

### 1. System CA bundle (required)

```sh check
# 1. Which bundle this host's OpenSSL reads, then every candidate that exists.
openssl version -d
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ca-certificates/extracted/tls-ca-bundle.pem /etc/ssl/cert.pem /usr/lib/ssl/cert.pem /usr/local/share/certs/ca-root-nss.crt /etc/openssl/certs/ca-certificates.crt; do
  [ -f "$f" ] && aia_file "$f"
done
# BSD: certctl lists the trusted and untrusted sets the bundle is built from.
command -v certctl >/dev/null 2>&1 && certctl list 2>&1 | grep -ci 'emSign\|AAA Certificate Services'
command -v certctl >/dev/null 2>&1 && certctl untrusted 2>&1 | grep -i 'emSign\|AAA Certificate Services'
# Package version, for the floor in advisory.json (floor-ca-certificates).
command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Package} ${Version}\n' ca-certificates ca-certificates-java libnss3 2>&1
command -v rpm >/dev/null 2>&1 && rpm -q ca-certificates nss 2>&1
command -v apk >/dev/null 2>&1 && apk info -v 2>/dev/null | grep '^ca-certificates'
command -v pacman >/dev/null 2>&1 && pacman -Q ca-certificates-mozilla nss 2>&1
command -v brew >/dev/null 2>&1 && brew list --versions ca-certificates 2>&1
command -v pkg >/dev/null 2>&1 && pkg info ca_root_nss 2>&1 | head -n 2
command -v freebsd-version >/dev/null 2>&1 && freebsd-version -ku
command -v sw_vers >/dev/null 2>&1 && sw_vers
echo "-- block 1 done"
```

Exercised output on Ubuntu 24.04, 2026-10-23:

```text
OPENSSLDIR: "/usr/lib/ssl"
== /etc/ssl/certs/ca-certificates.crt
parsed 121 certificates, 0 matched
markers 121
== /etc/ssl/cert.pem
parsed 121 certificates, 0 matched
markers 121
ca-certificates 20260816ubuntu0.24.04.1
```

Reading: parsed equals markers and 0 matched, and the package is at the
Ubuntu 24.04 floor, so this store is not_affected. On a host that matches:

```text
MATCH D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4
parsed 146 certificates, 1 matched
```

That is the Sectigo AAA root: affected, because every non-browser client using
this bundle validates the cross-signed chains. Compare the version with the
floor using the distribution's own comparator, for example
`dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge 20260816ubuntu0.24.04.1 && echo at-or-above || echo below`,
and remember that RHEL 7 and Bottlerocket had no fixed version on 2026-10-23.
A version at the floor with a MATCH means the bundle was edited locally or
regenerated from a local addition; the MATCH wins. `/etc/ssl/cert.pem` on macOS
is a separate copy from the keychain and is read by the built-in curl, git,
python3 and openssl, so it counts here even if block 6 is also run.

### 2. Bundles named by environment variables (required)

```sh check
# 2. Variables that redirect clients to another bundle. Unset is a finding, not an empty match.
for v in SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS NODE_OPTIONS GIT_SSL_CAINFO PIP_CERT AWS_CA_BUNDLE CARGO_HTTP_CAINFO DENO_CERT; do
  if printenv "$v" >/dev/null 2>&1; then echo "$v=$(printenv "$v")"; else echo "$v unset"; fi
done
for v in SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO PIP_CERT AWS_CA_BUNDLE CARGO_HTTP_CAINFO DENO_CERT; do
  f=$(printenv "$v" 2>/dev/null) || continue
  [ -f "$f" ] && aia_file "$f"
done
d=$(printenv SSL_CERT_DIR 2>/dev/null)
if [ -n "$d" ] && [ -d "$d" ]; then for f in "$d"/*; do [ -f "$f" ] && aia_file "$f"; done; fi
# Tool configuration that points at a bundle.
command -v git >/dev/null 2>&1 && git config --get http.sslcainfo
command -v pip >/dev/null 2>&1 && pip config list 2>/dev/null | grep -i cert
command -v npm >/dev/null 2>&1 && npm config get cafile 2>/dev/null
echo "-- block 2 done"
```

Exercised output: eleven `... unset` lines, `null` from npm. Every file that is
named gets its own parsed/markers pair and is reported like block 1. A named
file that does not exist is a gap for the client that reads the variable.

### 3. Python certifi copies (required)

```sh check
# 3. Which bundle each interpreter actually resolves, then every certifi copy on disk.
for py in python3 python python3.13 python3.12 python3.11; do
  command -v "$py" >/dev/null 2>&1 || continue
  echo "== $py: $(command -v "$py") $("$py" --version 2>&1)"
  "$py" -c 'import certifi; print("certifi", certifi.__version__, "resolves", certifi.where())' 2>&1
  "$py" -c 'import ssl; print("ssl default cafile", ssl.get_default_verify_paths().cafile)' 2>&1
  "$py" -m pip --version 2>&1
done
for d in /usr/lib/python3/dist-packages /usr/lib/python3*/site-packages /usr/local/lib/python3*/site-packages /usr/local/lib/python3*/dist-packages "$HOME"/.local/lib/python3*/site-packages "$HOME"/.cache/uv/archive-v0 "$HOME"/.local/share/uv "$HOME"/.local/pipx "$HOME"/.local/share/pipx "$HOME"/.virtualenvs "$HOME"/.venv "$HOME"/venv "$HOME"/.pyenv/versions "$HOME"/miniconda3 "$HOME"/anaconda3 "$HOME"/.pixi /opt/conda /opt/homebrew/lib/python3*/site-packages /usr/local/Cellar /Library/Frameworks/Python.framework/Versions; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 8 -path '*certifi/cacert.pem' 2>/dev/null
done | sort -u | while read -r f; do aia_file "$f"; done
echo "-- block 3 done"
```

Exercised output on Ubuntu 24.04 (abridged):

```text
== python3: /usr/bin/python3 Python 3.12.3
certifi 2023.11.17 resolves /etc/ssl/certs/ca-certificates.crt
ssl default cafile /usr/lib/ssl/cert.pem
pip 24.0 from /usr/lib/python3/dist-packages/pip (python 3.12)
== python3.11: /home/koshik/.local/bin/python3.11 Python 3.11.15
ModuleNotFoundError: No module named 'certifi'
ssl default cafile None
pip 26.1.2 from /home/koshik/.local/share/uv/python/cpython-3.11.15-linux-x86_64-gnu/lib/python3.11/site-packages/pip (python 3.11)
== /home/koshik/.cache/uv/archive-v0/1GOjVvI1Dki2R-Qd10oLR/certifi/cacert.pem
MATCH 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
parsed 121 certificates, 1 matched
markers 121
== /usr/lib/python3/dist-packages/certifi/cacert.pem
MATCH D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4
MATCH 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
parsed 146 certificates, 2 matched
markers 146
== /usr/lib/python3/dist-packages/pip/_vendor/certifi/cacert.pem
MATCH D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4
MATCH 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
parsed 141 certificates, 2 matched
markers 141
```

Reading, line by line. Debian and Ubuntu patch certifi to return the system
bundle, so the system interpreter resolves `/etc/ssl/certs/ca-certificates.crt`
(not_affected per block 1) and the dist-packages cacert.pem with both roots is
present but unused by that interpreter: report both facts separately, and
report the file as affected for any other interpreter or copied virtualenv that
resolves it. pip's vendored copy under `pip/_vendor` is what `pip install`
itself uses on Debian builds that are not patched to the system store, so that
MATCH is affected for pip 24.0, which is below the 26.2.2 floor. A standalone
interpreter (uv- or pyenv-managed) with no certifi and `ssl default cafile
None` has no store at all until a package installs one; it is not_affected
only for itself. A copy under the uv cache is the file every new virtualenv is
linked from, so its MATCH is affected for everything created from it. Project
virtualenvs outside the listed directories are a gap until the user names
them; ask for the project paths and add them to the `for d in` list. Python
3.15.1, 3.14.9 and 3.13.17 bundle a fixed certifi on python.org builds.

### 4. Java cacerts and blocked.certs (required when a JDK or JRE is installed)

```sh check
# 4. Every JDK found, its keystore, and its distrust list.
jh0=$(printenv JAVA_HOME 2>/dev/null)
for jh in "$jh0" /usr/lib/jvm/* /usr/java/* /opt/java* /opt/jdk* /Library/Java/JavaVirtualMachines/*/Contents/Home "$HOME"/.sdkman/candidates/java/* "$HOME"/.jdks/* "$HOME"/.local/share/mise/installs/java/* "$HOME"/.asdf/installs/java/*; do
  [ -n "$jh" ] && [ -x "$jh/bin/keytool" ] || continue
  echo "== $jh"
  "$jh/bin/java" -version 2>&1 | head -n 1
  ks="$jh/lib/security/cacerts"
  [ -f "$ks" ] || ks="$jh/jre/lib/security/cacerts"
  [ -L "$ks" ] && echo "symlink to $(readlink -f "$ks")"
  "$jh/bin/keytool" -list -rfc -keystore "$ks" -storepass changeit 2>&1 | aia_scan
  echo "entries $("$jh/bin/keytool" -list -keystore "$ks" -storepass changeit 2>/dev/null | grep -c trustedCertEntry)"
  bl="$jh/lib/security/blocked.certs"
  [ -f "$bl" ] || bl="$jh/jre/lib/security/blocked.certs"
  if [ -f "$bl" ]; then echo "$AIA_FPS" | tr '|' '\n' | while read -r fp; do grep -iq "$fp" "$bl" && echo "BLOCKED $fp"; done; echo "blocked.certs lines $(grep -c . "$bl")"; else echo "no blocked.certs"; fi
  KT="$jh/bin/keytool"
done
[ -f /etc/ssl/certs/java/cacerts ] && [ -n "$KT" ] && echo "== /etc/ssl/certs/java/cacerts (Debian, regenerated from the system bundle)" && "$KT" -list -rfc -keystore /etc/ssl/certs/java/cacerts -storepass changeit 2>&1 | aia_scan
[ -z "$KT" ] && echo "no JDK found in the listed locations"
echo "-- block 4 done"
```

Exercised output on this laptop: `no JDK found in the listed locations`, which
makes the item not applicable, established by looking, not by an empty keytool
run. With a JDK, expect `parsed 90 certificates, 0 matched` or similar plus
`BLOCKED ...` lines once the JDK carries the distrust entries. A root MATCH with
no BLOCKED lines is affected. A root MATCH with all thirteen compromised
fingerprints BLOCKED is not_affected for that JDK: the chain fails at the
intermediate. `keytool error: ... password was incorrect` or `Keystore was
tampered with` is a gap for that keystore. Distribution JDK packages carry their
own version numbers, so the floors (27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2,
17.0.21.0.2, 11.0.33.0.2, 8u511 b32) apply to the `java -version` string of
upstream builds only; the keystore read decides.

### 5. Node.js compiled-in store (required when Node is installed)

```sh check
# 5. Every node binary: version against the floor for its major, and its compiled-in roots.
n0=$(command -v node 2>/dev/null)
for n in "$n0" "$HOME"/.nvm/versions/node/*/bin/node "$HOME"/.local/share/fnm/node-versions/*/installation/bin/node "$HOME"/.volta/tools/image/node/*/bin/node "$HOME"/.asdf/installs/nodejs/*/bin/node "$HOME"/.local/share/mise/installs/node/*/bin/node /opt/homebrew/opt/node*/bin/node /usr/local/bin/node; do
  [ -n "$n" ] && [ -x "$n" ] || continue
  echo "== $n $("$n" --version 2>&1)"
  "$n" -p 'tls.rootCertificates.join("\n")' 2>&1 | aia_scan
done
[ -z "$n0" ] && echo "node not on PATH"
for t in bun deno; do command -v "$t" >/dev/null 2>&1 && echo "$t $("$t" --version 2>&1 | head -n 1)"; done
echo "-- block 5 done"
```

Exercised output on Ubuntu 24.04:

```text
== /usr/bin/node v24.21.0
MATCH 86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
parsed 121 certificates, 1 matched
bun 1.3.14
```

Reading: this Node still compiles in emSign ECC Root CA - G3, so every Node
program on the host that uses the default store is affected; v24.21.0 is below
the 24.22.1 floor, which agrees. Bun 1.3.14 is below the 1.4.4 floor, and its
store cannot be read, so Bun is affected by version. The floors are 26.12.1,
24.22.1 and 22.23.4 per Node major, 1.4.4 for Bun and 2.9.8 for Deno. When the
store reads 0 matched on a version below the floor (a rebuilt or patched
binary), the store wins and the report says both. `NODE_OPTIONS` containing `--use-openssl-ca` or `--use-system-ca` (block
2) means this Node uses the system bundle from block 1 instead.

### 6. macOS keychains (required on macOS)

```sh check
# 6. System roots, admin additions and the login keychain, as PEM.
for kc in /System/Library/Keychains/SystemRootCertificates.keychain /Library/Keychains/System.keychain "$HOME"/Library/Keychains/login.keychain-db; do
  [ -f "$kc" ] || continue
  echo "== $kc"
  security find-certificate -a -p "$kc" 2>&1 | aia_scan
done
security dump-trust-settings -d 2>&1 | grep -i -B1 -A3 'emSign\|AAA Certificate Services'
echo "-- block 6 done"
```

Not exercised on macOS. Expected: the system roots keychain parses about 150
certificates and matches emSign ECC Root CA - G3 and AAA Certificate Services
(Apple ships both) until Apple removes them. Report those as present. Apple
distributes blocks through its own revocation data separately from the root
list, so a present root does not say whether Secure Transport on this Mac still
accepts the chains; only the opt-in live check shows that for curl, and nothing
here shows it for Safari or Mail. The admin trust settings dump shows whether
someone has already marked the roots untrusted.

### 7. Windows stores (required on Windows)

```powershell check
# 7. SHA-256 of every certificate in the trust and distrust stores, plus the disallowed-list sync time and installed versions.
$fps = '7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D','F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B','42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493','45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE','5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699','98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B','579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512','E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838','0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19','62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72','7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489','CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F','432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3','FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F','9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4','A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8','4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1','84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD','3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD'
$sha = [System.Security.Cryptography.SHA256]::Create()
foreach ($store in 'Cert:\LocalMachine\Root','Cert:\LocalMachine\AuthRoot','Cert:\LocalMachine\CA','Cert:\LocalMachine\Disallowed','Cert:\CurrentUser\Root','Cert:\CurrentUser\CA','Cert:\CurrentUser\Disallowed') {
  $certs = @(Get-ChildItem -Path $store -ErrorAction SilentlyContinue)
  $hit = 0
  foreach ($c in $certs) {
    $h = ($sha.ComputeHash($c.RawData) | ForEach-Object { $_.ToString('X2') }) -join ''
    if ($fps -contains $h) { $hit++; "MATCH $store $h $($c.Subject)" }
  }
  "$store parsed $($certs.Count) certificates, $hit matched"
}
$au = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate' -ErrorAction SilentlyContinue
foreach ($k in 'LastSyncTime','DisallowedCertLastSyncTime') {
  if ($au -and $au.$k) { "$k $([DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($au.$k, 0)).ToString('u'))" } else { "$k absent" }
}
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Docker Desktop|^Git|Visual Studio Code|Obsidian|Node\.js|Python 3|Java|OpenJDK|Temurin|Claude' } | Select-Object DisplayName, DisplayVersion
```

Not exercised on Windows. Expected: `Cert:\LocalMachine\Root` or `AuthRoot`
matches the four roots (Microsoft includes all of them), so the anchors are
present. Microsoft distributes the block through the automatic disallowed
certificate list rather than by removing roots. A compromised certificate
matched in a `Disallowed` store is a distrust record. The automatic list does
not necessarily appear there as certificates, so also read
`DisallowedCertLastSyncTime`: a sync after 2026-10-20 means the machine fetched
a disallowed list published after Microsoft's block; absent or older means the
anchors are trusted with no block, which is affected. Stores that cannot be
opened (`Get-ChildItem` returns nothing for a store that exists) are a gap. The
installed-programs list feeds block 9.

### 8. NSS databases (optional; needs certutil from nss-tools)

```sh check
# 8. Firefox and Chrome-on-Linux databases, if the NSS certutil tool is present.
if command -v certutil >/dev/null 2>&1; then
  for db in "$HOME"/.pki/nssdb /etc/pki/nssdb "$HOME"/.mozilla/firefox/*/ "$HOME"/snap/firefox/common/.mozilla/firefox/*/ "$HOME"/.var/app/org.mozilla.firefox/.mozilla/firefox/*/; do
    [ -f "$db/cert9.db" ] || continue
    echo "== $db"
    certutil -d "sql:$db" -L 2>/dev/null | awk 'NR>4 && NF {sub(/ +[^ ]+$/,""); print}' | while read -r nick; do certutil -d "sql:$db" -L -n "$nick" -a 2>/dev/null; done | aia_scan
  done
else
  echo "certutil (nss-tools / libnss3-tools) not installed: NSS databases are a gap"
fi
echo "-- block 8 done"
```

Exercised output on this laptop: the `certutil ... not installed` line, so the
item is a gap and is reported as such, not as not_affected. Firefox and Chrome
are protected by OneCRL, CRLite and CRLSets regardless of what these databases
hold, so a MATCH here is present, not affected, for the browser; it is affected
for any other NSS client (for example an application linking libnss directly)
that reads the same database. The built-in roots live in libnssckbi, whose
version is the `nss` or `libnss3` package from block 1 against the 3.131.1
floor.

### 9. Other bundled and compiled-in stores (optional; version evidence only)

```sh check
# 9. Tools whose store cannot be read as PEM: version against the floors in advisory.json.
for t in go cargo rustup uv pip pip3 conda pixi mise code claude docker git; do
  if command -v "$t" >/dev/null 2>&1; then echo "$t: $("$t" --version 2>&1 | head -n 1)"; else echo "$t: not installed"; fi
done
command -v go >/dev/null 2>&1 && go version
command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Package} ${Version}\n' 'curl' libcurl4 libcurl4t64 2>&1
command -v rpm >/dev/null 2>&1 && rpm -q 'curl' libcurl 2>&1
ls -d /opt/Obsidian* "$HOME"/.local/share/applications/*obsidian* /Applications/Obsidian.app 2>/dev/null
# Container images on this host carry their own bundles and are a gap until checked inside.
command -v docker >/dev/null 2>&1 && docker image ls --format '{{.Repository}}:{{.Tag}}' 2>&1 | head -n 20
command -v podman >/dev/null 2>&1 && podman image ls --format '{{.Repository}}:{{.Tag}}' 2>&1 | head -n 20
echo "-- block 9 done"
```

Exercised output on Ubuntu 24.04 (abridged):

```text
go: not installed
cargo: cargo 1.95.0 (f2d3ce0bd 2026-03-21)
rustup: rustup 1.29.0 (28d1352db 2026-03-05)
uv: uv 0.11.6 (x86_64-unknown-linux-gnu)
pip: pip 24.0 from /usr/lib/python3/dist-packages/pip (python 3.12)
code: 1.138.0
claude: 2.1.309 (Claude Code)
docker: Docker version 29.1.3, build 29.1.3-0ubuntu3~24.04.2
git: git version 2.43.0
curl 8.5.0-2ubuntu10.16
ghcr.io/github/github-mcp-server:latest
```

Reading: rustup 1.29.0 is below 1.29.2, uv 0.11.6 below 0.13.5 and VS Code
1.138.0 below 1.143.1, so each is affected by version for its own bundled
store; Claude Code 2.1.309 is at or above 2.1.303. pip 24.0 is below 26.2.2 and
its vendored file was read in block 3. Docker Engine on Linux is not Docker
Desktop, and git on Linux reads the system bundle, so those floors do not
apply here. The one container image is a gap. On Linux, curl uses the system
bundle from block 1;
the curl CA bundle floor (2026-10-20) applies to the extracted cacert.pem that
Windows builds and downloads carry. Go 1.27.3 and 1.26.10, Rust rustls-webpki
0.103.16 and webpki-roots 1.0.10 apply per binary built with them; a Go or Rust
program on this host is a gap unless its build is known. Each container image
listed is a gap. Godot had no fixed version on 2026-10-23.

## Live check (opt-in, separate yes)

This is the only block that reaches the network. The four hosts are operated by
Dennis Jackson and serve certificates chained to the compromised EM DV TLS CA -
G3B. Privacy, quoted from the source: "The servers behind the checker record how
many times each user-agent connects successfully, meaning it still trusts the
compromised intermediates. Only these counts are recorded." A JSON dump with
counts per JA4 fingerprint is also published. Ask before running it, after the
read-only batch has been reported.

```sh live
# Live: a connection that succeeds means this client, with the store it uses, trusts the forged chain. Each success is counted by the operator.
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do [ -f "$f" ] && echo "system bundle $f"; done
curl -sS --max-time 15 -o /dev/null -w 'dv-g3b: TRUSTED by this curl\n' https://dv-g3b-emudhra.we-have-a-problem.com/ || echo 'dv-g3b: rejected by this curl'
curl -sS --max-time 15 -o /dev/null -w 'dv-g3b-aaa: TRUSTED by this curl\n' https://dv-g3b-aaa-emudhra.we-have-a-problem.com/ || echo 'dv-g3b-aaa: rejected by this curl'
curl -sS --max-time 15 -o /dev/null -w 'dv-g3b-noct: TRUSTED by this curl (no CT, the chain an attacker would use)\n' https://dv-g3b-noct-emudhra.we-have-a-problem.com/ || echo 'dv-g3b-noct: rejected by this curl'
curl -sS --max-time 15 -o /dev/null -w 'dv-g3b-aaa-noct: TRUSTED by this curl (no CT)\n' https://dv-g3b-aaa-noct-emudhra.we-have-a-problem.com/ || echo 'dv-g3b-aaa-noct: rejected by this curl'
# Every bundle block 3 found, tested against the live chain with OpenSSL. Set AIA_BUNDLES to the space-separated paths from block 3.
for f in $AIA_BUNDLES; do
  [ -f "$f" ] || continue
  echo "== $f"
  openssl s_client -connect dv-g3b-emudhra.we-have-a-problem.com:443 -servername dv-g3b-emudhra.we-have-a-problem.com -CAfile "$f" </dev/null 2>&1 | grep 'Verify return code'
  openssl s_client -connect dv-g3b-aaa-emudhra.we-have-a-problem.com:443 -servername dv-g3b-aaa-emudhra.we-have-a-problem.com -CAfile "$f" </dev/null 2>&1 | grep 'Verify return code'
done
```

Expected: `rejected by this curl` with curl's own message on the line above,
for example `curl: (60) SSL certificate problem: unable to get local issuer
certificate`, means this curl does not trust the chain. `TRUSTED by this curl`
means it does: affected for everything that shares curl's bundle, which on
Linux is block 1 and on macOS is `/etc/ssl/cert.pem`. For each bundle,
`Verify return code: 0 (ok)` means that file validates the forged chain and
`Verify return code: 20 (unable to get local issuer certificate)` means it does
not. A `noct` host that is trusted is the worst case: the client also ignores
Certificate Transparency. A timeout or DNS failure is a gap for the live check,
not a negative. Negative results here cover only the clients exercised, never
the host.

## What cannot be checked from here

- Android devices: no command on this host reads the phone's trust store or
  its Play services block list. The user opens Settings, searches Trusted
  credentials, System tab, and confirms emSign ECC Root CA - G3 and AAA
  Certificate Services are disabled or that the device received the block.
  Disabling AAA breaks sites that chain to it; some vendors (HarmonyOS) do not
  allow disabling system roots.
- Browsers: OneCRL, CRLite and CRLSets state is inside each profile. Keep the
  browser updated; the reference site's in-browser checker shows whether this
  browser still accepts the chains.
- Windows automatic trust-list update: block 7 shows the sync time, not the
  list contents. Offline machines and machines with the update disabled look
  like unprotected machines.
- Applications that embed certificates in their own format: use the vendor's
  advisory and the floors in advisory.json.
- Container images, VMs and remote hosts: run blocks 0 to 5 inside each.

## Verdict rules for this advisory

- affected: any store the host's clients use has a root MATCH without a
  distrust record for all thirteen compromised fingerprints, or a compromised
  intermediate MATCH as a trusted entry, or a version-only store below its
  floor.
- not_affected: every required item for this platform was read, parsed equals
  markers everywhere, 0 matched everywhere, each optional item was either read
  with 0 matched or established as not installed by looking for its binaries,
  and the advisory is within review_by. A single gap makes this unknown.
- unknown: anything else, including a declined batch, with the gaps listed.
