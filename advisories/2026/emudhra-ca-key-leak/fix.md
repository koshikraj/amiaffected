# Fix: remove trust in the eMudhra anchors

Order: most exposed first. Every step is reversible; the rollback is to
re-add the certificate you removed. Re-run `python3 -m amiaffected check`
after each step.

## 1. System bundle

**Debian, Ubuntu.** Update first: `sudo apt update && sudo apt install
ca-certificates`. If the check still reports the system bundle, disable the
roots by name in `/etc/ca-certificates.conf` (prefix the line with `!`,
for example `!mozilla/emSign_ECC_Root_CA_-_G3.crt`) and run
`sudo update-ca-certificates`. Rollback: remove the `!` and re-run.

**RHEL, Fedora, Alma, Rocky.** Update `ca-certificates`. To distrust
explicitly, copy each root's PEM into
`/etc/pki/ca-trust/source/blocklist/` and run `sudo update-ca-trust`.
Rollback: delete the file from the blocklist directory and re-run.

**Alpine.** Update `ca-certificates`; the bundle is regenerated from
`/usr/share/ca-certificates/mozilla/`, delete the four files and run
`update-ca-certificates`.

## 2. certifi (Python)

Every virtualenv, uv cache and container image has its own copy. Upgrade
`certifi` in each environment once a release without the roots is available.
Until then, generate a filtered bundle and point the environment at it:

```
python3 - <<'PY'
import base64, hashlib, re, certifi
drop = {"7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D",
        "F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5",
        "D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4",
        "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"}
src = open(certifi.where()).read()
keep = []
for m in re.finditer(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", src, re.S):
    der = base64.b64decode("".join(m.group(1).split()))
    if hashlib.sha256(der).hexdigest().upper() not in drop:
        keep.append(m.group(0))
open("filtered-cacert.pem", "w").write("\n".join(keep) + "\n")
print(len(keep), "certificates kept")
PY
export REQUESTS_CA_BUNDLE=$PWD/filtered-cacert.pem SSL_CERT_FILE=$PWD/filtered-cacert.pem
```

Rollback: unset the two variables.

## 3. Java cacerts

For each JDK the check lists, find the alias and delete it:

```
keytool -list -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit | grep -i -E 'emsign|aaa'
keytool -delete -alias <alias> -keystore "$JAVA_HOME/lib/security/cacerts" -storepass changeit
```

Rollback: `keytool -importcert -alias <alias> -file <root.pem> -keystore ... -storepass changeit`.
Package-managed JDKs restore the store on upgrade; prefer upgrading to a JDK
release that has dropped the roots once one exists.

## 4. Node

Node's store is compiled in and cannot be edited. Until a Node release ships
without the roots, make Node use the system store instead:

```
export NODE_OPTIONS=--use-openssl-ca
```

This only helps once step 1 is done. Rollback: unset `NODE_OPTIONS`.

## 5. Windows, macOS, browsers

Not inspected by this version. For Windows, the reference site publishes a
PowerShell script that imports the compromised certificates into the
Disallowed store after verifying the manifest hash:
https://emudhra.we-have-a-problem.com/ . Read it before running it. Browsers
ship their own distrust lists; keep them updated and use the site's browser
checker to confirm.

## 6. Verify

Re-run the check. For an independent confirmation against a specific bundle,
the reference site's captured chains can be verified offline:

```
openssl verify -CAfile /path/to/bundle.pem -untrusted chain.pem chain.pem
```

"OK" means that bundle still accepts the compromised chain.
