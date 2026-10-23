# Fix: AIA-2026-0001 eMudhra intermediate CA key leak

The durable fix for every store is the package or runtime version in
advisory.json (`floor-*` indicators), which ships a bundle without the four
roots or a distrust record for the intermediates. Where no fixed version exists
yet, the interim is to distrust the two Mozilla-program roots in the system
store. The reference site attaches two warnings that stay attached here: the
Linux blocklist edits are "NOT recommended for ordinary users", and the Windows
block "is not recommended for enterprise-managed devices". AAA Certificate
Services anchors many legitimate sites, so blocking it breaks them; blocking
emSign ECC Root CA - G3 alone closes the path most Linux bundles and certifi
had. Re-run the checks in advisory.md after any fix; the fix is verified by the
check, not by the command exiting 0.

Every block below writes to the system or installs packages and is presented
to the user as its own step after the report. Nothing here fetches and runs
code.

## Debian and Ubuntu

```sh fix debian
# Durable: the fixed ca-certificates (and the Java keystore built from it).
sudo apt-get update
sudo apt-get install --only-upgrade ca-certificates ca-certificates-java
dpkg-query -W -f='${Package} ${Version}\n' ca-certificates
```

```sh fix ubuntu
sudo apt-get update
sudo apt-get install --only-upgrade ca-certificates ca-certificates-java
dpkg-query -W -f='${Package} ${Version}\n' ca-certificates
```

Interim when the package is still below the floor (not recommended for ordinary
users; it is undone by the next package upgrade, which is fine once that
upgrade carries the fix):

```sh fix debian
# Interim: deselect the two roots in the bundle configuration and rebuild the bundle and the Java keystore.
sudo cp /etc/ca-certificates.conf /etc/ca-certificates.conf.bak-emudhra
sudo sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' /etc/ca-certificates.conf
sudo update-ca-certificates
sudo touch /var/lib/ca-certificates-java/fresh
sudo dpkg-reconfigure ca-certificates-java
```

## Alpine and Chainguard

```sh fix alpine
# Durable: ca-certificates 20261020-r0 or later (Chainguard: 20260909-r3).
apk update
apk upgrade ca-certificates ca-certificates-bundle
apk info -v | grep '^ca-certificates'
```

```sh fix alpine
# Interim: Alpine carries only the emSign ECC root in its configuration.
cp /etc/ca-certificates.conf /etc/ca-certificates.conf.bak-emudhra
sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' /etc/ca-certificates.conf
update-ca-certificates
```

## Fedora, RHEL, Oracle Linux, CentOS Stream

```sh fix fedora
# Durable: ca-certificates 2026.2.92_v9.0.319 (RHEL builds: -81.3.el8_10, -90.3.el9_8, -100.3.el10_2). RHEL 7 had no fix on 2026-10-23.
sudo dnf upgrade ca-certificates
rpm -q ca-certificates
```

```sh fix rhel
sudo dnf upgrade ca-certificates
rpm -q ca-certificates
```

```sh fix fedora
# Interim: put the roots in the p11-kit blocklist and regenerate the extracted bundles.
d=/etc/pki/ca-trust/source/blocklist
[ -d "$d" ] || d=/etc/pki/ca-trust/source/blacklist
sudo trust extract --overwrite --format=pem-bundle --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' "$d/emSign_ECC_Root_CA_-_G3.pem"
sudo update-ca-trust
# Only if the report showed the AAA root and the user accepts broken sites that chain to it:
# sudo trust extract --overwrite --format=pem-bundle --filter='pkcs11:object=AAA%20Certificate%20Services;type=cert' "$d/AAA_Certificate_Services.pem" && sudo update-ca-trust
```

## openSUSE and SLE

```sh fix suse
sudo zypper refresh
sudo zypper update ca-certificates-mozilla
rpm -q ca-certificates-mozilla
```

```sh fix suse
# Interim: same blocklist mechanism, different path and rebuild command.
sudo trust extract --overwrite --format=pem-bundle --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' /etc/pki/trust/blocklist/emSign_ECC_Root_CA_-_G3.pem
sudo update-ca-certificates
```

## Arch

```sh fix arch
# Durable: ca-certificates-mozilla 3.131.1-1.
sudo pacman -Syu ca-certificates-mozilla
pacman -Q ca-certificates-mozilla
```

```sh fix arch
# Interim.
sudo trust extract --overwrite --format=pem-bundle --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' /etc/ca-certificates/trust-source/blocklist/emSign_ECC_Root_CA_-_G3.pem
sudo update-ca-trust
```

## NixOS

Add to the system configuration and rebuild; this is declarative and survives
upgrades until removed:

```nix
security.pki.caCertificateBlacklist = [ "Comodo AAA Services root" "emSign ECC Root CA - G3" ];
```

```sh fix nixos
sudo nixos-rebuild switch
```

## macOS

The built-in curl, git, python3, perl, ruby and openssl read `/etc/ssl/cert.pem`,
which Apple ships with both roots. Apple's own block covers Safari, Mail and
Secure Transport clients, not that file. Homebrew's ca-certificates 2026-09-25_1
is already fixed for Homebrew-built tools.

```sh fix macos
# Durable for Homebrew tools.
brew update
brew upgrade ca-certificates
brew list --versions ca-certificates
```

```sh fix macos
# Interim for /etc/ssl/cert.pem: rewrite it without the two roots, keeping a backup. A macOS update may restore the original; re-run the check afterwards.
sudo cp /etc/ssl/cert.pem /etc/ssl/cert.pem.bak-emudhra
tmp=$(mktemp)
while openssl x509 2>/dev/null > "$tmp.one"; do
  fp=$(openssl x509 -noout -fingerprint -sha256 -in "$tmp.one" | tr -d ':' | sed 's/.*=//')
  case "$fp" in
    D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4|86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B) echo "dropping $fp" ;;
    *) cat "$tmp.one" >> "$tmp" ;;
  esac
done < /etc/ssl/cert.pem.bak-emudhra
grep -c 'BEGIN CERTIFICATE' /etc/ssl/cert.pem.bak-emudhra "$tmp"
sudo cp "$tmp" /etc/ssl/cert.pem
rm -f "$tmp" "$tmp.one"
```

Expected: two `dropping` lines and a marker count two lower than the backup.
If the counts differ by anything other than two, restore the backup. The
keychain roots are managed by Apple; do not delete them. Marking them
untrusted in Keychain Access (System Roots, Trust, Never Trust) is possible for
the ECC root; doing it for AAA breaks legitimate sites.

## Windows

Windows receives the block through the automatic disallowed certificate list;
a machine that is online with automatic root updates enabled needs no manual
step, and block 7 in advisory.md shows the sync time. For a machine that cannot
receive the update, the reference site publishes a PowerShell script,
Block-EmudhraCompromisedCA.ps1, that adds the compromised certificates to
`LocalMachine\Disallowed`. The site says it "is not recommended for
enterprise-managed devices". The agent does not fetch or run that script: the
user downloads it from emudhra.we-have-a-problem.com, reads it (it should only
import certificate data into the Disallowed store), and runs it in an
elevated PowerShell. If their execution policy blocks it, they run it with a
one-time unblock of that file (`Unblock-File`) rather than bypassing the policy
for the whole session. Re-run block 7 afterwards: the thirteen compromised
fingerprints should MATCH in `Cert:\LocalMachine\Disallowed`.

Applications that ship their own store get their fixed versions:

```powershell fix windows
# Durable: the application floors from advisory.json (winget ids; skip any that is not installed).
winget upgrade --id Git.Git
winget upgrade --id Docker.DockerDesktop
winget upgrade --id Microsoft.VisualStudioCode
winget upgrade --id OpenJS.NodeJS
winget upgrade --id OpenJS.NodeJS.LTS
winget upgrade --id Python.Python.3.13
winget upgrade --id Obsidian.Obsidian
winget upgrade --id Anthropic.ClaudeCode
```

## FreeBSD

```sh fix freebsd
# Durable: ca_root_nss 1.131.1 from ports, and the base caroot via the release patch level (15.1-p6, 14.5-p3, 14.4-p12).
sudo pkg upgrade ca_root_nss
sudo freebsd-update fetch install
freebsd-version -ku
```

```sh fix freebsd
# Interim from the reference site: move the two roots to the untrusted set and rebuild the hashes.
sudo cp /etc/ssl/certs/14bc7599.0 /usr/share/certs/untrusted/14bc7599.pem
sudo cp /etc/ssl/certs/ee64a828.0 /usr/share/certs/untrusted/ee64a828.pem
sudo certctl rehash
certctl untrusted
```

## NetBSD

```sh fix netbsd
sudo certctl untrust /usr/share/certs/mozilla/all/emSign_ECC_Root_CA_-_G3.pem
sudo certctl untrust /usr/share/certs/mozilla/all/Comodo_AAA_Services_root.pem
sudo certctl rehash
certctl list
```

## OpenBSD

Upgrade to current, 8.0 or 7.9 with the published errata (`syspatch`); the
base cert.pem is rebuilt by the patch.

## Android

No command applies. On the device: Settings, search "Trusted credentials",
System tab, and disable emSign ECC Root CA - G3 and, if the user accepts broken
sites, AAA Certificate Services. Devices with current Play services received
the block automatically; vendors that do not allow disabling system roots
(HarmonyOS) offer no user fix.

## Python certifi, pip, uv, conda, pixi

Every copy block 3 found is its own fix. certifi 2026.10.19 is fixed; pip
26.2.2 vendors a fixed copy; uv 0.13.5, conda 26.9.4 and pixi 0.82.1 ship their
own fixed bundles.

```sh fix any
# For each interpreter or virtualenv from block 3 (replace python3 with the interpreter path):
python3 -m pip install --upgrade 'certifi>=2026.10.19' 'pip>=26.2.2'
python3 -c 'import certifi; print(certifi.__version__, certifi.where())'
# uv-managed environments and the uv cache:
uv self update
uv cache clean certifi
uv pip install --upgrade 'certifi>=2026.10.19'
# conda and pixi:
conda update -n base conda
conda update --all certifi
pixi self-update
```

On Debian and Ubuntu the system interpreter resolves the system bundle, so the
fix for it is the ca-certificates upgrade above; the dist-packages certifi file
is fixed by the `python3-certifi` package or left alone if nothing resolves it.

## Node.js, Bun, Deno

```sh fix any
# Durable: the fixed release for the major in use (26.12.1, 24.22.1, 22.23.4). One of these, depending on how Node was installed:
nvm install 24.22.1
fnm install 24.22.1
volta install node@24.22.1
mise use -g node@24.22.1
sudo apt-get install --only-upgrade nodejs
brew upgrade node
bun upgrade
deno upgrade
node --version
```

Interim for a Node that cannot be upgraded: run it with
`NODE_OPTIONS=--use-system-ca` (Node 23.10 and later) or `--use-openssl-ca` so
it reads the fixed system bundle instead of its compiled-in store.

## Java

```sh fix any
# Durable: a JDK at or above its floor (27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511). Distribution packages:
sudo apt-get install --only-upgrade openjdk-21-jre-headless openjdk-17-jre-headless
sudo dnf upgrade java-21-openjdk-headless java-17-openjdk-headless
```

```sh fix any
# Interim for a JDK that stays below the floor: add the thirteen compromised fingerprints to its distrust list, then restart Java services. JH is the path block 4 printed.
JH=/usr/lib/jvm/java-17-openjdk-amd64
sudo cp "$JH/lib/security/blocked.certs" "$JH/lib/security/blocked.certs.bak-emudhra"
printf '%s\n' 42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493 45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE 5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699 98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B 579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512 E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838 0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19 62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72 7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489 CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F 432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3 FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F 9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4 A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8 4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1 84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD 3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD | sudo tee -a "$JH/lib/security/blocked.certs" >/dev/null
tail -n 3 "$JH/lib/security/blocked.certs"
```

The file already starts with `Algorithm: SHA-256`; the appended lines are read
on the next JVM start. Verify with block 4, which prints a `BLOCKED` line per
fingerprint. Distribution JDK upgrades replace the file, which is fine once the
upgrade carries the entries.

## Everything else by version

Upgrade to the floors in advisory.json: Go 1.27.3 or 1.26.10 and rebuild Go
binaries that use the fallback roots; rustls-webpki 0.103.16 and webpki-roots
1.0.10 and rebuild Rust binaries; Electron 44.9.1, 43.8.1 or 42.11.16 and
rebuild Electron apps; Claude Code 2.1.303; Docker Desktop 4.96.2; Git for
Windows 2.56.0.3; mise 2026.10.17; Obsidian 1.14.5; rustup 1.29.2; VS Code
1.143.1; ArgoCD 3.3.18, 3.4.12, 3.5.6 or 3.6.0-rc4; curl's extracted cacert.pem
dated 2026-10-20 or later; NSS 3.131.1; Mozilla::CA 20261020; Composer
ca-bundle 1.4.16 or 1.6.0; Erlang certifi 2.18.0; Elixir castore 1.0.22;
CFSSL 2026.10.1. Bottlerocket, RHEL 7 and Godot had no fixed version on
2026-10-23.
