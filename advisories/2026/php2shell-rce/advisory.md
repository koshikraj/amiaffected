# AIA-2026-0002: PHP2Shell, unauthenticated RCE in every PHP web SAPI

Rules: before anything runs, ask the user once for the whole batch below. Every
check block is read-only: no sudo, no network, no writes, no installs, no
restarts. Report per coverage item with the quoted output line that decided
it. A host is never "clean": the verdicts are affected, not_affected and
unknown, and empty output, exit 1, a missing tool or a permission error is a
gap, not a negative.

Severity: critical. Revision 1, published 2026-10-23, review by 2026-11-23.
Sources: php.net announcement of 21 October 2026, GHSA-w8hw-w9fx-j79w and
GHSA-6wmf-4rv5-p3rp, php2shell.com (Wiz Research, OpenAI Codex Security,
Calif), watchTowr Labs, and the Debian, Ubuntu, AlmaLinux, Alpine, Arch,
Homebrew, FreeBSD and docker-library package pages (all retrieved
2026-10-23).

The commands were exercised on Ubuntu 24.04 on 2026-10-23, on a laptop with no
PHP installed, so the quoted output is the "nothing found" case. Output for a
host that has PHP is described from the package pages and the vendor advisory,
not quoted. macOS, Windows and BSD are written from documentation.

## What happened

Two memory-safety bugs in the PHP engine were fixed on 21 October 2026 in PHP
8.5.12, 8.4.27, 8.3.36 and 8.2.35, a day after the details leaked on social
media and before the planned disclosure. CVE-2026-109618 is in the
out-of-memory path: a request can drive the engine out of memory at a point
where the bailout corrupts the heap. CVE-2026-109619 is in request cleanup: a
global pointer survives into the next request, so a worker that served an
attacker's request serves the next one with a dangling reference. Together
they give unauthenticated remote code execution with no application code
involved; Apache mod_php is exploitable before the first line of the site runs,
PHP-FPM, php-cgi and LiteSpeed are exposed by source analysis, FrankenPHP
likely for the first bug. The finders named the pair PHP2Shell. Exploitation in
the wild was seen from 21 October. CVSS 4.0 is 9.2.

Every PHP since 5.4 carries the bugs. PHP 8.1 and older are end of life and got
no release: php.net published minimal source patches for 7.4, 8.0 and 8.1 and
the distributions backported from those, usually without changing the version
number that `php -v` prints. PHP 8.2 itself reaches end of life on
31 December 2026. The mitigations php.net lists (memory_limit=-1, small
post_max_size, session.upload_progress.enabled=0, fatal_error_backtraces=0 on
8.5, pm.max_requests=1 on FPM) reduce exploitability and close nothing.

## Who is affected

Any host, container image or appliance that runs a PHP interpreter below the
floor and accepts HTTP requests through it. That is every PHP web server,
every control panel, most hosting stacks, and the developer laptop with a
local PHP stack listening on a port. A CLI-only PHP that serves nothing is
present but not exposed; it is still reported, because the package that
provides it also provides the web SAPIs. See applicability and coverage in
advisory.json. Container images, VMs and remote hosts have their own
interpreters; they are a gap unless the same checks run inside them.

The comparator matters more here than in most advisories. Debian, Ubuntu,
RHEL and their derivatives backport the fix and keep the upstream number: a
fixed Ubuntu 24.04 still prints `PHP 8.3.6`. For those, only the package
version decides, against the floor for that distribution in advisory.json.
`php -v` is the comparator only for interpreters built from php.net sources:
Homebrew, Arch, Alpine, FreeBSD ports, Remi, Sury, the official Docker image,
XAMPP, Herd and self-built.

## Checks

Run the blocks in one shell session on Linux, macOS or BSD. Windows uses block
7 instead. Each block ends with a `-- block N done` line; a block that stops
before it is a gap for the items it did not reach. Blocks 0 to 4 are required.
Block 5 (mitigations) is read only when a package is below its floor, and
block 6 (logs) is optional; both qualify a finding and never produce
not_affected.

### 0. Platform and packages (required: system-php)

```sh check
# 0. Platform, then every PHP package the package manager knows about. "no packages found" is the no-PHP case, not an error.
uname -srm
cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION_ID)='
command -v sw_vers >/dev/null 2>&1 && sw_vers
command -v freebsd-version >/dev/null 2>&1 && freebsd-version -ku
command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Package} ${Version} ${Status}\n' 'php*' 'libapache2-mod-php*' 2>&1
command -v rpm >/dev/null 2>&1 && rpm -qa 'php*' 2>&1 | sort
command -v dnf >/dev/null 2>&1 && dnf -C -q module list --enabled php 2>&1
command -v apk >/dev/null 2>&1 && apk info -v 2>/dev/null | grep -E '^php[0-9]'
command -v pacman >/dev/null 2>&1 && pacman -Q php php-legacy php-fpm php-apache 2>&1
command -v brew >/dev/null 2>&1 && brew list --versions php php@8.4 php@8.3 php@8.2 php@8.1 2>&1
command -v pkg >/dev/null 2>&1 && pkg info 'php8*' 2>&1
echo "-- block 0 done"
```

Exercised output on Ubuntu 24.04, 2026-10-23:

```text
Linux 7.0.0-38-generic x86_64
PRETTY_NAME="Ubuntu 24.04.5 LTS"
VERSION_ID="24.04"
dpkg-query: no packages found matching php*
dpkg-query: no packages found matching libapache2-mod-php*
-- block 0 done
```

Reading: dpkg knows no PHP package. That settles the system-php item for this
host only together with block 1 (a binary the package manager did not install
is still a binary). On a host with PHP, Ubuntu 24.04 prints for example
`php8.3-common 8.3.6-0ubuntu0.24.04.13 install ok installed`: compare the
version with the floor-php-ubuntu entry for 24.04 using the package manager's
own comparator, for example
`dpkg --compare-versions "$(dpkg-query -W -f='${Version}' php8.3-common)" ge 8.3.6-0ubuntu0.24.04.13 && echo at-or-above || echo below`.
At or above is a fixed package on disk; below is affected. On EL, read
`php-common` (or `php8.4-common` on EL 10) against floor-php-el for that
release and stream; the module build id after the plus sign differs per
vendor, the release before it is what matters. On Alpine, Arch, Homebrew and
FreeBSD the version carries the upstream number and is compared with
floor-php-upstream for its branch. A package on a branch with no entry in any
floor (PHP 8.1 on a distribution that has not backported, 7.3 or older
anywhere else) is affected with no package fix available.

### 1. Every interpreter binary and module on disk (required: every-binary)

```sh check
# 1. Known interpreter locations, including control panels and version managers. Only binaries at these listed paths are executed, with -v.
for b in /usr/bin/php /usr/bin/php[0-9]* /usr/bin/php-cgi* /usr/sbin/php-fpm* /usr/lib/cgi-bin/php* /usr/local/bin/php /usr/local/sbin/php-fpm /usr/local/bin/frankenphp /opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm /opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm /opt/cpanel/ea-php*/root/usr/bin/php /usr/local/lsws/lsphp*/bin/lsphp /opt/homebrew/opt/php*/bin/php /opt/homebrew/opt/php*/sbin/php-fpm /usr/local/opt/php*/bin/php "$HOME"/.phpenv/versions/*/bin/php "$HOME"/.phpbrew/php/*/bin/php "$HOME"/.asdf/installs/php/*/bin/php "$HOME"/.local/share/mise/installs/php/*/bin/php "$HOME"/Library/Application\ Support/Herd/bin/php* /Applications/XAMPP/xamppfiles/bin/php /Applications/MAMP/bin/php/php*/bin/php; do
  [ -x "$b" ] || continue
  echo "== $b resolves to $(readlink -f "$b" 2>/dev/null)"
  case "$b" in
    *frankenphp) "$b" version 2>&1 | head -n 1 ;;
    *) "$b" -v 2>&1 | head -n 1 ;;
  esac
done
# Apache modules. The file name carries the branch; the package that owns it carries the version.
ls -l /usr/lib/apache2/modules/libphp*.so /etc/httpd/modules/libphp*.so /usr/lib/httpd/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/local/lib/apache2/modules/libphp*.so /opt/homebrew/opt/php*/lib/httpd/modules/libphp.so 2>/dev/null
command -v dpkg >/dev/null 2>&1 && dpkg -S /usr/lib/apache2/modules/libphp*.so 2>&1 | grep -v 'not found'
command -v rpm >/dev/null 2>&1 && rpm -qf /etc/httpd/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so 2>&1 | grep -v 'No such'
# Anything else named php on PATH that the loop above did not cover.
command -v php php-fpm php-cgi frankenphp lsphp 2>/dev/null
echo "-- block 1 done"
```

Exercised output on Ubuntu 24.04, 2026-10-23:

```text
-- block 1 done
```

Reading: no interpreter at any listed path, no Apache module, nothing named
php on PATH. With block 0 this makes system-php and every-binary not_affected
for this host: there is no PHP. On a host with PHP each binary prints a line
such as `== /usr/bin/php resolves to /usr/bin/php8.3` followed by
`PHP 8.3.6 (cli) (built: Sep 30 2026 10:12:33) (NTS)`. The number after `PHP`
is the upstream branch and patch. For a distribution package it is reported
but not compared; the package version from block 0 is. For an upstream build
(the path is under /opt/remi, /opt/homebrew, /usr/local, a version manager,
XAMPP, MAMP or Herd, or `php -v` prints a number no distribution package
explains) compare it with floor-php-upstream: `8.3.36` or higher is fixed,
`8.3.35` or lower is affected, and `8.1.x`, `8.0.x`, `7.x` and `5.x` are
affected with no release. A binary that exists but prints nothing, or prints
a loader error, is a gap for that path.

### 2. Which SAPIs serve requests (required: web-sapi)

```sh check
# 2. Apache modules, FPM pools and services, listening sockets and processes. This decides exposure, not vulnerability.
command -v apache2ctl >/dev/null 2>&1 && apache2ctl -M 2>&1 | grep -Ei 'php|mpm'
command -v httpd >/dev/null 2>&1 && httpd -M 2>&1 | grep -Ei 'php|mpm'
ls /etc/apache2/mods-enabled/ 2>/dev/null | grep -i php
ls /etc/httpd/conf.modules.d/ 2>/dev/null | grep -i php
ls /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /etc/php8*/php-fpm.d/*.conf /usr/local/etc/php-fpm.d/*.conf /opt/homebrew/etc/php/*/php-fpm.d/*.conf 2>/dev/null
command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --all --no-pager --plain 2>&1 | grep -Ei 'php|apache2|httpd|nginx|lsws|frankenphp|caddy'
command -v brew >/dev/null 2>&1 && brew services list 2>&1 | grep -Ei 'php|httpd|nginx'
ps -eo pid,user,lstart,comm 2>/dev/null | grep -Ei 'php|apache2|httpd|frankenphp|lsphp'
ss -ltnp 2>/dev/null | grep -Ei 'php|apache2|httpd|nginx|frankenphp|lsphp|caddy'
ls -l /run/php/*.sock /var/run/php-fpm/*.sock /run/php-fpm/*.sock 2>/dev/null
grep -rlE 'fastcgi_pass|\.php' /etc/nginx/ 2>/dev/null | head -n 20
echo "-- block 2 done"
```

Exercised output on Ubuntu 24.04, 2026-10-23:

```text
-- block 2 done
```

Reading: nothing serves PHP on this host. On a host that does, the lines
decide the exposure of whatever block 0 and 1 found: `php_module (shared)`
from `apache2ctl -M` or `httpd -M` is mod_php, the SAPI both GHSAs confirm as
exploitable before any application code runs; `php8.3-fpm.service loaded
active running`, a `php-fpm: master process` line from ps, or an `*.sock`
under /run/php is PHP-FPM; `php-cgi` in ps or a `fastcgi_pass` to port 9000
is php-cgi or FPM behind nginx; `frankenphp` or `lsphp` in ps is FrankenPHP
or LiteSpeed. A vulnerable package with none of these is present_unused: the
report says the package is below the floor and nothing serves it, and the
verdict for the host is affected by version with the exposure noted as none
seen. `ss -ltnp` without root shows process names only for the user's own
processes; a listening port without a name is a gap for the process behind
it, not a negative.

### 3. Running workers versus the package on disk (required: running-workers)

```sh check
# 3. A worker started before the fixed package landed runs the old code. Compare process start times with the package or binary times.
date
command -v uptime >/dev/null 2>&1 && uptime -s 2>/dev/null
ps -eo pid,user,lstart,etimes,comm 2>/dev/null | grep -Ei 'php-fpm|php-cgi|apache2|httpd|frankenphp|lsphp'
ls -l /var/lib/dpkg/info/php*-common.list /var/lib/dpkg/info/libapache2-mod-php*.list 2>/dev/null
command -v rpm >/dev/null 2>&1 && rpm -q --last php-common php8.4-common 2>&1 | grep -v 'not installed'
ls -l /usr/bin/php[0-9]* /usr/sbin/php-fpm* /usr/lib/apache2/modules/libphp*.so /usr/lib64/httpd/modules/libphp*.so /usr/local/bin/php /usr/local/sbin/php-fpm /usr/local/bin/frankenphp 2>/dev/null
echo "-- block 3 done"
```

Exercised output on Ubuntu 24.04, 2026-10-23:

```text
Thu Oct 23 09:19:35 PM IST 2026
2026-10-23 10:02:42
-- block 3 done
```

Reading: no worker, nothing to compare. On a host with PHP, each ps line
carries the start time; the `.list` file or `rpm -q --last` line carries the
time the fixed package was installed, and the binary's `ls -l` time is a
fallback. A worker (php-fpm master, apache2 or httpd parent, frankenphp,
lsphp) whose start time is earlier than the install time of a package that
is at or above its floor is still running vulnerable code: the finding is
affected for running-workers with both quoted times, and the fix is the
restart in fix.md, not another upgrade. Where ps or the install time is
unreadable the item is a gap.

### 4. Container images and project Dockerfiles (required: container-images)

```sh check
# 4. Images that bundle PHP. The official image records the upstream version in PHP_VERSION; a floating tag alone decides nothing.
for e in docker podman; do
  command -v "$e" >/dev/null 2>&1 || continue
  echo "== $e images"
  "$e" images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.CreatedAt}}' 2>&1 | grep -Ei 'php|wordpress|nextcloud|drupal|phpmyadmin|matomo|mediawiki|moodle|laravel|symfony|magento|prestashop|joomla|typo3|craftcms|<none>'
  for i in $("$e" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -Ei 'php|wordpress|nextcloud|drupal|phpmyadmin|matomo|mediawiki|moodle|laravel|symfony|magento|prestashop|joomla|typo3|craftcms'); do
    echo "-- $i"
    "$e" image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$i" 2>&1 | grep -E '^PHP_VERSION='
  done
  echo "== $e running"
  "$e" ps --format '{{.Names}} {{.Image}} {{.Status}}' 2>&1
done
# Dockerfiles in the user's own projects, four levels under $HOME, up to fifty.
find "$HOME" -maxdepth 4 -name 'Dockerfile*' -not -path '*/node_modules/*' 2>/dev/null | head -n 50 | while read -r f; do grep -HE '^FROM .*php' "$f" 2>/dev/null; done
echo "-- block 4 done"
```

Exercised output on Ubuntu 24.04, 2026-10-23:

```text
== docker images
== docker running
-- block 4 done
```

Reading: docker is installed, lists no image that names PHP or a PHP
application, and runs no container; no project Dockerfile starts from a PHP
image. That makes container-images not_affected here. The one image on this
laptop (a Go MCP server) was listed by the full `docker images` and is outside
the match, which is the correct reading only because its name and purpose are
known; an unfamiliar image that does not match the pattern is a gap, listed
by name. On a host with PHP images, each `-- image` line is followed by
`PHP_VERSION=8.4.27` for the official image and the images built on it;
compare it with floor-php-upstream for its branch. An image without a
PHP_VERSION line (a distribution-based image that installed PHP with apt or
dnf, or a private image) is a gap until block 0 and 1 run inside it as their
own batch. `permission denied while trying to connect to the Docker daemon` is
a gap for every image on the host. A running container from an image below
the floor is affected regardless of what the host's packages say.

### 5. Mitigations in place (optional: mitigations; read when a package is below its floor)

```sh check
# 5. The php.net mitigations. They qualify an affected finding and never produce not_affected.
grep -HEn '^(memory_limit|post_max_size|upload_max_filesize|session.upload_progress.enabled|fatal_error_backtraces)' /etc/php/*/fpm/php.ini /etc/php/*/apache2/php.ini /etc/php/*/cgi/php.ini /etc/php.ini /etc/php8*/php.ini /usr/local/etc/php/php.ini /opt/homebrew/etc/php/*/php.ini 2>/dev/null
grep -HEn '^(pm.max_requests|php_admin_value|php_value|php_admin_flag|php_flag|listen)' /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf /etc/php8*/php-fpm.d/*.conf /usr/local/etc/php-fpm.d/*.conf /opt/homebrew/etc/php/*/php-fpm.d/*.conf 2>/dev/null
grep -rHEn 'php_admin_value|php_admin_flag|php_value|php_flag' /etc/apache2/ /etc/httpd/ 2>/dev/null | head -n 30
for f in /etc/php/*/fpm/conf.d /etc/php-fpm.d /etc/php.d /etc/php8*/conf.d /usr/local/etc/php/conf.d; do [ -d "$f" ] && grep -HEn '^(memory_limit|post_max_size|upload_max_filesize|session.upload_progress.enabled|fatal_error_backtraces)' "$f"/*.ini 2>/dev/null; done
echo "-- block 5 done"
```

Exercised output on Ubuntu 24.04, 2026-10-23: only `-- block 5 done`, since
no php.ini exists. On a host below the floor, the lines are read against the
mitigation-ini indicator: `memory_limit = -1` set as `php_admin_value` in a
pool or server config counts, `memory_limit = -1` in php.ini alone counts,
`ini_set` in application code and `.user.ini` do not; `post_max_size = 8M`
(or 32M with `upload_max_filesize` below it) counts; `session.upload_progress.enabled = 0`
counts only from php.ini, the pool or the server config; `pm.max_requests = 1`
in a pool counts for that pool; `fatal_error_backtraces = 0` counts on 8.5
only. The report lists which are in place and which are not, and the
verdict stays affected: php.net describes every one of these as reducing
exploitability, not closing the bugs.

### 6. Logs: exploitation attempts (optional: logs)

```sh check
# 6. Published indicators, counted per readable log. A match raises the finding to possibly compromised. No match establishes nothing.
for f in /var/log/apache2/error.log /var/log/apache2/error.log.1 /var/log/httpd/error_log /var/log/nginx/error.log /var/log/nginx/error.log.1 /var/log/php8.5-fpm.log /var/log/php8.4-fpm.log /var/log/php8.3-fpm.log /var/log/php8.2-fpm.log /var/log/php8.1-fpm.log /var/log/php7.4-fpm.log /var/log/php-fpm/error.log /var/log/php-fpm/www-error.log /var/log/php_errors.log /usr/local/var/log/php-fpm.log /opt/homebrew/var/log/php-fpm.log; do
  [ -e "$f" ] || continue
  if [ -r "$f" ]; then
    echo "$f: oom $(grep -cE 'Allowed memory size of 16777216 bytes exhausted' "$f"), segv $(grep -cE 'exit signal Segmentation fault|exited on signal 11|SIGSEGV' "$f"), line0 $(grep -cE 'Unknown on line 0' "$f")"
  else
    echo "$f: unreadable (permission)"
  fi
done
command -v journalctl >/dev/null 2>&1 && echo "journal since 2026-10-20: segv $(journalctl -q --no-pager --since 2026-10-20 2>/dev/null | grep -cE 'exit signal Segmentation fault|exited on signal 11|SIGSEGV.*php|php.*SIGSEGV')"
# Processes owned by the web user that are not the web server itself.
ps -eo user,pid,ppid,comm 2>/dev/null | grep -E '^(www-data|apache|nginx|http|_www|nobody)\b' | grep -Ev 'php-fpm|apache2|httpd|nginx|frankenphp|lsphp'
echo "-- block 6 done"
```

Exercised output on Ubuntu 24.04, 2026-10-23:

```text
journal since 2026-10-20: segv 0
-- block 6 done
```

Reading: no PHP or web server log exists, the journal has no segfault line
since the leak date, and no web-user process is running. That is not evidence
of anything beyond the sample. On a host with logs, `oom` counts the
out-of-memory trigger with the attacker's 16 MiB limit, `segv` counts
crashed workers, `line0` counts the `Unknown on line 0` signature; a nonzero
count in any of them, or a shell, perl, python or curl process owned by the
web user, is reported as a possible compromise with the quoted line, and the
user is told to treat the host as compromised until reviewed. `unreadable
(permission)` is a gap for that log; the agent does not retry with sudo.

### 7. Windows (described, not exercised)

```powershell check
# 7. Windows: php.exe on PATH and in the usual folders, IIS FastCGI handlers, Apache module lines, running workers.
Get-Command php.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
foreach ($p in @('C:\php\php.exe', 'C:\xampp\php\php.exe', 'C:\Program Files\PHP\php.exe', 'C:\tools\php\php.exe', 'C:\wamp64\bin\php')) {
  if (Test-Path $p) { Write-Output "== $p" }
}
Get-ChildItem -Path 'C:\laragon\bin\php', 'C:\wamp64\bin\php', 'C:\Program Files\PHP', 'C:\tools' -Filter php.exe -Recurse -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "== $($_.FullName)"; & $_.FullName -v 2>&1 | Select-Object -First 1 }
if (Test-Path "$env:windir\system32\inetsrv\appcmd.exe") { & "$env:windir\system32\inetsrv\appcmd.exe" list config -section:system.webServer/handlers 2>&1 | Select-String -Pattern 'php' }
Get-ChildItem -Path 'C:\Apache24\conf', 'C:\xampp\apache\conf' -Filter httpd.conf -ErrorAction SilentlyContinue | Select-String -Pattern 'LoadModule php'
Get-Process php-cgi, php, httpd, apache -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, StartTime
Write-Output "-- block 7 done"
```

Expected: one `== path` per interpreter found, each followed by its `PHP x.y.z`
line; windows.php.net builds, XAMPP, WampServer and Laragon carry upstream
numbers and compare with floor-php-upstream. An IIS handler line naming
`php-cgi.exe` or a `LoadModule php_module` line is a web SAPI; a
`php-cgi` or `httpd` process with a StartTime before the interpreter file's
write time is an old worker. No output from every line and no php.exe on PATH
is not_affected for this host only if the user confirms no other folder holds
a PHP; otherwise unknown.

## What cannot be checked from here

- Shared hosting, managed WordPress and PaaS: the interpreter is on the
  provider's host, and `phpinfo()` shows the upstream number that a backport
  does not change. Ask the provider for the package version and the restart
  time; treat the site as affected until answered.
- Appliances with an embedded PHP (NAS web UIs, firewalls, printers,
  management consoles): no shell, no package manager. Use the vendor's
  advisory for CVE-2026-109618 and CVE-2026-109619 and keep the interface off
  untrusted networks until it ships.
- Whether an attempt before the upgrade succeeded: block 6 finds the
  published proof-of-concept traces only. If any count is nonzero, or the
  host served PHP below the floor on an attacker-reachable port from
  20 October 2026 on, review for web shells, new cron entries and unexpected
  outbound connections, and rotate credentials the web user could read.
- Remote hosts, VMs and the inside of container images: run blocks 0 to 4
  inside each, as their own approved batch.

## Verdict rules for this advisory

- affected: any interpreter or package found by block 0 or 1 is below the
  floor for its origin (distribution package against its distribution floor,
  upstream build against floor-php-upstream), or on a branch with no fix; or
  a worker in block 3 started before the fixed package was installed; or a
  container image in block 4 carries a PHP_VERSION below its branch floor or
  a running container was started from one. Exposure from block 2 is
  reported next to it: mod_php or FPM or php-cgi serving is the worst case,
  nothing serving is present_unused, still affected by version.
- not_affected: every required item was read to its `done` line, every
  interpreter and package found is at or above its floor, every worker
  started after its package was installed, every image with a PHP_VERSION is
  at or above its floor and no image or Dockerfile is left unread, and the
  advisory is within review_by. A host with no PHP at all is not_affected
  when blocks 0, 1, 2 and 4 all found nothing, as exercised above. A single
  gap makes this unknown.
- unknown: anything else, including a declined batch, a package whose origin
  could not be established, a floating image tag with no PHP_VERSION read, or
  a daemon the user could not reach, with the gaps listed.
