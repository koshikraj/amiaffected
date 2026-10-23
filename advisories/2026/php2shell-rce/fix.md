# Fix: AIA-2026-0002 PHP2Shell, unauthenticated RCE in every PHP web SAPI

The fix is two steps, and the second is the one people skip: install a package
at or above the floor for your distribution (advisory.json, indicators
`floor-php-*`), then restart every process that loaded the old interpreter:
php-fpm, Apache with mod_php, php-cgi behind nginx or IIS, LiteSpeed,
FrankenPHP, and any long-running PHP worker (queue consumers, Octane,
RoadRunner, Swoole). A package upgrade alone leaves the running workers on the
old code; the Debian and Ubuntu packages restart their own php-fpm unit, and
nothing restarts Apache, nginx's upstream, or a custom service. Re-run the
checks in advisory.md after any fix; the fix is verified by the check (block 0
or 1 at the floor, block 3 with every worker started after the install), not by
the command exiting 0.

Every block below writes to the system or installs packages and is presented
to the user as its own step after the report. Nothing here fetches and runs
code.

## Debian and Ubuntu

Debian 12 (php 8.2), Debian 13 (php 8.4) and every Ubuntu release back to
14.04 ESM have a fixed package. The version `php -v` prints does not change.

```sh fix debian
sudo apt-get update
sudo apt-get install --only-upgrade 'php8.*' 'libapache2-mod-php8.*'
dpkg-query -W -f='${Package} ${Version}\n' 'php8*-common' 'libapache2-mod-php8*' 2>/dev/null
sudo systemctl restart 'php*-fpm.service' 2>/dev/null
sudo systemctl restart apache2 2>/dev/null
sudo systemctl restart nginx 2>/dev/null
```

```sh fix ubuntu
sudo apt-get update
sudo apt-get install --only-upgrade 'php*' 'libapache2-mod-php*'
dpkg-query -W -f='${Package} ${Version}\n' 'php*-common' 'libapache2-mod-php*' 2>/dev/null
sudo systemctl restart 'php*-fpm.service' 2>/dev/null
sudo systemctl restart apache2 2>/dev/null
sudo systemctl restart nginx 2>/dev/null
```

Ubuntu 20.04, 18.04, 16.04 and 14.04 get the fix only with Ubuntu Pro (ESM);
without it the package stays below the floor and the host stays affected.
Interpreters from the Sury repository (`deb.sury.org`, packages versioned like
`8.3.36-1+ubuntu24.04.1+deb.sury.org+1`) carry the upstream number; the same
apt commands update them and the floor is floor-php-upstream.

## RHEL, AlmaLinux, Rocky, Oracle Linux and CentOS Stream

Standard deployments on these use php-fpm with httpd, not mod_php, and the
php-fpm unit is not restarted by the package.

```sh fix rhel
sudo dnf upgrade --refresh 'php*'
rpm -q php-common php8.4-common 2>/dev/null
sudo systemctl restart php-fpm 2>/dev/null
sudo systemctl restart php84-php-fpm 2>/dev/null
sudo systemctl restart httpd 2>/dev/null
sudo systemctl restart nginx 2>/dev/null
```

Remi-repository streams (`php:remi-8.x` modules, `php8x-php-*` software
collections) carry upstream numbers and are compared with
floor-php-upstream; the dnf command above updates them too, and the service
is `php8x-php-fpm` for collections. CentOS 7 and EL 7 have no fixed package
and no supported path: the host is affected until the interpreter is
replaced.

## Fedora

```sh fix fedora
sudo dnf upgrade --refresh 'php*'
rpm -q php-common
sudo systemctl restart php-fpm 2>/dev/null
sudo systemctl restart httpd 2>/dev/null
sudo systemctl restart nginx 2>/dev/null
```

## Alpine

```sh fix alpine
sudo apk update
sudo apk upgrade 'php8*'
apk info -v 2>/dev/null | grep -E '^php8[0-9]-[0-9]|^php8[0-9]-fpm'
sudo rc-service php-fpm84 restart 2>/dev/null
sudo rc-service php-fpm83 restart 2>/dev/null
sudo rc-service php-fpm82 restart 2>/dev/null
sudo rc-service apache2 restart 2>/dev/null
sudo rc-service nginx restart 2>/dev/null
```

## Arch Linux

```sh fix arch
sudo pacman -Syu php php-fpm php-apache php-legacy php-legacy-fpm
pacman -Q php php-fpm php-apache php-legacy 2>/dev/null
sudo systemctl restart php-fpm 2>/dev/null
sudo systemctl restart php-legacy-fpm 2>/dev/null
sudo systemctl restart httpd 2>/dev/null
sudo systemctl restart nginx 2>/dev/null
```

## macOS with Homebrew

```sh fix macos
brew update
brew upgrade php php@8.4 php@8.3 php@8.2
brew list --versions php php@8.4 php@8.3 php@8.2
brew services restart php
brew services restart php@8.4
brew services restart php@8.3
brew services restart php@8.2
brew services restart httpd
brew services restart nginx
```

Herd, MAMP and XAMPP bundle their own interpreter: update the application
from its own updater to a build that prints 8.5.12, 8.4.27, 8.3.36 or 8.2.35
and restart it. Until the vendor ships, stop the bundled server.

## FreeBSD

```sh fix freebsd
sudo pkg update
sudo pkg upgrade 'php8*'
pkg info 'php8*'
sudo service php_fpm restart
sudo service php-fpm restart
sudo service apache24 restart
sudo service nginx restart
```

## Containers

Rebuild from a fixed base and redeploy; there is no in-place fix for an
image. The official `php` tags 8.5.12, 8.4.27, 8.3.36 and 8.2.35 are fixed for
every variant (cli, fpm, apache, zts on trixie, bookworm, alpine3.24 and
alpine3.23). A floating tag such as `php:8.4-apache` or `wordpress:latest`
only helps once it has been re-pulled and the container recreated; pin the
patch version in the Dockerfile and check `PHP_VERSION` in the built image
with block 4 of advisory.md. For distribution-based images, run the
distribution block from this file during the build and rebuild. Application
images (WordPress, Nextcloud, Drupal and the rest) need the upstream
project's rebuild on the fixed base; until that exists, build your own from
`php:<branch>-fpm` or put the mitigations below in the image and treat it as
still affected.

## Windows

Download the fixed build for your branch from the php.net Windows downloads
page, replace the installation folder (XAMPP, Laragon and WampServer ship
their own updates), then restart IIS (`iisreset`) or the Apache service.
Verify with block 7 of advisory.md: `php -v` prints the fixed number for
every interpreter and every php-cgi or httpd process started after the file
changed.

## PHP 8.1 and older

There is no upstream release. php.net published minimal patches for 7.4, 8.0
and 8.1 (source branches `PHP-8.1-CVE-2026-109618-109619` and the 8.0 and
7.4 equivalents); the distributions above backported them for the releases
listed in advisory.json. If you build from source or run 7.3 or older,
upgrade to a supported branch: there is no patch, and the mitigations below
do not close the bugs. PHP 8.2 itself reaches end of life on 31 December 2026.

## Mitigations while an upgrade is pending

php.net states that each of these reduces exploitability and that none
closes either bug; a host with all of them in place is still reported as
affected. Set them in php.ini, the FPM pool or the server configuration, not
with `ini_set` or `.user.ini`, which run too late or not at all for these
paths. Restart the SAPI after changing them.

- `memory_limit = -1`, as `php_admin_value[memory_limit] = -1` in every FPM
  pool or `php_admin_value memory_limit -1` in the Apache server config, so
  no request can set the attacker's limit. Only if the host can take it.
- `post_max_size = 8M` (or 32M with `upload_max_filesize` set below it).
- `session.upload_progress.enabled = 0`.
- `fatal_error_backtraces = 0` on PHP 8.5.
- `pm.max_requests = 1` in every FPM pool, so a worker never serves a second
  request after a poisoned one. Expensive and still partial.
- A cgroup memory limit on the SAPI and a restart of every worker.

If block 6 of advisory.md counted anything, or the host served PHP below the
floor on an attacker-reachable port from 20 October 2026 on, treat the host
as compromised: look for web shells and files the web user wrote recently,
new cron entries and systemd units, unexpected outbound connections, and
rotate every credential the web user could read. The upgrade does not remove
what an earlier attempt left behind.
