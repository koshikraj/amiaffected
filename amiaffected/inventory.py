"""Collect facts about this host from an allowlist of known locations.

Everything stays local. Facts are paths, types and versions; gaps are
first-class and are consumed by the matcher. The collector never elevates
and never walks the whole disk: it looks at known locations plus the scan
roots the user passed in, to a bounded depth.

The collector never executes anything. It records paths; the readers in
`pem` decide, against their own allowlists, which of those may be read by
running a runtime (keytool, node).
"""
import datetime as _dt
import glob
import os
import platform
import shutil
import site
import socket
import sysconfig

from . import __version__
from . import pem

INVENTORY_VERSION = "0.1"
SCAN_DEPTH = 6

SYSTEM_PEM_CANDIDATES = (
    "/etc/ssl/certs/ca-certificates.crt",            # Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",              # RHEL, Fedora
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/ca-bundle.pem",                        # SUSE
    "/etc/ssl/cert.pem",                             # BSD, macOS (OpenSSL)
)
ENV_PEM_VARS = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")
JAVA_GLOBS = ("/usr/lib/jvm/*/lib/security/cacerts", "/usr/lib/jvm/*/jre/lib/security/cacerts",
              "/opt/java/*/lib/security/cacerts", "/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts")
NSS_GLOBS = ("~/.pki/nssdb/cert9.db", "~/.mozilla/firefox/*/cert9.db",
             "~/snap/firefox/common/.mozilla/firefox/*/cert9.db")


def _now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def _os_facts():
    facts = {"system": platform.system(), "release": platform.release(), "machine": platform.machine()}
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    if k in ("ID", "VERSION_ID", "PRETTY_NAME"):
                        facts[k.lower()] = v.strip('"')
    except OSError:
        pass
    return facts


class Collector:
    def __init__(self, scan_roots=(), include_node=True, include_java=True, include_certifi=True):
        self.scan_roots = [os.path.abspath(os.path.expanduser(p)) for p in scan_roots]
        self.include_node = include_node
        self.include_java = include_java
        self.include_certifi = include_certifi
        self.stores = []
        self.gaps = []
        self._seen = set()

    def gap(self, what, why):
        self.gaps.append({"what": what, "why": why})

    def store(self, kind, store_type, path, readable=None):
        path = os.path.abspath(path) if store_type != "node_bundled" else path
        key = (store_type, os.path.realpath(path) if store_type != "node_bundled" else path)
        if key in self._seen:
            return
        self._seen.add(key)
        if readable is None:
            readable = os.access(path, os.R_OK)
        self.stores.append({
            "id": "%s:%s" % (kind, path),
            "kind": kind,
            "type": store_type,
            "path": path,
            "readable": bool(readable),
        })
        if not readable:
            self.gap("trust store %s" % path, "not readable by this user")

    # --- enumerators -----------------------------------------------------
    def system_pem(self):
        found = [p for p in SYSTEM_PEM_CANDIDATES if os.path.isfile(p)]
        for p in found:
            self.store("system", "pem_bundle", p)
        if not found:
            self.gap("system trust store", "no PEM bundle at any known location")

    def env_pem(self):
        for var in ENV_PEM_VARS:
            val = os.environ.get(var)
            if val:
                if os.path.isfile(val):
                    self.store("env:%s" % var, "pem_bundle", val)
                else:
                    self.gap("%s=%s" % (var, val), "points at a missing file")

    def java(self):
        if not self.include_java:
            self.gap("java keystores", "excluded by caller")
            return
        paths = []
        jh = os.environ.get("JAVA_HOME")
        if jh:
            paths.append(os.path.join(jh, "lib", "security", "cacerts"))
        for pat in JAVA_GLOBS:
            paths.extend(glob.glob(pat))
        for p in paths:
            if os.path.isfile(p):
                self.store("java", "java_keystore", p)
        # keytool is never taken from PATH: the reader runs the keytool that
        # belongs to the JVM owning each cacerts, and only at allowlisted
        # JVM locations. Nothing to record here beyond the files.

    def _site_dirs(self):
        dirs = []
        try:
            dirs.extend(site.getsitepackages())
        except AttributeError:  # some embedded interpreters
            pass
        try:
            dirs.append(site.getusersitepackages())
        except AttributeError:
            pass
        dirs.append(sysconfig.get_paths().get("purelib"))
        return [d for d in dict.fromkeys(dirs) if d]

    def certifi(self):
        if not self.include_certifi:
            self.gap("certifi bundles", "excluded by caller")
            return
        # The running interpreter's certifi, found on disk. We do not import
        # certifi: importing executes the package we are about to judge.
        for d in self._site_dirs():
            candidate = os.path.join(d, "certifi", "cacert.pem")
            if os.path.isfile(candidate):
                self.store("certifi:interpreter", "pem_bundle", candidate)
        for root in self.scan_roots:
            if not os.path.isdir(root):
                self.gap("scan root %s" % root, "not a directory")
                continue
            base_depth = root.rstrip(os.sep).count(os.sep)
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                if dirpath.count(os.sep) - base_depth >= SCAN_DEPTH:
                    dirnames[:] = []
                    continue
                if os.path.basename(dirpath) == "certifi" and "cacert.pem" in filenames:
                    self.store("certifi:%s" % root, "pem_bundle", os.path.join(dirpath, "cacert.pem"))

    def node(self):
        if not self.include_node:
            self.gap("node bundled store", "excluded by caller")
            return
        found = [p for p in pem.allowed_node_paths() if os.path.isfile(p)]
        for p in found:
            self.store("node", "node_bundled", p, readable=True)
        on_path = shutil.which("node")
        if on_path and os.path.abspath(on_path) not in found and os.path.realpath(on_path) not in map(os.path.realpath, found):
            self.gap("node at %s" % on_path,
                     "found on PATH but not an allowlisted executable; pass --node-bin %s to inspect it" % on_path)
        extra = os.environ.get("NODE_EXTRA_CA_CERTS")
        if extra and os.path.isfile(extra):
            self.store("node:extra", "pem_bundle", extra)

    def nss(self):
        for pat in NSS_GLOBS:
            for p in glob.glob(os.path.expanduser(pat)):
                self.store("nss", "nss", p)
        self.gap("NSS databases (Firefox, Chrome on Linux)", "store type not readable in v0; reported as unknown")

    def containers(self):
        self.gap("container images", "not enumerated in v0; run the check inside each container instead")

    def collect(self):
        for step in (self.system_pem, self.env_pem, self.java, self.certifi, self.node, self.nss, self.containers):
            try:
                step()
            except Exception as exc:  # a broken enumerator is a gap, not a crash
                self.gap(step.__name__, "%s: %s" % (exc.__class__.__name__, exc))
        return {
            "inventory_version": INVENTORY_VERSION,
            "collected_at": _now(),
            "collector": {"name": "amiaffected", "version": __version__},
            "target": {"id": socket.gethostname(), "kind": "host", "os": _os_facts()},
            "scope": {"scan_roots": self.scan_roots,
                      "enumerators": ["system_pem", "env_pem", "java", "certifi", "node", "nss"]},
            "facts": {"trust_stores": self.stores},
            "gaps": self.gaps,
        }


def collect(**kwargs):
    return Collector(**kwargs).collect()
