"""Trust store readers. Every reader returns the same shape and never raises:

    {"ok": bool, "store_type": str, "path": str, "count": int,
     "certs": [{"sha256": HEX}], "error": str | None}

Only certificate SHA-256 fingerprints leave this module. PEM bodies are
never included in evidence.

Execution policy. Two store types need an external runtime to print their
contents (Java keystores via keytool, Node's compiled-in store via node).
Inventory documents are untrusted input: a path found in an inventory
never selects an executable. The executables this module will run are

  * absolute paths in the allowlists below,
  * paths the user named on the command line (EXTRA_EXECUTABLES),
  * a JVM's own keytool, derived from a cacerts path that itself sits at an
    allowlisted JVM location (or under JAVA_HOME as set in this process).

Anything else is reported as an error, which the matcher turns into
`unknown`. Subprocesses get a minimal environment so NODE_OPTIONS,
JAVA_TOOL_OPTIONS and friends cannot inject code. Every executable that
actually ran is appended to EXECUTED so the result can list it.
"""
import base64
import binascii
import fnmatch
import hashlib
import os
import re
import subprocess

PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", re.S)
SUBPROCESS_TIMEOUT = 20
MINIMAL_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}

SUPPORTED_STORE_TYPES = ("pem_bundle", "java_keystore", "node_bundled")
UNSUPPORTED_STORE_TYPES = ("nss", "windows", "macos_keychain")

NODE_ALLOWLIST = (
    "/usr/bin/node",
    "/usr/local/bin/node",
    "/opt/homebrew/bin/node",
    "/snap/bin/node",
)
JAVA_HOME_GLOBS = (
    "/usr/lib/jvm/*",
    "/opt/java/*",
    "/Library/Java/JavaVirtualMachines/*/Contents/Home",
)
EXTRA_EXECUTABLES = set()   # absolute paths named on the command line
EXECUTED = []               # absolute paths actually executed in this process


def allowed_node_paths():
    return tuple(NODE_ALLOWLIST) + tuple(sorted(EXTRA_EXECUTABLES))


def _jvm_home_for(cacerts):
    for suffix in ("/jre/lib/security/cacerts", "/lib/security/cacerts"):
        if cacerts.endswith(suffix):
            return cacerts[: -len(suffix)]
    return None


def _jvm_home_allowed(home):
    if any(fnmatch.fnmatch(home, pat) for pat in JAVA_HOME_GLOBS):
        return True
    jh = os.environ.get("JAVA_HOME")
    return bool(jh) and os.path.abspath(jh) == home


def parse_pem_certs(text):
    """Return a list of DER blobs. Raises ValueError on an undecodable block."""
    ders = []
    for body in PEM_RE.findall(text):
        try:
            ders.append(base64.b64decode("".join(body.split()), validate=True))
        except (binascii.Error, ValueError) as exc:
            raise ValueError("PEM block does not decode: %s" % exc) from exc
    return ders


def sha256_hex(der):
    return hashlib.sha256(der).hexdigest().upper()


def _result(store_type, path, ok=False, ders=(), error=None):
    return {
        "ok": ok,
        "store_type": store_type,
        "path": path,
        "count": len(ders),
        "certs": [{"sha256": sha256_hex(d)} for d in ders],
        "error": error,
    }


def _from_text(store_type, path, text):
    try:
        ders = parse_pem_certs(text)
    except ValueError as exc:
        return _result(store_type, path, error=str(exc))
    if not ders:
        return _result(store_type, path, error="no certificates found")
    return _result(store_type, path, ok=True, ders=ders)


def read_pem_bundle(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return _result("pem_bundle", path, error="%s: %s" % (exc.__class__.__name__, exc.strerror or exc))
    return _from_text("pem_bundle", path, text)


def _run(cmd):
    """Run an already-authorised absolute executable with a minimal environment."""
    EXECUTED.append(cmd[0])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
                              check=False, env=dict(MINIMAL_ENV), cwd="/")
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "%s: %s" % (exc.__class__.__name__, exc)
    if proc.returncode != 0:
        first = (proc.stderr or proc.stdout or "").strip().splitlines()
        return None, "exit %d: %s" % (proc.returncode, first[0] if first else "no output")
    return proc.stdout, None


def read_java_keystore(path, storepass="changeit"):
    path = os.path.abspath(path)
    home = _jvm_home_for(path)
    if home is None or not _jvm_home_allowed(home):
        return _result("java_keystore", path,
                       error="cacerts is not at an allowlisted JVM location; not inspected")
    keytool = os.path.join(home, "bin", "keytool")
    if not os.path.isfile(keytool):
        return _result("java_keystore", path, error="no keytool at %s" % keytool)
    if not os.path.exists(path):
        return _result("java_keystore", path, error="FileNotFoundError: No such file or directory")
    out, err = _run([keytool, "-list", "-rfc", "-keystore", path, "-storepass", storepass])
    if err:
        return _result("java_keystore", path, error=err)
    return _from_text("java_keystore", path, out)


def read_node_bundled(node_path):
    """The store is compiled into the node binary; ask an allowlisted node to print it."""
    if not node_path or not os.path.isabs(node_path) or node_path not in allowed_node_paths():
        return _result("node_bundled", node_path,
                       error="node at %r is not an allowlisted executable; pass --node-bin to inspect it"
                             % (node_path,))
    if not os.path.isfile(node_path):
        return _result("node_bundled", node_path, error="node binary not found")
    out, err = _run([node_path, "-e", "process.stdout.write(require('tls').rootCertificates.join('\\n'))"])
    if err:
        return _result("node_bundled", node_path, error=err)
    return _from_text("node_bundled", node_path, out)


READERS = {
    "pem_bundle": read_pem_bundle,
    "java_keystore": read_java_keystore,
    "node_bundled": read_node_bundled,
}


def read_store(path, store_type):
    reader = READERS.get(store_type)
    if reader is None:
        return _result(store_type, path, error="store type %r unsupported in v0" % store_type)
    return reader(path)
