"""Trust store readers. Every reader returns the same shape and never raises:

    {"ok": bool, "store_type": str, "path": str, "count": int,
     "certs": [{"sha256": HEX}], "error": str | None}

Only certificate SHA-256 fingerprints leave this module. PEM bodies are
never included in evidence.
"""
import base64
import binascii
import hashlib
import os
import re
import shutil
import subprocess

PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", re.S)
SUBPROCESS_TIMEOUT = 20

SUPPORTED_STORE_TYPES = ("pem_bundle", "java_keystore", "node_bundled")
UNSUPPORTED_STORE_TYPES = ("nss", "windows", "macos_keychain")


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
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "%s: %s" % (exc.__class__.__name__, exc)
    if proc.returncode != 0:
        first = (proc.stderr or proc.stdout or "").strip().splitlines()
        return None, "exit %d: %s" % (proc.returncode, first[0] if first else "no output")
    return proc.stdout, None


def read_java_keystore(path, storepass="changeit"):
    keytool = shutil.which("keytool")
    if not keytool:
        return _result("java_keystore", path, error="keytool not found in PATH")
    if not os.path.exists(path):
        return _result("java_keystore", path, error="FileNotFoundError: No such file or directory")
    out, err = _run([keytool, "-list", "-rfc", "-keystore", path, "-storepass", storepass])
    if err:
        return _result("java_keystore", path, error=err)
    return _from_text("java_keystore", path, out)


def read_node_bundled(node_path):
    """The store is compiled into the node binary; ask node to print it."""
    if not node_path or not os.path.exists(node_path):
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
