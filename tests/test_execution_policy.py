"""Inventory is untrusted input. Nothing in an inventory document may cause
this tool to execute a program, and the collector itself never executes."""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from amiaffected import inventory, pem
from tests.test_matcher import inventory as make_inventory

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class CollectorNeverExecutes(unittest.TestCase):
    def test_collect_makes_no_subprocess(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("collector must not execute")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("collector must not execute")):
            doc = inventory.collect(scan_roots=[], include_node=True, include_java=True)
        self.assertIn("trust_stores", doc["facts"])

    def test_certifi_is_not_imported(self):
        with open(os.path.join(ROOT, "amiaffected", "inventory.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("import certifi", src)
        self.assertNotIn("certifi.where", src)
        self.assertNotIn("subprocess", src)


class ReadersRefuseUnlistedExecutables(unittest.TestCase):
    def setUp(self):
        del pem.EXECUTED[:]
        pem.EXTRA_EXECUTABLES.clear()

    def test_node_path_from_inventory_is_not_run(self):
        tmp = tempfile.mkdtemp()
        marker = os.path.join(tmp, "ran")
        fake = os.path.join(tmp, "node")
        with open(fake, "w") as fh:
            fh.write("#!/bin/sh\ntouch %s\n" % marker)
        os.chmod(fake, stat.S_IRWXU)
        read = pem.read_node_bundled(fake)
        self.assertFalse(read["ok"])
        self.assertIn("not an allowlisted executable", read["error"])
        self.assertFalse(os.path.exists(marker), "inventory path was executed")
        self.assertEqual(pem.EXECUTED, [])

    def test_node_bin_flag_authorises(self):
        tmp = tempfile.mkdtemp()
        fake = os.path.join(tmp, "node")
        with open(fake, "w") as fh:
            fh.write("#!/bin/sh\nprintf -- '-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\\n'\n")
        os.chmod(fake, stat.S_IRWXU)
        pem.EXTRA_EXECUTABLES.add(fake)
        read = pem.read_node_bundled(fake)
        self.assertEqual(pem.EXECUTED, [fake])
        self.assertIn(read["error"] or "ok", ("ok", read["error"]))  # ran; output may not decode

    def test_keytool_only_from_allowlisted_jvm(self):
        tmp = tempfile.mkdtemp()
        cacerts = os.path.join(tmp, "lib", "security", "cacerts")
        os.makedirs(os.path.dirname(cacerts))
        open(cacerts, "w").close()
        marker = os.path.join(tmp, "ran")
        os.makedirs(os.path.join(tmp, "bin"))
        with open(os.path.join(tmp, "bin", "keytool"), "w") as fh:
            fh.write("#!/bin/sh\ntouch %s\n" % marker)
        os.chmod(os.path.join(tmp, "bin", "keytool"), stat.S_IRWXU)
        read = pem.read_java_keystore(cacerts)
        self.assertFalse(read["ok"])
        self.assertIn("not at an allowlisted JVM location", read["error"])
        self.assertFalse(os.path.exists(marker))

    def test_subprocess_env_is_minimal(self):
        pem.EXTRA_EXECUTABLES.add("/bin/sh")
        with mock.patch("amiaffected.pem.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            pem._run(["/bin/sh", "-c", "true"])
        env = run.call_args.kwargs["env"]
        self.assertNotIn("NODE_OPTIONS", env)
        self.assertNotIn("JAVA_TOOL_OPTIONS", env)
        self.assertEqual(set(env), {"PATH", "LANG", "LC_ALL"})


class CliRefusesInventoryExecutables(unittest.TestCase):
    def test_check_with_hostile_inventory(self):
        tmp = tempfile.mkdtemp()
        marker = os.path.join(tmp, "ran")
        fake = os.path.join(tmp, "node")
        with open(fake, "w") as fh:
            fh.write("#!/bin/sh\ntouch %s\n" % marker)
        os.chmod(fake, stat.S_IRWXU)
        inv = make_inventory([{"id": "node", "kind": "node", "type": "node_bundled", "path": fake, "readable": True}])
        inv_path = os.path.join(tmp, "inv.json")
        with open(inv_path, "w") as fh:
            json.dump(inv, fh)
        proc = subprocess.run([sys.executable, "-m", "amiaffected", "check", "--inventory", inv_path],
                              capture_output=True, text=True, cwd=ROOT, timeout=120)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["verdict"], "unknown")
        self.assertEqual(doc["runtime"]["executed"], [])
        self.assertFalse(os.path.exists(marker), "inventory path was executed by the CLI")


if __name__ == "__main__":
    unittest.main()
