#!/usr/bin/env python3
"""Build the self-contained skill bundle from the canonical sources.

    python3 tools/build_bundle.py [--out dist] [--source-commit SHA]

Produces dist/amiaffected-check-<version>/ with:

    SKILL.md                 the check skill, copied from skills/check/
    TRUST.md                 docs/trust.md, what a reviewer should verify
    scripts/run.py           launcher; run with `python3 -I`
    scripts/amiaffected/     the package, copied (no __pycache__)
    scripts/advisories/      advisory data and fixtures, copied
    scripts/BUNDLE.json      version, source commit, build time, data revision

plus dist/amiaffected-check-<version>.tar.gz, dist/SHA256SUMS and
dist/RELEASE_NOTES.md. There is exactly one implementation: the bundle is
a copy of the repo's package and data, never a second code base.
"""
import argparse
import datetime as _dt
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from amiaffected import __version__  # noqa: E402
from amiaffected import matcher  # noqa: E402

REPO = "koshikraj/amiaffected"
WORKFLOW = "%s/.github/workflows/release.yml" % REPO


def _ignore(_dir, names):
    return {n for n in names if n == "__pycache__" or n.endswith(".pyc")}


def _source_commit(explicit):
    if explicit:
        return explicit
    env = os.environ.get("GITHUB_SHA")
    if env:
        return env
    try:
        return subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True,
                              text=True, check=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def build(out_dir, source_commit):
    name = "amiaffected-check-%s" % __version__
    bundle = os.path.join(out_dir, name)
    if os.path.isdir(bundle):
        shutil.rmtree(bundle)
    scripts = os.path.join(bundle, "scripts")
    os.makedirs(scripts)

    shutil.copy2(os.path.join(ROOT, "skills", "check", "SKILL.md"), os.path.join(bundle, "SKILL.md"))
    shutil.copy2(os.path.join(ROOT, "docs", "trust.md"), os.path.join(bundle, "TRUST.md"))
    for lic in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
        if os.path.isfile(os.path.join(ROOT, lic)):
            shutil.copy2(os.path.join(ROOT, lic), os.path.join(bundle, lic))
    shutil.copy2(os.path.join(ROOT, "tools", "bundle_launcher.py"), os.path.join(scripts, "run.py"))
    shutil.copytree(os.path.join(ROOT, "amiaffected"), os.path.join(scripts, "amiaffected"), ignore=_ignore)
    shutil.copytree(os.path.join(ROOT, "advisories"), os.path.join(scripts, "advisories"), ignore=_ignore)

    built_at = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    advisories = matcher.find_advisories(os.path.join(scripts, "advisories"))
    info = {
        "name": name,
        "version": __version__,
        "source_repo": REPO,
        "source_commit": source_commit,
        "built_at": built_at.isoformat(),
        "advisories": len(advisories),
        "data_revision": matcher.data_revision(advisories),
    }
    with open(os.path.join(scripts, "BUNDLE.json"), "w", encoding="utf-8") as fh:
        json.dump(info, fh, indent=2)
        fh.write("\n")

    # tarball: sorted entries, fixed mtime and ownership, so the same tree
    # produces the same bytes.
    tar_path = os.path.join(out_dir, name + ".tar.gz")
    epoch = int(built_at.timestamp())
    entries = []
    for dirpath, dirnames, filenames in os.walk(bundle):
        dirnames.sort()
        for fn in sorted(filenames):
            entries.append(os.path.join(dirpath, fn))
    with open(tar_path, "wb") as raw:
        import gzip
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=epoch) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                for path in entries:
                    arc = os.path.relpath(path, out_dir)
                    ti = tar.gettarinfo(path, arcname=arc)
                    ti.uid = ti.gid = 0
                    ti.uname = ti.gname = ""
                    ti.mtime = epoch
                    with open(path, "rb") as fh:
                        tar.addfile(ti, fh)
    with open(tar_path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    with open(os.path.join(out_dir, "SHA256SUMS"), "w", encoding="utf-8") as fh:
        fh.write("%s  %s\n" % (digest, os.path.basename(tar_path)))

    notes = io.StringIO()
    notes.write("## Verify before you extract\n\n")
    notes.write("```\ngh attestation verify %s.tar.gz --repo %s --signer-workflow %s\n"
                "sha256sum -c SHA256SUMS\n```\n\n" % (name, REPO, WORKFLOW))
    notes.write("The first command proves GitHub built this archive from `%s` at commit `%s` "
                "using the release workflow. The second only detects corruption.\n\n" % (REPO, source_commit))
    notes.write("## Install the skill\n\n")
    notes.write("```\ntar -xzf %s.tar.gz\nmv %s ~/.claude/skills/amiaffected-check\n```\n\n" % (name, name))
    notes.write("Then run `python3 -I ~/.claude/skills/amiaffected-check/scripts/run.py check`.\n\n")
    notes.write("## Contents\n\n")
    for k in ("version", "source_commit", "built_at", "advisories", "data_revision"):
        notes.write("- %s: `%s`\n" % (k, info[k]))
    with open(os.path.join(out_dir, "RELEASE_NOTES.md"), "w", encoding="utf-8") as fh:
        fh.write(notes.getvalue())
    return bundle, tar_path, info


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    ap.add_argument("--source-commit", default=None)
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    bundle, tar_path, info = build(args.out, _source_commit(args.source_commit))
    print("bundle   %s" % bundle)
    print("archive  %s" % tar_path)
    print("commit   %s" % info["source_commit"])
    print("data     %s (%d advisories)" % (info["data_revision"], info["advisories"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
