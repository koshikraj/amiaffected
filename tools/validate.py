#!/usr/bin/env python3
"""Maintainer tool: validate advisories, lint fenced commands, generate
index.json and the RULES.md adapters.

    python3 tools/validate.py            validate; fail if index/adapters are stale
    python3 tools/validate.py --write    validate and regenerate index.json,
                                         skills/check/SKILL.md and AGENTS.md

Standard library only. Never shipped to users; CI is its only consumer
besides maintainers. It is a deny list and a floor, not the review.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ADVISORIES = ROOT / "advisories"
RULES = ROOT / "RULES.md"
INDEX = ROOT / "index.json"
SKILL = ROOT / "skills" / "check" / "SKILL.md"
AGENTS = ROOT / "AGENTS.md"

SCHEMA_VERSION = "1.0"
STATES = {"draft", "active", "superseded", "withdrawn"}
SEVERITIES = {"low", "medium", "high", "critical"}
INDICATOR_TYPES = {"certificate", "version_floor", "file_hash", "config"}
VERSION_SCHEMES = {"semver", "pep440", "debian", "rpm", "apk", "date", "freebsd", "opaque"}
OSES = {"linux", "macos", "windows", "freebsd", "netbsd", "any"}
PLATFORMS = {"any", "linux", "debian", "ubuntu", "alpine", "fedora", "rhel", "suse",
             "arch", "nixos", "macos", "windows", "freebsd", "netbsd", "android"}
EVAL_KINDS = {"positive", "negative", "unreadable", "stale", "incomplete_coverage",
              "present_unused", "backported", "declined"}
VERDICTS = {"affected", "not_affected", "unknown"}
SHELL_LANGS = {"sh", "bash", "shell", "zsh", "console", "powershell", "pwsh", "cmd"}

ID_RE = re.compile(r"^AIA-\d{4}-\d{4}$")
SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
HEX_RE = re.compile(r"^[0-9A-F]+$")
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
FENCE_RE = re.compile(r"^(`{3,}|~{3,})(.*)$")
RULES_VERSION_RE = re.compile(r"^Rules version:\s*(\d+)\s*$", re.M)

PREAMBLE_WORDS = ["ask", "read-only", "network", "coverage", "clean"]

# --- command lint -----------------------------------------------------------

NETWORK_TOOLS = r"(curl|wget|nc|ncat|netcat|ssh|scp|sftp|telnet|ftp|rsync)"
INTERPRETERS = r"(sh|bash|zsh|dash|ksh|fish|python[0-9.]*|perl|ruby|node|php|eval|xargs|source)"

# Patterns denied in check blocks. Each is (regex, reason).
CHECK_DENY = [
    (r"(^|[\s;&|(])sudo\b", "sudo"),
    (r"(^|[\s;&|(])doas\b", "doas"),
    (r"(^|[\s;&|(])su\b", "su"),
    (r"(^|[\s;&|(`($])" + NETWORK_TOOLS + r"\b", "network tool"),
    (r"openssl\s+s_client", "openssl s_client reaches the network"),
    (r"-connect\s", "-connect reaches the network"),
    (r"\|\s*(sudo\s+)?" + INTERPRETERS + r"\b", "pipe into an interpreter or shell"),
    (r"(^|[^2&>])>(?!\s*/dev/null)", "redirect"),
    (r"2>(?!\s*/dev/null|&1)", "redirect"),
    (r"(^|[\s;&|(])tee\b", "tee"),
    (r"(^|[\s;&|(])(rm|mv|cp|chmod|chown|chgrp|install|ln|mkdir|touch|dd|truncate)\b", "write verb"),
    (r"(^|[\s;&|(])(apt|apt-get|dnf|yum|zypper|apk|brew|pip|pip3|pipx|uv|npm|pnpm|yarn|cargo|gem|conda|pacman|port|choco|winget)\s+(install|remove|purge|upgrade|update|add|del|delete|uninstall|dist-upgrade|sync|-S)\b", "package-manager verb"),
    (r"keytool\s+.*-(import|importcert|delete|changealias|storepasswd)\b", "keytool mutation"),
    (r"security\s+(add-trusted-cert|remove-trusted-cert|delete-certificate|import|add-certificates)\b", "keychain mutation"),
    (r"certutil(\.exe)?\s+.*-(addstore|delstore|importpfx|setreg|urlcache)\b", "certutil mutation or fetch"),
    (r"(^|[\s;&|(])(update-ca-certificates|update-ca-trust|certctl\s+(untrust|trust|rehash)|trust\s+(anchor|extract))\b", "trust-store mutation"),
    (r"(^|[\s;&|(])export\s", "export"),
    (r"(^|[\s;&|(])(env|setenv)\s", "env"),
    (r"(^|[\s;&|(])[A-Za-z_][A-Za-z0-9_]*=\S*\s+[A-Za-z_./]", "env-assignment prefix"),
    (r"(^|[\s;&|(])(git|docker|podman|kubectl|systemctl|service|crontab|reboot|shutdown|kill|pkill)\s+(clone|pull|push|fetch|run|exec|start|stop|restart|enable|disable|apply|delete|-e|-l)\b", "state change"),
    (r"(^|[\s;&|(])(python[0-9.]*|perl|ruby|node|php)\s+(-[a-zA-Z]+\s+)*(-c|-e|-p|-r)\s", "inline interpreter code"),
    (r"(^|[\s;&|(])(python[0-9.]*|perl|ruby|node|php)\s+-\s*<<", "heredoc into an interpreter"),
    (r"(^|[\s;&|(])powershell(\.exe)?\s+.*-(enc|encodedcommand|c|command)\b", "inline PowerShell code"),
    (r"Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|iwr\s|irm\s|Net\.WebClient", "PowerShell network"),
    (r"Set-ItemProperty|Remove-Item|Import-Certificate|Export-Certificate|Set-Content|Out-File|Add-Content", "PowerShell write"),
]

# Extra patterns that only the live mode relaxes.
LIVE_RELAX = {"network tool", "openssl s_client reaches the network", "-connect reaches the network"}

FIX_DENY = [
    (r"\|\s*(sudo\s+)?" + INTERPRETERS + r"\b", "pipe into an interpreter or shell"),
    (r"[`$(]\s*" + NETWORK_TOOLS + r"\b", "command substitution around a network tool"),
    (r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|python[0-9.]*|perl|node|ruby|php)\b", "fetch piped into an interpreter"),
    (r"(^|[\s;&|(])(python[0-9.]*|perl|ruby|node|php)\s+-\s*<<", "heredoc into an interpreter"),
    (r"(^|[\s;&|(])(python[0-9.]*|perl|ruby|node|php)\s+(-[a-zA-Z]+\s+)*(-c|-e|-p|-r)\s", "inline interpreter code"),
    (r"Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|iwr\s|irm\s|Net\.WebClient|Invoke-Expression|\biex\b", "PowerShell fetch or eval"),
    (r"-ExecutionPolicy\s+Bypass", "execution-policy bypass"),
]

URL_HOST_RE = re.compile(r"https?://([A-Za-z0-9.-]+)")
CONNECT_HOST_RE = re.compile(r"-(connect|servername)\s+([A-Za-z0-9.-]+)")


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append(f"{where}: {msg}")


def parse_date(value: object) -> dt.date | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def require(obj: dict, where: str, rep: Report, *fields: str) -> bool:
    ok = True
    for f in fields:
        if f not in obj:
            rep.error(where, f"missing field '{f}'")
            ok = False
    return ok


def is_list_of_dicts(v: object) -> bool:
    return isinstance(v, list) and all(isinstance(x, dict) for x in v)


def is_list_of_str(v: object) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) and x.strip() for x in v)


# --- advisory.json ----------------------------------------------------------

def validate_advisory_json(folder: Path, rep: Report) -> dict | None:
    where = str(folder.relative_to(ROOT) / "advisory.json")
    path = folder / "advisory.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        rep.error(where, f"cannot parse: {exc}")
        return None
    if not isinstance(data, dict):
        rep.error(where, "top level must be an object")
        return None

    required = ["schema_version", "rules_version", "id", "slug", "title", "summary",
                "aliases", "revision", "published", "updated", "review_by",
                "publication_state", "severity", "sources", "products",
                "applicability", "indicators", "coverage", "limitations", "remediation"]
    if not require(data, where, rep, *required):
        return None

    if data["schema_version"] != SCHEMA_VERSION:
        rep.error(where, f"schema_version must be {SCHEMA_VERSION!r}")
    if not isinstance(data["rules_version"], int) or data["rules_version"] < 1:
        rep.error(where, "rules_version must be a positive integer")
    if not isinstance(data["id"], str) or not ID_RE.match(data["id"]):
        rep.error(where, "id must look like AIA-2026-0001")
    if not isinstance(data["slug"], str) or not SLUG_RE.match(data["slug"]):
        rep.error(where, "slug must be lowercase words joined by hyphens")
    elif data["slug"] != folder.name:
        rep.error(where, f"slug {data['slug']!r} differs from directory name {folder.name!r}")
    for f in ("title", "summary"):
        if not isinstance(data[f], str) or not data[f].strip():
            rep.error(where, f"{f} must be a non-empty string")
    if not is_list_of_str(data["aliases"]) and data["aliases"] != []:
        rep.error(where, "aliases must be a list of strings")
    if not isinstance(data["revision"], int) or data["revision"] < 1:
        rep.error(where, "revision must be a positive integer")

    published, updated, review_by = (parse_date(data[f]) for f in ("published", "updated", "review_by"))
    for f, v in (("published", published), ("updated", updated), ("review_by", review_by)):
        if v is None:
            rep.error(where, f"{f} must be an ISO date")
    if published and updated and updated < published:
        rep.error(where, "updated is before published")
    if updated and review_by and review_by <= updated:
        rep.error(where, "review_by must be after updated")

    if data["publication_state"] not in STATES:
        rep.error(where, f"publication_state must be one of {sorted(STATES)}")
    if data["severity"] not in SEVERITIES:
        rep.error(where, f"severity must be one of {sorted(SEVERITIES)}")

    # sources
    source_ids: set[str] = set()
    if not is_list_of_dicts(data["sources"]) or not data["sources"]:
        rep.error(where, "sources must be a non-empty list of objects")
    else:
        for i, s in enumerate(data["sources"]):
            w = f"{where} sources[{i}]"
            if require(s, w, rep, "id", "title", "url", "role", "retrieved"):
                if s["id"] in source_ids:
                    rep.error(w, f"duplicate source id {s['id']!r}")
                source_ids.add(s["id"])
                if not str(s["url"]).startswith("https://"):
                    rep.error(w, "url must be https")
                if parse_date(s["retrieved"]) is None:
                    rep.error(w, "retrieved must be an ISO date")

    if "credits" in data:
        if not is_list_of_dicts(data["credits"]):
            rep.error(where, "credits must be a list of objects")
        else:
            for i, c in enumerate(data["credits"]):
                require(c, f"{where} credits[{i}]", rep, "name", "for")

    # products
    if not is_list_of_dicts(data["products"]) or not data["products"]:
        rep.error(where, "products must be a non-empty list of objects")
    else:
        for i, p in enumerate(data["products"]):
            require(p, f"{where} products[{i}]", rep, "name", "ecosystem", "scope")

    # applicability
    app = data["applicability"]
    if not isinstance(app, dict) or not require(app, f"{where} applicability", rep, "summary", "conditions"):
        pass
    else:
        if not isinstance(app["summary"], str) or not app["summary"].strip() or "\n" in app["summary"]:
            rep.error(where, "applicability.summary must be one non-empty line")
        if not is_list_of_str(app["conditions"]) or not app["conditions"]:
            rep.error(where, "applicability.conditions must be a non-empty list of sentences")

    # indicators
    indicator_ids: set[str] = set()
    if not is_list_of_dicts(data["indicators"]) or not data["indicators"]:
        rep.error(where, "indicators must be a non-empty list of objects")
    else:
        for i, ind in enumerate(data["indicators"]):
            w = f"{where} indicators[{i}]"
            if not require(ind, w, rep, "id", "type", "meaning", "source"):
                continue
            if ind["id"] in indicator_ids:
                rep.error(w, f"duplicate indicator id {ind['id']!r}")
            indicator_ids.add(ind["id"])
            if ind["source"] not in source_ids:
                rep.error(w, f"source {ind['source']!r} is not in sources[]")
            if not isinstance(ind["meaning"], str) or len(ind["meaning"].strip()) < 20:
                rep.error(w, "meaning must say in words what a match establishes")
            t = ind["type"]
            if t not in INDICATOR_TYPES:
                rep.error(w, f"type must be one of {sorted(INDICATOR_TYPES)}")
                continue
            if t == "certificate":
                if require(ind, w, rep, "name", "role", "sha256", "comparison"):
                    if ind["role"] not in {"anchor", "compromised"}:
                        rep.error(w, "role must be anchor or compromised")
                    fps = ind["sha256"]
                    if not is_list_of_str(fps) or not fps:
                        rep.error(w, "sha256 must be a non-empty list of hex strings")
                    else:
                        for fp in fps:
                            if len(fp) != 64 or not HEX_RE.match(fp):
                                rep.error(w, f"sha256 {fp!r} is not 64 uppercase hex chars")
                    ski = ind.get("ski")
                    if ski is not None and (not isinstance(ski, str) or len(ski) != 40 or not HEX_RE.match(ski)):
                        rep.error(w, "ski must be 40 uppercase hex chars")
            elif t == "version_floor":
                if require(ind, w, rep, "product", "ecosystem", "version_scheme", "affected", "fixed_in", "as_of"):
                    if ind["version_scheme"] not in VERSION_SCHEMES:
                        rep.error(w, f"version_scheme must be one of {sorted(VERSION_SCHEMES)}")
                    if not is_list_of_dicts(ind["affected"]) or not ind["affected"]:
                        rep.error(w, "affected must be a non-empty list of {introduced, fixed}")
                    else:
                        for j, r in enumerate(ind["affected"]):
                            require(r, f"{w} affected[{j}]", rep, "introduced", "fixed")
                    if not is_list_of_str(ind["fixed_in"]) or not ind["fixed_in"]:
                        rep.error(w, "fixed_in must be a non-empty list of version strings")
                    if parse_date(ind["as_of"]) is None:
                        rep.error(w, "as_of must be an ISO date")
            elif t == "file_hash":
                if require(ind, w, rep, "algorithm", "target", "hashes"):
                    if not is_list_of_str(ind["hashes"]) or not ind["hashes"]:
                        rep.error(w, "hashes must be a non-empty list")
            elif t == "config":
                require(ind, w, rep, "component", "setting", "interpretation")
            for forbidden in ("command", "commands", "expression", "rule", "rules", "script", "regex", "exit_codes"):
                if forbidden in ind:
                    rep.error(w, f"field {forbidden!r} is not allowed: advisory.json is descriptive only")

    # coverage
    coverage_ids: set[str] = set()
    if not is_list_of_dicts(data["coverage"]) or not data["coverage"]:
        rep.error(where, "coverage must be a non-empty list of objects")
    else:
        for i, c in enumerate(data["coverage"]):
            w = f"{where} coverage[{i}]"
            if not require(c, w, rep, "id", "store", "indicators", "platforms", "required"):
                continue
            if c["id"] in coverage_ids:
                rep.error(w, f"duplicate coverage id {c['id']!r}")
            coverage_ids.add(c["id"])
            if not is_list_of_str(c["indicators"]) or not c["indicators"]:
                rep.error(w, "indicators must be a non-empty list of indicator ids")
            else:
                for ref in c["indicators"]:
                    if ref not in indicator_ids:
                        rep.error(w, f"indicator {ref!r} does not exist")
            if not isinstance(c["required"], bool):
                rep.error(w, "required must be true or false")
            if not is_list_of_dicts(c["platforms"]) or not c["platforms"]:
                rep.error(w, "platforms must be a non-empty list of {os, locations, note}")
            else:
                for j, p in enumerate(c["platforms"]):
                    pw = f"{w} platforms[{j}]"
                    if require(p, pw, rep, "os", "locations"):
                        if p["os"] not in OSES:
                            rep.error(pw, f"os must be one of {sorted(OSES)}")
                        if not isinstance(p["locations"], list):
                            rep.error(pw, "locations must be a list")

    for f in ("limitations",):
        if not is_list_of_str(data[f]):
            rep.error(where, f"{f} must be a list of sentences")
    if "uncheckable" in data:
        if not is_list_of_dicts(data["uncheckable"]):
            rep.error(where, "uncheckable must be a list of objects")
        else:
            for i, u in enumerate(data["uncheckable"]):
                require(u, f"{where} uncheckable[{i}]", rep, "what", "why", "user_should")

    rem = data["remediation"]
    if isinstance(rem, dict) and require(rem, f"{where} remediation", rep, "summary", "file"):
        if rem["file"] != "fix.md":
            rep.error(where, "remediation.file must be fix.md")
        if not (folder / "fix.md").is_file():
            rep.error(where, "fix.md does not exist")
    elif not isinstance(rem, dict):
        rep.error(where, "remediation must be an object")

    live_hosts: list[str] = []
    if "live_check" in data:
        lc = data["live_check"]
        if not isinstance(lc, dict) or not require(lc, f"{where} live_check", rep, "hosts", "privacy", "operator"):
            pass
        else:
            if not is_list_of_dicts(lc["hosts"]) or not lc["hosts"]:
                rep.error(where, "live_check.hosts must be a non-empty list")
            else:
                for i, h in enumerate(lc["hosts"]):
                    hw = f"{where} live_check.hosts[{i}]"
                    if require(h, hw, rep, "host", "proves", "negative_means"):
                        if not HOST_RE.match(str(h["host"])):
                            rep.error(hw, f"host {h['host']!r} is not a plain hostname")
                        live_hosts.append(str(h["host"]).lower())
    data["_live_hosts"] = live_hosts
    data["_coverage_ids"] = coverage_ids
    data["_folder"] = folder
    return data


# --- markdown lint ----------------------------------------------------------

def iter_fences(text: str):
    """Yield (line_number, info_string, body) for every fenced block."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        fence, info = m.group(1), m.group(2).strip()
        start = i
        body: list[str] = []
        i += 1
        while i < len(lines) and not lines[i].startswith(fence[0] * 3):
            body.append(lines[i])
            i += 1
        yield start + 1, info, "\n".join(body)
        i += 1


def strip_quotes(line: str) -> str:
    """Remove single-quoted strings so quoted data (regexes, fingerprints,
    file names) does not trip the linter. Double-quoted strings stay: they
    can carry expansions and commands."""
    return re.sub(r"'[^']*'", "''", line)


def join_continuations(body: str) -> list[str]:
    out: list[str] = []
    cur = ""
    for raw in body.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            cur += line[:-1] + " "
            continue
        cur += line
        out.append(cur)
        cur = ""
    if cur:
        out.append(cur)
    return out


def lint_block(where: str, mode: str, body: str, live_hosts: list[str], rep: Report) -> None:
    deny = CHECK_DENY if mode in ("check", "live") else FIX_DENY
    for line in join_continuations(body):
        if line.strip().startswith("#") or not line.strip():
            continue
        probe = strip_quotes(line)
        for pattern, reason in deny:
            if mode == "live" and reason in LIVE_RELAX:
                continue
            if re.search(pattern, probe):
                rep.error(where, f"{mode} block uses {reason}: {line.strip()[:100]}")
        if mode == "live":
            hosts = {h.lower() for h in URL_HOST_RE.findall(probe)}
            hosts |= {h.lower() for _, h in CONNECT_HOST_RE.findall(probe)}
            for h in hosts:
                if h not in live_hosts:
                    rep.error(where, f"live block reaches {h!r}, which is not in live_check.hosts")
            uses_net = re.search(r"(^|[\s;&|(])(curl|wget)\b|openssl\s+s_client", probe)
            if uses_net and not hosts:
                rep.error(where, f"live block uses a network tool without a listed host: {line.strip()[:100]}")
        elif mode == "check":
            for h in URL_HOST_RE.findall(probe):
                rep.error(where, f"check block contains a URL ({h})")


def lint_markdown(folder: Path, data: dict | None, rep: Report) -> None:
    live_hosts = data["_live_hosts"] if data else []
    for name in ("advisory.md", "fix.md"):
        path = folder / name
        where = str(path.relative_to(ROOT))
        if not path.is_file():
            rep.error(where, "missing")
            continue
        text = path.read_text(encoding="utf-8")
        if name == "advisory.md":
            head = "\n".join(text.splitlines()[:25]).lower()
            missing = [w for w in PREAMBLE_WORDS if w not in head]
            if missing:
                rep.error(where, f"preamble in the first 25 lines must mention {missing}")
            for m in re.finditer(r"\b(is|are|looks|looked|reported as|report(ed)?|verdict)\s+(clean|safe)\b", text, re.I):
                rep.error(where, f"verdict word {m.group(3)!r} is not allowed: {m.group(0)!r}")
        for lineno, info, body in iter_fences(text):
            w = f"{where}:{lineno}"
            parts = info.split()
            lang = parts[0].lower() if parts else ""
            if lang == "" :
                rep.error(w, "fenced block needs a language (sh check | sh live | sh fix <platform> | text | ...)")
                continue
            if lang not in SHELL_LANGS:
                continue
            if len(parts) < 2:
                rep.error(w, "shell block needs a mode: check, live or fix <platform>")
                continue
            mode = parts[1].lower()
            if mode in ("check", "live"):
                if name != "advisory.md":
                    rep.error(w, f"{mode} blocks belong in advisory.md")
                    continue
                if mode == "live" and not live_hosts:
                    rep.error(w, "live block but advisory.json has no live_check")
                    continue
                if len(parts) > 2:
                    rep.error(w, f"{mode} blocks take no platform tag")
            elif mode == "fix":
                if name != "fix.md":
                    rep.error(w, "fix blocks belong in fix.md")
                    continue
                if len(parts) < 3 or parts[2].lower() not in PLATFORMS:
                    rep.error(w, f"fix block needs a platform tag from {sorted(PLATFORMS)}")
                    continue
                if lang in ("powershell", "pwsh", "cmd") and parts[2].lower() != "windows":
                    rep.error(w, "PowerShell fix blocks must be tagged windows")
            else:
                rep.error(w, f"unknown block mode {mode!r}")
                continue
            lint_block(w, mode, body, live_hosts, rep)


# --- eval -------------------------------------------------------------------

def validate_eval(folder: Path, data: dict | None, rep: Report) -> None:
    evaldir = folder / "eval"
    where = str(evaldir.relative_to(ROOT))
    if not evaldir.is_dir():
        rep.error(where, "missing eval/ directory")
        return
    cases = sorted(evaldir.glob("*.json"))
    if not cases:
        rep.error(where, "no eval cases")
    ids: set[str] = set()
    for case in cases:
        w = str(case.relative_to(ROOT))
        try:
            c = json.loads(case.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            rep.error(w, f"cannot parse: {exc}")
            continue
        if not isinstance(c, dict) or not require(c, w, rep, "id", "kind", "advisory_revision", "coverage", "input", "expected"):
            continue
        if c["id"] in ids:
            rep.error(w, f"duplicate case id {c['id']!r}")
        ids.add(c["id"])
        if c["kind"] not in EVAL_KINDS:
            rep.error(w, f"kind must be one of {sorted(EVAL_KINDS)}")
        if data and c["coverage"] != "all" and c["coverage"] not in data["_coverage_ids"]:
            rep.error(w, f"coverage {c['coverage']!r} does not exist in advisory.json")
        if data and c["advisory_revision"] != data["revision"]:
            rep.warn(w, f"written for revision {c['advisory_revision']}, advisory is at {data['revision']}")
        inp = c["input"]
        if not isinstance(inp, dict) or not ({"file", "captured_output"} & set(inp)):
            rep.error(w, "input must have file or captured_output")
        elif "file" in inp and not (evaldir / inp["file"]).is_file():
            rep.error(w, f"input file {inp['file']!r} does not exist under eval/")
        exp = c["expected"]
        if not isinstance(exp, dict) or not require(exp, f"{w} expected", rep, "verdict", "report_contains"):
            continue
        if exp["verdict"] not in VERDICTS:
            rep.error(w, f"expected.verdict must be one of {sorted(VERDICTS)}")
        if not is_list_of_str(exp["report_contains"]):
            rep.error(w, "expected.report_contains must be a list of strings")


# --- index and adapters -----------------------------------------------------

def build_index(advisories: list[dict]) -> str:
    entries = []
    for d in sorted(advisories, key=lambda x: x["id"]):
        entries.append({
            "id": d["id"],
            "slug": d["slug"],
            "path": str(d["_folder"].relative_to(ROOT)).replace("\\", "/"),
            "title": d["title"],
            "severity": d["severity"],
            "revision": d["revision"],
            "published": d["published"],
            "updated": d["updated"],
            "review_by": d["review_by"],
            "publication_state": d["publication_state"],
            "rules_version": d["rules_version"],
            "applicability": d["applicability"]["summary"],
            "products": [p["name"] for p in d["products"]],
            "indicator_types": sorted({i["type"] for i in d["indicators"]}),
            "live_check": "live_check" in d,
        })
    index = {
        "schema_version": SCHEMA_VERSION,
        "updated": max((d["updated"] for d in advisories), default=None),
        "count": len(entries),
        "advisories": entries,
    }
    return json.dumps(index, indent=2, ensure_ascii=False) + "\n"


def read_rules() -> tuple[int, str]:
    text = RULES.read_text(encoding="utf-8")
    m = RULES_VERSION_RE.search(text)
    if not m:
        raise ValueError("RULES.md has no 'Rules version: N' line")
    return int(m.group(1)), text


def build_skill(version: int, rules: str) -> str:
    return (
        "---\n"
        "name: amiaffected-check\n"
        "description: Check this machine against the Am I Affected advisories (known incidents such as a leaked CA key or a runtime RCE). Read-only, interactive, one approved batch of commands per advisory. Use when the user asks whether they are affected by an incident, or wants their trust stores, runtimes or packages checked against the advisory corpus.\n"
        "---\n"
        "\n"
        "<!-- GENERATED from RULES.md by tools/validate.py --write. Do not edit here. -->\n"
        f"<!-- rules_version: {version} -->\n"
        "\n"
        "This file is RULES.md verbatim, wrapped for Claude Code. The advisory\n"
        "corpus is in `advisories/` next to this skill's repository root;\n"
        "`index.json` at the root lists every advisory.\n"
        "\n"
        + rules
    )


def build_agents(version: int, rules: str) -> str:
    return (
        "<!-- GENERATED from RULES.md by tools/validate.py --write. Do not edit here. -->\n"
        f"<!-- rules_version: {version} -->\n"
        "\n"
        "# Am I Affected: instructions for agents\n"
        "\n"
        "This file is RULES.md verbatim, placed where agents that read AGENTS.md\n"
        "look for it. It applies when the user asks whether they are affected by\n"
        "an incident in `advisories/`. `index.json` lists every advisory.\n"
        "\n"
        + rules
    )


def check_generated(path: Path, expected: str, write: bool, rep: Report) -> None:
    where = str(path.relative_to(ROOT))
    current = path.read_text(encoding="utf-8") if path.is_file() else None
    if write:
        if current != expected:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8")
            print(f"wrote {where}")
        return
    if current is None:
        rep.error(where, "missing; run tools/validate.py --write")
    elif current != expected:
        rep.error(where, "stale; run tools/validate.py --write and commit the result")


# --- main -------------------------------------------------------------------

def main(argv: list[str]) -> int:
    write = "--write" in argv
    rep = Report()

    folders = sorted(p.parent for p in ADVISORIES.glob("*/*/advisory.json")) if ADVISORIES.is_dir() else []
    advisories: list[dict] = []
    seen_ids: set[str] = set()
    for folder in folders:
        data = validate_advisory_json(folder, rep)
        if data:
            if data["id"] in seen_ids:
                rep.error(str(folder.relative_to(ROOT)), f"duplicate advisory id {data['id']}")
            seen_ids.add(data["id"])
            advisories.append(data)
        lint_markdown(folder, data, rep)
        validate_eval(folder, data, rep)
        for stray in folder.rglob("*"):
            if stray.suffix in (".py", ".sh", ".ps1", ".exe", ".bat") and "eval" not in stray.parts:
                rep.error(str(stray.relative_to(ROOT)), "executable files are not allowed in an advisory")

    if RULES.is_file():
        try:
            version, rules = read_rules()
            for d in advisories:
                if d["rules_version"] > version:
                    rep.error(str(d["_folder"].relative_to(ROOT)), f"needs rules_version {d['rules_version']} but RULES.md is {version}")
            check_generated(SKILL, build_skill(version, rules), write, rep)
            check_generated(AGENTS, build_agents(version, rules), write, rep)
        except ValueError as exc:
            rep.error("RULES.md", str(exc))
    else:
        rep.error("RULES.md", "missing")

    if not rep.errors or write:
        check_generated(INDEX, build_index(advisories), write, rep)

    for w in rep.warnings:
        print(f"warning: {w}")
    for e in rep.errors:
        print(f"error: {e}")
    print(f"{len(advisories)} advisories, {len(rep.errors)} errors, {len(rep.warnings)} warnings")
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
