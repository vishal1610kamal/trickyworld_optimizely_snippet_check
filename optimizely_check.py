#!/usr/bin/env python3
"""optimizely_check: read-only checks for sites that use Optimizely Web Experimentation, written after the
16 November 2026 Optimizely supply chain attack (the "OPTIMJACK" campaign).

Three modes:

  snippet  Scan a served Optimizely snippet (a URL or a saved file). It pulls out the code customers write
           (Project JavaScript, variation custom code, redirect and locator functions) and looks in it for the
           published loader, its base64 and eval variants, and for scripts loaded from hosts you did not list.
           --baseline records a fingerprint so the next run tells you what changed.
  csp      Test a page's Content-Security-Policy against what the November payload needed: load a script from
           an unknown host, or run an inline copy through eval, then send data out.
  api      Read Project JavaScript, experiment and campaign code, page activation code and extension code through
           Optimizely's REST API, plus the change history for a time window. Needs OPTIMIZELY_TOKEN.

Python 3.10+, standard library only. It reads; it never changes anything.
Indicators come from Report URI, StepSecurity and Cynet (see README.md for links).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import gzip
import hashlib
import html.parser
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.0"
UA = f"optimizely-check/{VERSION} (+https://github.com/vishal1610kamal/trickyworld_optimizely_snippet_check)"

# ---------------------------------------------------------------------------------------------------------------
# Published indicators (16-17 November 2026)
# ---------------------------------------------------------------------------------------------------------------
IOC_DOMAINS = {
    "1688360.cc": "payload and data-collection host (track.js, card.php, hit.php)",
    "webshell.lol": "injector from the same actor's earlier wave (get.js)",
    "linkforge.cc": "SEO-panel script that carried the injector",
    "5vobauua3ojpklx.icu": "iOS stage router (boot.js)",
    "eil786npto9u5bq.icu": "iOS stage router and exploit pages",
    "l7bcsnwc7nzr3uo.icu": "Coruna telemetry host",
    "je4ft3gn8vxudum.icu": "fallback host hard-coded in boot.js",
    "q1ls1ho9x7wsxlu.icu": "fallback host hard-coded in boot.js",
    "ios-hack.icu": "fallback host hard-coded in boot.js",
    "p55abnw2pnsz0bo.icu": "registered with the iOS hosts (same certificates and IPs)",
    "1y69gy2mdzaltz1.icu": "registered with the iOS hosts (same certificates and IPs)",
    "gm38duxoihbmy5o.icu": "registered with the iOS hosts (same certificates and IPs)",
}
IOC_IPS = {
    "136.113.106.136": "last address of 1688360.cc",
    "34.96.213.201": "host of the first iOS routers",
    "34.87.36.58": "host of the second iOS routers",
}
IOC_WALLETS = {
    "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW": "BTC",
    "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e": "ETH/EVM",
    "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa": "TRON",
    "FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n": "SOL",
    "UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p": "TON",
    "0:2033556a49942224b486e70fa8beeaeae4265dc4b10adffec2326c002d30397b": "TON (raw)",
    "ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5": "LTC",
    "qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58": "BCH",
    "DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5": "DOGE",
}
IOC_MARKERS = {
    "window._k7": "global marker set by the payload",
    "__k7b": "global marker set by the payload",
    "data-channel-code": "attribute on the iOS loader's script tag",
    "BIGNIAO": "Coruna telemetry channel code",
    "JIUJIU888": "path of the Coruna loader",
}
IOC_HASHES = {
    "617df364120adc47fb4f55dcc0c69a9b6c9e108a92c60bc2b64a266254ab02f3": "track.js, earliest captured build",
    "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f": "track.js, 17:13 UTC build",
    "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40": "track.js, final 17:56 UTC build",
}
ATTACK_HOST = "1688360.cc"            # where track.js came from
IOS_HOST = "eil786npto9u5bq.icu"      # where the iOS stage and exploit frame came from
OPTIMIZELY_SUFFIX = "optimizely.com"

HIGH, MEDIUM, INFO = "HIGH", "MEDIUM", "INFO"
_RANK = {HIGH: 0, MEDIUM: 1, INFO: 2}


def defang(text: str) -> str:
    """Make hosts and IPs unclickable in output: 1688360.cc -> 1688360[.]cc."""
    return re.sub(r"(?<=[A-Za-z0-9])\.(?=[A-Za-z0-9])", "[.]", text)


@dataclasses.dataclass
class Finding:
    level: str
    message: str
    where: str = ""

    def line(self) -> str:
        loc = f"\n           at {self.where}" if self.where else ""
        return f"[{self.level:<6}] {self.message}{loc}"


def exit_code(findings: list[Finding]) -> int:
    """0 nothing to act on, 1 at least one HIGH, 2 MEDIUM items to review."""
    levels = {f.level for f in findings}
    return 1 if HIGH in levels else 2 if MEDIUM in levels else 0


# ---------------------------------------------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------------------------------------------
@dataclasses.dataclass
class Fetched:
    url: str
    status: int
    headers: dict[str, list[str]]
    body: bytes

    def header(self, name: str) -> str | None:
        values = self.headers.get(name.lower())
        return values[0] if values else None


class FetchError(Exception):
    pass


def http_get(url: str, headers: dict[str, str] | None = None, timeout: float = 30.0) -> Fetched:
    """GET a URL and return status, headers (lower-cased names, every value kept) and the decoded body."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "gzip", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw_headers, body = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as err:
        status, raw_headers, body = err.code, err.headers, err.read()
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise FetchError(f"{url}: {err}") from err
    hdrs: dict[str, list[str]] = {}
    for name, value in raw_headers.items():
        hdrs.setdefault(name.lower(), []).append(value)
    if (hdrs.get("content-encoding") or [""])[0].lower() == "gzip":
        body = gzip.decompress(body)
    return Fetched(url, status, hdrs, body)


# ---------------------------------------------------------------------------------------------------------------
# A small JavaScript-aware brace matcher: enough to cut function bodies out of a snippet without being fooled by
# braces inside strings, template literals, comments or regular-expression literals.
# ---------------------------------------------------------------------------------------------------------------
_REGEX_AFTER_CHARS = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_AFTER_WORDS = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw",
                      "instanceof", "yield", "await"}


def _skip_string(src: str, i: int, quote: str) -> int:
    i += 1
    while i < len(src):
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == quote or c == "\n":
            return i + 1
        i += 1
    return len(src)


def _skip_template(src: str, i: int) -> int:
    i += 1
    while i < len(src):
        c = src[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            return i + 1
        if c == "$" and src.startswith("${", i):
            end = match_brace(src, i + 1)
            if end is None:
                return len(src)
            i = end
            continue
        i += 1
    return len(src)


def _skip_regex(src: str, i: int) -> int | None:
    """Skip a regex literal starting at src[i] == '/'. None if it turns out not to be one (newline first)."""
    j, in_class = i + 1, False
    while j < len(src):
        c = src[j]
        if c == "\n":
            return None
        if c == "\\":
            j += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "/":
            j += 1
            while j < len(src) and (src[j].isalpha()):
                j += 1
            return j
        j += 1
    return None


def match_brace(src: str, open_idx: int) -> int | None:
    """Index just past the '}' that closes src[open_idx] == '{', or None if it never closes."""
    depth, i, n = 0, open_idx, len(src)
    prev_char, prev_word = "", ""
    while i < n:
        c = src[i]
        if c in "\"'":
            i = _skip_string(src, i, c)
            prev_char, prev_word = "a", ""
            continue
        if c == "`":
            i = _skip_template(src, i)
            prev_char, prev_word = "a", ""
            continue
        if c == "/" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "/":
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            if nxt == "*":
                j = src.find("*/", i + 2)
                i = n if j < 0 else j + 2
                continue
            if prev_char in _REGEX_AFTER_CHARS or prev_char == "" or prev_word in _REGEX_AFTER_WORDS:
                j = _skip_regex(src, i)
                if j is not None:
                    i = j
                    prev_char, prev_word = "a", ""
                    continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        if c.isalnum() or c in "_$":
            prev_word = prev_word + c if (prev_char.isalnum() or prev_char in "_$") else c
            prev_char = c
        elif not c.isspace():
            prev_char, prev_word = c, ""
        i += 1
    return None


# ---------------------------------------------------------------------------------------------------------------
# Snippet parsing
# ---------------------------------------------------------------------------------------------------------------
# Inside the data object, customer code appears as JSON-style keys followed by a space and a function, e.g.
#   "projectJS": function(){ ... }      "value": function($){ ... }      "dest": function(SelectiveReplace){ ... }
# Optimizely's own minified library never has the space, which keeps its code out of the scan.
_FN_KEY = re.compile(r'"(\w+)":\s+function\s*\(([^)]*)\)\s*\{')
_ACTION_SRC = re.compile(r'"src":\s*"(/actions/([0-9a-f]{64})\.js)"')
_UUID = re.compile(r'"id":\s*"([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})"')
_LABELS = {"projectJS": "Project JavaScript", "value": "custom code", "dest": "redirect function",
           "locator": "locator function"}


@dataclasses.dataclass
class Block:
    key: str
    body: str
    offset: int
    change_id: str = ""
    complete: bool = True

    @property
    def label(self) -> str:
        name = _LABELS.get(self.key, f'"{self.key}" function')
        return f"{name} (change {self.change_id})" if self.change_id else name


@dataclasses.dataclass
class Snippet:
    source: str
    text: str
    account_id: str | None
    project_id: str | None
    revision: str | None
    blocks: list[Block] | None      # None: no Optimizely data object found
    actions: list[str]              # "/actions/<sha256>.js" paths


def _change_id(text: str, data_start: int, key_start: int, body_end: int) -> str:
    """The "id" of the change object a function sits in: Optimizely writes it before "type" and "value", so look
    back to the start of the object first, then forward to its end."""
    before = text[max(data_start, key_start - 400):key_start]
    before = before[before.rfind("{"):] if "{" in before else before
    ids = _UUID.findall(before)
    if ids:
        return ids[-1]
    after = text[body_end:body_end + 400]
    after = after[:after.find("}")] if "}" in after else after
    ids = _UUID.findall(after)
    return ids[0] if ids else ""


def parse_snippet(text: str, source: str = "") -> Snippet:
    def first(pattern: str) -> str | None:
        m = re.search(pattern, text)
        return m.group(1) if m else None

    start = text.find('{"accountId"')
    blocks: list[Block] | None = None
    actions: list[str] = []
    if start >= 0:
        blocks, pos = [], start
        for m in _FN_KEY.finditer(text, start):
            if m.start() < pos:
                continue                      # a function nested inside a block we already cut out
            open_idx = m.end() - 1
            end = match_brace(text, open_idx)
            if end is None:
                blocks.append(Block(m.group(1), text[open_idx + 1:], m.start(), complete=False))
                break
            blocks.append(Block(m.group(1), text[open_idx + 1:end - 1], m.start(),
                                "" if m.group(1) == "projectJS" else _change_id(text, start, m.start(), end)))
            pos = end
        actions = sorted({m.group(1) for m in _ACTION_SRC.finditer(text, start)})
    return Snippet(source, text, first(r'"accountId":\s*"(\d+)"'), first(r'"projectId":\s*"(\d+)"'),
                   first(r'"revision":\s*"(\d+)"'), blocks, actions)


# ---------------------------------------------------------------------------------------------------------------
# Code checks (shared by the snippet and api modes)
# ---------------------------------------------------------------------------------------------------------------
_URL_LITERAL = re.compile(r"""["'`]((?:https?:)?//([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d+)?[^"'`\s]*)""")
_ATOB = re.compile(r"""atob\(\s*(["'])([A-Za-z0-9+/=_-]{8,})\1\s*\)""")
_HOOKS = [
    (re.compile(r"navigator\.clipboard|addEventListener\(\s*[\"']copy[\"']"), "reads or rewrites the clipboard"),
    (re.compile(r"sendBeacon\s*\("), "sends data out with navigator.sendBeacon"),
    (re.compile(r"Function\.prototype\.(?:call|apply)\s*="), "replaces Function.prototype.call/apply"),
    (re.compile(r"XMLHttpRequest\.prototype\.(?:open|send)\s*=|window\.fetch\s*=\s*"), "wraps fetch or XHR"),
    (re.compile(r"html2canvas"), "uses html2canvas (page screenshots)"),
    (re.compile(r"\b(?:cvv|cvc|cardnumber|card_number)\b", re.I), "looks for card fields"),
]


def host_allowed(host: str, allowed: set[str]) -> bool:
    host = host.lower().rstrip(".")
    for a in allowed:
        a = a.lower().lstrip(".")
        if host == a or host.endswith("." + a):
            return True
    return False


def _ioc_hits(text: str) -> list[tuple[str, str]]:
    low = text.lower()
    hits = [(f"published attacker host {defang(d)}: {why}", d) for d, why in IOC_DOMAINS.items() if d in low]
    hits += [(f"published attacker IP {defang(ip)}: {why}", ip) for ip, why in IOC_IPS.items() if ip in text]
    hits += [(f"attacker {chain} wallet address hard-coded in the payload", w)
             for w, chain in IOC_WALLETS.items() if w in text]
    hits += [(f"payload marker {m}: {why}", m) for m, why in IOC_MARKERS.items() if m in text]
    return hits


def check_code(code: str, where: str, allowed_hosts: set[str]) -> list[Finding]:
    """Look at one piece of customer code for the November loader and for things worth a second look."""
    out = [Finding(HIGH, msg, where) for msg, _ in _ioc_hits(code)]
    flagged_hosts: set[str] = set()

    for m in _ATOB.finditer(code):
        blob = m.group(2)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), altchars=b"-_" if "-" in blob or "_" in blob
                                       else None).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
        hidden_iocs = _ioc_hits(decoded)
        url = re.search(r"https?://([A-Za-z0-9.-]+)", decoded)
        if hidden_iocs:
            out.append(Finding(HIGH, f"base64 hides {hidden_iocs[0][0]} (decoded: {defang(decoded[:80])})", where))
        elif url and not host_allowed(url.group(1), allowed_hosts):
            flagged_hosts.add(url.group(1).lower())
            out.append(Finding(HIGH, f"base64 hides a URL on {defang(url.group(1))}, a host you have not listed "
                                     f"(decoded: {defang(decoded[:80])})", where))
    if "atob(" in code and not any("base64" in f.message for f in out):
        out.append(Finding(MEDIUM, "atob() in custom code: the November loader hid its URL this way", where))

    if re.search(r"createElement\(\s*[\"']script[\"']\s*\)", code):
        hosts = {m.group(2).lower() for m in _URL_LITERAL.finditer(code)}
        unknown = sorted(h for h in hosts if not host_allowed(h, allowed_hosts) and h not in flagged_hosts
                         and h not in IOC_DOMAINS)
        for h in unknown:
            out.append(Finding(MEDIUM, f"adds a <script> and names {defang(h)}: confirm your team added it "
                                       f"(--allow-host {h} once confirmed)", where))
        if not hosts:
            out.append(Finding(INFO, "creates a <script> element with a computed address", where))

    if re.search(r"\beval\s*\(|\bnew\s+Function\s*\(", code):
        out.append(Finding(MEDIUM, "eval() or new Function(): the November inline-fallback variant ran this way",
                           where))
    for pattern, what in _HOOKS:
        if pattern.search(code):
            out.append(Finding(MEDIUM, f"{what}: unusual in experiment code", where))
    return out


# ---------------------------------------------------------------------------------------------------------------
# snippet mode
# ---------------------------------------------------------------------------------------------------------------
def snippet_fingerprint(snip: Snippet, fetched: Fetched | None, allowed: set[str]) -> dict:
    blocks = {}
    for i, b in enumerate(snip.blocks or []):
        blocks[f"{i:03d} {b.label}"] = hashlib.sha256(b.body.encode()).hexdigest()
    hosts = sorted({m.group(2).lower() for b in (snip.blocks or []) for m in _URL_LITERAL.finditer(b.body)})
    return {
        "sha256": hashlib.sha256(snip.text.encode()).hexdigest(),
        "revision": snip.revision,
        "last_modified": fetched.header("last-modified") if fetched else None,
        "blocks": blocks,
        "external_hosts": [h for h in hosts if not host_allowed(h, allowed)],
        "actions": snip.actions,
    }


def compare_baseline(old: dict, new: dict, where: str) -> list[Finding]:
    if old.get("sha256") == new["sha256"]:
        return [Finding(INFO, "unchanged since the baseline", where)]
    out = [Finding(INFO, f"file changed since the baseline (revision {old.get('revision')} -> {new['revision']}, "
                         f"Last-Modified {old.get('last_modified')} -> {new['last_modified']})", where)]
    for label in sorted(set(old.get("blocks", {})) | set(new["blocks"])):
        before, after = old.get("blocks", {}).get(label), new["blocks"].get(label)
        if before != after:
            what = "new" if before is None else "removed" if after is None else "changed"
            out.append(Finding(MEDIUM if "Project JavaScript" in label else INFO,
                               f"{label.split(' ', 1)[1]} {what} since the baseline", where))
    for h in sorted(set(new["external_hosts"]) - set(old.get("external_hosts", []))):
        out.append(Finding(MEDIUM, f"new external host in custom code since the baseline: {defang(h)}", where))
    return out


def scan_snippet(source: str, allowed_hosts: list[str] | None = None, fetch_actions: bool = False,
                 baseline: str | None = None, fetch=http_get) -> tuple[list[Finding], dict]:
    """Scan one snippet. Returns findings and a summary dict (headers, ids, hashes)."""
    fetched = None
    if re.match(r"https?://", source):
        fetched = fetch(source)
        if fetched.status != 200:
            raise FetchError(f"{source}: HTTP {fetched.status}")
        text = fetched.body.decode("utf-8", "replace")
        page_host = urllib.parse.urlsplit(source).hostname or ""
    else:
        with open(source, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
        page_host = ""
    allowed = {OPTIMIZELY_SUFFIX, *(h.lower() for h in (allowed_hosts or []))}
    if page_host and not page_host.endswith(OPTIMIZELY_SUFFIX):
        allowed.add(page_host)                       # a snippet served from the customer's own domain

    snip = parse_snippet(text, source)
    findings: list[Finding] = []
    file_hash = hashlib.sha256(text.encode()).hexdigest()
    if file_hash in IOC_HASHES:
        findings.append(Finding(HIGH, f"this file is the payload itself: {IOC_HASHES[file_hash]}", source))

    if snip.blocks is None:
        findings.append(Finding(INFO, "no Optimizely data object found; checked the whole file for published "
                                      "indicators only", source))
        findings += [Finding(HIGH, msg, source) for msg, _ in _ioc_hits(text)]
    else:
        inside = "".join(b.body for b in snip.blocks)
        for b in snip.blocks:
            if not b.complete:
                findings.append(Finding(MEDIUM, f"{b.label} never closes: the file may be truncated or altered",
                                        source))
            findings += check_code(b.body, f"{source} -> {b.label}", allowed)
        for msg, needle in _ioc_hits(text):
            if needle.lower() not in inside.lower():
                findings.append(Finding(HIGH, f"{msg} (outside the customer code)", source))

    summary = {
        "source": source,
        "sha256": file_hash,
        "account_id": snip.account_id,
        "project_id": snip.project_id,
        "revision": snip.revision,
        "code_blocks": [b.label for b in (snip.blocks or [])],
        "action_files": len(snip.actions),
    }
    if fetched:
        for name in ("last-modified", "etag", "cache-control", "age", "x-amz-meta-revision", "server"):
            summary[name] = fetched.header(name)

    if fetch_actions and snip.actions:
        if not snip.account_id:
            findings.append(Finding(INFO, "action files listed but no accountId to build their URLs", source))
        for path in snip.actions:
            url = f"https://cdn.optimizely.com/public/{snip.account_id}/data{path}"
            try:
                got = fetch(url)
            except FetchError as err:
                findings.append(Finding(MEDIUM, f"could not fetch action file: {err}", url))
                continue
            if got.status != 200:
                findings.append(Finding(MEDIUM, f"action file returned HTTP {got.status}", url))
                continue
            digest = hashlib.sha256(got.body).hexdigest()
            name = path.rsplit("/", 1)[1][:-3]
            if digest != name:
                findings.append(Finding(HIGH, "action file content does not match the SHA-256 in its name", url))
            findings += check_code(got.body.decode("utf-8", "replace"), url, allowed)
        summary["action_files_checked"] = len(snip.actions)

    if baseline:
        new = snippet_fingerprint(snip, fetched, allowed)
        store: dict = {}
        if os.path.exists(baseline):
            with open(baseline, encoding="utf-8") as fh:
                store = json.load(fh)
        if source in store:
            findings += compare_baseline(store[source], new, source)
        else:
            store[source] = new
            with open(baseline, "w", encoding="utf-8") as fh:
                json.dump(store, fh, indent=1, sort_keys=True)
            findings.append(Finding(INFO, f"baseline saved to {baseline}", source))
    return findings, summary


# ---------------------------------------------------------------------------------------------------------------
# csp mode
# ---------------------------------------------------------------------------------------------------------------
_KEYWORDS = {"'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'unsafe-hashes'",
             "'report-sample'", "'wasm-unsafe-eval'", "'inline-speculation-rules'", "'unsafe-allow-redirects'"}
_DEFAULT_PORT = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def parse_policy(value: str) -> dict[str, list[str]]:
    """One serialized policy -> {directive: [sources]}. The first occurrence of a directive wins (CSP3)."""
    policy: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in policy:
            policy[name] = [t if not t.startswith("'") else t.lower() for t in tokens[1:]]
    return policy


def _effective(policy: dict[str, list[str]], chain: list[str]) -> tuple[str | None, list[str] | None]:
    for name in chain:
        if name in policy:
            return name, policy[name]
    return None, None


def source_matches(expr: str, url: str, page_url: str) -> bool:
    """Does one source expression match a URL? Follows CSP3's matching for '*', schemes, hosts and 'self'."""
    u = urllib.parse.urlsplit(url)
    page = urllib.parse.urlsplit(page_url)
    scheme, host = u.scheme.lower(), (u.hostname or "").lower()
    port = u.port or _DEFAULT_PORT.get(scheme)
    if expr == "*":
        return scheme in ("http", "https", "ws", "wss") or scheme == page.scheme
    if expr == "'self'":
        return host == (page.hostname or "").lower() and (scheme == page.scheme or
                                                          (page.scheme == "http" and scheme == "https"))
    if expr.startswith("'"):
        return False
    m = re.fullmatch(r"([a-zA-Z][a-zA-Z0-9+.-]*):", expr)
    if m:                                             # scheme-source such as https:
        s = m.group(1).lower()
        return s == scheme or (s == "http" and scheme == "https") or (s == "ws" and scheme == "wss")
    m = re.fullmatch(r"(?:([a-zA-Z][a-zA-Z0-9+.-]*)://)?(\*|\*\.[^/:]+|[^/:*]+)(?::(\d+|\*))?(/.*)?", expr)
    if not m:
        return False
    e_scheme, e_host, e_port, e_path = m.group(1), m.group(2).lower(), m.group(3), m.group(4)
    if e_scheme:
        e_scheme = e_scheme.lower()
        if not (e_scheme == scheme or (e_scheme == "http" and scheme == "https") or
                (e_scheme == "ws" and scheme in ("wss", "http", "https")) or (e_scheme == "wss" and scheme == "https")):
            return False
    elif not (scheme == page.scheme or (page.scheme == "http" and scheme == "https")):
        return False
    if e_host == "*":
        pass
    elif e_host.startswith("*."):
        if not host.endswith(e_host[1:]):
            return False
    elif host != e_host:
        return False
    if e_port and e_port != "*":
        if int(e_port) != port:
            return False
    elif not e_port:
        default = _DEFAULT_PORT.get(e_scheme or scheme)
        if port != default and not (e_scheme in (None, "http") and scheme == "https" and port == 443):
            return False
    if e_path and e_path != "/":
        path = urllib.parse.unquote(u.path or "/")
        if e_path.endswith("/"):
            if not path.startswith(e_path):
                return False
        elif path != e_path:
            return False
    return True


def _list_allows_url(sources: list[str], url: str, page_url: str) -> bool:
    return any(source_matches(s, url, page_url) for s in sources if s != "'none'")


def _has_nonce_or_hash(sources: list[str]) -> bool:
    return any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources)


@dataclasses.dataclass
class Step:
    name: str
    allowed: bool
    why: str


def evaluate_policy(policy: dict[str, list[str]], page_url: str, attack_host: str = ATTACK_HOST,
                    ios_host: str = IOS_HOST) -> dict[str, Step]:
    """What one enforced policy lets the November payload do on a page."""
    steps: dict[str, Step] = {}

    def script_load(host: str) -> Step:
        name, src = _effective(policy, ["script-src-elem", "script-src", "default-src"])
        if src is None:
            return Step("", True, "no script-src or default-src")
        if "'strict-dynamic'" in src:
            return Step("", True, f"'strict-dynamic' in {name} trusts any script the snippet inserts")
        url = f"https://{host}/track.js"
        if _list_allows_url(src, url, page_url):
            match = next(s for s in src if s != "'none'" and source_matches(s, url, page_url))
            return Step("", True, f"{name} allows it ({match})")
        return Step("", False, f"{name} does not list {defang(host)}")

    steps["load"] = script_load(attack_host)
    steps["load"].name = f"Load track.js from {defang(attack_host)}"

    name, src = _effective(policy, ["script-src", "default-src"])
    if src is None:
        eval_ok, eval_why = True, "no script-src or default-src"
    else:
        eval_ok = "'unsafe-eval'" in src
        eval_why = f"'unsafe-eval' in {name}" if eval_ok else f"{name} has no 'unsafe-eval'"
    name_i, src_i = _effective(policy, ["script-src-elem", "script-src", "default-src"])
    if src_i is None:
        inline_ok, inline_why = True, "no script-src or default-src"
    else:
        inline_ok = ("'unsafe-inline'" in src_i and not _has_nonce_or_hash(src_i)
                     and "'strict-dynamic'" not in src_i)
        inline_why = f"'unsafe-inline' in {name_i}" if inline_ok else ""
    steps["fallback"] = Step("Run the inline copy (eval or inline script)", eval_ok or inline_ok,
                             eval_why if eval_ok else (inline_why or eval_why + ", no usable 'unsafe-inline'"))

    name, src = _effective(policy, ["connect-src", "default-src"])
    url = f"https://{attack_host}/card.php"
    if src is None:
        steps["exfil"] = Step(f"Send card, cookie and screenshot data to {defang(attack_host)}", True,
                              "no connect-src or default-src")
    else:
        ok = _list_allows_url(src, url, page_url)
        steps["exfil"] = Step(f"Send card, cookie and screenshot data to {defang(attack_host)}", ok,
                              f"{name} allows it" if ok else f"{name} blocks it")

    steps["ios_load"] = script_load(ios_host)
    steps["ios_load"].name = f"Load the iOS stage (boot.js) from {defang(ios_host)}"
    name, src = _effective(policy, ["frame-src", "child-src", "default-src"])
    if src is None:
        steps["ios_frame"] = Step("Open the hidden iOS exploit frame", True, "no frame-src, child-src or default-src")
    else:
        ok = _list_allows_url(src, f"https://{ios_host}/JIUJIU888/weifile.html", page_url)
        steps["ios_frame"] = Step("Open the hidden iOS exploit frame", ok, f"{name} allows it" if ok
                                  else f"{name} blocks it")
    return steps


def red_flags(policy: dict[str, list[str]]) -> list[str]:
    flags = []
    _, src = _effective(policy, ["script-src", "default-src"])
    if src:
        if "'strict-dynamic'" in src:
            flags.append("'strict-dynamic' (any script a trusted script inserts is trusted too)")
        if "'unsafe-eval'" in src:
            flags.append("'unsafe-eval' (lets an inline copy of a payload run)")
        if "*" in src or "https:" in src or "http:" in src:
            flags.append("a wildcard or scheme-only source in script-src")
    if not _effective(policy, ["connect-src", "default-src"])[1]:
        flags.append("no connect-src or default-src (pages may send data anywhere)")
    return flags


class _MetaCSP(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.policies: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "meta":
            a = {k.lower(): (v or "") for k, v in attrs}
            if a.get("http-equiv", "").lower() == "content-security-policy" and a.get("content"):
                self.policies.append(a["content"])


def collect_policies(fetched: Fetched | None, header_policies: list[str], html_text: str | None):
    """Enforced and report-only policies from headers (comma-separated lists allowed) and <meta> tags."""
    enforced, report_only = [], []
    raw_enforced = list(header_policies)
    if fetched:
        raw_enforced += fetched.headers.get("content-security-policy", [])
        for value in fetched.headers.get("content-security-policy-report-only", []):
            report_only += [p for p in value.split(",") if p.strip()]
    for value in raw_enforced:
        enforced += [p for p in value.split(",") if p.strip()]
    if html_text:
        meta = _MetaCSP()
        meta.feed(html_text)
        enforced += meta.policies
    return [parse_policy(p) for p in enforced], [parse_policy(p) for p in report_only]


VERDICT_NONE = "No enforced CSP: nothing stood in the payload's way"
VERDICT_ALLOWED = "CSP allowed the payload and the data theft"
VERDICT_PARTIAL = "Payload ran, but connect-src blocked the data theft (the address swapping still worked)"
VERDICT_BLOCKED = "Payload blocked"


def assess_csp(enforced: list[dict], page_url: str, attack_host: str = ATTACK_HOST,
               ios_host: str = IOS_HOST) -> tuple[str, dict[str, Step], list[str]]:
    """Combine every enforced policy (a request must pass all of them) and give Report URI's four verdicts."""
    if not enforced:
        return VERDICT_NONE, {}, []
    combined: dict[str, Step] = {}
    for policy in enforced:
        for key, step in evaluate_policy(policy, page_url, attack_host, ios_host).items():
            if key not in combined or (combined[key].allowed and not step.allowed):
                combined[key] = step
    flags = sorted({f for p in enforced for f in red_flags(p)})
    runs = combined["load"].allowed or combined["fallback"].allowed
    if not runs:
        verdict = VERDICT_BLOCKED
    elif combined["exfil"].allowed:
        verdict = VERDICT_ALLOWED
    else:
        verdict = VERDICT_PARTIAL
    return verdict, combined, flags


# ---------------------------------------------------------------------------------------------------------------
# api mode (Optimizely REST API v2; paths and fields checked against api.optimizely.com/v2/swagger.json)
# ---------------------------------------------------------------------------------------------------------------
API_BASE = "https://api.optimizely.com/v2"


class Api:
    def __init__(self, token: str, base: str | None = None, fetch=http_get) -> None:
        self.token, self.base, self.fetch = token, (base or os.environ.get("OPTIMIZELY_API_BASE") or API_BASE), fetch

    def get(self, path: str, **params):
        query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
        url = f"{self.base}{path}" + (f"?{query}" if query else "")
        got = self.fetch(url, headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"})
        if got.status != 200:
            raise FetchError(f"GET {path}: HTTP {got.status} {got.body[:200]!r}")
        return json.loads(got.body)

    def pages(self, path: str, **params) -> list[dict]:
        items: list[dict] = []
        for page in range(1, 51):
            batch = self.get(path, per_page=100, page=page, **params)
            items += batch
            if len(batch) < 100:
                break
        return items


def _changes_code(changes: list[dict], where: str, allowed: set[str]) -> list[Finding]:
    out: list[Finding] = []
    for ch in changes or []:
        label = f"{where} -> change {ch.get('id') or '?'} ({ch.get('type')})"
        if ch.get("type") == "custom_code" and ch.get("value"):
            out += check_code(ch["value"], label, allowed)
        elif ch.get("type") == "redirect" and ch.get("destination_function"):
            out += check_code(ch["destination_function"], label, allowed)
        elif ch.get("type") == "insert_html" and "<script" in (ch.get("value") or "").lower():
            out.append(Finding(MEDIUM, "inserted HTML carries a <script> tag", label))
            out += check_code(ch["value"], label, allowed)
        if ch.get("async") and ch.get("src"):
            out.append(Finding(INFO, f"code loaded from the CDN at {ch['src']} (check it with snippet --actions)",
                               label))
    return out


def _touches_code(change: dict) -> bool:
    text = " ".join([change.get("summary") or ""] + [f"{d.get('property')} {d.get('description')}"
                                                      for d in change.get("changes") or []]).lower()
    return any(k in text for k in ("javascript", "custom_code", "custom code", "project_javascript", "code"))


def review_project(api: Api, project: dict, allowed: set[str], since: str | None, until: str | None):
    pid, name = project["id"], project.get("name") or ""
    tag = f"project {pid} ({name})"
    findings: list[Finding] = []
    snippet = project.get("web_snippet") or {}
    findings.append(Finding(INFO, f"snippet revision {snippet.get('code_revision')}, "
                                  f"{snippet.get('js_file_size')} bytes", tag))
    if snippet.get("project_javascript"):
        findings += check_code(snippet["project_javascript"], f"{tag} -> Project JavaScript", allowed)
    for exp in api.pages("/experiments", project_id=pid):
        where = f"{tag} -> experiment {exp.get('id')} ({exp.get('name') or ''})"
        findings += _changes_code(exp.get("changes"), where + " shared code", allowed)
        for var in exp.get("variations") or []:
            for action in var.get("actions") or []:
                findings += _changes_code(action.get("changes"), f"{where} variation {var.get('variation_id')}",
                                          allowed)
    for camp in api.pages("/campaigns", project_id=pid):
        findings += _changes_code(camp.get("changes"), f"{tag} -> campaign {camp.get('id')} shared code", allowed)
    for page in api.pages("/pages", project_id=pid):
        if page.get("activation_code"):
            findings += check_code(page["activation_code"], f"{tag} -> page {page.get('id')} activation code",
                                   allowed)
    for ext in api.pages("/extensions", project_id=pid):
        impl = ext.get("implementation") or {}
        for part in ("apply_js", "reset_js", "html"):
            if impl.get(part):
                findings += check_code(impl[part], f"{tag} -> extension {ext.get('id')} {part}", allowed)
    history: list[dict] = []
    if since or until:
        history = api.pages("/changes", project_id=pid, start_time=since, end_time=until)
        for ch in history:
            if _touches_code(ch):
                user = ch.get("user") or {}
                who = user.get("email") or user.get("display_name") or "unknown user"
                findings.append(Finding(MEDIUM, f"code changed {ch.get('created')} by {who} via "
                                                f"{ch.get('source')}: {ch.get('summary')} (confirm it was you)", tag))
    return findings, history


# ---------------------------------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------------------------------
def _print_findings(findings: list[Finding]) -> None:
    for f in sorted(findings, key=lambda f: _RANK[f.level]):
        print(f.line())


def cmd_snippet(args) -> int:
    all_findings: list[Finding] = []
    for source in args.sources:
        try:
            findings, summary = scan_snippet(source, args.allow_host, args.actions, args.baseline)
        except (FetchError, OSError) as err:
            print(f"[ERROR ] {err}", file=sys.stderr)
            return 3
        all_findings += findings
        if args.json:
            print(json.dumps({"summary": summary, "findings": [dataclasses.asdict(f) for f in findings]}, indent=1))
            continue
        print(f"Snippet {source}")
        print(f"  account {summary['account_id']}  project {summary['project_id']}  revision {summary['revision']}"
              f"  sha256 {summary['sha256'][:16]}...")
        if summary.get("last-modified"):
            print(f"  Last-Modified {summary['last-modified']}  cache-control {summary.get('cache-control')}"
                  f"  x-amz-meta-revision {summary.get('x-amz-meta-revision')}")
        print(f"  customer code blocks: {len(summary['code_blocks'])}  external action files: "
              f"{summary['action_files']}")
        _print_findings(findings)
        if not [f for f in findings if f.level != INFO]:
            print("  nothing found in this snippet")
        print()
    return exit_code(all_findings)


def cmd_csp(args) -> int:
    fetched, html_text, page_url = None, None, args.url or "https://example.invalid/"
    if args.url:
        try:
            fetched = http_get(args.url)
        except FetchError as err:
            print(f"[ERROR ] {err}", file=sys.stderr)
            return 3
        if "html" in (fetched.header("content-type") or ""):
            html_text = fetched.body.decode("utf-8", "replace")
    if args.html:
        with open(args.html, encoding="utf-8", errors="replace") as fh:
            html_text = fh.read()
    enforced, report_only = collect_policies(fetched, args.policy or [], html_text)
    verdict, steps, flags = assess_csp(enforced, page_url, args.host, args.ios_host)
    if args.json:
        print(json.dumps({"page": page_url, "enforced_policies": len(enforced), "report_only": len(report_only),
                          "verdict": verdict, "steps": {k: dataclasses.asdict(v) for k, v in steps.items()},
                          "red_flags": flags}, indent=1))
    else:
        print(f"CSP check for {page_url} (enforced policies: {len(enforced)}, report-only: {len(report_only)})")
        for step in steps.values():
            print(f"  {step.name:<58} {'allowed' if step.allowed else 'blocked':<8} {step.why}")
        print(f"Verdict: {verdict}")
        if report_only and not enforced:
            print("Note: a Report-Only policy reports violations but blocks nothing.")
        for flag in flags:
            print(f"Red flag: {flag}")
    return {VERDICT_BLOCKED: 0, VERDICT_PARTIAL: 2}.get(verdict, 1)


def cmd_api(args) -> int:
    token = os.environ.get("OPTIMIZELY_TOKEN")
    if not token:
        print("[ERROR ] set OPTIMIZELY_TOKEN to a personal access token (read access is enough)", file=sys.stderr)
        return 3
    api = Api(token)
    allowed = {OPTIMIZELY_SUFFIX, *(h.lower() for h in args.allow_host or [])}
    try:
        if args.project:
            projects = [api.get(f"/projects/{pid}") for pid in args.project]
        else:
            projects = [p for p in api.pages("/projects") if p.get("platform") == "web" and
                        p.get("status") != "archived"]
        all_findings: list[Finding] = []
        report = []
        for project in projects:
            findings, history = review_project(api, project, allowed, args.since, args.until)
            all_findings += findings
            report.append({"project": project["id"], "findings": [dataclasses.asdict(f) for f in findings],
                           "history": history})
            if not args.json:
                print(f"Project {project['id']} ({project.get('name') or ''})")
                _print_findings(findings)
                for ch in history:
                    user = ch.get("user") or {}
                    entity = ch.get("entity") or {}
                    print(f"  {ch.get('created')}  {ch.get('source', ''):<4} "
                          f"{user.get('email') or user.get('display_name') or '?':<28} "
                          f"{ch.get('change_type')} {entity.get('type')} '{entity.get('name')}': {ch.get('summary')}")
                print()
    except FetchError as err:
        print(f"[ERROR ] {err}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(report, indent=1))
    return exit_code(all_findings)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="optimizely_check.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--version", action="version", version=VERSION)
    sub = p.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("snippet", help="scan served snippets (URLs or saved files)")
    s.add_argument("sources", nargs="+", help="snippet URL, e.g. https://cdn.optimizely.com/js/<project>.js, or file")
    s.add_argument("--allow-host", action="append", default=[], help="a host your own code loads (repeatable)")
    s.add_argument("--actions", action="store_true", help="also fetch and check external custom-code files")
    s.add_argument("--baseline", help="JSON file: saved on the first run, compared on later runs")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_snippet)

    c = sub.add_parser("csp", help="test a page's Content-Security-Policy against the November payload")
    c.add_argument("url", nargs="?", help="page to fetch (headers and <meta> policies are read)")
    c.add_argument("--policy", action="append", help="evaluate this policy string instead (repeatable)")
    c.add_argument("--html", help="saved HTML file to read <meta> policies from")
    c.add_argument("--host", default=ATTACK_HOST, help=f"host the payload loads from (default {ATTACK_HOST})")
    c.add_argument("--ios-host", default=IOS_HOST, help=f"iOS stage host (default {IOS_HOST})")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_csp)

    a = sub.add_parser("api", help="review project code and change history through the REST API")
    a.add_argument("--project", action="append", type=int, help="project ID (repeatable); default: all web projects")
    a.add_argument("--since", default="2026-11-16T00:00:00Z", help="change-history window start (ISO 8601)")
    a.add_argument("--until", default="2026-11-17T06:00:00Z", help="change-history window end (ISO 8601)")
    a.add_argument("--allow-host", action="append", default=[], help="a host your own code loads (repeatable)")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_api)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
