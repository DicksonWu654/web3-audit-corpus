"""Shared helpers for the release link/source verification (scripts/verify/linkcheck_*.py).

Politeness: per-host concurrency <= 2 enforced across threads AND processes (flock slot files), a minimum
spacing between request starts per host, robots.txt honoured (RFC 9309 wildcard matching), a descriptive
User-Agent, and exponential backoff on 429/5xx. Downloads are treated as untrusted bytes: they are hashed or
handed to pdftotext/tesseract as data and never executed. All state lives under local-cache/linkcheck/
(gitignored).
"""
from __future__ import annotations

import fcntl
import http.client
import glob
import hashlib
import json
import os
import random
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / "local-cache" / "linkcheck"
STATE = STORE / "state"
LOCKS = STORE / "locks"
UA_TOKEN = "web3-audit-corpus-linkcheck"
# Honest, descriptive research UA. (The word "crawler" is omitted because some Cloudflare rules hard-block it.)
UA = (UA_TOKEN + "/1.0 (academic research link checker for the public web3-audit-corpus dataset; "
      "+https://github.com/DicksonWu654/web3-audit-corpus)")
SEED = 20261021
EXCLUDED_FIRMS = {"certik"}
DEFAULT_INTERVAL = 1.0           # seconds between request starts per host
HOST_INTERVAL = {"github.com": 0.25, "raw.githubusercontent.com": 0.5}
MAX_CONCURRENCY = 2
TIMEOUT = 30
GITHUB_BLOB = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/blob/([0-9a-f]{40})/(.+)$")


def utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def fresh_batch(name):
    """A new, empty directory for one download batch."""
    path = STORE / f"{name}-{stamp()}-{os.getpid()}"
    path.mkdir(parents=True, exist_ok=False)
    return path


def read_jsonl(path):
    out = []
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


class JsonlWriter:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(path, "a", encoding="utf-8")
        self.lock = threading.Lock()

    def write(self, obj):
        with self.lock:
            self.handle.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
            self.handle.flush()


# ---------------------------------------------------------------- corpus inputs

def report_rows():
    """Every collected report row of in-scope publishers (certik skipped)."""
    rows = []
    for path in sorted(glob.glob(str(ROOT / "data/collect/*/reports.jsonl"))):
        firm = Path(path).parent.name
        if firm in EXCLUDED_FIRMS:
            continue
        for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            if line.strip():
                row = json.loads(line)
                row["_source"] = f"data/collect/{firm}/reports.jsonl:{i}"
                rows.append(row)
    return rows


def github_parts(row):
    """(owner/repo, commit, path) for a GitHub-hosted report, else None."""
    notes = row.get("notes") or ""
    m = re.search(r"repo=([^;\s]+); commit=([0-9a-f]{40});(?: git_blob=[0-9a-f]+;)? path=(.+?)(?: \| |$)", notes)
    if m and row.get("source_kind") == "github":
        return m.group(1), m.group(2), m.group(3)
    m = GITHUB_BLOB.match(row.get("public_url") or "")
    if m:
        return f"{m.group(1)}/{m.group(2)}", m.group(3), urllib.parse.unquote(m.group(4))
    return None


def quote_path(path):
    return urllib.parse.quote(path, safe="/-_.~!$&'()*+,;=:@")


def permalink(parts):
    repo, commit, path = parts
    return f"https://github.com/{repo}/blob/{commit}/{quote_path(path)}"


def raw_url(parts):
    repo, commit, path = parts
    return f"https://raw.githubusercontent.com/{repo}/{commit}/{quote_path(path)}"


def notes_git_blob(row):
    m = re.search(r"git_blob=([0-9a-f]{40})", row.get("notes") or "")
    return m.group(1) if m else None


def lfs_oid(row):
    m = re.search(r"Git LFS pointer verified: oid=sha256:([0-9a-f]{64})", row.get("notes") or "")
    return m.group(1) if m else None


def download_url(row):
    """Best URL for the exact original bytes: pinned raw GitHub, then recorded retrieval/download URL, else public_url."""
    m = re.search(r"media_url=(https://media\.githubusercontent\.com/\S+)", row.get("notes") or "")
    if m and lfs_oid(row):
        return m.group(1).rstrip(";,|"), "github_lfs_media_pinned"
    parts = github_parts(row)
    if parts:
        return raw_url(parts), "github_raw_pinned"
    notes = row.get("notes") or ""
    for key in ("retrieval", "Download URL", "full original", "linked original", "listing original"):
        m = re.search(re.escape(key) + r"[:=]\s*\"?(https?://[^\s;\"|]+)", notes)
        if m:
            url = m.group(1).rstrip(".,)")
            gm = GITHUB_BLOB.match(url)
            if gm:
                return raw_url((f"{gm.group(1)}/{gm.group(2)}", gm.group(3), urllib.parse.unquote(gm.group(4)))), "notes_" + key
            return url, "notes_" + key.replace(" ", "_")
    return row["public_url"], "public_url"


def local_original(row):
    p = ROOT / (row.get("local_path") or "")
    return p if row.get("local_path") and p.is_file() else None


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def git_blob_sha(path):
    size = os.path.getsize(path)
    h = hashlib.sha1(b"blob %d\0" % size)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def allocate(counts, n, minimum=2):
    """Stratified allocation: min(count, minimum) per stratum, rest proportional (largest remainder)."""
    alloc = {k: min(c, minimum) for k, c in counts.items()}
    left = n - sum(alloc.values())
    if left <= 0:
        return alloc
    spare = {k: counts[k] - alloc[k] for k in counts}
    total = sum(spare.values())
    quota = {k: left * spare[k] / total for k in counts} if total else {}
    for k in quota:
        alloc[k] += min(int(quota[k]), spare[k])
    rest = n - sum(alloc.values())
    for k in sorted(quota, key=lambda k: (-(quota[k] - int(quota[k])), k)):
        if rest <= 0:
            break
        if alloc[k] < counts[k]:
            alloc[k] += 1
            rest -= 1
    return alloc


# ---------------------------------------------------------------- per-host gate (threads + processes)

class HostGate:
    def __init__(self, host):
        self.host = host
        self.key = hashlib.sha256(host.encode()).hexdigest()[:24]
        LOCKS.mkdir(parents=True, exist_ok=True)
        self.local = threading.local()
        self.penalty = 1.0

    def interval(self):
        base = HOST_INTERVAL.get(self.host, DEFAULT_INTERVAL)
        return max(base, ROBOTS_DELAY.get(self.host, 0)) * self.penalty

    def __enter__(self):
        slot = None
        while slot is None:
            for i in range(MAX_CONCURRENCY):
                handle = open(LOCKS / f"{self.key}.slot{i}", "a+")
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    slot = handle
                    break
                except BlockingIOError:
                    handle.close()
            if slot is not None:
                break
            time.sleep(0.05 + random.random() * 0.1)
        self.local.slot = slot
        with open(LOCKS / f"{self.key}.time", "a+") as t:
            fcntl.flock(t, fcntl.LOCK_EX)
            t.seek(0)
            try:
                nxt = float(t.read() or 0)
            except ValueError:
                nxt = 0.0
            now = time.time()
            start = max(now, nxt)
            t.seek(0)
            t.truncate()
            t.write(repr(start + self.interval()))
            t.flush()
        time.sleep(max(0.0, start - time.time()))
        return self

    def __exit__(self, *exc):
        slot = self.local.slot
        self.local.slot = None
        fcntl.flock(slot, fcntl.LOCK_UN)
        slot.close()


_GATES: dict = {}
_GATES_LOCK = threading.Lock()


def gate(host):
    with _GATES_LOCK:
        if host not in _GATES:
            _GATES[host] = HostGate(host)
        return _GATES[host]


# ---------------------------------------------------------------- raw HTTP (no automatic redirects)

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_SSL = ssl.create_default_context()
_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_SSL))


class Resp:
    def __init__(self, code, headers, body=b"", error=None, kind=None):
        self.code, self.headers, self.body, self.error, self.kind = code, headers or {}, body, error, kind


def requote(url):
    """Percent-encode characters urllib refuses (spaces, non-ASCII) without double-encoding existing escapes."""
    return urllib.parse.quote(url, safe=":/?#[]@!$&'()*+,;=%~")


def _one(url, method, max_bytes, extra_headers=None, sink=None):
    url = requote(url)
    headers = {"User-Agent": UA, "Accept": "*/*", "Accept-Encoding": "identity"}
    headers.update(extra_headers or {})
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        resp = _OPENER.open(req, timeout=TIMEOUT)
        code, hdrs = resp.status, {k.lower(): v for k, v in resp.headers.items()}
        body = b""
        if method == "GET":
            if sink is not None:
                h = hashlib.sha256()
                size = 0
                with open(sink, "wb") as out:
                    while True:
                        chunk = resp.read(1 << 16)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > max_bytes:
                            raise ValueError("body exceeds limit")
                        h.update(chunk)
                        out.write(chunk)
                hdrs["x-sha256"], hdrs["x-bytes"] = h.hexdigest(), str(size)
            else:
                body = resp.read(max_bytes)
        resp.close()
        return Resp(code, hdrs, body)
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            body = e.read(4096) if method == "GET" else b""
        except Exception:
            body = b""
        return Resp(e.code, hdrs, body)
    except (socket.timeout, TimeoutError) as e:
        return Resp(None, {}, error=f"timeout: {e}", kind="TIMEOUT")
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason):
            return Resp(None, {}, error=f"timeout: {reason}", kind="TIMEOUT")
        return Resp(None, {}, error=f"urlerror: {reason}", kind="OTHER")
    except (ConnectionError, ssl.SSLError, OSError, ValueError, http.client.HTTPException) as e:
        if "timed out" in str(e):
            return Resp(None, {}, error=f"timeout: {e}", kind="TIMEOUT")
        return Resp(None, {}, error=f"{type(e).__name__}: {e}", kind="OTHER")


def request(url, method="GET", max_bytes=65536, extra_headers=None, sink=None, retries=3, check_robots=True):
    """One hop (no redirect following) through the host gate, with backoff on 429/5xx/transient errors."""
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if check_robots and not robots_allowed(url):
        return Resp(None, {}, error="disallowed by robots.txt", kind="ROBOTS")
    g = gate(host)
    attempt = 0
    while True:
        with g:
            r = _one(url, method, max_bytes, extra_headers, sink)
        retry = (r.code in (429, 502, 503, 504)) or (r.code is None and r.kind in ("TIMEOUT", "OTHER")
                                                       and "Name or service not known" not in (r.error or "")
                                                       and "CERTIFICATE" not in (r.error or ""))
        if not retry or attempt >= retries:
            if r.code == 429:
                g.penalty = min(g.penalty * 2, 8)
            return r
        attempt += 1
        wait = 2 ** attempt + random.random()
        ra = r.headers.get("retry-after")
        if ra and ra.isdigit():
            wait = max(wait, min(int(ra), 120))
        if r.code == 429:
            g.penalty = min(g.penalty * 2, 8)
        time.sleep(wait)


def fetch(url, method="HEAD", max_bytes=65536, sink=None, max_hops=10, retries=3):
    """Follow redirects manually (robots + gate on every hop). Returns (Resp, final_url, hops)."""
    hops = []
    current = url
    for _ in range(max_hops + 1):
        r = request(current, method, max_bytes=max_bytes, sink=sink, retries=retries)
        if r.code in (301, 302, 303, 307, 308) and r.headers.get("location"):
            nxt = urllib.parse.urljoin(current, r.headers["location"])
            hops.append((r.code, current))
            current = nxt
            continue
        return r, current, hops
    return Resp(None, {}, error="too many redirects", kind="OTHER"), current, hops


# ---------------------------------------------------------------- robots.txt (RFC 9309 matching)

_ROBOTS: dict = {}
_ROBOTS_LOCK = threading.Lock()
_ROBOTS_HOST_LOCKS: dict = {}
ROBOTS_DELAY: dict = {}


def _parse_robots(text):
    groups, current, saw_rule = [], None, False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            if current is None or saw_rule:
                current = {"agents": [], "rules": [], "delay": None}
                groups.append(current)
                saw_rule = False
            current["agents"].append(value.lower())
        elif key in ("allow", "disallow") and current is not None:
            saw_rule = True
            if value or key == "allow":
                current["rules"].append((key == "allow", value))
        elif key == "crawl-delay" and current is not None:
            saw_rule = True
            try:
                current["delay"] = float(value)
            except ValueError:
                pass
    mine = [g for g in groups if any(a and a != "*" and a in UA_TOKEN for a in g["agents"])]
    chosen = mine or [g for g in groups if "*" in g["agents"]]
    rules, delay = [], None
    for g in chosen:
        rules.extend(g["rules"])
        if g["delay"] is not None:
            delay = g["delay"]
    compiled = []
    for allow, pat in rules:
        if not pat:
            continue
        anchored = pat.endswith("$")
        body = pat[:-1] if anchored else pat
        regex = "".join(".*" if ch == "*" else re.escape(ch) for ch in body)
        compiled.append((allow, len(pat), re.compile(regex + ("$" if anchored else ""))))
    return {"rules": compiled, "delay": delay}


def _robots_for(scheme, host, port):
    base = f"{scheme}://{host}" + (f":{port}" if port else "")
    with _ROBOTS_LOCK:
        if base in _ROBOTS:
            return _ROBOTS[base]
        lock = _ROBOTS_HOST_LOCKS.setdefault(base, threading.Lock())
    with lock:
        with _ROBOTS_LOCK:
            if base in _ROBOTS:
                return _ROBOTS[base]
        cache = STATE / "robots" / (hashlib.sha256(base.encode()).hexdigest()[:24] + ".json")
        entry = None
        if cache.exists() and time.time() - cache.stat().st_mtime < 86400:
            entry = json.loads(cache.read_text())
        if entry is None:
            r, final, _ = None, None, None
            url = base + "/robots.txt"
            for _ in range(5):
                r = request(url, "GET", max_bytes=512 * 1024, check_robots=False, retries=2)
                if r.code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                    url = urllib.parse.urljoin(url, r.headers["location"])
                    continue
                break
            if r.code is not None and 200 <= r.code < 300:
                entry = {"mode": "rules", "text": r.body.decode("utf-8", "replace")}
            elif r.code is not None and 400 <= r.code < 500:
                entry = {"mode": "allow_all", "code": r.code}
            elif r.code is not None and r.code >= 500:
                entry = {"mode": "disallow_all", "code": r.code}       # RFC 9309 2.3.1.4
            else:
                entry = {"mode": "unreachable", "error": r.error}     # actual request will report the failure
            entry["fetched_at"] = utc()
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(entry))
        parsed = _parse_robots(entry["text"]) if entry["mode"] == "rules" else {"rules": [], "delay": None}
        parsed["mode"] = entry["mode"]
        if parsed.get("delay"):
            ROBOTS_DELAY[host] = min(parsed["delay"], 10.0)
        with _ROBOTS_LOCK:
            _ROBOTS[base] = parsed
        return parsed


def robots_allowed(url):
    parts = urllib.parse.urlsplit(url)
    rb = _robots_for(parts.scheme, (parts.hostname or "").lower(), parts.port)
    if rb["mode"] == "disallow_all":
        return False
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    best = None
    for allow, length, rx in rb["rules"]:
        if rx.match(path):
            if best is None or length > best[1] or (length == best[1] and allow):
                best = (allow, length)
    return True if best is None else best[0]


# ---------------------------------------------------------------- classification

def classify(resp, url, final_url, hops):
    """OK / REDIRECT_OK / NOT_FOUND / GONE / FORBIDDEN / ROBOTS / TIMEOUT / OTHER plus a note."""
    if resp.kind in ("ROBOTS", "TIMEOUT"):
        return resp.kind, resp.error or ""
    if resp.code is None:
        return "OTHER", resp.error or "no response"
    code = resp.code
    if 200 <= code < 300:
        if hops and final_url != url:
            fp = urllib.parse.urlsplit(final_url)
            op = urllib.parse.urlsplit(url)
            if fp.path in ("", "/") and op.path not in ("", "/") and not fp.query:
                return "NOT_FOUND", "soft404: redirected to site root"
            return "REDIRECT_OK", ""
        return "OK", ""
    if code == 404:
        return "NOT_FOUND", ""
    if code == 410:
        return "GONE", ""
    if code in (401, 403, 451):
        if resp.headers.get("cf-mitigated"):
            return "FORBIDDEN", f"cloudflare {resp.headers['cf-mitigated']} (bot wall, not bypassed)"
        return "FORBIDDEN", ""
    if code == 429:
        return "OTHER", "rate limited (429) after retries"
    return "OTHER", f"http {code}"


def check_link(url):
    """HEAD, falling back to a short GET when HEAD is refused or unhelpful."""
    resp, final, hops = fetch(url, "HEAD")
    method = "HEAD"
    if resp.kind != "ROBOTS" and (resp.code is None or not (200 <= resp.code < 300)) and resp.code not in (404, 410):
        r2, f2, h2 = fetch(url, "GET", max_bytes=16384)
        if r2.code is not None or resp.code is None:
            resp, final, hops, method = r2, f2, h2, "GET"
    elif resp.code in (404, 410):
        # some servers 404 HEAD but serve GET; confirm cheaply
        r2, f2, h2 = fetch(url, "GET", max_bytes=16384)
        if r2.code is not None and 200 <= r2.code < 300:
            resp, final, hops, method = r2, f2, h2, "GET"
    status, note = classify(resp, url, final, hops)
    final = sanitize_url(final)
    ctype = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
    return {"status": status, "http_code": resp.code, "final_url": final if final != url else "",
            "hops": len(hops), "method": method, "content_type": ctype, "note": note, "error": resp.error or ""}


SIGNED_KEYS = ("x-amz-", "signature", "token", "expires", "sig", "awsaccesskeyid", "policy", "key-pair-id")


def sanitize_url(url):
    """Drop query strings of pre-signed / tokenised redirect targets (ephemeral, credential-like)."""
    parts = urllib.parse.urlsplit(url)
    if parts.query and any(k.lower().startswith(SIGNED_KEYS) for k, _ in urllib.parse.parse_qsl(parts.query)):
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")) + "?<signed-query-removed>"
    return url


def wayback_lookup(url, when=None):
    """Closest Wayback snapshot via the availability API, CDX API as fallback. Returns (archive_url, ts, how)."""
    ts = re.sub(r"[^0-9]", "", when or "")[:14]
    q = "https://archive.org/wayback/available?url=" + urllib.parse.quote(url, safe="") + (f"&timestamp={ts}" if ts else "")
    r, _, _ = fetch(q, "GET", max_bytes=1 << 20)
    if r.code == 200:
        try:
            snap = json.loads(r.body.decode("utf-8")).get("archived_snapshots", {}).get("closest") or {}
            if snap.get("available") and str(snap.get("status", "200")).startswith(("2", "3")):
                return snap["url"].replace("http://web.archive.org", "https://web.archive.org"), snap.get("timestamp"), "availability"
        except (ValueError, AttributeError):
            pass
    cdx = ("https://web.archive.org/cdx/search/cdx?output=json&limit=-1&fl=timestamp,original,statuscode"
           "&filter=statuscode:200&url=" + urllib.parse.quote(url, safe=""))
    r, _, _ = fetch(cdx, "GET", max_bytes=1 << 20)
    if r.code == 200:
        try:
            rows = json.loads(r.body.decode("utf-8") or "[]")
            if len(rows) > 1:
                t, orig = rows[-1][0], rows[-1][1]
                return f"https://web.archive.org/web/{t}/{orig}", t, "cdx"
        except ValueError:
            pass
        return "", "", "none"
    return "", "", f"lookup_failed:{r.code or r.error}"
