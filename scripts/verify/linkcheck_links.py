"""Release link check (steps 1-2) and GitHub pinned-blob verification.

  python3 -I scripts/verify/linkcheck_links.py http      # reachability of every report link (resumable)
  python3 -I scripts/verify/linkcheck_links.py github    # GitHub API: pinned blob == corpus file; HEAD-of-branch state
  python3 -I scripts/verify/linkcheck_links.py wayback   # Wayback snapshot for every non-OK link
  python3 -I scripts/verify/linkcheck_links.py csv       # docs/release/link_status.csv

GitHub links are checked at their commit-pinned permalink. GITHUB_TOKEN (optional) is used only for
api.github.com reads and is never written anywhere.
"""
from __future__ import annotations

import csv
import json
import os
import queue
import re
import sys
import threading
import time
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import linkcheck_common as C  # noqa: E402

HTTP_STATE = C.STATE / "links_http.jsonl"
GH_STATE = C.STATE / "github_api.jsonl"
GH_ROWS = C.STATE / "github_rows.jsonl"
WB_STATE = C.STATE / "wayback.jsonl"
CSV_OUT = C.ROOT / "docs/release/link_status.csv"
C.HOST_INTERVAL["api.github.com"] = 0.5
C.HOST_INTERVAL["archive.org"] = 1.0


def entries():
    """Unique (sha256, url) link entries."""
    out = {}
    for row in C.report_rows():
        key = (row["sha256"], row["public_url"])
        parts = C.github_parts(row)
        e = out.get(key)
        if e is None:
            e = out[key] = {
                "sha256": row["sha256"], "url": row["public_url"], "firm_ids": [], "source_kind": row.get("source_kind"),
                "file_format": row.get("file_format"), "retrieved_utc": row.get("retrieved_utc"),
                "permalink": C.permalink(parts) if parts else "", "gh": list(parts) if parts else None,
                "git_blob": C.notes_git_blob(row), "local_path": row.get("local_path"),
                "lfs_oid": C.lfs_oid(row),
            }
        if row["firm_id"] not in e["firm_ids"]:
            e["firm_ids"].append(row["firm_id"])
    for e in out.values():
        e["check_url"] = e["permalink"] or e["url"]
    return list(out.values())


def latest(path, key):
    got = {}
    for rec in C.read_jsonl(path):
        got[rec[key]] = rec
    return got


# ---------------------------------------------------------------- step 1: HTTP

def run_http(recheck_failed=False):
    ents = entries()
    done = latest(HTTP_STATE, "check_url")
    todo = sorted({e["check_url"] for e in ents})
    if recheck_failed:
        todo = [u for u in todo if u not in done or done[u]["status"] in ("OTHER", "TIMEOUT")]
    else:
        todo = [u for u in todo if u not in done]
    by_host = defaultdict(list)
    for u in todo:
        by_host[(urllib.parse.urlsplit(u).hostname or "").lower()].append(u)
    print(f"{len(todo)} URLs to check across {len(by_host)} hosts", flush=True)
    writer = C.JsonlWriter(HTTP_STATE)
    counter = Counter()
    lock = threading.Lock()
    t0 = time.time()

    def worker(q):
        while True:
            try:
                url = q.get_nowait()
            except queue.Empty:
                return
            try:
                res = C.check_link(url)
            except Exception as exc:  # never let one URL kill the sweep
                res = {"status": "OTHER", "http_code": None, "final_url": "", "hops": 0, "method": "",
                       "content_type": "", "note": "", "error": f"checker exception {type(exc).__name__}: {exc}"}
            res.update({"check_url": url, "checked_at": C.utc()})
            writer.write(res)
            with lock:
                counter[res["status"]] += 1
                n = sum(counter.values())
                if n % 250 == 0:
                    print(f"[{time.time() - t0:7.0f}s] {n}/{len(todo)} {dict(counter)}", flush=True)

    threads = []
    for host, urls in by_host.items():
        q = queue.Queue()
        for u in urls:
            q.put(u)
        for _ in range(min(C.MAX_CONCURRENCY, len(urls))):
            t = threading.Thread(target=worker, args=(q,), daemon=True)
            t.start()
            threads.append(t)
    for t in threads:
        t.join()
    print(f"done {dict(counter)} in {time.time() - t0:.0f}s", flush=True)


# ---------------------------------------------------------------- GitHub API

def api_get(path):
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    url = "https://api.github.com" + path
    for _ in range(5):
        r = C.request(url, "GET", max_bytes=200 << 20, extra_headers=headers, check_robots=False)
        if r.code in (301, 302, 307, 308) and r.headers.get("location"):
            url = urllib.parse.urljoin(url, r.headers["location"])
            continue
        if r.code == 403 and r.headers.get("x-ratelimit-remaining") == "0":
            reset = int(r.headers.get("x-ratelimit-reset", "0"))
            time.sleep(max(5, min(reset - time.time() + 5, 3700)))
            continue
        if r.headers.get("x-ratelimit-remaining", "9999").isdigit() and int(r.headers["x-ratelimit-remaining"]) < 300:
            print("GitHub API budget low; pausing 10 min", flush=True)
            time.sleep(600)
        data = None
        if r.code == 200:
            data = json.loads(r.body.decode("utf-8"))
        return r.code, data
    return None, None


def tree_map(repo, ref):
    code, data = api_get(f"/repos/{repo}/git/trees/{urllib.parse.quote(ref, safe='')}?recursive=1")
    if code != 200:
        return code, None, False
    return code, {t["path"]: t["sha"] for t in data.get("tree", []) if t.get("type") == "blob"}, bool(data.get("truncated"))


def contents_sha(repo, path, ref):
    code, data = api_get(f"/repos/{repo}/contents/{C.quote_path(path)}?ref={urllib.parse.quote(ref, safe='')}")
    if code == 200 and isinstance(data, dict):
        return data.get("sha")
    return None


def run_github():
    ents = [e for e in entries() if e["gh"]]
    done = latest(GH_STATE, "key")
    writer = C.JsonlWriter(GH_STATE)
    repos = sorted({e["gh"][0] for e in ents})
    pins = sorted({(e["gh"][0], e["gh"][1]) for e in ents})
    print(f"{len(ents)} GitHub links, {len(repos)} repos, {len(pins)} pinned commits", flush=True)

    def work(kind, repo, ref=None):
        key = f"{kind}|{repo}|{ref or ''}"
        if key in done:
            return done[key]
        if kind == "repo":
            code, data = api_get(f"/repos/{repo}")
            rec = {"key": key, "code": code, "full_name": (data or {}).get("full_name"),
                   "default_branch": (data or {}).get("default_branch"), "archived": (data or {}).get("archived"),
                   "checked_at": C.utc()}
        else:
            code, tmap, truncated = tree_map(repo, ref)
            rec = {"key": key, "code": code, "tree": tmap, "truncated": truncated, "checked_at": C.utc()}
        writer.write(rec)
        done[key] = rec
        return rec

    # repo metadata, then pinned trees, then default-branch trees (2 concurrent API requests max)
    jobs = queue.Queue()
    for r in repos:
        jobs.put(("repo", r, None))
    for r, c in pins:
        jobs.put(("tree", r, c))

    def drain():
        while True:
            try:
                job = jobs.get_nowait()
            except queue.Empty:
                return
            work(*job)
    ths = [threading.Thread(target=drain) for _ in range(2)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    for r in repos:
        info = done[f"repo|{r}|"]
        if info["code"] == 200 and info["default_branch"]:
            jobs.put(("tree", info["full_name"], info["default_branch"]))
    ths = [threading.Thread(target=drain) for _ in range(2)]
    [t.start() for t in ths]
    [t.join() for t in ths]

    # per-link evaluation
    out = []
    for i, e in enumerate(ents):
        repo, commit, path = e["gh"]
        local = C.ROOT / e["local_path"] if e.get("local_path") else None
        local_blob = C.git_blob_sha(local) if local and local.is_file() else None
        expected = local_blob or e["git_blob"]
        info = done[f"repo|{repo}|"]
        pin = done[f"tree|{repo}|{commit}"]
        if pin["code"] == 200:
            sha = pin["tree"].get(path)
            if sha is None and pin["truncated"]:
                sha = contents_sha(repo, path, commit)
            pinned = ("MATCH" if sha == expected else "BLOB_DIFFERS") if sha else "PATH_MISSING"
            if pinned == "BLOB_DIFFERS" and e.get("lfs_oid") == e["sha256"]:
                code, blob = api_get(f"/repos/{repo}/git/blobs/{sha}")
                content = ""
                if code == 200 and blob and blob.get("encoding") == "base64":
                    import base64
                    content = base64.b64decode(blob["content"]).decode("utf-8", "replace")
                if f"oid sha256:{e['sha256']}" in content:
                    pinned, expected = "MATCH_LFS_POINTER", sha   # pinned blob is a Git LFS pointer to our sha256
        elif info["code"] == 404:
            pinned, sha = "REPO_MISSING", None
        else:
            pinned, sha = f"COMMIT_UNAVAILABLE_{pin['code']}", None
        head_status, head_url = "", ""
        if info["code"] == 200 and info["default_branch"]:
            ht = done.get(f"tree|{info['full_name']}|{info['default_branch']}")
            if ht and ht["code"] == 200:
                hsha = ht["tree"].get(path)
                if hsha is None and ht["truncated"]:
                    hsha = contents_sha(info["full_name"], path, info["default_branch"])
                if hsha and hsha == expected:
                    head_status, hpath = "SAME", path
                elif hsha:
                    head_status, hpath = "UPDATED", path
                else:
                    moved = [p for p, s in ht["tree"].items() if s == expected]
                    head_status, hpath = ("MOVED", sorted(moved)[0]) if moved else ("REMOVED", "")
                if hpath:
                    head_url = f"https://github.com/{info['full_name']}/blob/{info['default_branch']}/{C.quote_path(hpath)}"
            else:
                head_status = f"HEAD_TREE_UNAVAILABLE_{ht['code'] if ht else 'none'}"
        elif info["code"] == 404:
            head_status = "REPO_MISSING"
        out.append({"sha256": e["sha256"], "url": e["url"], "repo": repo, "commit": commit, "path": path,
                    "renamed_to": info.get("full_name") if info.get("full_name") and info["full_name"].lower() != repo.lower() else "",
                    "archived": info.get("archived"), "expected_blob": expected, "local_blob_computed": bool(local_blob),
                    "notes_blob_agrees": (e["git_blob"] == local_blob) if (e["git_blob"] and local_blob) else None,
                    "pinned_blob": sha, "pinned_status": pinned, "head_status": head_status, "head_url": head_url})
        if (i + 1) % 1000 == 0:
            print(f"evaluated {i + 1}/{len(ents)}", flush=True)
    GH_ROWS.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in out))
    print("pinned", dict(Counter(r["pinned_status"] for r in out)))
    print("head", dict(Counter(r["head_status"] for r in out)))


# ---------------------------------------------------------------- step 2: Wayback

def wayback_original(url):
    m = re.match(r"^https?://web\.archive\.org/web/[0-9a-z_]+/(.+)$", url)
    return m.group(1) if m else None


def run_wayback():
    ents = entries()
    http = latest(HTTP_STATE, "check_url")
    done = latest(WB_STATE, "url")
    targets = {}
    for e in ents:
        res = http.get(e["check_url"])
        if res and res["status"] not in ("OK", "REDIRECT_OK"):
            for u in ([e["check_url"], e["url"]] if e["check_url"] != e["url"] else [e["url"]]):
                u = wayback_original(u) or u      # a dead archive URL: look up the page it archived
                if u not in done:
                    targets.setdefault(u, e.get("retrieved_utc"))
    print(f"{len(targets)} URLs need a Wayback lookup", flush=True)
    writer = C.JsonlWriter(WB_STATE)
    for i, (u, when) in enumerate(sorted(targets.items())):
        arch, ts, how = C.wayback_lookup(u, when)
        writer.write({"url": u, "archive_url": arch, "timestamp": ts, "how": how, "checked_at": C.utc()})
        if (i + 1) % 50 == 0:
            print(f"wayback {i + 1}/{len(targets)}", flush=True)


# ---------------------------------------------------------------- soft-404 probe

SOFT_STATE = C.STATE / "soft404_probe.jsonl"


def run_soft404(min_links=10):
    """One deliberately nonexistent URL per host with >= min_links links: does the host answer 200 anyway?"""
    ents = entries()
    by_host = defaultdict(list)
    for e in ents:
        by_host[(urllib.parse.urlsplit(e["check_url"]).hostname or "").lower()].append(e["check_url"])
    writer = C.JsonlWriter(SOFT_STATE)
    for host, urls in sorted(by_host.items()):
        if len(urls) < min_links:
            continue
        sample = sorted(urls)[0]
        parts = urllib.parse.urlsplit(sample)
        path = parts.path.rstrip("/")
        head, _, last = path.rpartition("/")
        stem, dot, ext = last.rpartition(".") if "." in last else (last, "", "")
        bogus_last = f"{stem}-linkcheck-nonexistent-{C.SEED}" + (dot + ext if dot else "")
        bogus = urllib.parse.urlunsplit((parts.scheme, parts.netloc, f"{head}/{bogus_last}", "", ""))
        res = C.check_link(bogus)
        writer.write({"host": host, "links": len(urls), "probe_url": bogus, "status": res["status"],
                      "http_code": res["http_code"], "final_url": res["final_url"], "checked_at": C.utc()})
        print(host, len(urls), res["status"], res["http_code"], flush=True)


# ---------------------------------------------------------------- CSV

FIELDS = ["sha256", "url", "final_url", "permalink", "status", "http_code", "archive_url", "checked_at",
          "firm_ids", "source_kind", "file_format", "method", "content_type", "note",
          "github_pinned_status", "github_head_status", "github_head_url"]


def run_csv():
    ents = entries()
    http = latest(HTTP_STATE, "check_url")
    wb = latest(WB_STATE, "url")
    gh = {(r["sha256"], r["url"]): r for r in C.read_jsonl(GH_ROWS)}
    rows = []
    missing = 0
    for e in sorted(ents, key=lambda e: (e["firm_ids"][0], e["sha256"], e["url"])):
        res = http.get(e["check_url"])
        if res is None:
            missing += 1
            res = {"status": "", "http_code": "", "final_url": "", "checked_at": "", "method": "", "content_type": "",
                   "note": "not checked"}
        arch = ""
        if res["status"] not in ("OK", "REDIRECT_OK", ""):
            keys = [wayback_original(e["check_url"]) or e["check_url"], wayback_original(e["url"]) or e["url"]]
            arch = next(((wb.get(k) or {}).get("archive_url") for k in keys if (wb.get(k) or {}).get("archive_url")), "")
            if arch == e["url"]:
                arch = ""
        note = (res.get("note") or res.get("error") or "").replace("(bot wall; not bypassed)", "(bot wall, not bypassed)")
        if res["status"] in ("OK", "REDIRECT_OK") and e["file_format"] == "pdf" and res.get("content_type") == "text/html" \
                and not e["permalink"]:
            note = (note + "; " if note else "") + "html served for pdf original (viewer/landing page)"
        g = gh.get((e["sha256"], e["url"]), {})
        rows.append({"sha256": e["sha256"], "url": e["url"], "final_url": res.get("final_url") or "",
                     "permalink": e["permalink"], "status": res["status"], "http_code": res.get("http_code") or "",
                     "archive_url": arch, "checked_at": res.get("checked_at") or "", "firm_ids": ";".join(e["firm_ids"]),
                     "source_kind": e["source_kind"], "file_format": e["file_format"],
                     "method": res.get("method") or "", "content_type": res.get("content_type") or "", "note": note,
                     "github_pinned_status": g.get("pinned_status", ""), "github_head_status": g.get("head_status", ""),
                     "github_head_url": g.get("head_url", "")})
    CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(CSV_OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows ({missing} unchecked) to {CSV_OUT}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "http"
    {"http": lambda: run_http("--recheck-failed" in sys.argv), "github": run_github, "wayback": run_wayback,
     "soft404": run_soft404, "csv": run_csv}[cmd]()
