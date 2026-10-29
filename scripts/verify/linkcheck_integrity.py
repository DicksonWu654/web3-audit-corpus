"""Step 3: integrity re-download for a stratified random sample of reports.

  python3 -I scripts/verify/linkcheck_integrity.py [--n 400]

Stratum = publisher (first firm_id of the sha256); min 2 per publisher, remainder proportional; seeded.
Each original is re-downloaded (commit-pinned raw file for GitHub, else the recorded retrieval/download URL, else
public_url) into a fresh batch directory under local-cache/linkcheck/ and its sha256 compared with the corpus.

Sherlock contest Markdown is re-derived exactly as collected (the `report` field of the official contest JSON).

Outcomes: MATCH; CHANGED_MARKUP_ONLY (HTML bytes differ but the visible text is identical: dynamic markup);
CHANGED (publisher now serves different content); NOT_DIRECT (the link serves an HTML page while the corpus file is a
derived rendition or API payload, so a byte comparison is impossible by construction); FAILED (HTTP error/timeout/robots).
"""
from __future__ import annotations

import difflib
import html
import json
import random
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import linkcheck_common as C  # noqa: E402

SAMPLE = C.STATE / "integrity_sample.json"
RESULTS = C.STATE / "integrity_results.jsonl"
MAX_BYTES = 400 << 20


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "svg"):
            self.skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "svg"):
            self.skip = max(0, self.skip - 1)

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_text(data):
    p = _Text()
    try:
        p.feed(data.decode("utf-8", "replace"))
    except Exception:
        return ""
    return re.sub(r"\s+", " ", html.unescape(" ".join(p.parts))).strip()


def sample(n):
    by_sha = {}
    for row in C.report_rows():
        by_sha.setdefault(row["sha256"], row)
    strata = defaultdict(list)
    for sha, row in sorted(by_sha.items()):
        strata[row["firm_id"]].append(sha)
    alloc = C.allocate({k: len(v) for k, v in strata.items()}, n)
    rng = random.Random(C.SEED)
    chosen = []
    for firm in sorted(strata):
        chosen += rng.sample(strata[firm], alloc[firm])
    return [by_sha[s] for s in chosen], alloc


def looks_html(head):
    h = head[:2048].lstrip().lower()
    return h.startswith((b"<!doctype html", b"<html")) or b"<html" in h[:1024]


SHERLOCK_JSON = re.compile(r"contest detail JSON report field: (https://mainnet-contest\.sherlock\.xyz/contests/\d+)")


def sherlock(row, batch):
    m = SHERLOCK_JSON.search(row.get("notes") or "")
    if not m:
        return None
    resp, final, hops = C.fetch(m.group(1), "GET", max_bytes=200 << 20)
    tried = [{"url": m.group(1), "how": "sherlock_contest_json.report", "code": resp.code, "error": resp.error}]
    if resp.code == 200:
        try:
            report = json.loads(resp.body.decode("utf-8")).get("report")
        except ValueError:
            report = None
        if isinstance(report, str):
            data = report.encode("utf-8")
            got = C.sha256_bytes(data)
            if got != row["sha256"]:
                (batch / f"{row['sha256']}.sherlock.md").write_bytes(data)
            return tried, {"downloaded_sha256": got, "bytes": len(data), "final_url": m.group(1),
                           "content_type": "text/markdown", "outcome": "MATCH" if got == row["sha256"] else "CHANGED"}
    status, note = C.classify(resp, m.group(1), final, hops)
    return tried, {"outcome": "FAILED", "fail_status": status, "http_code": resp.code, "error": resp.error or note}


def one(row, batch):
    sha = row["sha256"]
    tried = []
    url, how = C.download_url(row)
    candidates = [(url, how)] + ([(row["public_url"], "public_url")] if url != row["public_url"] else [])
    result = None
    special = sherlock(row, batch)
    if special:
        tried, result = special
        candidates = []
    for u, h in candidates:
        sink = batch / f"{sha}.{len(tried)}.bin"
        resp, final, hops = C.fetch(u, "GET", max_bytes=MAX_BYTES, sink=sink)
        tried.append({"url": u, "how": h, "code": resp.code, "error": resp.error})
        if resp.code is not None and 200 <= resp.code < 300 and resp.headers.get("x-sha256"):
            got = resp.headers["x-sha256"]
            head = sink.read_bytes()[:4096]
            rec = {"downloaded_sha256": got, "bytes": int(resp.headers["x-bytes"]), "final_url": C.sanitize_url(final),
                   "content_type": (resp.headers.get("content-type") or "").split(";")[0]}
            if got == sha:
                sink.unlink()
                result = dict(rec, outcome="MATCH")
                break
            fmt = row.get("file_format")
            if fmt != "html" and looks_html(head) and not (fmt == "other" and looks_html_local(row)):
                outcome = "NOT_DIRECT"
            else:
                outcome = "CHANGED"
            if outcome == "CHANGED" and (fmt == "html" or looks_html(head)):
                local = C.local_original(row)
                if local:
                    a, b = html_text(local.read_bytes()), html_text(sink.read_bytes())
                    rec["html_text_identical"] = a == b
                    rec["html_text_chars"] = [len(a), len(b)]
                    if a == b:
                        outcome = "CHANGED_MARKUP_ONLY"
                    else:
                        rec["html_text_ratio"] = round(difflib.SequenceMatcher(None, a[:50000], b[:50000],
                                                                               autojunk=False).ratio(), 4)
            if outcome == "CHANGED" and fmt == "pdf":
                rec["is_pdf"] = head.startswith(b"%PDF")
            result = dict(rec, outcome=outcome)
            if outcome == "CHANGED":
                break
        else:
            if sink.exists():
                sink.unlink()
            status, note = C.classify(resp, u, final, hops)
            result = {"outcome": "FAILED", "fail_status": status, "http_code": resp.code, "error": resp.error or note}
    base = {"sha256": sha, "firm_id": row["firm_id"], "source_kind": row.get("source_kind"),
            "file_format": row.get("file_format"), "public_url": row["public_url"], "tried": tried, "checked_at": C.utc()}
    return dict(base, **result)


def looks_html_local(row):
    p = C.local_original(row)
    return bool(p) and looks_html(p.read_bytes()[:4096])


def main():
    n = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 400
    rows, alloc = sample(n)
    SAMPLE.write_text(json.dumps({"n": len(rows), "seed": C.SEED, "allocation": alloc,
                                  "sha256": [r["sha256"] for r in rows]}, indent=1))
    batch = C.fresh_batch("integrity")
    print(f"sample {len(rows)} reports; downloads -> {batch}", flush=True)
    out = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for i, res in enumerate(ex.map(lambda r: one(r, batch), rows)):
            out.append(res)
            if (i + 1) % 50 == 0:
                print(f"{i + 1}/{len(rows)} {dict(Counter(r['outcome'] for r in out))}", flush=True)
    RESULTS.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in out))
    print(dict(Counter(r["outcome"] for r in out)))


if __name__ == "__main__":
    main()
