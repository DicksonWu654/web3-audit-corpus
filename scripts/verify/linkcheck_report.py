"""Render docs/release/links.md from docs/release/link_status.csv and the linkcheck state files.

  python3 -I scripts/verify/linkcheck_report.py
"""
from __future__ import annotations

import csv
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import linkcheck_common as C  # noqa: E402

CSV_IN = C.ROOT / "docs/release/link_status.csv"
OUT = C.ROOT / "docs/release/links.md"
STATUSES = ["OK", "REDIRECT_OK", "NOT_FOUND", "GONE", "FORBIDDEN", "ROBOTS", "TIMEOUT", "OTHER"]
TEXT = ["PASS_EXACT", "PASS_NORMALIZED", "FAIL_PARTIAL", "FAIL_NOT_FOUND", "FETCH_FAILED"]
INTEG = ["MATCH", "CHANGED_MARKUP_ONLY", "CHANGED", "NOT_DIRECT", "FAILED"]


def wilson(k, n, z=1.96):
    if not n:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (100 * (c - h), 100 * (c + h))


def pct(k, n):
    return f"{100 * k / n:.1f}%" if n else "-"


def table(header, rows):
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" if i == 0 else "---:" for i in range(len(header))) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def main():
    rows = list(csv.DictReader(open(CSV_IN, encoding="utf-8")))
    checked = [r for r in rows if r["status"]]
    dates = sorted(r["checked_at"] for r in checked if r["checked_at"])
    L = []
    L.append("# Release link and source verification\n")
    L.append(f"Checked {dates[0][:10]} to {dates[-1][:10]} (UTC). Producer scripts: `scripts/verify/linkcheck_links.py` "
             "(reachability, GitHub pinned-blob check, Wayback), `linkcheck_integrity.py` (sha256 re-download sample), "
             "`linkcheck_text.py` (finding-text sample), `linkcheck_report.py` (this file). Row-level output: "
             "`docs/release/link_status.csv` (one row per distinct report sha256 + url; join on `sha256`, `url`).\n")
    L.append("Method: every `public_url` in `data/collect/*/reports.jsonl` of in-scope publishers (CertiK skipped). "
             "GitHub-hosted reports are checked at their commit-pinned blob permalink. HEAD first, short GET fallback; "
             "redirects followed manually with robots.txt (RFC 9309 wildcard rules) honoured on every hop; per-host "
             f"concurrency <= {C.MAX_CONCURRENCY} (shared across processes), >= {C.HOST_INTERVAL['github.com']} s (github.com) / "
             f"{C.DEFAULT_INTERVAL:g} s (others, or robots Crawl-delay) between request starts per host, "
             "exponential backoff on 429/5xx; User-Agent `" + C.UA + "`. No logins, no challenge solving, "
             "no browser impersonation. Status classes: OK (2xx, no redirect), REDIRECT_OK (2xx after redirect, `final_url` "
             "recorded; pre-signed query strings stripped), NOT_FOUND (404, or redirect to the site root = soft 404), GONE "
             "(410), FORBIDDEN (401/403/451; Cloudflare challenges noted), ROBOTS (robots.txt disallows us), TIMEOUT, OTHER "
             "(DNS/TLS/connection errors, 5xx, persistent 429). Every non-OK link was looked up in the Wayback Machine "
             "availability API (CDX API fallback), closest to the corpus retrieval date.\n")

    # ---- overall
    n = len(rows)
    sc = Counter(r["status"] for r in rows)
    shas = defaultdict(set)
    for r in rows:
        shas[r["status"]].add(r["sha256"])
    nonok = [r for r in rows if r["status"] not in ("OK", "REDIRECT_OK")]
    arch = [r for r in nonok if r["archive_url"]]
    L.append("## Reachability\n")
    L.append(f"{n:,} distinct links ({len({r['sha256'] for r in rows}):,} distinct report sha256; "
             f"{len({r['url'] for r in rows}):,} distinct URLs). Reachable (OK + REDIRECT_OK): "
             f"**{sc['OK'] + sc['REDIRECT_OK']:,} ({pct(sc['OK'] + sc['REDIRECT_OK'], n)})**. Non-OK: {len(nonok):,}, of which "
             f"{len(arch):,} have a Wayback snapshot (`archive_url`) and {len(nonok) - len(arch):,} have none.\n")
    trows = []
    for s in STATUSES + ([""] if sc[""] else []):
        a = sum(1 for r in rows if r["status"] == s and r["archive_url"])
        trows.append([s or "(unchecked)", f"{sc[s]:,}", pct(sc[s], n), f"{len(shas[s]):,}",
                      "-" if s in ("OK", "REDIRECT_OK") else f"{a:,}"])
    L.append(table(["status", "links", "share", "report sha256", "with archive_url"], trows) + "\n")

    by_src = defaultdict(Counter)
    for r in rows:
        by_src[r["source_kind"]][r["status"]] += 1
    L.append("By source kind:\n")
    L.append(table(["source_kind", "links"] + STATUSES,
                   [[k, f"{sum(v.values()):,}"] + [f"{v[s]:,}" for s in STATUSES] for k, v in sorted(by_src.items())]) + "\n")

    notes = Counter()
    for r in rows:
        for part in (r["note"] or "").split("; "):
            if part and not part.startswith(("urlerror", "timeout", "checker")):
                notes[part] += 1
    if notes:
        L.append("Notable conditions (from `note`):\n")
        L.append(table(["note", "links"], [[k.replace("|", "/"), f"{v:,}"] for k, v in notes.most_common(12)]) + "\n")

    soft = C.read_jsonl(C.STATE / "soft404_probe.jsonl")
    if soft:
        latest_soft = {r["host"]: r for r in soft}
        weak = [r for r in latest_soft.values() if r["status"] in ("OK", "REDIRECT_OK")]
        L.append(f"Soft-404 probe: one deliberately nonexistent URL was requested on each of the {len(latest_soft)} hosts "
                 f"with >= 10 links. {len(latest_soft) - len(weak)} answered it with an error or a redirect to the site "
                 "root (so OK there means the specific document is served); "
                 + (", ".join(f"`{r['host']}` ({r['links']} links)" for r in sorted(weak, key=lambda r: r["host"]))
                    + " answered 200 for the nonexistent URL, so OK on those hosts only shows the host is up"
                    if weak else "none answered 200") + ".\n")

    # ---- per publisher
    L.append("## Per publisher\n")
    pub = defaultdict(Counter)
    pub_arch = Counter()
    for r in rows:
        f = r["firm_ids"].split(";")[0]
        pub[f][r["status"]] += 1
        if r["archive_url"] and r["status"] not in ("OK", "REDIRECT_OK"):
            pub_arch[f] += 1
    prow = []
    for f in sorted(pub, key=lambda f: (-sum(pub[f].values()), f)):
        v = pub[f]
        tot = sum(v.values())
        bad = tot - v["OK"] - v["REDIRECT_OK"]
        prow.append([f, f"{tot:,}", pct(v["OK"] + v["REDIRECT_OK"], tot)] + [f"{v[s]:,}" if v[s] else "" for s in STATUSES]
                    + [f"{pub_arch[f]}/{bad}" if bad else ""])
    L.append(table(["publisher", "links", "reachable"] + STATUSES + ["archived/non-OK"], prow) + "\n")

    # ---- GitHub
    gh = C.read_jsonl(C.STATE / "github_rows.jsonl")
    if gh:
        L.append("## GitHub pinned permalinks\n")
        pc = Counter(r["pinned_status"] for r in gh)
        hc = Counter(r["head_status"] for r in gh)
        computed = sum(1 for r in gh if r["local_blob_computed"])
        agree = Counter(r["notes_blob_agrees"] for r in gh if r["notes_blob_agrees"] is not None)
        renamed = len({r["repo"] for r in gh if r["renamed_to"]})
        L.append(f"{len(gh):,} GitHub links across {len({r['repo'] for r in gh}):,} repositories / "
                 f"{len({(r['repo'], r['commit']) for r in gh}):,} pinned commits, verified through the GitHub REST API "
                 "(git trees at the pinned commit and at the default branch). The expected blob is the git blob SHA-1 "
                 f"computed from the corpus original ({computed:,} links; the collector-recorded `git_blob` agrees on "
                 f"{agree[True]:,}/{sum(agree.values()):,} where both exist). {renamed} repositories have since been renamed "
                 "(GitHub redirects the permalink).\n")
        L.append(table(["pinned commit check", "links"], [[k, f"{v:,}"] for k, v in pc.most_common()]) + "\n")
        L.append("State of the same file on the repository's default branch today (`github_head_status`; `github_head_url` "
                 "is the current branch URL when the file still exists):\n")
        desc = {"SAME": "same blob at the same path", "UPDATED": "path exists, different bytes (publisher updated the file)",
                "MOVED": "identical blob now at another path", "REMOVED": "file no longer on the default branch",
                "REPO_MISSING": "repository gone"}
        L.append(table(["head status", "links", "meaning"],
                       [[k or "(n/a)", f"{v:,}", desc.get(k, "")] for k, v in hc.most_common()]) + "\n")
        ch = [r for r in gh if r["head_status"] in ("UPDATED", "MOVED")]
        if ch:
            L.append("Files updated or moved on the default branch since collection (the pinned permalink still serves "
                     "the corpus bytes):\n")
            L.append(table(["head status", "repository", "path", "sha256"],
                           [[r["head_status"], r["repo"], r["path"].replace("|", "/"), r["sha256"][:12]]
                            for r in sorted(ch, key=lambda r: (r["head_status"], r["repo"], r["path"]))]) + "\n")
        rem = Counter(r["repo"] for r in gh if r["head_status"] == "REMOVED")
        if rem:
            L.append("Files no longer on the default branch, by repository:\n")
            L.append(table(["repository", "links"], [[k, v] for k, v in rem.most_common()]) + "\n")

    # ---- integrity
    integ = C.read_jsonl(C.STATE / "integrity_results.jsonl")
    if integ:
        samp = json.loads((C.STATE / "integrity_sample.json").read_text())
        ic = Counter(r["outcome"] for r in integ)
        k, m = ic["MATCH"], len(integ)
        lo, hi = wilson(k, m)
        L.append("## Integrity re-download (sha256)\n")
        L.append(f"Stratified random sample of {m} distinct reports (stratum = publisher, {len(samp['allocation'])} strata, "
                 f"min 2 each, remainder proportional; seed {samp['seed']}). Each was re-downloaded (GitHub: raw file at the "
                 "pinned commit; others: the recorded retrieval/download URL, else `public_url`) and hashed. "
                 f"**{k}/{m} byte-identical ({pct(k, m)}; Wilson 95% CI {lo:.1f}-{hi:.1f}%).**\n")
        pdfs = [r for r in integ if r["file_format"] == "pdf"]
        eq = ic["MATCH"] + ic["CHANGED_MARKUP_ONLY"]
        L.append(f"PDFs: {sum(r['outcome'] == 'MATCH' for r in pdfs)}/{len(pdfs)} byte-identical. Content-equivalent "
                 f"(byte-identical, or HTML whose visible text is identical and only markup differs): {eq}/{m} "
                 f"({pct(eq, m)}). HTML pages carry per-request markup (build ids, nonces), so their bytes differ from fetch "
                 "to fetch and repeated runs move items between MATCH and CHANGED_MARKUP_ONLY; NOT_DIRECT items are "
                 "corpus files derived from an API payload or a rendering (such as Quantstamp certificate data chunks), "
                 "whose `public_url` is the human-facing page.\n")
        L.append(table(["outcome", "reports"], [[s, ic[s]] for s in INTEG]) + "\n")
        bysk = defaultdict(Counter)
        for r in integ:
            bysk[f"{r['source_kind']}/{r['file_format']}"][r["outcome"]] += 1
        L.append(table(["source/format", "n"] + INTEG,
                       [[k2, sum(v.values())] + [v[s] for s in INTEG] for k2, v in sorted(bysk.items())]) + "\n")
        bad = [r for r in integ if r["outcome"] != "MATCH"]
        if bad:
            L.append("Non-matching items:\n")
            brow = []
            for r in sorted(bad, key=lambda r: (r["outcome"], r["firm_id"])):
                extra = ""
                if r["outcome"] == "FAILED":
                    extra = f"{r.get('fail_status')} {r.get('http_code') or ''} {(r.get('error') or '')[:60]}"
                elif "html_text_ratio" in r:
                    extra = f"HTML text similarity {r['html_text_ratio']}"
                    if r.get("html_text_chars"):
                        extra += f"; visible text {r['html_text_chars'][0]:,} chars in corpus vs {r['html_text_chars'][1]:,} now"
                elif r["outcome"] == "CHANGED_MARKUP_ONLY":
                    extra = "HTML markup differs; visible text identical"
                elif r["outcome"] == "NOT_DIRECT":
                    extra = f"served {r.get('content_type')}"
                elif r["outcome"] == "CHANGED":
                    extra = f"{r.get('content_type')}, {r.get('bytes'):,} bytes" + ("" if r.get("is_pdf", True) else ", not a PDF")
                brow.append([r["outcome"], r["firm_id"], r["sha256"][:12], f"{r['source_kind']}/{r['file_format']}",
                             r["public_url"].replace("|", "%7C")[:110], extra.replace("|", "/")])
            L.append(table(["outcome", "publisher", "sha256", "kind", "url", "detail"], brow) + "\n")

    # ---- text
    tx = C.read_jsonl(C.STATE / "text_results.jsonl")
    if tx:
        samp = json.loads((C.STATE / "text_sample.json").read_text())
        tc = Counter(r["cls"] for r in tx)
        m = len(tx)
        ok = tc["PASS_EXACT"] + tc["PASS_NORMALIZED"]
        lo, hi = wilson(ok, m)
        lo2, hi2 = wilson(ok, m - tc["FETCH_FAILED"])
        src = Counter(r.get("source") for r in tx)
        L.append("## Finding-text check\n")
        L.append(f"Stratified random sample of {m} findings from `data/findings` ({sum(samp['population'].values()):,} "
                 f"records in {len(samp['population'])} publisher strata, min 2 each, remainder proportional; seed "
                 f"{samp['seed']}). The original was re-downloaded and sha-verified ({src['web']} from the web; {src['local']} "
                 "used the sha-verified local original because the public link does not serve the exact bytes, e.g. a "
                 "landing page) and its text extracted independently of the corpus pipeline: `pdftotext -layout` (OCR with "
                 "tesseract only for pages with no usable text layer), raw UTF-8 for Markdown, tag-stripped text for HTML. "
                 f"The check: title and the first {200} characters of `body_text` must occur in that text. PASS_EXACT = after "
                 "whitespace collapsing only; PASS_NORMALIZED = after NFKC (ligatures), quote/dash folding, line-end "
                 "dehyphenation, case folding and removal of punctuation/markup.\n")
        L.append(f"**Pass: {ok}/{m} ({pct(ok, m)}; Wilson 95% CI {lo:.1f}-{hi:.1f}%)**; excluding fetch failures "
                 f"{ok}/{m - tc['FETCH_FAILED']} ({pct(ok, m - tc['FETCH_FAILED'])}; CI {lo2:.1f}-{hi2:.1f}%).\n")
        L.append(table(["class", "findings"], [[s, tc[s]] for s in TEXT]) + "\n")
        bym = defaultdict(Counter)
        for r in tx:
            bym[r.get("text_method") or "-"][r["cls"]] += 1
        L.append(table(["text method", "n"] + TEXT, [[k2, sum(v.values())] + [v[s] for s in TEXT] for k2, v in sorted(bym.items())]) + "\n")
        bad = [r for r in tx if r["cls"] not in ("PASS_EXACT", "PASS_NORMALIZED")]
        if bad:
            L.append("Failures:\n")
            L.append(table(["class", "publisher", "sha256", "finding", "title", "text method", "title found",
                            "body prefix found", "after dropping first body block"],
                           [[r["cls"], r["firm_id"], r["sha256"][:12], (r.get("publisher_finding_id") or "")[:20],
                             (r["title"] or "")[:60].replace("|", "/"), r.get("text_method", ""), r.get("title_norm", ""),
                             r.get("body_prefix_fraction", ""),
                             (f"{r['without_first_block_cls']} (dropped: `{r['first_block'].strip().replace('|', '/')}`)"
                              if r.get("without_first_block_cls") else "")]
                            for r in sorted(bad, key=lambda r: (r["cls"], r["firm_id"]))]) + "\n")
    OUT.write_text("\n".join(L), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
