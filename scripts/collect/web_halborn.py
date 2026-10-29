#!/usr/bin/env python3
"""Collect Halborn's public web audit catalogue alongside its GitHub archive.

The current Halborn site renders each audit as a substantive HTML report.  The
site catalogue is paged server-side and also exposes a JSON object in the
Next.js flight stream.  This collector reads that object as data, downloads
the report pages as HTML originals, and keeps the older GitHub collection in
the same contract files.  No page JavaScript is evaluated.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys
import argparse
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_batch2_common import CACHE, Fetcher, DOM, flight_objects, utc, write_json

ROOT = Path(__file__).resolve().parents[2]
FIRM = "halborn"
SITE = "https://www.halborn.com"
INDEX = SITE + "/audits"
CHECKPOINT = ROOT / "data" / "collect" / FIRM / "catalogue_refresh_site_reports.jsonl"


def is_catalogue_row(row: dict) -> bool:
    """Only replace this collector's Halborn HTML catalogue, preserving mirrors."""
    url = urlsplit(row.get("public_url") or "")
    return (row.get("source_kind") == "website" and row.get("file_format") == "html"
            and url.hostname in {"halborn.com", "www.halborn.com"}
            and url.path.startswith("/audits/"))


def retained_collection_rows(rows: list[dict]) -> list[dict]:
    return [row for row in rows if not is_catalogue_row(row)]


def norm(value: str) -> str:
    value = (value or "").casefold()
    value = re.sub(r"[^a-z0-9]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def month(value: str) -> str:
    m = re.search(r"(20\d{2})[-/]([01]\d)", value or "")
    return f"{m[1]}-{m[2]}" if m else ""


def project_tokens(value: str) -> set[str]:
    stop = {"halborn", "audit", "audits", "smart", "contract", "security",
            "assessment", "report", "review", "final", "updated", "code",
            "the", "and", "of", "for", "v", "version"}
    return {t for t in norm(value).split() if len(t) > 1 and t not in stop}


def project_match(site_project: str, old_project: str) -> bool:
    a, b = project_tokens(site_project), project_tokens(old_project)
    if not a or not b:
        return False
    # Company names in the website catalogue are a subset of the descriptive
    # GitHub filename/project hint.  Require all company tokens and avoid
    # short generic tokens as accidental matches.
    return all(any(len(t) >= 3 and (t == x or t in x or x in t) for x in b) for t in a)


def listing_items(fetch: Fetcher):
    entries, listing_urls = [], []
    seen = set()
    empty_pages = 0
    for page in range(1, 50):
        url = f"{INDEX}?page={page}"
        listing_urls.append(url)
        text = fetch.text(url, fresh="--refresh" in sys.argv)
        candidates = []
        for obj in flight_objects(text):
            if not isinstance(obj, dict):
                continue
            data = obj.get("initialData")
            if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                continue
            # The same flight payload can contain an object twice (once as a
            # decoded segment and once nested in a parent); use the first list.
            candidates = data["items"]
            if candidates:
                break
        if not candidates:
            empty_pages += 1
            if page > 23 or empty_pages >= 2:
                break
            continue
        empty_pages = 0
        for row in candidates:
            if not isinstance(row, dict):
                continue
            slug = row.get("slug")
            company = (row.get("company") or {}).get("name") or ""
            if not slug or not company:
                continue
            public = urljoin(SITE, "/audits/" + str(company).strip().casefold().replace(" ", "-") + "/" + slug)
            # The company slug has punctuation rules that differ from a simple
            # space replacement.  The href in the card is authoritative.
            dom = DOM(text)
            href = next((n.attrs.get("href") for n in dom.all("a")
                         if n.attrs.get("href", "").rstrip("/").endswith("/" + slug)), None)
            if href:
                public = urljoin(SITE, href)
            if public in seen:
                continue
            seen.add(public)
            raw_date = str(row.get("date") or "")
            try:
                date = datetime.fromisoformat(raw_date.replace("Z", "+00:00")).date().isoformat()
            except ValueError:
                date = str(row.get("year") or "")
            entries.append({
                "public_url": public,
                "listing_url": url,
                "title_hint": str(row.get("title") or "").strip(),
                "project_hint": company.strip(),
                "date_hint": date,
                "date_precision": "day" if len(date) == 10 else ("year" if len(date) == 4 else "none"),
                "date_basis": "listing",
                "audit_type": str(row.get("auditType") or "Security audit"),
                "notes": "Halborn audit catalogue; ecosystems=" + ",".join(map(str, row.get("ecosystems") or []))
                         + "; tags=" + ",".join(map(str, row.get("tags") or [])),
                "expected_format": "html",
            })
    if len(entries) < 200:
        raise RuntimeError(f"Halborn catalogue unexpectedly short: {len(entries)}")
    listing_urls.append(SITE + "/audits/feed.xml")
    return entries, listing_urls


def html_is_report(body: bytes) -> bool:
    text = DOM(body.decode("utf-8", errors="replace")).root.visible_text()
    lower = text.casefold()
    return len(text) >= 300 and ("findings" in lower or "audit scope" in lower or "security assessment" in lower)


def row_for(entry, body, retrieved):
    sha = hashlib.sha256(body).hexdigest()
    ext = "html"
    local = Path("local-cache/originals") / sha[:2] / f"{sha}.{ext}"
    target = ROOT / local
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_bytes(body)
    return {
        "firm_id": FIRM,
        "collector": "web_halborn",
        "source_kind": "website",
        "public_url": entry["public_url"],
        "listing_url": entry["listing_url"],
        "sha256": sha,
        "bytes": len(body),
        "file_format": "html",
        "local_path": str(local),
        "filename": entry["public_url"].rstrip("/").rsplit("/", 1)[-1] + ".html",
        "title_hint": entry["title_hint"],
        "project_hint": entry["project_hint"],
        "date_hint": entry["date_hint"],
        "date_precision": entry["date_precision"],
        "date_basis": entry["date_basis"],
        "doc_kind": "audit_report",
        "retrieved_utc": retrieved,
        "notes": entry["notes"],
    }


def load_rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--end", type=int)
    parser.add_argument("--finalize", action="store_true")
    args = parser.parse_args()
    fetch = Fetcher(refresh="--refresh" in sys.argv)
    out = ROOT / "data" / "collect" / FIRM
    out.mkdir(parents=True, exist_ok=True)
    old_rows = load_rows(out / "reports.jsonl")
    old_status = json.loads((out / "status.json").read_text()) if (out / "status.json").exists() else {}
    retained_rows = retained_collection_rows(old_rows)
    old_sha = {r.get("sha256") for r in retained_rows if r.get("sha256")}
    old_projects = [(r.get("project_hint") or r.get("title_hint") or r.get("filename", ""), month(r.get("date_hint", "")))
                    for r in retained_rows]
    entries, listing_urls = listing_items(fetch)
    write_json(out / "catalogue_refresh_listing.json", {
        "firm_id": FIRM, "listing_urls": listing_urls, "measured_utc": utc(),
        "items": entries, "listed_count": len(entries),
        "method": "Halborn server-rendered Next.js flight data, page=1..N, plus RSS cross-check",
    })
    existing_site = {r.get("public_url"): r for r in old_rows if is_catalogue_row(r)}
    checkpoint_rows = {r.get("public_url"): r for r in load_rows(CHECKPOINT)}
    site_rows = list(checkpoint_rows.values())
    failures, duplicates = [], []
    end = len(entries) if args.end is None else min(len(entries), args.end)
    for i, entry in enumerate(entries[args.start:end], args.start + 1):
        if entry["public_url"] in checkpoint_rows:
            continue
        site_month = month(entry["date_hint"])
        dup = next((r for r, m in old_projects if m and m == site_month and project_match(entry["project_hint"], r)), None)
        if dup:
            duplicates.append({"url": entry["public_url"], "reason": "project+date", "matched_project": dup,
                               "date": entry["date_hint"]})
            continue
        cached = existing_site.get(entry["public_url"])
        try:
            if cached and (ROOT / cached["local_path"]).exists():
                body = (ROOT / cached["local_path"]).read_bytes()
                retrieved = cached.get("retrieved_utc", utc())
            else:
                meta, body = fetch.get(entry["public_url"], fresh="--refresh" in sys.argv)
                retrieved = meta["retrieved_utc"]
            if not html_is_report(body):
                raise RuntimeError("HTML is not a substantive Halborn audit report")
            row = row_for(entry, body, retrieved)
            if row["sha256"] in old_sha:
                duplicates.append({"url": entry["public_url"], "reason": "sha256", "sha256": row["sha256"]})
            elif any(r["sha256"] == row["sha256"] for r in site_rows):
                duplicates.append({"url": entry["public_url"], "reason": "sha256_site", "sha256": row["sha256"]})
            else:
                site_rows.append(row)
        except Exception as exc:
            failures.append({"url": entry["public_url"], "error": str(exc)})
        if i % 10 == 0 or i == end:
            CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
            CHECKPOINT.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in site_rows))
            print(f"halborn website: {i}/{len(entries)} collected={len(site_rows)} failed={len(failures)} duplicate={len(duplicates)}", flush=True)
    CHECKPOINT.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in site_rows))
    if not args.finalize and end < len(entries):
        print(json.dumps({"checkpoint": str(CHECKPOINT), "processed_through": end,
                          "website_collected": len(site_rows), "website_failed": len(failures)}))
        return
    merged = retained_rows + site_rows
    # Preserve deterministic one-row-per-content URL output.
    unique = {}
    for row in sorted(merged, key=lambda r: (r.get("source_kind", ""), r.get("public_url", ""), r.get("sha256", ""))):
        unique.setdefault((row.get("public_url"), row.get("sha256")), row)
    final_rows = list(unique.values())
    (out / "reports.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in final_rows))
    status = dict(old_status)
    previous_site_count = int((old_status.get("catalogue_refresh") or {}).get("website_listed") or 0)
    archive_listed = int(old_status.get("listed_count") or len(retained_rows)) - previous_site_count
    status.update({
        "firm_id": FIRM,
        "listing_urls": list(dict.fromkeys((old_status.get("listing_urls") or []) + listing_urls)),
        "listed_count": archive_listed + len(entries),
        "collected": len(final_rows),
        "doc_kind_counts": dict(sorted(Counter(r["doc_kind"] for r in final_rows).items())),
        "failed": int(old_status.get("failed") or 0) + len(failures),
        "skipped_non_report": int(old_status.get("skipped_non_report") or 0) + len(duplicates),
        "failures": (old_status.get("failures") or []) + failures,
        "collected_utc": utc(),
        "collector_script": "scripts/collect/web_halborn.py",
        "catalogue_refresh": {
            "archive_listed": archive_listed,
            "website_listed": len(entries), "website_collected": len(site_rows),
            "website_failed": len(failures), "website_duplicates": len(duplicates),
            "dedupe": "SHA-256, then normalized project plus listing month against GitHub rows",
        },
    })
    write_json(out / "status.json", status)
    write_json(out / "catalogue_refresh_receipts.json", {"duplicates": duplicates, "failures": failures,
                                                  "website_listed": len(entries), "website_collected": len(site_rows),
                                                  "retrieved_utc": utc(), "requests": fetch.evidence})
    print(json.dumps({k: status[k] for k in ("listed_count", "collected", "failed", "skipped_non_report")}, indent=2))


if __name__ == "__main__":
    main()
