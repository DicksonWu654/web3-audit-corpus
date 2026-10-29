#!/usr/bin/env python3
"""Discover Tier A audit-report links in DeFiLlama and L2BEAT metadata.

This script treats publisher API/config values as inert data. It never imports
or executes upstream source code. Network requests go through discovery/common.py.
"""
from __future__ import annotations

import argparse
import datetime as dt
import io
import json
from pathlib import Path
import re
import runpy
import tarfile
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
COMMON_PATH = ROOT / "scripts/discovery/common.py"
OUTPUT = ROOT / "data/discovery/_sources/ecosystem_sources.jsonl"
STATUS = ROOT / "data/discovery/_sources/ecosystem_sources.status.json"
LLAMA_LIST = "https://api.llama.fi/protocols"
LLAMA_PROTOCOL = "https://api.llama.fi/protocol/{}"
L2BEAT_REPO = "l2beat/l2beat"
L2BEAT_PAGE = "https://github.com/l2beat/l2beat"
L2BEAT_PROJECTS = "packages/config/src/projects/"
AUDIT_DATASET_REPO = "sergeyshemyakov/audit-dataset"
AUDIT_DATASET_PAGE = f"https://github.com/{AUDIT_DATASET_REPO}"
AUDIT_DATASET_INDEX = "audit-index.json"
MAX_ARCHIVE_BYTES = 512_000_000
MAX_PROJECT_FILE_BYTES = 1_000_000


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parse_commit(body: bytes) -> str | None:
    match = re.search(rb'currentOid\\\":\\\"([0-9a-f]{40})', body)
    if not match:
        match = re.search(rb'currentOid":"([0-9a-f]{40})', body)
    return match.group(1).decode("ascii") if match else None


def date_from_url(url: str) -> str | None:
    text = urlsplit(url).path
    match = re.search(r"(?<!\d)(20\d{2})[-_/](0?[1-9]|1[0-2])[-_/](0?[1-9]|[12]\d|3[01])(?!\d)", text)
    if match:
        try:
            return dt.date(int(match.group(1)), int(match.group(2)), int(match.group(3))).isoformat()
        except ValueError:
            return None
    match = re.search(r"(?<!\d)(20\d{2})[-_/](0?[1-9]|1[0-2])(?!\d)", text)
    if match:
        return f"{int(match.group(1)):04d}-{int(match.group(2)):02d}"
    match = re.search(r"(?<!\d)(20\d{2})(?!\d)", text)
    return match.group(1) if match else None


def report_specific(url: str) -> bool:
    """Accept an individual report file/page, not an audit directory or index."""
    try:
        p = urlsplit(url)
    except ValueError:
        return False
    if p.scheme != "https" or not p.hostname or p.username or p.password:
        return False
    path = p.path.rstrip("/")
    if not path or path == "/":
        return False
    lower = path.lower()
    if lower.endswith(("/audits", "/audit", "/reports", "/report", "/security", "/reviews", "/review")):
        return False
    # GitHub repository and tree links are directories; blob links are files.
    if p.hostname.lower() in {"github.com", "www.github.com"}:
        parts = [x for x in path.split("/") if x]
        if len(parts) < 5 or parts[2] != "blob":
            return False
    ext = Path(path).suffix.lower()
    if ext in {".pdf", ".md", ".html", ".htm", ".doc", ".docx"}:
        return True
    # Individual report pages often have non-file URLs. Require report language
    # and a specific terminal slug, excluding generic index-like endpoints.
    leaf = path.rsplit("/", 1)[-1].lower()
    if leaf in {"index", "audits", "audit", "reports", "report", "security", "reviews", "review"}:
        return False
    return bool(re.search(r"audit|report|security-review|assessment|review", lower)) and len(leaf) >= 5


def date_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if re.fullmatch(r"20\d{2}", s):
        return s
    if re.fullmatch(r"20\d{2}-\d{2}", s):
        return s
    if re.fullmatch(r"20\d{2}-\d{2}-\d{2}", s):
        try:
            return dt.date.fromisoformat(s).isoformat()
        except ValueError:
            return None
    return None


def literal_string(src: str, key: str) -> str | None:
    # Config records use quoted literal values. Ignore expressions and template strings.
    pattern = rf"\b{re.escape(key)}\s*:\s*(['\"])(.*?)\1"
    match = re.search(pattern, src, flags=re.S)
    return match.group(2).strip() if match else None


def balanced_end(src: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    i = start
    while i < len(src):
        c = src[i]
        n = src[i + 1] if i + 1 < len(src) else ""
        if line_comment:
            if c == "\n":
                line_comment = False
        elif block_comment:
            if c == "*" and n == "/":
                block_comment = False
                i += 1
        elif quote:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == quote:
                quote = ""
        elif c == "/" and n == "/":
            line_comment = True
            i += 1
        elif c == "/" and n == "*":
            block_comment = True
            i += 1
        elif c in "'\"`":
            quote = c
        elif c == opening:
            depth += 1
        elif c == closing:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return None


def audit_entries(src: str) -> list[tuple[str, int]]:
    """Read literal objects inside `audits: [...]` without evaluating TypeScript."""
    result: list[tuple[str, int]] = []
    for match in re.finditer(r"\baudits\s*:\s*\[", src):
        start = match.end() - 1
        end = balanced_end(src, start, "[", "]")
        if end is None:
            continue
        section = src[start + 1:end - 1]
        offset = start + 1
        for obj in re.finditer(r"\{", section):
            obj_end = balanced_end(section, obj.start(), "{", "}")
            if obj_end is None:
                continue
            text = section[obj.start():obj_end]
            if literal_string(text, "company") and literal_string(text, "url"):
                result.append((text, offset + obj.start()))
        # Do not match a nested audits property within the same array a second time.
    return result


def alias_map(helper: dict) -> dict[str, str]:
    return helper["aliases"]()


def llama_attribution(url: str, firms: dict[str, dict], aliases: dict[str, str]) -> tuple[str | None, dict | None]:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/")
    # Attribute only when the link is inside the publisher's registered canonical
    # reports URL. A client repository's owner alone is never used as attribution.
    for fid, row in firms.items():
        for canonical in (row.get("github_reports_url", ""), row.get("website_reports_url", "")):
            if not canonical:
                continue
            c = urlsplit(canonical)
            cp = c.path.rstrip("/")
            if host == (c.hostname or "").lower() and cp and (path == cp or path.startswith(cp + "/")):
                return fid, {"kind": "publisher_canonical_url", "value": canonical, "evidence_url": canonical}
    basename = Path(path).stem
    norm = helper_norm(basename)
    matches = {fid for alias, fid in aliases.items() if len(alias) >= 5 and alias in norm}
    if len(matches) == 1:
        fid = matches.pop()
        return fid, {"kind": "named_filename", "value": basename, "evidence_url": url}
    return None, None


def helper_norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def append_candidate(rows: list[dict], seen: set[tuple[str, str]], *, url: str,
                     firm_id: str, project: str, date_hint: str | None,
                     date_basis: str, source: str, attribution: dict,
                     record_id: str, evidence_url: str, notes: str,
                     original_url: str | None = None) -> None:
    key = (url, firm_id)
    if key in seen:
        return
    seen.add(key)
    rows.append({
        "candidate_url": url,
        "original_publisher_url": original_url,
        "firm_id": firm_id,
        "project_hint": project,
        "date_hint": date_hint,
        "date_basis": date_basis if date_hint else "none",
        "source": source,
        "attribution_basis": attribution,
        "source_record_id": record_id,
        "notes": notes,
    })


def discover_l2beat(helper: dict, firms: dict[str, dict], rows: list[dict], seen: set[tuple[str, str]]) -> dict:
    # Resolve live repository HEAD from the public web page; api.github.com is
    # blocked by its robots endpoint in this environment. Pin the archive by SHA.
    page_meta, page_body = helper["fetch"](L2BEAT_PAGE, limit=4_000_000)
    commit = parse_commit(page_body) if page_meta.get("status") == 200 else None
    result = {"source": "l2beat", "listing_url": L2BEAT_PAGE,
              "head_page_status": page_meta.get("status"), "head_page_error": page_meta.get("error"),
              "commit": commit, "tree_enumeration": "pinned codeload archive; path-prefix enumeration"}
    if not commit:
        result["error"] = "could not read a 40-character currentOid from GitHub repository page"
        return result
    archive_url = f"https://codeload.github.com/{L2BEAT_REPO}/tar.gz/{commit}"
    archive_meta, archive = helper["fetch"](archive_url, limit=MAX_ARCHIVE_BYTES, timeout=120)
    result.update({"archive_url": archive_url, "archive_status": archive_meta.get("status"),
                   "archive_sha256": archive_meta.get("sha256"), "archive_bytes": len(archive)})
    if archive_meta.get("status") != 200 or not archive:
        result["error"] = archive_meta.get("error") or "pinned archive unavailable"
        return result
    scope = firms
    file_count = 0
    audit_count = 0
    matched_firms = 0
    kept_count = 0
    skipped = {"unscoped_firm": 0, "non_report_url": 0, "invalid_url": 0}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
            members = [m for m in tf.getmembers() if m.isfile()
                       and L2BEAT_PROJECTS in m.name and m.name.endswith(".ts")]
            members.sort(key=lambda m: m.name)
            result["tree_file_count"] = len(members)
            result["tree_project_prefix"] = L2BEAT_PROJECTS
            result["tree_complete"] = True
            for member in members:
                if member.size > MAX_PROJECT_FILE_BYTES:
                    continue
                stream = tf.extractfile(member)
                if stream is None:
                    continue
                source_text = stream.read(MAX_PROJECT_FILE_BYTES + 1).decode("utf-8", errors="replace")
                if len(source_text.encode("utf-8")) > MAX_PROJECT_FILE_BYTES:
                    continue
                file_count += 1
                relative = member.name.split(L2BEAT_PROJECTS, 1)[-1]
                project = relative.split("/", 1)[0]
                for audit_text, offset in audit_entries(source_text):
                    audit_count += 1
                    company = literal_string(audit_text, "company")
                    url = literal_string(audit_text, "url")
                    if not company or not url:
                        continue
                    firm_id = helper["firm_name"](company)
                    if firm_id not in scope:
                        skipped["unscoped_firm"] += 1
                        continue
                    matched_firms += 1
                    if not url.startswith("https://"):
                        skipped["invalid_url"] += 1
                        continue
                    if not report_specific(url):
                        skipped["non_report_url"] += 1
                        continue
                    line = source_text.count("\n", 0, offset) + 1
                    source_record_id = f"{project}:{relative}#L{line}"
                    evidence_url = f"https://github.com/{L2BEAT_REPO}/blob/{commit}/{L2BEAT_PROJECTS}{relative}#L{line}"
                    raw_date = literal_string(audit_text, "date")
                    date_hint = date_value(raw_date) if raw_date else date_from_url(url)
                    date_basis = "listing" if raw_date and date_hint else "filename" if date_hint else "none"
                    attribution = {"kind": "explicit_auditor_field", "value": company,
                                  "evidence_url": evidence_url}
                    append_candidate(rows, seen, url=url, firm_id=firm_id, project=project,
                                     date_hint=date_hint, date_basis=date_basis, source="l2beat",
                                     attribution=attribution, record_id=source_record_id,
                                     evidence_url=evidence_url,
                                     notes="Auditor and URL are literal values in the pinned L2BEAT audits config; date is a config field or explicit URL date.",
                                     original_url=url)
                    kept_count += 1
    except (tarfile.TarError, OSError) as exc:
        result["error"] = f"archive parse failed: {type(exc).__name__}"
    result.update({"project_files_scanned": file_count, "audit_entries": audit_count,
                   "tier_a_attributed_entries": matched_firms, "report_specific_candidates": kept_count,
                   "skipped": skipped})
    # L2BEAT's current code reads a separate, explicit report index. Treat its
    # JSON as data and retain only report documents with an in-scope auditor.
    dataset = discover_l2beat_audit_index(helper, firms, rows, seen)
    result["audit_dataset"] = dataset
    return result


def discover_l2beat_audit_index(helper: dict, firms: dict[str, dict], rows: list[dict],
                                seen: set[tuple[str, str]]) -> dict:
    page_meta, page_body = helper["fetch"](AUDIT_DATASET_PAGE, limit=4_000_000)
    commit = parse_commit(page_body) if page_meta.get("status") == 200 else None
    result = {"source": "l2beat_audit_dataset", "listing_url": AUDIT_DATASET_PAGE,
              "head_page_status": page_meta.get("status"), "commit": commit}
    if not commit:
        result["error"] = "could not pin the audit dataset repository"
        return result
    index_url = f"https://raw.githubusercontent.com/{AUDIT_DATASET_REPO}/{commit}/{AUDIT_DATASET_INDEX}"
    meta, data = helper["get_json"](index_url, limit=32_000_000)
    result.update({"index_url": index_url, "index_status": meta.get("status"),
                   "index_sha256": meta.get("sha256"), "index_bytes": meta.get("bytes", 0)})
    if meta.get("status") != 200 or not isinstance(data, dict) or not isinstance(data.get("reports"), dict):
        result["error"] = meta.get("error") or "audit-index.json unavailable or invalid"
        return result
    collections = data.get("collections", {})
    reports = data["reports"]
    kept = 0
    skipped = {"unscoped_firm": 0, "non_report_document": 0, "missing_fields": 0}
    for report_id, report in sorted(reports.items()):
        if not isinstance(report, dict):
            skipped["missing_fields"] += 1
            continue
        auditor = report.get("auditor")
        document = report.get("document")
        if not isinstance(auditor, str) or not isinstance(document, str):
            skipped["missing_fields"] += 1
            continue
        fid = helper["firm_name"](auditor)
        if fid not in firms:
            skipped["unscoped_firm"] += 1
            continue
        parts = document.split("/")
        suffix = Path(document).suffix.lower()
        if (document.startswith("/") or ".." in parts or len(parts) < 3
                or parts[1] != "reports" or "irrelevant" in parts
                or suffix not in {".pdf", ".html", ".htm", ".md"}):
            skipped["non_report_document"] += 1
            continue
        collection_ids = report.get("collections") if isinstance(report.get("collections"), list) else []
        project_names = [collections.get(cid, {}).get("name", cid)
                         for cid in collection_ids if isinstance(cid, str)
                         and isinstance(collections.get(cid, {}), dict)]
        project = "; ".join(str(x) for x in project_names) or (collection_ids[0] if collection_ids else None)
        public_url = f"https://github.com/{AUDIT_DATASET_REPO}/blob/{commit}/{quote(document, safe='/')}"
        raw_date = date_value(report.get("date"))
        attribution = {"kind": "explicit_auditor_field", "value": auditor, "evidence_url": index_url}
        append_candidate(rows, seen, url=public_url, firm_id=fid, project=str(project or ""),
                         date_hint=raw_date, date_basis="listing" if raw_date else "none",
                         source="l2beat", attribution=attribution, record_id=str(report_id),
                         evidence_url=index_url,
                         notes="Pinned report document in the audit dataset referenced by L2BEAT's auditDataset.ts; this is a dataset-hosted copy, and the original publisher URL was not present in the index.")
        kept += 1
    result.update({"dataset_commit": commit, "indexed_reports": len(reports),
                   "tier_a_attributed_report_documents": kept,
                   "skipped": skipped,
                   "notes": "L2BEAT's auditDataset.ts identifies this index as its default report dataset; report rows are inert JSON with explicit auditor, date, and document fields."})
    return result


def discover_defillama(helper: dict, firms: dict[str, dict], rows: list[dict], seen: set[tuple[str, str]],
                       limit: int | None) -> dict:
    meta, protocols = helper["get_json"](LLAMA_LIST, limit=128_000_000)
    result = {"source": "defillama", "listing_url": LLAMA_LIST,
              "listing_status": meta.get("status"), "listing_sha256": meta.get("sha256"),
              "listed_protocols": len(protocols) if isinstance(protocols, list) else 0,
              "detail_limit": limit}
    if meta.get("status") != 200 or not isinstance(protocols, list):
        result["error"] = meta.get("error") or "protocol listing unavailable or invalid"
        return result
    marked = [p for p in protocols if str(p.get("audits", "0")) not in {"", "0", "None"}]
    marked.sort(key=lambda p: (-(p.get("tvl") if isinstance(p.get("tvl"), (int, float)) else 0),
                               str(p.get("slug") or p.get("id") or "")))
    selected = marked if limit is None else marked[:limit]
    result["audit_marked_protocols"] = len(marked)
    result["selected_protocols"] = len(selected)
    result["unqueried_marked_protocols"] = max(0, len(marked) - len(selected))
    links_seen = 0
    kept = 0
    fails = 0
    failed_details = []
    missing_links = 0
    skip = {"non_report_url": 0, "unknown_firm": 0, "invalid_url": 0}
    alias_index = alias_map(helper)
    for position, protocol in enumerate(selected, 1):
        slug = protocol.get("slug")
        if not isinstance(slug, str) or not slug:
            slug = str(protocol.get("id") or "")
        if not slug:
            fails += 1
            continue
        detail_url = LLAMA_PROTOCOL.format(slug)
        dm, detail = helper["get_json"](detail_url, limit=32_000_000)
        if dm.get("error") in {"body exceeds bound", "TimeoutError"}:
            dm, detail = helper["get_json"](detail_url, limit=128_000_000,
                                             timeout=60, refresh=True)
        if dm.get("status") != 200 or not isinstance(detail, dict):
            fails += 1
            failed_details.append({"protocol_id": protocol.get("id"), "slug": slug,
                                   "url": detail_url, "status": dm.get("status"),
                                   "error": dm.get("error") or "invalid_json_or_nonobject"})
            if position % 100 == 0:
                print(f"DeFiLlama detail progress: {position}/{len(selected)}; links={links_seen}; candidates={kept}; failures={fails}", flush=True)
            continue
        audit_links = detail.get("audit_links")
        if not isinstance(audit_links, list):
            missing_links += 1
            continue
        project = str(detail.get("name") or protocol.get("name") or slug)
        for link_number, url in enumerate(audit_links, 1):
            if not isinstance(url, str):
                continue
            links_seen += 1
            if not url.startswith("https://"):
                skip["invalid_url"] += 1
                continue
            if not report_specific(url):
                skip["non_report_url"] += 1
                continue
            fid, attribution = llama_attribution(url, firms, alias_index)
            if not fid or not attribution:
                skip["unknown_firm"] += 1
                continue
            append_candidate(rows, seen, url=url, firm_id=fid, project=project,
                             date_hint=date_from_url(url), date_basis="filename",
                             source="defillama", attribution=attribution,
                             record_id=f"{protocol.get('id') or slug}:{link_number}", evidence_url=detail_url,
                             notes="Report-specific audit_links entry from DeFiLlama protocol detail; auditor is matched only to a registered publisher URL or named filename.",
                             original_url=url)
            kept += 1
        if position % 100 == 0 or position == len(selected):
            print(f"DeFiLlama detail progress: {position}/{len(selected)}; links={links_seen}; candidates={kept}; failures={fails}", flush=True)
    result.update({"detail_records_fetched": len(selected) - fails, "detail_failures": fails,
                   "detail_failure_records": failed_details,
                   "protocol_details_without_audit_links": missing_links,
                   "audit_links_examined": links_seen, "report_specific_candidates": kept,
                   "skipped": skip})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--defillama-limit", type=int, default=None,
                        help="optional maximum audited protocols to inspect (default: all; each detail request is host-throttled)")
    args = parser.parse_args()
    if args.defillama_limit is not None and args.defillama_limit < 0:
        parser.error("--defillama-limit must be nonnegative")
    helper = runpy.run_path(str(COMMON_PATH))
    firms = helper["scope"]()
    rows: list[dict] = []
    seen: set[tuple[str, str]] = set()
    l2beat = discover_l2beat(helper, firms, rows, seen)
    defillama = discover_defillama(helper, firms, rows, seen, args.defillama_limit)
    rows.sort(key=lambda r: (r["source"], r["firm_id"], r["project_hint"] or "", r["candidate_url"]))
    helper["write_jsonl"](OUTPUT, rows)
    status = {
        "collector_script": "scripts/discovery/ecosystem_sources.py",
        "collected_utc": iso_now(),
        "scope": "registry/scope_tier_a.csv excluding certik",
        "firm_count": len(firms),
        "candidate_count": len(rows),
        "sources": {"l2beat": l2beat, "defillama": defillama},
        "limitations": [
            "DeFiLlama exposes audit_links on per-protocol detail; default run inspects every protocol whose bulk listing has a nonzero audits marker. Use --defillama-limit only for a bounded partial scan.",
            "Only individual report-like URLs are emitted; audit repositories, generic audit directories, and un-attributed links are skipped.",
            "The L2BEAT GitHub API robots endpoint returns 403 in this environment; the live GitHub repository page supplies the pinned SHA and a pinned archive is enumerated locally without extracting or executing code.",
        ],
    }
    helper["write_json"](STATUS, status)
    print(json.dumps({"candidate_count": len(rows),
                      "l2beat": {k: l2beat.get(k) for k in ("commit", "tree_file_count", "audit_entries", "tier_a_attributed_entries", "report_specific_candidates", "error")},
                      "defillama": {k: defillama.get(k) for k in ("listed_protocols", "audit_marked_protocols", "selected_protocols", "unqueried_marked_protocols", "audit_links_examined", "report_specific_candidates", "detail_failures", "error")}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
