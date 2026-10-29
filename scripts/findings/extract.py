"""Extract complete local reports; never consult Phase 3's local-cache/text cache."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import threading
from common import ROOT, VERSION, holdouts, original_path, read_snapshot, write_json, write_jsonl
from extraction_normalization import normalize_pdf, VERSION as NORMALIZATION_VERSION
from extraction_normalization import missing_font_mapping, needs_font_mapping_retry, font_mapping_pages, FONT_MAPPING_VERSION
from halborn_website import applies as halborn_applies, needs_retry as halborn_needs_retry, extract as halborn_extract
FITZ_LOCK = threading.Lock()


def cache_contract(meta, row):
    """A matching text hash alone cannot validate parser-routing metadata."""
    return (meta.get('sha256') == row['sha256']
            and meta.get('file_format') == row['file_format']
            and isinstance(meta.get('issues'), list)
            and (meta.get('method') != 'quantstamp-static-json-heading-text' or bool(meta.get('structured'))))


class HTMLText(HTMLParser):
    """Retain heading levels, tables and preformatted report content; omit active content."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "svg"}:
            self.skip += 1
        if self.skip:
            return
        if re.fullmatch(r"h[1-6]", tag):
            self.parts.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag in {"p", "div", "section", "article", "tr", "ul", "ol", "pre", "blockquote"}:
            self.parts.append("\n")
        elif tag == "br":
            self.parts.append("\n")
        elif tag == "li":
            self.parts.append("\n- ")
        elif tag in {"td", "th"}:
            self.parts.append(" | ")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "svg"}:
            self.skip = max(0, self.skip - 1)
        if not self.skip and (tag in {"p", "div", "tr", "pre", "li"} or re.fullmatch(r"h[1-6]", tag)):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)

    def text(self):
        return re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n", "".join(self.parts)).strip() + "\n"


def tool(name, root):
    local = root / "local-cache/fulltext/tools/usr/bin" / name
    return str(local) if local.exists() else shutil.which(name)


def tool_environment(root):
    env = os.environ.copy()
    lib = root / "local-cache/fulltext/tools/usr/lib/x86_64-linux-gnu"
    env["LD_LIBRARY_PATH"] = str(lib) + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    tessdata = root / "local-cache/fulltext/tools/usr/share/tesseract-ocr/5/tessdata"
    if tessdata.exists():
        env["TESSDATA_PREFIX"] = str(tessdata)
    env["OMP_THREAD_LIMIT"] = "1"
    return env


def extract_one(item, root, blocked, timeout=120, retry=False):
    sha, row = item
    if sha in blocked:
        raise RuntimeError("Holdout extraction denied")
    out = root / "local-cache/fulltext"
    txt_path, pages_path = out / (sha + ".txt"), out / (sha + ".pages.json")
    base = {"sha256": sha, "file_format": row["file_format"], "extractor_version": VERSION}
    previous = None
    if pages_path.exists() and txt_path.exists():
        previous = json.loads(pages_path.read_text())
        payload = txt_path.read_bytes().decode('utf-8')
        if hashlib.sha256(payload.encode()).hexdigest() != previous.get('text_sha256'):
            previous = None
    if previous is not None and not retry and cache_contract(previous, row):
        ocr_retry = previous.get("status") == "partial" and tool("tesseract", root) and "tesseract" not in previous.get("method", "")
        if previous.get("extractor_version") == VERSION and previous.get('normalization_version') == NORMALIZATION_VERSION and not ocr_retry and not needs_font_mapping_retry(previous) and not halborn_needs_retry(row, previous):
            payload = txt_path.read_bytes().decode("utf-8")
            if hashlib.sha256(payload.encode()).hexdigest() == previous.get("text_sha256"):
                return {**base, **{k: previous[k] for k in ("status", "method", "page_count", "characters", "text_sha256", "issues")},
                        "text_path": str(txt_path.relative_to(root)), "pages_path": str(pages_path.relative_to(root))}
    issues, method, texts, structured = [], None, [], None
    halborn_metadata = None
    try:
        path = original_path(row, root)
        if not path.is_file():
            raise FileNotFoundError("Original missing")
        h = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
        if h.hexdigest() != sha:
            raise ValueError("Original SHA-256 mismatch")
        fmt = row["file_format"]
        if fmt == "pdf":
            pdftotext = tool("pdftotext", root)
            if not pdftotext:
                raise RuntimeError("pdftotext unavailable")
            env = tool_environment(root)
            result = subprocess.run([pdftotext, "-layout", "-enc", "UTF-8", str(path), "-"],
                                    capture_output=True, timeout=timeout, env=env)
            full_warning = result.stderr.decode("utf-8", "replace")
            warning = full_warning[:3000]
            if result.returncode:
                kind = "encrypted" if re.search(r"password|encrypted", warning, re.I) else "pdftotext_error"
                return {**base, "status": "failed", "error": kind, "detail": warning}
            method = "pdftotext-layout"
            texts = result.stdout.decode("utf-8", "replace").split("\f")
            if texts and not texts[-1].strip():
                texts.pop()
            font_pages=font_mapping_pages(path,len(texts),pdftotext,env,timeout) if missing_font_mapping(full_warning) else []
            texts, page_issues = normalize_pdf(texts, path, root, tool("tesseract", root), env, timeout, FITZ_LOCK, previous, font_pages)
            issues.extend(page_issues)
            if any(i["kind"] == "ocr_page" for i in page_issues):
                method += "+tesseract"
            if any(i["kind"] == "letter_spaced_page" for i in page_issues):
                method += "+glyph-advances"
            if warning:
                issues.append({"kind": "poppler_warning", "detail": warning})
        elif fmt in {"md", "html"} or path.suffix.lower() in {".md", ".markdown", ".html", ".htm", ".txt"}:
            value = path.read_bytes().decode("utf-8-sig", "replace").replace("\r\n", "\n")
            if fmt == "html" or path.suffix.lower() in {".html", ".htm"}:
                parser = HTMLText()
                parser.feed(value)
                if halborn_applies(row):
                    supplement, halborn_metadata = halborn_extract(value)
                    value, method = parser.text() + supplement, "html-heading-text+halborn-flight"
                else:
                    value, method = parser.text(), "html-heading-text"
            else:
                method = "markdown-heading-text"  # Keep source Markdown, including headings, verbatim.
            texts = [value]
        elif row["firm_id"] == "quantstamp" and row["filename"].endswith(".js"):
            from structured import quantstamp_payload, render_report
            data = quantstamp_payload(path.read_text())
            rendered, structured = render_report(data)
            texts = [rendered]
            method = "quantstamp-static-json-heading-text"
        else:
            return {**base, "status": "failed", "error": "unsupported_format"}
        payload = "\f".join(texts)
        if sum(c.isalnum() for c in payload) < 20:
            return {**base, "status": "failed", "error": "empty_or_image_only", "issues": issues}
        status = "partial" if any(i["kind"] in {"ocr_failed", "image_only_page_ocr_unavailable"} for i in issues) else "ok"
        pages, start = [], 0
        for i, text in enumerate(texts, 1):
            pages.append({"page": i, "start": start, "end": start + len(text), "text": text})
            start += len(text) + 1
        meta = {**base, "status": status, "method": method, "page_count": len(pages), "characters": len(payload),
                "text_sha256": hashlib.sha256(payload.encode()).hexdigest(), "issues": issues,
                "normalization_version": NORMALIZATION_VERSION,
                "font_mapping_ocr_version": FONT_MAPPING_VERSION,
                "coordinate_system": "Unicode code points; zero-based half-open offsets; PDF pages joined by form feed; MD/HTML page=1 is logical, not printed",
                "pages": pages}
        if structured:
            meta["structured"] = structured
        if halborn_metadata is not None:
            meta["halborn_website"] = halborn_metadata
        tmp = txt_path.with_suffix(".txt.tmp")
        tmp.write_text(payload)
        tmp.replace(txt_path)
        write_json(pages_path, meta)
        return {k: v for k, v in meta.items() if k not in {"pages", "coordinate_system", "structured"}} | {
            "text_path": str(txt_path.relative_to(root)), "pages_path": str(pages_path.relative_to(root))}
    except subprocess.TimeoutExpired:
        return {**base, "status": "failed", "error": "timeout"}
    except Exception as exc:
        return {**base, "status": "failed", "error": type(exc).__name__, "detail": str(exc)[:500]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--retry", action="store_true")
    parser.add_argument("--max-new",type=int,help="Bound newly extracted/OCR-retried artifacts per invocation; cached receipts are preserved")
    args = parser.parse_args()
    versions = {}
    for name in ("pdftotext", "tesseract"):
        binary = tool(name,args.root)
        if binary:
            result = subprocess.run([binary,"-v" if name == "pdftotext" else "--version"],capture_output=True,env=tool_environment(args.root))
            versions[name] = {"binary":binary,"version_output":(result.stdout+result.stderr).decode("utf-8","replace").strip(),"returncode":result.returncode}
    import fitz
    versions["pymupdf"] = fitz.VersionBind
    versions["packages"] = [{"path":str(p.relative_to(args.root)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted((args.root/"local-cache").glob("*.deb"))]
    write_json(args.root/"data/fulltext/toolchain.json",versions)
    docs = read_snapshot(args.root)
    unique = {d["row"]["sha256"]: d["row"] for d in reversed(docs)}
    blocked = holdouts(args.root)
    rows, jobs, deferred = [], [], 0
    index=args.root/"data/fulltext/extractions.jsonl"
    old={r["sha256"]:r for r in map(json.loads,index.read_text().splitlines())} if index.exists() else {}
    for item in sorted(unique.items(),key=lambda item:(old.get(item[0],{}).get("status")=="failed",item[0])):
        sha,row=item
        meta_path=args.root/"local-cache/fulltext"/(sha+".pages.json")
        text_path=args.root/"local-cache/fulltext"/(sha+".txt")
        previous=json.loads(meta_path.read_text()) if meta_path.exists() and text_path.exists() else None
        needs_ocr=previous and previous.get("status")=="partial" and tool("tesseract",args.root) and "tesseract" not in previous.get("method","")
        if previous and cache_contract(previous,row) and previous.get("extractor_version")==VERSION and previous.get("normalization_version")==NORMALIZATION_VERSION and not needs_ocr and not args.retry and not needs_font_mapping_retry(previous) and not halborn_needs_retry(row, previous):
            rows.append({k:v for k,v in previous.items() if k not in {"pages","coordinate_system","structured"}} |
                        {"text_path":str(text_path.relative_to(args.root)),"pages_path":str(meta_path.relative_to(args.root))})
        elif args.max_new is None or len(jobs)<args.max_new:
            jobs.append(item)
        else:
            if old.get(sha,{}).get("status")=="failed":
                rows.append(old[sha])
            else:
                deferred+=1
                rows.append({"sha256":sha,"file_format":row["file_format"],"status":"pending","error":"deferred_to_next_batch","extractor_version":VERSION})
    print(f"Cached {len(rows)-deferred}; scheduled {len(jobs)}; deferred {deferred}",flush=True)
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(extract_one, item, args.root, blocked, retry=args.retry) for item in jobs]
        for future in as_completed(futures):
            rows.append(future.result())
            if len(rows) % 500 == 0:
                print(f"Extracted {len(rows)}/{len(unique)} artifacts; failures={sum(r['status']=='failed' for r in rows)}; elapsed={time.monotonic()-start:.0f}s", flush=True)
    rows.sort(key=lambda r: r["sha256"])
    write_jsonl(args.root / "data/fulltext/extractions.jsonl", rows)
    write_jsonl(args.root / "data/fulltext/failures.jsonl", [r for r in rows if r["status"] != "ok"])
    indexed = {r["sha256"]: r for r in rows}
    counts = {s: sum(indexed[d["row"]["sha256"]]["status"] == s for d in docs) for s in ("ok", "partial", "failed", "pending")}
    summary = {"documents": len(docs), "unique_artifacts": len(rows), "document_status": counts,
               "fulltext_percent": round(100 * counts["ok"] / len(docs), 4) if docs else None,
               "text_cache_percent": round(100 * (counts["ok"]+counts["partial"]) / len(docs), 4) if docs else None,
               "unique_status": {s: sum(r["status"] == s for r in rows) for s in counts},
               "pages": sum(r.get("page_count", 0) for r in rows), "holdouts_opened": 0}
    write_json(args.root / "data/fulltext/summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
