"""Run deterministic publisher parsers and independent printed-count reconciliation."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import time
from common import ROOT, VERSION, SEVERITIES, canonical, digest, holdouts, read_snapshot, uid, write_json, write_jsonl
from core import Report, candidate_severity, candidate_status, clean, finish, severity, status
from prior_findings import exclude_prior_findings
from variants import select
from parsers import module
from summary_counts import printed_counts


def finding_rows(doc, report, candidates, parser_name):
    if not hasattr(report, "layout_selection"):
        select(report, module(report.firm).VARIANTS)
    seen = Counter()
    for ordinal, c in enumerate(exclude_prior_findings(report, candidates), 1):
        from field_recovery import recover_fields, status_availability
        recover_fields(report,c)
        raw = {"start":c.start,"end":c.end,"title":c.title,"severity_raw":c.severity_raw,
               "publisher_finding_id":c.printed_id,"method":c.method,"status_raw":c.status_raw}
        sid = doc["document_id"] + ":" + VERSION + ":" + str(c.start)
        seen[c.printed_id] += 1
        mapping = candidate_severity(report, c, sha256=doc["row"]["sha256"])
        norm = mapping["normalized"]
        pages = [p["page"] for p in report.meta["pages"] if p["end"] > c.start and p["start"] < c.end]
        body = report.text[c.start:c.end]
        span = {"start":c.start,"end":c.end,"coordinate_system":"unicode_code_points_zero_based_half_open",
                "text_sha256":report.meta["text_sha256"],"original_sha256":doc["row"]["sha256"],"pages":pages}
        evidence = {**c.evidence,"body_span":span,"page":pages[0] if pages else None,
                    "page_basis":"pdf_page" if doc["row"]["file_format"] == "pdf" else "logical_text_page"}
        status_receipt = candidate_status(report, c, sha256=doc['row']['sha256'])
        evidence['status_availability'] = status_availability(report,c,status_receipt)
        evidence['status_mapping'] = status_receipt
        if c.normalized_status:
            evidence['parser_status_interpretation'] = c.normalized_status
        receipt = {k:doc[k] for k in ("source_file","source_locator","source_record_sha256","document_id")}
        row = {"finding_id":uid("finding","collect:"+report.firm,sid),"publisher_id":report.firm,"firm_id":report.firm,
               "document_id":doc["document_id"],"sha256":doc["row"]["sha256"],"source_family":"collected",
               "source_tag":"collect:"+report.firm,"source_file":doc["source_file"],"source_locator":doc["source_locator"],
               "source_record_sha256":doc["source_record_sha256"],"variant_id":report.layout_selection["variant_id"],"provenance":{"variant_id":report.layout_selection["variant_id"],"parent_receipt":receipt,"extraction_record":raw,"extraction_record_sha256":digest(raw),"parser":parser_name,"version":VERSION},
               "source_record_id":sid,"publisher_finding_id":c.printed_id,"ordinal":ordinal,"occurrence":seen[c.printed_id],
               "record_kind":c.record_kind,"finding_phase":c.finding_phase or ("fix_review" if doc["row"]["doc_kind"] == "fix_review" else "initial_audit"),
               "is_seed":False,"title":clean(c.title) if c.title else None,"title_raw":c.title,
               "severity_raw":c.severity_raw,"severity_original":c.severity_raw,"severity_source_normalized":None,
               "severity":norm,"severity_normalized":norm,
               "severity_mapping":mapping | {"basis":c.evidence.get("severity_basis","explicit_publisher_label")},
               "status_raw":c.status_raw,"status_original":c.status_raw,
               "status":status_receipt['normalized'],"status_mapping":status_receipt,
               "status_authority":"publisher" if c.status_raw else None,
               "category_raw":None,"category_semantics":"unknown","category":None,
               "description":None,"recommendation":c.recommendation,"resolution":c.resolution,"attributed_responses":[],
               "body_text":body,"body_span":span,"page":evidence["page"],"method":c.method if c.method in {"generic_fallback","summary_inventory"} else parser_name+":"+c.method,"confidence":c.confidence,
               "evidence":evidence,"review":{"unknown_layout":report.layout_selection["unknown_layout"],"state":"machine_extracted_unreviewed","confidence_is":"heuristic_not_probability"},
               "relationships":[],"unique_vulnerability_id":None,"public_url":doc["row"]["public_url"],
               "field_state":{k:"absent_or_not_separately_extracted" for k,v in {"description":None,"recommendation":c.recommendation,
                              "resolution":c.resolution,"status":c.status_raw,"category":None}.items() if v is None}}
        yield row


def rebuild_unknown_queue(root):
    # Rebuild from all diagnostics after partial runs too, retaining other firms.
    # One entry per artifact/publisher; source occurrences are listed explicitly.
    blocked=holdouts(root); known={d["row"]["firm_id"] for d in read_snapshot(root)}
    queue={}
    for path in sorted((root/"data/findings/validation").glob("*.jsonl")):
        if path.stem not in known:continue
        for line in path.read_text().splitlines():
            d=json.loads(line)
            if not d.get("unknown_layout"):continue
            if d["sha256"] in blocked:raise ValueError("Holdout queue denied")
            key=(d["firm_id"],d["sha256"])
            row=queue.setdefault(key,{"sha256":d["sha256"],"firm":d["firm_id"],"year":d.get("year"),
                                     "top_fingerprint_scores":d["scores"][:5],"document_ids":[]})
            row["document_ids"].append(d["document_id"])
    write_jsonl(root/"data/findings/_unknown_layouts.jsonl",[queue[k] for k in sorted(queue)])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=ROOT)
    p.add_argument("--firms", nargs="*")
    p.add_argument("--live-cache", action="store_true",help="Development run against completed cache pairs while extraction is in progress")
    p.add_argument("--no-queue", action="store_true",help="Defer shared unknown-layout queue refresh during parallel per-publisher runs")
    a = p.parse_args()
    docs = read_snapshot(a.root)
    blocked = holdouts(a.root)
    extraction = {r["sha256"]:r for r in map(json.loads,(a.root/"data/fulltext/extractions.jsonl").read_text().splitlines())}
    by_firm = defaultdict(list)
    for d in docs:
        if not a.firms or d["row"]["firm_id"] in a.firms:
            by_firm[d["row"]["firm_id"]].append(d)
    all_stats = []
    started = time.monotonic()
    for firm, firmdocs in sorted(by_firm.items()):
        parser = module(firm)
        name = parser.__name__.split(".")[-1]
        diagnostics, cache = [], {}
        finding_count_total, formal_total = 0, 0
        output_path = a.root/"data/findings"/(firm+".jsonl")
        output_path.parent.mkdir(parents=True,exist_ok=True)
        temporary_path = output_path.with_suffix(".jsonl.tmp")
        output = temporary_path.open("w")
        for d in firmdocs:
            sha = d["row"]["sha256"]
            if sha in blocked:
                raise RuntimeError("Holdout parsing denied")
            diag = {"document_id":d["document_id"],"sha256":sha,"firm_id":firm,"parser":name}
            ext = extraction.get(sha, {})
            textpath = a.root/"local-cache/fulltext"/(sha+".txt")
            metapath = a.root/"local-cache/fulltext"/(sha+".pages.json")
            if a.live_cache and metapath.exists() and textpath.exists():
                ext = json.loads(metapath.read_text())
            if ext.get("status") not in {"ok","partial"}:
                diagnostics.append(diag | {"validation":"extraction_failed","error":ext.get("error","not_extracted")})
                continue
            if sha not in cache or cache[sha][0].meta.get("date_hint") != d["row"].get("date_hint"):
                cache.clear()  # Keep memory bounded, including very long contest reports.
                for attempt in range(4):
                    meta = json.loads(metapath.read_text())
                    text = textpath.read_bytes().decode("utf-8")
                    if digest(text.encode()) == meta["text_sha256"]:
                        break
                    if a.live_cache:
                        time.sleep(.1)
                else:
                    raise ValueError("Fulltext hash mismatch: "+sha)
                report = Report(text,meta | {"file_format":d["row"]["file_format"],
                                            "sha256":sha,"date_hint":d["row"].get("date_hint")},firm)
                select(report, parser.VARIANTS)
                try:
                    candidates = finish(report,parser.parse(report))
                    summary = getattr(parser, "printed_counts", printed_counts)(report)
                    cache[sha] = report,candidates,summary,None
                except Exception as exc:
                    cache[sha] = report,[],None,type(exc).__name__+": "+str(exc)[:300]
            report,candidates,summary,error = cache[sha]
            diag |= report.layout_selection
            diag["year"] = (d["row"].get("date_hint") or "")[:4] or None
            rows = list(finding_rows(d,report,candidates,name))
            parsed = Counter(r["severity"] for r in rows if r["record_kind"] == "formal_finding")
            finding_count = len(rows)
            diag |= {"findings":finding_count,"formal_findings":sum(parsed.values()),"record_kinds":dict(Counter(r["record_kind"] for r in rows)),
                     "parsed_counts":{s:parsed[s] for s in SEVERITIES},"printed_summary":summary,"extraction_status":ext["status"],
                     "excluded_prior_findings": list(getattr(report, "excluded_prior_findings", {}).values()),
                     "unmapped_severities": dict(Counter(json.dumps(r["severity_original"], ensure_ascii=False) for r in rows if not r["severity_mapping"]["mapped"]))}
            diag['unmapped_statuses'] = dict(Counter(json.dumps(r['status_original'], ensure_ascii=False)
                                                    for r in rows if not r['status_mapping']['mapped']))
            if error:
                diag |= {"validation":"parser_error","error":error}
            elif not summary:
                diag["validation"] = "no_usable_printed_counts"
            elif summary.get("ambiguous"):
                diag["validation"] = "ambiguous_printed_counts"
            else:
                counts = summary["counts"]
                diag["compared_buckets"] = sorted(counts)
                diag["validation"] = "match" if all(parsed[s] == n for s,n in counts.items()) else "mismatch"
            # Link the comparison, but never use it to modify finding rows or severity.
            for row in rows:
                row["review"]["summary_reconciliation"] = diag["validation"]
            for row in rows:
                output.write(canonical(row)+"\n")
            finding_count_total += len(rows)
            formal_total += sum(r["record_kind"]=="formal_finding" for r in rows)
            diagnostics.append(diag)
        counts = Counter(d["validation"] for d in diagnostics)
        comparable = counts["match"] + counts["mismatch"]
        stats = {"firm_id":firm,"parser":name,"documents":len(firmdocs),"documents_with_findings":sum(d.get("findings",0)>0 for d in diagnostics),
                 "findings":finding_count_total,"formal_findings":formal_total,
                 "validations":dict(counts),"comparable_documents":comparable,"matching_documents":counts["match"],
                 "agreement_percent":round(100*counts["match"]/comparable,2) if comparable else None,
                 "summary_coverage_percent":round(100*comparable/len(firmdocs),2),"description":parser.DESCRIPTION}
        output.close()
        temporary_path.replace(output_path)
        write_jsonl(a.root/"data/findings/validation"/(firm+".jsonl"),diagnostics)
        write_json(a.root/"data/findings/validation"/(firm+".json"),stats)
        all_stats.append(stats)
        print(f"{firm}: {finding_count_total} findings; summary {counts['match']}/{comparable}; {stats['agreement_percent']}%; elapsed {time.monotonic()-started:.0f}s",flush=True)
    if not a.no_queue:
        rebuild_unknown_queue(a.root)
    # Partial firm runs don't overwrite the global summary; reporting recomputes from per-firm stats.
    if not a.firms:
        write_json(a.root/"data/findings/summary.json",{"version":VERSION,"by_firm":all_stats,"findings":sum(s["findings"] for s in all_stats),
                   "documents":sum(s["documents"] for s in all_stats),"holdouts_opened":0})


if __name__ == "__main__":
    main()
