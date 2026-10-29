"""Local Phase 4e development census; deny holdouts before every text read."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, documents, holdouts, read_snapshot
from core import Report, finish, status
from parsers import module
from run import finding_rows
from variants_report import metric

FIRMS = ("oak-security", "consensys-diligence")


def load(doc):
    sha = doc["row"]["sha256"]
    if sha in holdouts():
        raise ValueError("Holdout access denied")
    base = ROOT / "local-cache/fulltext"
    meta = json.loads((base / (sha + ".pages.json")).read_text())
    text = (base / (sha + ".txt")).read_bytes().decode("utf-8")
    if digest(text.encode()) != meta["text_sha256"]:
        raise ValueError("Text hash mismatch")
    return Report(text, meta | {"date_hint": doc["row"].get("date_hint")}, doc["row"]["firm_id"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firm", choices=FIRMS)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--new-only", action="store_true")
    parser.add_argument("--sha")
    parser.add_argument("--sample-years", action="store_true")
    parser.add_argument("--zero", action="store_true")
    parser.add_argument("--unknown", action="store_true")
    parser.add_argument("--metrics", action="store_true")
    parser.add_argument("--deltas", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--flags", action="store_true")
    parser.add_argument("--missing-status", action="store_true")
    parser.add_argument("--unread-resolution", action="store_true")
    parser.add_argument("--match", default=r"(?:Detailed Findings|Severity|Status|Resolution|Findings|Issues|Recommendations|^\s*\d+\.\d+\s)")
    parser.add_argument("--limit", type=int, default=60)
    parser.add_argument("--candidate-limit", type=int, default=2)
    args = parser.parse_args()
    groups = defaultdict(list)
    snapshot = read_snapshot()
    prior_hashes = {(doc["row"]["firm_id"], doc["row"]["sha256"]) for doc in snapshot}
    source = documents()[0] if args.live else snapshot
    for doc in source:
        if args.new_only and (doc["row"]["firm_id"], doc["row"]["sha256"]) in prior_hashes:
            continue
        if doc["row"]["firm_id"] in FIRMS and (not args.firm or doc["row"]["firm_id"] == args.firm):
            groups[doc["row"]["firm_id"]].append(doc)
    for firm, docs in sorted(groups.items()):
        print("CENSUS", firm, len(docs), dict(sorted(Counter(((d["row"].get("date_hint") or "unknown")[:4], d["row"]["file_format"]) for d in docs).items())))
        totals = defaultdict(Counter)
        diagnostics, emitted = defaultdict(list), defaultdict(list)
        seen_years = set()
        for doc in sorted(docs, key=lambda d: (d["row"].get("date_hint") or "", d["row"]["sha256"])):
            if args.sha and not doc["row"]["sha256"].startswith(args.sha):
                continue
            try:
                report = load(doc)
            except (FileNotFoundError, KeyError):
                totals["extraction_failed"]["documents"] += 1
                continue
            if report.meta.get("status") not in {"ok", "partial", None}:
                totals["extraction_failed"]["documents"] += 1
                continue
            adapter = module(firm)
            candidates = finish(report, adapter.parse(report))
            variant = report.layout_selection["variant_id"]
            if args.verify:
                if report.layout_selection["unknown_layout"]:
                    raise AssertionError("Unrecognized layout: " + doc["row"]["sha256"])
                for candidate in candidates:
                    if not (0 <= candidate.start < candidate.end <= len(report.text)):
                        raise AssertionError("Invalid finding span")
                    proof = candidate.evidence.get("status_evidence")
                    if candidate.status_raw is not None and not proof:
                        raise AssertionError("Status without publisher evidence: " + doc["row"]["sha256"] + " " + str(candidate.printed_id))
                    if proof and (report.text[proof["start"]:proof["end"]] != proof["text"] or candidate.status_raw != proof["text"]):
                        raise AssertionError("Status evidence is not exact")
                    for evidence in candidate.evidence.get("resolution_evidence", []):
                        if report.text[evidence["start"]:evidence["end"]] != evidence["text"]:
                            raise AssertionError("Resolution evidence is not exact")
            if args.deltas:
                from importlib import import_module
                raw = import_module(adapter.__name__)
                legacy = finish(report, raw.parse(report))
                if [(c.start, c.printed_id) for c in candidates] != [(c.start, c.printed_id) for c in legacy]:
                    print("GRAMMAR_DELTA", doc["row"]["sha256"], doc["row"]["filename"], variant, "legacy", len(legacy), "variant", len(candidates))
            if args.metrics:
                rows = list(finding_rows(doc, report, candidates, adapter.__name__.split(".")[-1]))
                summary = adapter.printed_counts(report)
                parsed = Counter(row["severity"] for row in rows if row["record_kind"] == "formal_finding")
                validation = "no_usable_printed_counts" if not summary else "ambiguous_printed_counts" if summary.get("ambiguous") else "match" if all(parsed[key] == n for key, n in summary["counts"].items()) else "mismatch"
                diagnostics[variant].append(dict(document_id=doc["document_id"], sha256=doc["row"]["sha256"], validation=validation))
                emitted[variant].extend(rows)
            count = totals[variant]
            count["documents"] += 1
            count["year:" + (doc["row"].get("date_hint") or "unknown")[:4]] += 1
            count["rows"] += len(candidates)
            count["documents_with_findings"] += bool(candidates)
            count["known_status"] += sum((c.normalized_status or status(c.status_raw)) not in {None, "other"} for c in candidates)
            for candidate in candidates:
                count["status:" + str(candidate.status_raw)] += 1
            year = ((doc["row"].get("date_hint") or "unknown")[:4], doc["row"]["file_format"])
            selected = bool(args.sha) or args.zero and not candidates or args.unknown and report.layout_selection["unknown_layout"] or args.missing_status and any(c.status_raw is None for c in candidates) or args.sample_years and year not in seen_years
            if args.unread_resolution:
                selected = any(c.status_raw is None and c.resolution for c in candidates)
            seen_years.add(year)
            if not selected:
                continue
            print("DOC", doc["row"]["sha256"], year, doc["row"]["filename"], variant, "rows", len(candidates))
            if args.missing_status:
                for candidate in [c for c in candidates if c.status_raw is None][:args.candidate_limit]:
                    body = report.text[candidate.start:candidate.end]
                    evidence = [line for line in body.splitlines() if re.search(r"status|resolution|remediation|update|fixed|addressed|mitigat", line, re.I)]
                    print("MISSING", candidate.printed_id, candidate.title, repr(body[:300]), "STATUS_LINES", evidence[:12])
            if args.unread_resolution:
                for candidate in [c for c in candidates if c.status_raw is None and c.resolution][:args.candidate_limit]:
                    print("UNREAD_RESOLUTION", candidate.printed_id, repr(candidate.resolution[:1100]))
            budget = args.limit
            for line in report.lines:
                if re.search(args.match, line.text, re.I) and budget > 0:
                    print("P", line.page, "CODE=" + str(line.code) if args.flags else "", line.text)
                    budget -= 1
        for variant, counts in sorted(totals.items()):
            print("METRIC", variant, dict(counts))
        if args.metrics:
            for variant in sorted(diagnostics):
                print("FRAMEWORK_METRIC", json.dumps(metric(firm, variant, diagnostics[variant], emitted[variant]), sort_keys=True))


if __name__ == "__main__":
    main()
