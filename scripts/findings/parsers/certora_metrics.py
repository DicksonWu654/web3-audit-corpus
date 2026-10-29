"""Reproduce group 4 development metrics without opening blocked originals/text.

Run: python3 scripts/findings/parsers/certora_metrics.py
The old generic parser is executed afresh against the same cache as the new parsers.
Index agreement tests extraction completeness, not gold-set precision or recall.
"""
from collections import Counter
import importlib
import json
from pathlib import Path
import re
import sys
import subprocess

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import ROOT, holdouts, read_snapshot, digest, write_json
from core import Report, clean, finish, severity
from parsers import generic

FIRMS = ("solidified", "certora", "pessimistic")


def expected_sequence(report):
    """Use a separately printed index, never derive expected rows from details."""
    if report.firm == "pessimistic":
        from parsers.pessimistic import index_entries, ID
        entries=index_entries(report)
        return [{"key":x["key"],"start":x["start"],"end":x["end"]} for x in entries], "printed_toc_ids_or_titles"
    if report.firm == "certora":
        entries=[]
        # TOCs can wrap before their dotted leader, or omit leaders entirely.
        # End at the first substantive front-matter section after the contents.
        started=False
        for line in report.lines:
            if entries and re.fullmatch(r"(?:Project Summary|Summary|Introduction)",line.content,re.I):
                break
            m=re.match(r"^\s*(Critical|High|Medium|Low|Informational|[CHMLIN])[-–]\s*(\d+)\s*[.:–-]?\s+",line.content,re.I)
            if m and (re.search(r"\.{3,}",line.content) or line.excluded or entries):
                entries.append({"key":m[1]+"-"+m[2],"start":line.start,"end":line.end})
        return entries,"printed_toc_ids"
    from parsers.solidified import index_entries
    entries=index_entries(report)
    return entries,"printed_issue_index_ids"


def measure(report, parser, summary, expected):
    rows=finish(report,parser.parse(report))
    counts=Counter(c.normalized or severity(c.severity_raw) for c in rows if c.record_kind=="formal_finding")
    actual=[c.printed_id or clean(c.title + (" ("+c.status_raw+")" if c.status_raw else "")) for c in rows if c.record_kind=="formal_finding"]
    raw_match=None if not summary else all(counts[k]==v for k,v in summary["counts"].items())
    match=None if not summary or summary.get("ambiguous") else raw_match
    expected_keys=[e["key"] for e in expected]
    if report.firm=='pessimistic':
        bare=lambda s:re.sub(r"\s*\([^()]*\)\s*$","",s)
        actual=[bare(s) for s in actual];expected_keys=[bare(s) for s in expected_keys]
    return {"findings":len(rows),"formal_findings":sum(counts.values()),"summary_match":match,
            "raw_summary_match_including_ambiguous":raw_match,
            "sequence_match":Counter(actual)==Counter(expected_keys) if expected else None,
            "ordered_sequence_match":actual==expected_keys if expected else None,
            "actual_sequence":actual,"severity_counts":dict(counts),"missing_title":sum(not clean(c.title or "") for c in rows),
            "missing_severity":sum(c.severity_raw is None for c in rows),"unknown_severity":counts["unknown"]}


def aggregate(records, key):
    values=[r[key] for r in records if key in r]
    comparable=[v for v in values if v["summary_match"] is not None]
    seq=[v for r,v in zip([r for r in records if key in r],values) if (not r.get("summary") or r["summary"].get('ambiguous')) and v["sequence_match"] is not None]
    allseq=[v for v in values if v["sequence_match"] is not None]
    raw=[v for v in values if v['raw_summary_match_including_ambiguous'] is not None]
    audits=[r[key] for r in records if key in r and r['doc_kind']=='audit_report']
    return {"documents":len(records),"readable_documents":len(values),"documents_with_formal_findings":sum(v["formal_findings"]>0 for v in values),
            "findings":sum(v["findings"] for v in values),"formal_findings":sum(v["formal_findings"] for v in values),
            "summary_comparable":len(comparable),"summary_matching":sum(v["summary_match"] for v in comparable),
            "summary_ambiguous":sum(bool(r.get('summary',{}).get('ambiguous')) for r in records if r.get('summary')),
            "all_numeric_summaries":len(raw),"raw_summary_matches_including_ambiguous":sum(v['raw_summary_match_including_ambiguous'] for v in raw),
            "raw_summary_agreement_percent_including_ambiguous":round(100*sum(v['raw_summary_match_including_ambiguous'] for v in raw)/len(raw),2) if raw else None,
            "summary_agreement_percent":round(100*sum(v["summary_match"] for v in comparable)/len(comparable),2) if comparable else None,
            "no_summary_sequence_comparable":len(seq),"no_summary_sequence_complete":sum(v["sequence_match"] for v in seq),
            "no_summary_sequence_percent":round(100*sum(v["sequence_match"] for v in seq)/len(seq),2) if seq else None,
            "all_sequence_comparable":len(allseq),"all_sequence_complete":sum(v["sequence_match"] for v in allseq),
            "readable_audit_reports":len(audits),"audit_reports_with_formal_findings":sum(v['formal_findings']>0 for v in audits),
            "audit_report_nonempty_coverage_percent":round(100*sum(v['formal_findings']>0 for v in audits)/len(audits),2) if audits else None,
            "missing_title_rows":sum(v["missing_title"] for v in values),"missing_severity_rows":sum(v["missing_severity"] for v in values),
            "unknown_severity_rows":sum(v["unknown_severity"] for v in values)}


def main():
    blocked=holdouts(ROOT)  # Must precede any document/cache access.
    docs=read_snapshot(ROOT)
    result={"holdouts_opened":0,"evaluation":"development; not held-out gold accuracy", "publishers":{},
            "limitations":["Printed numeric summaries compare only buckets the publisher explicitly states.",
                            "Explicit zero statements may compare only zero buckets, so high agreement is weak evidence of full recall.",
                            "Sequences come from separately printed TOCs or issue tables; not every report has one.",
                            "Legacy Pessimistic titles use the TOC to locate detail headings; that sequence check is correlated with extraction.",
                            "No-summary coverage and unavailable reference sequences are reported separately; zero rows never implies a clean audit."],
            "files_written":[f"scripts/findings/parsers/{f}.py" for f in FIRMS]+["scripts/findings/parsers/certora_metrics.py","scripts/findings/parsers/test_solidified_certora_pessimistic.py"]+
                            [f"data/findings/{f}.jsonl" for f in FIRMS]+[f"data/findings/validation/{f}.{ext}" for f in FIRMS for ext in ("json","jsonl")]+["local-cache/tmp/group4-solidified-certora-pessimistic.json","local-cache/tmp/group4-solidified-certora-pessimistic-metrics-stdout.txt"]}
    result['original_phase4a_validation_baseline']={
        'solidified':{'documents':246,'findings':717,'formal_findings':35,'documents_with_any_rows':139,'summary_comparable':0,'summary_matching':0},
        'certora':{'documents':197,'findings':1591,'formal_findings':1585,'documents_with_any_rows':116,'summary_comparable':105,'summary_matching':64},
        'pessimistic':{'documents':179,'findings':0,'formal_findings':0,'documents_with_any_rows':0,'summary_comparable':0,'summary_matching':0}}
    result['original_phase4a_validation_baseline_provenance']='Existing validation/{firm}.json read before owned parser edits. Recomputed generic baseline below uses the same new independent references for like-for-like comparison.'
    for firm in FIRMS:
        parser=importlib.import_module("parsers."+firm)
        records=[]
        firmdocs=[d for d in docs if d["row"]["firm_id"]==firm]
        unique=sorted({d["row"]["sha256"]:d for d in firmdocs}.values(),key=lambda d:(d["row"].get("date_hint") or "",d["row"]["filename"]))
        sample={unique[round(i*(len(unique)-1)/14)]["row"]["sha256"] for i in range(15)}
        manifest=[]
        for d in firmdocs:
            sha=d["row"]["sha256"]
            assert sha not in blocked
            p=ROOT/"local-cache/fulltext"/(sha+".txt")
            mp=p.with_suffix(".pages.json")
            record={"sha256":sha,"document_id":d["document_id"],"filename":d["row"]["filename"],"doc_kind":d["row"]["doc_kind"]}
            if not p.exists() or not mp.exists():
                record["error"]="cache_missing";records.append(record);continue
            text=p.read_text(); meta=json.loads(mp.read_text())
            if meta.get("status") not in {"ok","partial"}:
                record["error"]=meta.get("error",meta.get("status"));records.append(record);continue
            assert digest(text.encode())==meta["text_sha256"]
            report=Report(text,meta,firm)
            summary=parser.printed_counts(report)
            expected,basis=expected_sequence(report)
            record|={"summary":summary,"expected_sequence":[e["key"] for e in expected],"sequence_basis":basis,
                     "sequence_evidence":expected,"before":measure(report,generic,summary,expected),"after":measure(report,parser,summary,expected)}
            if sha in sample and sha not in {x["sha256"] for x in manifest}:
                layout="numbered detail sections" if firm=="solidified" else "severity-ID detail" if re.search(r"(?m)^\s*[CHMLIN]-\d+",text) else "legacy Issue cards or verification tables" if firm=="certora" else "severity-ID detail" if re.search(r"(?m)^\s*[CHMLNI]\d+[.]",text) else "legacy unnumbered titled issues"
                manifest.append({"sha256":sha,"filename":d["row"]["filename"],"year":(d["row"].get("date_hint") or "unknown")[:4],
                                 "layout_observation":layout,"has_independent_numeric_summary":bool(summary),"index_entries":len(expected),
                                 "formal_findings":record["after"]["formal_findings"],"pages":len(meta["pages"]),
                                 "severity_observation":("Critical/Major/Minor/Notes section labels; Warnings retain unknown" if firm=='solidified' else "Explicit Severity field takes precedence over the printed ID; contradictions retained" if firm=='certora' else "C/H/M/L/N ID prefix, or printed severity section for pre-ID reports"),
                                 "status_observation":("Explicit Status/Update fields only; unlabelled narrative not interpreted" if firm!='pessimistic' else "Parenthetic native status; commented/addressed retained without invented resolution"),
                                 "appendix_observation":("Audit detail stops before Bug Bounty/Appendix/Disclaimer" if firm=='solidified' else "Formal Verification rule references excluded after detail" if firm=='certora' else "Manual findings exclude Appendix A automation and removed-issue appendices"),
                                 "missing_severity_rows":record['after']['missing_severity'],
                                 "sample_evidence":text[expected[0]["start"]:expected[0]["end"]] if expected else text[:160]})
            records.append(record)
        residual=[{k:r[k] for k in ("sha256","filename","summary","expected_sequence","before","after") if k in r} for r in records
                  if "after" not in r or r["after"]["summary_match"] is False or r["after"]["sequence_match"] is False or not r["after"]["formal_findings"]]
        result["publishers"][firm]={"before":aggregate(records,"before"),"after":aggregate(records,"after"),"study_manifest":manifest,
                                    "residual_examples":residual,"documents":records}
        result['publishers'][firm]['report_kind_counts']=dict(Counter(r['doc_kind'] for r in records))
    result['residual_failure_classes']={
        'solidified':[
            {'class':'Publisher index/detail ID inconsistency; source IDs deliberately preserved','examples':['23b7a0f60a06','b0fa7e89478a','b98e5a4097fd','1dbcab9fba1a']},
            {'class':'Stale overview totals or mixed final-status/original-finding totals','examples':['6b2d2d0041','f87ac4acd6','86c18b91f0','786ee48743']},
            {'class':'Early numbered reports omit source severity; missing severity remains null/unknown','examples':['5476f99736bc','b864c44e9724']}],
        'certora':[
            {'class':'Published numeric summary and detail inventory disagree','examples':['521155b73e','16c5a4b3dd','65c8ccdb19','18e2ab6e8f','139542cb8a']},
            {'class':'Some detail Severity fields contradict severity-coded IDs; explicit field retained, numeric summary remains comparable','examples':['4b072c6d53','32d09ffd4d','12217c36c5']},
            {'class':'Early verification-only tables and non-ID narratives not comprehensively recovered; zero output is not a clean-audit claim','examples':['83b8f4e29a5','3b3832f703c4']}],
        'pessimistic':[
            {'class':'Sparse/image-like text in Kommodo; no invented findings','examples':['1f5ef095f20d']},
            {'class':'Legacy headings located with source TOC; title-only sequence agreement correlated with extraction','examples':['c725a9e71e70']}]}
    test=subprocess.run([sys.executable,str(Path(__file__).with_name('test_solidified_certora_pessimistic.py'))],capture_output=True,text=True,check=False)
    result['tests']={'command':'python3 scripts/findings/parsers/test_solidified_certora_pessimistic.py','exit_code':test.returncode,'output':test.stdout+test.stderr}
    if test.returncode:
        raise RuntimeError(result['tests']['output'])
    framework=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'test_framework.py')],capture_output=True,text=True,check=False)
    result['framework_tests']={'command':'python3 scripts/findings/test_framework.py','exit_code':framework.returncode,'output':framework.stdout+framework.stderr,
                               'ownership_note':'Shared framework and other publisher modules are outside this task ownership.'}
    write_json(Path("local-cache/tmp/group4-solidified-certora-pessimistic.json"),result)
    print(json.dumps({f:{k:v for k,v in d.items() if k in {"before","after"}} for f,d in result["publishers"].items()},indent=2))


if __name__=="__main__":
    main()
