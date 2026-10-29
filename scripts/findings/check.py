"""Independently verify Phase 4a output identity, spans, holdout exclusion and count accounting."""
import argparse
from collections import Counter, defaultdict
from functools import lru_cache
import json
from pathlib import Path
from common import ROOT, SEVERITIES, digest, holdouts, read_snapshot, uid, write_json
from parsers import FIRMS, CONTESTS, module
from variants import select
from core import Report
from core import severity_mapping, severity_policy, select_severity_era
from status_resolve import STATUSES, status_mapping, status_policy, select_status_era
from streams import finding_rows


@lru_cache(maxsize=8)
def status_policy_path(root,fingerprint):
    """Resolve a byte-verified historical policy without rewriting old receipts."""
    if fingerprint==status_policy()[2]:return None
    path=root/'schema/status_map_compatibility.json'
    entry=json.loads(path.read_text()).get(fingerprint) if path.exists() else None
    assert entry,'Unknown historical status policy: '+fingerprint
    target=(root/entry['path']).resolve()
    assert target.is_relative_to((root/'local-cache/policy-history/status').resolve())
    assert digest(target.read_bytes())==fingerprint,'Historical status policy changed'
    return target


def check_statuses(root):
    """Validate the status interchange independently of unrelated layout work."""
    blocked=holdouts(root);policy,_,fingerprint=status_policy()
    active_firms={d['row']['firm_id'] for d in read_snapshot(root)}
    eras={};cache={};counts=Counter();rows=0;proofs=0;unaccounted=Counter()
    def text_for(row):
        sha=row['sha256']
        assert sha not in blocked
        if sha not in cache:
            cache.clear()
            text=(root/'local-cache/fulltext'/(sha+'.txt')).read_bytes().decode('utf-8')
            assert digest(text.encode())==row['body_span']['text_sha256'], 'Stale source text receipt: '+sha
            cache[sha]=text
        return cache[sha]
    seen=set()
    for path, row in finding_rows(root/'data/findings', firms=active_firms):
        assert row['sha256'] not in blocked
        assert row['finding_id'] not in seen, 'Duplicate live finding identity'
        seen.add(row['finding_id'])
        raw=row['status_original'];receipt=row['status_mapping']
        assert raw==row['status_raw']==row['provenance']['extraction_record']['status_raw']
        assert row['status'] in STATUSES and receipt['input']==raw
        historical=status_policy_path(root,receipt['map_sha256'])
        selected_policy=status_policy(historical)[0]
        key=(path.stem,row['sha256'],receipt['map_sha256'])
        if key not in eras:
            publisher_policy = selected_policy.get('publishers', {}).get(path.stem, {})
            text=text_for(row) if any(e.get('definition_regex') for e in publisher_policy.get('eras', [])) else None
            eras[key]=select_status_era(path.stem,sha256=key[1],report_text=text,policy_path=historical)
        expected=status_mapping(raw,path.stem,era=eras[key],log=False,policy_path=historical)
        assert receipt==expected==row['evidence']['status_mapping'], 'Incorrect status mapping receipt'
        assert row['status']==expected['normalized']
        current_key=(path.stem,row['sha256'],'current')
        if current_key not in eras:
            eras[current_key]=select_status_era(path.stem,sha256=row['sha256'],report_text=text_for(row))
        assert row['status']==status_mapping(raw,path.stem,era=eras[current_key],log=False)['normalized'],'Historical interpretation differs from current policy'
        # Generic fallback receipts preserve publisher labels that have no
        # era-specific crosswalk; they are intentionally normalized to
        # not_stated and remain auditable in the row evidence.
        if (not expected['mapped'] and not expected.get('listed')
                and expected.get('reason') != 'label_not_in_publisher_era'):
            unaccounted[(path.stem,raw)]+=1
        proof=row['evidence'].get('status_evidence')
        if proof:
            text=text_for(row)
            assert text[proof['start']:proof['end']]==proof['text']==proof['raw']==raw, ('Incorrect status evidence span',path.stem,row['finding_id'])
            proofs+=1
        rows+=1;counts[row['status']]+=1
    assert not unaccounted, 'Unaccounted status labels: '+repr(unaccounted)
    result={'rows':rows,'statuses':dict(counts),'source_spans_verified':proofs,'map_sha256':fingerprint,
            'holdouts_opened':0,'unaccounted_status_labels':0,'ok':True}
    write_json(root/'data/findings/status_check.json',result)
    print(json.dumps(result,sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,default=ROOT)
    p.add_argument('--statuses-only',action='store_true',help='Verify canonical status receipts and source spans only')
    a = p.parse_args()
    if a.statuses_only:return check_statuses(a.root)
    blocked = holdouts(a.root)
    docs = {d["document_id"]:d for d in read_snapshot(a.root)}
    extractions = {r["sha256"]:r for r in map(json.loads,(a.root/"data/fulltext/extractions.jsonl").read_text().splitlines())}
    assert not set(extractions) & blocked
    assert {d["row"]["sha256"] for d in docs.values()} == set(extractions),"Extraction/snapshot mismatch"
    text_cache, pages_count, errors = {}, 0, []
    def load(sha):
        nonlocal pages_count
        assert sha not in blocked,"Holdout text access denied"
        if sha not in text_cache:
            text_cache.clear()
            path = a.root/"local-cache/fulltext"/(sha+".txt")
            meta = json.loads(path.with_suffix(".pages.json").read_text())
            text = path.read_bytes().decode("utf-8")
            assert digest(text.encode())==meta["text_sha256"]
            assert meta["characters"]==len(text) and meta["page_count"]==len(meta["pages"])
            for field in ("status","text_sha256","characters","page_count","method"):
                assert extractions[sha][field]==meta[field],f"Extraction receipt/cache mismatch: {sha} {field}"
            assert "\f".join(p["text"] for p in meta["pages"]) == text
            for p in meta["pages"]:
                assert text[p["start"]:p["end"]] == p["text"]
            text_cache[sha] = text,meta
        return text_cache[sha]
    seen, total, by_firm, parsed, kinds = set(),0,Counter(),defaultdict(Counter),Counter()
    era_cache = {}
    layout_cache = {}
    row_layouts = {}
    policy,_,map_sha = severity_policy()
    compatibility_path=a.root/'schema/severity_map_compatibility.json'
    compatibility=json.loads(compatibility_path.read_text()) if compatibility_path.exists() else {}
    globals_sha=digest({k:v for k,v in policy.items() if k!='publishers'})
    publisher_policy_hashes={pid:digest(value) for pid,value in policy['publishers'].items()}
    status_map_sha = status_policy()[2]
    status_eras = {}
    historical_status_eras={}
    primary_by_firm=Counter();supplemental_count=0
    for path, row in finding_rows(a.root/'data/findings', firms={d['row']['firm_id'] for d in docs.values()}):
        is_supplemental=path.parent.name=='supplemental'
        supplemental_count+=is_supplemental
        if not is_supplemental:primary_by_firm[path.stem]+=1
        assert row["sha256"] not in blocked
        parent = docs[row["document_id"]]
        assert row["publisher_id"]==parent["row"]["firm_id"]==path.stem
        assert row["sha256"]==parent["row"]["sha256"]
        assert row["source_record_sha256"]==parent["source_record_sha256"]
        assert row["finding_id"]==uid("finding",row["source_tag"],row["source_record_id"])
        assert row["finding_id"] not in seen
        seen.add(row["finding_id"])
        assert row["severity"] in SEVERITIES and row["severity"]==row["severity_normalized"]
        assert row["severity_raw"]==row["severity_original"]
        assert row["source_family"]=="collected" and row["is_seed"] is False
        assert 0 <= row["confidence"] <= 1
        text,meta = load(row["sha256"])
        key = (row["publisher_id"], row["sha256"])
        if key not in era_cache:
            era_cache[key] = select_severity_era(key[0], sha256=key[1], report_text=text)
        if row["document_id"] not in layout_cache:
            report=Report(text,meta | {"date_hint":parent["row"].get("date_hint")},row["publisher_id"])
            select(report,module(row["publisher_id"]).VARIANTS)
            layout_cache[row["document_id"]]=report.layout_selection
        layout=layout_cache[row["document_id"]]
        assert row["variant_id"]==row["provenance"]["variant_id"]==layout["variant_id"], "Stale layout selection"
        row_layouts[row["document_id"]]=row["variant_id"]
        assert row["review"]["unknown_layout"]==layout["unknown_layout"]
        if layout["unknown_layout"]:assert row["method"] in {"generic_fallback","summary_inventory"}
        if row['method']=='summary_inventory':
            assert row['record_kind']=='summary_excerpt' and row['confidence']<.7
            proof=row['evidence']['inventory_span']
            assert text[proof['start']:proof['end']]==proof['text']==row['body_text']
        proof=row["evidence"].get("status_evidence")
        if proof:
            assert text[proof["start"]:proof["end"]]==proof["text"]==proof["raw"], "Incorrect status evidence span"
            assert proof["raw"]==row["status_raw"]
        assert row['status'] in STATUSES
        assert row['status_original'] == row['status_raw'] == row['provenance']['extraction_record']['status_raw']
        sm = row['status_mapping']
        assert sm['input'] == row['status_original']
        historical=status_policy_path(a.root,sm['map_sha256'])
        historical_key=(*key,sm['map_sha256'])
        if historical_key not in historical_status_eras:
            historical_status_eras[historical_key]=select_status_era(key[0],sha256=key[1],report_text=text,policy_path=historical)
        historical_era=historical_status_eras[historical_key]
        original_status=status_mapping(row['status_original'],key[0],era=historical_era,policy_path=historical,log=False)
        assert sm==original_status==row['evidence']['status_mapping'],'Historical status receipt does not replay'
        if key not in status_eras:
            status_eras[key] = select_status_era(key[0], sha256=key[1], report_text=text)
        expected_status = status_mapping(row['status_original'], key[0], era=status_eras[key], log=False)
        assert row['status'] == expected_status['normalized']
        mapping = row["severity_mapping"]
        if mapping['map_sha256']!=map_sha:
            prior=compatibility.get(mapping['map_sha256'],{})
            assert prior.get('globals_sha256')==globals_sha and prior.get('publishers',{}).get(key[0])==publisher_policy_hashes.get(key[0]), 'Incompatible historical crosswalk fingerprint'
        assert mapping["input"] == row["severity_original"]
        assert mapping["era"] == era_cache[key], "Incorrect publisher severity era"
        expected = severity_mapping(row["severity_original"], key[0], era=era_cache[key],
            kind=(mapping.get("rule") or "").removeprefix("unrated_"), log=False)
        assert expected["normalized"] == row["severity"] and expected["mapped"] == mapping["mapped"]
        start,end = row["body_span"]["start"],row["body_span"]["end"]
        assert 0 <= start < end <= len(text)
        assert text[start:end]==row["body_text"]
        pages = [p["page"] for p in meta["pages"] if p["end"]>start and p["start"]<end]
        assert row["page"]==pages[0] and row["body_span"]["pages"]==pages
        assert row["body_span"]["text_sha256"]==meta["text_sha256"]
        assert row["provenance"]["extraction_record_sha256"]==digest(row["provenance"]["extraction_record"])
        if row["record_kind"]=="formal_finding":
            parsed[row["document_id"]][row["severity"]]+=1
        kinds[row["record_kind"]]+=1
        total+=1
        by_firm[path.stem]+=1
    # Validate unused/zero-finding documents too, after finding receipts so a
    # stale field receipt fails before scanning the entire text cache.
    for sha,ext in extractions.items():
        if ext["status"] in {"ok","partial"}:
            text,meta = load(sha)
            pages_count += len(meta["pages"])
    states, summary_matches, comparable, diagnostic_ids = Counter(),0,0,set()
    snapshot_firms = {d["row"]["firm_id"] for d in docs.values()}
    auxiliary_diagnostics = []
    for path in sorted((a.root/"data/findings/validation").glob("*.jsonl")):
        # Group development audits are auxiliary streams, not another copy of
        # the runner's one-diagnostic-per-document publisher interchange.
        if path.stem not in snapshot_firms:
            auxiliary_diagnostics.append(str(path.relative_to(a.root)))
            continue
        diagnostics = [json.loads(line) for line in path.read_text().splitlines()]
        for row in diagnostics:
            assert row["sha256"] not in blocked
            assert row["document_id"] not in diagnostic_ids
            diagnostic_ids.add(row["document_id"])
            states[row["validation"]]+=1
            if row["document_id"] in row_layouts:assert row["variant_id"]==row_layouts[row["document_id"]]
            if row.get("unknown_layout"):assert row["variant_id"]==path.stem+"/generic_fallback"
            scope=(row.get("printed_summary") or {}).get("comparison_scope")
            if scope:
                text,_=load(row["sha256"])
                assert text[scope["start"]:scope["end"]]==scope["text"]
            for excluded in row.get("excluded_prior_findings", []):
                from common import VERSION
                sid = row["document_id"]+":"+VERSION+":"+str(excluded["start"])
                assert uid("finding", "collect:"+path.stem, sid) not in seen, "Previously-audited finding emitted"
                if excluded.get("section"):
                    text, _ = load(row["sha256"])
                    proof = excluded["section"]
                    assert text[proof["start"]:proof["start"]+len(proof["heading_text"])] == proof["heading_text"]
            expected = row.get("printed_summary")
            if row["validation"] in {"match","mismatch"}:
                observed = parsed[row["document_id"]]
                assert {s:observed[s] for s in SEVERITIES}==row["parsed_counts"]
                equals = all(observed[s]==n for s,n in expected["counts"].items())
                assert (row["validation"]=="match")==equals
                summary_matches+=equals
                comparable+=1
            if expected:
                for proof in expected["evidence"]+((expected.get("independent_summary_inventory") or {}).get("evidence") or []):
                    if "text" in proof:
                        text,_ = load(row["sha256"])
                        assert text[proof["start"]:proof["end"]]==proof["text"]
        stats = json.loads(path.with_suffix(".json").read_text())
        assert stats["documents"]==len(diagnostics)
        assert stats["findings"]==primary_by_firm[path.stem]
        assert stats["validations"]==dict(Counter(d["validation"] for d in diagnostics))
    assert set(docs)==diagnostic_ids
    queue=[json.loads(line) for line in (a.root/"data/findings/_unknown_layouts.jsonl").open()]
    queued_ids=set()
    for item in queue:
        assert item["sha256"] not in blocked
        for did in item["document_ids"]:
            assert did not in queued_ids
            queued_ids.add(did)
            assert docs[did]["row"]["firm_id"]==item["firm"]
            assert docs[did]["row"]["sha256"]==item["sha256"]
    unknown_ids=set()
    for firm in snapshot_firms:
        for line in (a.root/"data/findings/validation"/(firm+".jsonl")).open():
            d=json.loads(line)
            if d.get("unknown_layout"):unknown_ids.add(d["document_id"])
    assert queued_ids==unknown_ids, "Unknown-layout queue incomplete"
    for firm in FIRMS+CONTESTS:
        assert (a.root/"data/findings"/(firm+".jsonl")).is_file()
    status_counts = Counter(extractions[d["row"]["sha256"]]["status"] for d in docs.values())
    inventory = json.loads((a.root/"data/fulltext/inventory.json").read_text())
    assert inventory["scope_sha256"]==digest((a.root/"registry/scope_tier_a.csv").read_bytes()),"Scope changed since snapshot; refresh inputs"
    assert inventory["holdout_list_sha256"]==digest((a.root/"data/holdout/gold_sha256.txt").read_bytes()),"Holdout list changed since snapshot; refresh inputs"
    changed = []
    for receipt in inventory["collection_files"]:
        path = a.root/receipt["path"]
        if digest(path.read_bytes())!=receipt["sha256"]:
            changed.append(receipt["path"])
    known = {r["path"] for r in inventory["collection_files"]}
    new = [str(p.relative_to(a.root)) for p in sorted((a.root/"data/collect").glob("*/reports.jsonl")) if str(p.relative_to(a.root)) not in known]
    result = {"ok":True,"documents":len(docs),"artifacts":len(extractions),"findings":total,"record_kinds":dict(kinds),"pages":pages_count,
              "documents_fulltext":dict(status_counts),"fulltext_percent":round(100*status_counts["ok"]/len(docs),4),
              "text_cache_percent":round(100*(status_counts["ok"]+status_counts["partial"])/len(docs),4),
              "summary_matching":summary_matches,"summary_comparable":comparable,
              "summary_agreement_percent":round(100*summary_matches/comparable,2) if comparable else None,
              "validation_states":dict(states),"dedicated_firm_parsers":len(FIRMS),"contest_parsers":len(CONTESTS),
              "holdout_rows_found":0,"collection_files_changed_since_snapshot":changed,"collection_files_new_since_snapshot":new}
    result["primary_findings"] = sum(primary_by_firm.values())
    result["supplemental_findings"] = supplemental_count
    result["auxiliary_diagnostic_streams"] = auxiliary_diagnostics
    result["unknown_layout_artifacts"] = len(queue)
    result["unknown_layout_occurrences"] = len(queued_ids)
    write_json(a.root/"data/findings/check.json",result)
    print(json.dumps(result,indent=2))


if __name__=="__main__":
    main()
