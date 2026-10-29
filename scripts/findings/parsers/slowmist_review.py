"""Guarded SlowMist development evidence and deterministic regression checks.

Run python3 scripts/findings/parsers/slowmist_review.py --write to refresh only
SlowMist's development manifest. No holdout originals or cached text are opened.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import ROOT, digest, holdouts, read_snapshot, write_json
from core import Report, finish, severity
from parsers import slowmist
from test_group2 import load_report, sequence

# Distinct eligible native layouts, eras and explicit zero-output classes.
SAMPLES = {
    'bf9eed647423631da2d13eecabad5398a714183e956ae3212cb4f160b967ad42': ('Chinese numbered severity chapters',14),
    'f6e5d59696dec787f00bd35a360375f9c47dd313535a0a9ba65744624f1a7858': ('English title-linked result classifications',12),
    '0c6a28903a9237cd19a6f10a734ce8dbd569809617f8c6d5647f9de60b0f51c6': ('English numbered severity chapters',6),
    'c488b9786eb9eba609e45f47a277481f40de9b294673a1a0243251c549200c28': ('English nested low and suggestion findings',10),
    'b9c145b59edf523585cc1799d7da86ee033dea1b89748a91bb1ad0f23137311e': ('English unnumbered risk parents/local numbers',8),
    '7d98cb7645ad53477004664c9ad5f5750f73de1c4dff55b3cca194c37263b0f5': ('Chinese unnumbered risk parents/local numbers',8),
    '9f78a39d01e7df77f191d99fe779d9e0d6efefcc73860ed9672934128dd4bc41': ('Wrapped inline risk suffixes and weakness',6),
    '96f37710cfe9e2e057537d3a4fd4c310f3207656ed6f07e13197e740f9e169f7': ('Standalone narrative findings under severity parents',8),
    '7f23f4d0a6dbe76c9fe0a679894e66bca67c6c5a7fbe579b818f8404820a63b2': ('Result references linked to earlier audit sections',7),
    '83ccbf9706145bafb73b7da8a7d4b80fb4869fa3b6f1ebb0dcbfb8ff13c0523f': ('Chrome wallet explicit Threat cells',6),
    '2b98b2e55eb475bab4273478596391eba0f26ba18f4ec223d91968172ff9ba2f': ('Android wallet Threat and suggestion cells',7),
    'f186523b0fcf31b59b99a09dbb2fc3242c77e02df56bf41628ab2f496d6b5169': ('iOS wallet Threat rows',9),
    '38114e61109ea4cfd7bbd49950b0a947048c6262b1c879a990fa898fe8ef427a': ('Wallet table two medium risks/one enhancement',3),
    '26ed7f6cbeff6b44feebec0e955ae247b4acaea5230785528768a9fc7612f971': ('Chinese split glyph Nn cards',3),
    '471f34c78b479ea66df0a9b26b7bba12b7840e6f50565aa062deef18098de4fc': ('Nn without ID brackets',3),
    'bab7413382b6070284230dc656a4eac8dc309dd2054a414dc6bcf41908ea2566': ('Nn without ID brackets, adjacent body prose',3),
    '9cbf2800f2b2da31806be067f586ba2881ffc09129c9f403ecec91bfa61c2eee': ('Modern Nn/status blocks',12),
    '89604b8c60257a747b275f9963c70f1963196ac81e1ca306b5fb5283387d0afd': ('Modern Solana Nn/unknown suggestion',6),
    '6833f04129ccdd66e27aa7cb4624e3052bb2d833a750f6f2786709df78edc3d5': ('Nn Critical/High/Medium/Information',5),
    '53fe3e3b113d35d2044d404ea6b5732790729f41a6bf8cc70f67c2faac515561': ('Image-link Markdown wrapper with passed metadata',0),
    '62a27ce7c6a3981232b6191fe4de6bd78d821a8b62286e875b598d760c849449': ('Chinese image-link Markdown wrapper',0),
    '218b868fdb5f268f0b1d4f8315d508f29a10e665093b931abae33289a7274857': ('Passed checklist with unrated informational privileges',0),
    'f390186029b4d35fc4e7aa6f5811279792b2a08e81ba796894f91e0864fa9d55': ('Token risk checklist/unrated privilege narrative',0),
    '824fd6340209f4a75693c7b6c383f615283320fcb4ee1fbf8ddd4d23e19ba47b': ('Summary totals and checklist only, no finding detail',0),
    '4d6d8940c9633a28529bc987951a04adcf23920e7aa1418dbca08575150ad768': ('Nn index only, detailed cards absent',0),
    'b323e553a10102cb54754cb6e365494c771fe2a35794731f91f61483c7964979': ('PDF code fences must not hide later cards',9),
    'a38349e5642df2ad74597547f3a6fcc7f22ce8a44f2a33b6980ac24df2f58c48': ('PDF code fences with twelve source cards',12),
    'cad093eee2dc1abb9c3d9f8c3aaa609c164d002e7304cf4d67856c0e320a82c9': ('PDF unmatched fences and Information label',9),
    'd0decfada1292da54ae433dde264e57fadb9539565eae8db3e3d7b1d725cf1fe': ('PDF unmatched fence with final Low card',4),
    '5afb844403ab706488fd82bbc0236c28c5ef104b6c0c7b8dbc103c95388059f9': ('Preserved conclusion/detail severity contradiction',22),
    '6244c6d64bd7a84321716480bc05b6c30783fb9560189d4869d7cab4d533f329': ('Publisher inconsistent section-number prefixes',6),
    '924145aae25356f0867d45b869f1a2893455ae3f56b4e32bba368f31eb5d12f5': ('Chinese enumeration comma after decimal finding ID',4),
    '2d29c914a18e5e9f10991f39560a3a551b95c560466d57d3651f07a0121025b6': ('Publisher prints repeated detail ID, both retained',10),
}


def synthetic(text,format='pdf'):
    return Report(text,{'file_format':format,'pages':[{'page':1,'start':0,'end':len(text),'text':text}]},'slowmist')


class SlowMistRegression(unittest.TestCase):
    def test_pdf_fence_does_not_hide_cards(self):
        text='[N1] [Low] First\n\nContent\n'+('Description. '*8)+'\n```\ncode\n\n[N2] [Suggestion] Second\n\nContent\n'+('Description. '*8)+'\nStatus\nAcknowledged\n'
        cs=finish(synthetic(text),slowmist.parse(synthetic(text)))
        self.assertEqual([c.printed_id for c in cs],['N1','N2'])
        self.assertEqual(cs[1].status_raw,'Acknowledged')
        self.assertEqual(severity(cs[1].severity_raw),'unknown')

    def test_definitions_and_passed_checklists_are_not_findings(self):
        text='Suggestions\n\n2. Audit Methodology\n\n Reentrancy attack\n\n3. Project Background\n\nNO. Audit Items Result\n1 Authority Control Passed\nAudit Result : Passed\n'
        self.assertEqual(slowmist.parse(synthetic(text)),[])

    def test_linked_status_does_not_leak_between_result_entries(self):
        text='4.2 Code Audit\n\n4.2.1 Alpha issue\n\n'+('Detailed issue. '*10)+'\n4.2.2 Beta issue\n\n'+('Detailed issue. '*10)+'\n5 Audit Result\n\n5.1 High-risk vulnerabilities\n\n Alpha issue\n\n Beta issue\n\nNote: It has been fixed in the fixed version code.\n\n5.2 Conclusion\n'
        cs=finish(synthetic(text),slowmist.parse(synthetic(text)))
        self.assertEqual([c.printed_id for c in cs],['4.2.1','4.2.2'])
        self.assertIsNone(cs[0].status_raw)
        self.assertEqual(cs[1].status_raw.lower(),'fixed')
        self.assertLessEqual(cs[1].end,text.index('5 Audit Result'))

    def test_conclusion_counts_do_not_include_resolution_subsets(self):
        r=synthetic('during the audit work we found a critical risk, two medium risks, four suggestions, and four suggestions were confirmed, and a medium risk vulnerability is fixed.')
        self.assertEqual(slowmist.printed_counts(r)['counts'],{'critical':1,'medium':2,'info':4})

    def test_markdown_fence_still_blocks_fake_cards(self):
        text='```\n[N1] [High] Example only\n'+('example '*20)+'\n```\n'
        self.assertEqual(slowmist.parse(synthetic(text,'md')),[])


def source_dates(doc,report):
    out=[]
    for m in re.finditer(r'(?:Audit Date|审计日期|审计时间|审计⽇期)',report.text,re.I):
        snippet=report.text[m.start():m.end()+260]
        date=re.search(r'(?:19|20)\d{2}\s*[.年/-]\s*\d{1,2}|(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+(?:19|20)\d{2}',snippet,re.I)
        if date:
            out.append({'start':m.start(),'text':snippet[:date.end()+35], 'year':int(re.search(r'(?:19|20)\d{2}',date[0])[0])})
    # A date_hint remains a metadata assertion, never a fabricated audit date.
    return {'date_hint':doc['row'].get('date_hint'), 'audit_date_field_evidence':out[:2]}


def zero_class(doc,report,diag):
    text=report.text
    if report.meta['file_format']=='md' and '![' in text:
        return 'image_link_markdown_wrapper'
    if re.search(r'Investigation|Statement',doc['row']['filename'],re.I):
        return 'statement_or_incident_investigation'
    summary=(diag.get('printed_summary') or {}).get('counts')
    if summary and any(summary.values()):
        return 'printed_findings_without_detail_sections'
    if summary and not any(summary.values()):
        return 'explicit_zero_printed_risk_buckets'
    if re.search(r'Some Risks|following (?:issues|information)|privilege risks',text,re.I):
        return 'checklist_or_narrative_with_unrated_risks_or_information'
    if re.search(r'Audit Result\s*[:：]\s*Passed|Comprehensive Audit Results\s+Passed|综合审计结果\s+通过|审计结果[:：]\s*通过',text,re.I):
        return 'printed_passed_checklist'
    return 'unresolved_zero_detail_review'


def native_sequence(rows):
    """Respect section-local numbers; audit-section references need not be contiguous."""
    groups=defaultdict(list);references=[]
    for r in rows:
        pid=r['publisher_finding_id']
        if 'title-linked-result' in r['method']:
            references.append(pid);continue
        if not pid:
            return {'state':'unassessable','reason':'native_list_has_no_printed_finding_ids'}
        key='native_global_or_decimal'
        if re.fullmatch(r'\d+',pid):
            key=str(r['evidence'].get('severity_section') or r['evidence'].get('printed_table_section') or r['severity_raw'])
        groups[key].append(pid)
    if not groups:
        return {'state':'unassessable','reason':'no_native_findings_or_audit_section_references_only','audit_section_references':references}
    detail={k:sequence(v) for k,v in groups.items()}
    return {'state':'complete' if all(g['state']=='complete' for g in detail.values()) else 'incomplete',
            'groups':detail,'audit_section_references':references}


def build_manifest():
    blocked=holdouts(ROOT)
    docs=[d for d in read_snapshot() if d['row']['firm_id']=='slowmist']
    assert all(d['row']['sha256'] not in blocked for d in docs)
    diagnostics={d['document_id']:d for d in map(json.loads,(ROOT/'data/findings/validation/slowmist.jsonl').read_text().splitlines())}
    output=defaultdict(list)
    for row in map(json.loads,(ROOT/'data/findings/slowmist.jsonl').read_text().splitlines()):
        assert row['sha256'] not in blocked
        output[row['document_id']].append(row)
    by_sha={d['row']['sha256']:d for d in docs}
    sample_rows=[]
    for sha,(layout,expected) in SAMPLES.items():
        if sha in blocked:
            raise RuntimeError('Holdout sample denied before opening text')
        doc=by_sha[sha];r=load_report(doc);cs=finish(r,slowmist.parse(r))
        assert len(cs)==expected,(sha,len(cs),expected)
        for c in cs:
            assert c.title and c.severity_raw and 0<=c.start<c.end<=len(r.text)
            assert r.text[c.start:c.end].strip()
        sample_rows.append({'sha256':sha,'filename':doc['row']['filename'],'layout':layout,'expected_rows':expected,
                            'rows':len(cs),'formal_rows':sum(c.record_kind=='formal_finding' for c in cs),
                            'date_evidence':source_dates(doc,r),'printed_ids':[c.printed_id for c in cs],
                            'validation':diagnostics[doc['document_id']]['validation']})
    states=Counter(d['validation'] for d in diagnostics.values())
    no_summary=[d for d in docs if diagnostics[d['document_id']]['validation'] in {'no_usable_printed_counts','ambiguous_printed_counts'}]
    sequences=Counter();native_sequences=Counter();sequence_details=[];zero=[];no_summary_audit=0;nonempty_audit=0
    for d in no_summary:
        rs=[r for r in output[d['document_id']] if r['record_kind']=='formal_finding']
        sequences[sequence([r['publisher_finding_id'] for r in rs])['state']]+=1
        native=native_sequence(rs);native_sequences[native['state']]+=1
        sequence_details.append({'sha256':d['row']['sha256'],'filename':d['row']['filename'],'scheme':native})
        if d['row']['doc_kind']=='audit_report':
            no_summary_audit+=1;nonempty_audit+=bool(rs)
    for d in docs:
        if not any(r['record_kind']=='formal_finding' for r in output[d['document_id']]):
            r=load_report(d)
            zero.append({'document_id':d['document_id'],'sha256':d['row']['sha256'],'filename':d['row']['filename'],
                         'doc_kind':d['row']['doc_kind'],'class':zero_class(d,r,diagnostics[d['document_id']])})
    all_rows=[r for rs in output.values() for r in rs]
    assert len({r['finding_id'] for r in all_rows})==len(all_rows)
    spans_checked=0
    for doc in docs:
        if not output[doc['document_id']]:continue
        report=load_report(doc)
        for row in output[doc['document_id']]:
            span=row['body_span'];start,end=span['start'],span['end']
            assert 0<=start<end<=len(report.text)
            assert row['body_text']==report.text[start:end]
            assert span['text_sha256']==report.meta['text_sha256']
            if re.search(r'suggestion|weakness|enhancement|建议|弱点',row['severity_raw'],re.I):
                assert row['severity']=='unknown'
            spans_checked+=1
    comparable=states['match']+states['mismatch']
    baseline=json.loads((ROOT/'data/findings/validation/group2_baseline_metrics.json').read_text())['slowmist']
    original_comparable=[d['document_id'] for d in baseline['documents_detail'] if d['validation'] in {'match','mismatch'}]
    metrics={'original_summary_matches':sum(diagnostics[docid]['validation']=='match' for docid in original_comparable),'original_summary_comparable':len(original_comparable),'documents':len(docs),'distinct_hashes':len(by_sha),'findings':len(all_rows),
             'formal_findings':sum(r['record_kind']=='formal_finding' for r in all_rows),
             'summary_matches':states['match'],'summary_comparable':comparable,
             'summary_agreement':round(100*states['match']/comparable,2),
             'validation_states':dict(states),'no_summary_documents':len(no_summary),'sequence_states':dict(sequences),'native_sequence_states':dict(native_sequences),
             'sequence_complete_percent_assessable':round(100*sequences['complete']/(sequences['complete']+sequences['incomplete']),2),
             'no_summary_audit_reports':no_summary_audit,'no_summary_audits_with_findings':nonempty_audit,
             'missing_title':sum(not r['title'] for r in all_rows),'missing_severity':sum(not r['severity_raw'] for r in all_rows),
             'unknown_severity':sum(r['severity']=='unknown' for r in all_rows),
             'status_present':sum(bool(r['status_raw']) for r in all_rows),'evidence_spans_checked':spans_checked,
             'zero_formal_audit_reports':sum(z['doc_kind']=='audit_report' for z in zero),
             'zero_classes':dict(Counter(z['class'] for z in zero)),
             'methods':dict(Counter(r['method'] for r in all_rows))}
    mismatches=[{'sha256':d['sha256'],'filename':by_sha[d['sha256']]['row']['filename'],
                 'parsed_counts':d['parsed_counts'],'printed_counts':d['printed_summary']['counts']}
                for d in diagnostics.values() if d['validation']=='mismatch']
    return {'firm_id':'slowmist','scope':'development_only_holdouts_excluded_before_text_reads',
            'baseline':{k:v for k,v in baseline.items() if k!='documents_detail'},'after':metrics,
            'sample_count':len(sample_rows),'sample_audit_date_years':sorted({e['year'] for s in sample_rows for e in s['date_evidence']['audit_date_field_evidence']}),'samples':sample_rows,'zero_formal_documents':zero,'mismatches':mismatches,
            'native_sequence_details_no_summary':sequence_details,
            'limitations':['Conclusion totals may disagree with the publisher detail-card severity labels. Both remain unchanged.',
                           'Assure checklists and sx.curve print findings totals/index rows but contain no separate detailed findings.',
                           'A passed token checklist does not establish zero historical vulnerabilities; unrated privilege narratives remain unclassified.',
                           'Image-link Markdown wrappers cache only wrapper text, not the linked report-page images.',
                           'Local row numbers restart across risk/table sections; aggregate numeric continuity is not recall.'],
            'parser_sha256':digest((Path(__file__).parent/'slowmist.py').read_bytes())}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');p.add_argument('--test',action='store_true');a=p.parse_args()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(SlowMistRegression)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():raise SystemExit(1)
    if a.write:
        manifest=build_manifest();write_json(ROOT/'data/findings/validation/slowmist_development.json',manifest)
        print(json.dumps(manifest['after'],sort_keys=True));print('Guarded samples:',manifest['sample_count'])


if __name__=='__main__':main()
