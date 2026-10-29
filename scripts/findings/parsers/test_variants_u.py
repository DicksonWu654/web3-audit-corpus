"""Phase 4e-U regressions and deterministic, holdout-guarded review receipts.

Run with --capture, --unknowns, --inspect FIRM SHA [--page N], or --report.
Without arguments this runs the synthetic regression suite.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
import tempfile
import struct
import zlib
from difflib import SequenceMatcher

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, digest, documents, holdouts, original_path, read_snapshot, write_json, write_jsonl
from core import Report
from parsers import module
from extract import tool, tool_environment
from unittest.mock import patch

FIRMS = ('chainsecurity', 'ottersec', 'kudelski-security', 'theori', 'cantina', 'zokyo', 'quantstamp')
LOCAL = ROOT / 'local-cache/phase4e-u'


class RemediationTests(unittest.TestCase):
    def parse(self,firm,text):
        from test_variants import report
        r=report(text,firm);cs=module(firm).parse(r)
        for c in cs:
            proof=c.evidence.get('status_evidence')
            if proof:
                self.assertEqual(r.text[proof['start']:proof['end']],proof['text'])
                self.assertEqual(proof['text'],c.status_raw)
        return r,cs

    def test_otter_patch_assertion_and_index(self):
        from test_variants import D
        r,cs=self.parse('ottersec','ID    Severity    Status    Description\nOS-TST-ADV-00    High    TO DO    Source description\n\fActual vulnerability    HIGH    OS-TST-ADV-00'+D+'Patch\nResolved in commit abcdef123.\n')
        self.assertEqual(cs[0].normalized_status,'resolved')
        self.assertEqual(cs[0].evidence['status_evidence']['basis'],'patch_assertion')
        _,cs=self.parse('ottersec','ID    Severity    Status    Description\nOS-TST-ADV-00    High    TO DO    Source description\n\fActual vulnerability    HIGH    OS-TST-ADV-00'+D)
        self.assertEqual(cs[0].normalized_status,'open')

    def test_spaced_otter_card_and_source_status(self):
        from test_variants import D
        text='I D    S e v e r i t y    S t a t u s    D e s c r i p t i o n\nO S - T S T - A D V - 0 0    H I G H    R E S O L V E D    Description\n\fA c t u a l   v u l n e r a b i l i t y    H I G H    O S - T S T - A D V - 0 0'+D
        r,cs=self.parse('ottersec',text)
        self.assertEqual(len(cs),1);self.assertEqual(cs[0].printed_id,'OS-TST-ADV-00')
        self.assertEqual(cs[0].normalized_status,'resolved')
        proof=cs[0].evidence['native_id_span']
        self.assertEqual(r.text[proof['start']:proof['end']],proof['text'])

    def test_grouped_otter_patch_claims_keep_mixed_outcomes(self):
        from test_variants import D
        base='OS-TST-SUG-00 | Actual group'+D+'Patch\n'
        _,cs=self.parse('ottersec',base+'1. Issue #1 resolved in abcdef1.\n2. Issue #2 resolved in abcdef2.\n')
        self.assertEqual(cs[0].normalized_status,'resolved')
        _,cs=self.parse('ottersec',base+'1. Issue #1 resolved in abcdef1.\n2. Issue #2 has been acknowledged.\n')
        self.assertEqual(cs[0].normalized_status,'other')
        self.assertEqual(len(cs[0].evidence['patch_status_claims']),2)

    def test_spaced_summary_only_otter_release_is_an_excerpt(self):
        r,cs=self.parse('ottersec','I D    D e s c r i p t i o n\nO S - T S T - S U G - 0 0    A source inventory description without a detailed card.\n')
        self.assertEqual(len(cs),1);self.assertEqual(cs[0].record_kind,'summary_excerpt')
        self.assertEqual(r.layout_disposition['reason'],'summary_inventory_only')

    def test_cantina_client_fix_and_ligature(self):
        from test_variants import D
        base='3.1 High Risk\n3.1.1 Actual vulnerability\nSeverity: High Risk'+D
        _,cs=self.parse('cantina',base+'Client Project: Fixed in commit abcdef123.\nCantina: Conﬁrmed.\n')
        self.assertEqual(cs[0].normalized_status,'fixed')
        self.assertEqual(cs[0].evidence['status_evidence']['actor'],'Client Project')
        _,cs=self.parse('cantina',base+'Cantina: Fix veriﬁed.\n')
        self.assertEqual(cs[0].normalized_status,'resolved')
        self.assertEqual(cs[0].status_raw,'Fix veriﬁed')

    def test_confirmation_and_recommendation_do_not_prove_a_fix(self):
        from test_variants import D
        _,cs=self.parse('cantina','3.1 High Risk\n3.1.1 Actual vulnerability\nSeverity: High Risk'+D+'Cantina: Confirmed.\nRecommendation: This should be fixed.\n')
        self.assertEqual(cs[0].normalized_status,'other')
        self.assertEqual(cs[0].status_raw,'Confirmed')

    def test_zokyo_post_audit_commit_and_future_plan(self):
        from test_variants import D
        base='Complete Analysis\n| HIGH\nActual vulnerability\n\n'+D+'Post-audit:\n'
        _,cs=self.parse('zokyo',base+'The commit with fix is abcdef123.\n')
        self.assertEqual(cs[0].normalized_status,'fixed')
        _,cs=self.parse('zokyo',base+'The issue will be fixed after deployment.\n')
        self.assertEqual(cs[0].normalized_status,'unknown')

    def test_kudelski_observation_status_is_not_invented(self):
        from test_variants import D
        _,cs=self.parse('kudelski-security','TECHNICAL FINDINGS\n2.1 KS-TST-F-01 Actual vulnerability\nSeverity: High'+D)
        self.assertEqual(cs[0].normalized_status,'unknown')
        self.assertEqual(cs[0].evidence['status_availability']['reason'],'not_stated')

    def test_kudelski_retest_does_not_create_new_initial_findings(self):
        from test_variants import D
        r,cs=self.parse('kudelski-security','Retest Report\n1 – Prior issue\nSeverity    Resolved'+D)
        self.assertFalse(cs);self.assertEqual(r.layout_disposition['reason'],'prior_audit_retest_only')

    def test_quantstamp_project_ids_do_not_steal_next_card_severity(self):
        from test_variants import D
        r,cs=self.parse('quantstamp','Findings\nMAR-1 Actual vulnerability    • High    Fixed'+D+'MAR-2 Another vulnerability    • Low    Unresolved'+D)
        self.assertEqual([c.printed_id for c in cs],['MAR-1','MAR-2'])
        self.assertEqual([c.severity_raw for c in cs],['High','Low'])
        self.assertEqual([c.normalized_status for c in cs],['fixed','open'])

    def test_theori_profile_retains_unmapped_labels(self):
        from core import severity_mapping
        self.assertEqual(severity_mapping('Medium','theori',log=False)['normalized'],'medium')
        self.assertEqual(severity_mapping('Note','theori',log=False)['normalized'],'info')
        self.assertFalse(severity_mapping('Warning','theori',log=False)['mapped'])

    def test_theori_fix_section_commit_is_distinct_from_future_plan(self):
        from test_variants import D
        base='Issue #1: Actual vulnerability\nSummary    Severity\nSource summary    High\nDescription\n'+D+'Fix\n'
        _,cs=self.parse('theori',base+'Replace the unsafe operation (commit abcdef123).\n')
        self.assertEqual(cs[0].normalized_status,'fixed')
        _,cs=self.parse('theori',base+'The team will replace the operation in a future release.\n')
        self.assertEqual(cs[0].normalized_status,'unknown')

    def test_holdout_guard_precedes_all_text_access(self):
        with patch(__name__+'.holdouts',return_value={'a'*64}),patch(__name__+'.original_path') as original:
            with self.assertRaisesRegex(ValueError,'Holdout'):
                load({'row':{'sha256':'a'*64}})
            original.assert_not_called()

    def test_stale_image_receipt_cannot_fill_a_status(self):
        from parsers import zokyo
        from test_variants import report
        r=report('An existing source title and body.','zokyo');r.meta['sha256']='b'*64
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'local-cache/phase4e-u/zokyo_badges';folder.mkdir(parents=True)
            (folder/('b'*64+'.json')).write_text(json.dumps(dict(sha256='b'*64,text_sha256='c'*64,claims=[])))
            with patch.object(zokyo,'ROOT',Path(temp)),patch.object(zokyo,'holdouts',return_value={'a'*64}):
                self.assertEqual(zokyo.visual_receipts(r),[])

    def test_image_badge_word_in_narrative_keeps_image_provenance(self):
        from parsers import zokyo
        from test_variants import report,D
        text='Actual source title\n'+D+'The formula uses a fixed number of units.\n'
        r=report(text,'zokyo');span=dict(start=0,end=19,text=text[:19])
        claim=dict(card_start=0,source_span=span,title_span=span,risk_raw='High',status_raw='Fixed')
        with patch.object(zokyo,'visual_receipts',return_value=[claim]):
            cs=zokyo.image_badges(r)
            from core import finish
            cs=finish(r,cs);zokyo.remediation_status(r,cs)
        self.assertEqual(cs[0].normalized_status,'fixed')
        self.assertNotIn('status_evidence',cs[0].evidence)
        self.assertEqual(cs[0].evidence['status_ocr_evidence'],claim)

    def test_zokyo_native_status_spellings_are_preserved(self):
        from test_variants import D
        for raw,norm in [('NOT VALID','invalid'),('ACKNOWLEDG','acknowledged'),('RESOLVE','resolved')]:
            with self.subTest(raw=raw):
                _,cs=self.parse('zokyo','Complete Analysis\nHigh '+raw+'\nActual source title\n\n'+D)
                self.assertEqual(cs[0].status_raw,raw);self.assertEqual(cs[0].normalized_status,norm)

    def test_visually_empty_status_area_is_not_an_ocr_failure(self):
        from parsers import zokyo
        from test_variants import report,D
        r=report('Complete Analysis\nHIGH\nActual source title\n\n'+D,'zokyo')
        start=r.text.index('HIGH');span=dict(start=start,end=start+4,text='HIGH')
        claim=dict(card_start=start,source_span=span,status_raw=None,absence_reason='not_stated',review_method='visual_review')
        with patch.object(zokyo,'visual_receipts',return_value=[claim]):
            cs=module('zokyo').parse(r)
        self.assertEqual(cs[0].normalized_status,'unknown')
        self.assertEqual(cs[0].evidence['status_availability']['reason'],'not_stated')


def load(doc):
    row = doc['row']; sha = row['sha256']
    if sha in holdouts():
        raise ValueError('Holdout review denied before text access')
    path = ROOT / 'local-cache/fulltext' / (sha + '.txt')
    if path.exists():
        meta = json.loads(path.with_suffix('.pages.json').read_text())
        text = path.read_bytes().decode('utf-8')
        assert digest(text.encode()) == meta['text_sha256']
    else:
        # Newly collected Theori inputs need not be in the frozen global snapshot.
        if row['firm_id'] != 'theori': raise FileNotFoundError(path)
        assert row['file_format'] == 'pdf'
        path = original_path(row)
        assert digest(path.read_bytes()) == sha
        text = subprocess.run([tool('pdftotext', ROOT), '-layout', str(path), '-'], check=True,
                              env=tool_environment(ROOT), capture_output=True).stdout.decode('utf-8').rstrip('\f')
        pages = []; offset = 0
        for i, part in enumerate(text.split('\f'), 1):
            pages.append(dict(page=i, start=offset, end=offset+len(part), text=part))
            offset += len(part)+1
        meta = dict(pages=pages, text_sha256=digest(text.encode()), file_format='pdf',
                    method='pdftotext-layout-phase4e-u')
    return Report(text, meta | {'sha256': sha, 'file_format': row['file_format'],
                               'date_hint': row.get('date_hint')}, row['firm_id'])


def inputs():
    docs = [d for d in read_snapshot() if d['row']['firm_id'] in FIRMS]
    current, _, _ = documents()
    seen = {d['document_id'] for d in docs}
    docs += [d for d in current if d['row']['firm_id'] == 'theori' and d['document_id'] not in seen]
    reconciliation=ROOT/'data/collect/chainlight/identity_reconciliation.json'
    if reconciliation.exists():
        official={r['sha256'] for r in json.loads(reconciliation.read_text()).get('source_links',[]) if r['source_firm_id']=='theori'}
        by_sha={d['row']['sha256']:d for d in current if d['row']['firm_id']=='chainlight'}
        for sha in sorted(official-{d['row']['sha256'] for d in docs if d['row']['firm_id']=='theori'}):
            if sha in holdouts():continue
            if sha in by_sha:
                d=by_sha[sha]
                docs.append(d|{'source_publisher':'chainlight','row':d['row']|{'firm_id':'theori'}})
    return docs


def theori_profile():
    path=ROOT/'schema/severity_map.yaml';policy=json.loads(path.read_text())
    blocked=holdouts();all_docs={d['row']['sha256']:d for d in read_snapshot()}
    evidence=[]
    for item in policy['publishers']['chainlight']['eras'][0]['evidence']:
        if item['sha256'] not in {'0219c05985328acfc262a87f7efe34004cad866fe15760f5463a5d9e485d40df',
                                  '7e46ec551a72a38ef80aea88994dc9e91b843056e5db5daec17059a0ba503159'}: continue
        assert item['sha256'] not in blocked
        report=load(all_docs[item['sha256']])
        page=next(p for p in report.meta['pages'] if p['page']==item['page'])
        assert item['quote'] in page['text'] and 'Theori' in page['text']
        evidence.append(item | {'attribution_note':'Source explicitly credits ChainLight, Theori; its collector attribution is unchanged.','accessed_utc':'2026-10-21'})
    for doc in inputs():
        if doc['row']['firm_id']!='theori': continue
        report=load(doc)
        if doc['row']['sha256']=='e09814e92ebc41597a515f1faf7a08222210ac3667d46fc15dd2e6ec8ad632c9':
            page=next(p for p in report.meta['pages'] if 'THE-BIFIBTC-001' in p['text'] and 'Fixed (Critical)' in p['text'])
            evidence.append(dict(sha256=doc['row']['sha256'],page=page['page'],page_basis='pdf_page',public_url=doc['row']['public_url'],
                                 kind='scale_or_example',quote=page['text'],accessed_utc='2026-10-21'))
    assert len(evidence)==3
    labels={}
    for raw,norm in [('Critical','critical'),('High','high'),('Medium','medium'),('Low','low'),('Informational','info'),('Information','info'),('Note','info')]:
        labels[raw]=dict(normalized=norm,rationale=('Publisher defines '+raw+' as '+('neutral information unrelated to safety/security.' if raw=='Note' else 'information with no direct protocol/user impact.' if norm=='info' else 'the native '+norm+' risk tier; preserve that tier without equating methodologies.')))
    entry=dict(review_status='reviewed_with_residual_unknowns',reviewed_utc='2026-10-21',eras=[dict(id='published-scale',default=True,
        description='Theori detail-card grades, with explicit Theori/ChainLight Severity Categories definitions. BiFi 2021 is a scale example, not a complete severity definition. Unlisted labels remain unknown.',
        labels=labels,evidence=evidence)])
    # Preserve the rest of the authoritative file byte for byte.
    source=path.read_text();key='    "theori": '
    if key in source:
        assert policy['publishers']['theori']==entry;return
    anchor='    "three-sigma": '
    rendered=json.dumps(entry,ensure_ascii=False,indent=2).splitlines()
    addition=key+rendered[0]+'\n'+'\n'.join('    '+line for line in rendered[1:])+',\n'
    assert source.count(anchor)==1
    path.write_text(source.replace(anchor,addition+anchor))


def ocr_zokyo(sha_prefix=None):
    """Read only the image risk/status bands; anchor each to existing source text."""
    from badge_ocr import ppm
    from parsers import zokyo
    from layout_support import status_value
    def key(value):return re.sub(r'[^a-z0-9]','',value.casefold())
    for doc in inputs():
        row=doc['row'];sha=row['sha256']
        if row['firm_id']!='zokyo' or (sha_prefix and not sha.startswith(sha_prefix)):continue
        try:r=load(doc)
        except FileNotFoundError:continue
        cs=module('zokyo').parse(r)
        needed=[c for c in cs if not c.status_raw and c.evidence.get('badge_span')]
        missing=not cs and getattr(r,'layout_disposition',{}).get('reason')=='finding_badges_missing_from_text_layer'
        if not needed and not missing:continue
        output=LOCAL/'zokyo_badges'/(sha+'.json')
        old={}
        if output.exists():
            old=json.loads(output.read_text())
            if old.get('reader_version')=='u-badges-v2' and old['text_sha256']==r.meta['text_sha256']:
                print('cached',sha[:12],len(old['claims']),flush=True);continue
        assert sha not in holdouts()
        path=original_path(row);assert digest(path.read_bytes())==sha
        start,end=zokyo._region(r)
        pages=[p for p in r.meta['pages'] if p['end']>start and p['start']<end and
               (missing or any(p['start']<=c.evidence['badge_span']['start']<p['end'] for c in needed))]
        claims=old.get('claims',[]) if old.get('text_sha256')==r.meta['text_sha256'] else [];reviews=[]
        for page in pages:
            number=page['page'];folder=LOCAL/'ocr'/sha;folder.mkdir(parents=True,exist_ok=True)
            prefix=folder/str(number)
            if not prefix.with_suffix('.ppm').exists():
                subprocess.run([tool('pdftoppm',ROOT),'-f',str(number),'-l',str(number),'-r','160','-singlefile',str(path),str(prefix)],env=tool_environment(ROOT),capture_output=True,check=True,timeout=120)
            payload=prefix.with_suffix('.ppm').read_bytes();w,h,data=ppm(payload)
            active=[]
            for y in range(h):
                sample=[data[(y*w+x)*3:(y*w+x)*3+3] for x in range(w//10,9*w//10,max(1,w//100))]
                if sum(min(pixel)>220 for pixel in sample)/len(sample)>.78:active.append(y)
            bands=[]
            for y in active:
                if bands and y==bands[-1][-1]+1:bands[-1].append(y)
                else:bands.append([y])
            bands=[b for b in bands if 15<=len(b)<=160 and b[0]<h*.85]
            merged=[]
            for band in bands:
                if merged and band[0]-merged[-1][-1]<=45 and band[-1]-merged[-1][0]<=160:merged[-1]+=band
                else:merged.append(band)
            bands=merged
            source=[c for c in cs if page['start']<=c.evidence.get('badge_span',{}).get('start',-1)<page['end']]
            decoded=[]
            for i,band in enumerate(bands):
                x0=w//15;x1=3*w//5;y0=max(0,band[0]-4);y1=min(h,band[-1]+5)
                pixels=b''.join(data[(y*w+x0)*3:(y*w+x1)*3] for y in range(y0,y1))
                pixels=bytes(0 if b<235 else 255 for b in pixels)
                crop=folder/f'{number}-{i}-band.ppm'
                crop.write_bytes(f'P6\n{x1-x0} {y1-y0}\n255\n'.encode()+pixels)
                result=subprocess.run([tool('tesseract',ROOT),str(crop),'stdout','-l','eng','--psm','7'],env=tool_environment(ROOT),capture_output=True,check=True,timeout=60)
                badge=result.stdout.decode()
                risk=re.search(r'\b('+zokyo.RISK+r')(?:\s*[-–]\s*\d+)?\b',badge,re.I)
                state=re.search(r'\b('+zokyo.STATUS+r')\b',badge,re.I)
                proof=dict(page=number,pixel_box=[x0,y0,x1,y1],image_sha256=digest(crop.read_bytes()),ocr_text=badge,
                           render_sha256=digest(payload),engine='tesseract-eng-psm7',original_sha256=sha,text_sha256=r.meta['text_sha256'])
                if not risk or not state:
                    reviews.append(proof|{'reason':'risk_or_status_not_decoded'});continue
                # OCR title immediately below the white band, separate from the badge.
                tx1=19*w//20;ty0=y1;ty1=min(h,y1+165)
                title_pixels=b''.join(data[(y*w+x0)*3:(y*w+tx1)*3] for y in range(ty0,ty1))
                title_crop=folder/f'{number}-{i}-title.ppm'
                title_crop.write_bytes(f'P6\n{tx1-x0} {ty1-ty0}\n255\n'.encode()+title_pixels)
                result=subprocess.run([tool('tesseract',ROOT),str(title_crop),'stdout','-l','eng','--psm','6'],env=tool_environment(ROOT),capture_output=True,check=True,timeout=60)
                title_ocr=result.stdout.decode().strip().split('\n\n')[0]
                proof.update(risk_raw=risk[1],status_raw=state[1],title_ocr=title_ocr)
                decoded.append(proof)
            if source and len(source)==len(decoded) and all(key(c.severity_raw)==key(b['risk_raw']) for c,b in zip(source,decoded)):
                for c,b in zip(source,decoded):
                    span=c.evidence['badge_span'];b.update(card_start=span['start'],source_span=span,association='complete_page_badge_sequence_and_exact_risk_labels')
                    claims.append(b)
            else:
                # Missing badge text: require a matching existing title fragment;
                # no finding can be created from an OCR severity/count alone.
                occupied=set()
                for b in decoded:
                    fragments=[l for l in r.lines if l.page==number and len(key(l.content))>=14 and not re.search(r'Smart Contract|Recommendation|Post-audit',l.content,re.I)]
                    score,line=max(((SequenceMatcher(None,key(b['title_ocr'])[:140],key(l.content)).ratio(),l) for l in fragments),key=lambda pair:pair[0],default=(0,None))
                    if score<.6 or line is None or line.start in occupied:
                        reviews.append(b|{'reason':'ambiguous_source_title','title_match_score':round(score,4)});continue
                    candidate=next((c for c in source if c.start<=line.start<c.end and key(c.severity_raw)==key(b['risk_raw'])),None)
                    span=candidate.evidence['badge_span'] if candidate else dict(start=line.start,end=line.end,text=r.text[line.start:line.end])
                    b.update(card_start=span['start'],source_span=span,title_span=dict(start=line.start,end=line.end,text=r.text[line.start:line.end]),
                             association='source_title_similarity_and_risk' if candidate else 'source_title_similarity',title_match_score=round(score,4))
                    claims.append(b);occupied.add(line.start)
            print('ocr',sha[:12],number,'claims',len(claims),'review',len(reviews),flush=True)
        claims=list({c['card_start']:c for c in claims}.values())
        write_json(output,dict(reader_version='u-badges-v2',sha256=sha,text_sha256=r.meta['text_sha256'],claims=claims,review=reviews))


def saved_snapshot():
    result = {'variants': {}, 'documents': {}, 'queue': []}
    grouped = defaultdict(lambda: Counter())
    for firm in FIRMS:
        path = ROOT / 'data/findings/validation' / (firm+'.jsonl')
        if path.exists():
            for line in path.read_text().splitlines():
                d = json.loads(line)
                result['documents'][d['document_id']] = d
                grouped[d.get('variant_id', firm+'/extraction_failed')]['documents'] += 1
        path = ROOT / 'data/findings' / (firm+'.jsonl')
        if path.exists():
            with path.open() as stream:
                for line in stream:
                    row = json.loads(line)
                    if row['record_kind'] == 'summary_excerpt': continue
                    count = grouped[row['variant_id']]
                    count['detailed'] += 1
                    count['known'] += row['status'] not in (None, 'unknown', 'other')
    result['variants'] = {k: dict(v) for k, v in sorted(grouped.items())}
    result['queue'] = [json.loads(line) for line in (ROOT/'data/findings/_unknown_layouts.jsonl').read_text().splitlines()
                       if json.loads(line)['firm'] in FIRMS]
    return result


def evaluate(firms=FIRMS):
    from core import status
    variants = defaultdict(Counter); receipts = []; queue = []; findings=[]
    for index,doc in enumerate(inputs()):
        firm = doc['row']['firm_id']; sha = doc['row']['sha256']
        if firm not in firms: continue
        if index%25==0:print('review',firm,sha[:12],flush=True)
        try: report = load(doc)
        except FileNotFoundError:
            variants[firm+'/extraction_failed']['documents'] += 1
            continue
        parser = module(firm); candidates = parser.parse(report)
        rows=[dict(sha256=sha,record_kind=c.record_kind,severity=c.normalized,status=c.normalized_status or status(c.status_raw),
                   status_raw=c.status_raw,evidence=c.evidence,start=c.start,end=c.end) for c in candidates]
        if firm=='theori':
            for c,row in zip(candidates,rows):
                findings.append(dict(validation_only=True,source_publisher=doc.get('source_publisher',firm),parser_publisher=firm,
                    source_file=doc['source_file'],document_id=doc['document_id'],sha256=sha,public_url=doc['row']['public_url'],
                    variant_id=report.layout_selection['variant_id'],publisher_finding_id=c.printed_id,title=c.title,
                    record_kind=c.record_kind,severity_original=c.severity_raw,severity_normalized=c.normalized,
                    status_raw=c.status_raw,status=row['status'],evidence=c.evidence,
                    body_span=dict(start=c.start,end=c.end,text_sha256=report.meta['text_sha256'])))
        variant = report.layout_selection['variant_id']; count = variants[variant]
        count['documents'] += 1
        for row in rows:
            assert row['sha256'] not in holdouts()
            s,e=row['start'],row['end'];assert 0<=s<e<=len(report.text)
            proof = row['evidence'].get('status_evidence')
            if proof:
                assert report.text[proof['start']:proof['end']] == proof['text'] == proof['raw'] == row['status_raw']
            if row['record_kind'] == 'summary_excerpt': continue
            count['detailed'] += 1
            count['known'] += row['status'] not in (None, 'unknown', 'other')
            count['other'] += row['status'] == 'other'
            count['not_stated'] += row['status'] == 'unknown' and row['evidence'].get('status_availability', {}).get('reason') == 'not_stated'
            count['needs_review'] += row['status'] in (None, 'unknown') and row['evidence'].get('status_availability', {}).get('reason') != 'not_stated'
        summary = parser.printed_counts(report)
        formal = Counter(r['severity'] for r in rows if r['record_kind'] == 'formal_finding')
        comparison = None if not summary or summary.get('ambiguous') else all(formal[k] == v for k, v in summary['counts'].items())
        if comparison is not None:
            count['comparable'] += 1; count['matching'] += comparison
        receipt = dict(document_id=doc['document_id'], firm=firm, sha256=sha, public_url=doc['row']['public_url'],
                       filename=doc['row']['filename'], variant=variant, findings=len(rows),
                       source_publisher=doc.get('source_publisher',firm),
                       statuses=dict(Counter(r['status'] or 'null' for r in rows)), comparison=comparison,
                       record_kinds=dict(Counter(r['record_kind'] for r in rows)),
                       disposition=getattr(report, 'layout_disposition', None))
        receipts.append(receipt)
        if report.layout_selection['unknown_layout']: queue.append(receipt)
    return dict(variants={k: dict(v) for k, v in sorted(variants.items())}, documents=receipts, queue=queue, finding_receipts=findings)


def export_profile():
    entry=json.loads((ROOT/'schema/severity_map.yaml').read_text())['publishers']['theori']
    path=ROOT/'schema/severity_map.json';source=path.read_text();policy=json.loads(source)
    if 'theori' in policy['publishers']:
        assert policy['publishers']['theori']==entry;return
    rendered=json.dumps(entry,ensure_ascii=False,indent=2).splitlines()
    addition='    "theori": '+rendered[0]+'\n'+'\n'.join('    '+line for line in rendered[1:])+',\n'
    assert source.count('    "three-sigma": ')==1
    path.write_text(source.replace('    "three-sigma": ',addition+'    "three-sigma": '))


def record_reviewed_badges():
    # Verbatim labels reviewed in the retained page-band montages, 2026-10-21.
    states={('cd1cdfccaf0c',18760):'UNRESOLVED',('cd1cdfccaf0c',19362):'VERIFIED',
            ('eb9d3884cb75',15720):'NOT VALID',('eb9d3884cb75',16648):'NOT VALID',
            ('eb9d3884cb75',22400):'NOT VALID',('eb9d3884cb75',22867):'NOT VALID',
            ('d8b670139603',11072):'NOT VALID',('ac24053453af',14006):'RESOLVED',
            ('2ad9642bbdca',8513):'NOT VALID',('dda1d178fa66',9699):'NOT VALID',
            ('02223738d7c0',7854):None,('9492b54983ef',18142):'ACKNOWLEDG',
            ('9492b54983ef',20075):'RESOLVE',('9492b54983ef',21160):'RESOLVE',
            ('d212c68fedc8',6869):'NOT VALID',('d212c68fedc8',7647):'NOT VALID'}
    pending=json.loads((LOCAL/'pending_badges.json').read_text());claims=[]
    docs={d['row']['sha256']:d for d in inputs()}
    assert {(p['sha256'][:12],p['card_start']) for p in pending}==set(states)
    for item in pending:
        sha=item['sha256'];r=load(docs[sha]);span=item['source_span']
        assert r.text[span['start']:span['end']]==span['text']
        receipt=json.loads((LOCAL/'zokyo_badges'/(sha+'.json')).read_text())
        proofs=sorted([p for p in receipt['review'] if p['page']==item['page']],key=lambda p:p['pixel_box'][1])
        risk=re.sub(r'\s','',item['risk_raw']).casefold()
        matching=[p for p in proofs if risk in re.sub(r'\s','',p['ocr_text']).casefold()]
        siblings=sorted([p for p in pending if p['sha256']==sha and p['page']==item['page'] and p['risk_raw']==item['risk_raw']],key=lambda p:p['card_start'])
        proof=(matching or proofs)[siblings.index(item)]
        raw=states[(sha[:12],item['card_start'])]
        norm={'NOT VALID':'invalid','ACKNOWLEDG':'acknowledged','RESOLVE':'resolved','RESOLVED':'resolved','UNRESOLVED':'open','VERIFIED':'other',None:'unknown'}[raw]
        montage=LOCAL/'review'/f"{sha}-{item['page']}.png"
        claim=item|{k:proof[k] for k in ('image_sha256','render_sha256','pixel_box','ocr_text')}
        claim.update(original_sha256=sha,text_sha256=r.meta['text_sha256'],status_raw=raw,normalized_status=norm,
                     review_method='visual_review',reviewed_utc='2026-10-21',public_url=docs[sha]['row']['public_url'],
                     review_render_sha256=digest(montage.read_bytes()))
        if raw is None:claim['absence_reason']='not_stated'
        claims.append(claim)
    write_json(ROOT/'scripts/findings/parsers/fixtures/zokyo_reviewed_badges.json',dict(purpose='Reviewed image status/absence regression receipts; no original or full narrative content.',claims=claims))


def verify_outputs():
    from core import severity_policy
    from common import uid
    docs={d['document_id']:d for d in read_snapshot()};blocked=holdouts();map_sha=severity_policy()[2]
    inventory=json.loads((ROOT/'data/fulltext/inventory.json').read_text())
    assert digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes())==inventory['holdout_list_sha256'], 'Holdout rule changed'
    checked=Counter();seen=set();last=None
    for firm in FIRMS:
        path=ROOT/'data/findings'/(firm+'.jsonl')
        if not path.exists():continue
        for line in path.open():
            row=json.loads(line);sha=row['sha256'];assert sha not in blocked
            assert row['publisher_id']==firm and row['finding_id'] not in seen;seen.add(row['finding_id'])
            assert row['finding_id']==uid('finding',row['source_tag'],row['source_record_id'])
            if last!=sha:r=load(docs[row['document_id']]);last=sha
            start,end=row['body_span']['start'],row['body_span']['end']
            assert r.text[start:end]==row['body_text'] and 0<=start<end<=len(r.text)
            assert row['severity_mapping']['map_sha256']==map_sha
            assert row['status'] not in (None,), 'Assigned publisher status has no availability reason'
            if row['status']=='unknown':assert row['evidence']['status_availability']['reason']
            proof=row['evidence'].get('status_evidence')
            if proof:assert r.text[proof['start']:proof['end']]==proof['text']==row['status_raw']
            proof=row['evidence'].get('status_ocr_evidence') or row['evidence'].get('status_image_evidence')
            if proof:
                assert proof['original_sha256']==sha and proof['text_sha256']==r.meta['text_sha256']
                span=proof['source_span'];assert r.text[span['start']:span['end']]==span['text']
                if proof.get('review_method')=='visual_review':
                    path=LOCAL/'review'/f"{sha}-{proof['page']}.png"
                    assert digest(path.read_bytes())==proof['review_render_sha256']
                    if proof['status_raw'] is None:assert row['status']=='unknown' and row['evidence']['status_availability']['reason']=='not_stated'
                else:assert proof['status_raw'].casefold() in proof['ocr_text'].casefold()
            checked[firm]+=1
    queue=[json.loads(l) for l in (ROOT/'data/findings/_unknown_layouts.jsonl').read_text().splitlines()]
    assert not [q for q in queue if q['firm'] in FIRMS], 'Assigned queue is not empty'
    result=dict(ok=True,rows=dict(checked),holdouts_opened=0,holdout_list_sha256=digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes()))
    write_json(LOCAL/'checks.json',result);print(json.dumps(result,indent=2))


def report_from_outputs():
    baseline=json.loads((LOCAL/'baseline_metrics.json').read_text())
    after=saved_snapshot();after['variants']={}
    groups=defaultdict(Counter);by_doc=defaultdict(list);documents_by_id={d['document_id']:d for d in inputs()}
    for did,d in after['documents'].items():groups[d.get('variant_id',d['firm_id']+'/extraction_failed')]['documents']+=1
    for firm in FIRMS:
        path=ROOT/'data/findings'/(firm+'.jsonl')
        if not path.exists():continue
        for line in path.open():
            row=json.loads(line);by_doc[row['document_id']].append(row)
            if row['record_kind']=='summary_excerpt':continue
            count=groups[row['variant_id']];count['detailed']+=1
            count['known']+=row['status'] not in (None,'unknown','other')
            count['other']+=row['status']=='other'
            reason=row['evidence'].get('status_availability',{}).get('reason')
            if row['status'] in (None,'unknown'):count[reason or 'unexplained']+=1
    # Theori originals arrived after the frozen extraction snapshot. Validation
    # is separate from the stored publisher attribution and extraction census.
    theori=evaluate(('theori',));assert not theori['queue'];groups.update({k:Counter(v) for k,v in theori['variants'].items()})
    write_jsonl(LOCAL/'theori_findings.jsonl',theori['finding_receipts'])
    queued=[]
    for item in baseline['queue']:
        did=item['document_ids'][0];doc=documents_by_id[did];diag=after['documents'][did]
        assert not diag['unknown_layout'];rows=by_doc[did];disposition=None;quote=None
        if rows:
            row=rows[0];heading=row['body_text'].splitlines()[0]
            quote=dict(start=row['body_span']['start'],end=row['body_span']['start']+len(heading),text=heading,page=row['page'],basis='parsed_detail_heading')
            if all(row['record_kind']=='summary_excerpt' for row in rows):disposition=dict(reason='summary_inventory_only',basis='source inventory excerpts, no invented detailed bodies')
        else:
            r=load(doc);cs=module(r.firm).parse(r)
            assert diag['variant_id']==r.layout_selection['variant_id'] and not cs
            disposition=getattr(r,'layout_disposition',None)
            assert disposition, 'Empty queued artifact needs a disposition: '+item['sha256']
            for name,pattern,_ in r.selected_variant.fingerprint.signatures:
                m=re.search(pattern,r.text,re.M|re.I)
                if m:
                    quote=dict(start=m.start(),end=m.end(),text=m[0],page=next((p['page'] for p in r.meta['pages'] if p['start']<=m.start()<p['end']),None));break
        queued.append(dict(firm=doc['row']['firm_id'],sha256=item['sha256'],variant=diag['variant_id'],findings=len(rows),
                           disposition=disposition,layout_evidence=quote,public_url=doc['row']['public_url']))
    after['variants']={k:dict(v) for k,v in sorted(groups.items())};after['reviewed_queue']=queued;after['theori_validation']=theori
    write_json(LOCAL/'after.json',after)
    def cell(n,d):return f'{n}/{d} ({100*n/d:.2f}%)' if d else 'N/A'
    before_counts=Counter(q['firm'] for q in baseline['queue']);after_counts=Counter(q['firm'] for q in after['queue'])
    lines=['# Phase 4e-U publisher variants','',
           'Generated by `python3 -I -S scripts/findings/parsers/test_variants_u.py --from-outputs`. The frozen Phase 4d development inputs and holdout rule are unchanged. New Theori collection is validated separately. All counts below come from this script; local evidence was reviewed on 2026-10-21.','',
           'Status coverage uses the Phase 4d definition: known normalized statuses divided by detailed rows, excluding summary excerpts and `other`. The requested explicit `status=unknown` is retained in staged JSONL with `evidence.status_availability.reason`; it is not counted as coverage. No SQL import/schema change is made.','',
           '| Publisher | Queued before | Queued after |','|---|---:|---:|']
    for firm in FIRMS:lines.append(f'| {firm} | {before_counts[firm]} | {after_counts[firm]} |')
    lines += [f'| **Total** | **{sum(before_counts.values())}** | **{sum(after_counts.values())}** |','',
              '| Variant | Status before | Status after | Unknown: not_stated after | Other after | Unread image badge / conflict after |',
              '|---|---:|---:|---:|---:|---:|']
    declared={v.variant_id for firm in FIRMS for v in module(firm).VARIANTS}
    for key in sorted(set(baseline['variants'])|set(groups)|declared):
        old=baseline['variants'].get(key,{});new=groups.get(key,Counter());n=new.get('detailed',0)
        unresolved=sum(v for k,v in new.items() if k in {'badge_not_decoded','conflicting_claims','resolution_text_unclassified','unexplained','needs_review'})
        lines.append(f"| {key} | {cell(old.get('known',0),old.get('detailed',0))} | {cell(new.get('known',0),n)} | {cell(new.get('not_stated',0),n)} | {new.get('other',0)} | {unresolved} |")
    reasons=Counter((q['firm'],(q['disposition'] or {}).get('reason','parsed_details')) for q in queued)
    lines += ['', 'Queue dispositions (each hash, variant and original link is listed below):','', '| Publisher | Disposition | Artifacts |','|---|---|---:|']
    for (firm,reason),n in sorted(reasons.items()):lines.append(f'| {firm} | {reason} | {n} |')
    lines += ['',
        'OtterSec now reads ID-linked status tables, including letter-spaced IDs and TO DO, labelled Patch assertions, commit references, and grouped subissue resolutions. Mixed subissue outcomes remain `other` with their individual claims. Letter-spaced titles remain verbatim source fragments; originals and full-text caches are unchanged.', '',
        'Cantina reads publisher and client resolution responses, preserving the named actor and PDF ligatures. Confirmed alone remains `other`; it does not prove remediation. Low Risk & Informational containers use explicit detail grades where printed. Deployment checklists, whitelist notes, summary/link-only releases and clean reports have separate dispositions. Review comments remain recommendations.', '',
        'Zokyo image status badges are not labelled not_stated when the text layer omits them. The local OCR reader keeps original/text hashes, page, pixel crop and image hash, OCR text, and association to an existing source badge or title. Complete page sequences must agree on risk labels; missing text badges require a matching existing title. The final unresolved image labels were visually reviewed in retained montages and recorded in `scripts/findings/parsers/fixtures/zokyo_reviewed_badges.json`. Source spellings NOT VALID, ACKNOWLEDG and RESOLVE are preserved and normalized within the Zokyo module. A visually blank status area is explicitly not_stated. Post-audit assertions and commit references are read separately. This is deterministic extraction validation, not an independent OCR accuracy estimate.', '',
        'Kudelski architecture/observation cards that genuinely print no status receive not_stated. The Beluga retest only rechecks prior-audit findings and does not create new initial-audit findings. Quantstamp project-specific IDs are parsed from risk/status badges; certificate/summary releases and the sparse EMR text layer are explicit exceptions. The EMR certificate visibly has an issue summary, so its sparse text is not interpreted as zero findings.', '',
        'Theori has a reviewed authoritative profile with citations to the 2021 BiFi scale example and explicit Theori/ChainLight severity definitions. Only that profile was added to the policy and its JSON export. Unlisted grades remain unknown. Older ChainSecurity C/H/M/L codes remain verbatim and unmapped because changing that publisher severity policy is outside this task.', '',
        'Theori validation cohort (stored publisher attribution is retained):','',
        '| Original | Stored publisher | Theori variant | Extracted entries | Outcome |','|---|---|---|---:|---|']
    for d in theori['documents']:
        outcome=(d.get('disposition') or {}).get('reason') or ', '.join(f'{k}={v}' for k,v in sorted(d['record_kinds'].items()))+'; '+', '.join(f'{k}={v}' for k,v in sorted(d['statuses'].items()))
        lines.append(f"| [{d['sha256'][:12]}]({d['public_url']}) | {d['source_publisher']} | {d['variant']} | {d['findings']} | {outcome} |")
    reconciliation=json.loads((ROOT/'data/collect/chainlight/identity_reconciliation.json').read_text())
    official={r['sha256'] for r in reconciliation['source_links'] if r['source_firm_id']=='theori'}
    lines += ['',f"The official alias ledger contains {len(official)} originals; {len(official & holdouts())} are holdouts and were excluded before text access. The cohort above contains {sum(d['source_publisher']=='chainlight' for d in theori['documents'])} eligible canonical ChainLight originals and {sum(d['source_publisher']=='theori' for d in theori['documents'])} directly collected Theori original. The bilingual variant has no eligible live sample here; its coverage remains N/A and its synthetic regression remains active."]
    lines += ['', 'A BiFi revision original has missing narrative glyphs in the rendering as well as the text layer. Its absence of extracted details is an explicit document limitation. Holdout originals are filtered before any original, text cache, or OCR receipt is opened. New canonical ChainLight receipts are used only as a Theori validation cohort here; collection files and attribution were not edited.', '',
        'Reproduce:','',
        '```sh',
        'python3 -I -S scripts/findings/parsers/test_variants_u.py --ocr-zokyo',
        'python3 -I -S scripts/findings/parsers/test_variants_u.py --regenerate',
        'python3 -I -S scripts/findings/parsers/test_variants_u.py --verify-outputs',
        'python3 -I -S scripts/findings/parsers/test_variants_u.py --from-outputs',
        'python3 -I -S scripts/findings/parsers/test_variants_u.py',
        'python3 -I -S -m unittest discover -s scripts/findings -p test_variants.py -q',
        '```','',
        'Full-corpus checks use regenerated outputs and the current severity/status maps. Missing status labels stay outside known-status denominators.', '',
        '<details><summary>Reviewed original queue</summary>','',
        '| Publisher | Original | Variant | Entries / disposition |','|---|---|---|---|']
    for q in queued:
        outcome=(str(q['findings'])+(' / '+q['disposition']['reason'] if q['disposition'] else '')) if q['findings'] else q['disposition']['reason']
        lines.append(f"| {q['firm']} | [{q['sha256'][:12]}]({q['public_url']}) | {q['variant']} | {outcome} |")
    lines += ['','</details>','']
    (ROOT/'docs/phase4/variants_u.md').write_text('\n'.join(lines))
    sources=['docs/phase4/variants_u.md','schema/severity_map.yaml','schema/severity_map.json','scripts/findings/test_variants.py','scripts/findings/parsers/test_variants_u.py']
    sources += ['scripts/findings/parsers/fixtures/zokyo_reviewed_badges.json']
    sources += ['scripts/findings/parsers/'+f.replace('-','_')+'.py' for f in FIRMS]
    generated=['data/findings/_unknown_layouts.jsonl']
    for f in FIRMS:
        if f=='theori':continue
        generated += [f'data/findings/{f}.jsonl',f'data/findings/validation/{f}.json',f'data/findings/validation/{f}.jsonl']
    files=sorted(set(sources+generated+[str(p.relative_to(ROOT)) for p in LOCAL.rglob('*') if p.is_file()]+[str(p) for p in Path('/tmp').glob('phase4e-u-*') if p.is_file()]+['local-cache/phase4e-u/files_written.txt']))
    (LOCAL/'files_written.txt').write_text('\n'.join(files)+'\n')
    print(json.dumps({'queue_before':dict(before_counts),'queue_after':dict(after_counts),'variants':after['variants']},indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture', action='store_true')
    p.add_argument('--unknowns', action='store_true')
    p.add_argument('--remaining', type=Path)
    p.add_argument('--status-gaps', action='store_true')
    p.add_argument('--audit-status', action='store_true')
    p.add_argument('--inspect', nargs=2, metavar=('FIRM', 'SHA'))
    p.add_argument('--page', type=int)
    p.add_argument('--raw', action='store_true')
    p.add_argument('--render', action='store_true')
    p.add_argument('--selection', action='store_true')
    p.add_argument('--report', action='store_true')
    p.add_argument('--firms', nargs='+', default=list(FIRMS))
    p.add_argument('--theori-profile', action='store_true')
    p.add_argument('--ocr-zokyo', action='store_true')
    p.add_argument('--sha')
    p.add_argument('--regenerate', action='store_true')
    p.add_argument('--verify-outputs', action='store_true')
    p.add_argument('--from-outputs', action='store_true')
    p.add_argument('--export-profile', action='store_true')
    p.add_argument('--pending-badges', action='store_true')
    p.add_argument('--record-reviewed-badges', action='store_true')
    args = p.parse_args()
    if args.record_reviewed_badges:
        record_reviewed_badges()
    elif args.pending_badges:
        pending=[];docs={d['document_id']:d for d in inputs()}
        for line in (ROOT/'data/findings/zokyo.jsonl').open():
            row=json.loads(line)
            if row['evidence'].get('status_availability',{}).get('reason')!='badge_not_decoded':continue
            span=row['evidence']['badge_span'];r=load(docs[row['document_id']])
            page=next(p['page'] for p in r.meta['pages'] if p['start']<=span['start']<p['end'])
            pending.append(dict(sha256=row['sha256'],page=page,title=row['title'],source_span=span,card_start=span['start'],risk_raw=row['severity_raw']))
        write_json(LOCAL/'pending_badges.json',pending);print(json.dumps(pending,indent=2))
        if args.render:
            from badge_ocr import ppm
            def chunk(kind,data):return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data))
            for sha,number in sorted({(p['sha256'],p['page']) for p in pending}):
                assert sha not in holdouts()
                receipt=json.loads((LOCAL/'zokyo_badges'/(sha+'.json')).read_text())
                proofs=[p for p in receipt['review'] if p['page']==number]
                payload=(LOCAL/'ocr'/sha/f'{number}.ppm').read_bytes()
                assert all(digest(payload)==p['render_sha256'] for p in proofs)
                w,h,rgb=ppm(payload);width=9*w//10;parts=[]
                for proof in proofs:
                    x0=max(0,w//20);y0=max(0,proof['pixel_box'][1]-10);y1=min(h,proof['pixel_box'][3]+90)
                    parts += [rgb[(y*w+x0)*3:(y*w+x0+width)*3] for y in range(y0,y1)]
                    parts += [b'\x40\x80\xc0'*width]*8
                if not parts:continue
                raw=b''.join(b'\0'+row for row in parts)
                png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!2I5B',width,len(parts),8,2,0,0,0))+chunk(b'IDAT',zlib.compress(raw))+chunk(b'IEND',b'')
                output=LOCAL/'review'/f'{sha}-{number}.png';output.parent.mkdir(exist_ok=True)
                output.write_bytes(png);print('REVIEW',sha,number,str(output),[(p['ocr_text'],p['pixel_box']) for p in proofs])
    elif args.export_profile:
        export_profile()
    elif args.regenerate:
        from run import main as regenerate
        sys.argv=[sys.argv[0],'--firms',*(f for f in FIRMS if f!='theori')]
        regenerate()
    elif args.verify_outputs:
        verify_outputs()
    elif args.from_outputs:
        report_from_outputs()
    elif args.ocr_zokyo:
        ocr_zokyo(args.sha)
    elif args.theori_profile:
        theori_profile()
    elif args.capture:
        target = LOCAL/'baseline_metrics.json'
        assert not target.exists(), 'Baseline is immutable'
        result = saved_snapshot(); write_json(target, result)
        print(json.dumps({'queue': dict(Counter(d['firm'] for d in result['queue'])), 'variants': result['variants']}, indent=2))
    elif args.audit_status:
        shown=Counter()
        for doc in inputs():
            if doc['row']['firm_id'] not in args.firms:continue
            try:r=load(doc)
            except FileNotFoundError:continue
            cs=module(r.firm).parse(r)
            for c in cs:
                if c.status_raw or shown[r.layout_selection['variant_id']]>=15:continue
                body=r.text[c.start:c.end]
                m=re.search(r'(?:^|\n)\s*(?:Patch|Post-audit|Resolution)\s*[:.]?\s*\n',body,re.I)
                if m:
                    tail=body[m.end():m.end()+650]
                    if re.search(r'fixed|resolved|accept|acknowledg',tail,re.I):
                        print('\nUNREAD',r.firm,doc['row']['sha256'],c.printed_id,c.title,'\n'+tail)
                        shown[r.layout_selection['variant_id']]+=1
    elif args.status_gaps:
        for firm in FIRMS:
            path = ROOT/'data/findings'/(firm+'.jsonl')
            if not path.exists(): continue
            samples = Counter(); markers = Counter()
            for line in path.open():
                row = json.loads(line)
                if row['status'] not in (None, 'unknown'): continue
                key = row['variant_id']
                hits = [v.strip() for v in row['body_text'].splitlines() if re.search(r'Status|Remediat|Resol|Fixed|Fix Review|Patch|Cantina:', v, re.I)]
                for hit in hits:
                    markers[(key, re.sub(r'[a-f0-9]{8,}', 'COMMIT', hit)[:120])] += 1
                if samples[key] >= 3: continue
                samples[key] += 1
                print('\nGAP', key, row['sha256'], row['publisher_finding_id'], row['title'])
                print('\n'.join(hits) if hits else '(no status markers)')
            print('\nMARKERS', firm)
            for (key, marker), n in markers.most_common(45): print(n, key, marker)
    elif args.inspect or args.unknowns or args.remaining:
        docs = inputs()
        queued = {d['sha256'] for d in json.loads((args.remaining or LOCAL/'baseline.json').read_text())['queue']}
        for d in docs:
            firm, sha = d['row']['firm_id'], d['row']['sha256']
            if args.inspect and not (firm == args.inspect[0] and sha.startswith(args.inspect[1])): continue
            if (args.unknowns or args.remaining) and sha not in queued: continue
            r = load(d)
            if args.selection:
                cs=module(r.firm).parse(r)
                print(json.dumps(r.layout_selection,indent=2));print('FINDINGS',len(cs),'DISPOSITION',getattr(r,'layout_disposition',None))
                if r.firm=='zokyo':
                    from parsers import zokyo
                    print('REGION',zokyo._region(r))
                continue
            if args.render:
                path=original_path(d['row'])
                assert digest(path.read_bytes())==sha and sha not in holdouts()
                prefix=LOCAL/'render'/f'{sha}-{args.page or 1}'
                prefix.parent.mkdir(parents=True,exist_ok=True)
                subprocess.run([tool('pdftoppm',ROOT),'-png','-r','100','-f',str(args.page or 1),'-l',str(args.page or 1),'-singlefile',str(path),str(prefix)],env=tool_environment(ROOT),check=True,capture_output=True)
                print(prefix.with_suffix('.png'));continue
            if args.raw:
                path=original_path(d['row'])
                assert digest(path.read_bytes())==sha and sha not in holdouts()
                command=[tool('pdftotext', ROOT),'-raw']
                if args.page: command += ['-f',str(args.page),'-l',str(args.page)]
                print(subprocess.run(command+[str(path),'-'],env=tool_environment(ROOT),capture_output=True,check=True).stdout.decode('utf-8'))
                continue
            print('\nDOC', firm, sha, d['row']['filename'], len(r.text))
            if args.inspect:
                for page in r.meta['pages']:
                    if args.page is None or page['page'] == args.page: print('PAGE', page['page'], '\n'+page['text'])
            else:
                lines = [f'{l.page}: {l.text}' for l in r.lines if not l.excluded and not re.search(r'(?:\.\s*){4,}\s*\d+\s*$',l.text) and re.search(r'Severity|Resolved|Status|Corrected|Findings|Issues|OS-|QSP-|^\s*\d+(?:\.\d+)+|^\s*(?:High|Medium|Low|Informational)\s*$', l.text, re.I)]
                print('\n'.join(lines[:30]) if lines else r.text[:800])
    elif args.report:
        result = evaluate(args.firms); write_json(LOCAL/('after.json' if tuple(args.firms)==FIRMS else 'after_'+'_'.join(args.firms)+'.json'), result)
        print(json.dumps({'queue': dict(Counter(d['firm'] for d in result['queue'])), 'variants': result['variants']}, indent=2))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1].startswith('--'):
        main()
    else: unittest.main()
