"""Holdout-guarded corpus survey, before/after receipts and hard-layout regressions.

All corpus access goes through eligible metadata before opening originals/caches.
Local immutable baseline: local-cache/phase4-hard-layouts/before.json.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest
import shutil
import importlib.util
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, digest, documents, holdouts, original_path, read_snapshot, write_json
from core import Report
from parsers import module
from extract import tool, tool_environment
from unittest.mock import patch

FIRMS = ('chainsecurity', 'ottersec', 'kudelski-security', 'theori', 'zokyo', 'quantstamp')
LOCAL = ROOT / 'local-cache/phase4-hard-layouts'


class HardLayoutTests(unittest.TestCase):
    def parse(self,firm,text):
        from test_variants import report
        r=report(text,firm);cs=module(firm).parse(r)
        for c in cs:
            self.assertTrue(0<=c.start<c.end<=len(r.text))
            if c.evidence.get('status_evidence'):
                e=c.evidence['status_evidence']
                self.assertEqual(r.text[e['start']:e['end']],e['text'])
                self.assertEqual(e['text'],c.status_raw)
        return r,cs

    def test_note_only_and_wrapped_version_cards(self):
        from test_variants import D
        r,cs=self.parse('chainsecurity','8 Notes\n8.1 Allowed Sender of Orders\nNote Version 1\n'+D+
                        '8.2 User Responsibility for Setting Trusted\nResolvers\nNote Version 1\n'+D)
        self.assertEqual(len(cs),2)
        self.assertEqual([c.normalized for c in cs],['info','info'])
        self.assertEqual(cs[1].title,'User Responsibility for Setting Trusted Resolvers')
        self.assertEqual(r.layout_selection['variant_id'],'chainsecurity/v2021_version_cards')

    def test_version_grade_cannot_leak_from_next_card(self):
        from test_variants import D
        _,cs=self.parse('chainsecurity','5.1 Supporting text\nNo grade is printed.\n5.2 Actual issue\nSecurity High Version 1\n'+D)
        self.assertEqual([c.printed_id for c in cs],['5.2'])

    def test_legacy_numeric_roman_scope_and_dispositions(self):
        from test_variants import D
        r,cs=self.parse('chainsecurity','Security Issues\n1.2 Challengers might not receive rewards M 3 Addressed\n'+D+
                        'Trust Issues\nI. Bond of darknode can be abused M 3 Acknowledged\n'+D+
                        'II. Basic specification 3 No Issue\n'+D+
                        'Design Issues\nI. Inefficient transfers L 3 Fixed\n'+D)
        self.assertEqual(len(cs),3)
        self.assertEqual([c.printed_id for c in cs],['1.2','I.','I.'])
        self.assertEqual([c.title for c in cs],['Challengers might not receive rewards','Bond of darknode can be abused','Inefficient transfers'])
        self.assertEqual([c.normalized for c in cs],['medium','medium','low'])
        self.assertEqual([c.normalized_status for c in cs],['resolved','acknowledged','fixed'])
        self.assertEqual(cs[1].evidence['source_section'],'Trust Issues')
        self.assertEqual(len(r.layout_disposition['excluded']),1)

    def test_kudelski_wrapped_title_before_id_and_bracket_status(self):
        from test_variants import D
        _,cs=self.parse('kudelski-security','TECHNICAL FINDINGS\n\nValidator unreferenced and unchecked\nin stake_reserve\nFinding ID: KS-MARINADE-01\nSeverity: Medium\nStatus: Resolved\n'+D+
                        '\n\n3.2 Another title\nFinding ID: source#2\nSeverity: [High]\nStatus: [Remediated]\n'+D)
        self.assertEqual(len(cs),2)
        self.assertEqual([c.printed_id for c in cs],['KS-MARINADE-01','source#2'])
        self.assertEqual(cs[0].title,'Validator unreferenced and unchecked in stake_reserve')
        self.assertEqual(cs[1].normalized_status,'resolved')

    def test_theori_vertical_card_does_not_use_summary_prose_grade(self):
        from test_variants import D
        _,cs=self.parse('theori','Issue #1:\nAn actual card\nSummary\nSeverity\nAn actual summary ends in High\nFixed (Low)\nDescription\n'+D+
                        'Issue #2:\nUnfixed card\nSummary\nSeverity\nSummary ends in Low\nMedium\nDescription\n'+D)
        self.assertEqual([c.normalized for c in cs],['low','medium'])
        self.assertEqual(cs[0].normalized_status,'fixed')

    def test_holdout_is_denied_before_any_path_or_cache_access(self):
        with patch(__name__+'.holdouts',return_value={'a'*64}),patch(__name__+'.original_path') as original,patch.object(Path,'exists') as exists:
            with self.assertRaisesRegex(ValueError,'Holdout'):load({'row':dict(sha256='a'*64)})
            original.assert_not_called();exists.assert_not_called()

    def test_page_detection_keeps_ordinary_text_and_blank_diagrams(self):
        from extraction_normalization import letter_spaced,needs_ocr
        self.assertFalse(letter_spaced('A normal report with a grade H and a variable x. '*20))
        self.assertTrue(letter_spaced('C u s t o d y   T o k e n   A c c o u n t   C l o s i n g   D o S    H I G H    O S - E L L - A D V - 0 0'))
        self.assertTrue(needs_ocr('Page footer',dict(image_fraction=0,vector_glyphs=200,vector_primitives=500)))
        self.assertTrue(needs_ocr('Page footer',dict(image_fraction=.8,vector_glyphs=0,vector_primitives=0)))
        self.assertFalse(needs_ocr('',dict(image_fraction=0,vector_glyphs=1,vector_primitives=4)))

    def test_native_advances_recover_words_ids_columns_and_duplicate_badges(self):
        from extraction_normalization import glyph_text
        chars=[];x=0
        for token in ['Custody','Token','Account','Closing','DoS']:
            for ch in token:
                chars.append((ord(ch),1,(x,20),(x,15,x+6,21)));x+=6
            x+=3
        risk=[(ord(ch),1,(250+6*i,20),(250+6*i,15,256+6*i,21)) for i,ch in enumerate('HIGH')]
        ids=[(ord(ch),1,(330+6*i,20),(330+6*i,15,336+6*i,21)) for i,ch in enumerate('OS-ELL-ADV-00')]
        class Page:
            def get_texttrace(self):return [dict(type=0,size=4,chars=chars),dict(type=0,size=10,chars=risk),dict(type=0,size=10,chars=risk),dict(type=0,size=4,chars=ids)]
        self.assertEqual(glyph_text(Page()).strip(),'Custody Token Account Closing DoS    HIGH    OS-ELL-ADV-00')

    def test_ocr_rows_keep_badge_and_summary_columns(self):
        from extraction_normalization import tsv_words,word_layout
        tsv='level\tleft\ttop\twidth\theight\tconf\ttext\n5\t250\t30\t30\t12\t95\tHIGH\n5\t20\t30\t70\t12\t95\tVulnerability\n5\t20\t60\t80\t12\t95\tSeverity\n5\t250\t60\t35\t12\t95\tStatus\n'
        self.assertEqual(word_layout(tsv_words(tsv)).splitlines(),['Vulnerability    HIGH','', 'Severity    Status'])
        descenders=[dict(text='for',box=[0,20,12,27]),dict(text='gas',box=[15,23,30,33]),dict(text='savings',box=[33,20,60,28])]
        self.assertEqual(word_layout(descenders).strip(),'for gas savings')

    def test_prior_ocr_structure_and_known_grades_survive_badge_repair(self):
        from extraction_normalization import merge_prior_ocr
        before='Complete Analysis\nHigh-1 Resolved\nActual vulnerability\nBody with original spacing.\n\nAnother vulnerability\nOther body.\n'
        receipt=dict(words=[dict(text='Actual vulnerability',box=[10,20,120,30]),dict(text='Another vulnerability',box=[10,100,120,110])],
            badge_crops=[dict(box=[0,0,200,10],words=[dict(text='High-1',box=[0,0,30,10]),dict(text='Open',box=[40,0,60,10])]),
                         dict(box=[0,80,200,90],words=[dict(text='Low-2',box=[0,80,30,90]),dict(text='Fixed',box=[40,80,60,90])])])
        value=merge_prior_ocr(before,'Replacement whole-page OCR loses a card.',receipt)
        self.assertEqual(value,before.replace('Another vulnerability','Low-2 Fixed\nAnother vulnerability'))
        self.assertEqual(value.count('High-1'),1)

    def test_partial_native_cards_retain_independently_anchored_image_cards(self):
        from test_variants import report,D
        from parsers import zokyo
        text='Complete Analysis\nHigh Resolved\nFirst vulnerability\n\n'+D+'\fSecond vulnerability\n\n'+D
        r=report(text,'zokyo');claims=[]
        for title,raw in [('First vulnerability','High'),('Second vulnerability','Low')]:
            start=text.index(title);span=dict(start=start,end=start+len(title),text=title)
            claims.append(dict(card_start=start,source_span=span,title_span=span,risk_raw=raw,status_raw='Resolved'))
        with patch.object(zokyo,'visual_receipts',return_value=claims):cs=module('zokyo').parse(r)
        self.assertEqual(len(cs),2)
        self.assertEqual([c.normalized for c in cs],['high','low'])

    def test_zokyo_ocr_icon_noise_is_gated_by_page_receipt(self):
        from test_variants import report,D
        from parsers import zokyo
        text='Complete Analysis\ncre_CRITICAL\nActual vulnerability\nContract.sol\n'+D
        r=report(text,'zokyo');self.assertFalse(zokyo._card_parse(r))
        r.meta['issues']=[dict(kind='ocr_page',page=1)]
        cs=zokyo._card_parse(r)
        self.assertEqual(len(cs),1);self.assertEqual(cs[0].severity_raw,'CRITICAL')
        self.assertEqual(cs[0].title,'Actual vulnerability')

    @unittest.skipUnless(importlib.util.find_spec('fitz') and tool('tesseract',ROOT), 'requires local PDF/OCR environment')
    def test_vector_and_raster_cards_recover_badge_before_fingerprinting(self):
        import fitz
        from extract import extract_one
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);out=root/'local-cache/fulltext';out.mkdir(parents=True)
            native=fitz.open();p=native.new_page(width=600,height=500)
            p.insert_text((30,60),'Actual vulnerability',fontsize=16)
            p.draw_rect(fitz.Rect(230,42,280,66),color=None,fill=(1,.83,.6))
            p.insert_text((235,59),'HIGH',fontsize=12,color=(.5,.2,0))
            p.insert_text((360,59),'OS-TST-ADV-00',fontsize=12)
            p.insert_text((30,120),'Description',fontsize=13)
            p.insert_text((30,150),'Source evidence describes an actual finding and its impact.',fontsize=11)
            p.insert_text((30,180),'Patch',fontsize=13)
            p.insert_text((30,210),'Resolved in commit abcdef123.',fontsize=11)
            svg=p.get_svg_image(text_as_path=True)
            with fitz.open('svg',svg.encode()) as vector_doc:vector=vector_doc.convert_to_pdf()
            raster_doc=fitz.open();rp=raster_doc.new_page(width=600,height=500)
            rp.insert_image(rp.rect,stream=p.get_pixmap(matrix=fitz.Matrix(2,2)).tobytes('png'))
            rp.insert_text((20,450),' '.join('LETTERSPACEDNATIVELAYERWITHMANYGLYPHS'),fontsize=7)
            for fmt,payload in [('vector',vector),('raster',raster_doc.tobytes())]:
                with self.subTest(fmt=fmt):
                    sha=digest(payload);path=root/'local-cache'/(sha+'.pdf');path.write_bytes(payload)
                    row=dict(sha256=sha,file_format='pdf',firm_id='ottersec',local_path=str(path))
                    with patch('extract.tool',side_effect=lambda name,_root:tool(name,ROOT)),patch('extract.tool_environment',return_value=tool_environment(ROOT)):
                        receipt=extract_one((sha,row),root,{'f'*64})
                    self.assertEqual(receipt['status'],'ok',receipt)
                    meta=json.loads((out/(sha+'.pages.json')).read_text());text=(out/(sha+'.txt')).read_text()
                    self.assertIn('ocr_page',[q['kind'] for q in meta['issues']])
                    r=Report(text,meta,'ottersec');cs=module('ottersec').parse(r)
                    self.assertEqual(len(cs),1,text)
                    self.assertEqual(cs[0].severity_raw,'HIGH')
                    self.assertEqual(cs[0].printed_id,'OS-TST-ADV-00')
                    self.assertEqual(cs[0].normalized_status,'resolved')
            native.close();raster_doc.close()

    @unittest.skipUnless(importlib.util.find_spec('fitz') and tool('tesseract',ROOT), 'requires local PDF/OCR environment')
    def test_wide_light_badge_on_dark_outlined_page_retains_status(self):
        import fitz
        from extraction_normalization import ocr_page
        with tempfile.TemporaryDirectory() as tmp:
            doc=fitz.open();p=doc.new_page(width=600,height=500)
            p.draw_rect(p.rect,color=None,fill=(.03,.01,.08))
            p.draw_rect(fitz.Rect(40,50,560,78),color=None,fill=(.97,.97,.97))
            p.insert_text((50,69),'HIGH',fontsize=12)
            p.insert_text((105,69),'RESOLVED',fontsize=12,color=(.68,.68,.68))
            p.insert_text((40,110),'Actual vulnerability',fontsize=14,color=(1,1,1))
            p.insert_text((40,140),'Description of the finding and its security impact.',fontsize=11,color=(1,1,1))
            with fitz.open('svg',p.get_svg_image(text_as_path=True).encode()) as svg:
                with fitz.open('pdf',svg.convert_to_pdf()) as outlined:
                    text,receipt=ocr_page(outlined[0],tool('tesseract',ROOT),tool_environment(ROOT),tmp,60)
            self.assertRegex(text,r'HIGH\s+RESOLVED')
            self.assertTrue(receipt['badge_crops'])
            doc.close()


def inputs():
    docs = [d for d in read_snapshot() if d['row']['firm_id'] in FIRMS]
    current, _, _ = documents()
    seen = {d['document_id'] for d in docs}
    docs += [d for d in current if d['row']['firm_id'] == 'theori' and d['document_id'] not in seen]
    return docs


def load(doc):
    row = doc['row']; sha = row['sha256']
    if sha in holdouts():
        raise ValueError('Holdout denied before cache/original access')
    folder = ROOT / 'local-cache/fulltext'
    meta_path = folder / (sha + '.pages.json')
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        text = (folder / (sha + '.txt')).read_bytes().decode('utf-8')
        assert digest(text.encode()) == meta['text_sha256']
    else:
        path = original_path(row)
        assert digest(path.read_bytes()) == sha
        text = subprocess.run([tool('pdftotext', ROOT), '-layout', str(path), '-'],
                              check=True, capture_output=True, env=tool_environment(ROOT)).stdout.decode('utf-8').rstrip('\f')
        pages = []; start = 0
        for i, value in enumerate(text.split('\f'), 1):
            pages.append(dict(page=i, start=start, end=start+len(value), text=value))
            start += len(value)+1
        meta = dict(pages=pages, text_sha256=digest(text.encode()), file_format=row['file_format'], method='pdftotext-layout')
    return Report(text, meta | {'sha256': sha, 'date_hint': row.get('date_hint')}, row['firm_id'])


def census(staged=False):
    saved={}
    if staged:
        for firm in FIRMS:
            path=ROOT/'data/findings/validation'/(firm+'.jsonl')
            if path.exists():
                for line in path.read_text().splitlines():
                    d=json.loads(line);saved[(firm,d['sha256'])]=d
    result = {}
    for doc in inputs():
        row = doc['row']; key = row['firm_id'] + ':' + row['sha256']
        if key in result: continue
        try:
            r = load(doc)
            if staged and (r.firm,row['sha256']) in saved:
                d=saved[(r.firm,row['sha256'])];cs=None
            else:cs = module(r.firm).parse(r)
        except FileNotFoundError:
            continue
        result[key] = dict(sha256=row['sha256'], firm=r.firm, document_id=doc['document_id'],
            public_url=row['public_url'], title=row.get('title_hint'), findings=len(cs) if cs is not None else d.get('findings',0),
            formal=sum(c.record_kind == 'formal_finding' for c in cs) if cs is not None else d.get('formal_findings',0),
            severity=dict(Counter(c.normalized for c in cs)) if cs is not None else d.get('parsed_counts',{}),
            variant=r.layout_selection['variant_id'] if cs is not None else d.get('variant_id'), text_sha256=r.meta['text_sha256'],
            classes=dict(letter_spaced=bool(re.search(r'O S\s*-\s*(?:[A-Z] ){2}',r.text)),
                         note=bool(re.search(r'\bNote\s+Version\s+\d+',r.text)),
                         legacy=r.firm=='chainsecurity' and bool(re.search(r'^.*\s+[CHML]\s*(?:[3Ë✓✔]\s*)?(?:Fixed|Addressed|Acknowledged)?\s*$',r.text,re.M)),
                         title_first=r.firm=='kudelski-security' and 'Finding ID:' in r.text,
                         theori=r.firm=='theori'),
            sparse_pages=[p['page'] for p in r.meta['pages'] if sum(c.isalnum() for c in p['text'])<250])
    return result


def freeze():
    path=LOCAL/'baseline.json'
    if path.exists():raise FileExistsError('Baseline already frozen')
    for name in ('extract.py','parsers/chainsecurity.py','parsers/kudelski_security.py','parsers/theori.py','parsers/ottersec.py'):
        target=LOCAL/'code_origin'/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes((Path(__file__).resolve().parents[1]/name).read_bytes())
    write_json(path,census(staged=True))
    print('Frozen staged pre-change diagnostics and new Theori',path,flush=True)


def capture():
    path = LOCAL / 'before.json'
    if path.exists(): raise FileExistsError('Baseline already frozen')
    write_json(path, census())
    for name in ('extract.py', 'parsers/chainsecurity.py', 'parsers/kudelski_security.py', 'parsers/theori.py', 'parsers/ottersec.py'):
        target = LOCAL / 'code_before' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((Path(__file__).resolve().parents[1] / name).read_bytes())
    print('Frozen',path)


def survey():
    before = json.loads((LOCAL / 'baseline.json').read_text())
    print('Cohort',dict(Counter(d['firm'] for d in before.values())))
    for name in ('letter_spaced', 'note', 'legacy', 'title_first', 'theori'):
        rows=[d for d in before.values() if d['classes'][name]]
        print(name,len(rows),[(d['sha256'][:12],d['findings'],d['title']) for d in rows[:12]])


def inspect(prefix, page=None, render=False, native=False):
    doc = next(d for d in inputs() if d['row']['sha256'].startswith(prefix))
    r = load(doc)
    print(doc['row']['public_url'])
    for p in r.meta['pages']:
        if page is not None and p['page'] != page: continue
        print('\nPAGE',p['page'],p['text'])
    if render or native:
        import fitz
        path = original_path(doc['row'])
        assert digest(path.read_bytes()) == doc['row']['sha256']
        LOCAL.mkdir(parents=True, exist_ok=True)
        with fitz.open(path) as pdf:
            if render:pdf[page-1].get_pixmap(matrix=fitz.Matrix(1.5,1.5)).save(LOCAL/(prefix+'-'+str(page)+'.png'))
            if native:
                pg=pdf[page-1]
                print('NO SYNTHETIC SPACES',pg.get_text(flags=fitz.TEXTFLAGS_TEXT|fitz.TEXT_INHIBIT_SPACES)[:2400])
                for span in pg.get_texttrace()[:12]:
                    print('TRACE',span['size'],span['bbox'],repr(''.join(chr(c[0]) for c in span['chars'])),str(span['chars'][:3]))
                print('BADGE RECTANGLES',[(list(d['rect']),d.get('fill'),len(d['items'])) for d in pg.get_drawings() if 18<d['rect'].width<240 and 6<d['rect'].height<35][:40])


def metadata():
    current,_,_=documents()
    for doc in current:
        row=doc['row']
        if re.search(r'theori|qubit',json.dumps(row),re.I):
            print(row['firm_id'],row['sha256'][:12],row.get('title_hint'),row.get('filename'),row['public_url'])


def search(firm, pattern):
    seen=set()
    for doc in inputs():
        if doc['row']['firm_id'] != firm or doc['row']['sha256'] in seen: continue
        seen.add(doc['row']['sha256'])
        try: r=load(doc)
        except FileNotFoundError: continue
        for p in r.meta['pages']:
            m=re.search(pattern,p['text'],re.I|re.M)
            if m:
                print(doc['row']['sha256'][:12],p['page'],doc['row'].get('title_hint'),repr(p['text'][max(0,m.start()-130):m.end()+220]))
                break


def preview(prefix):
    doc=next(d for d in inputs() if d['row']['sha256'].startswith(prefix));r=load(doc)
    cs=module(r.firm).parse(r)
    print(r.layout_selection['variant_id'],len(cs))
    for c in cs[:40]:print(c.printed_id,c.severity_raw,c.normalized,c.normalized_status,c.title)


def sparse():
    import fitz
    result={};seen=set()
    for doc in inputs():
        row=doc['row'];sha=row['sha256']
        if sha in seen or row['file_format']!='pdf':continue
        seen.add(sha)
        try:r=load(doc)
        except FileNotFoundError:continue
        low=[p for p in r.meta['pages'] if sum(c.isalnum() for c in p['text'])<250]
        if not low:continue
        path=original_path(row); assert digest(path.read_bytes())==sha
        with fitz.open(path) as pdf:
            pages=[]
            for p in low:
                page=pdf[p['page']-1]
                vectors=len(page.get_drawings());images=len(page.get_images())
                primitives=sum(len(d['items']) for d in page.get_drawings())
                if vectors>80 or images:
                    pages.append(dict(page=p['page'],characters=sum(c.isalnum() for c in p['text']),vectors=vectors,primitives=primitives,images=images))
            if pages:result[sha]=dict(firm=row['firm_id'],title=row.get('title_hint'),pages=pages)
    write_json(LOCAL/'sparse.json',result)
    for sha,d in result.items():print(sha[:12],d)


def policy():
    path=ROOT/'schema/severity_map.yaml';source=path.read_text();data=json.loads(source)
    docs=inputs();era=data['publishers']['chainsecurity']['eras'][0]
    for prefix,page,labels in [('10569b272f26',20,{'Note':'info'}),('1260dae236f8',7,{'H':'high','M':'medium','L':'low'}),('1260dae236f8',8,{'C':'critical'})]:
        doc=next(d for d in docs if d['row']['sha256'].startswith(prefix));r=load(doc)
        p=next(p for p in r.meta['pages'] if p['page']==page)
        if prefix=='10569b272f26':
            quote=p['text'][p['text'].index('8 Notes'):p['text'].index('8.1')].strip()
        else:
            quote=p['text'][p['text'].index('Terminology'):] if page==7 else p['text'][:p['text'].index('These severities')].strip()
        evidence=dict(sha256=doc['row']['sha256'],page=page,page_basis='pdf_page',public_url=doc['row']['public_url'],
                      kind='definition',quote=quote,accessed_utc='2026-10-21')
        if evidence not in era['evidence']:era['evidence'].append(evidence)
        for raw,norm in labels.items():
            era['labels'][raw]=dict(normalized=norm,rationale=('Publisher Notes clarify or support the report and do not require immediate project modification; informational awareness.' if raw=='Note' else 'Publisher explicitly defines '+raw+' as '+norm+' in its native risk scale.'))
    old=json.loads(source)['publishers']['chainsecurity']
    old_render=json.dumps(old,ensure_ascii=False,indent=2).splitlines()
    new_render=json.dumps(data['publishers']['chainsecurity'],ensure_ascii=False,indent=2).splitlines()
    def indented(lines):return '\n'.join(lines[:1]+['    '+l for l in lines[1:]])
    assert source.count(indented(old_render))==1
    path.write_text(source.replace(indented(old_render),indented(new_render)))
    exported=ROOT/'schema/severity_map.json';existing=exported.read_text()
    start=existing.index('    "chainsecurity": ')
    end=start+len('    "chainsecurity": ')+re.search(r'^    "[^"\n]+": ',existing[start+len('    "chainsecurity": '):],re.M).start()
    entry=json.dumps(data['publishers']['chainsecurity'],ensure_ascii=False,indent=2,sort_keys=True).splitlines()
    exported.write_text(existing[:start]+'    "chainsecurity": '+entry[0]+'\n'+'\n'.join('    '+l for l in entry[1:])+',\n'+existing[end:])
    assert json.loads(exported.read_text())==data
    print('Updated only ChainSecurity crosswalk and JSON export')


def prepare():
    if (LOCAL/'targets.json').exists():
        print('Using immutable pre-normalization extraction targets',flush=True);return
    from extraction_normalization import letter_spaced,visual_content,needs_ocr
    import fitz
    result={};seen=set()
    for doc in inputs():
        row=doc['row'];sha=row['sha256']
        if sha in seen or row['file_format']!='pdf':continue
        seen.add(sha)
        try:r=load(doc)
        except FileNotFoundError:continue
        letters=[p['page'] for p in r.meta['pages'] if letter_spaced(p['text'])]
        low=[p for p in r.meta['pages'] if sum(c.isalnum() for c in p['text'])<250]
        visual=[]
        if low:
            path=original_path(row);assert digest(path.read_bytes())==sha
            with fitz.open(path) as pdf:
                for p in low:
                    c=visual_content(pdf[p['page']-1])
                    if needs_ocr(p['text'],c):visual.append(dict(page=p['page'],**c))
        if not letters and not visual and row['firm_id']!='theori':continue
        result[sha]=dict(doc=doc,letter_pages=letters,visual_pages=visual)
        for ext in ('.txt','.pages.json'):
            source=ROOT/'local-cache/fulltext'/(sha+ext);target=LOCAL/'before_text'/(sha+ext)
            if source.exists() and not target.exists():
                target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
    write_json(LOCAL/'targets.json',result)
    print('Extraction targets',len(result),'letter-spaced',sum(bool(v['letter_pages']) for v in result.values()),
          'visual',sum(bool(v['visual_pages']) for v in result.values()),flush=True)


def rerun():
    from extract import extract_one
    from concurrent.futures import ProcessPoolExecutor,as_completed
    targets=json.loads((LOCAL/'targets.json').read_text());blocked=holdouts()
    existing={r['sha256']:r for r in map(json.loads,(ROOT/'data/fulltext/extractions.jsonl').read_text().splitlines())}
    # MuPDF does not support concurrent threads. Separate processes retain
    # each worker's own extraction lock and bound OCR memory/CPU usage.
    with ProcessPoolExecutor(max_workers=6) as pool:
        jobs={pool.submit(extract_one,(sha,d['doc']['row']),ROOT,blocked,retry=False):sha for sha,d in targets.items()}
        for i,future in enumerate(as_completed(jobs),1):
            result=future.result();existing[result['sha256']]=result
            print(i,len(jobs),result['sha256'][:12],result['status'],Counter(q['kind'] for q in result.get('issues',[])),flush=True)
    from common import write_jsonl
    write_jsonl(ROOT/'data/fulltext/extractions.jsonl',[existing[s] for s in sorted(existing)])
    write_json(LOCAL/'extraction_receipts.json',{s:existing[s] for s in targets})


def rerun_badges():
    """Re-extract wide-band pages after the initial sparse-page survey."""
    import fitz
    from extract import extract_one
    from concurrent.futures import ProcessPoolExecutor,as_completed
    from common import write_jsonl
    receipts=json.loads((LOCAL/'extraction_receipts.json').read_text())
    targets=json.loads((LOCAL/'targets.json').read_text());selected={}
    for sha,d in targets.items():
        pages=[q['page'] for q in receipts[sha].get('issues',[]) if q['kind']=='ocr_page']
        if not pages:continue
        row=d['doc']['row'];assert sha not in holdouts();path=original_path(row)
        assert digest(path.read_bytes())==sha
        with fitz.open(path) as pdf:
            if (row['firm_id']=='zokyo' and any(n>3 for n in pages)) or any(any(v.get('fill') and len(v['items'])<=12 and 240<v['rect'].width<pdf[n-1].rect.width*.96 and 6<v['rect'].height<35 for v in pdf[n-1].get_drawings()) for n in pages):
                selected[sha]=d
    print('Wide badge originals',len(selected),flush=True)
    index={r['sha256']:r for r in map(json.loads,(ROOT/'data/fulltext/extractions.jsonl').read_text().splitlines())}
    with ProcessPoolExecutor(max_workers=6) as pool:
        jobs=[pool.submit(extract_one,(sha,d['doc']['row']),ROOT,holdouts(),retry=True) for sha,d in selected.items()]
        for future in as_completed(jobs):
            r=future.result();receipts[r['sha256']]=r;index[r['sha256']]=r
            print(r['sha256'][:12],r['status'],flush=True)
    write_jsonl(ROOT/'data/fulltext/extractions.jsonl',[index[s] for s in sorted(index)])
    write_json(LOCAL/'extraction_receipts.json',receipts)
    write_json(LOCAL/'wide_badge_originals.json',sorted(selected))


def progress():
    targets=json.loads((LOCAL/'targets.json').read_text())
    done=set(re.findall(r'^\d+ \d+ ([0-9a-f]{12}) ',Path('local-cache/tmp/hard-rerun.log').read_text(),re.M))
    print('Completed',len(done),'of',len(targets))
    for sha,d in targets.items():
        if sha[:12] in done:continue
        path=LOCAL/'before_text'/(sha+'.pages.json')
        pages=len(json.loads(path.read_text())['pages']) if path.exists() else None
        print(sha[:12],d['doc']['row']['firm_id'],d['doc']['row'].get('title_hint'),'pages',pages)


def theori_cohort():
    # Reuse the official alias ledger without relabelling collected metadata.
    from parsers.test_variants_u import inputs as u_inputs
    from variants import dispatch
    import importlib.util
    source=LOCAL/'code_origin/parsers/theori.py'
    spec=importlib.util.spec_from_file_location('theori_before',source)
    old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    result=[];seen=set()
    for doc in u_inputs():
        if doc['row']['firm_id']!='theori' or doc['row']['sha256'] in seen:continue
        seen.add(doc['row']['sha256'])
        r=load(doc);before=dispatch(r,old.VARIANTS)
        before_count=len(before)
        r=load(doc);after=module('theori').parse(r)
        result.append(dict(sha256=doc['row']['sha256'],public_url=doc['row']['public_url'],
            stored_publisher=doc.get('source_publisher','theori'),variant=r.layout_selection['variant_id'],
            before=before_count,after=len(after),severity=dict(Counter(c.normalized for c in after)),
            disposition=getattr(r,'layout_disposition',None),
            rows=[dict(title=c.title,printed_id=c.printed_id,severity=c.normalized,start=c.start,end=c.end,status=c.normalized_status) for c in after]))
    write_json(ROOT/'data/findings/validation/theori_hard_layouts.json',dict(documents=result,holdouts_opened=0))
    print('Theori validation',[(r['sha256'][:12],r['before'],r['after'],r['variant']) for r in result],flush=True)


def regenerate(firms=FIRMS):
    finalize_extractions()
    rebase_badges()
    from run import main as run_main
    with patch.object(sys,'argv',['run.py','--firms',*firms]):run_main()
    # A crosswalk edit changes its fingerprint globally. Refresh unrelated
    # receipts only after asserting every existing semantic decision is equal.
    from severity_review import refresh_receipts
    refresh_receipts(ROOT)
    theori_cohort()
    stats=[]
    for path in sorted((ROOT/'data/findings/validation').glob('*.json')):
        value=json.loads(path.read_text())
        if isinstance(value,dict) and value.get('firm_id')==path.stem and 'findings' in value:stats.append(value)
    from common import VERSION
    write_json(ROOT/'data/findings/summary.json',dict(version=VERSION,by_firm=stats,
        findings=sum(s['findings'] for s in stats),documents=sum(s['documents'] for s in stats),holdouts_opened=0))


def preserve_prior_ocr():
    from extraction_normalization import merge_prior_ocr
    from common import write_jsonl
    targets=json.loads((LOCAL/'targets.json').read_text());changes=[]
    index={r['sha256']:r for r in map(json.loads,(ROOT/'data/fulltext/extractions.jsonl').read_text().splitlines())}
    receipts=json.loads((LOCAL/'extraction_receipts.json').read_text())
    for sha,d in targets.items():
        old_path=LOCAL/'before_text'/(sha+'.pages.json')
        if not old_path.exists():continue
        old=json.loads(old_path.read_text())
        pages={q['page'] for q in old.get('issues',[]) if q['kind'] in {'ocr_page','layout_triggered_ocr'}}
        if not pages:continue
        assert sha not in holdouts();r=load(d['doc']);assert digest((LOCAL/'before_text'/(sha+'.txt')).read_bytes())==old['text_sha256']
        path=ROOT/'local-cache/fulltext/normalization'/(sha+'.json')
        norm=json.loads(path.read_text()) if path.exists() else {};by_page={p['page']:p for p in norm.get('pages',[])}
        changed=[]
        for p in r.meta['pages']:
            if p['page'] not in pages:continue
            before=next(q['text'] for q in old['pages'] if q['page']==p['page'])
            if p['page'] in by_page and by_page[p['page']].get('words'):
                value=merge_prior_ocr(before,p['text'],by_page[p['page']])
                by_page[p['page']]['text_sha256']=digest(value.encode())
            else:value=before
            if value!=p['text']:changed.append(p['page'])
            p['text']=value
        start=0
        for p in r.meta['pages']:p['start']=start;p['end']=start+len(p['text']);start=p['end']+1
        payload='\f'.join(p['text'] for p in r.meta['pages'])
        r.meta['text_sha256']=digest(payload.encode());r.meta['characters']=len(payload)
        r.meta['prior_ocr_method']=old['method']
        represented={q['page'] for q in r.meta.get('issues',[]) if q['kind']=='ocr_page'}
        r.meta['issues']+= [dict(kind='ocr_page',page=n,reason='preserved_prior_ocr') for n in pages-represented]
        (ROOT/'local-cache/fulltext'/(sha+'.txt')).write_text(payload)
        write_json(ROOT/'local-cache/fulltext'/(sha+'.pages.json'),r.meta)
        if norm:write_json(path,norm)
        result={k:v for k,v in r.meta.items() if k not in {'pages','coordinate_system','structured','date_hint'}}
        result.update(text_path='local-cache/fulltext/'+sha+'.txt',pages_path='local-cache/fulltext/'+sha+'.pages.json')
        if sha in index:index[sha]=result
        receipts[sha]=result
        changes.append(dict(sha256=sha,pages=changed,prior_text_sha256=old['text_sha256'],text_sha256=r.meta['text_sha256']))
    write_jsonl(ROOT/'data/fulltext/extractions.jsonl',[index[s] for s in sorted(index)])
    write_json(LOCAL/'extraction_receipts.json',receipts);write_json(LOCAL/'prior_ocr_merges.json',changes)
    print('Preserved existing OCR',len(changes),'originals',flush=True)


def recover_legacy_badges():
    from parsers.test_variants_u import ocr_zokyo
    from concurrent.futures import ProcessPoolExecutor
    baseline=json.loads((LOCAL/'baseline.json').read_text())
    selected=[b['sha256'] for b in baseline.values() if b['firm']=='zokyo' and b['variant']=='zokyo/v2021_image_badges' and b['findings']]
    assert not set(selected)&holdouts()
    with ProcessPoolExecutor(max_workers=4) as pool:list(pool.map(ocr_zokyo,[s[:12] for s in selected]))
    write_json(LOCAL/'legacy_badges_refreshed.json',selected)


def finalize_extractions():
    from common import write_jsonl
    docs=read_snapshot();expected={d['row']['sha256'] for d in docs}
    path=ROOT/'data/fulltext/extractions.jsonl'
    rows=[r for r in map(json.loads,path.read_text().splitlines()) if r['sha256'] in expected]
    assert {r['sha256'] for r in rows}==expected
    write_jsonl(path,sorted(rows,key=lambda r:r['sha256']))
    write_jsonl(ROOT/'data/fulltext/failures.jsonl',[r for r in rows if r['status']!='ok'])
    index={r['sha256']:r for r in rows}
    counts=Counter(index[d['row']['sha256']]['status'] for d in docs)
    write_json(ROOT/'data/fulltext/summary.json',dict(documents=len(docs),unique_artifacts=len(rows),
        document_status={s:counts[s] for s in ('ok','partial','failed','pending')},
        fulltext_percent=round(100*counts['ok']/len(docs),4),
        text_cache_percent=round(100*(counts['ok']+counts['partial'])/len(docs),4),
        unique_status={s:sum(r['status']==s for r in rows) for s in ('ok','partial','failed','pending')},
        pages=sum(r.get('page_count',0) for r in rows),holdouts_opened=0))


def verify():
    from common import uid
    from core import severity_policy,severity_mapping
    docs={d['document_id']:d for d in inputs()};blocked=holdouts();checked=Counter();seen=set()
    policy_sha=severity_policy()[2];last=None;r=None
    inventory=json.loads((ROOT/'data/fulltext/inventory.json').read_text())
    assert digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes())==inventory['holdout_list_sha256']
    for firm in FIRMS:
        path=ROOT/'data/findings'/(firm+'.jsonl')
        if not path.exists():continue
        for line in path.open():
            row=json.loads(line);sha=row['sha256'];assert sha not in blocked
            assert row['finding_id'] not in seen;seen.add(row['finding_id'])
            assert row['finding_id']==uid('finding',row['source_tag'],row['source_record_id'])
            if last!=(firm,sha):r=load(docs[row['document_id']]);last=(firm,sha)
            start,end=row['body_span']['start'],row['body_span']['end']
            assert 0<=start<end<=len(r.text) and r.text[start:end]==row['body_text']
            assert row['body_span']['text_sha256']==r.meta['text_sha256']
            mapping=row['severity_mapping'];assert mapping['map_sha256']==policy_sha
            expect=severity_mapping(row['severity_original'],firm,era=mapping['era'],kind=(mapping.get('rule') or '').removeprefix('unrated_'),log=False)
            assert expect['normalized']==row['severity'] and expect['mapped']==mapping['mapped']
            proof=row['evidence'].get('status_evidence')
            if proof:assert r.text[proof['start']:proof['end']]==proof['text']==row['status_raw']
            for field in ('status_ocr_evidence','status_image_evidence'):
                proof=row['evidence'].get(field)
                if proof:
                    assert proof['original_sha256']==sha and proof['text_sha256']==r.meta['text_sha256']
                    span=proof['source_span'];assert r.text[span['start']:span['end']]==span['text']
            proof=row['evidence'].get('page_ocr_evidence')
            if proof:
                assert proof['original_sha256']==sha and proof['text_sha256']==r.meta['text_sha256']
                span=proof['source_span'];assert r.text[span['start']:span['end']]==span['text']
                path=ROOT/'local-cache/fulltext/normalization'/(sha+'.json')
                assert digest(path.read_bytes())==proof['receipt_sha256']
            checked[firm]+=1
    result=dict(ok=True,rows=dict(checked),holdouts_opened=0,holdout_list_sha256=digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes()))
    write_json(LOCAL/'verification.json',result);print(json.dumps(result,indent=2))


def report():
    baseline=json.loads((LOCAL/'baseline.json').read_text());after=census(staged=True)
    after={k:v for k,v in after.items() if k in baseline}
    targets=json.loads((LOCAL/'targets.json').read_text())
    extraction=json.loads((LOCAL/'extraction_receipts.json').read_text())
    classes={
        'Letter-spaced native pages':{k for k,b in baseline.items() if targets.get(b['sha256'],{}).get('letter_pages')},
        'ChainSecurity Note cards':{k for k,b in baseline.items() if b['firm']=='chainsecurity' and b['classes']['note']},
        'ChainSecurity legacy grades/cards':{k for k,b in baseline.items() if b['firm']=='chainsecurity' and b['variant'] in ('chainsecurity/v2018_risk_codes','chainsecurity/v2018_classification')},
        'Sparse vector/image pages and OCR badges':{k for k,b in baseline.items() if any(q['kind']=='ocr_page' for q in extraction.get(b['sha256'],{}).get('issues',[]))},
        'Kudelski title before Finding ID':{k for k,b in baseline.items() if b['classes']['title_first']},
    }
    metrics=[]
    for name,keys in classes.items():
        assert keys<=after.keys()
        metrics.append(dict(failure_class=name,documents=len(keys),
            before=sum(baseline[k]['findings'] for k in keys),after=sum(after[k]['findings'] for k in keys),
            count_changed=sum(baseline[k]['findings']!=after[k]['findings'] for k in keys),
            originals=sorted(keys)))
    cohort=json.loads((ROOT/'data/findings/validation/theori_hard_layouts.json').read_text())['documents']
    metrics.append(dict(failure_class='Theori current collection and official aliases',documents=len(cohort),
                        before=sum(c['before'] for c in cohort),after=sum(c['after'] for c in cohort),
                        count_changed=sum(c['before']!=c['after'] for c in cohort)))
    changed=[dict(firm=b['firm'],sha256=b['sha256'],public_url=b['public_url'],before=b['findings'],after=after[k]['findings'],
                  variant_before=b['variant'],variant_after=after[k]['variant']) for k,b in baseline.items()
             if k in after and (b['findings']!=after[k]['findings'] or b['variant']!=after[k]['variant'])]
    receipt=dict(classes=metrics,unique_original_publisher_pairs=len(baseline),
        before=sum(b['findings'] for b in baseline.values()),after=sum(b['findings'] for b in after.values()),
        documents_count_changed=sum(baseline[k]['findings']!=v['findings'] for k,v in after.items()),
        documents=changed,holdouts_opened=0,holdout_list_sha256=digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes()))
    legacy=classes['ChainSecurity legacy grades/cards']
    receipt['legacy_unknown_before']=sum(baseline[k]['severity'].get('unknown',0) for k in legacy)
    receipt['legacy_unknown_after']=sum(after[k]['severity'].get('unknown',0) for k in legacy)
    dispositions=[]
    for doc in inputs():
        key=doc['row']['firm_id']+':'+doc['row']['sha256']
        if key not in legacy:continue
        r=load(doc);module(r.firm).parse(r)
        if getattr(r,'layout_disposition',{}).get('excluded'):
            dispositions.append(dict(sha256=doc['row']['sha256'],**r.layout_disposition))
    receipt['legacy_disposition_exclusions']=dispositions
    scoped=json.loads((LOCAL/'verification.json').read_text())
    global_check=json.loads((ROOT/'data/findings/check.json').read_text())
    final_tests=Path('local-cache/tmp/hard-final-tests.log')
    passed=re.search(r'(\d+) passed, (\d+) subtests passed',final_tests.read_text()) if final_tests.exists() else None
    receipt['validation']=dict(scoped_ok=scoped['ok'],global_ok=global_check['ok'],
        tests=int(passed[1]) if passed else None,subtests=int(passed[2]) if passed else None)
    write_json(ROOT/'data/findings/validation/hard_layouts.json',receipt)
    lines=['# Phase 4 hard layouts','',
        'Generated by `scripts/findings/parsers/test_hard_layouts.py --report`. Evidence inspected locally on 2026-10-21; no network or model calls. Holdouts are filtered before original, cached text, rendering or OCR access. The holdout-list fingerprint is checked against the frozen extraction inventory.','',
        'Documents below are unique (publisher, original SHA-256) pairs with verified readable development text. Counts include emitted entries of every kind; they are extraction counts, not unique vulnerabilities. Classes overlap and must not be added together. Before counts are the immutable pre-change staged per-document diagnostics in `local-cache/phase4-hard-layouts/baseline.json`; new Theori documents and aliases use the frozen pre-change Theori parser. Original input metadata and the frozen extraction snapshot are unchanged.','',
        '| Failure class | Affected corpus documents | Findings before | Findings after | Documents with count changes |',
        '|---|---:|---:|---:|---:|']
    for m in metrics:lines.append(f"| {m['failure_class']} | {m['documents']} | {m['before']} | {m['after']} | {m['count_changed']} |")
    lines+=['',f"Across the measured development cohort: {receipt['before']} → {receipt['after']} entries; {receipt['documents_count_changed']} documents change count. Normalization, native IDs, clean titles, grades and dispositions can improve without changing counts.",
        f"Legacy ChainSecurity formal entries with unknown severity: {receipt['legacy_unknown_before']} → {receipt['legacy_unknown_after']}. Their single-letter labels are now resolved through the cited publisher scale.",'',
        '## Repairs and evidence','',
        '- Letter spacing: detect predominantly single-glyph tokens on each page, then reconstruct painted native glyph advances, deduplicating identical paint passes. Preserve real word and column gaps. The repaired text and its page offsets/hash are written before fingerprinting. The parser also accepts a single recovered gap before the badge. Example: [OtterSec Wormhole](https://osec.io/reports/d4a11ab1-28e4-44ee-a4eb-102b5da315a6), PDF page 7; its title becomes “Custody Token Account Closing DoS”. Native text hashes and page receipts remain under `local-cache/fulltext/normalization/`.','',
        '- Notes: ChainSecurity-local grammar and fingerprints accept `Note Version N`, including note-only documents and wrapped headings. The publisher explicitly says Notes clarify/support the report, require no immediate project modification, and raise awareness. `Note → info` is recorded with the verbatim definition in the YAML crosswalk and identical-content JSON export. Citation: [1inch Limit Order Settlement](https://www.chainsecurity.com/reports/1inch/ChainSecurity_1inch_1inchLimitOrderSettlement_Audit.pdf), PDF page 20.','',
        '- Legacy ChainSecurity: retain single-letter grades, numeric/roman native identifiers and Trust/Design section context, and read printed dispositions. Explicit No Issue dispositions are excluded with source spans. The publisher defines L/M/H on PDF page 7 and C on page 8 of [Republic Protocol](https://www.chainsecurity.com/reports/REPUBLICPROTOCOL/ChainSecurity_REPUBLICPROTOCOL_REPUBLICPROTOCOLs_Audit.pdf); these aliases are cited in the same crosswalk.','',
        '- Vector/images: inspect each sparse page for image area, small glyph paths and path primitives (outlined words may be batched in one path). OCR those pages individually; merge spatial words from ordinary and sparse OCR, preserve row/column gaps, and OCR tight colored badge cells. Receipts retain render hashes, pixel/point boxes, text, confidence and crop hashes. [Zokyo Gumball](https://github.com/zokyo-sec/audit-reports/blob/39b9e51ac1b68a42ac03b222167760f7035bf16e/Gumball/Gumball_Zokyo%20audit%20report.pdf) supplies a live finding-card example with no usable native text. Short OCR icon noise fused to a complete risk badge is accepted only on an OCR-backed analysis page. A certificate such as [EMR](https://certificate.quantstamp.com/full/emaar.pdf) remains summary-only; its printed totals never manufacture detailed findings.','',
        '- Kudelski: bind a `Finding ID:` field to the immediately preceding title block, retain wrapped/unnumbered titles and native IDs, and bound its metadata before the description. This also avoids duplicate numeric-title cards and retains bracketed statuses. Example: [Marinade assessment](https://kudelskisecurity.com/blockchain-archive/crypto-digital-asset-assessment), PDF page 13.','',
        '- Theori: validate the new collection and eligible official ChainLight aliases without changing stored attribution. The vertical Issue-card grammar requires explicit Summary/Severity metadata, supports wrapped titles and Fixed (grade) cells, stops at the next card, and cannot take a grade from summary prose. The Qubit original is a holdout and was not opened: the Qubit-style vertical/fragmented table structure is exercised by synthetic regressions; live eligible Issue/THE examples are listed below. The bilingual variant still has no new eligible Theori live example.','',
        '| Theori validation original | Stored publisher | Variant | Before | After |',
        '|---|---|---|---:|---:|']
    for c in cohort:lines.append(f"| [{c['sha256'][:12]}]({c['public_url']}) | {c['stored_publisher']} | {c['variant']} | {c['before']} | {c['after']} |")
    lines+=['','## Shared changes and validation','',
        'Shared implementation changes are limited to `extract.py` and the new `extraction_normalization.py`: page repair, OCR receipts, and a normalization-version cache marker. Markdown/HTML extraction and parser APIs remain unchanged. Severity-policy changes are limited to ChainSecurity in `schema/severity_map.yaml` and its JSON export. No shared severity grammar, resolver, layout dispatcher, SQL schema or collection policy was changed. Other publishers’ staged severity receipts receive the new crosswalk fingerprint only after asserting identical normalization, mapped state, era and rule.','',
        'Existing OCR text and table/card structure are preserved. Fresh badges can fill missing status or add a badge only beside a uniquely matching existing title; existing grades and IDs are retained. A sparse letter-spaced footer cannot suppress OCR of a raster body. Existing Zokyo image evidence is rebased only across byte-identical finding pages, with every source span rechecked; changed finding pages require fresh OCR. Native and image-backed cards can coexist in one report, without duplicate cards. Originals and provenance metadata are preserved. Newly collected Theori stays a separate validation cohort, as in Phase 4e-U; it is not appended to the frozen extraction snapshot.','',
        'Reproduce (use the existing PDF environment):','',
        '```sh','python3 -I scripts/findings/parsers/test_hard_layouts.py',
        '# Initial baseline/target preparation only; freeze refuses replacement:',
        'python3 -I -S scripts/findings/parsers/test_hard_layouts.py --freeze',
        'python3 -I scripts/findings/parsers/test_hard_layouts.py --prepare',
        'python3 -I scripts/findings/parsers/test_hard_layouts.py --rerun',
        'python3 -I scripts/findings/parsers/test_hard_layouts.py --rerun-badges',
        'python3 -I -S scripts/findings/parsers/test_hard_layouts.py --preserve-ocr',
        'python3 -I -S scripts/findings/parsers/test_hard_layouts.py --recover-legacy-badges',
        'python3 -I -S scripts/findings/parsers/test_hard_layouts.py --regenerate',
        'python3 -I -S scripts/findings/parsers/test_hard_layouts.py --verify',
        'python3 -I -S scripts/findings/parsers/test_hard_layouts.py --report','```','',
        f"Validation: scoped identity/span/severity/OCR-evidence checks pass; the complete findings integrity checker passes. The final suite passes {receipt['validation']['tests']} tests and {receipt['validation']['subtests']} subtests. Holdout-list identity is unchanged.",'',
        'The regression suite includes real raster and vector-only PDF cards through extraction, fingerprinting and parsing. Per-document changes and class membership are in `data/findings/validation/hard_layouts.json`; local pre-change text, glyph/OCR evidence, extraction receipts and verification receipts are preserved under `local-cache/phase4-hard-layouts/`. Findings and validation outputs have been regenerated for the affected publishers. All citation access dates above are 2026-10-21.','']
    lines+=['Complete written-file list: [hard_layouts_files_written.txt](../../data/findings/validation/hard_layouts_files_written.txt).','']
    (ROOT/'docs/phase4/hard_layouts.md').write_text('\n'.join(lines))
    print(json.dumps({k:v for k,v in receipt.items() if k!='documents'},indent=2))


def manifest():
    sources=['scripts/findings/parsers/test_hard_layouts.py','scripts/findings/extraction_normalization.py',
        'scripts/findings/extract.py','scripts/findings/parsers/chainsecurity.py','scripts/findings/parsers/kudelski_security.py',
        'scripts/findings/parsers/theori.py','scripts/findings/parsers/ottersec.py','scripts/findings/parsers/zokyo.py',
        'scripts/findings/test_variants.py','scripts/findings/parsers/fixtures/zokyo_reviewed_badges.json',
        'schema/severity_map.yaml','schema/severity_map.json','docs/phase4/hard_layouts.md',
        'data/fulltext/extractions.jsonl','data/fulltext/failures.jsonl','data/fulltext/summary.json',
        'data/findings/summary.json','data/findings/check.json','data/findings/_unknown_layouts.jsonl',
        'data/findings/validation/hard_layouts.json','data/findings/validation/theori_hard_layouts.json',
        'data/findings/validation/hard_layouts_files_written.txt']
    paths={ROOT/p for p in sources}
    paths.update(p for p in (ROOT/'data/findings').glob('*.jsonl') if not p.name.startswith('_'))
    for firm in FIRMS:
        paths.update(p for p in (ROOT/'data/findings/validation').glob(firm+'.*') if p.suffix in ('.json','.jsonl'))
    targets=json.loads((LOCAL/'targets.json').read_text())
    for sha in targets:
        paths.update(ROOT/'local-cache/fulltext'/(sha+ext) for ext in ('.txt','.pages.json'))
        p=ROOT/'local-cache/fulltext/normalization'/(sha+'.json')
        if p.exists():paths.add(p)
    for item in json.loads((LOCAL/'badge_rebase.json').read_text()):
        paths.add(ROOT/'local-cache/phase4e-u/zokyo_badges'/(item['sha256']+'.json'))
    recovered=LOCAL/'legacy_badges_refreshed.json'
    if recovered.exists():
        for sha in json.loads(recovered.read_text()):
            paths.add(ROOT/'local-cache/phase4e-u/zokyo_badges'/(sha+'.json'))
            paths.update(p for p in (ROOT/'local-cache/phase4e-u/ocr'/sha).rglob('*') if p.is_file())
    paths.update(p for p in LOCAL.rglob('*') if p.is_file())
    # Terminal captures are local-only and included for the complete receipt.
    paths.update(Path('/tmp').glob('hard-*.log'));paths.update(Path('/tmp').glob('hard-*.txt'))
    output=ROOT/'data/findings/validation/hard_layouts_files_written.txt'
    output.write_text('\n'.join(sorted(str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p) for p in paths if p.exists() or p==output))+'\n')
    print(output)


def changes():
    data=json.loads((ROOT/'data/findings/validation/hard_layouts.json').read_text())
    for d in sorted(data['documents'],key=lambda d:d['after']-d['before'])[:20]:
        path=LOCAL/'before_text'/(d['sha256']+'.pages.json')
        old=json.loads(path.read_text()) if path.exists() else {}
        print(d['firm'],d['sha256'][:12],d['before'],d['after'],d['variant_before'],d['variant_after'],
              old.get('method'),Counter(q['kind'] for q in old.get('issues',[])))


def rebase_badges():
    """Keep image evidence only when its complete anchored page is unchanged.

    A cover repair moves later offsets; it does not invalidate a reviewed
    image on a byte-identical finding page. Changed finding pages must be read
    again, never accepted by merely swapping a text hash.
    """
    import copy
    targets=json.loads((LOCAL/'targets.json').read_text())
    proof_path=LOCAL/'badge_rebase.json'
    proofs=json.loads(proof_path.read_text()) if proof_path.exists() else []
    fixture=ROOT/'scripts/findings/parsers/fixtures/zokyo_reviewed_badges.json'
    reviewed=json.loads(fixture.read_text());fixture_changed=False
    for sha,d in targets.items():
        if d['doc']['row']['firm_id']!='zokyo':continue
        before_path=LOCAL/'before_text'/(sha+'.pages.json')
        if not before_path.exists():continue
        before=json.loads(before_path.read_text());r=load(d['doc'])
        if before['text_sha256']==r.meta['text_sha256']:continue
        old={p['page']:p for p in before['pages']};new={p['page']:p for p in r.meta['pages']}
        def rebase(claim):
            if claim.get('text_sha256')!=before['text_sha256']:return None
            value=copy.deepcopy(claim)
            def shift(obj):
                if isinstance(obj,dict):
                    if 'start' in obj and 'end' in obj:
                        p=next((p for p in old.values() if p['start']<=obj['start']<obj['end']<=p['end']),None)
                        if p is None or p['text']!=new[p['page']]['text']:raise ValueError('changed anchor page')
                        delta=new[p['page']]['start']-p['start'];obj['start']+=delta;obj['end']+=delta
                        if 'text' in obj:assert r.text[obj['start']:obj['end']]==obj['text']
                    if 'card_start' in obj:
                        p=next((p for p in old.values() if p['start']<=obj['card_start']<p['end']),None)
                        if p is None or p['text']!=new[p['page']]['text']:raise ValueError('changed card page')
                        obj['card_start']+=new[p['page']]['start']-p['start']
                    if 'text_sha256' in obj:obj['text_sha256']=r.meta['text_sha256']
                    for child in obj.values():shift(child)
                elif isinstance(obj,list):
                    for child in obj:shift(child)
            try:shift(value)
            except ValueError:return None
            return value
        path=ROOT/'local-cache/phase4e-u/zokyo_badges'/(sha+'.json')
        if path.exists():
            data=json.loads(path.read_text())
            if data.get('text_sha256')==before['text_sha256']:
                claims=[v for c in data.get('claims',[]) if (v:=rebase(c)) is not None]
                proofs.append(dict(sha256=sha,original_claims=len(data.get('claims',[])),rebased_claims=len(claims)))
                data['reader_version']='u-badges-v2' if len(claims)==len(data.get('claims',[])) else 'hard-layouts-rebased-partial'
                data['claims']=claims;data['text_sha256']=r.meta['text_sha256'];write_json(path,data)
        for i,claim in enumerate(reviewed['claims']):
            if claim.get('sha256')!=sha:continue
            value=rebase(claim)
            if value is not None:reviewed['claims'][i]=value;fixture_changed=True
    if fixture_changed:write_json(fixture,reviewed)
    write_json(LOCAL/'badge_rebase.json',proofs)


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',action='store_true');p.add_argument('--survey',action='store_true')
    p.add_argument('--freeze',action='store_true')
    p.add_argument('--inspect');p.add_argument('--page',type=int);p.add_argument('--render',action='store_true')
    p.add_argument('--search',nargs=2);p.add_argument('--sparse',action='store_true')
    p.add_argument('--preview')
    p.add_argument('--native',action='store_true');p.add_argument('--metadata',action='store_true')
    p.add_argument('--policy',action='store_true');p.add_argument('--prepare',action='store_true');p.add_argument('--rerun',action='store_true')
    p.add_argument('--regenerate',action='store_true');p.add_argument('--theori',action='store_true')
    p.add_argument('--verify',action='store_true');p.add_argument('--report',action='store_true')
    p.add_argument('--rerun-badges',action='store_true')
    p.add_argument('--progress',action='store_true')
    p.add_argument('--manifest',action='store_true')
    p.add_argument('--changes',action='store_true')
    p.add_argument('--preserve-ocr',action='store_true')
    p.add_argument('--regenerate-zokyo',action='store_true')
    p.add_argument('--recover-legacy-badges',action='store_true')
    a=p.parse_args()
    if a.capture: capture()
    elif a.freeze: freeze()
    elif a.survey: survey()
    elif a.inspect: inspect(a.inspect,a.page,a.render,a.native)
    elif a.search: search(*a.search)
    elif a.preview: preview(a.preview)
    elif a.sparse: sparse()
    elif a.metadata: metadata()
    elif a.policy: policy()
    elif a.prepare: prepare()
    elif a.rerun: rerun()
    elif a.regenerate: regenerate()
    elif a.theori: theori_cohort()
    elif a.verify: verify()
    elif a.report: report()
    elif a.rerun_badges: rerun_badges()
    elif a.progress: progress()
    elif a.manifest: manifest()
    elif a.changes: changes()
    elif a.preserve_ocr: preserve_prior_ocr()
    elif a.regenerate_zokyo: regenerate(('zokyo',))
    elif a.recover_legacy_badges: recover_legacy_badges()
    else: unittest.main(argv=[sys.argv[0]])
