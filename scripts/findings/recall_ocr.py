"""Recover omitted Zokyo badges on development finding pages, with image receipts.

No cache text is rewritten. Claims require a uniquely matching existing title,
an OCR grade, and retained render/crop hashes. Native badge labels take priority.
"""
from concurrent.futures import ProcessPoolExecutor
from difflib import SequenceMatcher
import argparse
import json
from pathlib import Path
import re
import subprocess
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, holdouts, original_path, write_json
from recall_push import LOCAL, inputs, load
from extract import tool, tool_environment
from parsers import zokyo

# Labels read from the retained rendered badge, never inferred from a gap or
# summary. Keep the rejected OCR reading and render digest in the exported claim.
VISUAL_ID_REVIEWS=(
    ('120cd202dbd0',36,'Disqualification mechanism should be verified.','INFO-10'),
    ('120cd202dbd0',40,'Event is never used.','INFO-15'),
    ('6a58f565da3b',22,'Violations of Solidity Style Guide Conventions - magic numbers.','INFORMATIONAL-10.2'),
    ('8e46ba73aec2',31,'Typos and Incorrect comment','INFORMATIONAL-12'),
    ('f00cfcd3386e',29,'Fee value might exceed denominator.','LOW-5'),
)
VISUAL_TITLE_REVIEWS=(
    ('f00cfcd3386e',30,'Unlimited allowance.','INFO-2'),
    ('f00cfcd3386e',33,'Typos.','INFO-8'),
    ('f00cfcd3386e',35,'Possible frontrun attack.','HIGH-2'),
    ('f00cfcd3386e',37,'Variables lack validation.','LOW-1'),
)
VISUAL_ADDITIONAL_CARDS=(
    ('f00cfcd3386e',37,'Variables lack validation.','LOW-1','LOW',
     '74bc1cb27baae836ae1665fe85de6d0b30585e70486369d106bb864076422f36'),
)


def key(s): return re.sub(r'[^a-z0-9]', '', s.casefold())


def prepare():
    baseline = json.loads((LOCAL / 'before.json').read_text())['documents']
    if (LOCAL/'after.json').exists():baseline += json.loads((LOCAL/'after.json').read_text())['documents']
    flagged = {d['sha256'] for d in baseline if d['firm'] == 'zokyo' and
               any(d.get(k) for k in ('id_gaps', 'below_printed_summary', 'zero_finding_audit'))}
    seen = set(); jobs = []
    for doc in inputs():
        sha = doc['row']['sha256']
        if sha not in flagged or sha in seen: continue
        seen.add(sha); r = load(doc)
        if re.search(r'VULNERABILITIES DETAILS AND MITIGATIONS', r.text, re.I): continue
        start, end = zokyo._region(r)
        cards, _ = zokyo._cards(r)
        for page in r.meta['pages']:
            if page['end'] <= start or page['start'] >= end: continue
            present = [m for i, m in cards if r.lines[i].page == page['page']]
            # Repeated Recommendation blocks are an independent signal for
            # omitted detail headers. No summary totals create OCR claims.
            needed = len(re.findall(r'(?:^|\n)\s*Recommendations?\s*[.:]?\s*(?:\n|$)', page['text'], re.I))
            # Long findings can put their heading on one page and the first
            # Recommendation on the next. Census every analysis page of a
            # flagged report, rather than requiring both on one page.
            jobs.append((doc, page['page']))
    write_json(LOCAL / 'ocr_jobs.json', jobs)
    print('OCR finding pages:', len(jobs), flush=True)


def process(job):
    import fitz
    doc, number = job; sha = doc['row']['sha256']
    assert sha not in holdouts()
    r = load(doc); page = next(p for p in r.meta['pages'] if p['page'] == number)
    folder = LOCAL / 'ocr' / sha; folder.mkdir(parents=True, exist_ok=True)
    receipt = folder / f'{number}.json'
    if receipt.exists():
        saved = json.loads(receipt.read_text())
        if saved['text_sha256'] == r.meta['text_sha256'] and saved.get('reader_version') == 4: return saved
    original = original_path(doc['row']); assert digest(original.read_bytes()) == sha
    render = folder / f'{number}.png'
    if render.exists():pix=fitz.Pixmap(str(render))
    else:
        with fitz.open(original) as pdf:
            pix = pdf[number-1].get_pixmap(matrix=fitz.Matrix(160/72, 160/72), alpha=False)
            pix.save(render)
    w, h, data = pix.width, pix.height, pix.samples
    active = []
    for y in range(h):
        sample = [data[(y*w+x)*3:(y*w+x)*3+3] for x in range(w//10, 9*w//10, max(1, w//100))]
        if sum(max(p)>220 for p in sample)/len(sample)>.78: active.append(y)
    bands = []
    for y in active:
        if bands and y == bands[-1][-1]+1: bands[-1].append(y)
        else: bands.append([y])
    bands = [b for b in bands if 15 <= len(b) <= 160 and b[0] < h*.85]
    merged = []
    for b in bands:
        if merged and b[0]-merged[-1][-1] <= 45 and b[-1]-merged[-1][0] <= 160: merged[-1] += b
        else: merged.append(b)
    def ocr(box, tag, psm, threshold=False):
        x0,y0,x1,y1 = box
        pixels = b''.join(data[(y*w+x0)*3:(y*w+x1)*3] for y in range(y0,y1))
        if threshold:
            pixels = b''.join(bytes([0 if max(pixels[j:j+3]) < 220 else 255])*3
                              for j in range(0,len(pixels),3))
        path = folder / f'{number}-{tag}.ppm'
        path.write_bytes(f'P6\n{x1-x0} {y1-y0}\n255\n'.encode()+pixels)
        result = subprocess.run([tool('tesseract',ROOT), str(path), 'stdout', '-l', 'eng', '--psm', str(psm)],
            env=tool_environment(ROOT), capture_output=True, check=True, timeout=60)
        return result.stdout.decode(), digest(path.read_bytes())
    claims = []; reviews = []
    for i, b in enumerate(merged):
        x0=w//15; y0=max(0,b[0]-4); y1=min(h,b[-1]+5); x1=3*w//5
        badge, crop_sha = ocr([x0,y0,x1,y1], f'{i}-band', 7, True)
        risk = re.search(r'\b('+zokyo.RISK+r')(?:\s*[-–]\s*(\d+(?:\.\d+)*))?\b',badge,re.I)
        if not risk: continue
        state = re.search(r'\b('+zokyo.STATUS+r')\b',badge,re.I)
        title, title_sha = ocr([x0,y1,19*w//20,min(h,y1+165)], f'{i}-title', 6)
        title = title.strip().split('\n\n')[0]
        title_lines=[s.strip() for s in title.splitlines() if s.strip()]
        title_options=[' '.join(title_lines[:n]) for n in range(1,min(3,len(title_lines))+1)]
        choices = []
        for line in r.lines:
            if line.page != number or len(key(line.content)) < 14: continue
            if re.search(r'Smart Contract|Recommendation|Post-audit',line.content,re.I): continue
            score = max((SequenceMatcher(None,key(t)[:140],key(line.content)).ratio() for t in title_options),default=0)
            choices.append((score,line))
        choices.sort(key=lambda pair:pair[0],reverse=True)
        score, line = choices[0] if choices else (0,None)
        proof = dict(original_sha256=sha,text_sha256=r.meta['text_sha256'],page=number,
            render_sha256=digest(render.read_bytes()),image_sha256=crop_sha,title_image_sha256=title_sha,
            pixel_box=[x0,y0,x1,y1],engine='tesseract-eng-psm7',ocr_text=badge,title_ocr=title,
            risk_raw=risk[1],status_raw=state[1] if state else None,
            printed_id=risk[1]+'-'+risk[2] if risk[2] else None,title_match_score=round(score,4),
            review_method='recall_badge_ocr')
        if line is None or score < .65 or len(choices)>1 and score-choices[1][0]<.08:
            reviews.append(proof | {'reason':'ambiguous_title'}); continue
        span=dict(start=line.start,end=line.end,text=r.text[line.start:line.end])
        claims.append(proof | dict(card_start=line.start,source_span=span,title_span=span,
                                  association='unique_source_title_similarity'))
    result = dict(reader_version=4,sha256=sha,page=number,text_sha256=r.meta['text_sha256'],claims=claims,review=reviews)
    write_json(receipt,result)
    print('OCR',sha[:12],number,'claims',len(claims),'review',len(reviews),flush=True)
    return result


def run(workers):
    jobs=json.loads((LOCAL / 'ocr_jobs.json').read_text())
    with ProcessPoolExecutor(max_workers=workers) as pool: rows=list(pool.map(process,jobs))
    grouped={}
    for row in rows:
        group=grouped.setdefault(row['sha256'],dict(sha256=row['sha256'],text_sha256=row['text_sha256'],claims=[],review=[]))
        group['claims']+=row['claims'];group['review']+=row['review']
    for sha,row in grouped.items():write_json(LOCAL/'badges'/(sha+'.json'),row)


def export():
    docs={d['row']['sha256']:d for d in inputs() if d['row']['firm_id']=='zokyo'}
    claims=[]
    for path in sorted((LOCAL/'badges').glob('*.json')):
        row=json.loads(path.read_text());r=load(docs[row['sha256']])
        assert row['text_sha256']==r.meta['text_sha256']
        candidates=[(c,False) for c in row['claims']]+[(c,True) for c in row['review'] if c.get('reason')=='ambiguous_title']
        for claim,review in candidates:
            # A unique exact first title line outranks a matching longer crop
            # that also includes a file-location or narrative line.
            first=next((s.strip() for s in claim.get('title_ocr','').splitlines() if s.strip()),'')
            exact=[l for l in r.lines if l.page==claim['page'] and key(l.content)==key(first) and len(key(first))>=14]
            visual=next(((title,pid) for prefix,page,title,pid in VISUAL_TITLE_REVIEWS
                if row['sha256'].startswith(prefix) and claim['page']==page and key(title) in key(claim.get('title_ocr',''))),None)
            if visual:
                matches=[l for l in r.lines if l.page==claim['page'] and key(l.content)==key(visual[0])]
                assert matches,'Reviewed source title missing'
                exact=[matches[0]]
                claim=claim|dict(ocr_id_before_visual_review=claim.get('printed_id'),printed_id=visual[1],
                    review_method='recall_badge_visual_review',visual_review_basis='Rendered badge/title association; first exact source heading precedes its repeated narrative text')
            if len(exact)==1:
                line=exact[0];span=dict(start=line.start,end=line.end,text=r.text[line.start:line.end])
                claim=claim|dict(card_start=line.start,source_span=span,title_span=span,
                    association='unique_exact_first_title_line',title_match_score=1.0)
            elif review:continue
            assert claim['original_sha256']==row['sha256']
            for k in ('source_span','title_span'):
                span=claim[k];assert r.text[span['start']:span['end']]==span['text']
            claim=claim|{'sha256':row['sha256']}
            for prefix,page,title,pid in VISUAL_ID_REVIEWS:
                if row['sha256'].startswith(prefix) and claim['page']==page and claim['title_span']['text']==title:
                    claim.update(ocr_id_before_visual_review=claim['printed_id'],printed_id=pid,
                        review_method='recall_badge_visual_review',visual_review_basis='Printed ID read on the retained page render; no sequence-based inference')
            claims.append(claim)
        for prefix,page,title,pid,risk,render_sha in VISUAL_ADDITIONAL_CARDS:
            if not row['sha256'].startswith(prefix):continue
            render=LOCAL/'ocr'/row['sha256']/(str(page)+'.png');payload=render.read_bytes()
            assert digest(payload)==render_sha,'Visually reviewed render changed'
            line=next(l for l in r.lines if l.page==page and l.content==title)
            span=dict(start=line.start,end=line.end,text=r.text[line.start:line.end])
            width,height=struct.unpack('>II',payload[16:24])
            claims.append(dict(sha256=row['sha256'],original_sha256=row['sha256'],text_sha256=r.meta['text_sha256'],
                page=page,card_start=line.start,source_span=span,title_span=span,risk_raw=risk,printed_id=pid,status_raw='Resolved',
                render_sha256=render_sha,image_sha256=render_sha,title_image_sha256=render_sha,pixel_box=[0,0,width,height],
                engine='visual-review-of-retained-render',ocr_text='',title_ocr='',title_match_score=1.0,
                review_method='recall_badge_visual_review',association='visually_read_badge_and_exact_source_title',
                visual_review_basis='The rendered LOW-1 badge is clear; strip OCR did not decode it. No sequence inference.'))
    claims=list({(c['sha256'],c['card_start']):c for c in claims}.values())
    claims.sort(key=lambda c:(c['sha256'],c['card_start']))
    write_json(ROOT/'scripts/findings/parsers/fixtures/recall_zokyo_badges.json',
        dict(reader_version=4,holdouts_opened=0,claims=claims))
    print('Exported OCR badge claims:',len(claims),'documents:',len({c['sha256'] for c in claims}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--prepare',action='store_true');p.add_argument('--export',action='store_true');p.add_argument('--workers',type=int,default=4)
    a=p.parse_args()
    if a.prepare:prepare()
    elif a.export:export()
    else:run(a.workers)
