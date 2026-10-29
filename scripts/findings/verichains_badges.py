"""Recover outlined Verichains severity words from the existing original PDF.

Only the strip beside a uniquely located native finding ID is OCRed. No colors,
finding totals, descriptions, or impact estimates decide a risk. Missing,
conflicting and unrecognized OCR words fail closed. Original/text bytes and
finding coordinates never change. Caches are bound to original/text hashes.
"""
from __future__ import annotations
import json
from pathlib import Path
import re
import subprocess
import tempfile
from common import ROOT, digest, holdouts, write_json

VERSION='verichains-outlined-badge-v2'
RISK=re.compile(r'\b(?:VERY\s+LOW|INFORMATIONAL|INFORMATIVE|CRITICAL|MEDIUM|HIGH|LOW|INFO)\b',re.I)


def cache_path(sha):
    return ROOT/'local-cache/fulltext/field-evidence'/f'{sha}.json'


def build(report, candidates):
    import fitz
    from extract import tool, tool_environment
    sha=report.meta.get('sha256')
    if not sha or sha in holdouts():raise ValueError('Missing source hash or holdout badge access')
    original=ROOT/'local-cache/originals'/sha[:2]/f'{sha}.pdf'
    payload=original.read_bytes()
    if digest(payload)!=sha:raise ValueError('Original hash mismatch')
    records={}
    old_path=cache_path(sha)
    previous=json.loads(old_path.read_text()) if old_path.exists() else {}
    with fitz.open(stream=payload,filetype='pdf') as pdf, tempfile.TemporaryDirectory(prefix='field-badge-') as tmp:
        for c in candidates:
            if c.severity_raw or not c.printed_id:continue
            prior=previous.get('records',{}).get(str(c.start),{})
            if prior.get('accepted') and previous.get('text_sha256')==report.meta['text_sha256']:
                records[str(c.start)]=prior;continue
            pages=[p for p in report.meta['pages'] if p['start']<=c.start<p['end']]
            if len(pages)!=1:continue
            number=pages[0]['page']; page=pdf[number-1]
            matches=[]
            for block in page.get_text('dict')['blocks']:
                for line in block.get('lines',[]):
                    text=''.join(s['text'] for s in line['spans']).strip()
                    if re.match(r'^'+re.escape(c.printed_id)+r'\.?\s',text):matches.append(line)
            if len(matches)!=1:
                records[str(c.start)]={'accepted':False,'reason':'native_id_not_unique_on_page','page':number}
                continue
            line=matches[0];x0,y0,x1,y1=line['bbox']
            # The badge can precede or follow a wrapped title. Restrict OCR to
            # the heading strip, not the issue narrative beneath it.
            rect=fitz.Rect(max(0,x0-3),max(0,y0-3),page.rect.width-30,min(page.rect.height,y1+20))
            pix=page.get_pixmap(matrix=fitz.Matrix(3,3),clip=rect)
            path=Path(tmp)/'strip.png';pix.save(path)
            run=subprocess.run([tool('tesseract',ROOT),str(path),'stdout','-l','eng','--psm','6','tsv'],
                env=tool_environment(ROOT),capture_output=True,timeout=60,check=True)
            import csv,io
            words=list(csv.DictReader(io.StringIO(run.stdout.decode()),delimiter='\t',quoting=csv.QUOTE_NONE))
            # Only a complete OCR word in the publisher's vocabulary qualifies.
            hits=[w for w in words if w.get('text','').isupper() and RISK.fullmatch(w['text']) and float(w['conf'])>=70]
            labels={w['text'].upper() for w in hits}
            # Word's outlined badge letters are PDF paths, while the title is
            # native text. A tighter path-only crop improves OCR without fuzzy
            # spelling aliases (WEDIUM never silently becomes MEDIUM).
            if not labels:
                shapes=[d['rect'] for d in page.get_drawings() if d.get('fill') is not None
                    and d['rect'].width>0 and d['rect'].height>2
                    and d['rect'].y0>=y0-5 and d['rect'].y1<=y1+18
                    and d['rect'].x0>=x0-5 and d['rect'].x1<=page.rect.width-25]
                if shapes:
                    box=fitz.Rect(shapes[0])
                    for shape in shapes[1:]:box|=shape
                    box+=(-3,-3,3,3)
                    page.get_pixmap(matrix=fitz.Matrix(5,5),clip=box).save(path)
                    retry=subprocess.run([tool('tesseract',ROOT),str(path),'stdout','-l','eng','--psm','7','tsv'],
                        env=tool_environment(ROOT),capture_output=True,timeout=60,check=True)
                    retry_words=list(csv.DictReader(io.StringIO(retry.stdout.decode()),delimiter='\t',quoting=csv.QUOTE_NONE))
                    retry_hits=[w for w in retry_words if w.get('text','').isupper() and RISK.fullmatch(w['text']) and float(w['conf'])>=70]
                    if len({w['text'].upper() for w in retry_hits})==1:
                        rect=box;words=retry_words;hits=retry_hits;labels={w['text'].upper() for w in hits}
            record={'accepted':len(labels)==1,'page':number,'native_id':c.printed_id,
                'pdf_box':list(rect),'ocr_text':' '.join(w['text'] for w in words if w.get('text')),
                'heading_text':''.join(s['text'] for s in line['spans']),
                'image_sha256':digest(path.read_bytes()),'basis':'native_id_heading_strip_ocr'}
            if len(labels)==1:
                label=next(iter(labels));hit=next(w for w in hits if w['text'].upper()==label)
                record.update(raw=hit['text'],confidence=float(hit['conf']))
            else:record['reason']='no_unique_confident_severity_word'
            records[str(c.start)]=record
    result={'version':VERSION,'original_sha256':sha,'text_sha256':report.meta['text_sha256'],'records':records}
    write_json(cache_path(sha),result)
    return result


def evidence(report):
    sha=report.meta.get('sha256')
    if not sha:return {}
    if sha in holdouts():raise ValueError('Holdout badge access')
    path=cache_path(sha)
    if not path.exists():return {}
    data=json.loads(path.read_text())
    if (data['version']!=VERSION or data['original_sha256']!=sha
            or data['text_sha256']!=report.meta['text_sha256']):
        raise ValueError('Stale badge evidence; rerun field_audit.py badges')
    return data['records']


def build_labelled_cards(report,candidates):
    """Zokyo's dark penetration-test cards: OCR labelled Risk Score cells only."""
    import fitz
    from extract import tool,tool_environment
    sha=report.meta['sha256']
    if sha in holdouts():raise ValueError('Holdout field access')
    path=ROOT/'local-cache/originals'/sha[:2]/f'{sha}.pdf'
    payload=path.read_bytes()
    if digest(payload)!=sha:raise ValueError('Original hash mismatch')
    records={}
    with fitz.open(stream=payload,filetype='pdf') as pdf,tempfile.TemporaryDirectory(prefix='labelled-card-') as tmp:
        for c in candidates:
            number=next(p['page'] for p in report.meta['pages'] if p['start']<=c.start<p['end'])
            page=pdf[number-1];box=fitz.Rect(0,0,page.rect.width,page.rect.height*.32)
            crop=Path(tmp)/'card.png';page.get_pixmap(matrix=fitz.Matrix(3,3),clip=box).save(crop)
            run=subprocess.run([tool('tesseract',ROOT),str(crop),'stdout','-l','eng','--psm','6'],
                env=tool_environment(ROOT),capture_output=True,timeout=60,check=True)
            text=run.stdout.decode();risk=re.search(r'(?mi)^Risk Score\s+(Critical|High|Medium|Low|Informational)\s*$',text)
            native=bool(re.search(r'(?m)^'+re.escape(c.printed_id)+r'\s+',text) or re.match(re.escape(c.printed_id)+r'\s',report.text[c.start:c.start+60]))
            if not risk:
                # Colored cells can disappear in full-page OCR. Color locates
                # the field rectangle only; the printed word determines risk.
                pix=page.get_pixmap(matrix=fitz.Matrix(3,3),clip=box)
                w,h=pix.width,pix.height;data=pix.samples;bands=[]
                for y in range(h):
                    sample=[data[(y*w+x)*3:(y*w+x)*3+3] for x in range(w//10,9*w//10,12)]
                    colored=sum(max(p)>130 and max(p)-min(p)>65 for p in sample)
                    if colored>len(sample)*.7:
                        if bands and y==bands[-1][-1]+1:bands[-1].append(y)
                        else:bands.append([y])
                bands=[b for b in bands if len(b)>15]
                if len(bands)==1:
                    band=bands[0];a=max(0,band[0]-2);b=min(h,band[-1]+3)
                    pixels=bytes(255 if max(data[(y*w+x)*3:(y*w+x)*3+3])>125 else 0 for y in range(a,b) for x in range(w//12,11*w//12))
                    field=Path(tmp)/'risk.pgm';field.write_bytes(f'P5\n{11*w//12-w//12} {b-a}\n255\n'.encode()+pixels)
                    retry=subprocess.run([tool('tesseract',ROOT),str(field),'stdout','-l','eng','--psm','7'],
                        env=tool_environment(ROOT),capture_output=True,timeout=60,check=True)
                    risk_text=retry.stdout.decode().strip();risk=re.fullmatch(r'Risk Score\s+(Critical|High|Medium|Low|Informational)',risk_text,re.I)
                    if risk:
                        text+='\n'+risk_text+'\n';box=fitz.Rect(page.rect.width/12,a/3,11*page.rect.width/12,b/3)
                        page.get_pixmap(matrix=fitz.Matrix(3,3),clip=box).save(crop)
            proof=dict(accepted=bool(risk and native),native_id=c.printed_id,page=number,pdf_box=list(box),
                ocr_text=text,image_sha256=digest(crop.read_bytes()),basis='native_id_labelled_risk_score_cell_ocr')
            if risk:proof['raw']=risk[1]
            state=re.search(r'(?mi)^Status\s+(PARTIALLY FIXED|FIXED|RESOLVED|ACKNOWLEDGED|OPEN)\s*$',text)
            if state and native:proof['status_raw']=state[1]
            records[str(c.start)]=proof
    result=dict(version=VERSION,labelled_version=2,original_sha256=sha,text_sha256=report.meta['text_sha256'],records=records)
    write_json(cache_path(sha),result)
    return result
