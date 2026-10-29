"""Page-local PDF repairs before layout selection; originals remain untouched."""
from collections import Counter
import csv
import hashlib
import io
from pathlib import Path
import re
import subprocess
import tempfile
from difflib import SequenceMatcher

VERSION = 'page-normalization-v1'
FONT_MAPPING_VERSION = 3
RISK_WORD=r'(?:Critical|High|Medium|Low|Informational|Information|Info|Note|Gas)'
STATE_WORD=r'(?:Fixed|Resolved|Unresolved|Open|Acknowledged|Verified|Not Valid|Risk Accepted|Partially Fixed)'
BADGE=re.compile(r'^('+RISK_WORD+r')(?:\s*[-–]\s*(\d+(?:\.\d+)*))?(?:\s*\([^)]*\))?(?:\s+('+STATE_WORD+r'))?$',re.I)
MISSING_FONT = re.compile(r'Missing (?:language pack|CMap|font mapping)|(?:Adobe-(?:Korea|Japan|GB|CNS)\d).*?(?:mapping|CMap)',re.I)


def missing_font_mapping(warning):
    return bool(MISSING_FONT.search(warning))


def needs_font_mapping_retry(meta):
    pending={q['page'] for q in meta.get('issues',[]) if q['kind']=='missing_font_mapping'}
    done={q['page'] for q in meta.get('issues',[]) if q['kind']=='ocr_page'}
    return bool(pending-done) or (meta.get('font_mapping_ocr_version') != FONT_MAPPING_VERSION and any(
        q['kind']=='poppler_warning' and missing_font_mapping(q.get('detail',''))
        for q in meta.get('issues',[])))


def font_mapping_pages(path, count, binary, env, timeout):
    """A document-wide Poppler warning is not a page locator. Probe pages."""
    affected=[]
    for number in range(1,count+1):
        run=subprocess.run([binary,'-f',str(number),'-l',str(number),'-layout','-enc','UTF-8',str(path),'-'],
                           capture_output=True,timeout=timeout,env=env)
        warning=run.stderr.decode('utf-8','replace')
        if missing_font_mapping(warning):affected.append(number)
    return affected


def merge_prior_ocr(before, generated, receipt):
    """Preserve existing OCR structure; add badges beside matching titles.

    Existing grades/IDs never change. New evidence can fill a missing status
    or insert a missing badge only beside a uniquely matching source title.
    No finding totals or parser output participate in this decision.
    """
    receipt['prior_ocr_text_sha256']=hashlib.sha256(before.encode()).hexdigest()
    def key(text):return re.sub(r'[^a-z0-9]','',text.casefold())
    lines=before.splitlines(keepends=True);offsets=[];offset=0
    for line in lines:offsets.append(offset);offset+=len(line)
    inserts=[];associations=[];occupied=set()
    for crop in receipt.get('badge_crops',[]):
        header=' '.join(w['text'] for w in sorted(crop['words'],key=lambda w:w['box'][0]))
        grade=BADGE.fullmatch(header)
        if not grade:continue
        y=crop['box'][3]
        following=[w for w in receipt['words'] if y<w['box'][1]<y+45 and w['box'][0]>=crop['box'][0]-30]
        fragments=[l for l in word_layout(following).splitlines() if len(key(l))>=8]
        if not fragments:continue
        title=fragments[0]
        matches=sorted(((SequenceMatcher(None,key(title),key(line)).ratio(),j) for j,line in enumerate(lines) if len(key(line))>=8),reverse=True)
        score,j=matches[0] if matches else (0,None)
        proof=dict(badge=header,title_ocr=title,title_match_score=round(score,4),box=crop['box'])
        if score<.8 or j in occupied or len(matches)>1 and matches[1][0]>.95*score:
            associations.append(proof|{'accepted':False,'reason':'ambiguous_prior_title'});continue
        previous=next((k for k in range(j-1,max(-1,j-5),-1) if lines[k].strip()),None)
        existing=BADGE.fullmatch(lines[previous].strip().lstrip('|—– ')) if previous is not None else None
        if existing:
            if key(existing[1])!=key(grade[1]) or grade[2] and existing[2]!=grade[2]:
                associations.append(proof|{'accepted':False,'reason':'existing_grade_or_id_differs'});continue
            if grade[3] and not existing[3]:
                pos=offsets[previous]+len(lines[previous].rstrip('\r\n'));inserts.append((pos,' '+grade[3]))
        else:
            inserts.append((offsets[j],header+'\n'))
        occupied.add(j);associations.append(proof|{'accepted':True,'title_line':j})
    for offset,value in sorted(set(inserts),reverse=True):before=before[:offset]+value+before[offset:]
    receipt['prior_ocr_preserved']=True;receipt['badge_associations']=associations
    return before


def letter_spaced(text):
    tokens = re.findall(r'\b[A-Za-z0-9]+\b', text)
    return len(tokens) >= 30 and sum(len(t) == 1 for t in tokens) / len(tokens) > .55


def glyph_text(page):
    """Use actual glyph advances, not the broken font's nominal small bbox.

    MuPDF texttrace exposes painted advances even when ordinary extractors
    invent whitespace between every glyph. Real word/column gaps survive.
    Duplicate paint passes at identical coordinates are retained only once.
    """
    rows=[]; seen=set()
    for span in page.get_texttrace():
        if span['type'] == 3: continue  # invisible text is not painted evidence
        for code, _, origin, box in span['chars']:
            if code < 32 or code == 0xfffd: continue
            x,y=origin; key=(code,round(x,1),round(y,1))
            if key in seen: continue
            seen.add(key)
            rows.append((x,y,box[2],chr(code),span['size']))
    return spatial_text(rows)


def spatial_text(glyphs):
    rows=[]
    for item in sorted(glyphs,key=lambda v:(v[1],v[0])):
        if rows and abs(item[1]-rows[-1][0]) <= 2.6:
            rows[-1][1].append(item)
        else: rows.append((item[1],[item]))
    result=[]; previous_y=None
    for y,items in rows:
        value='';right=None;last_size=10
        for x,_,x1,word,size in sorted(items):
            if right is not None:
                gap=x-right
                if gap > max(14,size*2):value+='    '
                elif gap > max(.8,min(size,last_size)*.18):value+=' '
            value+=word;right=max(right or x1,x1);last_size=size
        if previous_y is not None and y-previous_y>22:result.append('')
        result.append(value.rstrip());previous_y=y
    return '\n'.join(result)+'\n'


def visual_content(page):
    area=page.rect.width*page.rect.height
    image_area=sum(r.width*r.height for im in page.get_images() for r in page.get_image_rects(im[0]))
    drawings=page.get_drawings()
    # Outlined letters may all be batched into a single drawing. Count path
    # primitives as well as small glyph-sized drawing rectangles.
    primitives=sum(len(d['items']) for d in drawings)
    glyphs=sum(1 for d in drawings if 1<d['rect'].width<45 and 2<d['rect'].height<45)
    return dict(image_fraction=min(1,image_area/area),vector_primitives=primitives,vector_glyphs=glyphs)


def needs_ocr(text, content):
    return sum(c.isalnum() for c in text)<250 and (content['image_fraction']>.12 or
        content['vector_glyphs']>=35 or content['vector_primitives']>=600)


def tsv_words(payload, scale=1, offset=(0,0)):
    words=[]
    for row in csv.DictReader(io.StringIO(payload),delimiter='\t',quoting=csv.QUOTE_NONE):
        if row.get('level')!='5' or not row.get('text','').strip():continue
        if float(row['conf'])<0:continue
        x=offset[0]+int(row['left'])/scale;y=offset[1]+int(row['top'])/scale
        w=int(row['width'])/scale;h=int(row['height'])/scale
        words.append(dict(text=row['text'],box=[x,y,x+w,y+h],confidence=float(row['conf'])))
    return words


def word_layout(words):
    """Row order and explicit column gaps, independent of OCR block ordering."""
    rows=[]
    for word in sorted(words,key=lambda w:(w['box'][1],w['box'][0])):
        x0,y0,x1,y1=word['box'];height=max(1,y1-y0);center=(y0+y1)/2
        match=None
        for row in reversed(rows[-2:]):
            overlap=max(0,min(y1,row['bottom'])-max(y0,row['top']))
            if overlap/min(height,max(1,row['bottom']-row['top']))>.35 and abs(center-row['center'])<.8*max(height,row['bottom']-row['top']):
                match=row;break
        if match is None:
            rows.append(dict(top=y0,bottom=y1,center=center,words=[word]))
        else:
            match['words'].append(word);match['top']=min(match['top'],y0);match['bottom']=max(match['bottom'],y1)
    # Each row gets one y coordinate, so descenders cannot push a word such as
    # "gas" out of a sentence into a spurious stand-alone severity heading.
    return spatial_text([(w['box'][0],row['center'],w['box'][2],w['text'],
                          max(5,w['box'][3]-w['box'][1])) for row in rows for w in row['words']])


def ocr_page(page, tess, env, folder, timeout, cached=None):
    import fitz
    folder=Path(folder); scale=3
    pix=page.get_pixmap(matrix=fitz.Matrix(scale,scale),alpha=False)
    png=folder/'page.png';pix.save(png)
    def read(path,psm,offset=(0,0),factor=scale):
        run=subprocess.run([tess,str(path),'stdout','-l','eng','--psm',str(psm),'tsv'],
                           capture_output=True,timeout=timeout,env=env)
        if run.returncode:raise RuntimeError(f'OCR failed (psm={psm}, input={Path(path).name}, code={run.returncode}): '+run.stderr.decode('utf-8','replace')[:200])
        return tsv_words(run.stdout.decode('utf-8','replace'),factor,offset)
    render_sha=hashlib.sha256(png.read_bytes()).hexdigest()
    reused=bool(cached and cached.get('render_sha256')==render_sha and cached.get('engine')=='tesseract-eng' and cached.get('words'))
    words=[dict(w) for w in cached['words']] if reused else read(png,3)
    if reused:
        receipt={k:v for k,v in cached.items() if k not in {'page','method','native_text_sha256','text_sha256','ocr_text_sha256','adopted_text'}}
        return word_layout(words),dict(receipt,reused_verified_page_words=True)
    optional_errors=[]
    try:supplement=[] if reused else read(png,11)
    except RuntimeError as exc:supplement=[];optional_errors.append(str(exc))
    crops=[]
    # Tight badge crops survive segmentation that drops colored risk/status
    # cells. OCR the painted cell itself, retaining its exact pixel evidence.
    rectangles=[d['rect'] for d in page.get_drawings() if d.get('fill') and len(d['items'])<=12 and
                18<d['rect'].width<page.rect.width*.96 and 6<d['rect'].height<35]
    # Rasterized cards have no drawing rectangles. Locate wide white bands on
    # dark bodies by pixels; whole white pages exceed the band-height bound.
    pixels=pix.samples;w=pix.width;h=pix.height;bands=[]
    for y in range(h):
        xs=range(int(w*.12),int(w*.92),max(1,w//80))
        white=sum(min(pixels[(y*w+x)*3:(y*w+x)*3+3])>220 for x in xs)/len(xs)
        if white>.62:
            if bands and bands[-1][-1]==y-1:bands[-1].append(y)
            else:bands.append([y])
    for band in bands:
        if not 6*scale<len(band)<35*scale:continue
        y=band[len(band)//2]
        white=[x for x in range(int(w*.02),int(w*.98)) if min(pixels[(y*w+x)*3:(y*w+x)*3+3])>220]
        if not white:continue
        rect=fitz.Rect(white[0]/scale,band[0]/scale,white[-1]/scale,band[-1]/scale)
        if rect.width<page.rect.width*.4:continue
        if not any((rect & r).get_area()>.8*rect.get_area() for r in rectangles):rectangles.append(rect)
    for rect in rectangles:
        clip=(rect+(-2,-2,2,2)) & page.rect
        crop=page.get_pixmap(matrix=fitz.Matrix(4,4),clip=clip,alpha=False)
        gray=fitz.Pixmap(fitz.csGRAY,crop)
        samples=gray.samples
        # Use the cell background to choose polarity, then isolate text.
        bg=Counter(samples).most_common(1)[0][0]
        values=bytes(255 if (v>max(150,bg-25) if bg>150 else v<min(140,bg+45)) else 0 for v in samples)
        path=folder/('badge-'+str(len(crops))+'.pgm')
        path.write_bytes(f'P5\n{gray.width} {gray.height}\n255\n'.encode()+values)
        try:found=read(path,7,(clip.x0,clip.y0),4)
        except RuntimeError as exc:optional_errors.append(str(exc));continue
        found=[w for w in found if not re.fullmatch(r'[|—–-]+',w['text'])]
        label=' '.join(w['text'] for w in found)
        if not BADGE.fullmatch(label) and not re.fullmatch(STATE_WORD,label,re.I):continue
        for w in found:w['source']='badge_crop'
        supplement+=found
        crops.append(dict(box=list(clip),image_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),words=found))
    for w in supplement:
        x0,y0,x1,y1=w['box'];area=max(1,(x1-x0)*(y1-y0))
        overlap=[v for v in words if max(0,min(x1,v['box'][2])-max(x0,v['box'][0]))*
                 max(0,min(y1,v['box'][3])-max(y0,v['box'][1]))/area>.45]
        if overlap and w.get('source')=='badge_crop':
            words=[v for v in words if v not in overlap];words.append(w)
        elif not overlap:words.append(w)
    value=word_layout(words)
    return value,dict(engine='tesseract-eng',modes=[3,11,7],render_sha256=render_sha,words=words,badge_crops=crops,reused_verified_page_words=reused,optional_ocr_failures=optional_errors)


def normalize_pdf(texts, path, root, tess, env, timeout, lock, previous=None, font_pages=()):
    import fitz
    import json
    from common import write_json
    issues=[];receipts=[];result=list(texts)
    sha=hashlib.sha256(path.read_bytes()).hexdigest()
    cache=root/'local-cache/fulltext/normalization'/(sha+'.json')
    old=json.loads(cache.read_text()) if cache.exists() else {}
    cached={p['page']:p for p in old.get('pages',[])} if old.get('sha256')==sha else {}
    prior_pages={p['page']:p['text'] for p in (previous or {}).get('pages',[])}
    prior_ocr={q['page'] for q in (previous or {}).get('issues',[]) if q['kind'] in {'ocr_page','layout_triggered_ocr'}}
    font_done={q['page'] for q in (previous or {}).get('issues',[]) if q['kind']=='ocr_page' and q.get('reason')=='missing_font_mapping'} if (previous or {}).get('font_mapping_ocr_version')==FONT_MAPPING_VERSION else set()
    with lock,fitz.open(path) as pdf:
        for i,text in enumerate(texts):
            page=pdf[i];native_sha=hashlib.sha256(text.encode()).hexdigest()
            font_failure=i+1 in font_pages
            force_ocr=font_failure
            if font_failure:issues.append(dict(kind='missing_font_mapping',page=i+1))
            if i+1 in font_done and i+1 in prior_pages:
                result[i]=prior_pages[i+1]
                issues.append(dict(kind='ocr_page',page=i+1,reason='missing_font_mapping'))
                continue
            if letter_spaced(text):
                value=glyph_text(page)
                if len(re.sub(r'\s','',value))>=.8*len(re.sub(r'\s','',text)):
                    result[i]=value
                    issues.append(dict(kind='letter_spaced_page',page=i+1))
                    receipts.append(dict(page=i+1,method='native-glyph-advances',native_text_sha256=native_sha,
                                         text_sha256=hashlib.sha256(value.encode()).hexdigest()))
                    if sum(c.isalnum() for c in value)>=250 and not force_ocr:continue
                    text=value  # A sparse glyph footer must not hide a raster body.
                else:force_ocr=True
            preserved=prior_pages.get(i+1) if i+1 in prior_ocr else None
            if preserved is not None:result[i]=preserved
            if sum(c.isalnum() for c in text)>=250 and not force_ocr:continue
            content=visual_content(page)
            if not force_ocr and not needs_ocr(text,content):continue
            if not tess:
                issues.append(dict(kind='image_only_page_ocr_unavailable',page=i+1));continue
            with tempfile.TemporaryDirectory(dir=root/'local-cache/fulltext',prefix='page-ocr-') as folder:
                previous=cached.get(i+1)
                if previous and previous.get('native_text_sha256')!=native_sha:previous=None
                try:value,receipt=ocr_page(page,tess,env,folder,timeout,previous)
                except (RuntimeError,subprocess.TimeoutExpired) as exc:
                    issues.append(dict(kind='ocr_failed',page=i+1,detail=str(exc)[:200]));continue
            if sum(c.isalnum() for c in value)<=20 or (not font_failure and
                    sum(c.isalnum() for c in value)<=sum(c.isalnum() for c in text)+20):continue
            # Some PDF resources request CJK mappings on otherwise complete
            # English cards. OCR still runs, but must not replace their usable
            # native metadata/narrative with recognition errors.
            if (font_failure and sum(c.isalnum() for c in text)>=250 and
                    re.search(r'\bSeverity\b',text,re.I) and re.search(r'\b(?:Descriptions?|Recommendations?|Suggestions?)\b',text,re.I)):
                result[i]=text
                issues.append(dict(kind='ocr_page',page=i+1,reason='missing_font_mapping',selected_text='native_complete_card'))
                receipts.append(dict(receipt,page=i+1,method='spatial-ocr-with-badges',native_text_sha256=native_sha,
                    text_sha256=native_sha,ocr_text_sha256=hashlib.sha256(value.encode()).hexdigest(),adopted_text=False))
                continue
            # Preserve native-only labels if OCR fails to reproduce them.
            compact=re.sub(r'\W','',value).casefold()
            for line in text.splitlines():
                key=re.sub(r'\W','',line).casefold()
                if key and key not in compact:value+='\n'+line+'\n'
            if preserved is not None:value=merge_prior_ocr(preserved,value,receipt)
            result[i]=value
            issues.append(dict(kind='ocr_page',page=i+1,
                               reason='missing_font_mapping' if font_failure else 'sparse_native_visual_content',**content))
            receipts.append(dict(page=i+1,method='spatial-ocr-with-badges',native_text_sha256=native_sha,
                                 text_sha256=hashlib.sha256(value.encode()).hexdigest(),**receipt))
    if receipts:
        merged={**cached,**{p['page']:p for p in receipts}}
        write_json(root/'local-cache/fulltext/normalization'/(sha+'.json'),dict(version=VERSION,sha256=sha,pages=[merged[n] for n in sorted(merged)]))
    represented={q['page'] for q in issues if q['kind']=='ocr_page'}
    issues.extend(dict(kind='ocr_page',page=n,reason='preserved_prior_ocr') for n in prior_ocr if n not in represented)
    return result,issues
