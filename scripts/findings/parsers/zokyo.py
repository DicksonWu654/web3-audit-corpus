"""Zokyo finding cards; metadata, legacy title-first cards, and numbered risk cards."""
from core import severity, Candidate, clean
from collections import Counter
import re
DESCRIPTION = 'Numbered/un-numbered severity/status cards, legacy title-first cards, wrapped titles, explicit detail bounds'
RISK=r'(?:Critical|High|Medium|Low|Informational|Information|Info|Gas)'
STATUS=r'(?:Partially\s+(?:Resolved|Fixed)|Not\s+(?:Resolved|Fixed)|Not\s*Valid|Acknowledg(?:e(?:d)?)?|Unresolved|Resolve(?:d)?|Fixed|Open|Invalid|Verified|Mitigated|Accepted|New|Pending)'
CARD=re.compile(r'^\s*(?:[—–|7]+\s*)?('+RISK+r')(?:\s*[-–]\s*(\d+(?:\.\d+)*))?(?:\s*\(([^)]+)\))?\s*(?:('+STATUS+r'))?\s*$',re.I)
STOP=re.compile(r'^(?:Code\s*Coverage|Test\s*Results|Automated\s*(?:Testing|Analysis)|Unit\s*Test|We are grateful|Disclaimer|Appendix)',re.I)


def _text(s):return s.replace('\u200b','').replace('\ufeff','').replace(' | ', ' ')


def _region(report):
    # Definition pages contain stand-alone Medium/High labels: exclude the entire legend.
    legends=[p['page'] for p in report.meta['pages'] if 'severity of each issue' in _text(p['text']).lower() or ('The issue affects' in p['text'] and len(re.findall(RISK,p['text'],re.I))>=4)]
    analysis=[l.start for l in report.lines if re.fullmatch(r'complete\s*analysis(?:\s*\([^)]*\))?',_text(l.content),re.I)]
    if legends:
        first_analysis=min(analysis) if analysis else len(report.text)
        eligible=[p for p in report.meta['pages'] if p['page'] in legends and p['start']<first_analysis]
        legend=eligible[-1] if eligible else next(p for p in report.meta['pages'] if p['page']==min(legends))
        start=legend['end']
    elif analysis:start=analysis[0]
    else:start=0
    end=len(report.text)
    for l in report.lines:
        if l.start>start and STOP.match(_text(l.content)) and not re.search(r'\d+\s*$',l.content):end=l.start;break
    return start,end


def _summary_pages(report):
    pages=set();active=False
    for p in report.meta['pages']:
        text=_text(p['text'])
        header=bool(re.search(r'Findings?\s+summary',text,re.I))
        # A leading OCR icon/ordinal plus risk/status is a detail badge, not
        # an inventory row. Continuation rows must also contain a title.
        row=any(len(line)<600 and re.match(r'^\s*\d+\s+\S.+?\s+'+RISK+r'\s+'+STATUS+r'\s*$',line,re.I) for line in text.splitlines())
        columns=bool(re.search(r'^\s*Risk\s+Status\s*$|^\s*(?:Title\s+)?Risk\s*$',text,re.I|re.M) and (re.search(r'^\s*Status\s*$',text,re.I|re.M) or len(re.findall(r'^\s*\d+\s+\S',text,re.M))>=3))
        separated=(sum(bool(re.fullmatch(RISK,l.strip(),re.I)) for l in text.splitlines())>=3 and sum(bool(re.fullmatch(STATUS,l.strip(),re.I)) for l in text.splitlines())>=3
                   and not any(len(l.strip())>120 for l in text.splitlines()))
        detail=bool(re.search(r'^\s*(?:Complete\s*Analysis|Description|Recommendation|Remediation)\b',text,re.I|re.M))
        if header or (active and not detail and (row or columns or separated)):
            pages.add(p['page']);active=True
        else:active=False
    return pages


def _cards(report):
    start,end=_region(report);summary=_summary_pages(report);out=[]
    ocr_pages={q['page'] for q in report.meta.get('issues',[]) if q['kind']=='ocr_page'}
    # SoullyCanto's retained OCR cache predates page-level issue receipts. The
    # source-bound profile restores two numbered badges without broadening the
    # icon grammar on unreviewed native-text pages. Canonical text is unchanged.
    if (report.meta.get('sha256') == '9412317ce1b293aee09b94dce1fda17dcfb5d74992320fb38025d2161b361faa'
            and report.meta.get('text_sha256') == 'afa21ba0ac87873968eabce3052015aebb3e2be41d0bb6a73f7ef9819afe5800'
            and report.meta.get('method') == 'pdftotext-layout+tesseract'):
        ocr_pages.update((17,26))
    report.ocr_icon_badges=set()
    report.ocr_pages=ocr_pages
    for i,l in enumerate(report.lines):
        if not start<=l.start<end or l.page in summary or l.code:continue
        m=CARD.fullmatch(_text(l.content))
        if m and l.page in ocr_pages and m[1].islower() and not m[2] and not m[4]:
            m=None  # ordinary prose fragments isolated by OCR are not badges
        if not m and l.page in ocr_pages:
            # Small severity icons can fuse with the badge word in page OCR.
            # Only a complete grade on an OCR-backed analysis page
            # can discard this short icon prefix; narrative prose never can.
            badge=re.fullmatch(r'[^\n]{1,7}?('+RISK+r')(\s*[-–]\s*\d+(?:\.\d+)*)?(?:\s+('+STATUS+r'))?',l.content,re.I)
            if badge and not badge[1].islower():
                m=CARD.fullmatch('| '+badge[1]+(badge[2] or '')+(' '+badge[3] if badge[3] else ''));report.ocr_icon_badges.add(l.start)
            if not m:
                # OCR can fuse pale status glyphs onto a complete numbered
                # risk badge. Keep the intact grade/ID, not the damaged state.
                numbered=re.fullmatch(r'[^\n]{0,7}?('+RISK+r')\s*[-–]\s*(\d+(?:\.\d+)*)(?:[A-Za-z]{1,12})',l.content,re.I)
                if numbered and not numbered[1].islower():
                    m=CARD.fullmatch('| '+numbered[1]+'-'+numbered[2]);report.ocr_icon_badges.add(l.start)
        if m:out.append((i,m))
    return out,end


def _content(l):
    s=_text(l.content)
    return bool(s and not re.fullmatch(r'[.\d\s]+',s) and not re.search(r'Smart Contract (?:Audit|Review)|Contract Audit|zokyo\.|zokyo security',s,re.I) and not re.fullmatch(r'complete\s*analysis(?:\s*\([^)]*\))?',s,re.I))


def layout(report):
    cards,_=_cards(report)
    if any(m[2] for _,m in cards):return 'numbered-risk-status-cards'
    if any(m[4] for _,m in cards):return 'unnumbered-risk-status-cards'
    if cards:return 'legacy-title-first-risk-cards'
    return 'unrecognized-or-clean'


def _special(report):
    out=[];active=False;parent=None
    pentest=False
    for i,l in enumerate(report.lines):
        text=_text(l.content)
        if re.fullmatch(r'1\s+VULNERABILITIES DETAILS AND MITIGATIONS',text,re.I):pentest=True
        if pentest and re.match(r'^[2-9]\s+[A-Z]',text):pentest=False
        if re.fullmatch(r'11\.\s*Results from Manual analysis',text,re.I):active=True
        if text=='Detailed Findings':active=True
        sev_parent=re.fullmatch(r'('+RISK+r')(?:-Severity Issues| Issues and Recommendations)',text,re.I)
        if sev_parent and active:parent=sev_parent[1];continue
        colon=re.match(r'^('+RISK+r')(?: severity)?,\s*('+STATUS+r'):\s*(.+)',text,re.I)
        if colon:
            out.append(Candidate(l.start,colon[3],colon[1],status_raw=colon[2],method='zokyo-inline-risk-heading',confidence=.92));continue
        num=re.match(r'^(\d+\.\d+|\d+)\.?\s+(.+)',text)
        if num and ((active and (num[1].startswith('11.') or (parent and '.' not in num[1]))) or (pentest and num[1].startswith('1.'))):
            # Exclude TOC rows; nested recommendations never match this two-level number.
            if re.search(r'\s{3,}\d+\s*$',l.text):continue
            raw=parent;status=None
            if num[1].startswith('11.'):
                following=[]
                for nxt in report.lines[i+1:]:
                    if re.match(r'^11\.\d+\s+',_text(nxt.content)):break
                    following.append(nxt.content)
                m=re.search(r'\bRisk:\s*('+RISK+r')\b','\n'.join(following),re.I)
                if not m:continue
                raw=m[1]
            elif pentest:
                near=report.near(i,9)
                m=re.search(r'\b(?:R?isk Score)\s+([A-Za-z]+)',near,re.I)
                raw=m[1] if m else None
                m=re.search(r'\bStatus\s+('+STATUS+r')\b',near,re.I);status=m[1] if m else None
            out.append(Candidate(l.start,num[2],raw,num[1],status_raw=status,method='zokyo-numbered-metadata',confidence=.88,
                                 evidence={'severity_availability':'explicit_text' if raw else 'not_textual_or_absent',
                                           **({'container_id':parent.casefold()} if parent else {})}))
        field=re.fullmatch(r'Severity\s+('+RISK+r')',text,re.I)
        if field:
            previous=[q for q in report.lines[max(0,i-6):i] if q.page==l.page and _content(q) and q.content.lower()!='findings']
            if previous:
                title=previous[-1];near=report.near(i,5);m=re.search(r'\bStatus\s+('+STATUS+r')\b',near,re.I)
                out.append(Candidate(title.start,title.content,field[1],status_raw=m[1] if m else None,method='zokyo-severity-field',confidence=.91))
    out.sort(key=lambda c:c.start)
    for i,c in enumerate(out):
        c.end=out[i+1].start if i+1<len(out) else len(report.text)
        tail=report.text[c.start:c.end]
        stop=re.search(r'\n\s*(?:Scope and Methodology|Appendix|[234]\.?\s+[A-Z][A-Z ]{5,})\s*\n',tail)
        if stop:c.end=c.start+stop.start()
    return out


def parse(report):
    cards,limit=_cards(report);out=[]
    special=_special(report)
    if not cards:return special
    for k,(i,m) in enumerate(cards):
        line=report.lines[i];end=report.lines[cards[k+1][0]].start if k+1<len(cards) else limit
        title=None;start=line.start;raw=m[1];pid=raw+'-'+m[2] if m[2] else None;status=m[4]
        # Pre-2022 PDFs put title BEFORE a bare severity label.
        if not m[2] and not status and raw.isupper() and not re.match(r'^[—–|7]',line.content) and line.start not in getattr(report,'ocr_icon_badges',set()):
            previous=[]
            for l in reversed(report.lines[max(0,i-10):i]):
                if l.page!=line.page:break
                if _content(l):
                    if previous and not l.content:break
                    previous.append(l)
                    # Heading is normally the last nonempty block before the risk badge.
                    if len(previous)>=3:break
                elif previous:break
            if previous:
                previous.reverse();title=clean(' '.join(_text(l.content) for l in previous));start=previous[0].start
        if not title:
            block=[]
            for l in report.lines[i+1:i+20]:
                if l.start>=end:break
                if not _content(l):
                    if block:break
                    continue
                if CARD.fullmatch(_text(l.content)):break
                if block and re.match(r'^[\w./ -]+\.(?:sol|rs|go|js|ts)(?:[:.]|$)',l.content,re.I):break
                if block and line.page in getattr(report,'ocr_pages',set()) and re.search(r'[.!?]$',block[-1]):break
                if re.match(r'(?:Description|Recommendation|Resolution|File|Issue|Function)\s*:',l.content,re.I) and not block:continue
                block.append(_text(l.content))
                if len(block)>=4:break
            title=clean(' '.join(block)) or None
        out.append(Candidate(start,title,raw,pid,normalized=severity(raw, report.firm),end=end,status_raw=status,
            method='zokyo-numbered-card' if pid else 'zokyo-legacy-card',confidence=.92 if pid else .85,
            evidence={'title_basis':'printed_heading_or_leading_source_text','status_basis':'card_label' if status else 'absent_on_card',
                      'severity_qualifier':m[3], 'badge_span':{'start':line.start,'end':line.end,'text':report.text[line.start:line.end]}}))
    # Legacy card starts can precede the label, so body bounds follow actual next titles.
    for c,n in zip(out,out[1:]):c.end=min(c.end,n.start)
    return sorted(out+special,key=lambda c:c.start)


def printed_counts(report):
    # Use printed aggregate issue totals, never count detail cards or summary-table rows.
    # Scoring examples are explicitly labelled as such and retained as uncertain evidence.
    evidence=[];values={}
    for p in report.meta['pages']:
        text=p['text']
        if not re.search(r'(?:Starting with a perfect score|Scoring Calculation|Scoring calculation)',text,re.I):continue
        for m in re.finditer(r'(?<![A-Za-z0-9])[-•]?\s*(\d+)\s+('+RISK+r')\s+issues?\s*:',text,re.I):
            key=severity(m[2], report.firm);value=int(m[1]);values.setdefault(key,set()).add(value)
            evidence.append({'page':p['page'],'start':p['start']+m.start(),'end':p['start']+m.end(),'text':m[0]})
    if not values:return None
    ambiguous=any(len(v)>1 for v in values.values())
    selected={k:min(v) for k,v in values.items()}
    inventory=summary_inventory_counts(report)
    conflict=bool(inventory and any(inventory['counts'].get(k,0)!=v for k,v in selected.items()))
    return {'counts':selected,'ambiguous':ambiguous or conflict,'independent_summary_inventory':inventory,'summary_conflict':conflict,
            'basis':'printed_scoring_issue_totals','evidence':evidence,
            'limitations':['Source labels the scoring calculation hypothetical; contradictions with detail remain mismatches.']}


def sequence_evidence(report):
    # Independent numbered summary rows (not card parsing) establish the expected detail sequence.
    entries=[];summary_pages=_summary_pages(report);vertical=[]
    for p in report.meta['pages']:
        if p['page'] not in summary_pages:continue
        for line in p['text'].splitlines():
            s=_text(line)
            if len(s)>600:continue
            m=re.match(r'^\s*(\d+)\s+(.+)',s)
            if m:entries.append({'ordinal':int(m[1]),'title_fragment':clean(m[2])})
            if re.fullmatch(r'\s*'+RISK+r'\s*',s,re.I):vertical.append(clean(s))
    if entries:
        ordinals=[e['ordinal'] for e in entries]
        return {'basis':'printed_numbered_summary_rows','entries':entries,'expected_count':max(ordinals),
                'ordinals_complete':sorted(set(ordinals))==list(range(1,max(ordinals)+1))}
    if vertical:return {'basis':'printed_summary_risk_column_rows','expected_count':len(vertical),'risk_labels':vertical,
                        'limitation':'OCR separated columns; counts rows in the independent summary, not aggregate totals.'}
    # Without a summary, independently census explicit risk badge lines in the analysis region.
    start,end=_region(report);headers=[]
    for l in report.lines:
        s=_text(l.content)
        if start<=l.start<end and re.fullmatch(r'(?:[—–|7]+\s*)?'+RISK+r'(?:\s*[-–]\s*\d+)?(?:\s*\([^)]*\))?(?:\s+'+STATUS+r')?',s,re.I):
            headers.append({'start':l.start,'label':s})
    if not headers:
        # A separate lexical census checks explicit metadata and inline heading layouts.
        fields=[l for l in report.lines if re.fullmatch(r'Severity\s+'+RISK,_text(l.content),re.I)
                or re.match(r'^'+RISK+r'(?: severity)?,\s*'+STATUS+r':',_text(l.content),re.I)]
        if fields:return {'basis':'explicit_metadata_or_inline_heading_census','expected_count':len(fields),
                          'limitation':'Structural completeness only; no independent published finding index.'}
    if headers:return {'basis':'analysis_risk_badge_census','expected_count':len(headers),'headers':headers,
                       'limitation':'Structural completeness only; no independent published finding index.'}
    return None

from layout_support import view, visible, attach_status, status_value
import json
from common import ROOT, digest, holdouts
from variants import Variant, Fingerprint
_card_parse=parse


def visual_receipts(report):
    sha=report.meta.get('sha256')
    if not sha:return []
    if sha in holdouts():raise ValueError('Holdout badge receipt denied')
    path=ROOT/'local-cache/phase4e-u/zokyo_badges'/(sha+'.json')
    receipt=json.loads(path.read_text()) if path.exists() else {}
    inputs=receipt.get('claims',[]) if receipt.get('text_sha256')==report.meta['text_sha256'] and receipt.get('sha256')==sha else []
    fixture=ROOT/'scripts/findings/parsers/fixtures/zokyo_reviewed_badges.json'
    if fixture.exists():
        inputs += [c for c in json.loads(fixture.read_text())['claims'] if c['sha256']==sha and c['text_sha256']==report.meta['text_sha256']]
    fixture=ROOT/'scripts/findings/parsers/fixtures/recall_zokyo_badges.json'
    if fixture.exists():
        inputs += [c for c in json.loads(fixture.read_text())['claims'] if c['sha256']==sha and c['text_sha256']==report.meta['text_sha256']]
    claims=[]
    for claim in inputs:
        start,end=claim['source_span']['start'],claim['source_span']['end']
        if not 0<=start<end<=len(report.text) or report.text[start:end]!=claim['source_span']['text']:continue
        if not re.fullmatch(STATUS,claim.get('status_raw') or '',re.I) and not (claim.get('review_method')=='visual_review' and claim.get('absence_reason')=='not_stated') and not (claim.get('review_method') in {'recall_badge_ocr','recall_badge_visual_review'} and re.fullmatch(RISK,claim.get('risk_raw') or '',re.I)):continue
        claims.append(claim)
    return claims


def page_ocr_receipts(report):
    sha=report.meta.get('sha256')
    if not sha:return {}
    if sha in holdouts():raise ValueError('Holdout page OCR receipt denied')
    path=ROOT/'local-cache/fulltext/normalization'/(sha+'.json')
    if not path.exists():return {}
    payload=path.read_bytes();receipt=json.loads(payload)
    if receipt.get('sha256')!=sha:return {}
    pages={p['page']:p for p in report.meta['pages']};out={}
    for p in receipt.get('pages',[]):
        if p.get('method')!='spatial-ocr-with-badges' or p['page'] not in pages:continue
        if digest(pages[p['page']]['text'].encode())!=p['text_sha256']:continue
        out[p['page']]=dict(original_sha256=sha,text_sha256=report.meta['text_sha256'],page=p['page'],
            receipt_sha256=digest(payload),native_text_sha256=p['native_text_sha256'],
            render_sha256=p['render_sha256'],engine=p['engine'],badge_crops=p.get('badge_crops',[]))
    return out


def remediation_status(report,candidates):
    pages=page_ocr_receipts(report)
    for c in candidates:
        if c.method=='zokyo-image-badge':
            # OCR labels have image provenance; a coincidental occurrence of
            # that word in the narrative must not become a printed-card span.
            c.status_raw=c.normalized_status=None
    attach_status(report,candidates,'zokyo')
    visual={v['card_start']:v for v in visual_receipts(report)}
    for c in candidates:
        body=report.text[c.start:c.end];claim=None
        badge=c.evidence.get('badge_span')
        if badge:
            page=next((p['page'] for p in report.meta['pages'] if p['start']<=badge['start']<p['end']),None)
            if page in pages:c.evidence['page_ocr_evidence']=pages[page] | {'source_span':badge}
        # Some cards print the status on its own line directly below the badge.
        if not c.status_raw:
            m=re.search(r'(?:^|\n)[ \t]*('+STATUS+r')[ \t]*\n',body[:250],re.I)
            if m: claim=(m[1],m.start(1),m.end(1),'standalone_card_status')
        for section in re.finditer(r'(?:^|\n)[ \t]*(?:Post[- ]audit|Resolution|Fix(?:ed)?)\s*[:.]?\s*\n',body,re.I):
            text=body[section.end():];base=section.end()
            # Future plans and recommendations do not prove a fix.
            patterns=(r'^\s*(Fixed|Resolved)\b',
                      r'\b(?:The |This )?(?:issue|finding|problem)\s+(?:was |is |has been )?(partially resolved|not resolved|unresolved|resolved|fixed)\b',
                      r'\b(The commit with fix is)\s+[a-f0-9]{7,40}\b')
            for pattern in patterns:
                m=re.search(pattern,text,re.I)
                if m:
                    claim=(m[1],base+m.start(1),base+m.end(1),'post_audit_resolution');break
        if claim:
            raw,start,end,basis=claim;start+=c.start;end+=c.start
            c.status_raw=raw;c.normalized_status='fixed' if raw.lower()=='the commit with fix is' else status_value(raw,'zokyo')
            c.evidence['status_evidence']=dict(raw=raw,start=start,end=end,text=report.text[start:end],basis=basis,profile='zokyo')
        badge=c.evidence.get('badge_span')
        image=visual.get(badge['start'] if badge else c.start)
        if image:
            c.evidence['status_image_evidence' if image.get('review_method')=='visual_review' else 'status_ocr_evidence']=image
            if not c.status_raw and image['status_raw']:
                c.status_raw=image['status_raw'];c.normalized_status=image.get('normalized_status') or status_value(c.status_raw,'zokyo')
        if c.status_raw:
            native={'notvalid':'invalid','acknowledg':'acknowledged','resolve':'resolved'}
            c.normalized_status=native.get(re.sub(r'\s','',c.status_raw).casefold(),c.normalized_status)
        if not c.status_raw:
            # Image badge text is absent from several legacy PDF text layers.
            # A failed/unavailable OCR read cannot establish that status is absent.
            reason='not_stated' if image and image.get('absence_reason')=='not_stated' else 'badge_not_decoded' if badge and not c.printed_id else 'not_stated'
            c.normalized_status='unknown';c.evidence['status_availability']=dict(status='unknown',reason=reason,checked='risk card, labelled status and post-audit resolution section')


def image_badges(report, native_fallback=True):
    by_start={}
    for claim in visual_receipts(report):
        if not claim.get('status_raw') and claim.get('review_method') not in {'recall_badge_ocr','recall_badge_visual_review'}:continue
        title=claim.get('title_span')
        if not title or report.text[title['start']:title['end']]!=title['text']:continue
        priority=(claim.get('review_method') in {'visual_review','recall_badge_visual_review'},
                  claim.get('review_method','').startswith('recall_'),bool(claim.get('printed_id')),claim.get('title_match_score',0))
        if title['start'] in by_start and by_start[title['start']][0]>priority:continue
        by_start[title['start']]=(priority,Candidate(title['start'],title['text'],claim['risk_raw'],claim.get('printed_id'),status_raw=claim['status_raw'],
                             method='zokyo-image-badge',confidence=.85,evidence={'status_ocr_evidence':claim,'severity_ocr_evidence':claim,'badge_span':claim['source_span']}))
    # Repeated receipts for one title must be collapsed before bounding spans;
    # otherwise the first copy ends at its own start and finish drops the card.
    out=[v[1] for _,v in sorted(by_start.items())]
    for c,n in zip(out,out[1:]):c.end=n.start
    if native_fallback and not out and any(q['kind']=='ocr_page' for q in report.meta.get('issues',[])):
        out=_card_parse(view(report))
    if native_fallback and not out:report.layout_disposition={'reason':'finding_badges_missing_from_text_layer','basis':'publisher_issue_legend_and_analysis_pages; visual OCR receipts retained separately'}
    return out


def clean_report(report):
    report.layout_disposition={'reason':'no_detailed_issue_cards','basis':'executive_outcome_and_complete_text_census'}
    return []


def _with_visual_cards(report):
    from layout_support import bounded
    out=_card_parse(view(report));images=image_badges(report,native_fallback=False)
    def key(value):return re.sub(r'\W','',(value or '').casefold())
    # The first surviving content line after a badge identifies its own
    # header. A later title inside a long body is not the same finding.
    associated=set()
    for c in out:
        badge=c.evidence.get('badge_span')
        if not badge:continue
        first=next((l for l in report.lines if l.start>badge['end'] and _content(l)
                    and not re.fullmatch(STATUS,_text(l.content),re.I)),None)
        if first is None:continue
        for image in images:
            if image.start!=first.start:continue
            if key(c.severity_raw).replace('informational','info')!=key(image.severity_raw).replace('informational','info'):continue
            claim=image.evidence['severity_ocr_evidence']
            c.evidence['image_card_association']=claim
            if c.title!=image.title:c.evidence['native_title_before_image_association']=c.title
            c.title=image.title
            if not c.printed_id and image.printed_id:
                c.printed_id=image.printed_id;c.evidence['id_ocr_evidence']=claim
            associated.add(id(image))
    for image in images:
        title=key(image.title)
        claim=image.evidence.get('severity_ocr_evidence',{})
        same_title=[]
        for c in out:
            native_title=key(c.title)
            if not title or len(title)<12 or not native_title:continue
            if abs(c.start-image.start)>=500:continue
            if not (title in native_title or native_title in title):continue
            if c.printed_id and image.printed_id and c.printed_id.casefold()!=image.printed_id.casefold():
                badge=c.evidence.get('badge_span',{})
                if not (badge.get('end',-1000)<=image.start<=badge.get('end',-1000)+250):continue
                c.evidence['id_ocr_conflict']=dict(native_id=c.printed_id,image_id=image.printed_id,claim=claim)
            same_title.append(c)
        if len(same_title)==1 and not same_title[0].printed_id and image.printed_id:
            # A raster badge can supply an absent ID; existing printed IDs
            # require an explicit visual review before replacement.
            same_title[0].printed_id=image.printed_id
            same_title[0].evidence['id_ocr_evidence']=claim
        if claim.get('review_method')=='recall_badge_visual_review':
            for c in out:
                if not (c.printed_id and image.printed_id and c.start<=image.start<(c.end or c.start)):continue
                if key(c.severity_raw)!=key(image.severity_raw) or not key(c.title).startswith(title):continue
                badge=c.evidence.get('badge_span',{})
                page=next((p['page'] for p in report.meta['pages'] if p['start']<=badge.get('start',-1)<p['end']),None)
                if page not in {q['page'] for q in report.meta.get('issues',[]) if q['kind']=='ocr_page'}:continue
                if c.printed_id.casefold()!=image.printed_id.casefold():
                    c.evidence.update(native_ocr_id=c.printed_id,id_ocr_evidence=claim)
                    c.printed_id=image.printed_id
        id_matches=[c for c in out if image.printed_id and c.printed_id and
                    image.printed_id.casefold()==c.printed_id.casefold() and c.start<=image.start<(c.end or c.start)]
        if len(id_matches)==1:
            # The source ID links a column-shuffled title back to its own
            # native card. Distinct native cards with repeated IDs remain.
            id_matches[0].evidence.setdefault('image_card_id_associations',[]).append(claim)
        duplicate=id(image) in associated or bool(same_title) or any(c.evidence.get('badge_span',{}).get('start')==image.evidence['badge_span']['start'] or
                      len(id_matches)==1 and c is id_matches[0] or
                      title and key(c.title) and abs(c.start-image.start)<300 and (key(c.title).startswith(title) or title.startswith(key(c.title))) for c in out)
        if not duplicate:out.append(image)
    limit=_region(report)[1]
    for c in out:
        if c.end is None or c.end>limit:c.end=limit
    rounds=[l for l in report.lines if len(l.content)<110 and re.match(
        r'^\d+(?:ST|ND|RD|TH)\s+(?:AUDIT\s+)?ITERATION\s+COMPLETE',_text(l.content),re.I)]
    if rounds:
        for c in out:
            section=next((l for l in reversed(rounds) if l.start<c.start),None)
            c.evidence['container_id']=_text(section.content).casefold() if section else 'initial analysis'
            if section:c.evidence['iteration_heading']={'start':section.start,'end':section.end,'text':report.text[section.start:section.end]}
    return bounded(report,out)


def numbered_cards(report):return _with_visual_cards(report)

def status_cards(report):return _with_visual_cards(report)

def title_first_cards(report):return _with_visual_cards(report)

def metadata_cards(report):return _special(view(report))

VARIANTS=(
 Variant('zokyo/v2022_numbered_cards',Fingerprint((('numbered_risk',r'^\s*(?:[—–|7]+\s*)?'+RISK+r'\s*[-–]\s*\d+',12),),('2022','2026')),numbered_cards,('zokyo_numbered',),remediation_status,printed_counts),
 Variant('zokyo/v2021_status_cards',Fingerprint((('risk_status',r'^\s*(?:\d+\s+)?'+RISK+r'\s+'+STATUS+r'\s*$',10),),('2021','2024')),status_cards,('zokyo_status',),remediation_status,printed_counts),
 Variant('zokyo/v2020_title_first',Fingerprint((('bare_risk',r'^\s*(?:[—–|7]+\s*)?'+RISK+r'\s*$',6),('analysis',r'Complete[\s\u200b]*Analysis',2)),('2020','2022')),title_first_cards,('zokyo_title_first',),remediation_status,printed_counts),
 Variant('zokyo/v2021_metadata',Fingerprint((('metadata',r'^\s*Severity\s+'+RISK+r'\s*$|'+RISK+r'(?: severity)?,\s*'+STATUS+r':|Results from Manual analysis|VULNERABILITIES DETAILS AND MITIGATIONS',11),),('2020','2026')),metadata_cards,('zokyo_metadata',),remediation_status,printed_counts),
)


def summary_inventory_counts(report):
    """Independent complete, numbered front index; never reads detail cards."""
    pages=_summary_pages(report);entries=[];proof=[]
    for line in report.lines:
        if line.page not in pages or len(line.text)>600:continue
        text=_text(line.content)
        ordinal=re.match(r"^(\d+)\s+\S",text)
        risk=re.search(r"\b("+RISK+r")\s+("+STATUS+r")\s*$",text,re.I)
        if ordinal and risk:
            entries.append((int(ordinal[1]),risk[1]))
            proof.append({'page':line.page,'start':line.start,'end':line.end,'text':report.text[line.start:line.end]})
    ids=[n for n,_ in entries]
    if not ids or len(ids)!=len(set(ids)) or sorted(ids)!=list(range(1,max(ids)+1)):return None
    counts=Counter(severity(raw,report.firm) for _,raw in entries)
    return {'counts':dict(counts),'basis':'complete_numbered_publisher_summary_index','evidence':proof}

VARIANTS += (Variant('zokyo/v2024_sectioned_findings',Fingerprint((('sectioned',r'^\s*Detailed Findings\s*$',8),)),metadata_cards,('zokyo_sectioned',),remediation_status,printed_counts),)
VARIANTS += (Variant('zokyo/v2021_outcome_only',Fingerprint((('outcome',r'There were no critical issues found during the audit\.',4),('publisher',r'zokyo',2))),clean_report,('zokyo_outcome',)),)
VARIANTS += (Variant('zokyo/v2021_image_badges',Fingerprint((('status_legend',r'Issues\s+are\s+tagged|Issues\s+are.*\n.*tagged',4),('analysis',r'Complete\s*Analysis',3))),image_badges,('zokyo_image_badges',),remediation_status,printed_counts),)
VARIANTS += (Variant('zokyo/v2022_ocr_badges',Fingerprint((('damaged_badge',r'^[ \t]*[^\n]{1,7}(?:CRITICAL|HIGH|MEDIUM|LOW|INFO(?:RMATIONAL)?)\s*[-–]\s*\d+(?:\.\d+)*(?:[A-Za-z]{1,12})?\s*$',9),('analysis',r'Complete\s*Analysis',3))),numbered_cards,('zokyo_ocr_numbered',),remediation_status,printed_counts,
    notes='OCR-backed numbered cards with a fused icon or pale status suffix; require a complete risk/ID and preserve damaged status as unknown.'),)
