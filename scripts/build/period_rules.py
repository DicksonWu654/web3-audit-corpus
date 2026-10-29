"""Source-local initial-work periods and semantic corrections, with exact receipts.

No filename, collector hint, crawl date or verification label supplies an anchor.
"""
from datetime import date, datetime, timedelta
import re
import unicodedata


def source_periods(text, receipt, existing):
    from metadata_rules import MONTH, parse_date, sha
    from date_rules import HISTORY, RETEST
    # Preserve character offsets through typography/format noise and known
    # month spelling variants. Parsing normalizes spelling only after capture.
    month = MONTH.replace('Feb(?:ruary)?', 'Feb(?:ruary|urary)?')
    day = r'\d{1,2}(?:st|nd|rd|th)?'
    named = rf'(?:{month}\s+{day}|(?:the\s+)?{day}\s+(?:of\s+)?{month})(?:\s*,?\s*20\d{{2}})?'
    numeric = r'(?:20\d{2}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[./-]\d{1,2}[./-]{1,2}20\d{2})'
    endpoint = rf'(?:{numeric}|{named})'
    pair = re.compile(rf'(?P<a>{endpoint}|(?:the\s+)?{day})\s*(?:[-–—]|to|through|until|and)\s*(?P<b>{endpoint}|(?:the\s+)?{day}(?:\s*,?\s*20\d{{2}})?)',re.I)
    masked = text.translate({ord(c):' ' for c in set(text) if unicodedata.category(c)=='Cf' or c=='('})
    claims=[]
    issues=[c for c in existing if c.get('date_value') and c['role']=='report_issue' and c.get('confidence',0)>=.8 and c.get('basis')=='document_text' and c.get('method')!='llm']
    anchor_claim=max(issues,key=lambda c:c['date_value']) if issues else None
    anchor=anchor_claim['date_value'] if anchor_claim else None

    def emit(value, role, method, lo, hi, raw):
        if not value: return
        value, precision=parse_date(value)
        if not value: return
        claims.append(dict(raw_value=raw,date_value=value,precision=precision,role=role,basis='document_text',
                           method=method,confidence=.97,evidence=text[lo:hi],text_start=lo,text_end=hi,
                           text_sha256=receipt.get('text_sha256') or sha(text.encode()),
                           text_source=receipt.get('source','local-cache/text'),
                           page=text[:lo].count('\f')+1 if isinstance(receipt.get('pages'),list) else None))
        if anchor_claim and not re.search(r'20\d{2}',text[lo:hi]):
            claims[-1]['year_anchor']={k:anchor_claim.get(k) for k in ['date_value','method','evidence','text_start','text_end','text_sha256','text_source','page']}
            claims[-1]['year_anchor']['year_offset']=int(value[:4])-int(anchor[:4])

    def parse_endpoint(raw, year=None, order=None, inherited_month=None):
        s=re.sub(r'(?<=\d)(?:st|nd|rd|th)\b','',raw,flags=re.I)
        s=re.sub(r'\b(?:of|the)\s+','',s,flags=re.I).replace('Feburary','February').replace('feburary','February')
        s=re.sub(r'-{2,}','-',s).strip()
        if inherited_month and re.fullmatch(r'\d{1,2}(?:\s*,?\s*20\d{2})?',s): s=inherited_month+' '+s
        if not re.search(r'20\d{2}',s) and year: s+=' '+str(year)
        if order:
            try:
                return datetime.strptime(s.replace('/','-').replace('.','-'),order).date().isoformat()
            except ValueError: pass
        return parse_date(s)[0]

    spans=[]
    for m in pair.finditer(masked):
        if '\f' in m[0]: continue
        lo=max(masked.rfind('\n',0,m.start())+1,masked.rfind('\f',0,m.start())+1)
        hi=min([p for p in [masked.find('\n',m.end()),masked.find('\f',m.end())] if p>=0] or [len(text)])
        # A wrapped period can carry its label on two preceding short lines.
        for _ in range(2):
            prev=max(masked.rfind('\n',0,max(0,lo-1))+1,masked.rfind('\f',0,m.start())+1)
            head=masked[prev:lo]
            if prev==lo or len(head)>200 or re.search(r'20\d{2}|\n\s*\n',head): break
            lo=prev
        context=masked[lo:hi]
        # Stop at sentence boundaries; a following retest sentence cannot
        # reinterpret the initial work on the same physical extraction line.
        breaks=list(re.finditer(r'(?<=[.!?])\s+(?=[A-Z])',context))
        for br in breaks:
            if lo+br.end()<=m.start(): lo=lo+br.end(); break
            if lo+br.start()>=m.end(): hi=lo+br.start(); break
        context=masked[lo:hi]
        low=re.sub(r'\s+',' ',context)
        period=bool(re.search(r'\b(?:audit(?:ed)?|review(?:ed)?|assessment|testing|test|engagement)\b.{0,250}\b(?:from|between|period|timeline|dates|conducted|performed|took place)|\b(?:period|timeline)\b|\bdates\s*[:| ]|\b(?:initial\s+)?(?:code\s+)?review\s*\)?\s*(?:completed|\(completed)|(?:audit|review)\s+was\s+performed|\b(?:competitions?|contests?)\b',low,re.I))
        # Source timeline rows often put the phase *after* the two dates.
        initial=bool(re.search(r'\b(?:initial\s+(?:code\s+)?review|code\s+review)\b',low,re.I))
        round_period=bool(re.search(r'\bround\s+\d+',low,re.I) and re.search(r'audit|engagement|review',masked[max(0,lo-1500):hi],re.I))
        period=period or initial or round_period or bool(re.search(r'\bdate\b',low,re.I) and re.search(r'audit|engagement|review',masked[max(0,lo-1000):lo],re.I))
        if not period: continue
        history=HISTORY.search(low) or re.search(r'code\s+versions?|when\s+they\s+were\s+received|code\s+(?:receipt|delivery)|commit\s+hash',low,re.I)
        later=bool(RETEST.search(low) or re.search(r'mitigation|verification\s+review|revision\s+(?:review|audit)|\bre[- ]audit(?:ed)?\b|\bre[- ]review(?:ed)?\b|review\s+of\s+(?:the\s+)?(?:fixes|revisions)',low,re.I))
        if history and not initial: continue
        ra,rb=m['a'],m['b']
        years=re.findall(r'20\d{2}',ra+' '+rb)
        year=int(years[-1]) if years else int(anchor[:4]) if anchor else None
        if not year: continue
        order=None; numeric_ambiguous=False
        nums=[re.fullmatch(r'(\d{1,2})[./-](\d{1,2})[./-]{1,2}(20\d{2})',s) for s in [ra,rb]]
        if all(nums):
            possible=[]
            for fmt in ['%d-%m-%Y','%m-%d-%Y']:
                try:
                    a,b=[datetime.strptime(re.sub(r'-{2,}','-',s.replace('/','-').replace('.','-')),fmt).date() for s in [ra,rb]]
                    if a<=b: possible.append((fmt,a.isoformat(),b.isoformat()))
                except ValueError: pass
            unique={(a,b) for _,a,b in possible}
            if len(unique)==1: order=possible[0][0]
            numeric_ambiguous=len(unique)>1
        ma=re.search(month,ra,re.I); mb=re.search(month,rb,re.I)
        a=parse_endpoint(ra,year,order,mb[0] if mb else None)
        b=parse_endpoint(rb,year,order,ma[0] if ma else None)
        if not b:
            # Pair has explicit years but neither numeric ordering is proven.
            if numeric_ambiguous and years and len(set(years))==1: b=years[0]
            else: continue
        if not years:
            if not anchor or len(b)!=10: continue
            # No October of the previous year inferred from a March dateline.
            # A December-to-January start can wrap, but the endpoint must fit
            # the current issue year and precede its date at stated precision.
            if b[:len(anchor)]>anchor: continue
        reversed_period=a and len(a)==len(b)==10 and a>b and bool(re.search(r'20\d{2}',ra))
        role='other' if reversed_period else 'retest' if later else 'audit_completion'
        method='source_reversed_work_period' if reversed_period else 'source_numbered_initial_round' if round_period and not later else 'source_initial_review_period' if initial else 'source_numeric_pair_order' if order else 'source_anchored_yearless_period' if not years else 'source_explicit_work_period'
        emit(b,role,method,lo,hi,text[m.start():m.end()])
        spans.append((lo,hi,b,role,method))
        if a:
            if len(a)==10 and len(b)==10 and a>b and not re.search(r'20\d{2}',ra):
                a=parse_endpoint(ra,int(b[:4])-1,order)
            emit(a,'other' if reversed_period else 'retest' if later else 'audit_start',method,lo,hi,text[m.start():m.end()])

    # Single timeline endpoints (Zellic), explicit debriefs (delivery of the
    # completed audit), and start/finished prose are semantically completion.
    from metadata_rules import DATE
    for m in DATE.finditer(masked):
        lo=max(masked.rfind('\n',0,m.start())+1,masked.rfind('\f',0,m.start())+1)
        hi=min([p for p in [masked.find('\n',m.end()),masked.find('\f',m.end())] if p>=0] or [len(text)])
        context=masked[lo:hi]
        if HISTORY.search(context) or RETEST.search(context): continue
        if re.search(r'end\s+of\s+(?:the\s+)?primary\s+review\s+period',context,re.I):
            # A later extension/new mechanism is not the initial work period.
            if re.search(r'period\s+for\s+\w',context,re.I): continue
            emit(m[0],'audit_completion','source_primary_review_endpoint',lo,hi,m[0])
        elif re.search(r'(?:final\s+)?debrief\s+(?:was\s+|took\s+place\s+)?(?:on|date|:)|\bfinished\s+on\b',context,re.I):
            emit(m[0],'audit_completion','source_finished_or_debrief',lo,hi,m[0])
        elif re.search(r'latest\s+audit\s+report',context,re.I):
            emit(m[0],'report_issue','report_revision_current_field',lo,hi,m[0])
    # A completed, retrospective work statement with a stated start and bounded
    # duration supports a year only if the entire possible duration is in it.
    for m in re.finditer(r'Starting\s+on\s+('+DATE.pattern+r')[^\f]{0,180}?\b(?:have\s+audited|audited)[^\f]{0,100}?\b(?:during|for)\s+(\d+|one|two|three|four|five|six|seven|eight)\s+weeks?\b',masked,re.I):
        start=parse_date(m[1])[0]
        words={'one':1,'two':2,'three':3,'four':4,'five':5,'six':6,'seven':7,'eight':8}
        weeks=int(m[2]) if m[2].isdigit() else words[m[2].lower()]
        # Use the duration solely to establish a year bound, never to invent
        # a completion day. A cross-year duration supplies no completion year.
        if start and len(start)==10 and weeks<=52 and (date.fromisoformat(start)+timedelta(weeks=weeks)).year==int(start[:4]):
            emit(start[:4],'audit_completion','source_completed_work_year',m.start(),m.end(),m[0])
    # Several explicit initial intervals in one statement describe one work
    # period. The last endpoint closes it; separate contradictory statements
    # remain independent claims.
    grouped={}
    for lo,hi,value,role,method in spans:
        if role=='audit_completion': grouped[(lo,hi)]=max(value,grouped.get((lo,hi),value))
    for c in claims:
        key=(c['text_start'],c['text_end'])
        if c['role']=='audit_completion' and key in grouped and c['date_value']!=grouped[key]:
            c.update(role='other',confidence=.4,resolution='intermediate_initial_work_interval')
    spans=[(lo,hi,grouped.get((lo,hi),value) if role=='audit_completion' else value,role,method) for lo,hi,value,role,method in spans]
    rounds=[value for lo,hi,value,role,method in spans if role=='audit_completion' and method=='source_numbered_initial_round']
    if rounds:
        last=max(rounds)
        for c in claims:
            if c['method']=='source_numbered_initial_round' and c['role']=='audit_completion' and c['date_value']!=last:
                c.update(role='other',confidence=.4,resolution='intermediate_initial_work_round')
        spans=[(lo,hi,last if method=='source_numbered_initial_round' and role=='audit_completion' else value,role,method) for lo,hi,value,role,method in spans]
    return claims,spans


def reconcile_source_periods(claims, sources):
    """Keep rejected claims with explicit semantic reasons, never erase evidence."""
    additions=[]; spans=[]
    for c in claims:
        quote=str(c.get('evidence') or '')
        surroundings=quote
        for payload,info in sources:
            if c.get('text_sha256')==info.get('text_sha256'):
                pos=c.get('text_start')
                if pos is not None:
                    # A PDF signature often wraps the signer and Date field,
                    # with blank extraction rows in between.
                    lo=max(payload.rfind('\f',0,pos)+1,pos-400)
                    surroundings=payload[lo:c.get('text_end',pos)]
                    break
        compact=re.sub(r'\s+','',surroundings).lower()
        reason=None; role='other'
        if 'digitally' in compact or re.search(r'digitalsign|signedby|signedon|signature[:|().-]{0,5}(?:date|timestamp|time)',compact): reason='signature_is_not_issue'
        elif c['role']=='report_issue' and re.search(r'version\s+of\s+(?:the\s+)?(?:language|compiler|software)|(?:language|compiler)\s+was\s+released',quote,re.I):
            reason='software_release_is_not_report_issue'
        elif c.get('raw_value') and any(c['raw_value'] in line and re.search(r'start\s+of\s+(?:the\s+)?(?:primary\s+)?review',line,re.I) for line in quote.splitlines()):
            reason='source_start_of_primary_review';role='audit_start'
        elif re.search(r'code\s+versions?\s+relevant|when\s+they\s+were\s+received|initial\s+(?:code\s+)?(?:receipt|delivery)|code\s+received',quote,re.I): reason='code_receipt_is_not_completion'
        elif re.search(r'\b(?:previous|prior|earlier)\b.{0,100}\b(?:audit|review|assessment)\b',quote,re.I): reason='prior_audit_context'
        elif c['role']=='audit_completion' and re.search(r'\bengaged\b',quote,re.I) and not re.search(r'\b(?:to|through|until|between|from)\s+(?:\d|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)|\b(?:end|complet|finish)',quote,re.I):
            reason='commissioning_is_start'; role='audit_start'
        elif c['role']=='audit_completion' and re.search(r'end\s+of\s+(?:the\s+)?primary\s+review\s+period\s+for\b',quote,re.I):
            reason='later_scope_extension'; role='other'
        if reason:
            c.setdefault('original_role',c['role']); c.update(role=role,confidence=.4,resolution=reason)
    # Sanitize possible anchors before resolving omitted years. In particular,
    # a signature timestamp on a later day/year must never supply the anchor.
    for text,receipt in sources:
        new,ss=source_periods(text,receipt,claims)
        additions.extend(new)
        spans.extend((receipt.get('text_sha256'),*s) for s in ss)
    for c in claims:
        quote=str(c.get('evidence') or '')
        reason=None; role='other'
        for text_hash,lo,hi,value,period_role,method in spans:
            if (c.get('text_sha256')==text_hash and c.get('text_start') is not None and
                lo<=c['text_start']<hi and c['role'] in {'audit_completion','report_issue'}):
                if period_role=='other': reason='source_reversed_work_period'; role='other'
                elif period_role=='retest': reason='explicit_later_review_period'; role='retest'
                elif c['role']=='audit_completion' and c.get('date_value')!=value:
                    if value.startswith(c.get('date_value') or '!'): reason='pair_establishes_more_precise_endpoint'
                    else: reason='period_start_or_misparsed_endpoint'
        # LLM dates are evidence proposals, not authority to invent a year or
        # promote a start. Deterministic source-local evidence must support a
        # yearless completion proposal; the original assertion stays retained.
        if c.get('method')=='llm' and c['role']=='audit_completion' and c.get('date_value'):
            from metadata_rules import DATE
            explicit=any(c['date_value'][:4] in m[0] for m in DATE.finditer(quote))
            supported=any(n['role']=='audit_completion' and n['date_value']==c['date_value'] for n in additions)
            if not explicit and not supported: reason='unsupported_completion_year_anchor'
        if reason:
            c.setdefault('original_role',c['role']); c.update(role=role,confidence=.4,resolution=reason)
    claims.extend(additions)
    return claims
