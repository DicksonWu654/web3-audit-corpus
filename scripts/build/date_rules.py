"""Source-local date semantics, full-text/OCR receipts and date resolution.

All evidence uses half-open offsets into a hash-verified text cache. Unrelated
history and separate retests stay distinct from the initial engagement endpoint.
"""
import json
from pathlib import Path
import re
import unicodedata


def load_date_text(root, digest, fallback, receipt):
    from metadata_rules import sha
    if not digest or not re.fullmatch(r'[a-f0-9]{64}', digest):
        return fallback, receipt
    for folder in ['local-cache/date-text', 'local-cache/fulltext']:
        base = Path(root)/folder/digest
        txt, pages = base.with_suffix('.txt'), base.with_suffix('.pages.json')
        if txt.exists() and pages.exists():
            text = txt.read_text()
            info = json.loads(pages.read_text())
            if sha(text.encode()) == info.get('text_sha256'):
                return text, dict(method=info.get('method'), text_sha256=info['text_sha256'],
                                 pages=list(range(1,len(text.split('\f'))+1)) if info.get('file_format')=='pdf' else None,
                                 source=folder, status=info.get('status'),
                                 html_metadata_dates=info.get('html_metadata_dates',[]))
    return fallback, receipt


# Labels are deliberately bounded to a line/nearby value, never an entire paragraph
# that happens to mention an audit and a date of a prior report or code change.
PERIOD = re.compile(r'(?:audit|assessment|review|engagement|testing?)\s*(?:time\s*)?(?:period|window|timeline|dates?|duration)|date\s+of\s+(?:the\s+)?engagement|\bstarted\s+delivered\b|\btime\s+(?:period|frame)|\btimeline\b|\bperiod\s+from|(?:conducted|performed|undertaken|undertook\s+(?:the\s+)?work|took place|carried out).{0,130}?(?:between|from|over|\bon\b)|(?:audit|assessment|review).{0,100}\b(?:between|from)\b', re.I)
COMPLETION = re.compile(r'(?:audit|review|assessment|engagement|test)\s*(?:(?:was|were)\s+)?(?:end(?:ed)?|complet(?:ed|ion)|finish(?:ed)?)|\bend(?:ing)?\s*date|\bcompleted\s*(?:on|at|:)|\b(?:audit|assessment|review).{0,100}\bending\b', re.I)
START = re.compile(r'(?:audit|review|assessment|engagement|test)\s*(?:(?:was|were)\s+)?(?:start(?:ed|ing)?|began|begin(?:ning)?)|\bstart\s*date', re.I)
RETEST = re.compile(r're[- ]?test|fix(?:es)?[- ]*(?:review|verification)|remediation|confirmation of (?:the )?patches|fixing\s+(?:period|round)|verification of (?:the )?fixes', re.I)
PUBLICATION = re.compile(r'publication|\bpublished\b|public(?:ly)?\s+releas|\breleased\s+(?:on|date|:)|\bposted\s+(?:on|:)', re.I)
ISSUE = re.compile(r'report\s*date|date\s+of\s+(?:the\s+)?report|report\s+(?:issued|delivered)|\bissued\s*(?:on|:)|\bdelivered\s*[:|]|\bdelivery\s+date|\bfinal\s+report|\blast\s+revised|\breport\s+version', re.I)
HISTORY = re.compile(r'previous\s+(?:audit|assessment|review|report)|prior\s+(?:audit|assessment|review|report)|earlier\s+(?:audit|assessment|review|report)|(?:original|previous|prior)\s+engagement|code\s+changes?|commit\s+(?:date|history)|git\s*(?:log|history)|audit\s+application|audit\s+request|copyright|©|all rights reserved|retrieved|generated\s+on|accessed|downloaded|digitally\s+signed|digital\s+signature|signature\s+date|^signed\s*(?:by|on)', re.I)


def extended_date_claims(text, receipt):
    from metadata_rules import DATE, MONTH, SHORT_PERIOD, parse_date, clean, sha
    claims, seen = [], set()
    text_hash = receipt.get('text_sha256') or sha(text.encode())

    def emit(raw, value, role, method, start, end, page, confidence=.94):
        value, precision = parse_date(value)
        # Unknown numeric order supports only the common year, never an invented day.
        if not value:
            m = re.fullmatch(r'(\d{1,2})[./-](\d{1,2})[./-](20\d{2})', raw.strip())
            if m and 1 <= int(m[1]) <= 12 and 1 <= int(m[2]) <= 12:
                value, precision = parse_date(m[3])
        key = (value or raw, role, start, end)
        if key in seen: return
        seen.add(key)
        claims.append(dict(raw_value=raw, date_value=value, precision=precision, role=role,
                           basis='document_text', method=method, confidence=confidence,
                           page=page if isinstance(receipt.get('pages'), list) else None,
                           evidence=text[start:end], text_start=start, text_end=end,
                           text_sha256=text_hash, text_source=receipt.get('source','local-cache/text')))

    offset = 0
    format_spaces={ord(c):' ' for c in set(text) if unicodedata.category(c)=='Cf'}
    for page, original_body in enumerate(text.split('\f'),1):
        # Same-length masking preserves offsets into the original text receipt.
        body=original_body.translate(format_spaces)
        lines = list(re.finditer(r'[^\n]+?(?:[.!?](?=[ \t]+[A-Z])|(?=\n|$))', body))
        for i, line in enumerate(lines):
            s = line[0]
            # Most report lines are findings/code, without a calendar year.
            # Only a semantic label adjacent to a year needs wrapped parsing.
            if not re.search(r'20\d{2}|2\s+0\s+\d\s+\d',s):
                if not re.search(r'audit|assessment|review|engagement|date|period|timeline|conducted|performed|completed|issued|delivered|审计',s,re.I):
                    continue
                if not any(re.search(r'20\d{2}',n[0]) for n in lines[i+1:i+5]):
                    continue
            # A date on the value row may use the adjacent label. Do not drag a
            # previous dated row, unrelated heading or prior paragraph into it.
            start, end = line.start(), line.end()
            prev = lines[i-1][0] if i else ''
            if i and not DATE.search(prev) and len(prev)<180 and (re.search(r'(?:date|period|timeline|completed|delivered|issued|published|revision|assessment|version|review)\s*[:|*]*\s*$',prev,re.I) or PERIOD.search(prev)):
                start = lines[i-1].start()
            local = body[start:end]
            # Join wrapped values, prose and table columns only when a semantic
            # label has not yet got both endpoints. Max four short continuation rows.
            if (PERIOD.search(local) or COMPLETION.search(local) or START.search(local) or ISSUE.search(local)
                or re.search(r'(?:audit|review|assessment).{0,80}(?:conducted|performed)\s*$',local,re.I)):
                for nxt in lines[i+1:i+5]:
                    tail = body[end:nxt.end()]
                    if len(tail)>250 or ('\n\n' in tail and DATE.search(local)) or (DATE.search(local) and not re.match(r'^\s*(?:[|*\s]*(?:to|and|through|until|[-–—])\b|\d|'+MONTH+r')',nxt[0],re.I)):
                        break
                    if re.match(r'^\s*(?:#{1,6}\s|\d+\.\s+[A-Z])',nxt[0]): break
                    end = nxt.end()
                    local = body[start:end]
                    if len(list(DATE.finditer(local)))>=2: break
            low = clean(local).replace('_',' ')
            matches = [m for m in DATE.finditer(local)
                       if not any(a<=m.start()<b for a,b in (u.span() for u in re.finditer(r'https?://\S+',local)))]
            # A labelled source year is valid at year precision; bare copyright
            # and footer years never enter this path.
            if not matches and (COMPLETION.search(local) or ISSUE.search(local) or re.search(r'audit\s+date',local,re.I)):
                matches=list(re.finditer(r'(?<!\d)20\d{2}(?!\d)',local))
            # Keep Chinese dates with their source-localized semantic label.
            if re.search(r'审计时间|审计日期|审计周期',local):
                zh = list(re.finditer(r'(20\d{2})\s*年\s*(\d{1,2})\s*月\s*(\d{1,2})\s*日',local))
                for j,m in enumerate(zh):
                    emit(m[0],f'{m[1]}-{int(m[2]):02}-{int(m[3]):02}', 'audit_start' if j==0 and len(zh)>1 else 'audit_completion', 'chinese_labelled_audit_date',offset+start,offset+end,page)
                for j,m in enumerate(matches if not zh else []):
                    emit(m[0],m[0], 'audit_start' if j==0 and len(matches)>1 else 'audit_completion','chinese_labelled_audit_date',offset+start,offset+end,page)
                continue
            if re.search(r'(?m)^\s*(?:title|description):|github\s*:|gitlab\s*:|^\s*[a-f0-9]{7,40}\s+20\d{2}',local,re.I):
                continue
            if HISTORY.search(low):
                # Preserve an explicit date as non-eligible history where possible.
                for m in matches: emit(m[0],m[0],'other','unrelated_history_or_signature',offset+start,offset+end,page,.4)
                continue
            short = SHORT_PERIOD.search(local)
            semantic_period = bool(PERIOD.search(low) or re.search(r'(?:audit|assessment|review).{0,80}(?:conducted|performed)',low,re.I)
                                   or re.match(r'\s*(?:[•*| -]*)dates\s*[:| ]',local,re.I) and re.search(r'engagement\s+summary|executive\s+summary|audit\s+details',body[max(0,start-1600):end],re.I))
            if short and semantic_period:
                for month,day,role in [(short[1],short[2],'audit_start'),(short[3] or short[1],short[4],'audit_completion')]:
                    emit(short[0],f'{month} {day} {short[5]}', 'retest' if RETEST.search(low) else role,'fulltext_shared_year_period',offset+start,offset+end,page)
                continue
            # A publisher-stated duration can resolve numeric ordering for the
            # *pair*. Otherwise preserve only the year for ambiguous endpoints.
            pair_values={}
            duration=re.search(r'\b(\d+)\s+(?:calendar\s+)?days?\b',low,re.I)
            if duration and len(matches)==2 and semantic_period:
                from datetime import datetime
                possibilities=[]
                for fmt in ['%d-%m-%Y','%m-%d-%Y']:
                    try:
                        a,b=[datetime.strptime(m[0].replace('/','-').replace('.','-'),fmt).date() for m in matches]
                        if (b-a).days in {int(duration[1]),int(duration[1])-1}:
                            possibilities.append((a.isoformat(),b.isoformat()))
                    except ValueError: pass
                if len(set(possibilities))==1:
                    pair_values=dict(enumerate(possibilities[0]))
            # Source-explicit revision tables, including rows on later pages.
            before = body[max(0,start-1800):start]
            revision = bool(re.search(r'revision\s+history|version\s+history|document\s+history|change\s*log|report\s+revisions', before, re.I)
                            and re.search(r'\b(?:\d+\.\d+|initial|final|draft|document review|revis(?:ed|ion))\b',local,re.I)
                            and not re.search(r'\b(?:commit|git|code changes)\b',local,re.I))
            role, method, confidence = 'other','unlabelled_date',.45
            if PUBLICATION.search(low): role,method,confidence='publication','fulltext_publication_label',.97
            elif RETEST.search(low): role,method,confidence='retest','fulltext_retest_label',.96
            elif COMPLETION.search(low): role,method,confidence='audit_completion','fulltext_completion_label',.97
            elif START.search(low) and not (semantic_period and len(matches)>1): role,method,confidence='audit_start','fulltext_start_label',.97
            elif semantic_period:
                explicit_endpoint=matches and re.search(r'\b(?:to|through|until)\s*'+re.escape(clean(matches[0][0])),low,re.I)
                if len(matches)>1 or explicit_endpoint or re.search(r'\bon\b|audit\s+date\s*[:|]|\bending\b',low,re.I):
                    role,method,confidence='audit_completion','fulltext_audit_period',.96
            elif revision: role,method,confidence='report_issue','report_revision_table',.95
            elif ISSUE.search(low): role,method,confidence='report_issue','fulltext_issue_label',.95
            elif re.search(r'(?i)\b(?:report\s+)?(?:version|revision)\s*[:|]?\s*v?\d',local) and page<=3:
                role,method,confidence='report_issue','report_revision_date',.88
            elif page<=3 and re.match(r'^\s*(?:\*{0,2})?date\s*[:|* ]',s,re.I): role,method,confidence='report_issue','cover_date_field',.94
            elif page==1 and line.start()<2500 and re.search(r'(?:security|code)\s+(?:review|audit|assessment)\s*[·:|–—-]',s,re.I):
                role,method,confidence='report_issue','dated_review_heading',.9
            elif page<=3 and re.search(r'prepared for',low,re.I): role,method,confidence='report_issue','prepared_for_dated_heading',.85
            elif page<=3 and re.search(r'(?:audit|project|security) report.{0,100}'+(re.escape(matches[0][0]) if matches else r'(?!)'),s,re.I):
                role,method,confidence='report_issue','dated_report_heading',.9
            elif matches and page==1 and line.start()<3000 and not isinstance(receipt.get('pages'),list) and re.search(r'(?m)^#{1,2} .*(?:audit|review)|\b(?:Security|Smart Contract)\s+(?:Audit|Review|Assessment)\b',body[:line.start()],re.I) and not HISTORY.search(prev):
                # Native HTML/Markdown reports have a logical page containing
                # the entire report. Its length cannot disqualify the dateline.
                residue=clean(DATE.sub('',s)).strip(' ,|.()[]-')
                first=DATE.match(s.strip())
                duplicate=first and DATE.fullmatch(s.strip()[first.end():].strip())
                if not residue or duplicate:
                    role,method,confidence='report_issue','native_report_dateline',.9
            elif matches and page==1 and line.start()<3500 and len(body)<10000 and not re.search(r'contents|disclaimer|references|findings',body[:line.start()],re.I):
                residue=clean(DATE.sub('',s)).strip(' ,|.()[]-')
                first=DATE.match(s.strip())
                duplicate=first and DATE.fullmatch(s.strip()[first.end():].strip())
                if not residue or duplicate or re.fullmatch(r'(?:v\.?|version|revision)\s*\d+(?:\.\d+)*',residue,re.I) or re.fullmatch(r'(?:[\w-]+\.)+[A-Za-z]{2,}',residue) and re.search(r'\b(?:audit|review|report|assessment)\b',body[:line.start()],re.I):
                    if len(matches)==2 and not duplicate:
                        role,method,confidence='audit_completion','cover_period',.85
                    else: role,method,confidence='report_issue','fulltext_cover_issue',.85
            elif matches and 1<page<=3 and line.start()<1400 and len(body)<2200 and not clean(DATE.sub('',s)) and re.search(r'\b(?:audit|security\s+(?:review|assessment))\b',body[:line.start()],re.I) and not re.search(r'contents|disclaimer|references|findings|executive\s+summary|introduction',body,re.I):
                role,method,confidence='report_issue','inner_title_page_dateline',.85
            # Standalone letterspaced and typographic cover dates.
            if not matches and page==1:
                compact=re.sub(r'\s+','',s)
                cover=re.fullmatch('('+MONTH+r')(\d{1,2})(?:st|nd|rd|th)?[,]?(20\d{2})(?:[–—-]Preparedby[A-Za-z]+)?',compact,re.I)
                masthead=re.fullmatch(r'(?:SECURITY|CODE)(?:REVIEW|AUDIT|ASSESSMENT)[·:|–—-]('+MONTH+r')(20\d{2})',compact,re.I)
                apostrophe=re.fullmatch('('+MONTH+r')\s*[‘’\x27`]\s*(20\d{2})',s.strip(),re.I)
                if cover: emit(s,f'{cover[1]} {cover[2]} {cover[3]}','report_issue','letterspaced_cover_date',offset+line.start(),offset+line.end(),page)
                elif masthead: emit(s,f'{masthead[1]} {masthead[2]}','report_issue','letterspaced_report_masthead',offset+line.start(),offset+line.end(),page)
                elif apostrophe: emit(s,f'{apostrophe[1]} {apostrophe[2]}','report_issue','typographic_cover_date',offset+line.start(),offset+line.end(),page)
            for j,m in enumerate(matches):
                this_role=role
                if role=='audit_completion' and len(matches)>1:
                    # Timeline endpoint pairs: start never competes with completion.
                    if method=='cover_period' or semantic_period or START.search(low) or re.search(r'\bbegin(?:ning)?\b.*\bending\b',low,re.I):
                        this_role='audit_start' if j==0 else 'audit_completion'
                emit(m[0],pair_values.get(j,m[0]),this_role,'duration_resolved_numeric_period' if pair_values else method,offset+start,offset+end,page,confidence)
        offset += len(body)+1
    for raw in receipt.get('publication_dates',[]):
        # HTML metadata remains independently labelled publication evidence.
        value,precision=parse_date(raw[:10])
        claims.append(dict(raw_value=raw,date_value=value,precision=precision,role='publication',basis='document_text',method='html_publication_meta',confidence=.99,page=None,evidence='HTML article:published_time/date metadata'))
    from date_layout_rules import layout_date_claims
    for c in layout_date_claims(text, receipt):
        # Keep a distinct control-table rule even when a generic line parser
        # found it: its explicit revision semantics participate in resolution.
        if 'revision' not in c['method'] and any(
            o.get('date_value')==c['date_value'] and o['role']==c['role']
            and o.get('text_start') is not None and o['text_start']<=c['text_start']
            and o['text_end']>=c['text_end'] for o in claims):
            continue
        claims.append(c)
    return claims


def supplement_opening_dates(text, receipt, claims):
    """Preserve supported opening-layout evidence with current semantic guards.

    Native PDF sort order and complete-layout extraction can differ. Retaining
    both receipts prevents an alternate extraction layout from erasing evidence.
    """
    from metadata_rules import opening_date_claims, sha
    current={(c['date_value'],c['role']) for c in claims if c['date_value']}
    for old in opening_date_claims(text,receipt):
        if not old['date_value'] or old['confidence']<.8: continue
        if (old['date_value'],old['role']) in current: continue
        raw=old['raw_value']
        occurrences=list(re.finditer(re.escape(raw),text))
        if not occurrences: continue
        if old.get('page'):
            occurrences=[m for m in occurrences if text[:m.start()].count('\f')+1==old['page']]
        if not occurrences: continue
        m=occurrences[0]
        start=max(text.rfind('\n',0,m.start())+1,text.rfind('\f',0,m.start())+1)
        end=text.find('\n',m.end());end=end if end>=0 else len(text)
        prev_start=max(text.rfind('\n',0,max(0,start-1))+1,text.rfind('\f',0,m.start())+1)
        context=text[prev_start:end]
        if HISTORY.search(context) or PUBLICATION.search(context) or RETEST.search(context): continue
        role=old['role']
        if role=='audit_completion' and START.search(context) and not COMPLETION.search(context):
            role='audit_start'
        # A generic Date/cover rule must not overrule a source-local semantic
        # start/retest/publication interpretation of the same calendar value.
        if role=='report_issue' and not ISSUE.search(context) and any((old['date_value'],r) in current for r in ['audit_start','retest','publication']):
            continue
        if (old['date_value'],role) in current: continue
        claims.append(dict(old,role=role,method='opening_layout_'+old['method'],
                           evidence=context,text_start=prev_start,text_end=end,
                           text_sha256=receipt.get('text_sha256') or sha(text.encode()),
                           text_source=receipt.get('source','local-cache/text')))
        current.add((old['date_value'],role))
    return claims


def resolve_dates(b):
    """Keep source claims, demote superseded revisions/coarse duplicates explicitly.

    Emit a single resolved date/precision only when all preferred evidence agrees.
    Genuine contradictions retain eligibility and the existing year-conflict rule.
    """
    from collections import defaultdict
    claims=defaultdict(list)
    links={d['document_id']:d for d in b.tables['engagement_documents'].values()}
    docs=b.tables['documents']
    for c in b.tables['date_claims'].values():
        link=links.get(c['document_id'])
        if link and docs[c['document_id']]['doc_kind']=='fix_review' and c['role'] in {'audit_start','audit_completion','report_issue'}:
            c['evidence']['phase3c_original_role']=c['role']
            c.update(role='retest',eligible_for_audit_year=False)
        eid=c['engagement_id'] or (link['engagement_id'] if link else None)
        if eid and c['eligible_for_audit_year']: claims[eid].append(c)
    def demote(c,reason):
        c['eligible_for_audit_year']=False
        c['evidence']['phase3c_resolution']=reason
    for eid,e in b.tables['engagements'].items():
        eligible=claims[eid]
        # A publisher-assigned report number or source-supported revision edge
        # can span separate artifacts. Current issue dates supersede older
        # editions, while initial completion claims retain priority.
        member_docs=[docs[d] for d in e['evidence'].get('documents',[]) if d in docs]
        revision_group=any(r['basis'] in {'same_report_number_revision','same_initial_commit_findings_revision'}
                           for d in member_docs for r in d['metadata'].get('engagement_relationships',[]))
        if revision_group:
            issues=[c for c in eligible if c['role']=='report_issue']
            if issues:
                latest=max(c['date_value'] for c in issues)
                for c in issues:
                    if not latest.startswith(c['date_value']):
                        demote(c,'source_linked_superseded_report_edition')
        issues=[c for c in eligible if c['role']=='report_issue']
        revisions=[c for c in issues if 'revision' in str((c['evidence'].get('assertion') or {}).get('method',''))]
        # A revision date explicitly supersedes earlier report editions, but does
        # not override a contradictory later dateline or an audit endpoint.
        if revisions:
            latest=max(c['date_value'] for c in revisions)
            for c in issues:
                if c['date_value']<latest and not latest.startswith(c['date_value']):
                    demote(c,'superseded_report_revision')
        for role in ['audit_completion','report_issue']:
            same=[c for c in eligible if c['eligible_for_audit_year'] and c['role']==role]
            for c in same:
                if any(o['date_value'].startswith(c['date_value']) and len(o['date_value'])>len(c['date_value']) for o in same):
                    demote(c,'more_precise_same_role_evidence')
        status_revision=any(r['basis']=='same_initial_commit_findings_revision'
                            for d in member_docs for r in d['metadata'].get('engagement_relationships',[]))
        if status_revision:
            by_doc=defaultdict(set)
            for c in eligible:
                if c['eligible_for_audit_year'] and c['role']=='audit_completion': by_doc[c['document_id']].add(c['date_value'])
            # Preserve internally contradictory originals. Only distinct,
            # internally coherent editions can retime a later status review.
            if len(by_doc)>1 and all(len(v)==1 for v in by_doc.values()):
                initial=min(next(iter(v)) for v in by_doc.values())
                for c in eligible:
                    if c['eligible_for_audit_year'] and c['role']=='audit_completion' and c['date_value']!=initial:
                        c['evidence']['phase3d_original_role']=c['role']
                        c['evidence']['phase3d_resolution']='same_initial_scope_revision_retest'
                        c.update(role='retest',eligible_for_audit_year=False)
        preferred=[c for c in eligible if c['eligible_for_audit_year']]
        priorities={'audit_completion':0,'report_issue':1,'review_year':2,'audit_year_inference':3}
        role=min((c['role'] for c in preferred),key=lambda r:priorities[r],default='report_issue')
        preferred=[c for c in preferred if c['role']==role]
        values={c['date_value'] for c in preferred}
        value=next(iter(values)) if len(values)==1 else None
        e['evidence']['resolved_date']=dict(value=value,precision={4:'year',7:'month',10:'day'}.get(len(value or ''),'none'),
                                          role=role if preferred else None,conflict=len(values)>1,
                                          claim_ids=sorted(c['claim_id'] for c in preferred),policy='initial_completion_then_current_issue_v1')
    return claims
