"""Bounded document datelines with verbatim, page/offset/hash receipts.

Calendar normalization never supplies semantics. Labels, title pages, report
control tables or an author dateline must independently establish the role.
"""
from collections import Counter
import re
import unicodedata


# Finite spelling/language variants; no fuzzy date matching or locale dependency.
MONTHS = {
    'january': 'jan janvier enero janeiro januar января',
    'february': 'feb feburary februrary ferbruary février fevrier febrero fevereiro februar февраля',
    'march': 'mar mars marzo março marco märz maerz марта',
    'april': 'apr avril abril апреля',
    'may': 'mai mayo maio мая',
    'june': 'jun juin junio junho juni июня',
    'july': 'jul juillet julio julho juli июля',
    'august': 'aug août aout agosto августа',
    'september': 'sep sept septembre septiembre setembro septiembre сентябрь сентября',
    'october': 'oct octobre octubre outubro oktober октября',
    'november': 'nov novembre noviembre novembro ноября',
    'december': 'dec décembre decembre diciembre dezembro dezember декабря',
}
MONTH_MAP = {word: name for name, words in MONTHS.items() for word in [name, *words.split()]}
MONTH = r'(?:'+'|'.join(sorted(MONTH_MAP,key=lambda s:(-len(s),s)))+r')\.?'
DAY = r'\d{1,2}(?:st|nd|rd|th|d|º|ª|er)?'
NAMED = rf'(?:{MONTH}\s*,?\s*{DAY}\s*,?\s+20\d{{2}}|{DAY}\s+(?:de\s+)?{MONTH}\s*,?\s+(?:de\s+)?20\d{{2}}|{MONTH}\s+20\d{{2}})'
CALENDAR = re.compile(rf'(?<![\w/])(?:{NAMED}|20\d{{2}}\s*年\s*\d{{1,2}}\s*月(?:\s*\d{{1,2}}\s*日)?|20\d{{2}}[-/.]\d{{1,2}}[-/.]\d{{1,2}}|\d{{1,2}}[./-]\d{{1,2}}[./-]20\d{{2}})(?!\w)',re.I)
CONTROL = re.compile(r'document\s+(?:control|properties|revisions?|history|information)|report\s+(?:revisions?|history)|revision\s+history|version\s+history|change\s*log',re.I)
REPORT = re.compile(r'(?:audit|security\s+(?:analysis|assessment|review)|contract\s+verification|findings\s*&\s*analysis)\s*(?:report|conclusion)?|审计报告|審計報告',re.I)


def normalized(raw):
    from metadata_rules import parse_date
    value=unicodedata.normalize('NFKC',raw).strip()
    zh=re.fullmatch(r'(20\d{2})\s*年\s*(\d{1,2})\s*月(?:\s*(\d{1,2})\s*日)?',value)
    if zh:
        return parse_date(f'{zh[1]}-{int(zh[2]):02}'+(f'-{int(zh[3]):02}' if zh[3] else ''))
    value=re.sub(r'(?<=\d)(?:st|nd|rd|th|d|º|ª|er)\b','',value,flags=re.I)
    value=re.sub(r'\bde\s+','',value,flags=re.I)
    value=re.sub(MONTH,lambda m:MONTH_MAP[m[0].lower().rstrip('.')],value,flags=re.I)
    return parse_date(value)


def layout_date_claims(text, receipt):
    from metadata_rules import sha, clean
    from date_rules import HISTORY, PUBLICATION, RETEST, START, PERIOD, COMPLETION
    claims=[];seen=set()
    # Only one-codepoint substitutions: all locators still address source bytes
    # decoded as text, including CJK compatibility glyphs and format spaces.
    masked=''.join(' ' if unicodedata.category(c)=='Cf' else unicodedata.normalize('NFKC',c) if len(unicodedata.normalize('NFKC',c))==1 else c for c in text)
    bodies=masked.split('\f')
    repeated=Counter(s.strip() for b in bodies for s in set(b.splitlines()) if re.match(r'\s*(?:report\s+)?date\s*[:|]',s,re.I))

    def emit(raw,value,role,method,lo,hi,page,**extra):
        value,precision=normalized(value)
        if not value: return
        key=(value,role,lo,hi,method)
        if key in seen:return
        seen.add(key)
        claims.append(dict(raw_value=raw,date_value=value,precision=precision,role=role,
                           basis='document_text',method='date_evidence_'+method,confidence=.96,
                           evidence=text[lo:hi],text_start=lo,text_end=hi,
                           text_sha256=receipt.get('text_sha256') or sha(text.encode()),
                           text_source=receipt.get('source','local-cache/text'),page=page,
                           page_kind='physical' if isinstance(receipt.get('pages'),list) else 'logical',**extra))

    offset=0
    for page,body in enumerate(bodies,1):
        lines=list(re.finditer(r'[^\n]+',body))
        for i,line in enumerate(lines):
            s=line[0];lo=offset+line.start();hi=offset+line.end()
            if not re.search(r'20\d{2}',s): continue
            imprint=re.fullmatch(r'\s*([A-Za-z][A-Za-z .&-]{1,55}),\s*(20\d{2})\s*',s)
            if imprint and page==1 and len(body)<1800 and REPORT.search(body[:line.start()]) and not HISTORY.search(s):
                emit(text[lo:hi],imprint[2],'report_issue','cover_author_year',lo,hi,page)
            found=list(CALENDAR.finditer(s))
            if not found: continue
            if HISTORY.search(s) or PUBLICATION.search(s) or RETEST.search(s) or re.search(r'https?://|\b(?:commit|hash)\b',s,re.I):continue
            before=body[max(0,line.start()-400):line.start()]
            residue=clean(CALENDAR.sub('',s)).strip(' #,*|.()[]–—-')
            # A complete dateline, optionally with a time, under a report heading.
            # This also handles Markdown h4 dates and exact month spelling variants.
            dateline=not residue or bool(re.fullmatch(r'\d{1,2}:\d{2}(?::\d{2})?\s*(?:UTC|GMT|[AP]M)?|Prepared\s+by\s+[A-Za-z .-]+',residue,re.I))
            cover=(page<=3 and line.start()<3000 and REPORT.search(before)
                   and not re.search(r'contents|executive\s+summary|disclaimer|references|findings\s+summary|introduction',before,re.I))
            if len(found)==1 and dateline and cover:
                emit(text[lo+found[0].start():lo+found[0].end()],found[0][0],'report_issue','report_title_dateline',lo,hi,page)
            inline=re.search(r'\bDate\s{2,}',s)
            if len(found)==1 and inline and page<=3 and line.start()<3000 and REPORT.search(body[:3000]) and not re.search(r'commit|signature|start|copyright|\bcode\b',s,re.I):
                if inline.end()<=found[0].start():
                    emit(text[lo+found[0].start():lo+found[0].end()],found[0][0],'report_issue','cover_date_column',lo,hi,page)
            if (len(found)==1 and normalized(found[0][0])[1]=='month'
                and re.match(r'\s*(?:(?:the|this)\s+)?(?:initial\s+)?(?:audit|assessment|review)\s+(?:was\s+)?conducted\s+in\s+',s,re.I)
                and not HISTORY.search(before) and not re.search(r'\b(?:began|started|ongoing|scheduled)\b',s,re.I)):
                emit(text[lo+found[0].start():lo+found[0].end()],found[0][0],'audit_completion','retrospective_work_month',lo,hi,page)
            # Audit conclusions sometimes follow several logo/separator pages.
            if len(found)==1 and dateline and re.search(r'audit\s+conclusion',before,re.I):
                emit(text[lo+found[0].start():lo+found[0].end()],found[0][0],'report_issue','audit_conclusion_dateline',lo,hi,page)
            end_label=re.search(r'\b(?:contest|competition)\s+(?:end(?:ed)?|clos(?:ed|ing))\s*(?:date)?\s*(?:on|at|:|\|)',s,re.I)
            if len(found)==1 and end_label and not re.search(r'\b(?:scheduled|planned|upcoming|mitigation)\b',s,re.I):
                emit(text[lo+found[0].start():lo+found[0].end()],found[0][0],'audit_completion','document_contest_end',lo,hi,page)
            # Explicit Date fields in page furniture or a document-control block.
            field=re.match(r'\s*[*| #]*(?:report\s+)?date\s*[:|*]+\s*',s,re.I)
            control=CONTROL.search(body[max(0,line.start()-1000):line.start()])
            furniture=(line.start()<350 or line.end()>len(body)-400) and REPORT.search(body[:350]) and not re.search(r'findings|description|example|transaction|timestamp',before,re.I)
            git_context=bool(re.search(r'(?im)^\s*(?:commit\s+[a-f0-9]{7,}|Merge:\s*[a-f0-9])|\bgit\s+log\b',before)
                             or re.search(r'(?im)^\s*[a-f0-9]{7,40}\s*$',before) and re.search(r'\bAuthor\s*:',before,re.I))
            if field and len(found)==1 and not START.search(s) and not git_context and (control or furniture or repeated[s.strip()]>=2):
                emit(text[lo+found[0].start():lo+found[0].end()],found[0][0],'report_issue','control_date_field' if control else 'header_footer_date_field',lo,hi,page)
            # Source author dateline at the end of an analysis. A bare signature,
            # publication label, copyright or unlabelled appendix date cannot qualify.
            author=body[max(0,line.start()-1400):line.start()]
            if (len(found)==1 and dateline and page>1 and page>=len(bodies)-3
                and re.search(r'(?:this\s+)?(?:analysis|audit|assessment|review)\s+(?:was\s+)?performed\s+by[^:\n]{0,70}:',author,re.I)
                and re.search(r'(?:security|blockchain)\s+(?:analysis|audit|assessment)',body[line.end():],re.I)):
                begin=offset+max(0,line.start()-1400)
                emit(text[lo+found[0].start():lo+found[0].end()],found[0][0],'report_issue','closing_author_dateline',begin,hi,page)

        if page==1:
            for m in CALENDAR.finditer(body[:3000]):
                if '\n' not in m[0]:continue
                before=body[max(0,m.start()-500):m.start()]
                start=body.rfind('\n',0,m.start())+1
                end=body.find('\n',m.end());end=end if end>=0 else len(body)
                residue=clean(CALENDAR.sub('',body[start:end])).strip(' #,*|.()[]–—-')
                labelled_elsewhere=any(p.search(before[-180:]) for p in [HISTORY,PUBLICATION,RETEST,START,PERIOD,COMPLETION])
                if REPORT.search(before) and not residue and not labelled_elsewhere and not re.search(r'contents|disclaimer|introduction|copyright|references',before,re.I):
                    emit(text[offset+m.start():offset+m.end()],m[0],'report_issue','wrapped_cover_dateline',offset+m.start(),offset+m.end(),page)
        # A version table can place the year on the following line after authors.
        # Parse within each row, never carry a year across a version-row boundary.
        for heading in CONTROL.finditer(body):
            block_end=min(len(body),heading.end()+3500)
            block=body[heading.end():block_end]
            if not re.search(r'\b(?:version|revision)\b',block[:500],re.I) or not re.search(r'\bdate\b',block[:500],re.I): continue
            rows=list(re.finditer(r'(?m)^\s*\|?\s*(?:v\s*)?\d+\.\d+(?:\.\d+)?\s*\|?\s+',block,re.I))
            for j,row in enumerate(rows):
                end=rows[j+1].start() if j+1<len(rows) else min(len(block),row.end()+500)
                payload=block[row.start():end]
                if re.search(r'\b(?:commit|git|dependencies|code\s+changes)\b|https?://',payload,re.I):continue
                matches=list(CALENDAR.finditer(payload))
                start=offset+heading.end()+row.start()
                if len(matches)==1:
                    m=matches[0]
                    emit(text[start+m.start():start+m.end()],m[0],'report_issue','report_revision_control_table',start,start+len(payload),page)
                elif not matches:
                    fragment=re.search(rf'(?P<month>{MONTH})\s+(?P<day>{DAY})\s*,?',payload,re.I)
                    years=list(re.finditer(r'(?m)^\s*(20\d{2})\s*\|?\s*$',payload))
                    if fragment and len(years)==1 and fragment.end()<=years[0].start():
                        year=years[0]
                        emit(text[start+fragment.start():start+year.end()],f'{fragment["month"]} {fragment["day"]} {year[1]}','report_issue','report_revision_wrapped_year',start,start+year.end(),page)

        # Non-English audit/report labels bind to the nearby table value. The
        # compatibility glyph 日 may be emitted as ⽇ by PDF extraction.
        label=re.compile(r'审计(?:时间|日期|周期)|審計(?:時間|日期|週期)|报告日期|報告日期')
        for m in label.finditer(body):
            end=min(len(body),m.end()+350)
            window=body[m.end():end]
            dates=list(CALENDAR.finditer(window))[:2]
            if not dates:continue
            issue='报告' in m[0] or '報告' in m[0]
            for j,d in enumerate(dates):
                role='report_issue' if issue else 'audit_start' if j==0 and len(dates)==2 else 'audit_completion'
                start=offset+m.start();finish=offset+m.end()+dates[-1].end()
                emit(text[offset+m.end()+d.start():offset+m.end()+d.end()],d[0],role,'localized_date_label',start,finish,page)

        # Day-first shared-month periods: "17-30 June, 2022". Require work or
        # contest context; software versions, findings and references cannot date it.
        pattern=rf'(?P<a>{DAY})\s*[-–—]\s*(?P<b>{DAY})\s+(?P<month>{MONTH})\s*,?\s*(?P<year>20\d{{2}})'
        for m in re.finditer(pattern,body,re.I):
            start=max(body.rfind('\n',0,m.start())+1,0)
            prev=max(body.rfind('\n',0,max(0,start-1))+1,0)
            finish=body.find('\n',m.end());finish=finish if finish>=0 else len(body)
            context=body[prev:finish]
            if not re.search(r'audit|assessment|review|contest|competition|evaluation',context,re.I):continue
            if HISTORY.search(context) or RETEST.search(context) or PUBLICATION.search(context) or 'http' in context:continue
            a=normalized(f'{m["a"]} {m["month"]} {m["year"]}')[0]
            b=normalized(f'{m["b"]} {m["month"]} {m["year"]}')[0]
            if not a or not b or a>b:continue
            for day,role in [(m['a'],'audit_start'),(m['b'],'audit_completion')]:
                emit(text[offset+m.start():offset+m.end()],f'{day} {m["month"]} {m["year"]}',role,'day_first_shared_month_period',offset+prev,offset+finish,page)
        offset+=len(body)+1
    for item in receipt.get('html_metadata_dates',[]):
        lo,hi=item['text_start'],item['text_end']
        if text[lo:hi]!=item['evidence'] or item['raw_value'] not in item['evidence']:
            raise ValueError('HTML metadata does not match its text receipt')
        emit(item['raw_value'],item['raw_value'][:10],item['role'],'html_'+item['kind']+'_meta',lo,hi,1,
             source_field=item['source_field'])
    return claims
