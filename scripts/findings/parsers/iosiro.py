"""iosiro numbered risk sections and embedded native HTML report cards."""
import html
import re
from core import Candidate, clean, severity
DESCRIPTION='Numbered findings under risk/open/closed sections and native IO-ID HTML cards; printed statuses retained'
RISK=r'(Critical|High|Medium|Low|Informational|Information|Info)'

def plain(s):
    return clean(html.unescape(re.sub(r'<[^>]+>',' ',s)))

def parse(report):
    out=[]; current=None; current_status=None; root=None
    fence=None; code_flags=[]
    for line in report.lines:
        s=line.content
        marker=re.match(r'^(`{3,}|~{3,})(.*)$',s)
        code_flags.append(fence is not None)
        if marker:
            kind=marker[1][0]
            if fence:
                if kind==fence and not marker[2].strip():fence=None
            elif not re.search(re.escape(marker[1])+r'\s*$',marker[2]):fence=kind
    for i,line in enumerate(report.lines):
        if not line.heading or code_flags[i]:continue
        s=clean(line.content)
        top=re.match(r'^(\d+)\.?\s+(.*findings.*)$',s,re.I)
        if line.heading==1:
            if top:
                root=top[1];current=None
                current_status='Closed' if re.search(r'closed',top[2],re.I) else 'Open' if re.search(r'open',top[2],re.I) else None
            else:root=None
        parent=re.fullmatch(r'(\d+\.\d+)\s+(.+)',s)
        if parent and root and parent[1].startswith(root+'.'):
            risk=re.match(RISK+r'(?:\s+risk)?\b',parent[2],re.I)
            current=risk[1] if risk else None
            if re.search(r'closed|resolved',parent[2],re.I):current_status=parent[2]
        m=re.match(r'^(\d+\.\d+\.\d+)\.?\s+(.+)',s)
        if not m or not root or not m[1].startswith(root+'.'):
            if root and line.heading>=3 and current_status and re.search(r'closed',current_status,re.I) and s.lower() not in {'update','description','remedial action'}:
                previous=next((l for l in reversed(report.lines[:i]) if l.heading and l.heading<=line.heading),None)
                if previous and previous.heading==2:
                    end=next((l.start for l in report.lines[i+1:] if l.heading and l.heading<=2),len(report.text))
                    out.append(Candidate(line.start,s,current,None,end=end,status_raw=current_status,method='unnumbered-closed-card',confidence=.85,evidence={'severity_basis':'unprinted_unknown'}))
            continue
        raw=current; title=m[2]
        suffix=re.search(r'\(\s*'+RISK+r'(?:[- ]risk)?\s*\)\s*$',title,re.I)
        if suffix:raw=suffix[1];title=title[:suffix.start()].strip()
        end=next((l.start for l in report.lines[i+1:] if l.heading and l.heading<=line.heading),len(report.text))
        out.append(Candidate(line.start,title,raw,m[1],end=end,status_raw=current_status,
                             method='numbered-risk-section',confidence=.94,
                             evidence={'severity_basis':'printed_heading_suffix' if suffix else 'printed_parent_risk_section' if raw else 'unprinted_unknown'}))
    # Since 2024 the publisher stores a complete HTML report inside its page.
    heads=list(re.finditer(r'<h([1-6])\b[^>]*>(.*?)</h\1>',report.text,re.I|re.S))
    for i,m in enumerate(heads):
        title=plain(m[2]); match=re.match(r'(IO-[A-Z0-9-]+)\s+(.+)',title,re.I)
        if not match:continue
        end=next((h.start() for h in heads[i+1:] if int(h[1])<=int(m[1])),len(report.text))
        body=report.text[m.start():end]
        risk=re.search(r'<td\b[^>]*class=["\'][^"\']*rating-[^"\']*["\'][^>]*>(.*?)</td>',body,re.I|re.S)
        state=re.search(r'<td\b[^>]*class=["\'][^"\']*status-[^"\']*["\'][^>]*>(.*?)</td>',body,re.I|re.S)
        out.append(Candidate(m.start(),match[2],plain(risk[1]) if risk else None,match[1],end=end,
                             status_raw=plain(state[1]) if state else None,method='native-html-card',confidence=.97,
                             evidence={'severity_basis':'explicit_metadata_cell' if risk else 'unprinted_unknown'}))
    # Native code-quality rows carry complete advice, but no printed risk label.
    for table in re.finditer(r'<table\b[^>]*>(.*?)</table>',report.text,re.I|re.S):
        previous=[h for h in heads if h.end() <= table.start() and int(h[1]) == 1]
        in_quality=bool(previous and plain(previous[-1][2]).casefold()=='code quality improvement suggestions')
        if not in_quality and not re.match(r'<table\b[^>]*class=["\'][^"\']*\bcodequality\b',table[0],re.I):continue
        for row in re.finditer(r'<tr\b[^>]*>(.*?)</tr>',table[1],re.I|re.S):
            cells=re.findall(r'<td\b[^>]*>(.*?)</td>',row[1],re.I|re.S)
            if len(cells)!=3:continue
            pid,location,advice=map(plain,cells)
            start=table.start(1)+row.start();end=table.start(1)+row.end()
            out.append(Candidate(start,None,None,pid,end=end,method='native-code-quality-row',confidence=.88,
                                 record_kind='recommendation',recommendation=advice,
                                 evidence={'severity_basis':'unprinted_unknown','location':location,'title_basis':'no_printed_title'}))
    for c in out:
        tail=report.text[c.start:c.end]
        footer=re.search(r'\nSecure your system\.|\nRequest a service\s*\n',tail)
        if footer:c.end=c.start+footer.start()
    return out

def printed_counts(report):
    # Independent publisher aggregate table: sum the printed, disjoint status rows.
    m=re.search(r'<table\b[^>]*class=["\'][^"\']*findings-count[^"\']*["\'][^>]*>(.*?)</table>',report.text,re.I|re.S)
    if not m:return None
    rows=re.findall(r'<tr\b[^>]*>(.*?)</tr>',m[1],re.I|re.S)
    if not rows:return None
    labels=[plain(v) for v in re.findall(r'<th\b[^>]*>(.*?)</th>',rows[0],re.I|re.S)]
    labels=[severity(v, report.firm) for v in labels if re.fullmatch(RISK,v,re.I)]
    counts={k:0 for k in labels}; observed=False
    for row in rows[1:]:
        cells=[plain(v) for v in re.findall(r'<t[dh]\b[^>]*>(.*?)</t[dh]>',row,re.I|re.S)]
        if len(cells)==len(labels)+1 and re.fullmatch(r'Open|Resolved|Closed|Acknowledged',cells[0],re.I) and all(v.isdigit() for v in cells[1:]):
            for k,v in zip(labels,cells[1:]):counts[k]+=int(v)
            observed=True
    if not observed:return None
    result={'counts':counts,'basis':'publisher_html_aggregate_status_table','evidence':[{'start':m.start(),'end':m.end(),'text':m[0]}]}
    # Native totals combine classified issue cards and separate, ungraded
    # code-quality suggestions. Preserve the printed informational total but
    # compare only buckets with the same formal-detail scope. This decision is
    # based solely on the publisher's explicit section, never parsed counts.
    scope=re.search(r'<h[1-6]\b[^>]*>Code quality improvement suggestions</h[1-6]>\s*<p>Code improvement suggestions without security implications are listed below.</p>',report.text,re.I)
    if scope and 'info' in counts:
        result['publisher_totals_outside_detail_scope']={'info':counts['info']}
        result['counts']={k:v for k,v in counts.items() if k!='info'}
        result['scope_evidence']={'start':scope.start(),'end':scope.end(),'text':scope[0]}
        result['scope_note']='Informational aggregate also includes explicitly separate ungraded code-quality suggestions; retain it without comparing it to formal graded issue cards.'
    return result


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses, receipt, normalize

def parse_numbered(report):
    return [c for c in parse(report) if c.method in {'numbered-risk-section','unnumbered-closed-card'}]

def parse_native(report):
    out=[c for c in parse(report) if c.method=='native-html-card']
    # New code-quality rows are included in the publisher's informational
    # totals, and the complete ID-linked findings index prints their risk and
    # status. Older rows have no risk/status and remain recommendations.
    index={}
    for table in re.finditer(r'<table\b[^>]*>(.*?)</table>',report.text,re.I|re.S):
        header=re.search(r'<tr\b[^>]*>(.*?)</tr>',table[1],re.I|re.S)
        labels=[plain(v).casefold() for v in re.findall(r'<th\b[^>]*>(.*?)</th>',header[1],re.I|re.S)] if header else []
        if labels != ['id','issue','risk','status']:continue
        for row in re.finditer(r'<tr\b[^>]*>(.*?)</tr>',table[1],re.I|re.S):
            cells=[plain(v) for v in re.findall(r'<td\b[^>]*>(.*?)</td>',row[1],re.I|re.S)]
            if len(cells)==4 and re.fullmatch(r'IO-[A-Z0-9-]+',cells[0],re.I):
                a=table.start(1)+row.start();b=table.start(1)+row.end()
                index[cells[0]]=(cells[2],cells[3],a,b)
    for c in parse(report):
        if c.method!='native-code-quality-row':continue
        meta=index.get(c.printed_id)
        if meta:
            c.severity_raw,c.status_raw,a,b=meta
            c.record_kind='formal_finding'
            c.evidence.update(severity_basis='printed_id_risk_index',risk_index={'start':a,'end':b,'text':report.text[a:b]})
        out.append(c)
    return sorted(out,key=lambda c:c.start)

def status_numbered(report,candidates):
    statuses(report,candidates,headings=True)
    # Parent Open/Closed findings headings are authoritative for old Markdown.
    for c in candidates:
        if not c.status_raw:continue
        previous=[l for l in report.lines if l.start<c.start and l.heading and re.search(r'\b(?:Open|Closed)\b',l.content,re.I)]
        if 'status_evidence' not in c.evidence and previous:
            l=previous[-1];m=re.search(r'\b(Open|Closed)\b',l.text,re.I)
            receipt(report,c,m[1],l.start+m.start(1),l.start+m.end(1),'printed_status_section',normalize(m[1],report.firm))

def status_native(report,candidates):
    replies={}
    # The code-quality section has an ID-linked client-response definition list.
    for m in re.finditer(r'<dt>\s*(IO-[A-Z0-9-]+)\s*</dt>\s*<dd>(.*?)</dd>',report.text,re.I|re.S):
        hit=re.match(r'\s*(Fixed|Resolved|Acknowledged|Closed|Open)\b',plain(m[2]),re.I)
        if hit:
            raw=hit[1];source=re.search(re.escape(raw),m[2],re.I)
            replies[m[1]]=(raw,m.start(2)+source.start(),m.start(2)+source.end())
    for c in candidates:
        body=report.text[c.start:c.end]
        m=re.search(r'<td\b[^>]*class=["\'][^"\']*status-[^"\']*["\'][^>]*>([^<]+)</td>',body,re.I|re.S)
        if m:
            raw=plain(m[1]);receipt(report,c,raw,c.start+m.start(1),c.start+m.end(1),'native_status_cell','acknowledged' if raw.lower()=='closed' else normalize(raw,report.firm))
        elif c.evidence.get('risk_index'):
            e=c.evidence['risk_index'];m=re.search(r'<td\b[^>]*class=["\'][^"\']*status-[^"\']*["\'][^>]*>([^<]+)</td>',e['text'],re.I|re.S)
            if m:
                raw=plain(m[1]);receipt(report,c,raw,e['start']+m.start(1),e['start']+m.end(1),'native_id_status_index','acknowledged' if raw.lower()=='closed' else normalize(raw,report.firm))
        elif c.printed_id in replies:
            raw,a,b=replies[c.printed_id];receipt(report,c,raw,a,b,'native_id_client_response','acknowledged' if raw.lower()=='closed' else normalize(raw,report.firm))

def parse_short_review(report):return []
def status_short_review(report,candidates):return None

VARIANTS=(
    Variant('iosiro/v2026_classless_html',Fingerprint((('classless quality table',r'<h1\b[^>]*>Code quality improvement suggestions</h1>\s*<p>[^<]*</p>\s*<table>',16),),('2026','2026')),parse_native,('iosiro_classless',),status_native,printed_counts,notes='Section-bounded code-quality tables and explicit ID/Issue/Risk/Status indexes, including HTML exports without CSS classes.'),
    Variant('iosiro/v2024_native_html',Fingerprint((('native cards',r'<h[1-6]\b[^>]*>\s*(?:<[^>]+>\s*)*IO-[A-Z0-9-]+',6),('metadata classes',r'<td\b[^>]*class=["\'][^"\']*rating-',3),('native aggregate',r'<table\b[^>]*class=["\']findings-count',3)),('2024','2026')),parse_native,('iosiro_html',),status_native,printed_counts,notes='Embedded HTML IO-ID cards and code-quality rows; use ID-linked risk/status index for rows covered by informational totals, with exact HTML offsets.'),
    Variant('iosiro/v2017_numbered',Fingerprint((('findings root',r'^#\s+\d+\.?\s+(?:Open |Closed )?(?:Audit )?Findings',4),('numbered details',r'^#{2,4}\s+\d+\.\d+\.\d+',3),('site identity',r'iosiro|Smart Contract Auditing|Penetration Testing',2)),('2017','2024')),parse_numbered,('iosiro_numbered',),status_numbered,printed_counts,notes='Markdown risk sections with three-component issue numbers; open/closed parent sections and explicit updates determine status, code blocks are excluded.'),
    Variant('iosiro/v2018_short_review',Fingerprint((('findings section',r'^#{1,3}\s+Findings\s*$',3),('clean review statement',r'No (?:functional or security flaws|substantial issues)|no new issues were identified',4)),('2018','2020')),parse_short_review,('iosiro_short',),status_short_review,printed_counts,notes='Short change-review posts with an explicit clean Findings section; no invented finding cards.'),
)
