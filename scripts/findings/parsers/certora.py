"""Certora modern severity-ID details and early Issue/Severity cards."""
from core import SeverityLookup, severity, Candidate, SHORT, clean, explicit_status, field_severity
import re
import unicodedata
from summary_counts import printed_counts as generic_counts

DESCRIPTION = "Severity-ID details with punctuation variants; legacy Issue cards; verification rules excluded"
ID = re.compile(r"^\s*(Critical|Crit|Cr|High|Medium|Low|Informational|INFO|Note|Issue|[CHMLIN])[-–]\s*(\d{1,3})(?:\s*[.:–-]\s*|\s+)(\S.*)$", re.I)


def parse_id_cards(report):
    report=view(report)
    out = []
    first_field = next((l.start for l in report.lines if re.match(r"^Severity\s*:",l.content,re.I)),len(report.text))
    boundaries = [l.start for l in report.lines if l.start < first_field and re.fullmatch(r"(?:Main Issues Discovered|Detailed Findings)",l.content,re.I)]
    detail_start = max(boundaries) if boundaries else 0
    active=False
    for i, line in enumerate(report.lines):
        s = re.sub(r'^В(?=[CHMLI]-\d)', '', clean(line.content))
        repaired=False;split_title=False
        missing=re.fullmatch(r'-(\d{1,3})([.:–-]?)(?:\s+(.*))?',s)
        if missing:
            following=next((l for l in report.lines[i+1:i+4] if l.content),None)
            glyph=re.fullmatch(r'([CHMLI])(?:\s{2,}(.*))?',following.content) if following else None
            if glyph:
                s=glyph[1]+'-'+missing[1]+missing[2]+' '+(missing[3] or glyph[2] or '')
                repaired=True
        if out and re.fullmatch(r"(?:Formal Verification|Formal Specifications?|Verification Results|Notations)",s,re.I):
            out[-1].end=line.start
            break
        if line.start>=detail_start and re.fullmatch(r"(?:Critical|High|Medium|Low|Informational)(?: Severity)? (?:Issues|Concerns)",s,re.I):
            active=True
        if line.code or re.search(r"\.{3,}", s):
            continue
        m = ID.match(s)
        bare=re.fullmatch(r'(Critical|Crit|Cr|High|Medium|Low|Informational|INFO|Note|Issue|[CHMLIN])[-–](\d{1,3})[.:]?',s,re.I)
        if not m and bare and line.start>=detail_start:
            ahead=[]
            for nxt in report.lines[i+1:i+10]:
                if ID.match(nxt.content) or re.fullmatch(r'[CHMLI]-\d+[.:]?',nxt.content,re.I):break
                ahead.append(nxt)
            field=r'^(?:Severity|Impact|Probability|Category|Description|Recommendation|Files?|(?:[\w’\x27.]+\s+)?Response)\s*:'
            if any(re.match(field,l.content,re.I) for l in ahead):
                titleparts=[]
                for l in ahead:
                    if re.match(field,l.content,re.I):break
                    if l.content:titleparts.append(l.content)
                if not titleparts:
                    previous=next((l for l in reversed(report.lines[max(0,i-3):i]) if l.content),None)
                    if previous and previous.page==line.page and not re.search(r'(?:Severity Issues|\d+)$',previous.content):titleparts=[previous.content]
                if titleparts:
                    m=ID.match(bare[1]+'-'+bare[2]+' '+clean(' '.join(titleparts)));split_title=True
        if m:
            if line.start < detail_start:
                continue
            metadata=[]
            for l in report.lines[i+1:i+12]:
                if ID.match(l.content) or re.match(r"^(?:Description|Bug description|Recommendation)\s*:?​?$",clean(l.content),re.I):
                    break
                metadata.append(l.text)
            explicit = field_severity("\n".join(metadata))
            if not active and not explicit:
                continue
            # The front issue index has a printed severity and status in columns.
            if re.search(r"\s{2,}(?:Critical|High|Medium|Low|Informational)\s{2,}",line.text,re.I):
                continue
            title = m[3]
            # Wrapped detail titles precede a blank line or the metadata block.
            for following in report.lines[i+1:i+5]:
                if split_title:break
                if repaired and re.fullmatch(r'[CHMLI](?:\s{2,}.*)?',following.content):continue
                if not following.content or following.page != line.page or re.match(r"^(?:Severity|Description|Status|Files|Impact|Likelihood|Recommendation|[CHMLIN]-\d+)\b",following.content,re.I):
                    break
                title += " " + following.content
            raw = explicit or m[1]
            out.append(Candidate(line.start,clean(title),raw,m[1]+"-"+m[2],normalized=severity(raw, report.firm),
                                 method="certora-id-detail",confidence=.93,
                                 evidence={"severity_basis":"explicit_field" if explicit else "printed_id_prefix", "printed_id_severity":m[1]}))
            if repaired or split_title:out[-1].evidence['split_pdf_header']=True
            continue
    for j,c in enumerate(out):
        c.end = c.end or (out[j+1].start if j+1<len(out) else len(report.text))
        stop = re.search(r"(?m)^\s*(?:Appendix|Notations|Verification (?:of|Of)|Formal (?:Specification|Verification)|Disclaimer)\b",report.text[c.start:c.end])
        if stop and stop.start()>100:
            c.end=c.start+stop.start()
        c.status_raw=explicit_status(report.text[c.start:c.end])
    return out


def parse_issue_cards(report):
    """2020–24 vertically printed Issue/Severity/Mitigation cards."""
    report=view(report);out=[]
    for i,line in enumerate(report.lines):
        if out and re.fullmatch(r'(?:Notations|Formal Verification|Verification (?:of|Of).*)',line.content,re.I):break
        m=re.match(r'^Issue:\s*(\S.*)$',clean(line.content),re.I)
        if not m or line.code:continue
        before='\n'.join(l.content for l in report.lines[max(0,i-6):i])
        raw=field_severity(before)
        if raw is None:
            labels=re.findall(r'(?m)^(Critical|High|Medium|Low|Informational|Recommendation)\s*$',before,re.I)
            raw=labels[-1] if labels else None
        title=m[1]
        for nxt in report.lines[i+1:i+5]:
            if not nxt.content or re.match(r'^(?:Rules? Broken|Description|Mitigation|Fix|Response|Severity|Recommendation|Category|Issue)\b',nxt.content,re.I):break
            title+=' '+nxt.content
        # Some PDF cards repeat their title after a page break. A repeated
        # header without a new severity field continues the same finding.
        if out and clean(title)==out[-1].title and not field_severity(before):continue
        out.append(Candidate(line.start,clean(title),raw,method='certora-issue-card',confidence=.9,
                             evidence={'severity_basis':'explicit_field' if raw else 'not_printed'}))
    return _bound_findings(report,out)


def _bound_findings(report,out):
    for i,c in enumerate(out):
        c.end=out[i+1].start if i+1<len(out) else len(report.text)
        stop=re.search(r'(?m)^\s*(?:Appendix|Notations|Verification (?:of|Of)|Formal (?:Specification|Verification)|Disclaimer)\b',report.text[c.start:c.end])
        if stop and stop.start()>45:c.end=c.start+stop.start()
    return out


def parse_narrative(report):
    """2018–20 numbered prose issues; lower-case cross-references are not titles."""
    out=[]
    for line in report.lines:
        m=re.match(r'^Issue\s+(\d+)\s+(.+)',line.content)
        if m and not line.code:
            out.append(Candidate(line.start,m[2].split('. ')[0],None,m[1],method='certora-numbered-narrative',confidence=.9,
                                 evidence={'severity_basis':'not_printed'}))
    return _bound_findings(report,out)


def parse_tabular_issue_cards(report):
    """2021–23 Issue/Severity/Description/Fix cards without colon separators."""
    r=view(report);out=[]
    for i,line in enumerate(r.lines):
        if out and re.fullmatch(r'(?:Notations|Verification of.*|Formal Verification)',line.content,re.I):break
        m=re.match(r'^Issue[ \t]{2,}(?!Rule broken|Description)(\S.*)',line.content,re.I)
        if not m or line.code:continue
        title=[m[1]]
        for nxt in r.lines[i+1:i+5]:
            if not nxt.content or re.match(r'^(?:Severity|Description|Fix|Response|Recommendation|Issue)\b',nxt.content,re.I):break
            title.append(nxt.content)
        nearby=r.lines[max(0,i-4):i]+r.lines[i+1:i+7]
        raw=None
        for l in nearby:
            risk=re.match(r'^Severity\s*(?::|[ \t]{2,})\s*(Critical|High|Medium|Low|Informational|Recommendation)\b',l.content,re.I)
            if risk:raw=risk[1]
        title=clean(' '.join(title));pid=None
        identifier=re.match(r'^\(([CHMLI]\d+)\)\s*(.+)',title,re.I)
        if identifier:pid=identifier[1];title=identifier[2]
        if raw:
            out.append(Candidate(line.start,title,raw,pid,method='certora-tabular-issue-card',confidence=.93,
                                 evidence={'severity_basis':'explicit_field'}))
    return _bound_findings(report,out)


def parse_verification_tables(report):
    """Early review tables; verified rule inventories are never findings."""
    report=view(report);out=[]; columns=None
    for i,line in enumerate(report.lines):
        header=re.match(r'^\s*Issue\s{2,}.*?Description\s{2,}Severity\b',line.text,re.I)
        if header:
            issue_width=re.search(r'\s{2,}(?:Rule broken|Description)',line.text,re.I)
            columns=(line.text.lower().index('description'),line.text.lower().index('severity'),issue_width.start() if issue_width else line.text.lower().index('description'))
            continue
        if columns and re.fullmatch(r'(?:Disclaimer|Notations|Verification.*)',line.content,re.I):break
        if not columns:continue
        desc_col,sev_col,width=columns
        m=re.match(r'\s*(Critical|High|Medium|Low|Informational|Recommendation)\b',line.text[max(desc_col,sev_col-3):],re.I)
        title=line.text[:desc_col].strip()
        if not m or not title:continue
        # The first column is the issue, while a middle Rule broken column is
        # optional. Its boundary is supplied by the printed header.
        pieces=[line.text[:width].strip()]
        for nxt in report.lines[i+1:i+16]:
            if re.match(r'\s*(?:Critical|High|Medium|Low|Informational)\b',nxt.text[max(desc_col,sev_col-3):],re.I):break
            left=nxt.text[:width].strip()
            if left and not re.search(r'www\.certora|Disclaimer|Notations',left,re.I):pieces.append(left)
        out.append(Candidate(line.start,clean(' '.join(pieces)),m[1],method='certora-early-issue-table',confidence=.88,
                             evidence={'severity_basis':'explicit_table_column'}))
    return _bound_findings(report,out)


def parse_bug_advisory(report):
    """2019 standalone ungraded advisory, one document-level issue."""
    title=next((l for l in report.lines if l.content),None)
    if not title:return []
    return [Candidate(title.start,clean(title.content),None,method='certora-standalone-bug-advisory',confidence=.9,
                      evidence={'severity_basis':'not_printed'})]


def parse_scoped_id_cards(report):
    """2025–26 combined reviews restart native finding IDs per project scope."""
    candidates=parse_id_cards(report)
    r=view(report)
    sections=[]
    for i,line in enumerate(r.lines):
        if line.content!='Project Overview':continue
        previous=next((l for l in reversed(r.lines[max(0,i-5):i]) if l.content),None)
        if previous and not re.search(r'Project Summary|\.{3,}|\d+$',previous.content,re.I):
            sections.append((previous.start,clean(previous.content),previous.end))
    # Only explicit distinct project chapters establish namespaces.
    if len({s[1] for s in sections})<2:return candidates
    for c in candidates:
        applicable=[s for s in sections if s[0]<c.start]
        if applicable:
            pos,title,end=applicable[-1]
            c.evidence['container_id']=title
            c.evidence['scope_heading_span']={'start':pos,'end':end,'text':report.text[pos:end]}
    return candidates


def filter_resolution_prose(candidates):
    """Exclude an already-seen ID restated as a resolution sentence.

    The real detail card remains authoritative. Require all three source
    signals: repeated ID, prefix-derived severity, and the observed sentence.
    This does not deduplicate report findings merely because IDs recur.
    """
    seen, output, excluded = set(), [], []
    for candidate in candidates:
        prose = (candidate.printed_id in seen
                 and candidate.evidence.get('severity_basis') == 'printed_id_prefix'
                 and re.match(r'^should therefore be marked\s+', candidate.title or '', re.I))
        if prose:
            if output and output[-1].end == candidate.start and candidate.end is not None:
                output[-1].end = candidate.end
            excluded.append(dict(start=candidate.start, end=candidate.end, printed_id=candidate.printed_id,
                                 title=candidate.title, reason='repeated_finding_id_in_resolution_sentence'))
            continue
        seen.add(candidate.printed_id)
        output.append(candidate)
    return output, excluded


def parse(report):
    """Direct-call compatibility; dispatcher uses only one era entry point."""
    ids=parse_id_cards(report)
    return filter_resolution_prose(ids or parse_issue_cards(report) or parse_narrative(report) or parse_verification_tables(report))[0]


def printed_counts(report):
    report=view(report)
    # Modern Discovered/Confirmed/Fixed tables print '-' for zero. Read only the
    # Discovered column; later columns represent remediation, not finding totals.
    for i,line in enumerate(report.lines):
        if not re.fullmatch(r"(?:Findings Summary|Summary of findings)",line.content,re.I):
            continue
        counts,proof={},[]
        ls=report.lines[i+1:i+45]
        for ix,l in enumerate(ls):
            if re.fullmatch(r"(?:Detailed Findings|Main Issues Discovered|Severity Matrix)",l.content,re.I):
                break
            m=re.match(r"^\s*(Critical|High|Medium|Low|Informational)\s+(-|\d+)(?:\s|$)",unicodedata.normalize('NFKC',l.text),re.I)
            label=re.fullmatch(r"(Critical|High|Medium|Low|Informational)(?:\s+\d+\s+full,.*)?",l.content,re.I)
            if label:
                following=next((x for x in ls[ix+1:ix+4] if x.content),None)
                number=re.match(r"^\s*(\d+|-)(?:\s|$)",following.content) if following else None
                if number:
                    key=SeverityLookup(report.firm, ('informational',)).get(label[1].lower(),label[1].lower())
                    counts[key]=0 if number[1]=='-' else int(number[1])
                    proof.append({"start":l.start,"end":following.end,"text":report.text[l.start:following.end]})
                    continue
            if m:
                key=SeverityLookup(report.firm, ('informational',)).get(m[1].lower(),m[1].lower())
                counts[key]=0 if m[2]=='-' else int(m[2])
                proof.append({"start":l.start,"end":l.end,"page":l.page,"text":report.text[l.start:l.end]})
        if len(counts)>=3:
            result={"counts":counts,"basis":"printed_discovered_column","evidence":proof}
            conflicts=source_severity_conflicts(report)
            if conflicts:
                result|={"severity_conflicts":conflicts,
                         "detail_conflict_note":"Printed severity fields contradict finding ID prefixes; numeric summary remains comparable."}
            return result
    # Several early verification summaries state numeric findings in prose.
    counts,proof={},[]
    for m in re.finditer(r"\b(\d+)\s+(high|medium|low)\s+severity\s+issues?",report.text[:7000],re.I):
        counts[m[2].lower()]=int(m[1]);proof.append({"start":m.start(),"end":m.end(),"text":m[0]})
    return {"counts":counts,"basis":"printed_severity_totals_prose","evidence":proof} if len(counts)>=2 else None


def source_severity_conflicts(report):
    """Independent raw-source evidence; never consult extracted Candidates."""
    conflicts=[]
    for i,line in enumerate(report.lines):
        m=ID.match(line.content)
        if not m or re.search(r"\.{3,}",line.content):
            continue
        expected=severity(m[1], report.firm)
        if expected=='unknown':
            continue
        metadata=[]
        for l in report.lines[i+1:i+12]:
            if ID.match(l.content) or re.match(r"^(?:Description|Bug description|Recommendation)\s*:?​?$",clean(l.content),re.I):
                break
            metadata.append(l)
        raw=field_severity('\n'.join(l.text for l in metadata))
        if raw and severity(raw, report.firm)!=expected:
            end=metadata[-1].end if metadata else line.end
            conflicts.append({"start":line.start,"end":end,"printed_id":m[1]+'-'+m[2],"id_bucket":expected,
                              "severity_field":raw,"text":report.text[line.start:end]})
    return conflicts


from variants import Variant, Fingerprint
from layout_support import STATUS, status_value, view

CERTORA_STATUS=(r'(?:Acknowledged and will be fixed|Acknowledged and fixed|Will not be fixed|Will be fixed|'
                r'Not yet fixed|Not an issue|No fix required|Partially (?:Fixed|Resolved|Addressed|Mitigated)|'+STATUS+r')')


def _set_status(report,c,claim):
    raw,start,end,basis=claim
    c.status_raw=raw
    key=clean(raw).casefold()
    c.normalized_status={'not yet fixed':'open','no fix required':'acknowledged','partially addressed':'partial',
                         'partially mitigated':'partial','will not be fixed':'acknowledged','will be fixed':'open',
                         'acknowledged and will be fixed':'open','not an issue':'invalid',
                         'acknowledged and fixed':'fixed'}.get(key) or status_value(raw,'certora')
    c.evidence['status_evidence']={'raw':raw,'start':start,'end':end,'text':report.text[start:end],
                                  'basis':basis,'profile':'certora'}


def status_id_cards(report,candidates):
    indices={};scope=None
    scope_names={c.evidence['container_id'] for c in candidates if c.evidence.get('container_id')}
    for line in report.lines:
        if clean(line.content) in scope_names:scope=clean(line.content)
        m=ID.match(line.content)
        if not m or not re.search(r'\s{2,}',line.text):continue
        st=re.search(r'\b('+CERTORA_STATUS+r')\b',line.text,re.I)
        if st:indices.setdefault((scope,(m[1]+'-'+m[2]).casefold()),[]).append((st[1],line.start+st.start(1),line.start+st.end(1),'printed_id_status_table'))
    for c in candidates:
        c.evidence['status_reader_complete']=True
        # Clear inferred/legacy statuses: final evidence must identify an exact
        # labelled field inside this finding or a uniquely linked index row.
        c.status_raw=None;c.normalized_status=None
        body=report.text[c.start:c.end]
        claims=[]
        for m in re.finditer(r'\b(?:Status|Resolution Status)(?:[ \t]*:[ \t]*|[ \t]*\n[ \t\n]*)(?:\{\s*)?('+CERTORA_STATUS+r')\b',body,re.I):
            claims.append((m[1],c.start+m.start(1),c.start+m.end(1),'labelled_status_field'))
        for m in re.finditer(r'(?:^|\n)\s*(?:Resolution|Fix Review|Mitigation/Fix|Update)\s*:?\s*\n\s*('+CERTORA_STATUS+r')\b',body,re.I):
            claims.append((m[1],c.start+m.start(1),c.start+m.end(1),'resolution_section'))
        if claims:_set_status(report,c,max(claims,key=lambda claim:claim[1]));continue
        claims=indices.get((c.evidence.get('container_id'),(c.printed_id or '').casefold()),[])
        if len({status_value(x[0],'certora') for x in claims})==1:
            _set_status(report,c,claims[-1])
        elif claims:c.evidence['status_conflict']=True


def status_issue_cards(report,candidates):
    status_id_cards(report,candidates)
    for c in candidates:
        if c.status_raw:continue
        body=report.text[c.start:c.end]
        # A mitigation suggestion is not a fix assertion. Read only an actual
        # remediation label at the start of the publisher's response field.
        m=re.search(r'\b(?:Mitigation/Fix|Mitigation|Fix|Response|Resolution)\s*:\s*('+CERTORA_STATUS+r')\b',body,re.I)
        if not m:
            # PDF table extraction can place the first response line above
            # its left-column Mitigation/Fix label. Keep the source offsets.
            m=re.search(r'(?m)^[ \t]{4,}('+CERTORA_STATUS+r')\b[^\n]*\n[ \t]*Mitigation/Fix:',body,re.I)
        if m:
            _set_status(report,c,(m[1],c.start+m.start(1),c.start+m.end(1),'publisher_resolution_response'))
            continue
        for response in re.finditer(r'\bResponse\s*:',body,re.I):
            start=max(0,response.start()-150);end=min(len(body),response.end()+400)
            text=body[start:end]
            m=re.search(r'\b(?:This (?:issue|bug)|The issue)\s+(?:was|has been)\s+('+CERTORA_STATUS+r')\b',text,re.I)
            if m:
                _set_status(report,c,(m[1],c.start+start+m.start(1),c.start+start+m.end(1),'publisher_resolution_response'))
                break
        if c.status_raw:continue
        # Early narrative advisories explicitly record verification of a later
        # version even without a Response label. Never read a proposed fix.
        m=re.search(r'\b(?:confirmed|verified)\s+that\s+(?:it|the issue|this issue)\s+(?:was|has been)\s+(fixed|resolved)\b',body,re.I)
        if m:_set_status(report,c,(m[1],c.start+m.start(1),c.start+m.end(1),'verified_later_version_assertion'))


def status_verification_tables(report,candidates):
    status_issue_cards(report,candidates)
    for c in candidates:
        if c.status_raw:continue
        body=report.text[c.start:c.end]
        cells=list(re.finditer(r'\b(?:Critical|High|Medium|Low)\s{2,}(Fixed|Resolved|Acknowledged|Known issue)\b',body,re.I))
        # Some old extraction cards span several table rows. Never borrow a
        # neighbouring row's verdict for one of those ambiguous candidates.
        if len(cells)==1:
            cell=cells[0]
            _set_status(report,c,(cell[1],c.start+cell.start(1),c.start+cell.end(1),'verification_table_response_cell'))
    # Source-explicit collective remediation applies only to the named grades.
    m=re.search(r'All (?:the )?(high[-\s]+and[-\s]+medium) issues were promptly (corrected)',report.text,re.I)
    if m:
        for c in candidates:
            if not c.status_raw and severity(c.severity_raw,report.firm) in {'high','medium'}:
                _set_status(report,c,(m[2],m.start(2),m.end(2),'explicit_collective_remediation_statement'))
                c.normalized_status='fixed'
                c.evidence['status_scope']={'start':m.start(),'end':m.end(),'text':m[0]}


def status_tabular_issue_cards(report,candidates):
    status_issue_cards(report,candidates)
    all_fixed=re.search(r'All\s+issues were (corrected)',report.text,re.I)
    for c in candidates:
        if c.status_raw:continue
        body=report.text[c.start:c.end]
        response=re.search(r'(?:^|\n)\s*Response[ \t]{2,}([\s\S]*?)(?=\n\s*(?:Severity|Issue|Notations)\b|\Z)',body,re.I)
        if response:
            claim=re.search(r'\b(?:The issue|This issue)\s+(?:was|has been)\s+('+CERTORA_STATUS+r')\b',response[1],re.I)
            if claim:
                start=c.start+response.start(1)+claim.start(1)
                _set_status(report,c,(claim[1],start,start+len(claim[1]),'publisher_resolution_response'))
                continue
            claim=re.search(r'\b(not an issue)\b',response[1],re.I)
            if claim:
                start=c.start+response.start(1)+claim.start(1)
                _set_status(report,c,(claim[1],start,start+len(claim[1]),'publisher_resolution_response'))
                c.normalized_status='invalid'
                continue
        if all_fixed:
            _set_status(report,c,(all_fixed[1],all_fixed.start(1),all_fixed.end(1),'explicit_collective_remediation_statement'))
            c.normalized_status='fixed'
            c.evidence['status_scope']={'start':all_fixed.start(),'end':all_fixed.end(),'text':all_fixed[0]}


VARIANTS=(
    Variant('certora/v2025_multi_scope_cards',Fingerprint((
        ('repeated_project_overviews',r'^\s*Project Overview\s*$[\s\S]*?^\s*Project Overview\s*$',19),
        ('severity_id',r'^\s*[CHMLI]-\d+',2),
    ),('2025','2026')),parse_scoped_id_cards,('certora_scoped_cards',),status_id_cards,printed_counts,
            notes='Combined reviews with explicit project chapters; repeated IDs and index statuses are scoped to their printed project.'),
    Variant('certora/v2023_severity_id_cards',Fingerprint((
        ('severity_id',r'^\s*(?:Critical|Crit|Cr|High|Medium|Low|Informational|INFO|Note|Issue|[CHMLIN])[-–]\s*\d{1,3}[.:–-]?\s+\S',11),
        ('discovered_summary',r'^\s*Severity\s+Discovered\s+Confirmed\s+Fixed',4),
        ('detail_chapter',r'^\s*(?:Detailed Findings|Main Issues Discovered)\s*$',2),
    ),('2023','2026')),lambda report: filter_resolution_prose(parse_id_cards(report))[0],('certora_id_card','certora_id_source_conflict','certora_split_ids'),status_id_cards,printed_counts,
            notes='ID/title followed by labelled Severity/Status; numeric Discovered column independent of remediation.'),
    Variant('certora/v2020_issue_cards',Fingerprint((
        ('issue_card',r'^\s*Issue:\s*\S',8),('severity_field',r'^\s*Severity:',2),
    ),('2020','2024')),parse_issue_cards,('certora_issue_card',),status_issue_cards,printed_counts,
            notes='Vertical Issue cards preceded by severity; Mitigation/Fix is read only when it asserts an outcome.'),
    Variant('certora/v2021_tabular_issue_cards',Fingerprint((
        ('aligned_issue_card',r'^\s*Issue[ \t]{2,}(?!Rule broken|Description)\S',8),
        ('aligned_severity',r'^\s*Severity[ \t]{2,}(?:Critical|High|Medium|Low|Informational)',3),
        ('severity_field',r'^\s*Severity:',2),
    ),('2021','2023')),parse_tabular_issue_cards,('certora_tabular_issue_card',),status_tabular_issue_cards,printed_counts,
            notes='Aligned Issue/Severity cards without punctuation, optional (M1) IDs; fixes require explicit responses or collective assertions.'),
    Variant('certora/v2018_numbered_narrative',Fingerprint((
        ('numbered_issue',r'^\s*Issue\s+\d+\s+\S',12),('sekura',r'Sekura Team',2),
    ),('2018','2020')),parse_narrative,('certora_numbered_narrative',),status_issue_cards,printed_counts,
            notes='Unrated numbered prose issues; lower-case issue references are excluded.'),
    Variant('certora/v2019_bug_advisories',Fingerprint((
        ('advisory_title',r'\A[ \t\n]*[^\n]{3,100}\bbug\b[^\n]{0,60}\n',8),
        ('technical_description',r'General Description|Technical Description and Example|finite supply property',4),
    ),('2019','2019')),parse_bug_advisory,('certora_bug_advisory',),status_issue_cards,printed_counts,
            notes='Standalone bug advisories; the document title is the single ungraded issue title.'),
    Variant('certora/v2019_verification_tables',Fingerprint((
        ('issue_table',r'^\s*Issue\s{2,}[^\n]*Description\s{2,}Severity\b',9),
        ('formal_verification',r'Formal Verification|Verification (?:Report|of)|Certora Prover|certora\.com',6),
        ('early_prototype',r'Compound Verification|Sekura Team',6),
    ),('2018','2024')),parse_verification_tables,('certora_verification_table','certora_verification_only'),status_verification_tables,printed_counts,
            notes='Early issue tables or verification-only narratives; verified rule tables do not emit findings.'),
)
