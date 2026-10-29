"""ChainLight/Theori detail cards, legacy issues and bilingual Orb findings.

Risk comes from the detail card, never the independent front breakdown. Printed
THE-prefixed card IDs take precedence over shorter IDs used in some headings.
"""
from core import severity, Candidate, clean
import re

DESCRIPTION = "ChainLight/Theori detail-card risk, legacy Issue headings, Orb ID Code fields and separate recommendations"
RISK = r"Critical|High|Medium|Low|Minor|Informational|Information|Note"
PID = r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{3}"


def visible(text):
    return re.sub(r"[\u202a-\u202e\u2066-\u2069]", "", text)


def _cards(report, family=None):
    out = []
    lines = report.lines
    index_status={}
    for page in report.meta["pages"]:
        if not re.search(r"\bID\s+Title\s+Severity\s+Status",page["text"]):
            continue
        offset=page["start"]
        for row in page["text"].splitlines(keepends=True):
            m=re.search(r"\b("+PID+r")\b.*?\s{2,}(Patched|Fixed|Acknowledged|Mitigated|WIP|Reported|Won[’']t Fix)\s*$",row)
            if m:
                index_status[m[1]]=(m[2],{"start":offset,"end":offset+len(row.rstrip('\n')),"page":page["page"]})
            offset+=len(row)
    for i, line in enumerate(lines):
        value = visible(line.content)
        modern = re.match(r"^#(\d+)\s+(" + PID + r")\s+(.+)", value)
        legacy = re.match(r"^Issue\s*#(\d+)(?:\s*:\s*|\s+)(.+)", value)
        orb = re.match(r"^4\.2\.\d+\.\s+(" + PID + r"):\s*(.+)", value)
        if family == 'issue':
            modern = orb = None
        elif family == 'numbered':
            legacy = orb = None
        elif family == 'bilingual':
            modern = legacy = None
        rec = re.match(r"^Recommendation\s*#(\d+)(?:\s*:\s*|\s+)(.+)", value)
        if family in {'numbered', 'bilingual'}:
            rec = None
        if not any((modern, legacy, orb, rec)):
            continue
        # A TOC entry can wrap onto several lines. Require its actual metadata
        # header nearby; report.lines' page-wide exclusions also mark real cards.
        ahead = []
        for following in lines[i+1:i+18]:
            if re.match(r'^(?:Issue|Recommendation)\s*#\d+\b|^#\d+\s+'+PID,visible(following.content),re.I):break
            ahead.append(following)
        header = next((j for j,l in enumerate(ahead)
                       if re.search(r"(?:Summary\s+Severity|ID Code.*Severity)",visible(l.text))), None)
        if rec:
            if line.excluded or re.search(r"(?:\.\s*){4,}\s*\d+\s*$",line.text) or re.search(r"\s{3,}\d+\s*$", line.text):
                continue
            following = []
            for l in ahead:
                if not l.content or len(l.content)>60 or re.match(r"(?:The |During |In |We )",l.content):
                    break
                following.append(visible(l.content))
            out.append(Candidate(line.start, clean(" ".join([rec[2]]+following)),
                                 printed_id="Recommendation #"+rec[1], record_kind="recommendation",
                                 method="legacy-recommendation", confidence=.94))
            continue
        if header is None:
            continue
        title = (modern[3] if modern else legacy[2] if legacy else orb[2])
        continuation = [visible(l.content) for l in ahead[:header] if l.content]
        title = clean(" ".join([title]+continuation))
        card = ahead[header:]
        raw, risk_line, split_risk = None, None, False
        for ci,l in enumerate(card):
            t = visible(l.text)
            if re.match(r"^\s*(?:Description\.?|Root Cause|Type|Target)\s*$",t):
                break
            m = re.search(r"\b("+RISK+r")\)?\s*$",t,re.I)
            if m:
                raw, risk_line = m[1], l
                break
            if re.search(r"\bInformationa\s*$",t) and any(re.search(r"\s{3,}l\s*$",visible(q.text)) for q in card[ci+1:ci+3]):
                raw,risk_line,split_risk="Informationa l",l,True
                break
        if not raw:
            continue
        card_text = "\n".join(visible(l.text) for l in card)
        card_id = re.search(r"^\s*("+PID+r")\b",card_text,re.M) if re.search(r"\bID\b",visible(card[0].text)) else None
        pid = card_id[1] if card_id else modern[2] if modern else orb[1] if orb else "Issue #"+legacy[1]
        fixed = re.search(r"\b(Fixed)\s*(?:\(|$)",card_text[:card_text.find(raw)+len(raw)],re.M)
        evidence={"severity_basis":"detail_card_severity", "severity_span":{"start":risk_line.start,"end":risk_line.end}}
        if not fixed and pid in index_status:
            evidence["status_basis"]="printed_id_status_index"
            evidence["status_span"]=index_status[pid][1]
        out.append(Candidate(line.start,title,raw,pid,
                             normalized=severity(raw, report.firm),
                             status_raw=fixed[1] if fixed else index_status.get(pid,(None,None))[0],
                             method="orb-id-code" if orb else "theori-detail-card", confidence=.97,
                             evidence=evidence))
    out.sort(key=lambda c:c.start)
    for i,c in enumerate(out):
        limit = out[i+1].start if i+1<len(out) else len(report.text)
        end = limit
        for li,l in enumerate(lines):
            if not c.start < l.start < limit:
                continue
            t=visible(l.content)
            next_text=next((q.content for q in lines[li+1:li+5] if q.content),"")
            if (re.match(r"^(?:Appendix(?:\b|:)|Revisions$|Revision History$|Theori, Inc\. \()",t)
                    or t=="Recommendations" and next_text.startswith("These are")
                    or c.method=="orb-id-code" and re.match(r"^5\.\s+",t)):
                end=l.start
                break
        c.end=end
        body=visible(report.text[c.start:end])
        m=re.search(r"(?:^|\n)\s*Remediation\.?\s*\n\s*(Patched|Mitigated|Acknowledged|Won[’']t Fix|Fixed|Reported|WIP)\b",body)
        if m:
            c.status_raw=m[1]
        # Preserve native labels; formal era readers add exact status receipts.
    return out


def printed_counts(report):
    """Read only explicitly printed numeric aggregate tables, including bidi PDFs."""
    for page in report.meta["pages"]:
        text=visible(page["text"])
        if not (re.search(r"^Finding Breakdown by Severity\s*$",text,re.M)
                or re.search(r"Severity Classification|취약점 Severity 분류",text)):
            continue
        counts, proof = {}, []
        offset=page["start"]
        for line in page["text"].splitlines(keepends=True):
            m=re.match(r"^\s*("+RISK+r")\s+(\d+)\b",visible(line),re.I)
            if m:
                key=severity(m[1], report.firm)
                counts[key]=counts.get(key,0)+int(m[2])
                proof.append({"page":page["page"],"start":offset,"end":offset+len(line.rstrip('\n')),"text":line.rstrip('\n')})
            offset+=len(line)
        if len(counts)>=3:
            return {"counts":counts,"basis":"chainlight_printed_severity_breakdown","evidence":proof}
    return None


def parse(report):
    """Compatibility entrypoint used by Theori; formal variants restrict grammar."""
    return _cards(report)


def issue_cards(report):
    return _cards(report, 'issue')


def numbered_cards(report):
    return _cards(report, 'numbered')


def bilingual_cards(report):
    return _cards(report, 'bilingual')


STATUS = r"Partially (?:Fixed|Resolved)|Not (?:Fixed|Resolved)|Patched|Fixed|Acknowledged|Mitigated|WIP|Reported|Won[’']t Fix|Confirm|Resolved|Open"


def _proof(report, raw, start, end, basis):
    return {'raw':raw, 'start':start, 'end':end,
            'text':report.text[start:end], 'basis':basis, 'profile':'chainlight'}


def _set_status(report, c, match, basis, offset=0):
    from layout_support import status_value
    raw=match[1]
    c.status_raw=raw
    c.normalized_status=status_value(raw, 'chainlight')
    c.evidence['status_evidence']=_proof(report,raw,offset+match.start(1),offset+match.end(1),basis)


def _status(report, candidates, family):
    """Use final remediation badges, then card badges, then ID-linked indexes.

    Status index rows can span several PDF lines. Matching is constrained to
    the printed status column and to one ID block. No recommendation prose can
    create a fix, and disagreeing index claims leave the status unfilled.
    """
    from layout_support import status_value
    indices={}
    for page in report.meta['pages']:
        if not re.search(r'ID\s+Title\s+Severity\s+Status',visible(page['text'])):
            continue
        header=re.search(r'\bStatus\b',page['text'])
        if not header:continue
        lines=page['text'].splitlines(keepends=True);offset=page['start'];current=None
        for row in lines:
            pid=re.search(r'\b('+PID+r')\b',row)
            if pid:current=pid[1]
            m=re.search(r'\b('+STATUS+r')\s*$',row,re.I)
            if current and m:
                claim=(m[1],offset+m.start(1),offset+m.end(1))
                indices.setdefault(current,[]).append(claim)
            offset+=len(row)
    for c in candidates:
        # Remove the legacy parser's status guess; this reader supplies receipts.
        c.status_raw=c.normalized_status=None
        body=report.text[c.start:c.end]
        lines=[l for l in report.lines if c.start<=l.start<c.end]
        claims=[]
        for i,line in enumerate(lines):
            value=visible(line.content)
            # Recognize labelled fields and the native remediation status badge.
            m=re.fullmatch(r'(?:Status|Resolution Status)\s*[:|]?\s*('+STATUS+r')',line.content,re.I)
            if m:claims.append((m,'labelled_status_field',line.start+len(line.text)-len(line.text.lstrip())))
            if not re.fullmatch(r'Remediation[.:]?|Resolution[.:]?|Fix Review[.:]?',value,re.I):continue
            for nxt in lines[i+1:i+10]:
                t=visible(nxt.content)
                if not t or re.match(r'©|Theori, Inc\.|\d+\s*(?:/\s*\d+)?$',t):continue
                m=re.fullmatch(r'('+STATUS+r')',nxt.content,re.I)
                if m:
                    leading=len(nxt.text)-len(nxt.text.lstrip())
                    claims.append((m,'remediation_status_badge',nxt.start+leading))
                break
        if claims:
            _set_status(report,c,*claims[-1])
            continue
        # Older cards sometimes print Fixed above a separate commit parenthesis.
        head=body[:min(1000,body.find('Description') if 'Description' in body else 1000)]
        m=re.search(r'\b(Fixed)\s*\(',head)
        if m:
            _set_status(report,c,m,'detail_card_fix_badge',c.start)
            continue
        indexed=indices.get(c.printed_id,[])
        if len({status_value(x[0],'chainlight') for x in indexed})==1:
            raw,start,end=indexed[-1]
            c.status_raw=raw;c.normalized_status=status_value(raw,'chainlight')
            c.evidence['status_evidence']=_proof(report,raw,start,end,'printed_id_status_table')
        elif indexed:
            c.evidence['status_conflict']=True
        # A native Fix section may contain an explicit completed-fix assertion.
        if c.status_raw:continue
        for m in re.finditer(r'(?:^|\n)[ \t]*Fix[.:]?[ \t]*\n([^\f]+?)(?=\n[ \t]*\n|$)',body,re.I):
            response=m[1]
            fixed=re.search(r'\b(Fixed|Resolved|Acknowledged|Not Fixed|Partially Fixed)\b',response,re.I)
            if fixed and not re.search(r'\b(?:should|could|would|will|must|to be)\b',response[:fixed.start()],re.I):
                _set_status(report,c,fixed,'fix_section_completed_assertion',c.start+m.start(1))
        # The old native Fix sections identify implemented patches by commit,
        # even when their prose is imperative. The reference is the assertion;
        # a proposed patch without an identified commit never sets a status.
        if c.status_raw:continue
        fix=re.search(r'(?:^|\n)[ \t]*Fix[.:]?[ \t]*\n',body,re.I)
        if not fix:continue
        response=body[fix.end():]
        incomplete=re.search(r'\b(?:fix was incomplete|partially (?:fixed|applied))\b',response,re.I)
        if incomplete:
            raw=incomplete[0];start=c.start+fix.end()+incomplete.start()
            c.status_raw=raw;c.normalized_status='partial'
            c.evidence['status_evidence']=_proof(report,raw,start,start+len(raw),'fix_section_partial_assertion')
            continue
        paragraph=re.split(r'\n[ \t]*\n',response,1)[0]
        if re.search(r'\(commit [0-9a-f]{7,40}\)',paragraph,re.I) and not re.search(r'\b(?:should|could|would|will|proposed|suggested)\b',paragraph,re.I):
            raw=paragraph.strip();start=c.start+fix.end()+paragraph.index(raw)
            c.status_raw=raw
            c.normalized_status='partial' if re.search(r'decided to keep',raw,re.I) else 'fixed'
            c.evidence['status_evidence']=_proof(report,raw,start,start+len(raw),'fix_section_commit_reference')


def issue_status(report,candidates):
    return _status(report,candidates,'issue')


def numbered_status(report,candidates):
    return _status(report,candidates,'numbered')


def bilingual_status(report,candidates):
    return _status(report,candidates,'bilingual')


from variants import Variant, Fingerprint
VARIANTS=(
    Variant('chainlight/v2021_issue_cards',
            Fingerprint((('issue_heading',r'^\s*(?:Issue|Recommendation)\s*#\d+(?:\s*:|\s+\S)',8),
                         ('legacy_tracking',r'Issue Tracking',2)),('2021','2023')),
            issue_cards,('chainlight_issue','chainlight_issue_missing_glyphs'),issue_status,printed_counts,
            notes='Issue # headings and Summary/Severity cards; old image-glyph body failures remain empty.'),
    Variant('chainlight/v2023_numbered_cards',
            Fingerprint((('numbered_heading',r'^\s*#\d+\s+'+PID+r'\s+\S',8),
                         ('status_categories',r'^\s*Status Categories\s*$',3),
                         ('severity_categories',r'^\s*Severity Categories\s*$',3),
                         ('breakdown',r'^\s*Finding Breakdown by Severity\s*$',2)),('2023','2026')),
            numbered_cards,('chainlight_numbered','chainlight_numbered_zero'),numbered_status,printed_counts,
            notes='ID/Summary/Severity cards and ID-linked status tables; later Remediation badges are authoritative.'),
    Variant('chainlight/v2025_bilingual_orb',
            Fingerprint((('id_code',r'ID Code.*Severity',6),
                         ('orb_heading',r'4\.2\.\d+\.\s+'+PID+r':',5)),('2025','2026')),
            bilingual_cards,('chainlight_bilingual',),bilingual_status,printed_counts,
            notes='English/Korean Orb ID Code cards with bidi text; missing native statuses remain null.'),
)
