"""Matching views and explicit remediation receipts shared by layout variants."""
from copy import copy
from dataclasses import replace
import re
import unicodedata
from core import clean, status

RISK=r'(?:Critical|High|Medium|Low|Informational|Information|Info|Gas(?: Optimizations?)?|Undetermined)'
STATUS=r'(?:Code Partially Corrected|Partially (?:Resolved|Fixed|Implemented)|Not (?:Resolved|Fixed|Implemented)|Code Corrected|Specification (?:Changed|Updated)|Risk Accepted|Design Changed|Remediated|Addressed|Acknowledged|Acknowledge|Ack[’\x27]d|Unresolved|Resolved|Fixed|Open|Pending|Implemented|Mitigated|Accepted|Invalid|Verified|Patched|Won[’\x27]t Fix|To-do|WIP|Reported)'


def visible(text):
    text=re.sub(r'[\u200b\ufeff\u202a-\u202e\u2066-\u2069]','',text)
    for word in ('Critical','High','Medium','Low','Informational','Information','Resolved','Unresolved','Acknowledged','Fixed'):
        pattern=r'(?<!\w)'+r'[ \t]*'.join(word)+r'(?!\w)'
        text=re.sub(pattern,lambda m:re.sub(r'[ \t]','',m[0]),text,flags=re.I)
    return text


def view(report):
    result=copy(report)
    result.lines=[replace(l,text=visible(l.text),content=visible(l.content)) for l in report.lines]
    return result


def bounded(report,candidates,stop=None):
    candidates=sorted(candidates,key=lambda c:c.start)
    for i,c in enumerate(candidates):
        end=candidates[i+1].start if i+1<len(candidates) else len(report.text)
        if c.end is not None:end=min(end,c.end)
        if stop:
            for line in report.lines:
                if c.start<line.start<end and re.fullmatch(stop,visible(line.content),re.I):
                    end=line.start;break
        c.end=end
    return candidates


def _key(raw):
    return re.sub(r'\s+',' ',visible(raw).casefold()).strip().rstrip('.')


def status_value(raw,profile):
    key=_key(raw)
    shared={'code corrected':'fixed','code partially corrected':'partial','specification changed':'resolved',
            'specification updated':'resolved','design changed':'resolved','risk accepted':'acknowledged',
            'remediated':'resolved','addressed':'resolved','acknowledge':'acknowledged',"ack'd":'acknowledged','ack’d':'acknowledged',
            'to-do':'open','not fixed':'open','reported':'open','mitigated':'resolved',
            'accepted':'acknowledged',"won't fix":'acknowledged','won’t fix':'acknowledged'}
    if key=='verified' and profile=='cantina':return 'resolved'
    return shared.get(key) or status(raw)


def attach_status(report,candidates,profile):
    """Only labelled fields, card badges, ID-linked tables and resolution headings.

    Never infer remediation from a free-text recommendation or the word 'fixed'
    in an arbitrary paragraph. Ambiguous index claims cannot fill missing status.
    """
    indices={}
    for line in report.lines:
        value=visible(line.text)
        if not (re.search(r'\s{2,}|\|',value) or re.match(r'^\s*(?:OS-|KS-|QSP-|[CHMLIG]-)',value)):
            continue
        ids=re.findall(r'\b(?:OS-[A-Z0-9-]+-\d+|KS-[A-Z0-9-]+-\d+|QSP-\d+|[CHMLIG]-\d+)\b',value)
        m=re.search(r'\b('+STATUS+r')\b',line.text,re.I)
        if m:
            for pid in ids:indices.setdefault(pid,[]).append((m[1],line.start+m.start(1),line.start+m.end(1),'printed_id_status_table'))
    for c in candidates:
        body=report.text[c.start:c.end]
        matches=[]
        for m in re.finditer(r'(?:Status|Resolution Status)\s*[:|]?\s*\n?\s*('+STATUS+r')\b',body,re.I):
            matches.append((m[1],c.start+m.start(1),c.start+m.end(1),'labelled_status_field'))
        if profile=='chainsecurity':
            for m in re.finditer(r'\b(?:Version\s+\d+\s+|[Ë✓]\s*)('+STATUS+r')\b',body[:1300],re.I):
                matches.append((m[1],c.start+m.start(1),c.start+m.end(1),'classification_status_badge'))
        if profile=='cantina':
            for m in re.finditer(r'Cantina(?: Security| Managed)?\s*:\s*(?:Fix\s+)?('+STATUS+r')\b',body,re.I):
                matches.append((m[1],c.start+m.start(1),c.start+m.end(1),'publisher_resolution_response'))
        if profile in {'ottersec','theori','kudelski-security','zokyo'}:
            for m in re.finditer(r'(?:^|\n)\s*(?:Remediation|Resolution|Fix Review|Update)\s*[.:]?\s*\n\s*('+STATUS+r')\b',body,re.I):
                matches.append((m[1],c.start+m.start(1),c.start+m.end(1),'resolution_section'))
        if matches:
            raw,start,end,basis=matches[-1]
            c.status_raw=raw
        elif c.status_raw:
            # Existing parser selected a printed card label; record its exact
            # location if matching-only glyph normalization changed the string.
            raw=c.status_raw; start=body.lower().find(raw.lower())
            if start<0:
                pattern=r'\s*'.join(re.escape(ch) for ch in re.sub(r'\s','',raw))
                m=re.search(pattern,body,re.I)
                if m:raw=m[0];start=m.start()
            if start>=0:start+=c.start;end=start+len(raw);basis='printed_card_label'
            else:
                c.normalized_status=status_value(raw,profile)
                continue
        else:
            claims=indices.get(c.printed_id,[])
            unique={status_value(claim[0],profile) for claim in claims}
            if len(unique)!=1:
                if claims:c.evidence['status_conflict']=True
                continue
            raw,start,end,basis=claims[-1];c.status_raw=raw
        c.normalized_status=status_value(raw,profile)
        c.evidence['status_evidence']={'raw':raw,'start':start,'end':end,'text':report.text[start:end],
                                      'basis':basis,'profile':profile}


def status_parser(profile):
    def parse(report,candidates):return attach_status(report,candidates,profile)
    return parse
