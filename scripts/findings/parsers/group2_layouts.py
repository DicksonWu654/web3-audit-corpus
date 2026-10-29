"""Status receipts used only by the Phase 4e group 2 publishers.

Matching is restricted to labelled metadata, publisher responses and ID-linked
index/fix-review rows. Recommendations never establish remediation.
"""
import re
from core import clean, status
from layout_support import status_value

LABEL = (r"Partially\s+(?:Resolved|Fixed|Implemented|Addressed)|Not\s+(?:Resolved|Fixed|Implemented)|"
         r"Confirmed\s+(?:and|&)\s+fixed|Fix\s+verified|Code\s+Partially\s+Corrected|Code\s+Corrected|"
         r"Risk\s+Accepted|Won[’']t\s+Fix|False\s+Positive|Unresolved|Resolved|Acknowledged|"
         r"Fixed|Open|Pending|Implemented|Mitigated|Accepted|Invalid|Verified|Closed|Confirmed|"
         r"Declined|Reported|Addressed|Patched|Void")


def receipt(report, c, raw, start, end, basis, normalized=None):
    c.status_raw = raw
    c.normalized_status = normalized or status_value(raw, report.firm)
    c.evidence['status_evidence'] = dict(raw=raw, start=start, end=end,
        text=report.text[start:end], basis=basis, profile=report.firm)


def normalize(raw, firm):
    key=clean(raw).lower().rstrip('.')
    if key in {'confirmed and fixed','confirmed & fixed','fix verified'}:return 'fixed'
    # A publisher's verification response concerns this finding's fix. It is
    # distinct from a generic Verified badge or code/audit-scope verification.
    if firm=='spearbit' and key=='verified':return 'resolved'
    if key=='partially addressed':return 'partial'
    if key in {'confirmed','reported'}:return 'open'
    if key in {'false positive','void'}:return 'invalid'
    # A declined contest finding may be rejected or accepted without a fix;
    # the label alone cannot distinguish those dispositions.
    if key=='declined':return 'other'
    return status_value(raw,firm)


def statuses(report, candidates, *, fields=('Status','Resolution Status'), responses=False,
             index_id=None, headings=False, narrative=False):
    indices={};review_indices={};review_mode=False
    if index_id:
        # Only an explicit ID and separated columns, or an ID first on a row,
        # can supply an index claim. Multiple contradictory claims stay null.
        for line in report.lines:
            if headings and re.fullmatch(r'(?:\d+(?:\.\d+)*[.)]?\s+)?(?:Fix[- ]Review|Fix Verification|Retest Results|Remediation Summary|Resolution Updates)\s*:?',line.content,re.I):
                review_mode=True;continue
            if line.heading or re.fullmatch(r'(?:Appendix|Conclusion|References)',line.content,re.I):review_mode=False
            pid=re.search(index_id,line.text,re.I)
            if not pid or not (re.search(r'\s{2,}|\|',line.text) or line.content.startswith(pid[0])):continue
            # Status must occupy the terminal separated cell. A word such as
            # Fixed in the issue title or description is not an index status.
            m=re.search(r'(?:[ \t]{2,}|\|[ \t]*)('+LABEL+r')(?:[ \t]+(?:in|at)[ \t]+[^|\n]+)?[ \t.]*$',line.text[pid.end():],re.I)
            if m:
                if m[1].casefold()=='reported' and re.match(r'\s*:',line.text[pid.end()+m.end():]):continue
                start=line.start+pid.end()+m.start(1)
                indices.setdefault(clean(pid[0]).casefold(),[]).append((m[1],start,start+len(m[1])))
                if review_mode:review_indices.setdefault(clean(pid[0]).casefold(),[]).append((m[1],start,start+len(m[1])))
    names='|'.join(re.escape(v) for v in fields)
    for c in candidates:
        body=report.text[c.start:c.end]
        retest=review_indices.get(clean(c.printed_id or '').casefold(),[])
        if retest:
            values={normalize(raw,report.firm) for raw,_,_ in retest}
            if len(values)==1:
                raw,a,b=retest[-1];receipt(report,c,raw,a,b,'fix_review_id_status_table',normalize(raw,report.firm))
            else:c.status_raw=None;c.normalized_status=None;c.evidence['status_conflict']=True
            continue
        claims=[]
        for m in re.finditer(r'(?im)^[ \t]*(?:[•*]\s*)?(?:'+names+r')[ \t]*[:：|]?[ \t]*(?:\n[ \t]*)?('+LABEL+r')\b',body):
            claims.append((m[1],c.start+m.start(1),c.start+m.end(1),'labelled_status_field'))
        if responses:
            for m in re.finditer(r'(?im)^[ \t]*(?:Spearbit|Cantina(?: Managed)?)[ \t]*:[ \t]*(?:(?:This (?:is|has been)|The (?:issue|fix) (?:is|has been))\s+)?('+LABEL+r')\b',body):
                claims.append((m[1],c.start+m.start(1),c.start+m.end(1),'publisher_fix_response'))
        if headings:
            for m in re.finditer(r'(?im)^[ \t]*(?:Resolution|Remediation|Fix Review|Verification)[ \t]*[:：]?[ \t]*\n[ \t]*('+LABEL+r')\b',body):
                claims.append((m[1],c.start+m.start(1),c.start+m.end(1),'resolution_section'))
        if narrative:
            # Assertion text is scoped to the explicit Status field only.
            for m in re.finditer(r'(?im)^[ \t]*(?:[•*]\s*)?Status[ \t]*[:：]?[ \t]*([^\n]*(?:\n(?![ \t]*\n|[ \t]*(?:Description|Recommendation|Contracts?|Resources?|References?|Impact|Target)\b)[^\n]+){0,2})',body):
                assertion=m[1]
                hit=re.search(r'\b(?:has been|have been|had been|is|was|were)\s+('+LABEL+r')\b',assertion,re.I)
                if hit:
                    a=c.start+m.start(1)+hit.start(1)
                    claims.append((hit[1],a,a+len(hit[1]),'labelled_status_assertion'))
        if claims:
            raw,a,b,basis=max(claims,key=lambda x:x[1])
            receipt(report,c,raw,a,b,basis,normalize(raw,report.firm));continue
        # Retain explicit parser-selected statuses (metadata cells/parentheses),
        # locating the exact source spelling for their receipt where possible.
        if c.status_raw:
            raw=c.status_raw
            hit=re.search(re.escape(raw),body,re.I)
            if not hit:
                # PDF direction controls can split a printed PARTIALLY /
                # IMPLEMENTED badge. Keep matching-only normalization out of
                # the evidence coordinates and recover its exact source span.
                controls=r'[\u202a-\u202e\u2066-\u2069]*'
                tokens=re.split(r'\s+',raw.strip())
                pattern=r'[\s\u202a-\u202e\u2066-\u2069]+'.join(controls.join(map(re.escape,token)) for token in tokens)
                hit=re.search(pattern,body,re.I)
            if hit:receipt(report,c,hit[0],c.start+hit.start(),c.start+hit.end(),'printed_card_label',normalize(raw,report.firm));continue
        claims=indices.get(clean(c.printed_id or '').casefold(),[])
        if claims:
            values={normalize(raw,report.firm) for raw,_,_ in claims}
            if len(values)==1:
                raw,a,b=claims[-1];receipt(report,c,raw,a,b,'printed_id_status_index',normalize(raw,report.firm))
            else:
                c.status_raw=None;c.normalized_status=None;c.evidence['status_conflict']=True


def subset(report, predicate):
    """Matching-only line view; source offsets and full original text persist."""
    from copy import copy
    result=copy(report)
    result.lines=[l for l in report.lines if predicate(l)]
    return result
