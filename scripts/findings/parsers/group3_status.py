"""Explicit status receipts for the ten Phase 4e group 3 publisher grammars.

Publisher parsers supply the structural patterns and table joins. This module
only preserves exact offsets, precedence and their reviewed native vocabulary.
It is not a generic report-wide keyword scanner.
"""
import re
from core import status

STATE = (r'(?:Partially (?:Fixed|Resolved|Solved|Implemented|Addressed)|'
         r'Not (?:Fixed|Resolved|Retested|Implemented)|Risk Accepted|No action taken|'
         r'Failed [Rr]esolution|W[oO][nN][’\x27]t [Ff]ix|Largely Resolved|Partly Resolved|'
         r'Acknowledged|Unresolved|Resolved|Implemented|Mitigated|Addressed|Accepted|'
         r'False Positive|Dismissed|Rejected|Invalid|Closed|Pending|Reported|Fixed|Solved|Open|New|ACKED|INFO)')


def normalized(raw, firm):
    key = re.sub(r'\s+', ' ', raw.casefold()).strip().rstrip('.!')
    common = {'solved':'fixed', 'partially solved':'partial', 'partly resolved':'partial',
              'largely resolved':'resolved', 'partially addressed':'partial',
              'mitigated':'resolved', 'addressed':'resolved', 'reported':'open',
              'new':'open', 'no action taken':'open', 'failed resolution':'open',
              'not fixed':'open', 'not retested':'other', 'false positive':'invalid'}
    if firm == 'dedaub':
        common.update({'dismissed':'acknowledged', "won't fix":'acknowledged', 'won’t fix':'acknowledged'})
    return common.get(key) or status(raw)


def claim(report, match, offset=0, basis='labelled_status_field', group=1):
    start, end = offset+match.start(group), offset+match.end(group)
    return {'raw':report.text[start:end], 'start':start, 'end':end,
            'text':report.text[start:end], 'basis':basis, 'profile':report.firm}


def apply(report, candidate, claims):
    if not claims:
        candidate.status_raw = candidate.normalized_status = None
        return
    proof = claims[-1]
    candidate.status_raw = proof['raw']
    candidate.normalized_status = normalized(proof['raw'], report.firm)
    candidate.evidence['status_evidence'] = proof
    if len(claims) > 1:
        candidate.evidence['status_claims'] = claims
        if len({normalized(c['raw'],report.firm) for c in claims}) > 1:
            candidate.evidence['status_precedence'] = 'last_explicit_detail_claim_over_index_or_heading'


def fields(report, candidates, patterns=(), *, tables=None, preserve=True):
    """Index fallback, then the card's label, then explicit body response fields."""
    for c in candidates:
        body = report.text[c.start:c.end]
        claims = list((tables or {}).get(c.printed_id, []))
        if len({normalized(v['raw'],report.firm) for v in claims}) > 1:
            c.evidence['status_index_conflict'] = claims
            claims = []
        if preserve and c.status_raw:
            m = re.search(re.escape(c.status_raw), body, re.I)
            if m:
                claims.append(claim(report,m,c.start,'printed_card_label',0))
            elif c.evidence.get('status_evidence'):
                proof=c.evidence['status_evidence']
                if report.text[proof['start']:proof['end']] == c.status_raw:
                    claims.append(proof)
            # Overview status may lie outside the finding body.
            elif c.evidence.get('overview_row'):
                row=c.evidence['overview_row']
                m=re.search(re.escape(c.status_raw),report.text[row['start']:row['end']],re.I)
                if m: claims.append(claim(report,m,row['start'],'printed_overview_status',0))
        found=[]
        for basis, pattern in patterns:
            for m in re.finditer(pattern,body,re.I|re.M):
                found.append(claim(report,m,c.start,basis))
        claims.extend(sorted(found,key=lambda v:v['start']))
        apply(report,c,claims)


FIELD = ('labelled_status_field',r'^[ \t]*(?:Status|Resolution Status)[ \t]*[:|]?[ \t]*(?:\n[ \t]*)*('+STATE+r')\b')
