"""Veridise numbered detail sections with tabular Severity/Commit/Type/Status metadata."""
from core import severity, Candidate, clean, finish
import re
from summary_counts import printed_counts as generic_printed_counts
from layout_support import bounded, status_value
from variants import Variant, Fingerprint

DESCRIPTION = 'Numbered Veridise issue details; native V-project IDs, Warning and status labels'


def _details(report, *, field_ids=False):
    out = []
    overview={}
    label=r'Critical|High|Medium|Moderate|Low|Warning|Informational|Info'
    for line in report.lines:
        row=re.fullmatch(r'(V-[A-Z0-9-]+-\d+)\s+.+?\s{2,}('+label+r')\s{2,}(.+)',line.content,re.I)
        if row:
            raw = row[3].strip()
            status_start = line.start + line.text.rfind(raw)
            overview.setdefault(row[1],[]).append((row[2],raw,line.start,line.end,status_start))
    for i,line in enumerate(report.lines):
        m = re.match(r'^(\d+\.\d+\.\d+)\s+(.*)',line.content)
        if not m or re.search(r'(?:\.\s*){4,}',line.text):
            continue
        # Metadata must belong to this card, never the next short finding.
        following = report.lines[i:i+16]
        stop = next((j for j, l in enumerate(following[1:], 1)
                     if re.match(r'^\d+\.\d+\.\d+\s', l.content)), len(following))
        near = '\n'.join(l.text for l in following[:stop])
        sev = re.search(r'\bSeverity\s+('+label+r')\b',near,re.I)
        start=line.start
        above=[l for l in report.lines[max(0,i-10):i] if l.page==line.page]
        before='\n'.join(l.text for l in above)
        if not sev and re.search(r'\bFinding ID\s+V-',before):
            previous=re.search(r'\bSeverity\s+('+label+r')\b',before,re.I)
            if previous:
                sev=previous
                near=before+'\n'+near
                start=next(l.start for l in above if re.search(r'\bSeverity\s+('+label+r')\b',l.content,re.I))
        heading_id=re.match(r'(V(?:UL)?-[A-Z0-9-]+-\d+)\s*:',m[2])
        references=overview.get(heading_id[1],[]) if heading_id else []
        reference=references[0] if references and len({r[:2] for r in references})==1 else None
        if not sev and not (reference and re.search(r'^\s*Description\b',near,re.M)):
            continue
        parts = [m[2]]
        for nxt in report.lines[i+1:i+8]:
            if re.match(r'(?:Severity|Commit|Type|Status|Files|Functions|Description)\b',nxt.content):
                break
            if nxt.content:
                parts.append(nxt.content)
        title = clean(' '.join(parts))
        pid = re.match(r'(V(?:UL)?-[A-Z0-9-]+-\d+)\s*:\s*(.*)', title)
        native_id=re.search(r'\bFinding ID\s+(V-[A-Z0-9-]+-\d+)\b',near)
        raw=sev[1] if sev else reference[0]
        evidence={'section':m[1], 'severity_basis':'explicit_field' if sev else 'explicit_issue_overview'}
        if start<line.start:
            evidence['detail_heading_start']=line.start
        if native_id:
            # A legacy detail can discuss several named properties in one card.
            # Retain those IDs together instead of duplicating the shared issue body.
            id_block=near[native_id.start():].split('Description',1)[0]
            evidence['publisher_finding_ids']=list(dict.fromkeys(re.findall(r'V-[A-Z0-9-]+-\d+',id_block)))
        if not sev:
            evidence['severity_overview_span']={'start':reference[2],'end':reference[3]}
            evidence['status_overview_span']={'start':reference[4],
                'end':reference[4]+len(reference[1]),'text':reference[1]}
        out.append(Candidate(start, pid[2] if pid else title, raw, pid[1] if pid else native_id[1] if native_id else m[1],
                             normalized=severity(raw, report.firm),
                             status_raw=reference[1] if reference and not sev else None,
                             method='veridise-detail-metadata',confidence=.96 if sev else .91,
                             evidence=evidence))
    out = finish(report, bounded(report,out))
    if field_ids:
        # Several native vulnerability IDs can share one description. They
        # remain separate publisher findings, with an explicit shared-card span.
        expanded = []
        for c in out:
            ids = c.evidence.get('publisher_finding_ids', [])
            expanded.append(c)
            if len(ids) < 2:
                continue
            from dataclasses import replace
            c.evidence['shared_card_span'] = {'start': c.start, 'end': c.end}
            for pid in ids[1:]:
                match = re.search(r'\b' + re.escape(pid) + r'\b', report.text[c.start:c.end])
                if match:
                    expanded.append(replace(c, start=c.start+match.start(), printed_id=pid,
                                            evidence=dict(c.evidence)))
        out = expanded
    return out


def parse_field_ids(report):
    return _details(report, field_ids=True)


def parse_named_cards(report):
    return _details(report)


def parse_fix_commits(report):
    return _details(report)


_STATUS = r'(?:Addressed and Partially Verified|Partially Fixed|Intended\s+Behavior|Expected\s+Behavior|Confirming Fix|Won[’\x27]t Fix|Acknowledged|Invalid|Fixed|Open|Unknown)'


def _status(report, candidates, *, fix_commits=False):
    for c in candidates:
        c.evidence['status_reader_complete'] = True
        # An expanded grouped ID still refers to its complete metadata card.
        span = c.evidence.get('shared_card_span') or {'start': c.start, 'end': c.end}
        body = report.text[span['start']:span['end']]
        header = re.split(r'\n\s*(?:Description|Impact|Recommendation|Developer[s]? Response)\b', body, maxsplit=1)[0]
        metadata = re.search(r'(?m)^[ \t]*Severity[ \t]+', header)
        if metadata:
            end_metadata = re.search(r'\n[ \t]*\n', header[metadata.start():])
            if end_metadata:
                header = header[:metadata.start()+end_metadata.start()]
        hit = re.search(r'\bStatus[ \t]+(' + _STATUS + r')\b', header, re.I)
        basis = 'labelled_status_field'
        if not hit and fix_commits:
            # A nonempty confirmed commit is explicit verification, while a
            # prospective developer response alone is not a verified fix.
            hit = re.search(r'\b(Confirmed Fix At)[ \t]+[0-9a-f]{7,40}\b', header, re.I)
            basis = 'confirmed_fix_commit'
        c.status_raw = None
        c.normalized_status = None
        if not hit:
            overview = c.evidence.get('status_overview_span')
            if not overview or not re.fullmatch(_STATUS, overview['text'], re.I):
                continue
            raw = report.text[overview['start']:overview['end']]
            if raw != overview['text']:
                raise ValueError('Veridise overview status span mismatch')
            start = overview['start']
            basis = 'explicit_issue_overview'
        else:
            raw = hit[1]
            start = span['start'] + hit.start(1)
        key = re.sub(r'\s+', ' ', raw).casefold()
        native = {'intended behavior': 'acknowledged', 'expected behavior': 'acknowledged',
                  'confirming fix': 'partial', 'addressed and partially verified': 'partial',
                  'confirmed fix at': 'fixed', 'unknown': None}
        c.status_raw = raw
        c.normalized_status = native.get(key) if key in native else status_value(raw, 'veridise')
        c.evidence['status_evidence'] = {'raw': raw, 'start': start, 'end': start+len(raw),
                                        'text': raw, 'basis': basis, 'profile': 'veridise'}
        response = re.search(r'\bDeveloper[s]? Response\s+(.+?)(?=\n\s*\n|\Z)', body, re.S)
        if response:
            c.resolution = response[1].strip()


def status_field_ids(report, candidates):
    _status(report, candidates)


def status_named_cards(report, candidates):
    _status(report, candidates)


def status_fix_commits(report, candidates):
    _status(report, candidates, fix_commits=True)


def printed_counts(report):
    # Category Breakdown's 'Gas Optimization' counts are categories, not risks.
    # Read only the independently printed Vulnerability/Issue Summary rows.
    counts, proof={},[]
    for line in report.lines:
        m=re.match(r'^(Critical|High|Medium|Moderate|Low|Warning|Informational|Info)-Severity Issues\s+(\d+)\b',line.content,re.I)
        if not m:
            continue
        key=m[1].casefold()
        if key in counts and counts[key]!=int(m[2]):
            return {'counts':counts,'basis':'veridise_vulnerability_summary','evidence':proof,'ambiguous':True}
        counts[key]=int(m[2])
        proof.append({'start':line.start,'end':line.end,'page':line.page,'text':line.text})
    if counts:
        normalized = {}
        for raw, count in counts.items():
            bucket = severity(raw, report.firm)
            normalized[bucket] = normalized.get(bucket, 0) + count
        return {'counts':normalized,'basis':'veridise_vulnerability_summary','evidence':proof}
    return generic_printed_counts(report)


VARIANTS = (
    Variant('veridise/v2022_finding_id_fields', Fingerprint(
        (('native_id_field', r'Finding ID\s+V-', 8),), ('2022', '2022')),
        parse_field_ids, ('veridise_field_ids', 'veridise_grouped_ids'), status_field_ids,
        notes='Legacy Difficulty/Target/Finding ID metadata; grouped native IDs retain shared-card receipts.'),
    Variant('veridise/v2023_confirmed_fix_commits', Fingerprint(
        (('confirmed_commit', r'Confirmed Fix At', 8),
         ('native_heading', r'^\s*\d+\.\d+\.\d+\s+V(?:UL)?-[A-Z0-9-]+-\d+\s*:', 4)), ('2023', '2026')),
        parse_fix_commits, ('veridise_fix_commit',), status_fix_commits,
        notes='Named V-project cards with independently printed confirmed fix commits.'),
    Variant('veridise/v2022_named_metadata', Fingerprint(
        (('native_heading', r'^\s*\d+\.\d+\.\d+\s+V(?:UL)?-[A-Z0-9-]+-\d+\s*:', 7),
         ('severity_commit', r'Severity\s+\w+\s+Commit\b', 2)), ('2022', '2026')),
        parse_named_cards, ('veridise_named_card', 'veridise_blank_status'), status_named_cards,
        notes='Named V-project detail headings and Type/Status metadata; blank statuses stay missing.'),
)


def parse(report):
    from variants import dispatch
    return dispatch(report, VARIANTS)
