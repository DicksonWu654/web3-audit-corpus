"""Oxorio cards retain native Critical/Major/Warning/Info severities."""
import re
from core import Candidate, clean, severity
from layout_support import bounded, status_value
from variants import Variant, Fingerprint
DESCRIPTION = 'Oxorio column-layout detail cards; severity is governed by the reviewed publisher crosswalk'
RISK_FIELD = '(?:' + '|'.join(r'[ \t]*'.join(word) for word in
    ('CRITICAL', 'MAJOR', 'WARNING', 'INFO', 'INFORMATIONAL', 'HIGH', 'MEDIUM', 'LOW')) + ')'


def visible(line):
    return line.content.replace('\u200b','').replace('\ufeff','').strip()


def _cards(report, *, native_ids):
    out=[]
    for i,line in enumerate(report.lines):
        m=re.match(r'^Severity\s+(.+?)\s*$',visible(line),re.I)
        if not m:
            continue
        raw=m[1]
        normlabel=re.sub(r'\s+','',raw).upper()
        if normlabel not in {'CRITICAL','MAJOR','WARNING','INFO','INFORMATIONAL','HIGH','MEDIUM','LOW'}:
            continue
        indices=[j for j in range(max(0,i-10),i) if re.match(r'^\[?[CMWILH]-\d+\]?\s*',visible(report.lines[j]))]
        fragments={}
        if not indices and not native_ids:
            indices=[j for j in range(max(0,i-7),i) if re.match(r'^\d+\.\d+\.\d+\s+\S',visible(report.lines[j]))]
            for j in range(max(0,i-7),i):
                fragment=re.match(r'^\.(\d+\.\d+)\s+(.+)',visible(report.lines[j]))
                if not fragment:
                    continue
                digits=[k for k in range(j+1,i) if re.fullmatch(r'\d{1,2}',visible(report.lines[k])) and report.lines[k].page==line.page]
                if len(digits)==1:
                    indices.append(j)
                    fragments[j]=(fragment,digits[0])
            if not indices:
                continue
        if not indices:
            continue
        j=max(indices)
        idline=report.lines[j]
        pm=re.match(r'^(?:\[?([CMWILH]-\d+)\]?|(\d+\.\d+\.\d+))\s*(.*)',visible(idline))
        evidence={}
        skip=None
        if j in fragments:
            fragment,skip=fragments[j]
            pid=visible(report.lines[skip])+'.'+fragment[1]
            first_title=fragment[2]
            evidence={'id_reconstruction':'PDF leading chapter digit displaced below suffix/title',
                      'id_fragments':[{'start':idline.start,'end':idline.end},
                                      {'start':report.lines[skip].start,'end':report.lines[skip].end}]}
        else:
            pid=pm[1] or pm[2]
            first_title=pm[3]
        before=[]
        indent=len(idline.text)-len(idline.text.lstrip())
        for k in range(j-1,max(j-5,-1),-1):
            prev=report.lines[k]
            if not prev.content or prev.page!=idline.page or len(prev.text)-len(prev.text.lstrip())<=indent+4:
                break
            before.insert(0,prev.content)
        title=before+[first_title]+[l.content for k,l in enumerate(report.lines[j+1:i],j+1) if visible(l) and k!=skip]
        st=re.search(r'\bStatus\s+[•●]?\s*([^\n]+)',report.near(i,6),re.I)
        out.append(Candidate(report.lines[j-len(before)].start,clean(' '.join(title)),raw,pid,
                             status_raw=st[1].strip() if st else None,method='oxorio-detail-card',confidence=.96,evidence=evidence))
    return bounded(report,out)


def parse_numbered(report):
    return _cards(report, native_ids=False)


def parse_native_ids(report):
    return _cards(report, native_ids=True)


def parse_markdown_badges(report):
    out = []
    current = None
    active = False
    parent = None
    for line in report.lines:
        if line.heading == 2:
            active = line.content.casefold() == 'findings report'
        if not active or line.code:
            continue
        if line.heading == 3 and re.fullmatch(r'CRITICAL|MAJOR|WARNING|INFO', line.content, re.I):
            current = line.content
            parent = line
        hit = re.match(r'^\[(FIXED|ACKNOWLEDGED|NO ISSUE|NEW)\]\s+(.+)', line.content, re.I)
        if line.heading == 4 and hit and current:
            out.append(Candidate(line.start, hit[2], current, method='oxorio-markdown-badge',
                                 confidence=.96, evidence={
                                     'severity_basis': 'explicit_severity_section',
                                     'severity_section_span': {'start': parent.start, 'end': parent.end,
                                                               'text': parent.text}}))
    return bounded(report, out, stop=r'##\s+Appendix')


def parse_verification(report):
    return []


def parse_services(report):
    return []


def _status_cards(report, candidates):
    token = r'(?:PARTIALLY[ _]+FIXED|NO[ _]+ISSUE|ACKNOWLEDGED|DISMISSED|FIXED|NEW)'
    for c in candidates:
        c.evidence['status_reader_complete'] = True
        body = report.text[c.start:c.end]
        header = re.split(r'(?m)^\s*(?:Location|Description|Recommendation)\b', body, maxsplit=1)[0]
        hit = re.search(r'(?m)^\s*Status[ \t]+[•●]?[ \t]*(' + token + r')\b', header, re.I)
        c.status_raw = None
        c.normalized_status = None
        if not hit:
            continue
        raw = hit[1]
        key = re.sub(r'[ _]+', ' ', raw).casefold()
        native = {'new': 'open', 'no issue': 'invalid', 'dismissed': 'invalid'}
        c.status_raw = raw
        c.normalized_status = native.get(key) or status_value(raw, 'oxorio')
        start = c.start + hit.start(1)
        c.evidence['status_evidence'] = {'raw': raw, 'text': raw, 'start': start,
                                        'end': start+len(raw), 'basis': 'labelled_status_field',
                                        'profile': 'oxorio'}


def status_numbered(report, candidates):
    _status_cards(report, candidates)


def status_native_ids(report, candidates):
    _status_cards(report, candidates)


def status_markdown_badges(report, candidates):
    for c in candidates:
        c.evidence['status_reader_complete'] = True
        body = report.text[c.start:c.end]
        hit = re.match(r'^####\s+\[(FIXED|ACKNOWLEDGED|NO ISSUE|NEW)\]', body, re.I)
        if not hit:
            continue
        raw = hit[1]
        c.status_raw = raw
        c.normalized_status = {'no issue': 'invalid', 'new': 'open'}.get(raw.casefold()) or status_value(raw, 'oxorio')
        start = c.start + hit.start(1)
        c.evidence['status_evidence'] = {'raw': raw, 'text': raw, 'start': start,
                                        'end': start+len(raw), 'basis': 'heading_status_badge',
                                        'profile': 'oxorio'}
        update = re.search(r'(?m)^#####\s+Update\s*\n([\s\S]*?)(?=\n#####\s|\Z)', body)
        if update:
            c.resolution = update[1].strip()


def status_verification(report, candidates):
    # PASS is a verification result, not a remediation status for a finding.
    return None


def status_services(report, candidates):
    return None


def printed_counts(report):
    groups=[]
    for i,line in enumerate(report.lines):
        if not re.match(r'^(?:Severity|Level)\s+',line.content,re.I):
            continue
        cells=re.split(r'\s{2,}|\|',line.content)
        cells=[c.strip().upper() for c in cells if c.strip()]
        if not any(c in {'TOTAL','AMOUNT','COUNT','NUMBER'} for c in cells[1:]):
            continue
        index=next(j for j,c in enumerate(cells[1:]) if c in {'TOTAL','AMOUNT','COUNT','NUMBER'})
        counts,proof={},[]
        for nxt in report.lines[i+1:i+16]:
            row=re.match(r'^(CRITICAL|MAJOR|WARNING|INFO(?:RMATIONAL)?)\s+([\d\s]+)$',nxt.content,re.I)
            if not row:
                continue
            nums=re.findall(r'\d+',row[2])
            if index>=len(nums):
                continue
            bucket = severity(row[1], report.firm)
            counts[bucket] = counts.get(bucket, 0) + int(nums[index])
            proof.append({'start':nxt.start,'end':nxt.end,'page':nxt.page,'text':nxt.text})
        if len(counts)>=2:
            groups.append((counts,proof,{'start':line.start,'end':line.end,'text':line.text,'page':line.page}))
    if not groups:
        return None
    counts,proof,header=groups[0]
    # Distinct audit rounds may each have their own table. Do not silently pick
    # one round and compare it against the combined detailed occurrences.
    differing=[g for g in groups if g[0]!=counts]
    return {'counts':counts,'basis':'oxorio_labelled_total_column','evidence':[header]+proof,
            **({'ambiguous':True,'alternatives':[{'counts':c,'evidence':p} for c,p,h in differing]} if differing else {})}


VARIANTS = (
    Variant('oxorio/v2025_markdown_badges', Fingerprint(
        (('findings_chapter', r'^\s*## Findings Report', 4),
         ('status_heading', r'^\s*#### \[(?:FIXED|ACKNOWLEDGED|NO ISSUE|NEW)\]', 4)),
        ('2025', '2026'), formats=('md',)),
        parse_markdown_badges, ('oxorio_markdown_badge',), status_markdown_badges,
        notes='Native Markdown severity sections and status-badged, unnumbered finding headings.'),
    Variant('oxorio/v2022_numbered_cards', Fingerprint(
        (('numbered_detail', r'^\s*\d+\.\d+\.\d+\s+\S|^\s*\.\d+\.\d+\s+\S', 4),
         ('severity_field', r'^\s*Severity\s+' + RISK_FIELD + r'\b', 3)), ('2022', '2023')),
        parse_numbered, ('oxorio_numbered', 'oxorio_displaced_number'), status_numbered),
    Variant('oxorio/v2023_native_id_cards', Fingerprint(
        (('native_id', r'^\s*\[?[CMWILH]-\d+\]?\s*', 8),
         ('modern_summary', r'^\s*Severity\s+TOTAL\s+NEW\b', 6)), ('2023', '2026')),
        parse_native_ids, ('oxorio_native', 'oxorio_clean_native'), status_native_ids,
        notes='C/M/W/I native IDs; TOTAL/NEW/FIXED table also identifies zero-finding reports.'),
    Variant('oxorio/v2024_deployment_verification', Fingerprint(
        (('deployment_pass', r'Deployment Verification:\s*PASS', 8),
         ('verification_details', r'VERIFICATION DETAILS', 2)), ('2024', '2026')),
        parse_verification, ('oxorio_verification',), status_verification,
        notes='Verification-only supporting report; third-party audit findings are not new Oxorio findings.'),
    Variant('oxorio/v2022_service_overview', Fingerprint(
        (('service_brochure', r'We are OXORIO', 4),
         ('methodology', r'Audit Methodology', 3)), ('2022', '2026')),
        parse_services, ('oxorio_service_overview',), status_services,
        notes='Publisher services brochure, not a finding-bearing audit.'),
)


def parse(report):
    from variants import dispatch
    return dispatch(report, VARIANTS)
