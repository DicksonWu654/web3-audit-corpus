"""C4 eras: PDF, linked Markdown, HTML, anchored Markdown, QA and mitigation reviews.

Linked-only legacy entries remain summary excerpts: they do not acquire an invented
description or count as detailed formal findings. Initial and mitigation rounds are
distinct; their repeated IDs must not double the initial severity totals.
"""
from core import severity, Candidate, SHORT, bracket_findings
from collections import Counter, defaultdict
import re

DESCRIPTION = "Anchored/linked severity-ID details, Unicode QA IDs, native chapter totals, separate mitigation reviews and linked-only excerpts"
ANCHOR = re.compile(r'^(?:\[\]\(#[^)]*\))+\s*')
ID = re.compile(r'^\[{0,2}(?P<id>(?:MR-)?(?P<code>Info|NC|QA|C|H|M|L|I|N|G)[-\u2010-\u2015\u2212 ]\d+)\]?\s*(?:[:.)|\u2013-]\s*|\s+)(?P<title>.+)', re.I)
BARE_ID = re.compile(r'^\[(?P<id>(?P<code>H|M|L|G|N|I)-\d+)\]$')
NATIVE_ID = re.compile(r'^\[{0,2}(?P<id>F-\d+)\]?\s+(?P<title>.+)')


def content(line):
    return ANCHOR.sub('', line.content).strip()


def title_text(text):
    text = re.sub(r'\]\(https?://.*?\)\s*(?:_Submitted by.*)?$', '', text)
    return re.sub(r'\s+#+\s*$', '', text).strip()


def _parse_sections(report):
    pdf = report.meta.get('file_format') == 'pdf'
    if pdf:
        out = bracket_findings(report)
        for j,c in enumerate(out):
            end = out[j+1].start if j+1 < len(out) else len(report.text)
            stops = [l.start for l in report.lines if l.start > c.start and
                     l.start < end and re.fullmatch(r'Disputed Findings|Disclosures', l.content, re.I)]
            if stops:
                c.end = min(stops)
        return out
    out, boundaries = [], []
    mitigation = False
    section = ''
    qa_subsection = ''
    fence = None
    issue_bases=set()
    for i,line in enumerate(report.lines):
        s = content(line)
        malformed_fence_recovery=False
        # HTML h tags are structural evidence. Literal backticks in a code sample
        # must not turn the rest of an HTML document into a Markdown code fence.
        if report.meta.get('file_format') != 'html':
            marker=re.match(r'^\s*(`{3,}|~{3,})(.*)$',line.text)
            if marker:
                if fence:
                    if marker[1][0]==fence[0] and len(marker[1])>=fence[1] and not marker[2].strip():
                        fence=None
                elif marker[1][0] not in marker[2]:
                    fence=(marker[1][0],len(marker[1]))
                continue
            if fence:
                coded=ID.match(s) if line.heading==2 else None
                issue=re.search(r'https://github\.com/code-423n4/[^/\s)]+-findings/issues/\d+',line.text)
                previous=next((c for c in reversed(out) if coded and c.severity_raw==coded['code']),None)
                # Legacy generators occasionally forgot a closing fence before
                # the next published issue. Recover only the next sequential
                # ID linked to the same already-established official issue base.
                malformed_fence_recovery=bool(coded and issue and previous and
                    re.sub(r'\d+$','',issue[0]) in issue_bases and
                    int(re.search(r'\d+$',coded['id'])[0])==int(re.search(r'\d+$',previous.printed_id)[0])+1)
                if not malformed_fence_recovery:
                    continue
        if line.heading == 1 and re.match(r'(?:Overview|Summary|Scope|Severity Criteria|(?:Critical|High|Medium|Low) Risk Findings|Informational Findings|Low Risk and|Non-Critical|Gas Optimi[sz]ations?|Audit Analysis|Mitigation (?:Review|Report)|Fix Review|Disclosures)(?:\b|$)',s,re.I):
            boundaries.append(line.start)
            section = s
            qa_subsection = ''
            if re.match(r'Mitigation (?:Review|Report)|Fix Review',s,re.I):
                mitigation = True
            if re.match(r'Disclosures',s,re.I):
                break
        if line.heading == 2 and re.fullmatch(r'(?:Low Risk|Non-Critical|Informational)(?: (?:Issues|Findings))?',s,re.I):
            qa_subsection=s
            boundaries.append(line.start)
        is_index = bool(re.match(r'^\s*[-*]\s+\[{1,2}(?:H|M|L|N|NC|G|I)-\d+',line.text))
        if not line.heading and not is_index:
            continue
        if is_index:
            # Bullet issue links in the findings section are source excerpts,
            # whereas the table of contents contains the same labels elsewhere.
            if not re.search(r'Findings|Non-Critical|Gas Optim',section,re.I):
                continue
            s = re.sub(r'^[-*]\s+', '', line.text.strip())
        m = ID.match(s) or BARE_ID.match(s) or NATIVE_ID.match(s)
        if not m:
            # Some QA winners publish full finding narratives without severity
            # codes. A mixed low/non-critical parent does not establish which
            # grade applies to any individual item; retain that uncertainty.
            if line.heading == 2 and re.match(r'(?:Low Risk and (?:Non-Critical|Informational) Issues|Gas Optimi[sz]ations?|Informational Findings)',section,re.I):
                next_heading=next((l for l in report.lines[i+1:] if l.heading),None)
                numeric=re.match(r'^\[(\d+)\]\s+(.+)',s)
                detailed=next_heading and next_heading.heading>=3 and re.match(r'Impact|Finding [Dd]escription|Proof of Concept|Recommended [Mm]itigation',content(next_heading))
                if numeric or detailed:
                    grade=qa_subsection or section
                    mixed_qa = bool(re.match(r'Low Risk and (?:Non-Critical|Informational) Issues', grade, re.I))
                    out.append(Candidate(line.start,numeric[2] if numeric else s,
                                         severity_raw=None if mixed_qa else grade,
                                         printed_id=numeric[1] if numeric else None,
                                         normalized=severity(None if mixed_qa else grade, report.firm, kind='qa' if mixed_qa else 'issue'),
                                         method='uncoded-qa-detail',confidence=.83,
                                         record_kind='remediation_review' if mitigation else 'formal_finding',
                                         finding_phase='fix_review' if mitigation else 'initial_audit',
                                         evidence={'severity_basis':'mixed_parent_grade_not_individually_printed' if mixed_qa else 'explicit_severity_section',
                                                   'kind':'qa' if mixed_qa else 'issue',
                                                   'section':section,'sequence_group':section+'|'+qa_subsection}))
            continue
        raw = m['code'] if 'code' in m.re.groupindex else None
        if raw is None:
            parent = re.match(r'(Critical|High|Medium|Low) Risk Findings',section,re.I)
            raw = parent[1] if parent else None
        elif line.heading > 2 and raw.upper() in {'C','H','M'}:
            continue
        # Heading-only references in an analysis/QA narrative are not the official
        # H/M entries. Mitigation findings have their own record kind below.
        if not mitigation and (raw or '').upper() in {'H','M','C'} and section and not re.search(r'(?:High|Medium|Critical) (?:Risk )?Findings',section,re.I):
            continue
        c = Candidate(line.start,title_text(m['title']) if 'title' in m.re.groupindex else None,raw,m['id'],severity(raw, report.firm),
                      method='published-linked-index' if is_index else 'c4-detail-heading',
                      confidence=.55 if is_index else .94,
                      record_kind='summary_excerpt' if is_index else ('remediation_review' if mitigation or m['id'].startswith('MR-') else 'formal_finding'),
                      finding_phase='fix_review' if mitigation else 'initial_audit',
                      evidence={'severity_basis':'printed_id_prefix' if 'code' in m.re.groupindex else 'printed_severity_section','label_is_code':'code' in m.re.groupindex,
                                'review_round':'mitigation' if mitigation else 'initial', 'section':section,
                                'malformed_fence_recovery':malformed_fence_recovery})
        if mitigation:
            if m['id'].startswith('MR-'):
                # New flaws introduced by mitigation have their own native MR
                # identifiers. These are findings of this review engagement.
                c.record_kind = 'formal_finding'
            else:
                c.evidence['previous_audit_finding'] = True
        out.append(c)
        issue=re.search(r'https://github\.com/code-423n4/[^/\s)]+-findings/issues/\d+',line.text)
        if issue:
            issue_bases.add(re.sub(r'\d+$','',issue[0]))
    # Stop at the next actual finding or parent section, so QA/mitigation/disclosure
    # content never becomes the tail of the preceding initial finding.
    for j,c in enumerate(out):
        end=out[j+1].start if j+1<len(out) else len(report.text)
        parent=next((b for b in boundaries if c.start < b < end),None)
        c.end = parent if parent is not None else end
        body=report.text[c.start:c.end]
        # Explicit publication labels only; ordinary mention of a patch in prose
        # does not establish remediation status.
        status=re.search(r'(?:\*\*\[|^\s*)(?:[^\n]{0,100}?\([^\n)]*\)\s+)?(confirmed and patched|acknowledged|disputed|confirmed)\]?(?:\(|\s*$)',body,re.I|re.M)
        if status:
            c.status_raw=status[1]
    return out


def _summary_prose(report):
    summary=next((l for l in report.lines if content(l)=='Summary' and
                  (l.heading or report.meta.get('file_format')=='pdf') and not l.excluded),None)
    if summary is None:
        return None
    end=next((l.start for l in report.lines if l.start>summary.end and content(l)=='Scope' and
              (l.heading or report.meta.get('file_format')=='pdf')),min(summary.end+6000,len(report.text)))
    counts,proof={},[]
    pattern=r'(\d+)\s+received\s+a\s+risk\s+rating\s+(?:in\s+the\s+category\s+of|of)\s+(HIGH|MEDIUM|LOW)\s+severity'
    for m in re.finditer(pattern,report.text[summary.end:end],re.I):
        start=summary.end+m.start();stop=summary.end+m.end()
        counts[m[2].lower()]=int(m[1])
        proof.append({'start':start,'end':stop,'text':report.text[start:stop]})
    return {'counts':counts,'evidence':proof,'basis':'printed_c4_summary_prose'} if proof else None


def printed_counts(report):
    """Read only printed section/chapter totals, independently of finding IDs.

    Actual headings exclude the HTML navigation TOC. Distinct component chapters
    add their independently printed totals, rather than selecting the first one.
    PDF contents page numbers are never treated as severity counts.
    """
    values, evidence = defaultdict(list), []
    mitigation=False
    for line in report.lines:
        s=content(line)
        if line.heading == 1 and re.match(r'Mitigation (?:Review|Report)',s,re.I):
            mitigation=True
        if mitigation:
            continue
        if report.meta.get('file_format') != 'pdf' and not line.heading:
            continue
        m=re.fullmatch(r'(Critical|High|Medium|Low|Informational|Gas)\s+(?:Risk\s+)?(?:Findings|Issues)\s*\((\d+)\)',s,re.I)
        if not m:
            continue
        raw=m[1].lower()
        values['info' if raw=='informational' else raw].append(int(m[2]))
        evidence.append({'page':line.page,'start':line.start,'end':line.end,'text':report.text[line.start:line.end]})
    prose=_summary_prose(report)
    if not evidence:
        return prose
    result={'counts':{k:sum(ns) for k,ns in values.items()},'basis':'printed_c4_component_section_totals','evidence':evidence}
    if prose and any(k in result['counts'] and result['counts'][k]!=n for k,n in prose['counts'].items()):
        result.update(ambiguous=True,alternatives=[prose],
                      ambiguity_reason='Independently printed summary prose contradicts section totals; parsed findings were not consulted.')
    return result


def sequence_diagnostics(report, candidates):
    groups=defaultdict(list)
    for c in candidates:
        if c.record_kind != 'formal_finding':
            continue
        m=re.fullmatch(r'(Info|NC|QA|[CHMLING])[-\u2010-\u2015\u2212 ](\d+)',c.printed_id or '',re.I)
        if m:
            prefix='N' if m[1].upper()=='NC' else m[1].upper()
            groups[prefix].append(int(m[2]))
        elif (c.printed_id or '').isdigit():
            groups['QA:'+c.evidence.get('sequence_group',c.evidence.get('section',''))].append(int(c.printed_id))
    if not groups:
        return {'complete':None,'reason':'no_sequential_primary_finding_ids','gaps':[],'duplicates':[]}
    gaps,duplicates=[],[]
    for prefix,ns in groups.items():
        gaps += [f'{prefix}-{n}' for n in range(1,max(ns)+1) if n not in ns]
        duplicates += [f'{prefix}-{n}' for n,v in Counter(ns).items() if v>1]
    return {'complete':not gaps and not duplicates,'reason':'initial_severity_id_runs','gaps':gaps,'duplicates':duplicates}


# Era sample inspected before parser development; additional mismatches were reviewed.
REVIEWED_SHA256 = (
    '4c2f14aacb517ff8d0d3d2934f4caea663199e83236c80823199eff7493e38a6',
    'be3a3f83364179720e70dcb2c64a8c62dd50590a37da9da36e3f0584d86dbe98',
    '408a0f52a622ede982887d3d101505a76458ba5cc579a1d011cb489798082e2a',
    'a085b932d679ba348cbf8f65ad69f55ca849e6e837397359cc15490dfcbc7ea0',
    '4858aabfd168cd00c3bf9e3347c262d9b6ba5bae893ee4277a1cf71c84edd730',
    'f64630c449837e1ed559745ac9ea5ff335a0becfb47a4d0594ad8652c8fd5ddc',
    '73310b797d465b90c0a20f8f15094d9e36683ea2dde4bf80f71e817de853e487',
    'd520d336b867e0008c60b2e1a15cb4146950619dce929ff8bb803181fbda74c7',
    '366ec149d5e987722bb15fe0ca6a8d6845c640fd626d7dd39be958ed8dd44fca',
    'b58b419fb1cafe141fe742b025f9b785594cec03e079809e6a04218f899da4b5',
    'de1b9406b2c4194ad236fe7b99db331a46025506d29feedeadbc96d216d8fbc4',
    'b6655dbfbf67fd2fc9545ef25c2ff6bc2e5150bb9a526d7a3c0d74f815bb5baa',
    '1896a89bbfc24dc4695bf66a0746efe2d7edc32d8fb0c88240b8633f121c70b7',
    '32cf714877dd013c07c9414bab112c62b264810172f8280328b6741e169143a4',
    '725aa75c41a1eb5bc3177e00d2dff6aab104b6e2cb4a5e92411070d9cfbd4b77',
    'a5ea26818daee996e882a3b091c00bd4bf02b572571498a65f4a897bf9d46589',
    '4b04a6ad477ae42bcf1b64b27f187ab459f4e698426b6dc3635b23988e27491e',
    '5cede10f763ad2dfd1b721cd6c87783540d8cc4a50689c5b048191696dc83c91',
    'ce35ce7b17faa9338a36ef71da147b5f4fefeb3fc5f239038fa980636508f9c5',
    '24455163b55821ca810825046e26259b6eabdc50a586f72a1a0d8265bf289999',
    'b59ea38ca22458c6c01029486ce0714b4863375dc3f3b24ec8689d323ed2724b',
    '56e1a6f77d15df0ba6e89125c59d31479fa959fe25f28c514e4b35663ee5eb79',
    'f16c78d1dc8ad077e545f7542ceba2b91eb467202c451f2497a70e170c3a07e1',
    '90217c7a07159350c6b7399cca58a868e689f16a78bd3a6a7b70b2df6be793ef',
)


def _namespaces(report, candidates):
    # QA/gas authors restart numeric IDs per chapter. Preserve the native ID;
    # the explicit enclosing heading establishes its independent namespace.
    for c in candidates:
        if (c.printed_id or '').isdigit():
            c.evidence['container_id'] = c.evidence.get('sequence_group') or c.evidence.get('section', '')
    return candidates


def parse_pdf(report):
    return _parse_sections(report)


def parse_linked_markdown(report):
    return _namespaces(report, _parse_sections(report))


def parse_plain_markdown(report):
    return _namespaces(report, _parse_sections(report))


def parse_linked_indexes(report):
    # These early chapters publish URLs/titles without a detailed body. Their
    # rows remain summary excerpts and their strict summary deficits stay visible.
    return _namespaces(report, _parse_sections(report))


def parse_web_sections(report):
    return _namespaces(report, _parse_sections(report))


def parse_anchored_markdown(report):
    return _namespaces(report, _parse_sections(report))


def parse_formal_verification(report):
    # Verification reports can have titleless F/M entries or an explicit clean
    # result. They do not inherit synthetic vulnerabilities from verified rules.
    return _namespaces(report, _parse_sections(report))


_C4_STATUS = (r'Unmitigated|Partially mitigated|Mitigation (?:not confirmed|unconfirmed|confirmed)|'
              r'Confirmed and patched|Partially (?:Fixed|Resolved|Implemented)|Not (?:Fixed|Implemented)|'
              r'Acknowledged|Resolved|Fixed|Unresolved|Disputed|Confirmed|Accepted|Mitigated|Implemented|Invalid|Open|Pending')


def read_status(report, candidates):
    """Read publication labels, source responses and ID-linked fix reviews only."""
    from core import status
    from bisect import bisect_right
    line_starts=[l.start for l in report.lines]
    def eligible(offset):
        line=report.lines[max(0,bisect_right(line_starts,offset)-1)]
        return not line.code or report.meta.get('file_format') in {'pdf','html'}
    claims = defaultdict(list)
    in_review = False
    for line in report.lines:
        if line.heading == 1 and re.match(r'Mitigation (?:Review|Report)|Fix Review', content(line), re.I):
            in_review = True
        if not in_review or line.code:
            continue
        # Review summaries explicitly link the original ID to the verdict.
        if re.search(r'\|', line.text):
            pid = re.search(r'\b([HMLC]-\d+)\b', line.text)
            verdict = re.search(r'\b(' + _C4_STATUS + r')\b', line.text, re.I)
            if pid and verdict:
                claims[pid[1]].append((verdict, line.start, 'mitigation_review_id_table'))
    native = {'confirmed and patched': 'fixed', 'mitigation confirmed': 'resolved',
              'mitigation not confirmed': 'open', 'mitigation unconfirmed': 'open',
              'unmitigated': 'open', 'partially mitigated': 'partial'}
    for c in candidates:
        c.evidence['status_reader_complete'] = True
        body = report.text[c.start:c.end]
        matches = []
        patterns = (
            r'(?mi)^[ \t]*(?:\*\*)?(?:Status|Mitigation status)(?:\*\*)?\s*:\s*(?:\*\*)?[ \t]*(' + _C4_STATUS + r')\b',
            r'(?mi)^[ \t]*\*\*\[(' + _C4_STATUS + r')\]',
            r'(?mi)^[ \t]*(?:\*\*)?[^\n:]{1,90}\((?![^)]*\b(?:judge|warden)\b)[^\n)]{1,60}\)(?:\*\*)?[ \t]+(' + _C4_STATUS + r')(?:\*\*)?[ \t]*(?:and (?:commented|confirmed|acknowledged)|\(in separate issue[^\n)]*\)|(?:and|but) (?:disputed|disagreed with) (?:the )?severity)?[ \t]*(?:[.:]|$)',
            r'(?mi)^[ \t]*(?:\*\*)?[^\n:]{1,90}\((?![^)]*\b(?:judge|warden)\b)[^\n)]{1,60}\)(?:\*\*)?[ \t]+commented(?:\*\*)?[ \t]*:[ \t]*\n(?:[ \t]*\n)*[ \t]*(' + _C4_STATUS + r')\b',
        )
        for pattern in patterns:
            for m in re.finditer(pattern, body):
                if not eligible(c.start+m.start(1)): continue
                matches.append((m.start(1), m[1], c.start+m.start(1), c.start+m.end(1), 'published_status_or_response'))
        if matches:
            _, raw, start, end, basis = max(matches)
        elif claims.get(c.printed_id) and len({m[1].lower() for m, _, _ in claims[c.printed_id]}) == 1:
            m, offset, basis = claims[c.printed_id][-1]
            raw, start, end = m[1], offset+m.start(1), offset+m.end(1)
        else:
            # Old parsing recognized bare "confirmed" lines without source
            # attribution. Such words do not prove a remediation status.
            c.status_raw = None
            c.normalized_status = None
            continue
        c.status_raw = raw
        c.normalized_status = native.get(raw.lower(), status(raw))
        c.evidence['status_evidence'] = dict(raw=raw, start=start, end=end,
            text=report.text[start:end], basis=basis, profile='code4rena')


from variants import Variant, Fingerprint, dispatch

VARIANTS = (
    Variant('code4rena/v2021_pdf', Fingerprint((
        ('contest_report', r'Findings\s*&\s*Analysis Report', 6),
        ('severity_criteria', r'^Severity Criteria\s*$', 2)), ('2021', '2021'), formats=('pdf',)),
        parse_pdf, ('c4_pdf',), read_status, printed_counts),
    Variant('code4rena/v2021_linked_summary_sections', Fingerprint((
        ('linked_only_chapter', r'^# (?:Low Risk Findings|Non.Critical Findings|Gas Optimizations)[^\n]*\n(?:[ \t]*\n){0,4}[-*][ \t]+\[{1,2}(?:L|NC|N|G)-\d+', 25),
        ('c4_overview', r'^# (?:Overview|Summary|Severity Criteria)', 2)), ('2021', '2023'), formats=('md', 'html')),
        parse_linked_indexes, ('c4_linked_index',), read_status, printed_counts,
        notes='Publisher linked-only low/noncritical/gas chapters remain excerpts; strict formal-detail agreement cannot count them.'),
    Variant('code4rena/v2023_formal_verification', Fingerprint((
        ('formal_verification_report', r'(?:formal.verification (?:audit|report)|\b(?:Blockswap|GMX).*Formal Verification)', 9),
        ('verification_findings', r'^#{1,2}\s+(?:Findings|Verification Results)', 2)), ('2023', '2026')),
        parse_formal_verification, ('c4_verification',), read_status, printed_counts),
    Variant('code4rena/v2024_anchored_markdown', Fingerprint((
        ('anchored_sections', r'^#{1,3}\s+\[\]\(#[^)]+\)', 8),
        ('c4_overview', r'About C4|Severity Criteria', 2)), ('2024', '2026'), formats=('md',)),
        parse_anchored_markdown, ('c4_anchored',), read_status, printed_counts,
        notes='Anchored export era; older reports are re-rendered with this template.'),
    Variant('code4rena/v2021_linked_markdown', Fingerprint((
        ('linked_finding', r'^#{2}\s+\[\[(?:MR-)?(?:H|M|L|NC|N|G|F)-\d+', 12),
        ('linked_index', r'^[-*]\s+\[\[(?:H|M|L|NC|N|G)-\d+', 6),
        ('c4_overview', r'^# (?:Overview|Summary|Severity Criteria)', 2)), ('2021', '2026'), formats=('md',)),
        parse_linked_markdown, ('c4_linked',), read_status, printed_counts),
    Variant('code4rena/v2021_web_sections', Fingerprint((
        ('c4_overview', r'^# (?:Overview|Summary|Severity Criteria)', 4),
        ('risk_sections', r'^# (?:Critical|High|Medium|Low) Risk Findings|^# Low Risk and', 6)), ('2021', '2026'), formats=('html',)),
        parse_web_sections, ('c4_web',), read_status, printed_counts),
    Variant('code4rena/v2021_plain_markdown', Fingerprint((
        ('risk_sections', r'^# (?:Critical|High|Medium|Low) Risk Findings|^# Low Risk and', 6),
        ('detail_heading', r'^## \[{1,2}(?:[HMLINGF]|NC)-\d+', 4)), ('2021', '2026'), formats=('md',)),
        parse_plain_markdown, ('c4_plain',), read_status, printed_counts),
)


def parse(report):
    return dispatch(report, VARIANTS)
