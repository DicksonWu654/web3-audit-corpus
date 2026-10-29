"""Official Immunefi contest indexes contain linked/listed reports, not their details."""
import re
from core import Candidate, clean
from parsers.shieldify import bounded
DESCRIPTION = 'Official contest listing excerpts; repeated Reports by Type listings excluded'


def parse_markdown(report):
    out=[]
    active=False
    seen=set()
    for line in report.lines:
        if line.heading==2:
            active=line.content.lower()=='reports by severity'
        if not active or line.code:
            continue
        # Older indexes link to submission Markdown; newer indexes list bare IDs.
        value=line.content.replace('\\','')
        m=re.match(r'^\*\s+\[?(?:[^\[]*?\s+)?(?:#)?(\d+)\s*-?\s*\[((?:[^\]]*?)\s*-\s*(Critical|High|Medium|Low|Insight))\]\s*(.+)',value,re.I)
        if not m or m[1] in seen:
            continue
        title=re.sub(r'\]\([^\n]*\)\s*$','',m[4])
        seen.add(m[1])
        out.append(Candidate(line.start,clean(title),m[3],m[1],end=line.end,record_kind='summary_excerpt',
                             method='immunefi-published-index',confidence=.8,
                             evidence={'severity_basis':'explicit_listing_label','detail_not_acquired':True,
                                       'id_scheme':'global_submission_id_noncontiguous'}))
    return bounded(report,out)


def pdf_summary_candidates(report):
    """Read publisher-confirmed top-report cards, never leaderboard totals.

    Summaries intentionally print excerpts of selected accepted submissions.
    Their counts are not the competition's total accepted findings.
    """
    if report.meta.get('file_format') != 'pdf':
        return []
    from core import Candidate
    found = []
    for page in report.meta['pages']:
        value = page['text']
        ids = list(re.finditer(r'(?m)^\s*Report number:\s*(\d+)\b', value))
        if len(ids) != 1:
            continue
        # Program Action is the publisher's final severity, unlike submission
        # labels in public result indexes, which can include invalid reports.
        action = re.search(r'Program Action:\s*Confirmed as\s+(critical|high|medium|low|insight)\b', value, re.I)
        severity_basis = 'explicit_publisher_final_confirmation'
        if action is None:
            action = re.search(r'Rewarded as\s+(insight)\s+report\b',value,re.I)
            severity_basis = 'explicit_publisher_reward_class'
        if action is None:
            continue
        prior = value[:ids[0].start()]
        right = re.search(r'(?m)^.*?(Bug Description:|Report Excerpt:)', prior)
        column = right.start(1) - (prior.rfind('\n', 0, right.start(1)) + 1) if right else None
        title_parts = []
        title_start = None
        offset = 0
        for line in prior.splitlines(keepends=True):
            left = line[:column] if column and column > 15 else line
            title = re.split(r'\s{2,}',left.strip())[0]
            if title and not re.fullmatch(r'(?:immunefi\.com|Top \d+(?: Best)? Reports|\d+)', title, re.I):
                if title_start is None:
                    title_start = page['start'] + offset + len(left) - len(left.lstrip())
                title_parts.append(title)
            offset += len(line)
        title = ' '.join(title_parts)
        if not title or len(title) < 8:
            continue
        start = title_start if title_start is not None else page['start']
        proof_start = page['start'] + action.start(1)
        proof_end = page['start'] + action.end(1)
        found.append(Candidate(start, title, action[1], ids[0][1], end=page['end'],
            method='immunefi-final-summary-top-report', record_kind='summary_excerpt', confidence=.95,
            evidence={'severity_basis':severity_basis,
                'severity_span':{'start':proof_start,'end':proof_end,'text':action[1]},
                'accepted_by_publisher':True,'detail_not_acquired':True,
                'coverage_note':'Selected top-report excerpt; not a complete competition finding census.'}))
    return found


def parse(report):
    return pdf_summary_candidates(report) if report.meta.get("file_format") == "pdf" else parse_markdown(report)


# Phase 4d compatibility contract; preserve the existing parser until era review.
from variants import legacy as _legacy_variant
VARIANTS = (_legacy_variant('immunefi', parse),)
