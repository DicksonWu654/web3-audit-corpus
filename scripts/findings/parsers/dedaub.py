"""Dedaub's detailed severity cards, including wrapped titles and 2021 prose cards.

Native C/H/M/L severity prefixes agree with the surrounding risk category. A is
Other/Advisory Issues (informational), not an additional security risk. Status is
the separate right hand column; compiler advisories labelled INFO remain findings.
Early March 2021 cards have no printed IDs or titles: their opening description
is retained as a source excerpt title, never an invented label or identifier.
"""
from core import SeverityLookup, severity, Candidate, clean
from collections import Counter, defaultdict
import re

DESCRIPTION = "Dedaub severity/advisory cards, wrapped description/status columns and legacy unnumbered cards"

REVIEWED_SHA256 = (
    "3f283f1ac2f69f7b298d5c509200dcc5a99dfee7a2fb47b81c1d75c833c4ea47",
    "6a035f00914179d67a39a914751e9f39e952bffd294b744e2197d5ead347d372",
    "4c9522cdbdf3e757371ba66f9bdbd96181793d401067416661c3b264c9f0ceac",
    "f2ed3335a93e78d37c85b75d23d9cc7a0a9c06279eedcb12076ac0fc57978b9a",
    "8e86b8f8857de702a78d80bf0d98de8974a594a0f9396007388d33b6261c6f0c",
    "07020ca12f7766a7893e189aa927610b0530b50dbb98bd23af8435c0f91bdd27",
    "8c01f4abee8156ace8cacdc89459c2cc7631eef3bae249fbe3dcbd45ec63223d",
    "480a9383a20ae65ee4dfd7bc52e8e15e3bacbe203aafab0eeaba76f480b8c732",
    "3584f4f6cbb2169bd0973db2ed6e675cafc97e51a9ccba51b2d24b37019377de",
    "8229e598d13261b24eb28e5499fb55bc4af7700dd7f9e6b882f5b2e37443d352",
    "71a6310ec3e5d0eb6e46c0dfd5835d27629ca996e1e1cffa27f5edc05f6a414a",
    "2f2e2f482b11cb6f6ad615982fb5378df0ecb89cefa25533767d394d1fa90560",
    "81d1b8e40c5bfa670c538a425ce8311f41ffda5f0ad753e81a9bb92398965822",
    "8b688a8903aedd9add2014543996055182a56519604a2d67cad35d6ded70fad1",
    "8894d3adbf326efe88c499836d169b49c521fc0ef4404a64b1d60106e1579841",
)

_ID = re.compile(r"^\s{0,8}([CHMLA]\d{1,2})\b(?:\s+|$)")
_SECTION = re.compile(r"^(Critical|High|Medium|Low)\s+Severity\s*:?$", re.I)
_STATUS = re.compile(r"\b(?:PARTIALLY\s+(?:FIXED|RESOLVED)|PARTLY\s+RESOLVED|LARGELY\s+RESOLVED|WON[’']T\s+FIX|ACKNOWLEDGED|RESOLVED|DISMISSED|INVALID|CLOSED|OPEN|FIXED|INFO)\b", re.I)
_NORMAL = SeverityLookup('dedaub', ('C', 'H', 'M', 'L', 'A'))


def _normalized_status(raw):
    if not raw:
        return None
    s = raw.lower()
    if re.search(r"\b(?:partly|partially)\b", s):
        return "partial"
    if s in {"closed", "largely resolved"}:
        return "resolved"
    return None


def _cell(line, status_col):
    """Split fixed-width PDF cards without treating the status as title prose."""
    s = line.rstrip()
    if len(s) - len(s.lstrip()) >= status_col - 14:
        return "", s.strip()
    # The right column sometimes begins left of the nominal STATUS heading.
    for m in re.finditer(r"(?<=\S)\s{3,}(?=\S)", s):
        if _STATUS.match(s[m.end():]) or m.end() >= status_col - 14:
            return s[:m.start()].strip(), s[m.end():].strip()
    if len(s) > status_col - 7:
        m = _STATUS.search(s)
        if m and m.start() >= status_col - 15:
            return s[:m.start()].strip(), s[m.start():].strip()
    return s.strip(), ""


def parse(report, era=None):
    lines, out = report.lines, []
    status_col, section = 76, None
    numbered = era == 'numbered' or (era is None and any(_ID.match(l.text) for l in lines))
    for i, line in enumerate(lines):
        if line.code or line.excluded:
            continue
        sec = _SECTION.match(line.content)
        if sec:
            section = sec[1]
        if re.fullmatch(r"OTHER\s*/?\s*ADVISORY ISSUES\s*:?", line.content, re.I):
            section = line.content.rstrip(":")
        if re.search(r"\bDescription\s+STATUS\b", line.text, re.I):
            status_col = re.search("STATUS", line.text, re.I).start()
        m = _ID.match(line.text)
        if not m or era == 'unnumbered':
            continue
        pid = m[1]
        # A source ID can be vertically centered in a 2--5-line detail card.
        first, last = i, i
        while first > 0 and i - first < 5 and lines[first - 1].content:
            p = lines[first - 1]
            if _ID.match(p.text) or re.search(r"\b(?:Description|STATUS)\b", p.content, re.I):
                break
            if p.page != line.page:
                break
            first -= 1
        while last + 1 < len(lines) and last - i < 6 and lines[last + 1].content:
            p = lines[last + 1]
            if _ID.match(p.text) or p.page != line.page:
                break
            last += 1
        title, statuses = [], []
        for j in range(first, last + 1):
            left, right = _cell(lines[j].text, status_col)
            left = re.sub(r"^" + re.escape(pid) + r"\b\s*", "", left)
            if left and not re.fullmatch(r"\d+|DEDAUB.COM", left, re.I):
                title.append(left)
            if right:
                statuses.append(right)
        raw_status = _STATUS.search(" ".join(statuses))
        # The C/H/M/L code is exact printed evidence even when the title card
        # spans a page and the surrounding severity heading is on the previous one.
        raw = section if section and (pid[0] == "A" or section.lower().startswith(_NORMAL[pid[0]])) else pid[0]
        out.append(Candidate(lines[first].start, clean(" ".join(title)), raw, pid,
                             severity(raw, report.firm), status_raw=raw_status[0] if raw_status else None,
                             method="native-severity-card", confidence=.96,
                             evidence={"severity_basis": "printed_id_and_severity_section"}))
    if numbered:
        # Repeated references to source IDs are not detail cards. Native cards
        # have a right-column status or a surrounding severity/advisory section.
        for c in out:
            c.normalized_status = _normalized_status(c.status_raw)
        return out
    # Before May 2021 the card's description starts in the same row as its status.
    # Narrative studies have no severity sections and correctly produce no rows.
    section = None
    for i, line in enumerate(lines):
        sec = _SECTION.match(line.content)
        if sec:
            section = sec[1]
            continue
        if section is None or line.excluded or line.code:
            continue
        if re.match(r"^(?:Other|Disclaimer|Compiler|About Dedaub|Disclaimer)", line.content, re.I):
            section = None
            continue
        left, right = _cell(line.text, 84)
        m = _STATUS.match(right)
        if not m or len(left) < 12:
            continue
        # Each unnumbered paragraph is an actual finding. Its first description
        # row is the only printed title material, with an explicit excerpt marker.
        parts = [left]
        for j in range(i + 1, min(i + 4, len(lines))):
            if not lines[j].content:
                break
            text, _ = _cell(lines[j].text, 84)
            if text:
                parts.append(text)
        out.append(Candidate(line.start, clean(" ".join(parts)), section, normalized=severity(section, report.firm),
                             status_raw=m[0], method="legacy-unnumbered-description-card", confidence=.84,
                             evidence={"severity_basis": "severity_section", "title_basis": "opening_description_excerpt", "no_printed_finding_id": True}))
    return out


def sequence_diagnostics(report, candidates):
    groups = defaultdict(list)
    for c in candidates:
        m = re.fullmatch(r"([CHMLA])(\d+)", c.printed_id or "")
        if m:
            groups[m[1]].append(int(m[2]))
    if not groups:
        return {"complete": None, "reason": "unnumbered_cards_or_narrative_study", "gaps": [], "duplicates": []}
    gaps, duplicates = [], []
    for prefix, values in groups.items():
        counts = Counter(values)
        gaps += [f"{prefix}{n}" for n in range(1, max(values) + 1) if n not in counts]
        duplicates += [f"{prefix}{n}" for n, count in counts.items() if count > 1]
    return {"complete": not gaps and not duplicates, "reason": "native_severity_sequences", "gaps": gaps, "duplicates": duplicates}


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, fields, normalized, claim, apply, STATE


def parse_unnumbered(report):
    return parse(report,'unnumbered')


def parse_numbered(report):
    return parse(report,'numbered')


def parse_study(report):
    # Economic/bytecode research studies have no graded vulnerability cards.
    return []


def _web_cards(report, extended=False):
    out=[];section=None;active=False
    for i,line in enumerate(report.lines):
        value=clean(line.content).replace('\x00','')
        if line.heading==2 and re.search(r'VULNERABILITIES.*FUNCTIONAL ISSUES',value,re.I):active=True
        if not active:continue
        if line.heading==2 and re.search(r'SEVERITY|ADVISORY ISSUES|CENTRALIZATION|OPTIMIZATION|PROTOCOL.LEVEL CONSIDERATIONS',value,re.I):
            section=re.sub(r'\s+SEVERITY\s*:?$','',value,flags=re.I)
        m=re.fullmatch(r'([A-Z]\d+(?:[a-z])?)',value)
        if line.heading!=3 or not m or (not extended and m[1][0] not in 'CHMLA'):continue
        nxt=next((l for l in report.lines[i+1:i+8] if clean(l.content)),None)
        if not nxt or nxt.heading!=3:continue
        title=clean(nxt.content)
        raw=section if section else m[1][0]
        out.append(Candidate(line.start,title,raw,m[1],method='dedaub-web-detail-card',confidence=.98,
            evidence={'severity_basis':'printed_severity_section','section':section,'title_start':nxt.start,'id_raw':line.content}))
    for i,c in enumerate(out):
        end=out[i+1].start if i+1<len(out) else len(report.text)
        # Stop before footer navigation and report boilerplate.
        stop=next((l.start for l in report.lines if c.start<l.start<end and l.heading<=2 and re.fullmatch(r'Disclaimer|About Dedaub|Related.*|Contact.*',clean(l.content),re.I)),end)
        c.end=stop
    return out


def parse_web_cards(report):
    return _web_cards(report)


def parse_web_extended(report):
    return _web_cards(report,True)


def parse_markdown_list(report):
    out=[];active=False;section='';kind='recommendation'
    for line in report.lines:
        if line.heading:
            value=clean(line.content)
            if value=='Findings / items':active=True;section=value
            elif active:
                section=value
                kind='observation' if re.search(r'questions|observations',value,re.I) else 'recommendation'
        m=re.match(r'^\s*(\d+)\)\s+(.+)',line.text)
        if active and m:
            out.append(Candidate(line.start,clean(m[2]),printed_id=m[1],record_kind=kind,
                method='dedaub-ungraded-markdown-list',confidence=.92,
                evidence={'container_id':section,'severity_basis':'explicit_ungraded_issues_suggestions_section'}))
    for i,c in enumerate(out):c.end=out[i+1].start if i+1<len(out) else len(report.text)
    return out


def parse_markdown_bullets(report):
    out=[];active=False
    for line in report.lines:
        if line.heading==1 and clean(line.content)=='Findings / items':active=True;continue
        if line.heading and re.search(r'Questions',line.content,re.I):active=False
        m=re.match(r'^- \[([^\]]+)\]\s+(.+)',line.content)
        if active and m:
            # These source-only notes have no separate detail body; retain the
            # exact published bullet as an excerpt, including short sentences.
            out.append(Candidate(line.start,clean(m[2]),m[1],end=line.end,record_kind='summary_excerpt',
                method='dedaub-markdown-bullet-excerpt',confidence=.95,evidence={'severity_basis':'printed_bullet_label'}))
    return out


def parse_focus_points(report):
    out=[]
    for i,line in enumerate(report.lines):
        m=re.fullmatch(r'FOCUS POINT (\d+):?',clean(line.content))
        if line.heading!=3 or not m:continue
        nxt=next((l for l in report.lines[i+1:i+8] if clean(l.content)),None)
        if nxt and nxt.heading==4:
            out.append(Candidate(line.start,clean(nxt.content),printed_id='FOCUS POINT '+m[1],record_kind='recommendation',
                method='dedaub-design-focus-point',confidence=.96,evidence={'severity_basis':'ungraded_design_recommendations'}))
    for i,c in enumerate(out):c.end=out[i+1].start if i+1<len(out) else len(report.text)
    return out


def status_web(report,candidates):
    for c in candidates:
        tokens=[l for l in report.lines if c.start<=l.start<c.end and clean(l.content)]
        claims=[]
        for j,line in enumerate(tokens[:-1]):
            # The compact card repeats grade followed immediately by a native
            # status cell. Summary navigation lies before the heading boundary.
            if re.fullmatch(r'CRITICAL|HIGH|MEDIUM|LOW|ADVISORY|CENTRALIZATION|OPTIMIZATION|OTHER',clean(line.content),re.I):
                value=tokens[j+1]
                if re.match(r'(?:'+STATE+r'|Acknowledged\s*\+\s*resolved)',clean(value.content),re.I):
                    m=re.search(r'\S(?:.*\S)?',value.text)
                    if m:claims.append(claim(report,m,value.start,'native_web_status_cell',0))
            if line.heading==3 and re.fullmatch(r'(?:'+STATE+r'|Acknowledged\s*\+\s*resolved)',clean(line.content),re.I):
                m=re.search(re.escape(clean(line.content)),line.text,re.I)
                if m:claims.append(claim(report,m,line.start,'publisher_resolution_heading',0))
        apply(report,c,claims)
        if c.status_raw and re.fullmatch(r'acknowledged\s*\+\s*resolved',c.status_raw,re.I):c.normalized_status='resolved'


def status_unnumbered(report,candidates):
    fields(report,candidates,(FIELD,))


def status_numbered(report,candidates):
    # The original column parser selects the right-hand STATUS cell, including
    # vertically centred labels. Preserve that exact cell and its disposition.
    old={c.start:c.status_raw for c in candidates}
    fields(report,candidates,(FIELD,))
    for c in candidates:
        raw=old[c.start]
        if c.status_raw or not raw or len(raw.split())<2:continue
        fragments=[];cursor=c.start
        for word in raw.split():
            found=None
            for line in report.lines:
                if not cursor<=line.start<c.end:continue
                matches=list(re.finditer(r'\b'+re.escape(word)+r'\b',line.text,re.I))
                if matches and matches[-1].start()>=45:
                    m=matches[-1];found={'start':line.start+m.start(),'end':line.start+m.end(),'text':m[0]};break
            if not found:break
            fragments.append(found);cursor=found['end']
        if len(fragments)==len(raw.split()):
            c.status_raw=' '.join(f['text'] for f in fragments)
            c.normalized_status=normalized(c.status_raw,report.firm)
            c.evidence['status_fragments']=fragments
            c.evidence['status_basis']='native_status_column_fragments'


def status_study(report,candidates):
    fields(report,candidates,(FIELD,),preserve=False)


VARIANTS=(
    Variant('dedaub/v2021_markdown_bullets',Fingerprint((('graded_bullet',r'^- \[(?:Low|High|Medium|Opt)\]',8),('findings_list',r'^# Findings / items\s*$',2)),('2021','2022'),formats=('md',)),parse_markdown_bullets,('dedaub_bullets',),status_study),
    Variant('dedaub/v2021_markdown_list',Fingerprint((('findings_list',r'^# Findings / items\s*$',8),),('2021','2022'),formats=('md',)),parse_markdown_list,('dedaub_markdown',),status_study),
    Variant('dedaub/v2023_design_focus',Fingerprint((('design_focus',r'^## FOCUS POINTS AND RECOMMENDATIONS',8),),('2023','2025'),formats=('html',)),parse_focus_points,('dedaub_focus',),status_study),
    Variant('dedaub/v2023_web_extended',Fingerprint((('extended_class',r'^## (?:CENTRALIZATION ISSUES|OPTIMIZATIONS?|OTHER ISSUES)',5),('web_id',r'^### [A-Z]\d+[a-z]?\x00*\s*$',7)),('2023','2026'),formats=('html',)),parse_web_extended,('dedaub_web_extended',),status_web),
    Variant('dedaub/v2021_web_cards',Fingerprint((('web_id',r'^### [CHMLA]\d+[a-z]?\x00*\s*$',8),('web_detail_section',r'^## VULNERABILITIES.*FUNCTIONAL ISSUES',2)),('2021','2026'),formats=('html',)),parse_web_cards,('dedaub_web',),status_web),
    Variant('dedaub/v2021_numbered_cards',Fingerprint((('native_id',r'^\s*[CHMLA]\d{1,2}\b',7),('status_columns',r'\bDescription\s+STATUS\b',3)),('2021','2023')),parse_numbered,('dedaub_numbered',),status_numbered),
    Variant('dedaub/v2021_unnumbered_cards',Fingerprint((('risk_chapter',r'^\s*(?:Critical|High|Medium|Low)\s+Severity\s*:?\s*$',6),),('2021','2021')),parse_unnumbered,('dedaub_unnumbered',),status_unnumbered),
    Variant('dedaub/v2019_research_study',Fingerprint((('study_section',r'Experimental Findings and Study|Financial\s+Considerations|Smart Contract Design Advisory|Verkle.*(?:gas|cost)|gas.*Verkle',8),),('2019','2023')),parse_study,('dedaub_study',),status_study,notes='Narrative economic/bytecode research; no manufactured findings.'),
)
