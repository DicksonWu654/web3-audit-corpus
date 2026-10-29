"""OtterSec detail-page headers place title, severity and OS-project-ID on one line."""
from core import SeverityLookup, severity, Candidate, SEV, SPACED_SEV, is_toc
import re
DESCRIPTION = "OS-project-ID detail-page headers with adjacent printed severity; general findings stay distinct"


def parse(report):
    out = []
    for i, line in enumerate(report.lines):
        if is_toc(line):
            continue
        m = re.match(r"^(OS-[A-Z0-9-]+)\s+\[(crit|critical|high|med|medium|low|info)\](?:\s+\[([^\]]+)\])?\s*\|\s*(.+)",line.content,re.I)
        if m:
            out.append(Candidate(line.start,m[4],m[2],m[1],normalized=severity(m[2], report.firm),status_raw=m[3],method="ottersec-bracket-header",confidence=.93))
            continue
        m = re.match(r"^(.*?)\s+(" + SPACED_SEV + r")\s+(OS-[A-Z0-9-]+)\s*$", line.text.strip(), re.I)
        if m and len(m[1].strip()) > 3:
            out.append(Candidate(line.start, m[1].strip(), m[2], m[3], method="ottersec-os-header", confidence=.93))
            continue
        m = re.match(r"^(.+?)\s{2,}(OS-[A-Z0-9]+-SUG-\d+)\s*$", line.content)
        if m and "General Findings" not in m[1]:
            out.append(Candidate(line.start,m[1],"General Findings",m[2],normalized=severity("General Findings", report.firm),method="ottersec-general-detail",
                                 confidence=.85,evidence={"severity_basis":"publisher_general_findings_definition"}))
            continue
        m = re.match(r"^(OS-[A-Z0-9-]+-SUG-\d+)\s*\|\s*(.+)",line.content)
        if m:
            out.append(Candidate(line.start,m[2],"General Findings",m[1],normalized=severity("General Findings", report.firm),method="ottersec-general-pipe",
                                 confidence=.9,evidence={"severity_basis":"publisher_general_findings_definition"}))
            continue
        m = re.match(r"^(OS-[A-Z0-9-]+-\d+)\s*[:|–]\s*(.+)", line.content)
        if m:
            nearby = report.near(i, 5)
            sev = re.search(r"\b(" + SEV + r")\b", nearby, re.I)
            if sev:
                out.append(Candidate(line.start, m[2], sev[1], m[1], method="ottersec-os-metadata", confidence=.8))
    return out

# Layout-era entry points remain explicit even where two templates share grammar.
from layout_support import view, visible, bounded, RISK, STATUS, attach_status, status_value
from variants import Variant, Fingerprint
_legacy_parse = parse
PID=r'OS-[A-Z0-9-]+-\d+'


def _letters(value):
    return r'[ \t]*'.join(re.escape(ch) for ch in value)


def _ids(line):
    compact=''; offsets=[]
    for i,ch in enumerate(line.text):
        if not ch.isspace(): compact+=ch; offsets.append(i)
    return [(m[0], offsets[m.start()], offsets[m.end()-1]+1)
            for m in re.finditer(PID,compact,re.I)]


def spaced_cards(report):
    """Match the publisher's letter-spaced PDF export without rewriting its cache."""
    out=[]
    for line in report.lines:
        if line.code: continue
        for pid,start,end in _ids(line):
            if line.text[end:].strip(): continue  # Index rows have fields after the ID.
            left=line.text[:start]
            matches=list(re.finditer(r'\b('+ '|'.join(_letters(s) for s in ('Critical','High','Medium','Low','Informational','Info','Gas'))+r')\b',left,re.I))
            raw=matches[-1][0] if matches else 'General Findings' if '-SUG-' in pid.upper() else None
            if not raw: continue
            title=left[:matches[-1].start()].strip() if matches else left.strip()
            if len(re.sub(r'\s','',title))<4: continue
            out.append(Candidate(line.start,title,raw,pid.upper(),method='ottersec-letter-spaced-card',confidence=.9,
                                 evidence={'title_basis':'verbatim_letter_spaced_heading','native_id_span':{'start':line.start+start,'end':line.start+end,'text':report.text[line.start+start:line.start+end]}}))
    if not out:
        # A short public release can consist solely of a general-finding
        # inventory. Preserve it as an excerpt, never invent a detail body.
        for page in report.meta['pages']:
            if 'IDDESCRIPTION' not in re.sub(r'\s','',page['text']).upper():continue
            for line in report.lines:
                if line.page!=page['page']:continue
                for pid,start,end in _ids(line):
                    title=line.text[end:].strip()
                    if '-SUG-' in pid.upper() and len(re.sub(r'\s','',title))>=8:
                        out.append(Candidate(line.start,title,'General Findings',pid.upper(),end=line.end,record_kind='summary_excerpt',
                                             method='ottersec-spaced-summary-only',confidence=.7,evidence={'severity_basis':'publisher_general_findings_classification','detail_availability':'summary_inventory_only'}))
        if out:report.layout_disposition={'reason':'summary_inventory_only','basis':'publisher ID/Description inventory; no detailed cards printed'}
    return bounded(report,out)


def remediation_status(report,candidates):
    attach_status(report,candidates,'ottersec')
    claims={}
    labels={'resolved':'resolved','fixed':'fixed','acknowledged':'acknowledged','todo':'open',
            'unresolved':'open','partiallyresolved':'partial','partiallyfixed':'partial'}
    pattern=re.compile(r'(?<!\w)('+'|'.join(_letters(s) for s in ('Partially Resolved','Partially Fixed','Acknowledged','Unresolved','Resolved','Fixed','TO DO'))+r')(?!\w)',re.I)
    for page in report.meta['pages']:
        compact=re.sub(r'\s','',page['text']).upper()
        if not re.search(r'ID(?:SEVERITY)?STATUSDESCRIPTION',compact): continue
        lines=[l for l in report.lines if l.page==page['page']]
        for i,line in enumerate(lines):
            for pid,_,_ in _ids(line):
                near=[]
                for j in range(max(0,i-2),min(len(lines),i+3)):
                    if j!=i and _ids(lines[j]): continue
                    for m in pattern.finditer(lines[j].text):
                        near.append((abs(j-i),m,lines[j]))
                if near:
                    _,m,l=min(near,key=lambda item:item[0])
                    claims.setdefault(pid.upper(),[]).append((m[0],l.start+m.start(),l.start+m.end(),'printed_id_status_table'))
    for c in candidates:
        body=report.text[c.start:c.end]; selected=None
        # Only assertions at the start of a publisher-labelled Patch section.
        # A recommendation such as "should be fixed" cannot establish status.
        section=re.compile(r'(?:^|\n)[ \t]*(?:'+ '|'.join(_letters(s) for s in ('Patch','Resolution','Update'))+r')[ \t]*[:.]?[ \t]*\n',re.I)
        for h in section.finditer(body):
            following=body[h.end():h.end()+1600]
            # Letter-spaced patches still have original exact offsets.
            m=re.match(r'\s*('+ '|'.join(_letters(s) for s in ('Partially Resolved','Partially Fixed','Acknowledged','Unresolved','Resolved','Fixed'))+r')\b',following,re.I)
            if m:
                selected=(m[1],c.start+h.end()+m.start(1),c.start+h.end()+m.end(1),'patch_assertion')
            else:
                m=re.search(r'\b(?:decided (?:not to patch|to accept the risk)|accepted (?:this|the) risk|acknowledged (?:this|the) (?:issue|risk))\b',following,re.I)
                if m:
                    selected=(m[0],c.start+h.end()+m.start(),c.start+h.end()+m.end(),'explicit_risk_acceptance')
            if selected is None:
                assertions=list(re.finditer(r'(?:^|\n)[ \t]*(?:\d+[.)][ \t]*)?(?:(?:Issue[ \t]*#?\d+|The[^\n.]{0,130}?issues?[^\n.]{0,80}?)\s+(?:(?:was|were|has been)\s+)?)?(Resolved|Fixed|Acknowledged)\b',following,re.I))
                if assertions:
                    states={m[1].lower() for m in assertions}
                    first,last=assertions[0],assertions[-1]
                    start=c.start+h.end()+first.start(1);end=c.start+h.end()+last.end(1)
                    if len(states)==1:
                        selected=(report.text[start:end],start,end,'grouped_patch_assertions')
                        group_status=next(iter(states))
                    else:
                        selected=(report.text[start:end],start,end,'mixed_patch_assertions');group_status='other'
                    c.evidence['patch_status_claims']=[{'raw':m[1],'start':c.start+h.end()+m.start(1),'end':c.start+h.end()+m.end(1)} for m in assertions]
        if selected is None and not c.status_raw:
            linked=claims.get((c.printed_id or '').upper(),[])
            if len({re.sub(r'\s','',x[0]).casefold() for x in linked})==1: selected=linked[-1]
            elif linked: c.evidence['status_conflict']=True
        if selected:
            raw,start,end,basis=selected; c.status_raw=raw
            key=re.sub(r'\s','',raw).casefold()
            c.normalized_status=(group_status if basis in {'grouped_patch_assertions','mixed_patch_assertions'} else 'acknowledged' if basis=='explicit_risk_acceptance' else labels.get(key,status_value(raw,'ottersec')))
            c.evidence['status_evidence']=dict(raw=raw,start=start,end=end,text=report.text[start:end],basis=basis,profile='ottersec')
        if not c.status_raw:
            c.normalized_status='unknown'
            c.evidence['status_availability']=dict(status='unknown',reason='conflicting_claims' if c.evidence.get('status_conflict') else 'not_stated',
                                                  checked='card, ID-linked index, labelled patch and resolution sections')


def bracket_cards(report):
    r=view(report);out=[]
    for l in r.lines:
        if is_toc(l) or re.search(r'\s{3,}\d+\s*$',l.text):continue
        m=re.match(r'^('+PID+r')\s*(?:\[('+SEV+r'|crit|med)\])?\s*(?:\[([^\]]+)\])?\s*[:|–]\s*(.+)',l.content,re.I)
        if not m:continue
        raw=m[2] or ('General Findings' if re.search(r'-(?:SUG|GAS|VER|OBS)-',m[1]) else None)
        if raw:
            out.append(Candidate(l.start,m[4],raw,m[1],status_raw=m[3],method='ottersec-bracket-card',confidence=.94,
                                 evidence={'severity_basis':'publisher_general_findings_classification' if raw=='General Findings' else 'explicit_card_badge',
                                           'native_namespace':m[1].rsplit('-',2)[-2]}))
    return bounded(report,out,r'(?:[A-Z]\s*[|:]?\s*)?(?:Appendix.*|Vulnerability Classifications?|Vulnerability Rating Scale|Disclaimer)')


def title_cards(report):
    r=view(report)
    out=_legacy_parse(r)
    # Modern PDF places title above the ID/severity/status two-row metadata table.
    for i,l in enumerate(r.lines):
        m=re.fullmatch(r'('+PID+r')\s+('+RISK+r')\s+(?:[✓✗✔]\s*)?('+STATUS+r')(?:\s+[a-f0-9]{7,40})?',l.content,re.I)
        if not m:continue
        prev=[q for q in r.lines[max(0,i-12):i] if q.content and q.page==l.page]
        if not prev or not re.fullmatch(r'ID\s+Severity\s+Status(?:\s+Found in)?',prev[-1].content,re.I):continue
        title=[]
        for q in reversed(prev[:-1]):
            if re.search(r'Security (?:Assessment|Audit)|OtterSec|\d+\s*/\s*\d+|\|\s*(?:Findings|General Findings)',q.content,re.I):break
            title.insert(0,q)
            if len(title)>=3:break
        if title:
            out.append(Candidate(title[0].start,' '.join(q.content for q in title),m[2],m[1],status_raw=m[3],method='ottersec-metadata-table-card',confidence=.96))
    return bounded(report,out,r'(?:[A-Z]\s*[|:]?\s*)?(?:Appendix.*|Vulnerability Classifications?|Vulnerability Rating Scale|Disclaimer)')


def parse(report):
    return bracket_cards(report)+title_cards(report)

VARIANTS=(
 Variant('ottersec/v2022_brackets',Fingerprint((('os_bracket',r'OS-[A-Z0-9-]+-\d+\s*\[',8),('os_pipe',r'^\s*OS-[A-Z0-9-]+-\d+\s*(?:\[[^\]]+\]\s*)?[:|]\s*\S',8),),('2022','2023')),bracket_cards,('ottersec_bracket','ottersec_general'),remediation_status),
 Variant('ottersec/v2025_metadata_tables',Fingerprint((('metadata_header',r'^\s*ID\s+Severity\s+Status(?:\s+Found in)?\s*$',8),('os_id',PID,2)),('2025','2026')),title_cards,('ottersec_table',),remediation_status),
 Variant('ottersec/v2023_title_badges',Fingerprint((('title_badge',r'^\s*\S[^\n]{2,180}\s+(?:'+SPACED_SEV+r')\s+'+PID+r'\s*$',8),('general_badge',r'^[ \t]*\S[^\n]{0,180}?[ \t]{2,}OS-[A-Z0-9-]+-SUG-\d+\s*$',6)),('2022','2026')),title_cards,('ottersec_title',),remediation_status),
 Variant('ottersec/v2024_letter_spaced',Fingerprint((('spaced_native_id',r'\bO[ \t]+S[ \t]*-[ \t]*[A-Z0-9]',8),('normalized_inventory',r'^\s*ID\s+Description\s*$',6)),('2023','2026')),spaced_cards,('ottersec_spaced',),remediation_status),
)


def supporting(report):
    report.layout_disposition={'reason':'formal_verification_methodology' if 'Formal Verification Audit' in report.text else 'incident_postmortem',
                               'basis':'explicit_report_heading_without_audit_finding_cards'}
    return []

VARIANTS += (Variant('ottersec/v2022_supporting',Fingerprint((('supporting_heading',r'Formal Verification Audit|Slope (?:Wallet|Log Server)|Slope Finance',6),)),supporting,('ottersec_supporting',)),)
