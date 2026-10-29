"""Neodyme detail tables and the prefix-labelled early peer-review reports."""
import re
from core import Candidate, clean
from layout_support import bounded, status_value
from summary_counts import printed_counts as generic_counts
DESCRIPTION = 'Neodyme legacy severity titles and modern ND-ID detail metadata tables'
LABEL=r'Critical|High|Medium|Low|Informational|Info'
STATUS=r'Partially (?:Fixed|Resolved)|Not (?:Fixed|Resolved)|Fixed before report|Acknowledged|Accepted|Unresolved|Resolved|Fixed|Open|Pending|WIP'


def _tables(report, family=None):
    out=[]
    for i,line in enumerate(report.lines):
        if not re.match(r'^Severity\s+Impact\b',line.content,re.I):
            continue
        nexts=[l for l in report.lines[i+1:i+5] if l.content]
        if not nexts:
            continue
        sm=re.match(r'^('+LABEL+r')\b',nexts[0].content,re.I)
        if not sm:
            continue
        # Walk back over just the wrapped title, stopping at the running header.
        parts=[]
        indices=[]
        for j in range(i-1,max(-1,i-9),-1):
            prev=report.lines[j]
            if prev.page!=line.page:
                break
            if not prev.content:
                if parts:
                    break
                continue
            if re.fullmatch(r'Affected|Component|Status',prev.content):
                continue
            if re.match(r'(?:Security Audit|Peer Review|\d+\s*/\s*\d+|Severity|\d+ Findings)',prev.content,re.I):
                break
            if re.search(r'(?:\.\s*){4,}',prev.content):
                break
            parts.insert(0,prev.content)
            indices.insert(0,j)
            if re.match(r'^\[?ND-|^[CHMLI]\d+\s*:',prev.content):
                break
        if not parts:
            continue
        title=clean(' '.join(parts))
        pid=re.match(r'^\[?(ND-[\w-]+)\]?\s*(?:[–:-]\s*)?(.*)',title)
        short=re.match(r'^([CHMLI]\d+)\s*:\s*(.*)',title)
        if family == 'unnumbered' and (pid or short):continue
        if family == 'short' and not short:continue
        if family == 'nd_short' and not (pid and re.fullmatch(r'ND-[A-Z0-9]+-[CHMLI]\d+',pid[1],re.I)):continue
        if family == 'nd_long' and not (pid and re.fullmatch(r'ND-[A-Z0-9]+-(?:CR|HI|MD|LO|IN)-\d+',pid[1],re.I)):continue
        st=re.search(r'\b('+STATUS+r')\s*$',nexts[0].content,re.I)
        old=re.search(r'\[('+STATUS+r')\]\s*$|\((?:'+LABEL+r')\s*;\s*('+STATUS+r')\)\s*$',title,re.I)
        rawtitle=pid[2] if pid else short[2] if short else title
        rawtitle=re.sub(r'\s*\((?:'+LABEL+r')(?:;[^)]*)?\)\s*$','',rawtitle,flags=re.I)
        rawtitle=re.sub(r'\s*\[(?:'+STATUS+r')\]\s*$','',rawtitle,flags=re.I)
        evidence={}
        if st:
            pos=nexts[0].start+len(nexts[0].text)-len(nexts[0].text.lstrip())+st.start(1)
            evidence['status_evidence']={'raw':st[1],'start':pos,'end':pos+len(st[1]),'text':report.text[pos:pos+len(st[1])],'basis':'detail_metadata_status_column','profile':'neodyme'}
        out.append(Candidate(report.lines[indices[0]].start,rawtitle,sm[1],pid[1] if pid else short[1] if short else None,
                             status_raw=st[1] if st else (old[1] or old[2]) if old else None,
                             method='neodyme-detail-table',confidence=.96,evidence=evidence))
    return bounded(report,out,stop=r'[A-Z]\s*\|?\s*(?:About Neodyme|Methodology|Vulnerability Severity Rating)')


def _titles(report):
    out=[]
    # 2021 SPL peer review predates per-finding metadata tables and IDs.
    table_starts=[]
    for i,line in enumerate(report.lines):
        if line.page<4 or re.search(r'(?:\.\s*){4,}',line.content):
            continue
        # Early reports state severity/status in the title rather than a table.
        suffix=re.fullmatch(r'(.+?)\s*\(('+LABEL+r');\s*(Resolved|Fixed|Acknowledged|Open)\)',line.content,re.I)
        coded=re.match(r'^('+LABEL+r')\s+([CHMLI]\d+)\s*[-–:]\s*(.+)',line.content,re.I)
        if suffix or coded:
            if any(abs(start-line.start)<150 for start in table_starts):
                continue
            title=suffix[1] if suffix else coded[3]
            if coded:
                # PDF line breaks preserve an empty line after a wrapped title.
                for nxt in report.lines[i+1:i+5]:
                    if not nxt.content or nxt.page!=line.page:
                        break
                    title+=' '+nxt.content
            out.append(Candidate(line.start,clean(title),suffix[2] if suffix else coded[1],
                                 None if suffix else coded[2],status_raw=suffix[3] if suffix else None,
                                 method='neodyme-legacy-title-risk',confidence=.95))
            continue
        m=re.match(r'^('+LABEL+r'):\s+(.+)',line.content,re.I)
        if not m or line.page<4 or re.search(r'(?:\.\s*){4,}',line.content):
            continue
        if any(abs(c.start-line.start)<150 for c in out):
            continue
        ahead=[l for l in report.lines[i+1:i+7] if l.content and l.page==line.page]
        header=next((j for j,l in enumerate(ahead[:3]) if l.content=='Description'),None)
        if header is not None:
            title=clean(' '.join([m[2]]+[l.content for l in ahead[:header]]))
            out.append(Candidate(line.start,title,m[1],None,method='neodyme-legacy-peer-review',confidence=.94))
    return bounded(report,out,stop=r'(?:Neodyme AG|[A-Z]\s*\|?\s*(?:About Neodyme|Methodology|Vulnerability Severity Rating))')


def printed_counts(report):
    """Native prose totals supplement numeric tables; neither uses detail IDs."""
    result=generic_counts(report)
    if result:
        return result
    for page in report.meta['pages']:
        text=page['text']
        m=re.search(r'The audit team reported a total of (\d+|[a-z]+) findings, of which',text,re.I)
        if m:
            tail=text[m.start():m.start()+500]
            counts={label.lower().replace('informational','info'):int(n)
                    for n,label in re.findall(r'[•*]\s*(\d+)\s+were\s+('+LABEL+r')\b',tail,re.I)}
            proof=tail
        else:
            m=re.search(r'In total, there was (.+? finding\.)',text,re.I)
            words={'zero':0,'one':1,'two':2,'three':3,'four':4,'five':5}
            counts={label.lower():words[n.lower()] for n,label in
                    re.findall(r'\b(zero|one|two|three|four|five)\s+(Critical|High|Medium|Low)\b',m[1],re.I)} if m else {}
            proof=m[0] if m else ''
        if m and counts:
            start=page['start']+m.start()
            result={'counts':counts,'basis':'neodyme_printed_prose_totals',
                    'evidence':[{'page':page['page'],'start':start,'end':start+len(proof),'text':proof}]}
            # Internal disagreement is detected from the printed summary alone.
            # Parsed detail counts never determine comparability.
            total=re.search(r'total of (\d+|[a-z]+) findings',proof,re.I)
            if total:
                words={w:i for i,w in enumerate(('zero','one','two','three','four','five','six','seven','eight','nine','ten','eleven','twelve','thirteen','fourteen','fifteen','sixteen','seventeen','eighteen','nineteen','twenty'))}
                n=int(total[1]) if total[1].isdigit() else words.get(total[1].lower())
                if n is not None and n!=sum(counts.values()):
                    result.update(ambiguous=True,summary_conflict={'basis':'printed_total_vs_printed_severity_sum','declared_total':n,'severity_sum':sum(counts.values())})
            return result
    return None


def parse(report):
    """Compatibility grammar; dispatch uses the separate era entrypoints below."""
    tables=_tables(report)
    return bounded(report,tables+[c for c in _titles(report)
                                  if not any(abs(c.start-t.start)<150 for t in tables)])


def peer_titles(report):
    return _titles(report)


def unnumbered_tables(report):
    # The short Anker peer review uses title risk/status without metadata.
    tables=_tables(report,'unnumbered')
    return bounded(report,tables+[c for c in _titles(report)
                                  if not any(abs(c.start-t.start)<150 for t in tables)])


def short_id_tables(report):
    return _tables(report,'short')


def nd_short_tables(report):
    return _tables(report,'nd_short')


def nd_long_tables(report):
    return _tables(report,'nd_long')


def _set_claim(report,c,raw,start,end,basis):
    c.status_raw=raw;c.normalized_status=status_value(raw,'neodyme')
    c.evidence['status_evidence']={'raw':raw,'start':start,'end':end,
                                 'text':report.text[start:end],'basis':basis,'profile':'neodyme'}


def _status(report,candidates,era):
    """Attach native fields/title statuses and explicit resolution responses.

    Acknowledgement is retained as acknowledgement even where the response also
    describes new checks. Future fixes, suggestions and arbitrary body mentions
    are not completed fixes. Status evidence always quotes the selected source.
    """
    for c in candidates:
        c.evidence['status_reader_complete']=True
        proof=c.evidence.get('status_evidence')
        if proof:
            c.normalized_status=status_value(c.status_raw,'neodyme')
            continue
        body=report.text[c.start:c.end]
        head=body.split('Severity',1)[0][:1200]
        if head:
            m=re.search(r'\[('+STATUS+r')\]\s*$|\((?:'+LABEL+r');\s*('+STATUS+r')\)\s*$',head,re.I|re.M)
            if m:
                group=1 if m[1] else 2
                _set_claim(report,c,m[group],c.start+m.start(group),c.start+m.end(group),'finding_title_status')
                continue
        c.status_raw=c.normalized_status=None
        # Only the first response paragraph after a labelled resolution/fix.
        # Blank lines after headings are common; a page footer is not a reply.
        for m in re.finditer(r'(?:^|\n)[ \t]*(?:Resolution|Remediation|Fix)(?:[.:][ \t]*|[ \t]*\n)[ \t\n]*([^\f]+?)(?=\n[ \t]*\n|$)',body,re.I):
            response=m[1]
            claim=re.search(r'\b('+STATUS+r')\b',response,re.I)
            if not claim:continue
            if re.search(r'\b(?:should|could|would|will|must|to be|not yet|not been)\b',response[:claim.start()],re.I):continue
            # Passive assertions and publisher/client acknowledgements are
            # permitted; code snippets and suggested patches are not responses.
            if re.search(r'\b(?:if|unless)\b',response[:claim.start()],re.I):continue
            start=c.start+m.start(1)+claim.start(1)
            _set_claim(report,c,claim[1],start,start+len(claim[1]),'resolution_response_assertion')
        if c.status_raw:continue
        # Older peer reviews use unlabelled author assertions after the finding
        # narrative, including a direct verification of the supplied fix.
        assertions = list(re.finditer(r'\b(?:Neodyme\s+(verified the\s+fix)|This(?: specific bug[^.\n]{0,80})?\s+(?:was|has been)\s+(fixed)|(?:This|The) (?:issue|finding|bug)\s+(?:was|has been)\s+(fixed|resolved|acknowledged))\b',body,re.I))
        if assertions:
            m=assertions[-1]; group=next(j for j in range(1,4) if m[j])
            _set_claim(report,c,m[group],c.start+m.start(group),c.start+m.end(group),'publisher_completed_fix_assertion')
            continue
        # ID-linked review tables provide status where the detail omits it.
        if not c.printed_id:continue
        claims=[]
        pattern=r'(?<![A-Z0-9-])'+re.escape(c.printed_id)+r'(?![A-Z0-9-])'
        for page in report.meta['pages']:
            if not re.search(r'(?:Finding|ID)[^\n]*(?:Status|Resolution)',page['text'],re.I):continue
            offset=page['start']
            for line in page['text'].splitlines(keepends=True):
                if re.search(pattern,line,re.I):
                    match=re.search(r'\b('+STATUS+r')\s*$',line,re.I)
                    if match:claims.append((match[1],offset+match.start(1),offset+match.end(1)))
                offset+=len(line)
        if len({status_value(x[0],'neodyme') for x in claims})==1:
            raw,start,end=claims[-1];_set_claim(report,c,raw,start,end,'printed_id_status_table')
        elif claims:c.evidence['status_conflict']=True


def peer_status(report,candidates):return _status(report,candidates,'peer')
def unnumbered_status(report,candidates):return _status(report,candidates,'unnumbered')
def short_status(report,candidates):return _status(report,candidates,'short')
def nd_short_status(report,candidates):return _status(report,candidates,'nd_short')
def nd_long_status(report,candidates):return _status(report,candidates,'nd_long')


from variants import Variant, Fingerprint
VARIANTS=(
    Variant('neodyme/v2021_peer_titles',
            Fingerprint((('peer_overview',r'Peer review result: Overview',6),
                         ('peer_details',r'Peer review result: Detailed findings',3),
                         ('prefix_risk_title',r'^\s*(?:'+LABEL+r'):\s+\S',7),
                         ('coded_risk_title',r'^\s*(?:'+LABEL+r')\s+[CHMLI]\d+\s*[-–:]',7)),('2021','2023')),
            peer_titles,('neodyme_peer','neodyme_peer_zero','neodyme_peer_coded'),peer_status,printed_counts,
            notes='Peer-review severity-prefixed titles; explicit response assertions only.'),
    Variant('neodyme/v2021_unnumbered_tables',
            Fingerprint((('metadata_columns',r'^\s*Severity\s+Impact\b',7),
                         ('suffix_risk_title',r'^.*\((?:'+LABEL+r')(?:;[^)]*)?\)\s*$',6)),('2021','2022')),
            unnumbered_tables,('neodyme_unnumbered','neodyme_suffix'),unnumbered_status,printed_counts,
            notes='Unnumbered Impact/Component metadata and transitional risk/status suffix titles.'),
    Variant('neodyme/v2023_short_ids',
            Fingerprint((('short_id_heading',r'^\s*[CHMLI]\d+\s*:\s+\S',10),
                         ('metadata_columns',r'^\s*Severity\s+Impact\b',2)),('2023','2023')),
            short_id_tables,('neodyme_short',),short_status,printed_counts,
            notes='C01/H01-style IDs with bracketed status and metadata.'),
    Variant('neodyme/v2023_nd_compact',
            Fingerprint((('nd_compact_heading',r'^\s*\[?ND-[A-Z0-9]+-[CHMLI]\d+\]?\s',10),
                         ('bar_introduction',r'^\s*1\s*\|\s*Introduction',3),
                         ('summary_findings',r'^\s*Summary of Findings\s*$',3)),('2023','2025')),
            nd_short_tables,('neodyme_compact','neodyme_compact_zero'),nd_short_status,printed_counts,
            notes='ND-PROJECT-H1 IDs and bar-numbered sections; same template includes explicit zero-finding reviews.'),
    Variant('neodyme/v2024_nd_expanded',
            Fingerprint((('nd_expanded_heading',r'^\s*\[ND-[A-Z0-9]+-(?:CR|HI|MD|LO|IN)-\d+\]\s',10),
                         ('executive_summary',r'^\s*1\s+Executive Summary',3),
                         ('findings_figure',r'Figure 1: Overview of Findings',3)),('2024','2026')),
            nd_long_tables,('neodyme_expanded','neodyme_expanded_zero'),nd_long_status,printed_counts,
            notes='Expanded ND-PROJECT-HI-01 IDs with metadata and executive severity figure; zero reports keep empty findings.'),
)
