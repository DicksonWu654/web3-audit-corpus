"""PeckShield PVE detail cards, excluding generic appendix recommendations."""
from core import SeverityLookup, severity, Candidate, clean, field_severity, is_toc
import re
from summary_counts import printed_counts as common_printed_counts
DESCRIPTION = "PVE (and legacy security-review) detail metadata; wrapped titles, explicit status paragraphs, no appendix rows"
CHINESE = SeverityLookup('peckshield', ('严重', '高危', '高', '中危', '中', '低危', '低', '建议项', '参考'))


def match_text(text):
    # A legacy embedded font maps ASCII to U+5100+codepoint. Decode for
    # matching only; original source spans and labels are left untouched.
    if "児兖充" in text or "危害性儺" in text:
        return "".join(chr(ord(c)-0x5100) if 0x5120<=ord(c)<=0x517e else c for c in text)
    return text


def parse(report):
    out=[]
    for i,line in enumerate(report.lines):
        if is_toc(line):
            continue
        m=re.match(r"^(\d+\.\d+)\.?\s+(.+)",line.content)
        if not m:
            continue
        following=report.lines[i+1:i+18]
        stop=next((j for j,l in enumerate(following) if re.match(r"^\d+\.\d+\s+",l.content)),len(following))
        following=following[:stop]
        nearby="\n".join(l.content for l in following)
        pid=re.search(r"\bID:\s*(PVE-\d+)\b",match_text(nearby)) or re.search(r"\b(PVE-\d+):",m[2])
        raw=field_severity(match_text(nearby))
        chinese=re.search(r"危害性[:：儺]\s*(严重|高危|中危|低危|建议项|参考|高|中|低)",nearby)
        if not raw and chinese:
            raw=chinese[1]
        # Security reviews predate PVE IDs but have the same explicit bullet metadata.
        review=bool(re.search(r"Security Review",report.text[:2500],re.I))
        if not raw or (not pid and not (review and m[1].startswith('3.'))):
            continue
        title=[re.sub(r"^PVE-\d+:\s*", "", m[2])]
        for l in following:
            if not l.content:
                continue
            if re.search(r"(?:ID|Severity|Target|Category|Likelihood|Impact):|危害性|目标[:：儺]|光兄儺",l.content):
                break
            if l.page!=line.page or re.fullmatch(r"\d+\s*/\s*\d+",l.content):
                break
            title.append(l.content)
        out.append(Candidate(line.start,clean(" ".join(title)),raw,pid[1] if pid else m[1],
                             normalized=severity(raw, report.firm),
                             method="peckshield-detail-card",confidence=.97,
                             evidence={"section":m[1],"severity_basis":"explicit_field","parser_revision":"phase4b-group4-v1"}))
    for i,c in enumerate(out):
        end=out[i+1].start if i+1<len(out) else len(report.text)
        tail=report.text[c.start:end]
        stop=re.search(r"\n\s*(?:\d+\s*(?:\|\s*)?)?(?:Appendix|Conclusions?|References)\s*(?:\n|$|[A-Z]:)",tail,re.I)
        if stop:
            end=c.start+stop.start()
        c.end=end
        status=re.search(r"(?m)^\s*Status\s+(?!Codes\b)([^\n]+(?:\n[^\n]+){0,2})",report.text[c.start:end])
        if status:
            paragraph=clean(status[1])
            # Preserve the publisher's actual status assertion. Narrative assertions
            # stay 'other' under article-v1 rather than inventing a new raw label.
            label=re.search(r"\b(?:has been|have been|is|was)\s+(partially fixed|fixed|resolved|acknowledged|confirmed|addressed|mitigated)\b",paragraph,re.I)
            c.status_raw=label[1] if label else paragraph
            c.evidence['status_assertion']=paragraph
            c.evidence['status_basis']='labelled_status_paragraph'
        else:
            native_status=re.search(r"(?m)^\s*状态\s+([^\n]+(?:\n[^\n]+){0,2})",report.text[c.start:end])
            if native_status:
                c.status_raw=clean(native_status[1])
                c.evidence['status_basis']='labelled_native_status_paragraph'
    return out


def printed_counts(report):
    values,proof={},[]
    for line in report.lines:
        s=match_text(line.content)
        # Decode summary digits only in the same legacy-font report.
        if "危害性儺" in report.text and any(0x5130<=ord(c)<=0x5139 for c in s):
            s="".join(chr(ord(c)-0x5100) if 0x5130<=ord(c)<=0x5139 else c for c in s)
        m=re.fullmatch(r"(严重|高危|中危|低危|建议项|参考)\s+(\d+)",s)
        if m:
            values[CHINESE[m[1]]]=int(m[2])
            proof.append({"page":line.page,"start":line.start,"end":line.end,"text":line.text})
    if len(values)>=2:
        return {"counts":values,"basis":"printed_chinese_severity_summary","evidence":proof}
    return common_printed_counts(report)


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses


def parse_pve(report):
    return [c for c in parse(report) if c.printed_id and c.printed_id.startswith('PVE-')]


def parse_review(report):
    # Short reviews print PVE in the title or omit it entirely; both carry
    # bullet metadata, whereas audit cards print a dedicated ID field.
    return parse(report)


def parse_chinese(report):
    return parse(report)

def parse_compliance(report):
    return []

def status_compliance(report,candidates):return None


def status_pve(report, candidates):
    statuses(report,candidates,narrative=True,index_id=r'\bPVE-\d+\b',headings=True)
    _status_sentences(report,candidates)


def status_review(report, candidates):
    statuses(report,candidates,narrative=True,headings=True)
    _status_sentences(report,candidates)


def _status_sentences(report,candidates):
    from core import status
    from status_sentences import sentence_span
    for c in candidates:
        c.evidence['status_reader_complete']=True
        body=report.text[c.start:c.end]
        for heading in re.finditer(r'(?m)^[ \t]*(?:Status|STATUS)\b(?![ \t]+(?:Codes|CODES)\b)[ \t]*:?[ \t]*(?:\n[ \t]*)*',body):
            start=heading.end()
            # Empty Status fields sometimes lead straight into page furniture.
            # Neither that footer nor the next finding is a source assertion.
            while start < len(body):
                chrome=re.match(r'(?:[ \t\n\f]+|\d+/\d+[^\n]*\n|(?:Public|Confidential)[ \t]*(?:\n|$))',body[start:])
                if not chrome:break
                start+=chrome.end()
            if start >= len(body):
                if c.evidence.get('status_evidence',{}).get('basis') not in {
                        'printed_id_status_index','fix_review_id_status_table','peckshield_status_sentence'}:
                    c.status_raw=c.normalized_status=None
                    c.evidence.pop('status_evidence',None)
                continue
            a,b=sentence_span(body,start)
            if a==b:continue
            raw=body[a:b]
            if '✓' in raw or re.match(r'^\d+\s*\|\s*(?:Conclusion|Appendix)',raw,re.I):
                continue
            c.status_raw=raw;c.normalized_status=c.normalized_status or status(raw)
            c.evidence['status_evidence']=dict(raw=raw,text=raw,start=c.start+a,end=c.start+b,
                basis='peckshield_status_sentence',profile=report.firm)


def status_chinese(report, candidates):
    status_pve(report,candidates)
    from parsers.group2_layouts import receipt
    for c in candidates:
        body=report.text[c.start:c.end]
        m=re.search(r'状态\s*[:：]?\s*(已修复|部分修复|未修复|已确认|已解决)',body)
        if m:receipt(report,c,m[1],c.start+m.start(1),c.start+m.end(1),'native_status_field',{'已修复':'fixed','部分修复':'partial','未修复':'open','已确认':'acknowledged','已解决':'resolved'}[m[1]])


VARIANTS = (
    Variant('peckshield/v2019_chinese',Fingerprint((('native risk',r'危害性\s*[:：儺]',12),),('2019','2022')),parse_chinese,('peckshield_chinese',),status_chinese,printed_counts,notes='Chinese bullet metadata, including matching-only legacy font decoding; native status assertions retain source spans.'),
    Variant('peckshield/v2020_security_review',Fingerprint((('review cover',r'PeckShield(?:\s+Security)?\s+Review|Security\s+Review',6),('title ID',r'^\s*\d+\.\d+\s+PVE-\d+:',4)),('2020','2022')),parse_review,('peckshield_review',),status_review,printed_counts,notes='Short security reviews: title-embedded PVE IDs or numbered bullet cards; labelled narrative Status and fix-review sections.'),
    Variant('peckshield/v2019_pve_cards',Fingerprint((('PVE field',r'\bID:\s*PVE-\d+',7),('audit layout',r'PeckShield\s+Audit\s+Report|Detailed Results',2)),('2019','2026')),parse_pve,('peckshield_pve',),status_pve,printed_counts,notes='PVE metadata cards across all observed audit years; status paragraphs take precedence over ID-linked summary/fix-review rows.'),
    Variant('peckshield/v2021_compliance',Fingerprint((('publisher audit',r'PeckShield\s+Audit\s+Report',3),('clean compliance',r'no (?:ERC20|SPL) (?:compliance |inconsistency)|without any issue that needs to be addressed|conforms to SPL standards without\s+compliance issues or security vulnerabilities',3)),('2021','2026')),parse_compliance,('peckshield_compliance',),status_compliance,printed_counts,notes='Clean ERC20/SPL token-compliance reviews without PVE cards; checklist checkmarks are compliance observations rather than fixed vulnerabilities.'),
)
