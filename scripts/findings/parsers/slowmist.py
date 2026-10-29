"""SlowMist native Nn cards and legacy English/Chinese severity sections.

Only explicit publisher risk labels define severity. Checklists and passed audit
items are not findings. Later result lists may label earlier detail sections by
an exact title match; they never supply independent numeric expectations.
"""
from core import SeverityLookup, severity, Candidate, clean
import re
from summary_counts import printed_counts as common_printed_counts

DESCRIPTION = "Nn cards and numbered English/Chinese severity sections; native labels/status and bounded detail spans"
CHINESE = SeverityLookup('slowmist', ('严重漏洞', '高危漏洞', '中危漏洞', '低危漏洞', '严重', '高', '中', '低'))
RISK_TITLE = re.compile(r"^(?:(Critical|High|Medium|Low)(?:[ -](?:Risk|Severity))?\s+Vulnerabilit(?:y|ies)|"
                       r"(Enhancement Suggestions?|Improve Recommendations?|Suggestions?|Weakness(?:es)?|"
                       r"Information(?:al)?|严重漏洞|高危漏洞|中危漏洞|低危漏洞|增强建议|弱点))$", re.I)
NUMBERED = re.compile(r"^(\d+(?:\.[ \t]*\d+)*)(?:\.[ \t]+|[ \t]+|、)(.+)")
BULLET = re.compile(r"^[●•]\s*(.+)")
SIMPLE = re.compile(r"^(\d{1,2})[.)、]\s*(.+)")
STOP_TITLE = re.compile(r"^(?:(?:Audit\s+)?(?:conclusions?|results?|summary|statement|disclaimers?)|免责声明|声明|总结|结论|审计结果|修复记录|Fix Log)$", re.I)


def _skip(report, line):
    # PDF snippets sometimes contain unmatched printed Markdown fences. They
    # cannot hide later native finding cards as if the whole PDF were code.
    return bool(line.excluded or re.search(r"(?:\.\s*){4,}\s*\d+\s*$",line.text)
                or re.match(r"^\s*(?:[-*] |\|)",line.text)
                or (line.code and report.meta.get("file_format")!="pdf"))


def native_risk(title):
    m = RISK_TITLE.fullmatch(clean(title))
    if not m:
        return None
    # Preserve the actual printed label; normalize only known policy labels.
    raw = m[1] or m[2]
    return raw, CHINESE.get(raw, severity(raw, 'slowmist'))


def title_key(value):
    return re.sub(r"[\W_]+", "", re.sub(r"\s+Audit$", "", value, flags=re.I)).casefold()


def heading(report, i):
    """Join contiguous PDF heading wraps, never across a blank or page break."""
    line = report.lines[i]
    parts = [line.content]
    if report.meta.get("file_format") == "pdf":
        for following in report.lines[i+1:i+4]:
            if not following.content or following.page != line.page:
                break
            if re.match(r"^(?:\d+[.)、]|\[N|[●•]|Status\b|Category\b|ID:)", following.content):
                break
            # Body prose often follows an unnumbered legacy title without a
            # blank. Only join a typographic continuation of the heading.
            if not (len(parts[-1]) >= 75 or re.search(r"\b(?:and|in|for|of|the|to|with)$",parts[-1],re.I)
                    or (re.match(r"^[a-z]", following.content) and len(following.content)<60)
                    or re.search(r"\[(?:critical|high|medium|low|weakness|enhancement)[^]]*\]$",following.content,re.I)):
                break
            parts.append(following.content)
    return clean(" ".join(parts))


def _sections(report):
    """Actual numbered headings and exact unnumbered legacy risk headings."""
    out = []
    for i, line in enumerate(report.lines):
        if _skip(report,line):
            continue
        m = NUMBERED.match(line.content)
        if m and ("." in m[1] or re.fullmatch(r"(?:Audit (?:Result|Conclusion|Scope)|Code (?:Overview|Audit)|Project Background(?: \(Context\))?|Statement|Conclusion|Result|Summary|Fix Log|Scope of Audit|代码概述|审计方法|声明|概要|项目背景|审计结果)",m[2],re.I)):
            joined = NUMBERED.match(heading(report, i))
            out.append((i, re.sub(r"\s+","",m[1]), joined[2]))
        elif native_risk(line.content) or STOP_TITLE.fullmatch(line.content):
            out.append((i, None, line.content))
    return out


def _status(candidate, report, extra=None):
    """Take assertions only from labelled status fields or explicit result notes."""
    body = report.text[candidate.start:candidate.end]
    m = re.search(r"(?mi)^[ \t\f]*(?:Status|Fix status|修复状态|漏洞状态)(?:[ \t]*[:：][ \t]*|[ \t]*\n)[ \t\n]*([^\n]+)", body)
    if not m:
        m = re.search(r"(?mi)^\s*(?:Note\s*:\s*|\()(?:This issue |It |该问题)?(?:has been |is |已)(fixed|resolved|acknowledged)\b[^\n]*", body)
    if m:
        assertion = clean(m[0])
        value = clean(m[1])
        known = re.match(r"(Partially Fixed|Not Fixed|Acknowledged|Unresolved|Resolved|Fixed|Open|Pending|Implemented)\b", value, re.I)
        native=re.match(r"(已修复|未修复|暂未修复|部分修复|已确认|已忽略)",value)
        candidate.status_raw = known[1] if known else native[1] if native else value
        if native and native[1] in {"已修复","未修复","暂未修复","部分修复"}:
            candidate.normalized_status={"已修复":"fixed","未修复":"open","暂未修复":"open","部分修复":"partial"}[native[1]]
        candidate.evidence.update(status_basis="publisher_status_assertion", status_assertion=assertion)
    elif extra:
        candidate.status_raw = extra.status_raw
        if extra.evidence.get("status_assertion"):
            candidate.evidence.update(status_basis="title_linked_result_assertion", status_assertion=extra.evidence["status_assertion"])


def parse(report):
    sections = _sections(report)
    out = []
    # Modern cards have explicit bracket labels. Bound before post-audit sections.
    for i, line in enumerate(report.lines):
        if _skip(report,line):
            continue
        m = re.match(r"^\[?(N\d+)\]?\s+\[([^\]]+)\]\s*(.+)", heading(report, i))
        split = None
        if not m and re.fullmatch(r"\[(N\d+)\]\s*\[\s*\]?",line.content) and i>0:
            previous=report.lines[i-1]
            label=re.fullmatch(r"(严重|高|中|低|建议|弱点)\s*\]?\s+(.+)",previous.content)
            if label and previous.page==line.page:
                pid=re.match(r"^\[(N\d+)\]",line.content)[1]
                split=(pid,label[1],label[2],previous.start)
        if m or split:
            raw = m[2] if m else split[1]
            out.append(Candidate(line.start if m else split[3], m[3] if m else split[2], raw, m[1] if m else split[0], severity(raw, report.firm),
                                 method="slowmist-n-heading", confidence=.97,
                                 evidence={"severity_basis": "printed_bracket_label"}))
    if out:
        return _bound(report, out, sections)

    # Legacy severity parents can contain numbered details, or result-list bullets.
    # Parent hierarchy bounds prevent conclusion repeats being read as findings.
    summaries = []
    for n, (i, number, title) in enumerate(sections):
        risk = native_risk(title)
        if not risk:
            continue
        # Unnumbered labels in the front matter are risk definitions. Only
        # enter the old unnumbered layout after its actual result chapter.
        if number is None and not any(re.fullmatch(r"(?:Audit Result|审计结果)",t,re.I) for _,_,t in sections[:n]):
            continue
        level = len(number.split('.')) if number else None
        end_i = len(report.lines)
        for j, num2, title2 in sections[n+1:]:
            if num2 is None or number is None or len(num2.split('.')) <= level:
                end_i = j
                break
        # A severity section under an audit conclusion repeats earlier details.
        if number and any(pnum and number.startswith(pnum + '.') and re.fullmatch(r"(?:Audit )?conclusions?|总结|结论",ptitle,re.I)
                          for _, pnum, ptitle in sections[:n]):
            continue
        children = [(j,num,t) for j,num,t in sections[n+1:] if j < end_i and num and number
                    and len(num.split('.'))==level+1 and not native_risk(t)]
        for j, num, t in children:
            out.append(Candidate(report.lines[j].start, t, risk[0], num, severity(risk[0], report.firm),
                                 method="slowmist-severity-section", confidence=.96,
                                 evidence={"severity_basis":"printed_parent_section", "severity_section":number, "section_number_prefix_differs":not num.startswith(number+'.')}))
        if children:
            continue
        for j in range(i+1, end_i):
            line = report.lines[j]
            if _skip(report,line):
                continue
            # Unnumbered old severity chapters use local 1./2. (or Chinese 、).
            m = SIMPLE.match(line.content)
            if NUMBERED.match(line.content) and "." in NUMBERED.match(line.content)[1]:
                m=None
            b = BULLET.match(line.content)
            if not m and not b:
                continue
            title = heading(report, j)
            match = SIMPLE.match(title) if m else BULLET.match(title)
            c = Candidate(line.start, match[2] if m else match[1], risk[0], m[1] if m else None, severity(risk[0], report.firm),
                          method="slowmist-severity-list", confidence=.86,
                          evidence={"severity_basis":"printed_parent_section", "severity_section":number or sections[n][2]})
            c.end = report.lines[end_i].start if end_i < len(report.lines) else len(report.text)
            summaries.append(c)
    # Exact normalized title joins give detail bodies the publisher's later risk
    # classification. This is metadata linkage, not extracting rows to match totals.
    for n,c in enumerate(summaries):
        if n+1<len(summaries):
            c.end=min(c.end,summaries[n+1].start)
        _status(c,report)
    linked = set()
    for i, number, title in sections:
        if number is None or native_risk(title) or STOP_TITLE.fullmatch(title):
            continue
        if any(c.start == report.lines[i].start for c in out):
            continue
        same = [s for s in summaries if title_key(s.title) == title_key(title)]
        if len(same) != 1:
            continue
        source = same[0]
        c = Candidate(report.lines[i].start, title, source.severity_raw, number, severity(source.severity_raw, report.firm),
                      method="slowmist-title-linked-result", confidence=.92,
                      evidence={"severity_basis":"exact_title_link_to_result_section", "classification_start":source.start})
        c.status_raw=source.status_raw
        if source.evidence.get("status_assertion"):
            c.evidence.update(status_basis="title_linked_result_assertion", status_assertion=source.evidence["status_assertion"])
        out.append(c)
        linked.add(source.start)
    # A standalone list statement must contain substantive issue text. Short
    # result references with no matching body remain summary excerpts.
    for c in summaries:
        if c.start not in linked:
            if c.printed_id is None and len(c.title) < 45:
                c.record_kind = "summary_excerpt"
                c.confidence = .65
            out.append(c)
    # Legacy inline suffix labels, including wrapped [low-risk] titles.
    for i, number, title in sections:
        m = re.fullmatch(r"(.+?)\s*\[((?:critical|high|medium|low)(?:[ -]risk)?)\]|(.+?)\s*\[(weakness|enhancement|suggestion)\]", title, re.I)
        if m and number and not any(c.start == report.lines[i].start for c in out):
            raw = m[2] or m[4]
            out.append(Candidate(report.lines[i].start, m[1] or m[3], raw, number, normalized=severity(raw, report.firm),
                                 method="slowmist-inline-risk-heading", confidence=.95,
                                 evidence={"severity_basis":"printed_title_suffix"}))
    out.extend(_risk_tables(report, sections))
    return _bound(report, out, sections)


def _risk_tables(report, sections):
    """Only rows with a printed non-Passed Threat cell are findings.

    The row question is retained as its title, including when the response gives
    post-fix behavior. Checked/passed items and general test headings never emit.
    """
    out=[]
    for n,(i,num,title) in enumerate(sections):
        if not num or not re.search(r"Security Test|Business Logic Test",title,re.I):
            continue
        end_i=sections[n+1][0] if n+1<len(sections) else len(report.lines)
        segment=report.lines[i+1:end_i]
        headers=[l for l in segment if re.search(r"NO\.\s+Check\s+Response\s+Threat\s+OK",l.text)]
        if not headers:
            continue
        bullets=[m.start() for l in segment if (m:=re.search(r"[●•]",l.text))]
        if not bullets:
            continue
        response_left=min(bullets)
        anchors=[m.start() for l in segment if (m:=re.search(r"(?<!\S)(?:Critical|High|Medium|Low|Weakness|Enhancement|Passed)(?:\s+(?:suggestion|Fixed|√))*\s*$",l.text,re.I)) and m.start()>response_left+20]
        threat_left=min(anchors) if anchors else headers[0].text.index("Threat")-12
        markers=[j for j in range(i+1,end_i) if re.match(r"^ {0,4}(\d{1,2})(?: {2,}|$)",report.lines[j].text)]
        starts=[]
        for k,j in enumerate(markers):
            lo=markers[k-1]+1 if k else i+1
            blanks=[x for x in range(lo,j) if not report.lines[x].content]
            start=blanks[-1]+1 if blanks else lo
            if not blanks and k:
                anchors=[x for x in range(lo,j) if re.search(r"(?:Passed|Fixed|High|Medium|Low)\b",report.lines[x].text[threat_left:])]
                if anchors:
                    start=anchors[-1]+1
            # Table headers and centred PDF page numbers are outside the row.
            while start<j and (not report.lines[start].content or report.lines[start] in headers
                              or re.fullmatch(r"\s*\d+\s*",report.lines[start].text)):
                start+=1
            starts.append(start)
        for k,j in enumerate(markers):
            start=starts[k]
            end=starts[k+1] if k+1<len(starts) else end_i
            lines=report.lines[start:end]
            cells=" ".join(l.text[threat_left:] for l in lines)
            risk=re.search(r"\b(Critical|High|Medium|Low|Weakness|Enhancement(?:\s+suggestion)?)\b",cells,re.I)
            if not risk:
                continue
            raw=clean(risk[1])
            question=clean(" ".join(re.sub(r"^\s*\d{1,2}\s+", "", l.text[:response_left]) for l in lines
                                     if not re.fullmatch(r"\s*\d+\s*",l.text)))
            if not question or "Check" in question or len(question)>300:
                continue
            pid=re.match(r"^\s*(\d+)",report.lines[j].text)[1]
            state=re.search(r"\b(Fixed|Acknowledged|Open|Unresolved)\b",cells,re.I)
            out.append(Candidate(report.lines[start].start,question,raw,pid,end=report.lines[end].start if end<len(report.lines) else len(report.text),
                                 status_raw=state[1] if state else None, method="slowmist-explicit-threat-row",confidence=.90,
                                 evidence={"severity_basis":"printed_threat_cell","printed_table_section":num,"printed_row_number":pid}))
    return out


def _bound(report, out, sections):
    out.sort(key=lambda c:c.start)
    for n,c in enumerate(out):
        end = out[n+1].start if n+1<len(out) else len(report.text)
        # End at the next actual numbered section (severity parents included),
        # except subordinate headings internal to a finding body.
        for i,num,title in sections:
            pos = report.lines[i].start
            if pos <= c.start or pos >= end:
                continue
            own = c.printed_id if c.printed_id and re.fullmatch(r"\d+(?:\.\d+)+",c.printed_id) else None
            if own and num and num.startswith(own+'.'):
                continue
            if native_risk(title) or STOP_TITLE.fullmatch(title) or (own and num):
                end=pos
                break
        c.end=min(end,c.end) if c.end else end
        _status(c, report)
    return out


def printed_counts(report):
    # Independently printed conclusion sentences extend numeric-table coverage.
    # Omitted risk levels stay omitted; no expected rows come from detail IDs.
    table=common_printed_counts(report)
    if table:
        return table
    groups=[]
    pattern=re.compile(r"(?:during the audit(?: work)?|审计期间)[^.。]{0,90}?(?:we\s+found|发现了?)\s*([^.;。；]+)",re.I)
    labels=re.compile(r"(?<![\w.])(\d{1,3}|a|an|one|two|three|four|five|six|seven|eight|nine|ten)\s*(?:个\s*)?"
                      r"(critical|high|medium|low|(?:enhancement\s+)?suggestions?|information(?:al)?|info|weakness(?:es)?|严重漏洞|高危漏洞|中危漏洞|低危漏洞|增强建议|弱点)",re.I)
    words={"a":1,"an":1,"one":1,"two":2,"three":3,"four":4,"five":5,"six":6,"seven":7,"eight":8,"nine":9,"ten":10}
    for m in pattern.finditer(report.text):
        # Resolution clauses repeat subset counts. Stop before their assertions.
        sentence=re.split(r"[;,]\s*(?:and\s+)?(?:all|the|among|of which|after|其中)|[,，]\s*(?:and\s+)?(?=(?:\d+|a|an|one|two|three|four|five|six|seven|eight|nine|ten)\b[^,;]{0,70}\b(?:were|was|have|has|are|is)\b)",m[1],maxsplit=1,flags=re.I)[0]
        counts={}
        for num,label in labels.findall(sentence):
            count=int(num) if num.isdigit() else words[num.lower()]
            raw=label.lower()
            bucket=severity(label, report.firm)
            counts[bucket]=counts.get(bucket,0)+count
        if counts:
            start=m.start();end=m.start(1)+len(sentence)
            page=next((p["page"] for p in report.meta["pages"] if p["start"]<=start<p["end"]),None)
            groups.append({"counts":counts,"basis":"printed_conclusion_counts","evidence":[{"page":page,"start":start,"end":end,"text":report.text[start:end]}]})
    if not groups:
        return None
    selected=groups[0]
    alternatives=[g for g in groups[1:] if g["counts"]!=selected["counts"]]
    if alternatives:
        selected={**selected,"ambiguous":True,"alternatives":alternatives}
    return selected


# Phase 4d compatibility contract; preserve the existing parser until era review.
from variants import legacy as _legacy_variant
VARIANTS = (_legacy_variant('slowmist', parse),)
