"""General source-content rules for countability, client identity and renderings."""
import re
from collections import Counter


def generic_project(value):
    from metadata_rules import clean, DATE, MONTH, parse_date
    s=clean(value)
    if not s or parse_date(s)[0] or DATE.fullmatch(s): return True
    if not re.search(r'[A-Za-z0-9]',s): return True
    if s.casefold() in {'for','of','of the','by','annex','appendix','summary','introduction','contents'}: return True
    if re.fullmatch('(?:'+MONTH+r')[. -]?\d{2,4}',s,re.I): return True
    if re.fullmatch(r'(?:\d+(?:\.\d+)*\s*)?(?:(?:smart\s*)?contracts?|security|audit|report|review|assessment|analysis|finance|changes|layer|projects?|code|source code|secure code|chain|circuit|public|private|confidential|competitive|comprehensive|blockchain|application|cryptographic|program|description|this|the|x|authors of this|v\d+(?:\.\d+)*)',s,re.I): return True
    if re.fullmatch(r'(?:(?:smart contract|security|code|source code)\s+)*(?:audit(?:ing)?|review|assessment|analysis)(?:\s+report)?',s,re.I): return True
    # Labels and prose are not named clients, even when a faulty title rule
    # captured the beginning of a sentence or several table column headings.
    return bool(re.search(r'^(?:this|the (?:team|report|review|audit|following)|in code4rena|noted that|authors of)\b|\b(?:team was commissioned|submit an inquiry|message on telegram|competition is limited|repository\s*link\s*commit\s*hash|table of contents)\b',s,re.I))


def project_from_text(text, meta):
    """Keep multi-line client names; reject generic headings and date placeholders."""
    from metadata_rules import clean, field, REPORT, DATE
    front=text.split('\f')[0][:6000]
    lines=[clean(s) for s in front.splitlines() if clean(s)]
    # Source-native named scope, including wrapped report covers. Do not let a
    # confidentiality banner or an adjective describing the report win.
    for i,line in enumerate(lines[:35]):
        if re.fullmatch(r'(?:for|of)(?: the)?',line,re.I) and i and REPORT.search(' '.join(lines[max(0,i-3):i])):
            following=[]
            for s in lines[i+1:i+5]:
                if generic_project(s) or DATE.search(s) or re.search(r'report\s*(?:#|no|id)|version|prepared|https?://|^v\d',s,re.I): break
                following.append(s)
            value=clean(' '.join(following))
            if 2<=len(value)<120:
                return field(value,'wrapped_named_cover_scope',.99,evidence='\n'.join([line]+following))
        m=re.match(r'(?:(?:smart\s+contract\s+)?(?:security\s+)?audit\s+report|(?:security\s+)?review\s+report|code\s+assessment|security\s+assessment)\s+(?:of|for)\s+(?:the\s+)?(.+)',line,re.I)
        if not m and re.match(r'^(?:of|for) the\s+',line,re.I) and any(REPORT.search(p) for p in lines[max(0,i-3):i]):
            m=re.match(r'(?:of|for) (?:the )?(.+)',line,re.I)
        if m:
            v=clean(m[1])
            if not generic_project(v) and len(v)<120:
                return field(v,'named_cover_scope',.99,evidence=line)
    for i,line in enumerate(lines[:80]):
        m=re.match(r'(?:project\s+name|client|customer|target)\s*[:|]?\s{1,}(.+)$',line,re.I)
        if m:
            v=re.split(r'\s+(?:Repository|Commit|Timeline|Auditors|Platform|Version)\b',m[1],maxsplit=1,flags=re.I)[0]
            if not generic_project(v) and 2<=len(v)<120 and not re.match(r'name\b|description\b|the\b|this\b',v,re.I):
                return field(v,'named_scope_table_field',.98,evidence=line)
    # A title immediately above a report-type banner is the client. Earlier
    # navigation/CTA lines cannot become part of that name.
    for i,line in enumerate(lines[:30]):
        if re.fullmatch(r'(?:(?:comprehensive|competitive|blockchain|application|cryptographic|smart contract|source code)\s+)*(?:security\s+)?(?:audit|assessment|review)(?: report)?',line,re.I):
            prior=lines[i-1] if i else ''
            if generic_project(prior) and i>1: prior=lines[i-2]
            if re.match(r'(?:comprehensive|competitive|blockchain|application|cryptographic|source code)\b',line,re.I) and prior and not generic_project(prior) and len(prior)<110 and not DATE.search(prior) and not re.search(r'https?://|version|prepared|telegram|inquiry',prior,re.I):
                return field(prior,'adjacent_cover_client',.96,evidence=prior+'\n'+line)
            if i+1<len(lines):
                nxt=lines[i+1]
                if not generic_project(nxt) and not DATE.search(nxt) and len(nxt)<110 and not re.search(r'contents|version|prepared|https?://',nxt,re.I):
                    return field(nxt,'following_cover_client',.96,evidence=line+'\n'+nxt)
    # Explicit client fields, including a label/value on different lines.
    for i,line in enumerate(lines[:100]):
        m=re.match(r'(?:project(?:\s+name)?|client(?:\s+name)?|prepared\s+for|customer)\s*[:|]\s*(.*)$',line,re.I)
        if m:
            v=m[1] or (lines[i+1] if i+1<len(lines) else '')
            if 2<=len(v)<120 and not generic_project(v) and not re.match(r'name|description|address|website|contact|the |this ',v,re.I):
                return field(v,'named_client_field',.97,evidence=line+' '+v)
    # A cover often wraps both the client name and the generic report heading.
    for i,line in enumerate(lines[:22]):
        if re.fullmatch(r'(?:(?:smart\s*)?contracts? |code |security )*(?:audit|assessment|review|analysis)(?: report)?',line,re.I):
            candidates=[]
            for prev in reversed(lines[max(0,i-4):i]):
                if (REPORT.search(prev) or DATE.search(prev) or (generic_project(prev) and prev.lower()!='finance') or re.search(r'prepared|confidential|version|final|^v\.?\s*\d|https?://|www\.|inquiry|telegram|^or$',prev,re.I)
                    or re.fullmatch(r'(?:(?:smart\s*)?contracts?|security|code)',prev,re.I)):
                    break
                if len(prev)>110: break
                candidates.insert(0,prev)
            if candidates:
                value=' '.join(candidates)
                if not generic_project(value) and len(value)<160:
                    return field(value,'multiline_cover_client',.88,evidence='\n'.join(candidates+[line]))
    # Source titles that put the client before a report type.
    title=meta['report_title'].get('value') or ''
    m=re.match(r'^(.{2,120}?)\s*[-–—:|]?\s+(?:(?:smart\s*)?contracts?\s+)?(?:security\s+)?(?:audit|review|assessment|analysis)(?:\s+report)?\b',title,re.I)
    if m and not generic_project(m[1]) and not re.search(r'^formal|^report|^public|^smart$',m[1],re.I):
        return field(clean(m[1]),'named_report_title',.86,evidence=title)
    # Commissioned scope names are useful when the cover consists of logos.
    for pattern in [r'(?:security assessment|security audit|review)\s+of\s+their\s+([^.!?\n]{2,110})',
                    r'(?:Three Sigma(?: Labs)?|\w+ Security)\s+audited\s+([^\n.]{2,110}?)\s+(?:smart contracts|in a|in an)',
                    r'(?:commissioned|engaged)\s+by\s+(?:the\s+)?([^\n.]{2,100}?)\s+to\s+conduct']:
        m=re.search(pattern,text[:22000],re.I)
        if m and not generic_project(m[1]):
            return field(clean(m[1]),'commissioned_source_scope',.96,evidence=m[0])
    return None


def content_kind(text, meta, fmt):
    """Reject evidence of another resource; uncertain acquired leads stay provisional."""
    from metadata_rules import clean, field, REPORT
    front=text[:7000]
    short=clean(text)
    heading=' '.join(clean(s) for s in text.splitlines()[:18])
    rules=[
        ('wrong_source_response',r'^(?:404(?:\s+page)?\s+not\s+found|404\b|page\s+not\s+found|access\s+denied|this\s+page\s+(?:does not|doesn.t)\s+exist)'),
        ('preparation_checklist',r'(?:audit|security review)\s+(?:preparation|readiness)\s+checklist|preparing\s+for\s+(?:an?\s+)?audit'),
        ('token_sale_particulars',r'token\s+sale\s+particulars'),
        ('supporting_specification',r'partial\s+(?:alloy\s+)?specification|specification.{0,120}(?:included\s+in|supplement\s+to).{0,100}(?:audit|report)'),
        ('incident_postmortem',r'^(?:.{0,100}?\s)?(?:post[- ]mortem|incident\s+(?:report|analysis))\b'),
    ]
    for kind,pattern in rules:
        m=re.search(pattern,short[:4500] if kind=='supporting_specification' else heading,re.I)
        if m: return field(kind,'source_content_classification',.98,evidence=m[0])
    if fmt=='html':
        title=meta.get('text_receipt',{}).get('html_title','')
        if re.fullmatch(r'(?:Research|Insights|Blog|Audits|Security Audits|Audit Reports)(?:\s*[|–—-].*)?',title,re.I) and not re.search(r'(?:audit|assessment)\s+(?:scope|period|results)|\bfindings\s+(?:summary|overview)',front,re.I):
            return field('generic_landing_page','source_content_classification',.95,evidence=title)
    if re.search(r'\babstract\b',front,re.I) and re.search(r'\breferences\b',text,re.I) and not REPORT.search(heading) and re.search(r'\b(?:university|paper|coq|theorem)\b',front,re.I):
        return field('academic_paper','source_content_classification',.9,evidence=heading[:200])
    if re.search(r'testimonial|what our clients say',heading,re.I) and not re.search(r'findings|audit scope',text,re.I):
        return field('testimonial','source_content_classification',.95,evidence=heading[:200])
    return field('report' if meta.get('structured_report') or REPORT.search(front) or meta.get('audit_type',{}).get('value') else 'unknown','source_content_classification',.85)


def auditor(text, current):
    """Shared Bit repositories and Theori's ChainLight team require named authorship.

    Both brands are scoped publishers. Theori-only covers count as Theori;
    ChainLight-labelled covers count as ChainLight, retaining its parent branding.
    Repository ownership does not supply either attribution.
    """
    from metadata_rules import field
    families=[{'movebit':'MoveBit','scalebit':'ScaleBit'}, {'chainlight':'ChainLight','theori':'Theori'},
              {'cantina':'Cantina','spearbit':'Spearbit'}, {'consensys-diligence':'ConsenSys Diligence','abdk-consulting':'ABDK Consulting'}]
    family=next((f for f in families if current in f),None)
    if not family: return None
    cover=text.split('\f')[0][:4000]
    front=text[:24000]
    explicit=[]
    for pid,name in family.items():
        m=re.search(r'(?:prepared\s+by|audited\s+by|assessment\s+by|conducted\s+by|auditors?\s*[:|]?|engaged\s+(?:with\s+)?)\s*[:|]?\s*('+re.escape(name)+r')\b',front,re.I)
        if m and re.search(r'previous|prior|earlier',front[max(0,m.start()-70):m.start()],re.I): m=None
        if m: explicit.append((pid,m[0]))
    brand_text=front if current in {'chainlight','theori','movebit','scalebit'} else cover
    named=[(pid,name) for pid,name in family.items() if re.search(r'\b'+re.escape(name)+r'\b',brand_text,re.I)]
    selected=explicit[0] if len(explicit)==1 else named[0] if len(named)==1 else next(((pid,n) for pid,n in named if pid=='chainlight'),None) if current in {'chainlight','theori'} else None
    if selected: return field(selected[0],'source_named_auditor_brand_policy_v2',.98,evidence=selected[1])
    return None


def report_content(text):
    """Fingerprints of substantive headings and scope, excluding shared boilerplate.

    These are candidate tokens, never a merge decision on their own.
    """
    from metadata_rules import normalize, sha
    headings=[]
    for line in text.splitlines():
        s=line.strip()
        if re.match(r'^#{2,6}\s',s) or re.match(r'^(?:[CHMLIG]|[A-Z]{2,5})[-_ ]?\d{1,3}[\]:.) -]',s):
            s=re.sub(r'^#{1,6}\s*','',s)
            s=re.sub(r'\b(?:fixed|resolved|acknowledged|open|closed|severity|status)\b','',s,flags=re.I)
            s=normalize(s)
            if len(s)>=18 and not re.search(r'tableofcontents|executivesummary|disclaimer|recommendations|methodology',s): headings.append(s)
    # Cross-format reports often lose Markdown heading markers in PDF/HTML.
    # Long distinct lines remain content evidence after excluding common prose.
    lines=[]
    for line in text.splitlines():
        if re.search(r'copyright|disclaimer|all rights reserved|not financial|no guarantee',line,re.I): continue
        n=normalize(re.sub(r'^[#*|\s]+','',line))
        if 45<=len(n)<=220: lines.append(n)
    counts=Counter(lines)
    return dict(headings=sorted(set(headings)), lines=sorted(sha(s.encode()) for s,n in counts.items() if n==1),
                complete_sha256=sha(re.sub(r'[^a-z0-9]','',text.lower()).encode()) if len(text)>1000 else None)
