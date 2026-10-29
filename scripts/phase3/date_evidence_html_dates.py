"""Retain literal HTML date metadata without conflating publication and audit dates."""
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/phase3'))
sys.path.insert(0,str(ROOT/'scripts/build'))
from metadata_rules import atomic, canonical, sha
from date_evidence_dates import capture, documents


class DateMetadata(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.dates=[]

    def handle_starttag(self,tag,attrs):
        if tag!='meta':return
        attrs=dict(attrs)
        key=attrs.get('property') or attrs.get('name') or attrs.get('itemprop') or ''
        value=attrs.get('content') or ''
        if not re.match(r'20\d{2}-\d{2}(?:-\d{2})?',value):return
        normalized=re.sub(r'[^a-z]','',key.lower())
        if normalized in {'reportdate','reportissuedate','dateissued','dcdateissued'}:
            role,kind='report_issue','report_issue'
        elif normalized in {'auditenddate','auditcompletiondate','assessmentenddate','reviewenddate','contestenddate'}:
            role,kind='audit_completion','completion'
        elif normalized in {'articlepublishedtime','datepublished','date','pubdate','dcdate','dcdatecreated'}:
            role,kind='publication','publication'
        elif normalized in {'datemodified','articlemodifiedtime'}:
            role,kind='other','modified'
        else:return
        self.dates.append(dict(raw_value=value,role=role,kind=kind,source_field=key,
                               evidence=self.get_starttag_text()))


def warm(root=ROOT):
    results=[];seen=set()
    for d,text,receipt,cause in documents(root,capture(root)):
        digest=d['sha256']
        if cause or not digest or digest in seen or d['file_format']!='html':continue
        seen.add(digest)
        candidates=sorted((root/'local-cache/originals'/digest[:2]).glob(digest+'.*'))
        if not candidates:continue
        body=candidates[0].read_bytes()
        if sha(body)!=digest:raise ValueError('HTML original hash mismatch')
        parser=DateMetadata();parser.feed(body.decode('utf-8','replace'))
        out=root/'local-cache/date-text'/(digest+'.txt')
        meta=out.with_suffix('.pages.json')
        # Repeated runs stay byte-identical after the cache becomes preferred.
        if out.exists() and meta.exists():
            info=json.loads(meta.read_text())
            if info.get('method')=='date_evidence_html_literal_metadata' and sha(out.read_bytes())==info.get('text_sha256'):
                results.append(dict(sha256=digest,status='cached',fields=len(info['html_metadata_dates'])))
                continue
        if not parser.dates:
            results.append(dict(sha256=digest,status='no_date_metadata',fields=0));continue
        payload=text+'\n\nHTML metadata (verbatim from SHA-verified original):\n'
        items=[]
        for item in parser.dates:
            start=len(payload);payload+=item['evidence']+'\n'
            items.append(item|dict(text_start=start,text_end=len(payload)-1))
        info=dict(file_format='html',status='ok',method='date_evidence_html_literal_metadata',
                  original_sha256=digest,original_hash_verified=True,text_sha256=sha(payload.encode()),
                  html_metadata_dates=items,base_text_sha256=sha(text.encode()),page_count=1)
        atomic(out,payload);atomic(meta,canonical(info)+'\n')
        results.append(dict(sha256=digest,status='extracted',fields=len(items)))
    atomic(root/'local-cache/phase3f/html_metadata.json',canonical(dict(holdouts_opened=0,results=results))+'\n')
    from collections import Counter
    print(canonical(dict(statuses=dict(Counter(r['status'] for r in results)),fields=sum(r['fields'] for r in results))))


if __name__=='__main__':
    warm()
