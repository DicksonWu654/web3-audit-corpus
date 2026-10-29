"""Ordered, scored layout contracts. Selection never consults parsed rows or totals."""
from dataclasses import dataclass
import re
from core import finish, severity_context, candidate_severity
from prior_findings import exclude_prior_findings
from layout_support import visible
from text_patterns import index_line

THRESHOLD = 6


@dataclass(frozen=True)
class Fingerprint:
    # (name, regex, weight), on source text; at most one vote per signature.
    signatures: tuple = ()
    date_range: tuple = (None, None)
    formats: tuple = ()
    structured: bool | None = None
    legacy: bool = False
    reject_signatures: tuple = ()

    def score(self, report):
        matches=[]; score=0
        if (self.signatures or self.reject_signatures) and not hasattr(report,'_fingerprint_text'):
            report._fingerprint_text='\n'.join(visible(l.text) for l in report.lines if not l.code and not index_line(l.text))
        text=getattr(report,'_fingerprint_text','')
        for pattern in self.reject_signatures:
            if re.search(pattern,text,re.I|re.M):return {'score':0,'matches':[],'rejected':'incompatible_detail_signature'}
        if self.formats and report.meta.get('file_format') not in self.formats:
            return {'score':0,'matches':[], 'rejected':'file_format'}
        if self.structured is not None and bool(report.native) != self.structured:
            return {'score':0,'matches':[], 'rejected':'structured_payload'}
        if self.structured is True:
            score+=8;matches.append('native_payload')
        for name,pattern,weight in self.signatures:
            if re.search(pattern.replace(r'^\s*', r'^[ \t]*'),text,re.I|re.M):score+=weight;matches.append(name)
        # Date is a weak hint, never enough by itself. A date outside a range
        # does not veto a report that uses an older template in a later year.
        date=report.meta.get('date_hint')
        lo,hi=self.date_range
        if date and (not lo or date[:4]>=lo[:4]) and (not hi or date[:4]<=hi[:4]):
            score+=1;matches.append('date_hint')
        if self.legacy:
            score+=THRESHOLD;matches.append('legacy_compatibility_contract')
        return {'score':score,'matches':matches}

@dataclass(frozen=True)
class Variant:
    variant_id: str
    fingerprint: Fingerprint
    parse: object
    fixtures: tuple
    status_parser: object = None
    printed_counts: object = None
    notes: str = ''


def select(report, variants):
    if len({v.variant_id for v in variants})!=len(variants):raise ValueError('Duplicate variant ID')
    scores=[dict(variant_id=v.variant_id,order=i,**v.fingerprint.score(report)) for i,v in enumerate(variants)]
    ranked=sorted(scores,key=lambda s:(-s['score'],s['order']))
    best=ranked[0] if ranked else None
    chosen=variants[best['order']] if best and best['score']>=THRESHOLD else None
    report.layout_selection={'variant_id':chosen.variant_id if chosen else report.firm+'/generic_fallback',
                             'unknown_layout':chosen is None,'threshold':THRESHOLD,'scores':ranked}
    report.selected_variant=chosen
    return chosen


def dispatch(report, variants):
    from parsers.generic import parse as generic
    variant=select(report,variants)
    with severity_context(report):
        candidates=(variant.parse if variant else generic)(report)
        if variant and not variant.fingerprint.legacy:
            for c in candidates:
                if not c.severity_raw or report.native:continue
                pattern=r'(?<!\w)'+r'[ \t]*'.join(re.escape(ch) for ch in re.sub(r'\s','',c.severity_raw))+r'(?!\w)'
                end=c.end if c.end is not None else min(len(report.text),c.start+1500)
                for m in re.finditer(pattern,report.text[c.start:end],re.I):
                    if re.search(r'[A-Za-z][ \t]+[A-Za-z]',m[0]) and re.sub(r'\s','',m[0]).casefold()==re.sub(r'\s','',c.severity_raw).casefold():
                        c.severity_raw=m[0];c.evidence['severity_label_span']={'start':c.start+m.start(),'end':c.start+m.end(),'text':m[0]};break
        if not variant or not variant.fingerprint.legacy:candidates=finish(report,candidates)
        if variant and variant.status_parser:
            variant.status_parser(report,candidates)
        candidates=exclude_prior_findings(report,candidates)
        # A public excerpt can contain an inventory without any detail cards.
        # Never supplement partial detail extraction from the summary or totals.
        disposition=getattr(report,'layout_disposition',{}).get('reason')
        if (not any(c.record_kind!='summary_excerpt' for c in candidates)
                and disposition not in {'prior_audit_retest_only','external_auditor_client_archive'}):
            from summary_inventory import inventory
            excerpts=finish(report,inventory(report))
            if excerpts:candidates=excerpts
        for c in candidates:
            c.normalized=candidate_severity(report,c)['normalized']
            if not variant and c.method!='summary_inventory':
                c.evidence['generic_method']=c.method
                c.method='generic_fallback'
                c.confidence=min(c.confidence,.4)
                c.evidence['unknown_layout']=True
            c.evidence['variant_id']=report.layout_selection['variant_id']
        return candidates


def legacy(firm, parse):
    return Variant(firm+'/legacy',Fingerprint(legacy=True),parse,
                   ('legacy_contract',),notes='Compatibility wrapper; no layout-era validation.')
