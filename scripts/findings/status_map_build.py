"""Rebuild the reviewed status crosswalk from the frozen vocabulary and receipts.

This is an editorial policy compiler, not a runtime keyword classifier. Only
the explicit native vocabulary and qualified assertion grammars below acquire
a remediation bucket. Other observed strings are listed for review and fail to
not_stated. Definition pages are curated; examples never masquerade as definitions.
"""
from __future__ import annotations
from collections import defaultdict
from functools import lru_cache
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import ROOT, holdouts, read_snapshot
from status_resolve import canonicalize_label as key

BASE = ROOT / 'local-cache/phase4-status'
NATIVE = {
    'fixed': ('Fixed', 'Fixed before report', 'Resolved', 'Resolve', 'Solved', 'Patched',
              'Patched without reaudit', 'Implemented', 'Remediated', 'Addressed', 'Corrected',
              'Code Corrected', 'Specification Changed', 'Specification Updated', 'Design Changed',
              'Confirmed and fixed', 'Confirmed & fixed', 'Acknowledged and fixed',
              'Acknowledged and resolved', 'Confirmed and patched', 'Mitigation confirmed',
              'Fix verified', 'Fix confirmed', 'Confirmed fix', 'Fix implemented', 'Done'),
    'partially_fixed': ('Partially Fixed', 'Partially Resolved', 'Partially Solved', 'Partially Implemented',
                        'Partially Addressed', 'Partially Mitigated', 'Partly Resolved', 'Code Partially Corrected'),
    'acknowledged': ('Acknowledged', 'Acknowledge', 'Acknowledg', 'Acknowledgement', 'Acked', 'Ack',
                     "Ack'd", 'Ack’d', 'Risk Accepted', 'Accepted', "Won't Fix", 'Won’t Fix', 'Wont Do',
                     "Won't Do", 'Will not be fixed', 'No fix required', 'Commented', 'Intended behavior',
                     'Expected behavior', 'Replied'),
    'unresolved': ('Unresolved', 'Open', 'Opened', 'Pending', 'WIP', 'In Progress', 'New', 'New issue',
                   'Reported', 'Not Fixed', 'Not Resolved', 'Not Implemented', 'Not Addressed', 'Unaddressed',
                   'No action taken', 'Failed Resolution', 'Planned', 'Deferred', 'To-do', 'TODO',
                   'Not yet fixed', 'Will be fixed', 'Acknowledged and will be fixed', 'Unmitigated',
                   'Mitigation not confirmed', 'Mitigation unconfirmed', 'Not fixing', 'Not to be fixed'),
    'not_stated': ('Invalid', 'Invalidated', 'Not valid', 'No Issue', 'NO_ISSUE', 'Not an issue', 'False Positive',
                   'Determined non-issue', 'Found to be not applicable', 'Not Applicable', 'Void',
                   'Disputed', 'Rejected', 'Undetermined', 'Unknown', 'N/A', 'None', 'Info', 'Informational',
                   'Other', 'Not Retested', 'Impact', 'Skipped', 'Declined', 'Outdated', 'Caution advised'),
}
EXACT = {key(label): (bucket, label) for bucket, labels in NATIVE.items() for label in labels}
EXTRAS = {
    'abdk-consulting': ('Info', 'INFO', 'Fixed', 'Opened', 'Reported', 'Replied', 'Skipped', 'Ruled Out'),
    'code4rena': ('Confirmed', 'Acknowledged', 'Disputed', 'Confirmed and patched', 'Mitigation confirmed',
                 'Mitigation not confirmed', 'Partially mitigated', 'Unmitigated'),
    'sherlock': ('Fixed', "Won't fix", 'Acknowledged', 'Confirmed fix', 'Not fixing'),
    'oxorio': ('Invalid', 'NO_ISSUE', 'NEW', 'Fixed', 'Acknowledged', 'Dismissed'),
    'macro': ('Wont Do', 'Fixed', 'Addressed', 'Acknowledged'),
    'neodyme': ('verified the fix', 'Fixed', 'Resolved', 'Acknowledged'),
    'zellic': ('Fixed', 'Resolved', 'Acknowledged', 'Remediated', 'Addressed', 'Partially fixed'),
    'trail-of-bits': ('Fixed', 'Not fixed', 'Risk Accepted', 'Partially Resolved', 'Resolved', 'Undetermined'),
    'runtime-verification': ('Fix implemented', 'Addressed', 'Fixed', 'Resolved', 'Acknowledged'),
    'verichains': ('Acknowledged and fixed', 'Acknowledged and resolved'),
}
# Curated native definitions, inspected independently of extraction output.
DEFINITIONS = {
    'chainlight': ('0219c05985328acfc262a87f7efe34004cad866fe15760f5463a5d9e485d40df', 10),
    'mixbytes': ('03cf6121b0eb3d6d6e32fe715996b045776de9e4b616e9339bfba69bd7355faf', 11),
    'movebit': ('03403505f5c6d18936f8b942fa6ce3282f53a366df3f1fc18f842c76172b24ac', 13),
    'scalebit': ('07df95ef1e6411e7801875a26ae10af629369c3f8c8fe56d07cf969280010289', 11),
    'statemind': ('1036145ab27ce97f7f504dfc484e29515bc23e20b62cf631774ed721eebdd19f', 7),
    'trail-of-bits': ('b8260e48c7eb3b27904b7f232c15bbb80b11cb49c3b559c100724969acd6f00a', 56),
    'oxorio': ('4a807645c692664c799b933e881ababdf01ed322fce42058b2564c173d3db8a1', 8),
    'dedaub': ('2f2e2f482b11cb6f6ad615982fb5378df0ecb89cefa25533767d394d1fa90560', 4),
    'iosiro': ('73b5fffd23f7fbe4352f02da1b14ad53e69fb47e3c4404befab76064fcecf85e', 1),
}
DEFINITION_LABELS={
    'chainlight':('Confirm','Reported','Fixed','Acknowledged','WIP',"Won't Fix"),
    'mixbytes':('Fixed','Partially Fixed','Acknowledged'),
    'movebit':('Fixed','Partially Fixed','Acknowledged'),
    'scalebit':('Fixed','Partially Fixed','Acknowledged'),
    'statemind':('Fixed','Acknowledged'),
    'trail-of-bits':('Undetermined','Risk Accepted','Unresolved','Partially Resolved','Resolved'),
    'oxorio':('New','Fixed','Acknowledged','No Issue','Dismissed'),
    'dedaub':('Dismissed','Acknowledged','Resolved'),
    'iosiro':('Closed',),
}
SIGMA_MODERN_DEFINITION=('d54806eccfd20e7deb67b55bb0915fa43c1d83bfb060f2e77602be2851a90a37',5)
SIGMA_DEFINITION_REGEX=r'Closed:\s*the issue was acknowledged by the project team but no further actions have been taken'
SPECIAL_EXAMPLES = {
    ('abdk-consulting','info'): ('7c05430c00bb374b8b5ca2d0e032fdffbd86e29abc350fc64888caa001531793',10),
    ('macro','wontdo'): ('7d09d82c5a80a0563e06679fed29e3e895fa0d2d5aea15373111f3b4fbc9429b',1),
    ('sherlock','acknowledged'): ('3d63d9c1e34c9ed2bd0b1667270fa8e207bd12ce8951efdc4cc3af5dd90ac5eb',1),
    ('verichains','acknowledgedandfixed'): ('f7e06d7b2f9cdb42a88d9e1a935397c1166d7e89ea9da000971809dcbfa91ae3',9),
    ('chainsecurity','codecorrected'): ('10569b272f26d8e4de23e01a3455398f08273d86bf4fd50604a7c164c3213b85',17),
    ('chainsecurity','acknowledged'): ('10569b272f26d8e4de23e01a3455398f08273d86bf4fd50604a7c164c3213b85',16),
}


def decision(firm, raw):
    k=key(raw)
    if firm=='abdk-consulting' and k=='info':
        return 'acknowledged', 'ABDK prints Info beside client decisions such as “Won’t fix”; this is an accepted comment, not an informational severity.', False
    if firm=='oxorio' and k=='invalid':
        return 'not_stated','Listed: the native legend defines NO ISSUE as a validity disposition; a separate Invalid status definition was not located.',True
    if firm=='neodyme' and k=='verifiedthefix':
        return 'fixed', 'Neodyme explicitly states it verified the supplied fix.', False
    if k in {'confirmed','confirm','conrmed'}:
        return 'acknowledged', 'Publisher/client confirmation accepts the finding but does not assert completed remediation.', False
    if firm=='dedaub' and k=='dismissed':
        return 'acknowledged','Dedaub defines dismissed/acknowledged as client decisions with no action taken, distinct from auditor-resolved issues.',False
    if firm=='iosiro' and k=='closed':
        return 'fixed','iosiro defines Closed as satisfactorily addressed, removing the risk posed.',False
    if k=='dismissed':
        return 'not_stated', 'Dismissal is a validity/disposition decision; it does not establish remediation.', False
    if firm=='coinspect' and k in {'decidednottoaddressthisissue','smartcontractwillnotbemodified'}:
        return 'acknowledged','The native Status section records the team’s explicit decision to keep the issue/design.',False
    if firm=='ackee-blockchain' and (re.search(r'\bhave been renamed\b',raw) or re.search(r'\bare now used in the\s+code\b',raw)):
        return 'fixed','The revision-qualified Solution describes the completed implementation change.',False
    if firm=='runtime-verification' and (k in {'fullyawareoftheissue','takenintoconsideration','currentlyleftasis'} or re.search(r'\bis aware of this\b',raw)):
        return 'acknowledged','The publisher’s Status section explicitly records client awareness or consideration, without claiming a fix.',False
    if firm=='runtime-verification' and re.match(r'(?:A check|The check).*has been introduced',raw):
        return 'fixed','The publisher’s Status section explicitly records an implemented validation check.',False
    if firm=='chainlight' and k=='fixwasincomplete':
        return 'partially_fixed','ChainLight explicitly states that the supplied fix was incomplete.',False
    if firm=='chainlight' and re.search(r'\bcommit\s+[a-f0-9]{6,40}\b',raw,re.I):
        return 'fixed','The native Resolution names the implemented change and its review commit.',False
    if firm=='statemind' and k=='acknownledged':
        return 'acknowledged','Native misspelling of Statemind’s defined Acknowledged status.',False
    if k in {'verified','fixok','ok','confirmingfix','confirmedfixat'} and firm in {'cantina','spearbit','veridise','zokyo','least-authority','decurity'}:
        return 'fixed', 'Publisher verification is presented as the finding’s remediation verdict; it is not general code verification.', False
    if k=='mitigated':
        return 'fixed', 'The source states mitigation was completed; acknowledgement alone would be a separate status.', False
    if k=='closed':
        return 'not_stated', 'Closed alone does not distinguish remediation from administrative closure or invalidation.', True
    if k in EXACT:
        bucket=EXACT[k][0]
        why={'fixed':'The publisher explicitly records completed correction or resolution.',
             'partially_fixed':'The publisher explicitly qualifies remediation as partial.',
             'acknowledged':'The publisher records acknowledgement or a decision to accept/defer the issue, without asserting a completed fix.',
             'unresolved':'The publisher records a persisting, pending or unfinished issue.',
             'not_stated':'The label concerns validity, severity, applicability or missing verification; no remediation state is established.'}[bucket]
        return bucket,why,False
    plain=re.sub(r'\s+',' ',raw.replace('\\n','\n')).strip()
    if firm=='runtime-verification':
        native=re.sub(r'[\u200b\ufeff]','',plain)
        if re.search(r'\b(?:partially|primary concern)\s+addressed\b',native,re.I):
            return 'partially_fixed','The native Status assertion limits the completed correction to part of the concern.',False
        if re.search(r'\b(?:not|never)\s+(?:to be )?(?:fixed|addressed|resolved)|\bno fix\b|\bintends? to address\b|\bwill be fixed\b',native,re.I) and not re.search(r'\backnowledged\b',native,re.I):
            return 'unresolved','The native Status explicitly states noncompletion or a future correction.',False
        if re.search(r'\backnowledged and addressed\b',native,re.I):
            return 'fixed','The client explicitly reports both acknowledgement and completed remediation.',False
        if re.search(r'\backnowledged\b',native,re.I):
            return 'acknowledged','The native Status explicitly records client acknowledgement without a completed fix.',False
        if (re.search(r'\b(?:this|the) (?:issue|finding|recommendation) (?:has been|was|is) (?:fully )?(?:addressed|fixed|resolved)\b',native,re.I)
            or re.search(r'\b(?:fixed|solved)\s+(?:in|using|for|this issue)\b|\bconfirm fixed\b|\bfix implemented\b',native,re.I)
            or re.match(r'(?:Swaap Labs|Atlendis Labs|Morpho(?: Labs)?|The client) (?:has )?(?:addressed|fixed)\b',native,re.I)
            or re.match(r'Addressed(?:\s*\(|\s+(?:via|following))',native,re.I)
            or re.search(r'\b(?:comments|issues) have been addressed\b|\bapplied strategy \(1\) to resolve\b',native,re.I)):
            return 'fixed','The publisher’s Status sentence explicitly records completed remediation, retaining the client/commit qualification.',False
    # Prefixes apply only while compiling exact observed labels, never to unseen
    # runtime inputs. Negation and partial outcomes take precedence.
    if re.match(r'(?i)^(?:partially|partly)\s+(?:fixed|addressed|resolved|implemented)',plain) or re.search(r'(?i)\bfixed only\b',plain):
        return 'partially_fixed','The source assertion explicitly limits the fix to part of the affected scope.',False
    if re.match(r'(?i)^(?:not (?:fixed|resolved|addressed)|will (?:be )?fixed|fix (?:unverified|not reviewed)|unverified fix)',plain):
        return 'unresolved','The source explicitly denies completion or verification of remediation.',False
    if re.match(r'(?i)^(?:acknowledged|acknowledge|risk accepted|noted.{0,10}risk accepted)\b',plain):
        return 'acknowledged','The source assertion begins with acknowledgement/risk acceptance, not completed remediation.',False
    if re.match(r'(?i)^(?:fixed|addressed|resolved|solved|implemented)(?:\s+(?:in|at|by|here|for|with|before|as)\b|[.!:]|$)',plain):
        return 'fixed','The native status assertion explicitly records completed remediation, retaining its commit/version qualifier.',False
    if re.match(r'(?i)^(?:this (?:(?:issue|finding) )?(?:was|is|has been)|the (?:issue|finding) (?:was|is|has been))\s+(?:fully\s+)?(?:fixed|addressed|resolved)\b',plain):
        return 'fixed','The source sentence explicitly asserts that this issue was corrected.',False
    if re.match(r'(?i)^currently being reviewed\b',plain):
        return 'unresolved','The source states review is ongoing, without a completed remediation verdict.',False
    return 'not_stated','Listed for review: this narrative/truncated or unsupported label cannot establish a canonical remediation state.',True


@lru_cache(maxsize=128)
def metadata(sha):
    if sha in holdouts(): raise ValueError('Holdout definition access denied')
    p=ROOT/'local-cache/fulltext'/(sha+'.pages.json')
    return json.loads(p.read_text()) if p.exists() else None


def proof(row, page, quote, kind):
    return dict(sha256=row['sha256'],page=page['page'],quote=quote,kind=kind,
                page_basis='pdf_page' if row['file_format']=='pdf' else 'logical_text_page',public_url=row['public_url'])


def main():
    before=json.loads((BASE/'before.json').read_text())
    current={}
    # Include new raw labels from a scoped rebuild as well as the immutable old
    # vocabulary. Never inspect a held-out row to expand this policy.
    blocked=holdouts()
    for path in sorted((ROOT/'data/findings').glob('*.jsonl')):
        if path.name.startswith('_'):continue
        examples={}
        for line in path.open():
            row=json.loads(line)
            if row['sha256'] in blocked:raise ValueError('Holdout row denied')
            raw=row.get('status_original',row.get('status_raw'))
            if raw is not None:examples.setdefault(json.dumps(raw,ensure_ascii=False),row)
        current[path.stem]=examples
    docs=defaultdict(dict)
    for d in read_snapshot():docs[d['row']['firm_id']].setdefault(d['row']['sha256'],d['row'])
    policy={'policy':'publisher-status-v1','schema_version':1,
            'statuses':['fixed','partially_fixed','acknowledged','unresolved','not_stated'],
            'matching':'NFKC/casefold, punctuation and whitespace (including letter spacing); negations and qualifiers remain distinct.',
            'unscoped_labels':{bucket:bucket for bucket in ('fixed','partially_fixed','acknowledged','unresolved','not_stated')},
            'publishers':{}}
    for firm in sorted(docs):
        examples=before.get(firm,{}).get('examples',{})|current.get(firm,{})
        grouped=defaultdict(list)
        for encoded in examples:
            raw=json.loads(encoded)
            if raw is not None:grouped[key(raw)].append(raw)
        for raw in EXTRAS.get(firm,()):
            if raw not in grouped[key(raw)]:grouped[key(raw)].append(raw)
        labels={}
        for k,aliases in sorted(grouped.items()):
            raw=min(aliases,key=lambda s:(len(s),s))
            normalized,rationale,listed=decision(firm,raw)
            evidence=[]
            if firm in DEFINITIONS:
                sha,n=DEFINITIONS[firm];meta=metadata(sha)
                page=next(p for p in meta['pages'] if p['page']==n)
                # Use a definition only if its native vocabulary actually names
                # this class. Commit-qualified labels cite the base definition.
                bases=sorted(DEFINITION_LABELS[firm],key=len,reverse=True)
                base=next((b for b in bases if k.startswith(key(b))),None)
                if base:
                    quote=page['text']
                    if firm=='iosiro':quote=re.search(r'\* \*\*Closed\*\*[^\n]+',quote)[0]
                    if firm=='dedaub':quote=re.search(r'Issue resolution includes[\s\S]+?auditors\.',quote)[0]
                    evidence.append(proof(docs[firm][sha],page,quote,'definition'))
                if firm=='oxorio' and k=='invalid':
                    evidence.append(proof(docs[firm][sha],page,page['text'],'native_legend_reference'))
            special=SPECIAL_EXAMPLES.get((firm,k))
            exemplar=examples.get(json.dumps(raw,ensure_ascii=False)) or next((examples[json.dumps(a,ensure_ascii=False)] for a in aliases if json.dumps(a,ensure_ascii=False) in examples),None)
            sha=special[0] if special else exemplar.get('sha256') if exemplar else None
            candidates=[]
            if sha and sha in docs[firm]:
                meta=metadata(sha)
                if meta:
                    pages=meta['pages']
                    if special:pages=[p for p in pages if p['page']==special[1]]
                    for page in pages:
                        patterns=[r'(?<!\w)'+re.escape(a)+r'(?!\w)' for a in aliases]
                        pattern='|'.join(patterns)
                        hits=list(re.finditer(pattern,page['text'],re.I))
                        if not hits and special:hits=[re.search(r'\S',page['text'])]
                        for hit in hits:
                            if not hit:continue
                            start=max(0,hit.start()-160);end=min(len(page['text']),hit.end()+320)
                            context=page['text'][start:end]
                            if special and firm=='abdk-consulting':context=page['text']
                            score=10*bool(re.search(r'Status|Resolution|Remediation|Client Comment|Team|Watson',context,re.I))
                            line_start=page['text'].rfind('\n',0,hit.start())+1
                            line_end=page['text'].find('\n',hit.end())
                            line_text=page['text'][line_start:line_end if line_end>=0 else len(page['text'])]
                            score+=30*bool(re.search(r'Status|Resolution|Remediation',line_text,re.I))
                            score-=50*bool(re.search(r'\b(?:should|could|recommend)\b',line_text,re.I))
                            if special:score+=100
                            candidates.append((score,page,context))
            # Newly extracted labels absent from the old vocabulary find their
            # own exact source assertion rather than borrowing another firm.
            if not candidates and not evidence:
                for sha,row in docs[firm].items():
                    meta=metadata(sha)
                    if not meta:continue
                    found=False
                    for page in meta['pages']:
                        m=re.search(r'(?<!\w)'+re.escape(raw)+r'(?!\w)',page['text'],re.I)
                        if m:
                            candidates.append((0,page,page['text'][max(0,m.start()-120):m.end()+250]))
                            found=True;break
                    if found:break
            if candidates:
                _,page,quote=max(candidates,key=lambda c:c[0])
                evidence.append(proof(docs[firm][sha],page,quote,'source_example'))
            if not evidence:
                listed=True; normalized='not_stated'
                rationale='Listed for review: no verbatim native assertion/definition was located for this inherited label.'
            labels[raw]={'normalized':normalized,'rationale':rationale,'evidence':evidence,
                         'observed_labels':sorted(set(aliases)),
                         'review_state':'listed_unresolved' if listed else 'mapped',
                         'definition_basis':'native_definition' if any(e['kind']=='definition' for e in evidence) else 'native_example_only' if evidence else 'not_located'}
        policy['publishers'][firm]={'eras':[{'id':'published-status-v1','default':True,
            'era_basis':'Native status vocabulary; no evidenced semantic cutover is assumed from filename/collection dates.',
            'labels':labels}]}
        if firm=='sigma-prime':
            # Legacy Closed can accompany either a fix or acknowledgement;
            # the later native legend gives Closed a precise no-action meaning.
            sha,n=SIGMA_MODERN_DEFINITION;meta=metadata(sha)
            page=next(p for p in meta['pages'] if p['page']==n)
            modern=json.loads(json.dumps(labels))
            closed=next(label for label in modern if key(label)=='closed')
            modern[closed]={'normalized':'acknowledged','rationale':'Sigma Prime explicitly defines Closed as acknowledged with no further action; Resolved separately requires mitigating updates.',
                'evidence':[proof(docs[firm][sha],page,page['text'],'definition')],
                'observed_labels':labels[closed]['observed_labels'],'review_state':'mapped','definition_basis':'native_definition'}
            shas=[]
            for docsha in docs[firm]:
                docmeta=metadata(docsha)
                if docmeta and re.search(SIGMA_DEFINITION_REGEX,re.sub(r'\s+',' ',' '.join(p['text'] for p in docmeta['pages'])),re.I):shas.append(docsha)
            policy['publishers'][firm]['eras'].insert(0,{'id':'defined-status-v2',
                'definition_regex':SIGMA_DEFINITION_REGEX,'document_sha256s':sorted(shas),
                'era_basis':'Source-native status definition, not an inferred date boundary. Legacy bare Closed remains listed because it covers multiple dispositions.',
                'labels':modern})
    from status_families import GENERIC_FALLBACK
    policy['generic_fallback'] = GENERIC_FALLBACK
    payload=json.dumps(policy,ensure_ascii=False,indent=2,sort_keys=True)+'\n'
    for suffix in ('yaml','json'):(ROOT/'schema'/('status_map.'+suffix)).write_text(payload)
    print(json.dumps({'publishers':len(policy['publishers']),'canonical_labels':sum(len(e['eras'][0]['labels']) for e in policy['publishers'].values())}))


if __name__=='__main__':main()
