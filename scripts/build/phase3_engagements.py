"""Reproducible metadata enrichment and conservative evidence-based identity grouping."""
from collections import defaultdict
from copy import deepcopy
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

from metadata_rules import (RULE_VERSION, RULES_SHA256, REPORT, atomic, canonical, clean, field,
                            normalize, parse_date, process_artifact, sha)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'phase3'))
import identity_rules as identity


def identity_url(url):
    u = urlsplit(url or '')
    path = unquote(u.path).rstrip('/')
    parts = path.strip('/').split('/')
    if u.netloc.lower() == 'raw.githubusercontent.com' and len(parts) >= 4:
        return 'github.com/' + '/'.join(parts[:2] + parts[3:])
    if u.netloc.lower() == 'github.com' and len(parts) >= 5 and parts[2] in {'blob', 'raw'}:
        return 'github.com/' + '/'.join(parts[:2] + parts[4:])
    return u.netloc.lower().removeprefix('www.') + path


def import_discovery(b):
    from build_db import uid, file_format
    represented = defaultdict(list)
    for doc in b.tables['documents'].values():
        if not doc['is_seed']:
            represented[(doc['publisher_id'], identity_url(doc['public_url']))].append(doc)
    for path in b.discovery_files:
        for raw, meta, ledger in b.rows(path, 'discovery:'+path.parent.name, 'discovery', 'reports'):
            publisher = raw.get('firm_id')
            attribution = raw.get('attribution_basis')
            if publisher in {'certik','hacken'} or publisher not in b.publishers or not attribution or not isinstance(attribution, dict) or not attribution.get('kind'):
                ledger['excluded_scope_rows'] += 1
                continue
            url = raw.get('candidate_url')
            if not url or urlsplit(url).scheme not in {'http', 'https'}:
                ledger['excluded_scope_rows'] += 1
                continue
            aliases = [url, raw.get('original_publisher_url')]
            aliases += [e.get('candidate_url') for e in raw.get('evidence', []) if isinstance(e, dict)]
            matches = {d['document_id']: d for u in aliases if u for d in represented.get((publisher, identity_url(u)), [])}
            if matches:
                for doc in matches.values():
                    doc['provenance'].setdefault('discovery_matches', []).append(dict(receipt=meta, source_row=raw))
                ledger['duplicate_rows'] += 1
                continue
            sid = uid('discovery', url)
            doc = b.document(raw, meta, publisher, sid, source_kind='aggregator', public_url=url,
                             url_kind='discovery', filename=Path(unquote(urlsplit(url).path)).name,
                             file_format=file_format(None, url), project=raw.get('project_hint'),
                             project_basis='catalog_unverified' if raw.get('project_hint') else None,
                             title=raw.get('title_hint'), doc_kind='unknown', counting_role='lead',
                             wayback_url=raw.get('wayback_url'),
                             provenance={'retained_record': meta, 'source_row': raw, 'source': 'discovery', 'attribution_basis': attribution},
                             notes=['Discovery evidence; original not acquired.'])
            if b.add('documents', doc['document_id'], doc, ledger):
                represented[(publisher, identity_url(url))].append(doc)
                value = raw.get('date_hint')
                if value:
                    b.claim({'document_id': doc['document_id']}, meta['source_tag'], 'discovery.date_hint', value,
                            'filename_hint' if raw.get('date_basis') == 'filename' else 'catalog',
                            basis='filename' if raw.get('date_basis') == 'filename' else 'catalog', authority='catalog_unverified',
                            evidence={'method': 'discovery_date_hint', 'confidence': .4, 'page': None,
                                      'source_field':'date_hint','raw_value':value,'source_date_basis':raw.get('date_basis'),
                                      'source_locator':meta.get('source_locator'),'candidate_url':url,
                                      'listing_url':raw.get('listing_url'),'source':raw.get('source')})


def fallback_project(doc, publishers):
    """Explicit source field first; clean a filename only as a labelled fallback."""
    value = doc.get('project')
    basis = doc.get('project_basis')
    from engagement_rules import generic_project
    if value and not generic_project(value) and basis in {'publisher_project', 'client_fallback', 'catalog_unverified'}:
        return field(value, basis, .9 if basis != 'catalog_unverified' else .5)
    filename = unquote(doc.get('filename') or '')
    base = Path(filename).name
    base = re.sub(r'\.(?:pdf|md|html?|txt)$', '', base, flags=re.I)
    if value and not generic_project(value) and doc.get('source_kind') in {'website', 'contest'}:
        base = value
        method, confidence = 'publisher_listing_hint', .75
    else:
        method, confidence = 'filename_fallback', .55
    base = base.replace('_', ' ')
    name = publishers[doc['publisher_id']]['name']
    aliases = [doc['publisher_id'].replace('-', ' '), name, 'ABDK', 'yAudit', 'Zenith' if doc['publisher_id']=='code4rena-zenith' else name]
    for alias in sorted(set(aliases), key=len, reverse=True):
        pattern=r'[ _-]+'.join(re.escape(part) for part in re.split(r'[ _-]+',alias))
        base = re.sub(r'(?<!\w)' + pattern + r'(?!\w)', '', base, flags=re.I)
    base = re.sub(r'(?<!\d)20\d{2}[- _./]\d{1,2}(?:[- _./]\d{1,2})?(?!\d)', '', base)
    base = re.sub(r'(?<!\d)20\d{2}(?!\d)', '', base)
    base = re.sub(r'\b(?:smart[- ]contract[- ]|security[- ])?(?:audit|review|assessment|analysis)(?:[- ]report)?\b|\b(?:final|draft|public report|executive summary|report|non disclosed|signed|en-us|en|cn|zh)\b', '', base, flags=re.I)
    base = re.sub(r'(?:\bv(?:ersion)?\s*\d+(?:\.\d+)+|\brevision\s*\d+)\s*$', '', base, flags=re.I)
    base = clean(base).strip(' []()-,.')
    if len(base) < 2 or generic_project(base) or normalize(base) in {'readme', 'index', 'summary', 'report', 'review'}:
        return field()
    return field(base, method, confidence, evidence=filename)


def prose_project(value):
    """Reject report prose/severity definitions masquerading as client names."""
    s=clean(value)
    return bool(re.search(r'\b(?:the issue|severity|risk)\b.{0,90}\b(?:puts|users|subset|likelihood|impact|means|represents)\b|\b(?:was|were|has been|have been)\s+(?:reviewed|audited|conducted|performed|commissioned)|\b(?:contracts?|code|team)\b.{0,60}\b(?:reviewed|audited|commissioned|engaged)\b',s,re.I))


def pin_artifact_text(root, digest, meta, replay=None):
    """Preserve the exact text versions behind receipts during shared-cache writes."""
    versions={}
    for key in ['text_receipt','date_text_receipt']:
        receipt=meta.get(key,{})
        text_hash=receipt.get('text_sha256')
        if not text_hash: continue
        source=receipt.get('source','local-cache/text')
        if source not in {'local-cache/text','local-cache/fulltext','local-cache/date-text'}:
            raise ValueError('Unsupported text receipt source')
        relative=Path('local-cache/phase3d/text')/(text_hash+'.txt')
        target=root/relative
        if target.exists():
            text=target.read_text()
            if sha(text.encode())!=text_hash: raise ValueError('Pinned text hash mismatch')
        else:
            original=root/source/(digest+'.txt')
            if not original.exists(): return False
            text=original.read_text()
            if sha(text.encode())!=text_hash: return False
            atomic(target,text)
        receipt['text_snapshot']=relative.as_posix()
        versions[text_hash]=relative.as_posix()
        if replay:
            dest=replay/source/(digest+'.txt')
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_text(text)
            if source=='local-cache/text':
                dest.with_suffix('.receipt.json').write_text(canonical(receipt)+'\n')
            else:
                info=dict(method=receipt.get('method'),text_sha256=text_hash,status=receipt.get('status'),
                          file_format='pdf' if isinstance(receipt.get('pages'),list) else None,
                          html_metadata_dates=receipt.get('html_metadata_dates',[]))
                dest.with_suffix('.pages.json').write_text(canonical(info)+'\n')
    for claim in meta['dates']:
        for assertion in [claim,claim.get('year_anchor')]:
            if assertion and assertion.get('text_sha256') in versions:
                assertion['text_snapshot']=versions[assertion['text_sha256']]
    return True


def pinned_text(root,meta,complete=False):
    key='date_text_receipt' if complete and meta.get('date_text_receipt',{}).get('text_snapshot') else 'text_receipt'
    receipt=meta.get(key,{})
    path=receipt.get('text_snapshot')
    return ((root/path).read_text() if path else ''),receipt


def reject_software_advisory_dates(claims,sources):
    """Revalidate cached proposals before they can authorize an audit year.

    Dependency-scanner output repeats Date fields and can look like page
    furniture. Its Crate/Package, Version and Title record dates the advisory,
    not the enclosing report. Reject dependent year anchors as well.
    """
    payloads={info.get('text_sha256') or sha(text.encode()):text for text,info in sources}
    for claim in claims:
        if claim['role'] not in {'audit_completion','report_issue'} or claim['confidence']<.8:continue
        for assertion in [claim,claim.get('year_anchor')]:
            if not assertion:continue
            text=payloads.get(assertion.get('text_sha256'))
            start,end=assertion.get('text_start'),assertion.get('text_end')
            if text is None or not isinstance(start,int) or not isinstance(end,int):continue
            quote=text[start:end];before=text[max(0,start-350):start].replace('\f','\n')
            advisory=(re.search(r'(?im)^\s*(?:Crate|Package)\s*:',before)
                      and re.search(r'(?im)^\s*Version\s*:',before)
                      and re.search(r'(?im)^\s*(?:Title|Warning)\s*:',before)
                      and re.search(r'(?im)^\s*Date\s*:',quote))
            if advisory:
                claim.setdefault('original_role',claim['role'])
                claim.update(role='other',confidence=.4,resolution='software_advisory_is_not_report_date',
                             builder_date_guard='date_evidence_non_report_date_fields_v1')
                break
    return claims


def source_year_claims(root,doc,meta):
    """Retain explicitly stated year-only periods/cover fields at year precision."""
    from metadata_rules import read_text
    from date_rules import load_date_text, HISTORY, PUBLICATION, RETEST
    text,receipt=read_text(root,doc)
    current={(c['date_value'],c['role']) for c in meta['dates']}
    has_completion=any(c['date_value'] and c['role']=='audit_completion' and c['confidence']>=.8 for c in meta['dates'])
    complete,full_receipt=(text,receipt) if has_completion else load_date_text(root,doc['sha256'],text,receipt)
    patterns=[(r'(?im)^\s*date\s*[:|]\s*(20\d{2})\s*$',text.split('\f')[0],receipt,'report_issue','explicit_year_cover_field')]
    if not has_completion:
        patterns.append((r'(?i)\b(?:audit|review|assessment)\s+(?:(?:was|were)\s+)?(?:performed|conducted|completed)\s+(?:in|during)\s+(20\d{2})(?:\s*/\s*Q[1-4])?\b',complete[:16000],full_receipt,'audit_completion','explicit_year_audit_period'))
    for pattern,payload,info,role,method in patterns:
        for m in re.finditer(pattern,payload):
            value,precision=parse_date(m[1])
            if not value or (value,role) in current: continue
            start=payload.rfind('\n',0,m.start())+1
            end=payload.find('\n',m.end());end=end if end>=0 else len(payload)
            before=payload.rfind('\n',0,max(0,start-1))+1
            quote=payload[before:end]
            if HISTORY.search(quote) or PUBLICATION.search(quote) or RETEST.search(quote) or re.search(r'https?://|signature|signed\s+by|scheduled|planned|proposed',quote,re.I): continue
            meta['dates'].append(dict(raw_value=m[1],date_value=value,precision=precision,role=role,basis='document_text',method=method,confidence=.94,
                                      evidence=quote,text_start=before,text_end=end,text_sha256=info.get('text_sha256') or sha(payload.encode()),
                                      text_source=info.get('source','local-cache/text'),page=payload[:before].count('\f')+1 if isinstance(info.get('pages'),list) else None))
            current.add((value,role))
    if not has_completion:
        from metadata_rules import SHORT_PERIOD, DATE
        payload=complete[:16000]
        # A wrapped "assessment was conducted\nbetween ..." sentence can
        # separate its semantic label from both endpoints. Parse the bounded
        # original span, without joining or rewriting the evidence text.
        prefix=r'\b(?:audit|assessment|review)\b[^\n]{0,140}\b(?:conducted|performed|undertaken)\s*\n\s*(?:between|from|over)\s+'
        for m in re.finditer(prefix,payload,re.I):
            window=payload[m.end():m.end()+300]
            short=SHORT_PERIOD.search(window)
            endpoints=[]
            if short and short.start()<35:
                endpoints=[(short[0],f'{short[1]} {short[2]} {short[5]}','audit_start'),(short[0],f'{short[3] or short[1]} {short[4]} {short[5]}','audit_completion')]
                end=m.end()+short.end()
            else:
                dates=list(DATE.finditer(window))
                if len(dates)<2 or dates[0].start()>35: continue
                separator=window[dates[0].end():dates[1].start()].strip(' \t\r\n,;')
                if not re.fullmatch(r'to|and|through|until|[-–—]',separator,re.I): continue
                endpoints=[(dates[0][0],dates[0][0],'audit_start'),(dates[1][0],dates[1][0],'audit_completion')]
                end=m.end()+dates[1].end()
            start=payload.rfind('\n',0,m.start())+1
            quote=payload[start:end]
            if HISTORY.search(quote) or PUBLICATION.search(quote) or RETEST.search(quote) or re.search(r'mitigation\s+review|https?://',quote,re.I): continue
            for raw,parsed,role in endpoints:
                value,precision=parse_date(parsed)
                if not value or (value,role) in current: continue
                meta['dates'].append(dict(raw_value=raw,date_value=value,precision=precision,role=role,basis='document_text',method='wrapped_explicit_audit_period',confidence=.96,
                                          evidence=quote,text_start=start,text_end=end,text_sha256=full_receipt.get('text_sha256') or sha(complete.encode()),
                                          text_source=full_receipt.get('source','local-cache/text'),page=payload[:start].count('\f')+1 if isinstance(full_receipt.get('pages'),list) else None))
                current.add((value,role))


def enrich(b):
    from build_db import uid
    from date_rules import load_date_text
    from metadata_rules import read_text
    proposed = defaultdict(list)
    llm_path = b.root/'data/phase3/llm_dates.jsonl'
    if llm_path.exists():
        held_path=b.root/'data/holdout/gold_sha256.txt'
        if not held_path.exists():
            raise ValueError('LLM date import requires the holdout boundary')
        held={s.strip() for s in held_path.read_text().splitlines() if s.strip() and not s.startswith('#')}
        if not held:
            raise ValueError('LLM date import requires a nonempty holdout boundary')
        for line in llm_path.read_text().split('\n'):
            if line.strip():
                claim=json.loads(line)
                if claim['sha256'] in held:
                    raise ValueError('LLM date claim targets a held-out original')
                proposed[claim['sha256']].append(claim)
    artifact_path = b.root/'data/phase3/artifact_metadata.jsonl'
    artifacts = {}
    alias_cache = {}
    if artifact_path.exists():
        for line in artifact_path.read_text().split('\n'):
            if line.strip():
                meta = json.loads(line)
                if meta.get('rule_version') == RULE_VERSION and meta.get('rules_sha256') == RULES_SHA256:
                    text_path=b.root/'local-cache/text'/(meta['sha256']+'.txt')
                    if text_path.exists() and sha(text_path.read_bytes())==meta.get('text_receipt',{}).get('text_sha256'):
                        full=b.root/'local-cache/fulltext'/(meta['sha256']+'.txt')
                        ocr=b.root/'local-cache/date-text'/(meta['sha256']+'.txt')
                        dr=meta.get('date_text_receipt',{})
                        current=ocr if ocr.exists() else full
                        if dr.get('source') in {'local-cache/fulltext','local-cache/date-text'}:
                            if not current.exists() or sha(current.read_bytes())!=dr.get('text_sha256'):
                                continue
                        elif current.exists():
                            continue
                        if pin_artifact_text(b.root,meta['sha256'],meta,getattr(b,'snapshot_inputs',None)):
                            artifacts[meta['sha256']] = meta
    docs = b.tables['documents']
    processed=0
    for doc in sorted(docs.values(), key=lambda d:(d['source_family']!='collected', d['document_id'])):
        if doc['is_seed']:
            continue
        processed+=1
        if processed%1000==0:
            print(f'Phase 3: enriched {processed} non-seed occurrences',file=sys.stderr,flush=True)
        digest = doc['sha256']
        if digest and digest not in artifacts:
            for attempt in range(3):
                _, candidate = process_artifact((b.root, doc))
                candidate['sha256']=digest
                if pin_artifact_text(b.root,digest,candidate,getattr(b,'snapshot_inputs',None)):
                    artifacts[digest]=candidate
                    break
            else: raise ValueError('Text cache changed repeatedly during extraction: '+digest)
        meta = deepcopy(artifacts[digest]) if digest else process_artifact((b.root, doc))[1]
        from engagement_rules import auditor
        if doc['publisher_id'] in {'movebit','scalebit','chainlight','theori','spearbit','cantina','abdk-consulting','consensys-diligence'}:
            text,_=pinned_text(b.root,meta,complete=True)
            attribution=auditor(text,doc['publisher_id'])
            if attribution and attribution['value'] in b.publishers:
                meta['auditor_attribution']=attribution
                if attribution['value']!=doc['publisher_id']:
                    doc['provenance']['phase3c_collected_publisher_id']=doc['publisher_id']
                    doc['publisher_id']=attribution['value']
        # Source-explicit fix-review headings are stronger than a collector's
        # broad audit_report default. Findings in the original audit do not suffice.
        labels=' '.join(str(s or '') for s in [doc['filename'],meta['report_title']['value']]).replace('_',' ')
        fix_heading=bool(re.search(r'\b(?:fix(?:es)?[- _]*(?:review|verification)|re[- _]?test|remediation[- _]*review|mitigation[- _]*(?:review|report))\b',labels,re.I))
        combined=bool(re.search(r'(?:audit|(?:security\s+)?assessment|security\s+review)\s*(?:and|&|\+)\s*(?:fix|mitigation)',labels,re.I))
        if fix_heading and combined:
            if doc['doc_kind']=='fix_review':
                doc['provenance']['phase3c_collected_doc_kind']='fix_review'
            doc['doc_kind']='audit_report'
            meta['document_kind']=field('audit_report','combined_initial_assessment_and_fix_review',.95,evidence=labels)
        elif fix_heading:
            doc['provenance']['phase3c_collected_doc_kind']=doc['doc_kind']
            doc['doc_kind']='fix_review'
            meta['document_kind']=field('fix_review','explicit_fix_review_heading',.95,evidence=labels)
        elif doc['doc_kind']=='fix_review' and meta['audit_type']['value']:
            # A full initial report can contain a fix-review appendix. A
            # collector's body-keyword default must not discard the whole audit.
            native,_=pinned_text(b.root,meta)
            cover=native.split('\f')[0] if doc['file_format']=='pdf' else meta['report_title']['value'] or native[:500]
            if not re.search(r'fix(?:es)?\s+(?:review|verification)|remediation\s+review|\bretest\b',cover,re.I) and re.search(r'(?:project|audit|review)\s+scope|detailed\s+findings|summary\s+of\s+findings',native,re.I):
                doc['provenance']['phase3c_collected_doc_kind']='fix_review'
                doc['doc_kind']='audit_report'
                meta['document_kind']=field('audit_report','initial_report_with_fix_appendix',.9,evidence=cover[:500])
        if proposed.get(digest):
            text,receipt=pinned_text(b.root,meta,complete=True)
            for claim in proposed[digest]:
                evidence=claim.get('evidence')
                if (claim.get('method')!='llm' or claim.get('model')!='gpt-6-luna' or
                    not isinstance(evidence,str) or not evidence.strip() or evidence not in text or
                    claim.get('text_sha256')!=sha(text.encode()) or
                    not claim.get('date_value') or claim['date_value'][:4] not in evidence or
                    parse_date(claim['date_value'])!=(claim['date_value'],claim.get('precision')) or
                    claim.get('role') not in {'audit_completion','report_issue','publication','other'}):
                    raise ValueError('Invalid or stale LLM date evidence: '+str(digest))
                meta['dates'].append({k:v for k,v in claim.items() if k!='sha256'})
        if not meta.get('source_periods_resolved'):
            source_year_claims(b.root,doc,meta)
        if not meta.get('structured_report') and (proposed.get(digest) or not meta.get('source_periods_resolved')):
            from period_rules import reconcile_source_periods
            opening,opening_receipt=pinned_text(b.root,meta)
            complete,complete_receipt=pinned_text(b.root,meta,complete=True)
            sources=[(opening,opening_receipt)]
            if complete_receipt.get('text_sha256')!=opening_receipt.get('text_sha256'):
                sources.append((complete,complete_receipt))
            reconcile_source_periods(meta['dates'],sources)
        if digest:
            pin_artifact_text(b.root,digest,meta)
        # Cached metadata is a proposal, not authority to promote dependency
        # advisory dates or anchors. Apply this guard on every build/cache hit.
        opening,opening_info=pinned_text(b.root,meta)
        complete,complete_info=pinned_text(b.root,meta,complete=True)
        reject_software_advisory_dates(meta['dates'],[(opening,opening_info),(complete,complete_info)])
        auditor_names={normalize(doc['publisher_id']),normalize(b.publishers[doc['publisher_id']]['name'])}
        if prose_project(meta['client']['value']):
            meta['client_rejection']=field(meta['client']['value'],'prose_or_severity_definition_not_client',1,evidence=meta['client'].get('evidence'))
            meta['client']=field()
        if normalize(meta['client']['value']) in auditor_names or (meta['client']['method']=='named_report_title' and re.match(r'about\b|introduction\b|methodology\b|(?:a|the)\s+(?:security|smart\s+contract|code)\b|^(?:pre|post|initial|final|draft|public|private)$|^\d+(?:\.\d+)*\.?$',meta['client']['value'] or '',re.I)):
            meta['client']=field()
        opening,_=pinned_text(b.root,meta)
        complete,_=pinned_text(b.root,meta,complete=True)
        meta['client']=identity.source_client(opening,meta['client'],
            [doc['publisher_id'],b.publishers[doc['publisher_id']]['name']]) or field()
        project = meta['client'] if meta['client']['value'] else fallback_project(doc, b.publishers)
        if prose_project(project['value']):
            meta['client_rejection']=field(project['value'],'prose_or_severity_definition_not_client',1,evidence=project.get('evidence'))
            project=fallback_project({**doc,'project':None},b.publishers)
        meta['client'] = project
        alias_key=(digest,doc['file_format'])
        if alias_key not in alias_cache:
            alias_cache[alias_key]=identity.report_aliases(b.root,doc)
        meta['project_identity']=identity.evidence(complete or opening,doc,meta,alias_cache[alias_key])
        if meta['project_identity']['mitigation_only']:
            doc['provenance'].setdefault('phase3c_collected_doc_kind',doc['doc_kind'])
            doc['doc_kind']='fix_review'
            meta['document_kind']=field('fix_review','source_explicit_mitigation_only',.99,
                evidence=meta['project_identity']['mitigation_only'])
        if not meta['report_title']['value']:
            meta['report_title'] = field(doc['title'] or doc['filename'], 'source_title_hint', .6) if doc['title'] or doc['filename'] else field()
        if not meta['audit_type']['value'] and doc['doc_kind'] not in {'unknown', 'non_report'}:
            meta['audit_type'] = field(doc['doc_kind'], 'collector_document_kind', .7)
        # Page attribution is known only for PDF page-delimited cache receipts.
        meta['firm'] = field(doc['publisher_id'], 'scope_registry_and_source_attribution', .95,
                             evidence=doc['provenance'].get('attribution_basis') or doc['source_tag'])
        doc['metadata'] = meta
        # Preserve native archive export columns for Phase 1 reconciliation.
        if doc['source_family'] != 'firm_export':
            if project['value']:
                doc['project'] = project['value']
            doc['title'] = meta['report_title']['value']
            doc['chains'] = meta['chains']['value']
            doc['languages'] = meta['languages']['value']
            for key in ['project','title','chains','languages']:
                if doc[key] is not None:
                    doc['field_state'].pop(key,None)
        for i, claim in enumerate(meta['dates']):
            if claim.get('text_start') is not None and claim.get('page') is None and doc['file_format']!='pdf':
                claim.update(page=1,page_kind='logical')
            b.claim({'document_id': doc['document_id']}, doc['source_tag'], f'phase3.date[{i}]',
                    claim['date_value'] or claim['raw_value'], claim['role'], basis=claim['basis'],
                    authority='publisher' if claim['confidence'] >= .8 else 'inherited_unverified',
                    evidence={**claim,'text_sha256':claim.get('text_sha256') or meta['text_receipt'].get('text_sha256'),'rule_version':RULE_VERSION,'rules_sha256':RULES_SHA256})
            saved = b.tables['date_claims'][uid('date', {'document_id':doc['document_id']}, doc['source_tag'], f'phase3.date[{i}]')]
            saved.update(raw_value=claim['raw_value'], date_value=claim['date_value'], precision=claim['precision'],
                         eligible_for_audit_year=bool(claim['date_value'] and claim['role'] in {'audit_completion','report_issue'} and claim['confidence']>=.8))
    # Intrinsic results include all unique collected hashes, independent of occurrence count.
    if any(d['source_family']=='collected' and artifacts.get(d['sha256'], {}).get('text_receipt', {}).get('status')=='ok' for d in docs.values()):
        atomic(artifact_path, ''.join(canonical({'sha256': h, **m})+'\n' for h,m in sorted(artifacts.items())))
    for finding in b.tables['findings'].values():
        if finding['document_id'] and not finding['is_seed']:
            doc=docs[finding['document_id']]
            if finding['publisher_id']!=doc['publisher_id']:
                finding['publisher_id']=doc['publisher_id']
                try:
                    from build_db import publisher_severity_mapping
                except ImportError:
                    continue  # Article-v1 uses the same buckets for every publisher.
                raw,normalized=finding['severity_raw'],finding['severity_source_normalized']
                mapping=publisher_severity_mapping(raw if raw is not None else normalized,doc['publisher_id'],kind=finding['record_kind'],sha256=doc['sha256'])
                mapping.update(raw=raw,source_normalized=normalized,basis='source_normalized_only' if raw is None and normalized is not None else 'publisher_raw_label')
                finding.update(severity=mapping['normalized'],severity_mapping=mapping)
    # This also covers orphan reviews, which have no engagement link later.
    for claim in b.tables['date_claims'].values():
        doc=docs.get(claim['document_id'])
        if doc and doc['doc_kind']=='fix_review' and claim['role'] in {'audit_start','audit_completion','report_issue'}:
            claim['evidence']['phase3c_original_role']=claim['role']
            claim.update(role='retest',eligible_for_audit_year=False)


class Groups:
    def __init__(self, keys):
        self.parent = {k:k for k in keys}

    def find(self, key):
        while self.parent[key] != key:
            self.parent[key] = self.parent[self.parent[key]]
            key = self.parent[key]
        return key

    def union(self, a, b):
        a, b = self.find(a), self.find(b)
        self.parent[max(a,b)] = min(a,b)


def stem(doc):
    text = Path(unquote(doc.get('filename') or urlsplit(doc['public_url']).path)).name
    text = re.sub(r'\.(?:pdf|md|html?|txt)$', '', text, flags=re.I)
    text = re.sub(r'(?i)(?:[\s_-]+|\()(?:final|draft|revised|revision|fix[- _]?review|remediation|en[-_]us|english|chinese|zh[-_]cn|en|cn|zh)(?:\)|$|[\s_-])', ' ', text)
    text = re.sub(r'(?i)(?:[\s_-]+|\()v?\d+(?:[._]\d+){1,3}\)?$', '', text)
    text = re.sub(r'(?i)(?<!\w)'+re.escape(doc['publisher_id']).replace(r'\-',r'[ _-]+')+r'(?!\w)', ' ', text)
    text = text.replace('_',' ').replace('-',' ')
    text = re.sub(r'(?i)\b(?:smart contracts? |security )?(?:audit|review|assessment)(?: report)?\b|\breport\b', ' ', text)
    return normalize(text)


def rendering_pair(a,b):
    """A complete publisher basename plus substantive content bridges layouts."""
    ma, mb = a['metadata'], b['metadata']
    ca, cb = set(ma['commits']['value'] or []), set(mb['commits']['value'] or [])
    if ca and cb and not ca&cb: return False
    # A publisher's complete PDF/Markdown basename identifies a rendering even
    # when one format omits the cover or spells the client differently. Require
    # independent substantive text and preserve conflicting initial endpoints.
    raw_a=normalize(re.sub(r'\.(?:pdf|md|html?)$','',Path(a.get('filename') or '').name,flags=re.I))
    raw_b=normalize(re.sub(r'\.(?:pdf|md|html?)$','',Path(b.get('filename') or '').name,flags=re.I))
    if a['file_format']!=b['file_format'] and len(raw_a)>=12 and raw_a==raw_b and len(re.sub(r'\d','',stem(a)))>=4:
        la,lb=(set(m.get('report_content',{}).get('lines',[])) for m in [ma,mb])
        ea,eb=({c['date_value'] for c in m['dates'] if c['date_value'] and c['role']=='audit_completion'} for m in [ma,mb])
        conflict=ea and eb and not any(x.startswith(y) or y.startswith(x) for x in ea for y in eb)
        if len(la&lb)>=5 and not conflict:
            return True
    return False


def compatible(a, b):
    """A filename match needs independent temporal/scope support."""
    ma, mb = a['metadata'], b['metadata']
    ia,ib=(set(m.get('source_relationships',{}).get('report_ids',[])) for m in [ma,mb])
    if ia and ib and not ia&ib: return False
    ca, cb = set(ma['commits']['value'] or []), set(mb['commits']['value'] or [])
    if ca and cb:
        return bool(ca & cb)
    if rendering_pair(a,b): return True
    da = {c['date_value'][:7] for c in ma['dates'] if c['date_value'] and c['role'] in {'audit_completion', 'report_issue'}}
    db = {c['date_value'][:7] for c in mb['dates'] if c['date_value'] and c['role'] in {'audit_completion', 'report_issue'}}
    if da and db:
        return bool(da & db)
    # Explicit rendering pairs share the complete basename and project, not merely client.
    raw_a=normalize(re.sub(r'\.(?:pdf|md|html?)$','',Path(a.get('filename') or '').name,flags=re.I))
    raw_b=normalize(re.sub(r'\.(?:pdf|md|html?)$','',Path(b.get('filename') or '').name,flags=re.I))
    return (a['file_format'] != b['file_format'] and len(raw_a)>=12 and raw_a==raw_b
            and bool(ma['client']['value']) and normalize(ma['client']['value']) == normalize(mb['client']['value']))


def same_content(a,b):
    """Require substantive content AND audited scope, never client/date alone."""
    ma,mb=a['metadata'],b['metadata']
    ia,ib=(set(m.get('source_relationships',{}).get('report_ids',[])) for m in [ma,mb])
    if ia and ib and not ia&ib: return False
    ca,cb=set(ma['commits']['value'] or []),set(mb['commits']['value'] or [])
    if ca and cb and not ca&cb: return False
    ra,rb=ma.get('report_content',{}),mb.get('report_content',{})
    la,lb=set(ra.get('lines',[])),set(rb.get('lines',[]))
    # Shared generic section headings are template evidence, not findings.
    finding_heading=lambda h: bool(re.match(r'(?:[chmlig]|critical|high|medium|low|info|gas)\d{1,3}[a-z]',h))
    ha,hb=({h for h in r.get('headings',[]) if finding_heading(h)} for r in [ra,rb])
    common=len(la&lb)
    containment=common/max(1,min(len(la),len(lb)))
    from engagement_rules import generic_project
    client=ma['client']['value']
    repositories=lambda m: {u.split('/tree/')[0].split('/commit/')[0].rstrip('/') for u in m['repositories']['value'] or []
                            if not re.search(r'/(?:audits?|reports?|publications|public[-_]audits)(?:/|$)',u,re.I)}
    scope=bool(ca&cb) or bool(repositories(ma)&repositories(mb)) or (not generic_project(client) and normalize(client)==normalize(mb['client']['value']))
    if not scope: return False
    # Exact complete substantive text is a rendering, regardless of host/path.
    if ra.get('complete_sha256') and ra.get('complete_sha256')==rb.get('complete_sha256'): return True
    ends=lambda m: {c['date_value'] for c in m['dates'] if c['date_value'] and c['role']=='audit_completion'}
    da,db=ends(ma),ends(mb)
    if da and db and not any(x.startswith(y) or y.startswith(x) for x in da for y in db): return False
    # Revisions need largely identical report content, plus specific headings or
    # a matching audited commit. A repeated disclaimer cannot satisfy this rule.
    return common>=12 and containment>=.88 and (bool(ca&cb) or (len(ha&hb)>=3 and len(ha&hb)/max(1,min(len(ha),len(hb)))>=.9))


def parent_scope_commits(doc):
    """Only source-labelled non-remediation hash evidence can infer a parent."""
    meta=doc['metadata']['commits']
    supported=set()
    for evidence in meta.get('evidence') or []:
        line=evidence.get('text','') if isinstance(evidence,dict) else ''
        if re.search(r'fixed|resolved|patch|remediation|previous|prior',line,re.I): continue
        if re.search(r'commit|hash|revision',line,re.I):
            supported.update(re.findall(r'\b[a-f0-9]{40}\b',line,re.I))
    return supported & set(meta['value'] or [])


def versioned_fix_scope(doc):
    """A named version/component from an explicit fix-review heading."""
    title=doc['metadata']['report_title']['value'] or ''
    if not re.search(r'fix(?:es)?\s+review',title,re.I): return None
    title=re.sub(r'fix(?:es)?\s+review.*$','',title,flags=re.I).strip(' -–—:')
    return normalize(title) if re.search(r'\bv\d+(?:\.\d+)*\b',title,re.I) else None


def scope_repositories(root,doc):
    """Source-labelled scope references; ordinary findings/patch links do not qualify."""
    from metadata_rules import read_text
    from date_rules import load_date_text
    text,receipt=read_text(root,doc)
    text,receipt=load_date_text(root,doc['sha256'],text,receipt)
    refs=set()
    for m in re.finditer(r'(?im)^.*\b(?:repositories|repository|codebase|repo|scope)\b[^\n]*(?:\n[^\n]*){0,2}',text[:24000]):
        if re.search(r'fixed|patch|remediation|references',m[0],re.I): continue
        refs.update(re.findall(r'https?://(?:github\.com|gitlab\.com)/[\w.-]+/[\w.-]+',m[0]))
    return refs


def report_stage_dates(b):
    """Initial/final report timeline rows are explicit issue revisions.

    They can supersede an old cover dateline; client response and public-release
    rows keep their separate semantics. This never selects an audit endpoint.
    """
    from date_rules import HISTORY, PUBLICATION, RETEST
    from metadata_rules import DATE
    for claim in b.tables['date_claims'].values():
        doc=b.tables['documents'].get(claim['document_id'])
        if not doc or doc['is_seed'] or doc['doc_kind']=='fix_review' or not claim['date_value'] or claim['basis']!='document_text': continue
        assertion=claim['evidence'].get('assertion') or {}
        quote=assertion.get('evidence')
        if not isinstance(quote,str) or HISTORY.search(quote) or PUBLICATION.search(quote) or RETEST.search(quote): continue
        for line in quote.splitlines():
            stage=re.match(r'^[\s|*#]*(?:initial|draft|final|revised)\s+(?:audit\s+|security\s+assessment\s+)?report\s*[:|]?\s+(.+)$',line,re.I)
            if not stage: continue
            date=DATE.search(stage[1])
            if not date or parse_date(date[0])[0]!=claim['date_value']: continue
            claim['evidence'].setdefault('phase3c_original_role',claim['role'])
            assertion.setdefault('extraction_method',assertion.get('method'))
            assertion.update(method='report_revision_stage_timeline',role='report_issue',confidence=.97)
            claim.update(role='report_issue',authority='publisher',eligible_for_audit_year=True)
            break


def contest_review_relations(b):
    """Official mitigation formats and parent IDs are relationship/date evidence."""
    docs=b.tables['documents'];contests=b.tables['contests']
    by_id={(c['publisher_id'],c['platform_contest_id']):c for c in contests.values()}
    initial_docs={c['document_id'] for c in contests.values() if c['format']!='mitigation' and c['document_id']}
    initial_hashes={(docs[did]['publisher_id'],docs[did]['sha256']) for did in initial_docs if docs[did]['sha256']}
    mitigation_ids=set();edges=[]
    for c in contests.values():
        if c['format']!='mitigation': continue
        mitigation_ids.add(c['contest_id'])
        raw=c['provenance']['source_row']
        parent_id=raw.get('parent_contest_id') or raw.get('mitigation_of')
        parent=by_id.get((c['publisher_id'],str(parent_id))) if isinstance(parent_id,(str,int)) else None
        did=c['document_id']
        if not did: continue
        doc=docs[did]
        doc['metadata'].setdefault('mitigation_relationships',[]).append(dict(contest_id=c['contest_id'],parent_contest_id=parent['contest_id'] if parent else None,basis='official_contest_parent_field',report_relation=raw.get('report_relation')))
        # Some official mitigation listings link the original report with an
        # appended mitigation section. Never relabel that whole artifact a fix.
        combined=(did in initial_docs or (doc['publisher_id'],doc['sha256']) in initial_hashes or raw.get('report_relation')=='mitigation_appendix')
        if not combined:
            doc['provenance'].setdefault('phase3c_collected_doc_kind',doc['doc_kind'])
            doc['doc_kind']='fix_review'
            doc['metadata']['document_kind']=field('fix_review','official_mitigation_format',.99,evidence={'contest_id':c['contest_id'],'parent_contest_id':parent_id})
        elif doc['doc_kind']=='fix_review':
            doc['provenance'].setdefault('phase3c_collected_doc_kind','fix_review')
            doc['doc_kind']='contest_report'
            doc['metadata']['document_kind']=field('contest_report','initial_report_with_mitigation_appendix',.99,evidence={'contest_id':c['contest_id'],'parent_contest_id':parent_id})
        if parent and parent['document_id']:
            edges.append((did,parent['document_id']))
    for claim in b.tables['date_claims'].values():
        assertion=claim['evidence'].get('assertion') or {}
        if assertion.get('contest_id') in mitigation_ids:
            claim['evidence']['phase3c_original_role']=claim['role']
            claim.update(role='retest',eligible_for_audit_year=False)
    return edges


def exclusion_reason(doc):
    if doc['is_seed']:
        return 'legacy_seed_not_acquired'
    source=doc.get('provenance',{}).get('source_row',{})
    if source.get('firm_id')=='certik' and source.get('doc_kind')=='unknown':
        return 'unvalidated_public_copy'
    kind=doc['metadata'].get('content_kind',{}).get('value')
    if kind not in {None,'report','unknown'}:
        return 'source_content_'+kind
    if doc['doc_kind'] == 'non_report':
        return 'collector_classified_non_report'
    if re.search(r'\.(?:js|css|json|png|jpg|zip)$', doc.get('filename') or '', re.I) and not doc['metadata'].get('structured_report'):
        return 'application_asset_not_report'
    if doc['metadata']['text_receipt'].get('status') in {'original_hash_mismatch', 'invalid_local_path'}:
        return 'invalid_original_evidence'
    if doc['source_family'] == 'discovery':
        # Recorded attribution supports a separate provisional engagement, not a confirmed original.
        return None
    if doc['doc_kind'] == 'unknown' and not doc['metadata']['audit_type']['value']:
        return 'unclassified_document_without_report_evidence'
    return None


def group_scope_reports(b, registry):
    """Apply the corpus engagement definition to resolved report identities.

    Rendering identity remains a separate, retained partition. A fix-review
    attachment never supplies a client, scope, program or completion date for
    this step; it remains a separately identified supporting report artifact.
    """
    import engagement_grouping_rules as scope
    engagements=b.tables['engagements']
    links=b.tables['engagement_documents']
    docs=b.tables['documents']
    by_doc={link['document_id']:link['engagement_id'] for link in links.values()}
    members=defaultdict(list)
    claims=defaultdict(list)
    contests=defaultdict(list)
    for did,eid in by_doc.items():members[eid].append(docs[did])
    for c in b.tables['date_claims'].values():
        eid=c['engagement_id'] or by_doc.get(c['document_id'])
        if eid in engagements and (not c['document_id'] or docs[c['document_id']]['doc_kind']!='fix_review'):
            claims[eid].append(c)
    for c in b.tables['contests'].values():
        contests[c['engagement_id']].append((c['platform_contest_id'],c['format'],str(c['start_utc']) if c['start_utc'] else None))
    profiles={eid:scope.profile(eid,members[eid],claims[eid],contests[eid]) for eid in engagements}
    for eid,p in profiles.items():
        if engagements[eid]['identity_status']!='confirmed':p['eligible']=False
    remap={}
    for group in scope.cluster(profiles.values()):
        target=min(group,key=lambda eid:(registry['birth'].get(eid,0),eid))
        remap.update({eid:target for eid in group})
        e=engagements[target]
        all_docs=sorted({d for eid in group for d in profiles[eid]['documents']})
        report_ids=sorted({r for eid in group for r in profiles[eid]['report_ids']})
        recovered=[row for eid in group for row in engagements[eid]['evidence'].get('date_recovery',[])]
        # Preserve one report identity per initial scope, even when it has PDF,
        # HTML, translation, edition and fix-review artifacts of its own.
        units=[dict(report_identity=eid,documents=profiles[eid]['documents'],
                    report_ids=profiles[eid]['report_ids']) for eid in sorted(group)]
        e['evidence'].update(documents=all_docs,report_ids=report_ids,report_count=len(report_ids),
            scope_report_count=len(units),scope_grouping=dict(version=scope.VERSION,rules_sha256=scope.RULES_SHA256,
            max_completion_span_days=scope.RULES['max_completion_span_days'],report_groups=units,
            client_family=profiles[target]['family'],program=profiles[target]['program']))
        if recovered:e['evidence']['date_recovery']=recovered
        if len(group)>1:
            e['evidence']['scope_grouping']['completion_dates']=sorted({profiles[eid]['date'] for eid in group})
            e['notes'].append('Component scope reports bundled by '+scope.VERSION+'; report identities and originals retained.')
            eligible=[c for eid in group for c in claims[eid] if c['eligible_for_audit_year']]
            role='audit_completion' if any(c['role']=='audit_completion' for c in eligible) else 'report_issue'
            preferred=[c for c in eligible if c['role']==role]
            values={c['date_value'] for c in preferred}
            value=next(iter(values)) if len(values)==1 else None
            e['evidence']['resolved_date']=dict(value=value,precision={4:'year',7:'month',10:'day'}.get(len(value or ''),'none'),
                role=role if preferred else None,conflict=len(values)>1,claim_ids=sorted(c['claim_id'] for c in preferred),
                policy='initial_completion_then_current_issue_v1')
        for eid in group:
            if eid!=target:
                registry['redirects'][eid]=target
                registry.setdefault('redirect_basis',{})[eid]='scope_reports_one_client_engagement_v1'
                b.tables['engagement_identity_crosswalk'][eid]=dict(previous_engagement_id=eid,engagement_id=target,
                    basis='scope_reports_one_client_engagement_v1')
                del engagements[eid]
    rebuilt={}
    for link in links.values():
        old=link['engagement_id']
        new=remap[old]
        link['engagement_id']=new
        if old!=new:
            link['evidence'].update(report_identity=old,report_identity_role=link['role'])
            link['role']='supporting'
        rebuilt[new,link['document_id']]=link
    b.tables['engagement_documents']=rebuilt
    for c in b.tables['date_claims'].values():
        if c['engagement_id'] in remap:c['engagement_id']=remap[c['engagement_id']]
    for c in b.tables['contests'].values():
        if c['engagement_id'] in remap:c['engagement_id']=remap[c['engagement_id']]
    for anchor,eid in registry['anchors'].items():
        if eid in remap:registry['anchors'][anchor]=remap[eid]
    for crosswalk in b.tables['engagement_identity_crosswalk'].values():
        crosswalk['engagement_id']=remap.get(crosswalk['engagement_id'],crosswalk['engagement_id'])
    # Recompute industry identity *after* publisher scope grouping. Shared
    # originals retain the cross-publisher deduplication used by the corpus.
    from build_db import uid
    industry=Groups(engagements)
    shared={}
    for link in sorted(rebuilt.values(),key=lambda r:r['document_id']):
        eid=link['engagement_id'];doc=docs[link['document_id']]
        if doc['sha256'] and engagements[eid]['identity_status']=='confirmed':
            if doc['sha256'] in shared:industry.union(eid,shared[doc['sha256']])
            shared[doc['sha256']]=eid
    for eid,e in engagements.items():
        if e['identity_status']=='confirmed':e['industry_engagement_id']=uid('industry',industry.find(eid))
    return remap


def enrich_and_group(b):
    from build_db import uid
    import_discovery(b)
    enrich(b)
    contest_parent_edges=contest_review_relations(b)
    docs = b.tables['documents']
    source_mitigation_edges=[]
    source_urls=defaultdict(list)
    source_routes=defaultdict(list)
    for did,doc in docs.items():
        if doc['is_seed']: continue
        source_urls[(doc['publisher_id'],identity_url(doc['public_url']))].append(did)
        for route in doc['metadata'].get('project_identity',{}).get('report_routes',[]):
            source_routes[(doc['publisher_id'],route)].append(did)
    for parent,doc in docs.items():
        for ref in doc['metadata'].get('project_identity',{}).get('mitigation_targets',[]):
            targets=set(source_urls.get((doc['publisher_id'],identity_url(ref['url'])),[]))
            for target in list(targets):
                for route in docs[target]['metadata'].get('project_identity',{}).get('report_routes',[]):
                    targets.update(source_routes[(doc['publisher_id'],route)])
            for target in sorted(targets-{parent}):
                review=docs[target]
                review['doc_kind']='fix_review'
                review['metadata']['document_kind']=field('fix_review','source_linked_mitigated_code_review',.99,evidence=ref)
                source_mitigation_edges.append((target,parent))
    old_engagements = b.tables['engagements']
    old_links = list(b.tables['engagement_documents'].values())
    educational = {c['document_id'] for c in b.tables['contests'].values() if c['provenance']['source_row'].get('format')=='first_flight'}
    active = {}
    for did, doc in docs.items():
        reason = 'educational_first_flight' if did in educational else exclusion_reason(doc)
        if reason:
            b.tables['document_exclusions'][did] = dict(document_id=did, reason=reason, evidence={'source':doc['source_tag']})
        else:
            active[did] = doc
    groups = Groups(active)
    edges = []
    rejected_edges = []
    document_edges = defaultdict(list)
    def merge(a, c, basis):
        if a in active and c in active and active[a]['publisher_id']==active[c]['publisher_id']:
            # Check whole components: a rendering/bridge must not indirectly
            # join two explicitly different implementation scopes.
            ga,gc=groups.find(a),groups.find(c)
            if ga!=gc and basis not in {'identical_original_sha256','original_sha256_or_source_explicit_alternate','source_explicit_mitigated_code_followup_link','official_mitigation_parent_contest_id'}:
                if any(identity.scope_conflict(active[x],active[y]) and not identity.family_relation(active[x],active[y])
                       for x in group_members[ga] for y in group_members[gc]):
                    rejected_edges.append(dict(documents=[a,c],basis=basis,rejection='different_substantive_scope_assets'))
                    return False
            joins=groups.find(a)!=groups.find(c)
            groups.union(a,c)
            if joins:
                members=group_members.pop(ga)|group_members.pop(gc)
                group_members[groups.find(a)]=members
            edges.append({'documents':[a,c], 'basis':basis,'joins_components':joins})
            document_edges[a].append(edges[-1])
            document_edges[c].append(edges[-1])
            return True
        return False
    group_members={did:{did} for did in active}
    by_old = defaultdict(list)
    for link in old_links:
        by_old[link['engagement_id']].append(link['document_id'])
    for members in by_old.values():
        for did in members[1:]:
            merge(members[0], did, 'original_sha256_or_source_explicit_alternate')
    # Reviewed gap-fill revisions retain distinct original bytes and document
    # rows. Bind the exact local texts before joining their engagement only.
    revisions_path = b.root / 'data/coverage/gapfill_v120_equivalence.json'
    if revisions_path.exists():
        for revision in json.loads(revisions_path.read_text()):
            if revision.get('publisher_id') != 'quantstamp':
                raise ValueError('Unexpected reviewed revision publisher')
            left, right = revision['sha256'], revision['existing_sha256']
            for value, expected in ((left, revision['text_sha256']), (right, revision['existing_text_sha256'])):
                if not re.fullmatch(r'[0-9a-f]{64}', value):
                    raise ValueError('Invalid reviewed revision hash')
                text_path = b.root / 'local-cache/fulltext' / (value + '.txt')
                if sha(text_path.read_bytes()) != expected:
                    raise ValueError('Reviewed revision text changed')
            if set(revision['new_finding_ids']) != set(revision['existing_finding_ids']) or not revision['counts_match']:
                raise ValueError('Reviewed revision finding identity changed')
            left_docs = [d for d in active.values() if d['publisher_id'] == 'quantstamp' and d['sha256'] == left]
            right_docs = [d for d in active.values() if d['publisher_id'] == 'quantstamp' and d['sha256'] == right]
            for a in left_docs:
                for c in right_docs:
                    if not merge(a['document_id'], c['document_id'], 'reviewed_publisher_report_revision'):
                        raise ValueError('Reviewed revision conflicts with substantive scope')
    for child,parent in contest_parent_edges:
        merge(child,parent,'official_mitigation_parent_contest_id')
    for child,parent in source_mitigation_edges:
        merge(child,parent,'source_explicit_mitigated_code_followup_link')
    indexes = [defaultdict(list) for _ in range(4)]
    content_index=defaultdict(set)
    for did, doc in sorted(active.items()):
        meta = doc['metadata']
        keys = [doc['sha256'], identity_url(doc['public_url']), meta.get('normalized_text_sha256'), stem(doc)]
        for i,key in enumerate(keys):
            if not key:
                continue
            index_key = (doc['publisher_id'], key)
            others = indexes[i][index_key]
            for other in others:
                scope_support = (len(stem(doc))>=8 and stem(doc)==stem(active[other])) or bool(set(meta['commits']['value'] or []) & set(active[other]['metadata']['commits']['value'] or []))
                if i == 0 or (i == 1 and (not doc['sha256'] or not active[other]['sha256'] or compatible(doc,active[other]))) or (i == 2 and scope_support and compatible(doc,active[other])) or (i == 3 and len(key)>=8 and compatible(doc,active[other])):
                    basis=['identical_original_sha256','same_report_url','same_normalized_report_text','report_stem_with_scope_or_date_support'][i]
                    if i>0 and rendering_pair(doc,active[other]): basis='complete_basename_rendering_with_substantive_content'
                    merge(other,did,basis)
            others.append(did)
        keys=[('commit',c) for c in meta['commits']['value'] or []]
        keys += [('repository',u.split('/tree/')[0].split('/commit/')[0].rstrip('/')) for u in meta['repositories']['value'] or []
                 if not re.search(r'/(?:audits?|reports?|publications|public[-_]audits)(?:/|$)',u,re.I)]
        from engagement_rules import generic_project
        if not generic_project(meta['client']['value']):
            keys.append(('client',normalize(meta['client']['value'])))
        candidates=set().union(*(content_index[(doc['publisher_id'],k)] for k in keys)) if keys else set()
        for other in sorted(candidates):
            if same_content(doc,active[other]):
                merge(other,did,'same_scope_and_substantive_report_content')
        for key in keys: content_index[(doc['publisher_id'],key)].add(did)
    # Broad candidate discovery followed by source relationship checks, including
    # different filenames/layouts that stem matching cannot find. Short windows
    # trigger semantic checks; they never decide the merge themselves.
    from relationship_rules import candidate_keys as prior_candidate_keys, relationship, short_window, distinctive_content
    def candidate_keys(doc):
        return prior_candidate_keys(doc)+identity.candidate_keys(doc)
    rare_content=distinctive_content(active)
    relations=defaultdict(set)
    relationship_checks=[]
    for did,doc in sorted(active.items()):
        keys=candidate_keys(doc)
        candidates=set().union(*(relations[(doc['publisher_id'],key)] for key in keys)) if keys else set()
        for other in sorted(candidates):
            if groups.find(other)==groups.find(did): continue
            basis=identity.family_relation(doc,active[other]) or relationship(doc,active[other],rare_content[did],rare_content[other])
            if basis:
                if merge(did,other,basis):
                    for source,target in [(doc,active[other]),(active[other],doc)]:
                        source['metadata'].setdefault('engagement_relationships',[]).append(dict(document_id=target['document_id'],basis=basis))
                else:
                    basis='rejected_different_substantive_scope_assets'
            if basis or short_window(doc,active[other]):
                relationship_checks.append(dict(documents=[did,other],basis=basis or 'independent_or_insufficient_relationship_evidence'))
        for key in keys: relations[(doc['publisher_id'],key)].add(did)
    if any(d['source_family']=='collected' for d in active.values()):
        atomic(b.root/'data/phase3/relationship_checks.jsonl',''.join(canonical(r)+'\n' for r in relationship_checks))
    for did,doc in active.items():
        if doc['doc_kind']=='fix_review':
            latest=identity.mitigation_parent(doc,active.values())
            roots={groups.find(parent) for parent in latest or []}
            if len(roots)==1:
                merge(did,next(iter(roots)),'source_mitigation_only_latest_supported_scope')
            explicit_parents=set()
            for url in doc['metadata'].get('parent_report_urls',{}).get('value') or []:
                for parent in indexes[1].get((doc['publisher_id'],identity_url(url)),[]):
                    if active[parent]['doc_kind'] != 'fix_review':
                        explicit_parents.add(groups.find(parent))
            if len(explicit_parents)==1:
                merge(did,next(iter(explicit_parents)),'explicit_parent_report_reference')
            # A source filename can explicitly identify a fix review while the
            # document omits a URL. Require a unique initial scope parent, with
            # exact audited commit or exact report stem plus substantive content.
            parents=set()
            commits=parent_scope_commits(doc)
            candidates=set().union(*(content_index[(doc['publisher_id'],('commit',c))] for c in commits)) if commits else set()
            candidates.update(indexes[3].get((doc['publisher_id'],stem(doc)),[]))
            for parent in candidates:
                candidate=active[parent]
                if parent!=did and candidate['doc_kind']!='fix_review':
                    match=bool(commits & parent_scope_commits(candidate))
                    if match or same_content(doc,candidate): parents.add(groups.find(parent))
            if len(parents)==1:
                merge(did,next(iter(parents)),'unique_fix_review_parent_scope')
            from relationship_rules import fix_parent_support
            scoped_parents={groups.find(parent) for key in candidate_keys(doc)
                            for parent in relations.get((doc['publisher_id'],key),set())
                            if parent!=did and fix_parent_support(doc,active[parent])}
            if len(scoped_parents)==1:
                merge(did,next(iter(scoped_parents)),'unique_named_fix_scope_and_relisted_findings')
            # Dedicated, version-labelled fix reviews can refer to a unique
            # initial report without printing its URL. Require the named scope
            # AND a source-labelled audited repository, never a client alone.
            version_scope=versioned_fix_scope(doc)
            if version_scope and not explicit_parents:
                candidates=[parent for parent,candidate in active.items() if candidate['publisher_id']==doc['publisher_id'] and candidate['doc_kind'] not in {'fix_review','unknown'} and normalize(candidate['metadata']['client']['value'])==version_scope]
                if candidates:
                    refs=scope_repositories(b.root,doc)
                    candidates=[parent for parent in candidates if refs & scope_repositories(b.root,active[parent])]
                    roots={groups.find(parent) for parent in candidates}
                    if len(roots)==1:
                        merge(did,next(iter(roots)),'explicit_versioned_fix_scope_and_repository')
        # Some Markdown records are a publisher's one-report PDF wrapper.
        # Resolve the explicit embed within the same repository (including its
        # public/ static root), never from a similar filename or title date.
        if doc['file_format'] in {'md','html'} and doc['sha256']:
            cache=b.root/'local-cache/text'/(doc['sha256']+'.txt')
            text=cache.read_text() if cache.exists() else ''
            if len(text)<6000:
                refs=set(re.findall(r'<(?:object|embed|iframe)\b[^>]*(?:data|src)=[\"\']([^\"\']+\.pdf)[\"\']',text,re.I))
                if len(refs)==1:
                    ref=unquote(next(iter(refs))).lstrip('/')
                    ident=identity_url(doc['public_url'])
                    keys=[]
                    if re.match(r'https?://',ref):
                        keys=[identity_url(ref)]
                    elif ident.startswith('github.com/') and '..' not in ref.split('/'):
                        repo='/'.join(ident.split('/')[:3])
                        keys=[repo+'/'+ref,repo+'/public/'+ref,ident.rsplit('/',1)[0]+'/'+ref]
                    targets={other for key in keys for other in indexes[1].get((doc['publisher_id'],key),[])
                             if active[other]['file_format']=='pdf'}
                    if len(targets)==1:
                        merge(did,next(iter(targets)),'source_explicit_embedded_pdf')
    # Cross-host rendering bridges may reveal two occurrences under the same firm.
    global_groups = Groups(active)
    shared_hash = {}
    for did,doc in active.items():
        global_groups.union(did,groups.find(did))
        if doc['sha256']:
            if doc['sha256'] in shared_hash:
                global_groups.union(did,shared_hash[doc['sha256']])
            shared_hash[doc['sha256']]=did
    projected = {}
    for did,doc in active.items():
        key=(global_groups.find(did),doc['publisher_id'])
        if key in projected:
            merge(did,projected[key],'cross_publisher_shared_report_bridge')
        projected[key]=did
    if any(d['source_family']=='collected' for d in active.values()):
        atomic(b.root/'data/phase3/identity_scope_merge_edges.jsonl',''.join(canonical(r)+'\n' for r in edges))
        atomic(b.root/'data/phase3/identity_scope_rejected_edges.jsonl',''.join(canonical(r)+'\n' for r in rejected_edges))
    components = defaultdict(list)
    for did in active:
        components[groups.find(did)].append(did)
    registry_path = b.root/'data/phase3/identity_map.json'
    registry = json.loads(registry_path.read_text()) if registry_path.exists() else {'version':1,'anchors':{},'redirects':{},'birth':{}}
    # Report identity has its own registry layer. Scope bundles must not turn
    # their component IDs into fresh "split" IDs on every subsequent build.
    anchors=registry.setdefault('report_anchors',dict(registry['anchors']))
    redirects=registry.setdefault('report_redirects',{k:v for k,v in registry['redirects'].items()
        if registry.get('redirect_basis',{}).get(k)!='scope_reports_one_client_engagement_v1'})
    birth=registry['birth']
    split_history=registry.setdefault('splits',{})
    def resolve(eid):
        visited=set()
        while eid in redirects:
            if eid in visited:
                raise ValueError('Cycle in Phase 3 identity redirects')
            visited.add(eid)
            eid = redirects[eid]
        return eid
    def component_anchors_for(members):
        return [active[did]['publisher_id']+'|'+a for did in members for a in ['document:'+did] + (['sha256:'+active[did]['sha256']] if active[did]['sha256'] else [])]
    # If a previous identity splits, only one current component may retain it.
    # Prefer the greatest surviving anchor overlap, breaking ties deterministically.
    previous_owners=defaultdict(lambda:defaultdict(int))
    for members in components.values():
        key=min(members)
        for anchor in set(component_anchors_for(members)):
            if anchor in anchors:
                previous_owners[resolve(anchors[anchor])][key]+=1
    retainers={prior:min(owners,key=lambda key:(-owners[key],key)) for prior,owners in previous_owners.items()}
    b.tables['engagements'] = {}
    b.tables['engagement_documents'] = {}
    document_to_eid = {}
    for members in sorted(components.values(), key=lambda m: min(m)):
        if all(active[d]['doc_kind']=='fix_review' for d in members):
            for did in members:
                b.tables['document_exclusions'][did] = dict(document_id=did, reason='fix_review_parent_not_identified', evidence={'basis':'no_supported_parent_report_in_snapshot'})
            continue
        members.sort(key=lambda did:(active[did]['source_family']=='discovery', active[did]['doc_kind']=='fix_review', did))
        first = active[members[0]]
        component_anchors = component_anchors_for(members)
        previous = {resolve(anchors[a]) for a in component_anchors if a in anchors}
        eligible_previous={prior for prior in previous if retainers.get(prior)==min(members) and prior not in b.tables['engagements']}
        eid = min(eligible_previous, key=lambda x:(birth.get(x, 0), x)) if eligible_previous else uid('engagement', first['publisher_id'], first['sha256'] or first['document_id'])
        serial=0
        while eid in b.tables['engagements'] or eid in redirects or (eid in retainers and retainers[eid]!=min(members)):
            eid = uid('engagement',first['publisher_id'],'split',min(members),serial)
            serial+=1
        birth.setdefault(eid, len(birth))
        split_history[eid]=sorted(set(split_history.get(eid,[])) | (previous-eligible_previous))
        for prior in eligible_previous - {eid}:
            redirects[prior] = eid
        for anchor in component_anchors:
            anchors[anchor] = eid
        # Acquired non-seed report evidence is sufficient for a conservative singleton;
        # grouping ambiguity remains visible in merge evidence and limitations.
        confirmed = any(active[d]['source_family'] != 'discovery' and active[d]['doc_kind'] not in {'unknown','non_report','fix_review'}
                        and (active[d]['metadata']['text_receipt'].get('status')=='ok' or active[d]['metadata'].get('date_text_receipt',{}).get('status') in {'ok','partial'})
                        and active[d]['metadata'].get('content_kind',{}).get('value') in {'report','unknown'} for d in members)
        kinds = {active[d]['doc_kind'] for d in members}
        best_project=max((active[d]['metadata']['client'] for d in members),key=lambda f:(bool(f['value']),f['confidence']))['value']
        b.tables['engagements'][eid] = dict(engagement_id=eid, publisher_id=first['publisher_id'],
            industry_engagement_id=uid('industry',eid) if confirmed else None, project=best_project,
            engagement_kind='contest' if 'contest_report' in kinds else 'formal_verification' if 'formal_verification' in kinds else 'audit',
            identity_status='confirmed' if confirmed else 'provisional', identity_basis='phase3_deterministic_evidence_group',
            evidence={'documents':members,'rule_version':RULE_VERSION,'identity_rules_version':identity.VERSION,
                      'identity_rules_sha256':identity.RULES_SHA256,'split_from_previous_identities':split_history[eid]},
            notes=['Conservative automatic identity; independent sample accuracy is not established.'] + ([] if confirmed else ['Discovery attribution recorded; original not acquired.']))
        for index,did in enumerate(members):
            doc = active[did]
            role = 'primary' if index==0 else 'supporting' if doc['source_family']=='discovery' or doc['doc_kind']=='fix_review' else 'alternate' if doc['sha256']==first['sha256'] or doc['file_format'] != first['file_format'] else 'translation' if re.search(r'(?i)(?:[_-](?:en|cn|zh)(?:[-_]|\.)|english|chinese)', doc.get('filename') or '') else 'revision'
            b.tables['engagement_documents'][(eid,did)] = dict(engagement_id=eid, document_id=did, role=role,
                evidence={'basis':'phase3_evidence_component', 'merge_edges':document_edges[did]})
            document_to_eid[did] = eid
    # Remap existing contest-end claims and FK links after identity merges.
    old_to_new = {old: next((document_to_eid[d] for d in members if d in document_to_eid), None) for old,members in by_old.items()}
    for claim in b.tables['date_claims'].values():
        if claim['engagement_id']:
            old = claim['engagement_id']
            if old_to_new.get(old):
                claim['engagement_id'] = old_to_new[old]
            elif old in by_old:
                claim.update(engagement_id=None, document_id=by_old[old][0])
    for contest in b.tables['contests'].values():
        contest['engagement_id'] = document_to_eid.get(contest['document_id'])
    # A report mirrored by multiple publishers represents one industry engagement.
    industry = Groups(b.tables['engagements'])
    shared = {}
    for did,doc in sorted(active.items()):
        eid = document_to_eid.get(did)
        if not eid:
            continue
        if doc['sha256'] and b.tables['engagements'][eid]['identity_status']=='confirmed':
            if doc['sha256'] in shared:
                industry.union(eid, shared[doc['sha256']])
            shared[doc['sha256']] = eid
    by_industry=defaultdict(set)
    for did,doc in active.items():
        if did in document_to_eid:
            by_industry[industry.find(document_to_eid[did])].add(doc['publisher_id'])
    for did,doc in active.items():
        if did in document_to_eid:
            publishers = by_industry[industry.find(document_to_eid[did])] - {doc['publisher_id']}
            if publishers:
                doc['metadata']['shared_report_publishers']=field(sorted(publishers),'shared_original_report_across_publishers',.99,
                    evidence={'limitation':'Shared hosting is not evidence of joint authorship.'})
    for eid, engagement in b.tables['engagements'].items():
        if engagement['identity_status']=='confirmed':
            engagement['industry_engagement_id'] = uid('industry', industry.find(eid))
    for prior in redirects:
        target = resolve(prior)
        if prior != target and target in b.tables['engagements'] and prior not in b.tables['engagements']:
            b.tables['engagement_identity_crosswalk'][prior] = dict(previous_engagement_id=prior, engagement_id=target, basis=registry.get('redirect_basis',{}).get(prior,'phase3_identity_registry_merge'))
    # Persist only when real inputs exist; fixtures remain self-contained and rerunnable.
    from date_rules import resolve_dates
    # Official contest claims can be remapped onto an excluded review occurrence
    # after enrichment. Apply the same role policy after that FK remapping.
    for claim in b.tables['date_claims'].values():
        doc=docs.get(claim['document_id'])
        if doc and doc['doc_kind']=='fix_review' and claim['role'] in {'audit_start','audit_completion','report_issue'}:
            claim['evidence']['phase3c_original_role']=claim['role']
            claim.update(role='retest',eligible_for_audit_year=False)
    report_stage_dates(b)
    for claim in b.tables['date_claims'].values():
        assertion=claim['evidence'].get('assertion') or {}
        quote=str(assertion.get('evidence','')).translate({ord(ch):' ' for ch in '\u200b\u200c\u200d\u200e\u200f\u00ad'})
        if claim['basis']=='document_text' and re.search(r'\bmitigation\s+(?:review|verification|phase|period)\b',quote,re.I) and claim['role'] in {'audit_start','audit_completion','report_issue'}:
            claim['evidence'].setdefault('phase3c_original_role',claim['role'])
            claim['evidence']['phase3c_resolution']='explicit_mitigation_phase_date'
            claim.update(role='retest',eligible_for_audit_year=False)
    resolve_dates(b)
    from recovered_years import apply_recovered_years, validate_grouped_years
    apply_recovered_years(b)
    resolve_dates(b)
    registry['anchors']=dict(anchors)
    registry['redirects']=dict(redirects)
    scope_remap=group_scope_reports(b,registry)
    validate_grouped_years(b)
    document_to_eid={did:scope_remap[eid] for did,eid in document_to_eid.items()}
    anchors,redirects=registry['anchors'],registry['redirects']
    # Reattribution retires the prior publisher-qualified identity. Keep a
    # redirect only when all surviving anchors identify one new engagement.
    attributed=defaultdict(set)
    for did,doc in active.items():
        old_publisher=doc['provenance'].get('phase3c_collected_publisher_id')
        if old_publisher and did in document_to_eid:
            for key in ['document:'+did]+(['sha256:'+doc['sha256']] if doc['sha256'] else []):
                previous=anchors.get(old_publisher+'|'+key)
                if previous:
                    attributed[previous].add(document_to_eid[did])
    for prior,targets in attributed.items():
        if len(targets)==1 and prior not in b.tables['engagements']:
            target=next(iter(targets))
            if prior!=target:
                redirects[prior]=target
                registry.setdefault('redirect_basis',{})[prior]='phase3c_source_named_auditor_reattribution'
                b.tables['engagement_identity_crosswalk'][prior]=dict(previous_engagement_id=prior,engagement_id=target,basis='phase3c_source_named_auditor_reattribution')
    atomic(registry_path, canonical(registry)+'\n')
