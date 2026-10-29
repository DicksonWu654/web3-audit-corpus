"""Identity-bound, evidence-preserving selection of reviewed date proposals."""
from collections import defaultdict


def apply_recovered_years(b):
    from build_db import uid, iso
    links=defaultdict(list)
    for link in b.tables['engagement_documents'].values():
        links[link['engagement_id']].append(link['document_id'])
    claims=defaultdict(list)
    by_doc={did:eid for eid,dids in links.items() for did in dids}
    for claim in b.tables['date_claims'].values():
        claims[claim['engagement_id'] or by_doc.get(claim['document_id'])].append(claim)
    for inferred in (False,True):
        path=b.root/'data/phase3/date_recovery/engagement_years'/('date_overrides_inferred.jsonl' if inferred else 'date_overrides_explicit.jsonl')
        if not path.exists():
            continue
        for row,meta,ledger in b.rows(path,'recovered_engagement_years','collected','date_overrides'):
            eid=row['engagement_id']
            e=b.tables['engagements'].get(eid)
            expected=set(row['report_ids'])
            actual={b.tables['documents'][did]['sha256'] for did in links[eid] if b.tables['documents'][did]['sha256']}
            if not e or e['publisher_id']!=row['firm_id'] or actual!=expected or row['year_inferred'] is not inferred:
                raise ValueError('Recovered year report identity changed: '+eid)
            source_basis,source_role=row['audit_date_basis'].split(':',1)
            role='audit_year_inference' if inferred else source_role if source_role in {'audit_completion','report_issue'} else 'review_year'
            value=row['date_value'] or str(row['audit_year'])
            if iso(value)!=(value,row['date_precision']) or int(value[:4])!=row['audit_year']:
                raise ValueError('Invalid recovered date: '+eid)
            if inferred and (row['date_value'] is not None or row['date_precision']!='year'):
                raise ValueError('Inferred year cannot assert an exact completion date')
            # Preserve every contradictory original, marking its selection state.
            # No role or source assertion is silently rewritten.
            if row['replace_conflicting_claim_selection']:
                for old in claims[eid]:
                    if old['eligible_for_audit_year']:
                        old['evidence']['date_recovery_selection']=dict(superseded_by=uid('date_recovery',eid),
                            original_eligible_for_audit_year=True,rationale=row['rationale'])
                        old['eligible_for_audit_year']=False
            elif any(c['eligible_for_audit_year'] and c['role']=='audit_completion' for c in claims[eid]):
                # New source extraction may already recover the same year. Never
                # let a weaker proposal override contradictory completion evidence.
                years={int(c['date_value'][:4]) for c in claims[eid] if c['eligible_for_audit_year'] and c['role']=='audit_completion'}
                if years!={row['audit_year']}:
                    raise ValueError('Recovered proposal contradicts current completion: '+eid)
            claim=dict(claim_id=uid('date_recovery',eid),document_id=None,engagement_id=eid,finding_id=None,
                source_tag=meta['source_tag'],role=role,raw_value=row['date_value'] or str(row['audit_year']),
                date_value=value,date_end=None,precision=row['date_precision'],basis=source_basis,
                authority='collector_hint' if inferred else 'publisher',eligible_for_audit_year=True,
                evidence=dict(field='reviewed_engagement_date_override',date_recovery=row,source_record=meta,year_inferred=inferred,
                    audit_date_basis=row['audit_date_basis'],assertion={'date_recovery_evidence':row['evidence']}))
            b.add('date_claims',claim['claim_id'],claim,ledger)
            e['evidence'].setdefault('date_recovery',[]).append(row)


def validate_grouped_years(b):
    """An override may follow its exact scope group into a larger bundle only."""
    for e in b.tables['engagements'].values():
        recovered=e['evidence'].get('date_recovery',[])
        groups=e['evidence'].get('scope_grouping',{}).get('report_groups',[])
        for row in recovered:
            if not any(set(g['report_ids'])==set(row['report_ids']) for g in groups):
                raise ValueError('Recovered year lost its retained scope identity: '+row['engagement_id'])
