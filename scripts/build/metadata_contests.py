"""Import source-evidenced competitions without inventing report artifacts."""
from urllib.parse import urlsplit


def import_metadata_contests(b):
    from build_db import uid
    path=b.root/'data/collect/immunefi/metadata_engagements.jsonl'
    if not path.exists() or 'immunefi' not in b.publishers:
        return
    for row,meta,ledger in b.rows(path,'competition_metadata:immunefi','collected','engagement_metadata'):
        if row['platform']!='immunefi' or not row['eligible_metadata_engagement']:
            raise ValueError('Ineligible competition metadata')
        url=row.get('engagement_evidence_url')
        if urlsplit(url or '').scheme not in {'http','https'}:
            raise ValueError('Competition lacks public result evidence')
        cid=uid('contest',row['platform'],row['contest_id'])
        contest=b.tables['contests'].get(cid)
        if not contest:
            raise ValueError('Metadata competition absent from official listing: '+cid)
        for key in ('start_utc','end_utc','format','report_url','findings_high','findings_medium'):
            if contest[key]!=row[key]:
                raise ValueError('Competition metadata/listing mismatch: '+cid+' '+key)
        # Existing report association has precedence, including the CircuitDAO
        # client-hosted mirror already matched by its original SHA-256.
        eid=contest['engagement_id']
        if not eid:
            eid=uid('engagement','competition_metadata',row['platform'],str(row['contest_id']))
            b.tables['engagements'][eid]=dict(engagement_id=eid,publisher_id=row['platform'],
                industry_engagement_id=uid('industry',eid),project=row['sponsor/project'],
                engagement_kind='contest',identity_status='confirmed',
                identity_basis='publisher_competition_metadata',
                evidence=dict(metadata_only=True,platform=row['platform'],contest_id=str(row['contest_id']),
                    source_url=url,listing_url=row['listing_url'],source_record=meta,competition=row,
                    documents=[],report_ids=[],report_count=0,scope_report_count=0),
                notes=['Confirmed from public competition results; original report and unique findings unobserved.'])
            contest['engagement_id']=eid
            if contest['end_utc']:
                mitigation=contest['format']=='mitigation'
                b.claim({'engagement_id':eid},meta['source_tag'],'contest:'+str(row['contest_id'])+'.end_utc',
                    contest['end_utc'][:10],'retest' if mitigation else 'audit_completion',basis='contest_end',
                    authority='publisher' if contest['timing_status']!='source_conflict' else 'inherited_unverified',
                    evidence=dict(contest_id=cid,source_url=url,timing_status=contest['timing_status']))
        b.tables['engagements'][eid]['evidence'].setdefault('competition_metadata',[]).append(dict(**meta,source_url=url))
        ledger['imported_rows']+=1
