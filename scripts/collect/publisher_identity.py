"""Reconcile publisher aliases by SHA-256 while retaining link provenance."""
import json
from pathlib import Path
from web_common import ROOT, atomic_json


def rows(path):
    return [json.loads(s) for s in path.read_text().splitlines() if s.strip()] if path.exists() else []


def save(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.jsonl.tmp')
    tmp.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records))
    tmp.replace(path)


def reconcile(canonical, aliases, merge_all=False):
    base = ROOT/'data/collect'
    path = base/canonical/'reports.jsonl'
    previous_path = path.with_name('identity_reconciliation.json')
    previous = json.loads(previous_path.read_text()) if previous_path.exists() else {}
    unique, links = {}, list(previous.get('source_links', []))
    for source in [canonical] + aliases:
        sp = base/source/'reports.jsonl'
        retained = []
        for original in rows(sp):
            row = dict(original)
            sha = row['sha256']
            if source != canonical and not merge_all and sha not in unique:
                retained.append(row)
                continue
            evidence = dict(source_firm_id=source, canonical_firm_id=canonical, sha256=sha,
                            public_url=row['public_url'], listing_url=row['listing_url'])
            links.append(evidence)
            if sha in unique:
                note = f'Alternate publisher/listing provenance: {source}; public_url={row["public_url"]}; listing_url={row["listing_url"]}.'
                if note not in unique[sha]['notes']:
                    unique[sha]['notes'] += '\n' + note
            else:
                row['firm_id'] = canonical
                if source != canonical:
                    row['notes'] += f'\nPublisher identity reconciled from {source} to {canonical}; original collector retained as provenance.'
                unique[sha] = row
        if source != canonical:
            save(sp, retained)
            status_path = sp.with_name('status.json')
            if status_path.exists():
                status = json.loads(status_path.read_text())
                status.update(collected=len(retained))
                if merge_all:
                    status.update(canonical_publisher=canonical,
                        identity_reconciliation='Publisher alias: all originals attributed once to canonical publisher; links retained in canonical identity_reconciliation.json.')
                else:
                    if status.get('canonical_publisher') == canonical:
                        status.pop('canonical_publisher')
                    status['identity_reconciliation'] = 'Cross-publisher SHA-256 overlaps attributed to '+canonical+'; this host/listing is not a publisher alias.'
                atomic_json(status_path, status)
            cp = sp.with_name('contests.jsonl')
            if cp.exists():
                contests = rows(cp)
                for c in contests:
                    if c.get('sha256') in unique:
                        c.update(publisher_firm_id=canonical, engagement_counted_under=canonical,
                                 eligible_public_cohort=False, excluded_reason='publisher_attributed_to_'+canonical)
                save(cp, contests)
    save(path, sorted(unique.values(), key=lambda r:r['public_url']))
    status_path = path.with_name('status.json')
    status = json.loads(status_path.read_text())
    status.update(collected=len(unique), canonical_publisher=canonical, sha256_deduplicated=True)
    status['identity_aliases' if merge_all else 'related_host_listings'] = aliases
    if not merge_all:
        status.pop('identity_aliases', None)
    atomic_json(status_path, status)
    links = list({(r['source_firm_id'], r['sha256'], r['public_url'], r['listing_url']):r for r in links}.values())
    evidence = dict(canonical_publisher=canonical, related_sources=aliases, merge_all=merge_all,
                    unique_originals=len(unique), source_links=links)
    atomic_json(path.with_name('identity_reconciliation.json'), evidence)
    return evidence
