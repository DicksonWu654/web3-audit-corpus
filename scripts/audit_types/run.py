#!/usr/bin/env python3
"""Label every snapshot engagement offline; write only audit-type-owned outputs.

Run with nice -n 19 and python -I. One process, one DuckDB thread. No extraction,
classification top-up, collector, full analysis, release or site build is invoked.
"""
import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_types.common import file_sha, TYPES
from audit_types.rules import VERSION, api_input, canonical, classify_engagement, document_input, obj
from audit_types.llm import Merger, config as llm_config, prepare, source_hashes, work, write_frozen, content_key, payload
from audit_types.source import model_source


def query(con, sql):
    cur = con.execute(sql)
    keys = [c[0] for c in cur.description]
    return [dict(zip(keys, row)) for row in cur.fetchall()]


def api_index(root):
    path = root / 'data/collect/hacken/api_audits.jsonl'
    if not path.exists():
        return {}
    with path.open() as stream:
        rows = [api_input(json.loads(line)) for line in stream if line.strip()]
    return {r['report_link']: r for r in rows if r.get('audit_type') == 'SCA'}


def api_for(engagement, index):
    evidence = obj(engagement.get('evidence'))
    urls = {evidence.get('source_url')}
    urls.update(r.get('source_url') for r in evidence.get('sca_api_matches', []))
    return [index[u] for u in sorted(u for u in urls if u) if u in index]


def label_tables(root, engagements, documents, links, findings):
    """Shared producer used by both the isolated sidecar and engagement DB build."""
    by_engagement = defaultdict(list)
    by_doc = defaultdict(list)
    for f in findings:
        if f.get('record_kind') == 'formal_finding' and f.get('title'):
            by_doc[f.get('document_id')].append(f['title'])
    prepared = {}
    for link in sorted(links, key=lambda r: (r['engagement_id'], r['document_id'])):
        d = documents[link['document_id']]
        if d.get('is_seed') or d.get('doc_kind') in {'fix_review', 'non_report'} or link.get('role') in {'translation', 'alternate'}:
            continue
        did = d['document_id']
        if did not in prepared:
            if len(prepared) % 500 == 0:
                print(f'audit types: preparing source document {len(prepared)} ({did})', file=sys.stderr, flush=True)
            prepared[did] = document_input(root, d, by_doc[did])
            prepared[did]['llm_scope_text'], prepared[did]['llm_text_receipt'] = model_source(root, d)
            # Model titles come from formal finding records, not generic report
            # section headings. Numbered issue headings cover unparsed reports.
            prepared[did]['llm_finding_titles'] = sorted(set(by_doc[did]))
            if not prepared[did]['llm_finding_titles']:
                import re
                from audit_types.rules import local_text
                text, _ = local_text(root, d)
                prepared[did]['llm_finding_titles'] = list(dict.fromkeys(re.findall(
                    r'(?m)^[ \t#]*(?:\[(?:[HMLICG]-?\d+)\]|(?:Issue[ \t]+)?[HMLICG]-\d+)[ \t:]+([^\n]{8,160})', text[:120000])))
        by_engagement[link['engagement_id']].append(prepared[did])
    index = api_index(root)
    for n, e in enumerate(sorted(engagements.values(), key=lambda r: r['engagement_id'])):
        if n and n % 2000 == 0:
            print(f'audit types: {n} engagements', file=sys.stderr, flush=True)
        yield classify_engagement(e, by_engagement[e['engagement_id']], api_for(e, index))


def merge_label(merger, label, allow_uncached_abstentions=False):
    """Keep cached validation intact; explicit integration misses are abstentions."""
    merged = merger.merge(label)
    if merged.get('llm_status') == 'pending':
        if not allow_uncached_abstentions:
            raise ValueError('Uncached audit-type abstention requires explicit integration mode')
        merged['llm_status'] = 'uncached_not_requested'
        merged['uncached_abstention'] = dict(
            status='uncached_not_requested', reason='no_validated_cache_for_current_source_input',
            content_key=content_key(payload(label)), input_sha256=label['input_sha256'])
    return merged


def merge_policy_receipt(rows, allow_uncached_abstentions):
    missing = [r for r in rows if r.get('llm_status') == 'uncached_not_requested']
    return dict(allow_uncached_abstentions=bool(allow_uncached_abstentions),
        cache_status_counts=dict(sorted(Counter(r.get('llm_status') or 'authoritative_rule' for r in rows).items())),
        uncached_abstentions=len(missing),
        uncached_abstention_engagement_ids=sorted(r['engagement_id'] for r in missing),
        uncached_abstention_content_keys=sorted({r['uncached_abstention']['content_key'] for r in missing}))


def apply_to_builder(builder, allow_uncached_abstentions=None):
    rules_sha256 = file_sha(Path(__file__).with_name('rules.py'))
    allow_uncached_abstentions = (getattr(builder, 'allow_uncached_abstentions', False)
                                 if allow_uncached_abstentions is None else allow_uncached_abstentions)
    merger = Merger(builder.root, require_complete=not allow_uncached_abstentions)
    merged_rows = []
    for label in label_tables(builder.root, builder.tables['engagements'], builder.tables['documents'],
                              builder.tables['engagement_documents'].values(), builder.tables['findings'].values()):
        # Small rule-only fixtures need no LLM. Production builders require all
        # eligible source inputs in the validated cache, including new inputs.
        label = merge_label(merger, label, allow_uncached_abstentions)
        merged_rows.append(label)
        e = builder.tables['engagements'][label['engagement_id']]
        e.update(audit_type=label['audit_type'], audit_type_basis=label['audit_type_basis'])
        e['evidence']['audit_type_receipt'] = {k: v for k, v in label.items() if k not in ('inputs', 'public_urls')}
        e['evidence']['audit_type_receipt'].update(rule_version=VERSION, rules_sha256=rules_sha256,
            allow_uncached_abstentions=bool(allow_uncached_abstentions))
    builder.audit_type_merge_receipt = merge_policy_receipt(merged_rows, allow_uncached_abstentions)


def main():
    import duckdb
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--db', type=Path)
    parser.add_argument('--allow-uncached-abstentions', action='store_true',
        help='Integration only: abstain for missing current-input caches; validate every existing cache normally')
    parser.add_argument('--prepare-llm', action='store_true', help='Freeze source inputs and prompts; do not publish labels')
    args = parser.parse_args()
    root = args.root.resolve(); db = (args.db or root / 'data/corpus.duckdb').resolve()
    before = file_sha(db)
    con = duckdb.connect(str(db), read_only=True)
    con.execute('SET threads=1'); con.execute('BEGIN TRANSACTION')
    engagements = {r['engagement_id']: r for r in query(con, 'SELECT * FROM engagements ORDER BY engagement_id')}
    documents = {r['document_id']: r for r in query(con, '''SELECT document_id,sha256,title,project,filename,public_url,is_seed,doc_kind,local_path,file_format,
        json_object('project_identity',json_extract(metadata,'$.project_identity'),
                    'date_text_receipt',json_extract(metadata,'$.date_text_receipt'),
                    'text_receipt',json_extract(metadata,'$.text_receipt')) AS metadata,
        chains,languages FROM documents WHERE NOT is_seed''')}
    links = query(con, 'SELECT ed.* FROM engagement_documents ed JOIN documents d USING(document_id) WHERE NOT d.is_seed')
    findings = query(con, "SELECT document_id,title,record_kind FROM findings WHERE NOT is_seed AND record_kind='formal_finding'")
    publishers = {r['publisher_id']: r for r in query(con, 'SELECT publisher_id,name,publisher_kind FROM publishers')}
    con.execute('COMMIT'); con.close()
    print(f'audit types: snapshot loaded ({len(engagements)} engagements, {len(documents)} documents, {len(links)} links)', file=sys.stderr, flush=True)
    out = root / 'data/audit_types'; out.mkdir(parents=True, exist_ok=True)
    cache = root / 'local-cache/audit-types'; cache.mkdir(parents=True, exist_ok=True)
    source_rows = list(label_tables(root, engagements, documents, links, findings))
    if before != file_sha(db):
        raise ValueError('Database changed during labeling; rerun against a stable snapshot')
    if args.prepare_llm:
        target = work(root)/('rule_inputs.' + before + '.' + file_sha(Path(__file__).with_name('rules.py')) + '.jsonl')
        write_frozen(target, ''.join(canonical(row) + '\n' for row in source_rows))
        manifest = prepare(root, target, before)
        print(canonical({key: value for key, value in manifest.items() if key != 'batches'}))
        return
    merger = Merger(root, require_complete=not args.allow_uncached_abstentions)
    merged = [merge_label(merger, row, args.allow_uncached_abstentions) for row in source_rows]
    if before != file_sha(db):
        raise ValueError('Database changed during cache merge; rerun against a stable snapshot')
    rows = [{k: v for k, v in row.items() if k != 'inputs'} for row in merged]
    (cache/'inputs.jsonl').write_text(''.join(canonical(row) + '\n' for row in source_rows))
    labels = out / 'labels.jsonl'
    labels.write_text(''.join(canonical(row) + '\n' for row in rows))
    confirmed = [r for r in rows if r['identity_status'] == 'confirmed']
    by_firm = defaultdict(Counter)
    for r in confirmed:
        by_firm[r['publisher_id']][r['audit_type']] += 1
    firm_rows = []
    for pid, counts in sorted(by_firm.items(), key=lambda kv: (-sum(kv[1].values()), kv[0])):
        total = sum(counts.values())
        firm_rows.append(dict(firm_id=pid, firm=publishers[pid]['name'], kind=publishers[pid]['publisher_kind'],
                              engagements=total, token_only=counts['token_only'], token_only_share=counts['token_only']/total,
                              engagements_excluding_token_only=total-counts['token_only'], **{t: counts[t] for t in TYPES if t != 'token_only'}))
    with (out / 'firm_shares.csv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(firm_rows[0])); writer.writeheader(); writer.writerows(firm_rows)
    receipt = dict(rule_version=VERSION, rules_sha256=file_sha(Path(__file__).with_name('rules.py')),
                   producer_sha256=file_sha(Path(__file__)), database_sha256=before, labels_sha256=file_sha(labels),
                   api_sha256=file_sha(root / 'data/collect/hacken/api_audits.jsonl') if api_index(root) else None,
                   input_evidence_sha256=file_sha(cache / 'inputs.jsonl'),
                   merge_version=llm_config()['version'], merge_source_hashes=source_hashes(),
                   manifest_sha256=file_sha(work(root)/'manifest.json') if merger.manifest else None,
                   llm=dict(used=any(r.get('llm_status') == 'complete' for r in merged), **llm_config()),
                   **merge_policy_receipt(merged, args.allow_uncached_abstentions),
                   basis_counts=dict(merger.used),
                   confirmed_rule_types=dict(Counter(r['rule_audit_type'] for r in confirmed)),
                   engagements=len(rows), confirmed_engagements=len(confirmed), publishers=len(by_firm),
                   all_types=dict(Counter(r['audit_type'] for r in rows)), confirmed_types=dict(Counter(r['audit_type'] for r in confirmed)),
                   top25_firms=[r for r in firm_rows if r['kind'] != 'contest_platform'][:25])
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
