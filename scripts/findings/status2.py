"""Local-only status-quality census, source inspection and integration replay.

Never reads the external evaluation tree. Every source access rejects the
repository's holdout hashes first. Large receipts stay in local-cache.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, holdouts, read_snapshot, write_json
from streams import finding_rows, finding_paths

LOCAL = ROOT / 'local-cache/phase4-status2'
TARGETS = ('certora', 'halborn', 'ackee-blockchain', 'mixbytes', 'trail-of-bits',
           'ncc-group', 'pashov-audit-group', 'code4rena', 'runtime-verification',
           'peckshield', 'pessimistic', 'verichains')


def streams(base=None):
    base = base or ROOT / 'data/findings'
    return [(p, 'supplemental' if p.parent.name=='supplemental' else 'snapshot') for p in finding_paths(base)]


def rows(base=None, firm=None):
    blocked = holdouts()
    for path, row in finding_rows(base or ROOT/'data/findings', firms={firm} if firm else None):
        assert row['sha256'] not in blocked, 'Holdout finding denied'
        yield path.stem, 'supplemental' if path.parent.name=='supplemental' else 'snapshot', row


def census(base=None):
    firms = {}
    labels = Counter()
    reasons = {}
    for firm, cohort, row in rows(base):
        out = firms.setdefault(firm, dict(rows=0, snapshot=0, supplemental=0,
            source_status=0, unmapped_rows=0, statuses=Counter(), variants={}))
        out['rows'] += 1
        out[cohort] += 1
        out['source_status'] += bool((row['status_original'] or '').strip())
        out['statuses'][row['status']] += 1
        variant = out['variants'].setdefault(row['variant_id'], dict(rows=0, source_status=0))
        variant['rows'] += 1
        variant['source_status'] += bool((row['status_original'] or '').strip())
        receipt = row['status_mapping']
        if not receipt['mapped']:
            raw = row['status_original']
            labels[firm, raw] += 1
            reasons[firm, raw] = dict(reason=receipt.get('reason', receipt.get('rationale')),
                                     listed=receipt.get('listed', False), era=receipt['era'])
            out['unmapped_rows'] += 1
    statuses = Counter()
    for item in firms.values():
        statuses.update(item['statuses'])
    return dict(by_firm=firms, statuses=dict(statuses), rows=sum(statuses.values()),
        source_status=sum(r['source_status'] for r in firms.values()),
        unmapped_rows=sum(labels.values()), unmapped_distinct_labels=len({v for _, v in labels}),
        unmapped_publisher_label_pairs=len(labels),
        unmapped=[dict(publisher=f, status_original=v, count=n, **reasons[f, v])
                  for (f, v), n in sorted(labels.items())],
        holdout_list_sha256=digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes()),
        holdouts_opened=0)


def save_census(name, base=None):
    path = LOCAL/(name+'.json')
    if name == 'before' and path.exists():
        raise FileExistsError('Baseline already frozen')
    result = census(base)
    write_json(path, result)
    with (LOCAL/(name+'_unmapped.csv')).open('w') as out:
        writer = csv.DictWriter(out, fieldnames=('publisher', 'status_original', 'count',
                                                 'reason', 'listed', 'era'))
        writer.writeheader()
        writer.writerows(result['unmapped'])
    print(json.dumps({k:v for k,v in result.items() if k not in ('by_firm','unmapped')}, indent=2))


def inspect(firm, pattern, limit, missing=True):
    seen = set()
    for _, _, row in rows(firm=firm):
        if missing and row['status_original'] is not None:
            continue
        key = row['sha256'], row['publisher_finding_id']
        if key in seen:
            continue
        seen.add(key)
        hits = list(re.finditer(pattern, row['body_text'], re.I))
        if not hits:
            continue
        print(json.dumps({k:row[k] for k in ('sha256', 'publisher_finding_id', 'title',
              'variant_id', 'status_original', 'public_url', 'body_span')}, ensure_ascii=False))
        for hit in hits[:6]:
            print(repr(row['body_text'][max(0,hit.start()-130):hit.end()+260]))
        limit -= 1
        if not limit:
            break


def binding_audit():
    findings = []
    for firm in ('pessimistic', 'verichains'):
        for _, _, row in rows(firm=firm):
            proof = row['evidence'].get('status_evidence')
            if not proof:
                continue
            a, b = row['body_span']['start'], row['body_span']['end']
            if a <= proof['start'] < b and proof['start'] > b-300:
                findings.append(dict(publisher=firm, sha256=row['sha256'],
                    id=row['publisher_finding_id'], raw=row['status_original'],
                    start=a, end=b, proof=proof, head=row['body_text'][:200],
                    tail=row['body_text'][-400:]))
    write_json(LOCAL/'bindings.json', findings)
    for item in findings[:12]:
        print(json.dumps(item, ensure_ascii=False))


def fallback_study():
    from status_resolve import status_mapping
    before = json.loads((LOCAL/'before.json').read_text())
    results = [dict(row, after=status_mapping(row['status_original'], row['publisher'],
                    era=row['era'], log=False)) for row in before['unmapped']]
    write_json(LOCAL/'fallback_study.json', results)
    counts = Counter()
    for row in results:
        if row['after']['mapped']:
            counts[row['after']['rule']] += row['count']
    print(json.dumps(dict(mapped_pairs=sum(r['after']['mapped'] for r in results),
                         mapped_rows=sum(counts.values()), by_family=counts), indent=2))


def study():
    """Parse targeted source artifacts without changing any finding stream."""
    from core import Report, finish, candidate_status
    from parsers import module
    unknown = {}; changes = []; counts = Counter()
    for firm in TARGETS:
        old = defaultdict(dict)
        for _, _, row in rows(firm=firm):
            old[row['sha256']][row['body_span']['start']] = row
        for sha, originals in old.items():
            assert sha not in holdouts()
            path = ROOT/'local-cache/fulltext'/sha
            text = path.with_suffix('.txt').read_text()
            meta = json.loads(path.with_suffix('.pages.json').read_text())
            assert digest(text.encode()) == meta['text_sha256']
            report = Report(text, meta, firm)
            cs = finish(report, module(firm).parse(report))
            for c in cs:
                mapping = candidate_status(report,c,sha256=sha)
                previous = originals.get(c.start)
                if previous and previous['status_original'] != c.status_raw:
                    counts[firm] += 1
                    changes.append(dict(publisher=firm,sha256=sha,id=c.printed_id,
                        start=c.start,end=c.end,old=previous['status_original'],new=c.status_raw,
                        status=mapping['normalized'],evidence=c.evidence.get('status_evidence')))
                if not mapping['mapped'] and not mapping.get('listed'):
                    key=(firm,c.status_raw)
                    out=unknown.setdefault(key,dict(publisher=firm,raw=c.status_raw,count=0,
                        sha256=sha,id=c.printed_id,evidence=c.evidence.get('status_evidence')))
                    out['count'] += 1
        print(firm, 'studied', flush=True)
    write_json(LOCAL/'study_changes.json', changes)
    write_json(LOCAL/'study_unknown.json', list(unknown.values()))
    print(json.dumps(dict(changed_artifact_findings=counts,unaccounted_pairs=len(unknown)),indent=2))


def fixtures():
    """Freeze small, verbatim source excerpts with hashes and source offsets."""
    cases = []
    specs = [
        ('certora_preceding_cell', 'certora', '6083cd7bd277e9eb517f7743dd9750a793fc36553cb1e5f5edfc281377060c8e', 3736, 'status_issue_cards', 'Fixed', 'fixed'),
        ('certora_table', 'certora', '8357bd7e644f4990987086b1097af2c35f4b21bcdadf59d63070c17085f42805', 1498, 'status_verification_tables', 'Fixed', 'fixed'),
        ('halborn_banner', 'halborn', 'f097486d52c39a3e4f980489749204f00f172484221553abe633c34cb1937f3e', 36349, 'status_hal', 'SOLVED', 'fixed'),
        ('halborn_double_colon', 'halborn', 'f097486d52c39a3e4f980489749204f00f172484221553abe633c34cb1937f3e', 78087, 'status_hal', 'ACKNOWLEDGED', 'acknowledged'),
        ('ackee_fix_log', 'ackee-blockchain', '50bd6604c026a971cb0b0abb478dd6b618ff3527bf5b1da5bcbe4ded781bdb04', 38662, 'status_revision', 'This issue was acknowledged by the client.', 'acknowledged'),
        ('mixbytes_removed', 'mixbytes', '07954331ad61cb71f20ff9e3e79820804400a02f0a0f9648352f2c1444b346eb', 5381, 'numbered_status', 'REMOVED     – at 18474eabd96a6dda2abb39e90493d95e2cb5da9a', 'fixed'),
        ('ncc_retest', 'ncc-group', '1399f9fe104b47af9c983a0f2f1b2c32aee5bdab63ff0adfbebbe18e4a2eec68', 27402, 'status_overall_risk', 'Partially Fixed', 'partially_fixed'),
        ('pashov_inline', 'pashov-audit-group', '8e3e7ced5dc4fa7cb79e99dcab9760022ffa8c6e9e2040265e66143da6e1b69c', 7897, 'read_status', 'Acknowledged', 'acknowledged'),
        ('c4_separate_issue', 'code4rena', '7215cc99245adf5d6d8aa66b1e900bb5f0fa646aec1a5de93025247aa3565df2', 33327, 'read_status', 'acknowledged', 'acknowledged'),
        ('c4_severity_dispute', 'code4rena', '71d55b0766dd48015e8a8fda856dd7771f5b1d0c9695fc38d1485df9f657369d', 31555, 'read_status', 'acknowledged', 'acknowledged'),
        ('c4_sponsor_response', 'code4rena', '9ffefcf2dbf012f28e4628d1b6bfd5d5b0c87e598e58adb25b739561373357a2', 6467, 'read_status', 'Acknowledged', 'acknowledged'),
        ('runtime_sentence', 'runtime-verification', 'b09097e6dbc3215d6f167fd1770af5a6d4f1b89806a3af1d200688cb8386d569', 21596, 'read_status', "This finding has been addressed in commit ID 091d3aa on the project's main branch.", 'fixed'),
        ('peckshield_sentence', 'peckshield', '0afb99949a57ea5261ccc5148c5a5f24f3f95e26a3fa63ca637b3540c3e6b706', 42680, 'status_pve', 'This issue has been confirmed by the team.', 'acknowledged'),
        ('peckshield_compliance_status', 'peckshield', 'ea05734cb2b7fc803ae2c02cfd55f1d3e2b2dc20caf186800ba53cbbf698ca1b', 36020, 'status_pve', 'The issue has been fixed by this commit: de05115.', 'fixed'),
    ]
    for name, firm, sha, start, reader, raw, normalized in specs:
        row = next(r for _, _, r in rows(firm=firm)
                   if r['sha256']==sha and r['body_span']['start']==start)
        end = row['body_span']['end']
        text = (ROOT/'local-cache/fulltext'/(sha+'.txt')).read_text()
        assert text[start:end] == row['body_text']
        cases.append(dict(name=name,publisher=firm,sha256=sha,public_url=row['public_url'],
            source_start=start,source_end=end,text=text[start:end],text_sha256=digest(text[start:end].encode()),
            id=row['publisher_finding_id'],title=row['title'],severity=row['severity_original'],
            reader=reader,expected_raw=raw,expected_status=normalized))
    for name, firm, sha, expected in [
        ('verichains_wrapped_index','verichains','d17a20a68276cde9775757f146c7e19631b018b943166d23baa37d6d4cadfbf1',
         {'2.2.8':'acknowledged','2.2.9':'acknowledged','2.2.10':'acknowledged and fixed','2.2.11':'acknowledged and fixed','2.2.12':'acknowledged'}),
        ('pessimistic_adjacent_headers','pessimistic','c265a4d18ee3141755f773d982837bb2b86b9b2f6384f97926fa06b2664e78f4',
         {'L13':'fixed','L14':'new','N01':'commented','N03':'fixed'}),
        ('tob_wrapped_pr','trail-of-bits','c3ce60dcc9ce017fcfd311f827c735792db2053b1d7175341c8a81b69c5bb1fa',
         {'1':'Resolved','2':'Partially resolved','7':'Resolved'}),
        ('peckshield_empty_detail_index','peckshield','f9784a23471b4c68904d223232540f84f972a50e0c943fc1b7d64cf35af37609',
         {'PVE-001':'Fixed'}),
    ]:
        row=next(r for _,_,r in rows(firm=firm) if r['sha256']==sha)
        assert sha not in holdouts()
        text=(ROOT/'local-cache/fulltext'/(sha+'.txt')).read_text()
        cases.append(dict(name=name,publisher=firm,sha256=sha,public_url=row['public_url'],
            source_start=0,source_end=len(text),text=text,text_sha256=digest(text.encode()),expected_bindings=expected))
    write_json(ROOT/'scripts/findings/fixtures/status2.json',cases)
    print(json.dumps(dict(fixtures=len(cases),publishers=sorted({r['publisher'] for r in cases}))))


def review_new():
    """List source-verified but uninterpretable assertions, retaining not_stated.

    This does not assign a status or broaden any family. It satisfies the
    interchange's explicit review inventory for newly captured prose.
    """
    from core import Report, finish, candidate_status
    from parsers import module
    policy=json.loads((ROOT/'schema/status_map.json').read_text())
    docs={(d['row']['firm_id'],d['row']['sha256']):d for d in read_snapshot()}
    changes=[];cache={}
    for entry in json.loads((LOCAL/'study_unknown.json').read_text()):
        firm,sha,raw=entry['publisher'],entry['sha256'],entry['raw']
        assert sha not in holdouts()
        key=firm,sha
        if key not in cache:
            path=ROOT/'local-cache/fulltext'/sha
            text=path.with_suffix('.txt').read_text()
            meta=json.loads(path.with_suffix('.pages.json').read_text())
            assert digest(text.encode())==meta['text_sha256']
            report=Report(text,meta,firm)
            cache[key]=(report,finish(report,module(firm).parse(report)))
        report,cs=cache[key]
        matches=[c for c in cs if c.status_raw==raw]
        if not matches:continue  # A repaired reader no longer emits the old artifact.
        c=matches[0];mapping=candidate_status(report,c,sha256=sha)
        if mapping['mapped'] or mapping.get('listed'):continue
        proof=c.evidence['status_evidence']
        assert report.text[proof['start']:proof['end']]==raw
        page=next(p for p in report.meta['pages'] if p['start']<=proof['start']<=p['end'])
        era=next(e for e in policy['publishers'][firm]['eras'] if e['id']==mapping['era'])
        era['labels'][raw]=dict(normalized='not_stated',review_state='listed_unresolved',
            rationale='Source assertion retained for review: this sentence alone does not establish acknowledgement, an outstanding fix, or completed remediation.',
            definition_basis='native_example_only',observed_labels=[raw],
            evidence=[dict(kind='source_example',sha256=sha,page=page['page'],page_basis='pdf_page',
                public_url=docs[key]['row']['public_url'],quote=raw)])
        changes.append(dict(publisher=firm,raw=raw,sha256=sha))
    payload=json.dumps(policy,ensure_ascii=False,indent=2,sort_keys=True)+'\n'
    for suffix in ('yaml','json'):(ROOT/'schema'/('status_map.'+suffix)).write_text(payload)
    write_json(LOCAL/'new_review_labels.json',changes)
    print(json.dumps(changes,ensure_ascii=False,indent=2))


def comparison():
    previous={r['finding_id']:(firm,r['status_original'],r['status'])
              for firm,_,r in rows(LOCAL/'findings_before')}
    result=dict(recovered_source=Counter(),changed_source=Counter(),changed_status=Counter(),
                resolver_only_changes=Counter(),lost_known=[],added=[],removed=[],transitions=Counter())
    for firm,_,row in rows():
        old=previous.pop(row['finding_id'],None)
        if old is None:
            result['added'].append(row['finding_id']);continue
        _,raw,bucket=old
        result['recovered_source'][firm] += raw is None and row['status_original'] is not None
        result['changed_source'][firm] += raw != row['status_original']
        result['changed_status'][firm] += bucket != row['status']
        result['resolver_only_changes'][firm] += raw == row['status_original'] and bucket != row['status']
        result['transitions'][bucket+' -> '+row['status']] += 1
        if bucket!='not_stated' and row['status']=='not_stated':
            result['lost_known'].append(dict(publisher=firm,id=row['finding_id'],sha256=row['sha256'],
                public_url=row['public_url'],old_raw=raw,new_raw=row['status_original'],old_status=bucket))
    result['removed']=sorted(previous)
    write_json(LOCAL/'comparison.json',result)
    return result


def report_results():
    before=json.loads((LOCAL/'before.json').read_text())
    after=json.loads((LOCAL/'after.json').read_text())
    tests=json.loads((LOCAL/'tests.json').read_text())
    replay=json.loads((LOCAL/'determinism.json').read_text())
    checker=json.loads((ROOT/'data/findings/check.json').read_text())
    statuses=json.loads((ROOT/'data/findings/status_check.json').read_text())
    changes=comparison()
    assert tests['ok'] and replay['ok'] and checker['ok'] and statuses['ok']
    assert before['holdout_list_sha256']==after['holdout_list_sha256']
    share=lambda n,total:f'{100*n/total:.2f}%' if total else '—'
    total=lambda key:sum(changes[key].values())
    out=['# Finding-status quality: status2','',
        'Generated by `scripts/findings/status2.py report`. All counts include frozen-snapshot and supplemental streams and all emitted record kinds; they are document occurrences, not unique vulnerabilities. No external evaluation tree was accessed. Source inspection, fixtures, parsing and checks reject the repository holdout hashes before source access.','',
        f"Rows: **{before['rows']:,} → {after['rows']:,}**. Source labels: **{before['source_status']:,} → {after['source_status']:,}**. "
        f"Known canonical status: **{share(before['rows']-before['statuses']['not_stated'],before['rows'])} → {share(after['rows']-after['statuses']['not_stated'],after['rows'])}**.",'',
        '| Canonical status | Before | After | Share before | Share after |','|---|---:|---:|---:|---:|']
    for state in ('fixed','partially_fixed','acknowledged','unresolved','not_stated'):
        a,b=before['statuses'].get(state,0),after['statuses'].get(state,0)
        out.append(f"| {state} | {a:,} | {b:,} | {share(a,before['rows'])} | {share(b,after['rows'])} |")
    out += ['',f"Unmapped verbatim distinct labels: **{before['unmapped_distinct_labels']} → {after['unmapped_distinct_labels']}**; "
        f"publisher/label pairs: **{before['unmapped_publisher_label_pairs']} → {after['unmapped_publisher_label_pairs']}**; "
        f"unmapped rows: **{before['unmapped_rows']} → {after['unmapped_rows']}**. These include explicit review placeholders. Missing labels are counted separately as `not_stated`, not as unmapped strings.",'',
        'Complete, unabridged inventories with counts are in `local-cache/phase4-status2/before_unmapped.csv` and `after_unmapped.csv`; the before JSON preserves every label and its reason/era. `fallback_study.json` replays every baseline unmapped publisher/label pair through the final families. The appendix below tabulates every baseline distinct string.','',
        '## Resolver and capture changes','',
        'The JSON-compatible YAML and identical JSON export now contain ordered, publisher-independent regex families. Mapped publisher/era entries retain precedence, including native Not fixed, Closed, Info and verification semantics. `listed_unresolved` entries are review placeholders rather than semantic decisions; they may use the fallback, as may true lookup misses. Ambiguous known publisher eras still fail closed. Receipts retain the verbatim input, era, policy hash, resolver version and matched family. Negation, partial repair and future work precede positive fix assertions; recommendations, incidental fixed values/resolved batches and ambiguous mixed dispositions cannot establish a fix. Bare Closed/Verified remain publisher-specific.','',
        '- Certora: response text preceding the Mitigation/Fix cell and unique verification-table response cells; multi-row ambiguous cards cannot borrow a neighbour’s status.',
        '- Halborn: standalone SOLVED/ACKNOWLEDGED verdicts despite banners and repeated remediation colons.',
        '- Ackee: ID-linked overview rows with or without colons, plus explicit client acknowledgement in fix-log descriptions; later revision Solutions retain precedence.',
        '- MixBytes: multiline Status fields, explicit removal-at-commit dispositions and Almost all fixed qualifiers; ordinary removed prose is excluded.',
        '- Trail of Bits: wrapped PR annotations no longer suppress complete fix-log verdicts; native TOB-ID joins and explicit partial reviews retain precedence.',
        '- NCC: right-column Status metadata and finding-local dated Retest Results, with the later retest superseding the earlier card.',
        '- Pashov: inline bold Markdown status fields, preserving exact source spans and the legacy finding grammar.',
        '- Code4rena: separate-issue references, severity-disagreement suffixes and leading acknowledgement in attributed sponsor responses. Judge/warden responses and code blocks remain excluded.',
        '- Runtime Verification: the complete bounded response sentence, including wrapped commit/PR references, replaces first-line truncation.',
        '- PeckShield: exact status sentences replace detached verbs; empty fields retain valid ID-linked overview statuses, and lowercase compliance-table status cells cannot erase a real assertion. Footers, conclusions and checklists cannot supply a status sentence.',
        '- Verichains: title/status index rows now join the current title and its forward continuation lines, replacing the backward window that could use the preceding title. Duplicate titles remain ambiguous. The FCO PDF index was visually checked. Pessimistic’s real adjacent fixed/new/commented headers were checked and retained their own statuses; no speculative grammar change was applied.','',
        f"Recovered previously null source statuses: **{total('recovered_source')}**. Other/source assertion changes (including recoveries): **{total('changed_source')}**. "
        f"Canonical transitions: **{total('changed_status')}**, including **{total('resolver_only_changes')}** with unchanged source labels. "
        f"Finding identities added/removed: **{len(changes['added'])}/{len(changes['removed'])}**. "
        f"Previously known rows becoming not_stated: **{len(changes['lost_known'])}**; exact cases are in `comparison.json` and require the source-based interpretation described below.",'',
        '## not_stated by publisher','',
        '| Publisher | Rows before → after | not_stated before → after | Share before → after | Recovered source labels |',
        '|---|---:|---:|---:|---:|']
    for firm in sorted(set(before['by_firm'])|set(after['by_firm'])):
        a=before['by_firm'].get(firm,dict(rows=0,statuses={}))
        b=after['by_firm'].get(firm,dict(rows=0,statuses={}))
        na,nb=a['statuses'].get('not_stated',0),b['statuses'].get('not_stated',0)
        out.append(f"| {firm} | {a['rows']} → {b['rows']} | {na} → {nb} | {share(na,a['rows'])} → {share(nb,b['rows'])} | {changes['recovered_source'][firm]} |")
    out += ['', '## Verification and reproduction','',
        f"Full suite: **{tests['totals']['passed']} passed**, **{tests['totals']['subtests_passed']} subtests passed**, "
        f"{tests['totals']['failures']} failures, {tests['totals']['errors']} errors, {tests['totals']['skipped']} skips. "
        f"Full findings checker: **pass**, {checker['findings']:,} snapshot rows. Status checker: **pass**, {statuses['source_spans_verified']:,} exact source spans verified. Supplemental recall checker: **pass**.",'',
        f"Deterministic cold regeneration and independent replay: **{replay['files']} files with identical SHA-256 hashes**. "
        f"Manifest: `{replay['manifest_sha256']}`. The integration engine runs fresh isolated processes and empty bytecode caches; the first pass begins with an empty findings tree. Previous findings are preserved in `local-cache/phase4-status2/findings_before/`. The extraction snapshot, original files and cached source text are retained; there is no collection, OCR, model call, database build or network access in this task.",'',
        f"Holdout-list digest unchanged: `{after['holdout_list_sha256']}`. Held-out source documents/text opened: **0**. These are corpus coverage results and source-based regressions, not held-out accuracy measurements. Unsupported status assertions and bare administrative labels remain explicitly unmapped; no missing status is manufactured.",'',
        '```sh',
        'python3 -I -S scripts/findings/status2.py before  # once, before editing',
        'python3 -I -S scripts/findings/status2.py policy',
        'python3 -I -S scripts/findings/status2.py fixtures',
        'python3 -I -S scripts/findings/status2.py study',
        'python3 -I -S scripts/findings/status2.py review-new',
        'python3 -I scripts/findings/status2.py tests',
        'python3 -I scripts/findings/status2.py regenerate  # once',
        'python3 -I scripts/findings/status2.py replay',
        'python3 -I scripts/findings/status2.py checks',
        'python3 -I -S scripts/findings/status2.py after',
        'python3 -I -S scripts/findings/status2.py fallback-study',
        'python3 -I -S scripts/findings/status2.py report',
        '```','',
        'Commands, test membership, logs, before/after census, parser source fingerprints and per-file output hashes are retained in `local-cache/phase4-status2/`. All written source and substantive generated files are enumerated in `docs/phase4/status2_files_written.txt`; bytecode/test caches are excluded from that inventory. No commits or pushes.','',
        '## Baseline distinct unmapped labels','',
        'JSON quoting preserves original newlines, punctuation and Unicode; counts aggregate identical verbatim strings across publishers. Per-publisher counts and resolution receipts are in the CSV/JSON inventories.','',
        '| status_original (verbatim JSON string) | Rows | Publishers |','|---|---:|---|']
    labels=defaultdict(Counter)
    for row in before['unmapped']:labels[row['status_original']][row['publisher']]+=row['count']
    for raw,counts in sorted(labels.items()):
        value=json.dumps(raw,ensure_ascii=False).replace('|','&#124;').replace('`','&#96;')
        out.append(f"| {value} | {sum(counts.values())} | {', '.join(f'{f}: {n}' for f,n in sorted(counts.items()))} |")
    (ROOT/'docs/phase4/status2.md').write_text('\n'.join(out)+'\n')
    import integration as integration
    sources=['schema/status_map.json','schema/status_map.json','scripts/findings/status_resolve.py',
        'scripts/findings/status_map_build.py','scripts/findings/status_families.py','scripts/findings/status_sentences.py',
        'scripts/findings/status2.py','scripts/findings/test_status2.py','scripts/findings/fixtures/status2.json',
        'docs/phase4/status2.md','docs/phase4/status2_files_written.txt']
    sources += ['scripts/findings/parsers/'+f.replace('-','_')+'.py' for f in TARGETS if f!='pessimistic']
    generated=list(integration.fingerprints())+['data/findings/check.json','data/findings/status_check.json',
        'data/fulltext/extractions.jsonl','data/fulltext/failures.jsonl','data/fulltext/summary.json',
        'local-cache/phase4-status2/findings_before/severity_canon/cache_sync.json']
    generated += [str(p.relative_to(ROOT)) for p in LOCAL.rglob('*') if p.is_file()
                  and not any(part.startswith('bytecode-') or part=='findings_before' for part in p.relative_to(LOCAL).parts)]
    (ROOT/'docs/phase4/status2_files_written.txt').write_text('\n'.join(sorted(set(sources+generated)))+'\n')
    print(json.dumps(dict(before_rows=before['rows'],after_rows=after['rows'],
        unmapped_before=before['unmapped_distinct_labels'],unmapped_after=after['unmapped_distinct_labels'],
        recovered_source=total('recovered_source'),changed_status=total('changed_status')),indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('before', 'after', 'inspect', 'source', 'policy', 'bindings', 'study', 'fallback-study', 'fixtures', 'review-new', 'compare', 'report', 'tests',
                                          'regenerate', 'resume', 'replay', 'checks'))
    parser.add_argument('--firm', choices=TARGETS)
    parser.add_argument('--pattern', default=r'\b(?:status|fixed|resolved|acknowledged|addressed|mitigated|confirmed|partially)\b')
    parser.add_argument('--limit', type=int, default=6)
    parser.add_argument('--include-known', action='store_true')
    parser.add_argument('--sha')
    args = parser.parse_args()
    if args.command == 'compare':
        result=comparison()
        print(json.dumps(result['lost_known'],ensure_ascii=False,indent=2))
    elif args.command == 'report':
        report_results()
    elif args.command == 'review-new':
        review_new()
    elif args.command == 'fixtures':
        fixtures()
    elif args.command == 'study':
        study()
    elif args.command == 'fallback-study':
        fallback_study()
    elif args.command == 'bindings':
        binding_audit()
    elif args.command == 'source':
        assert args.sha and args.sha not in holdouts(), 'Holdout text denied'
        assert re.fullmatch('[0-9a-f]{64}', args.sha)
        text = (ROOT/'local-cache/fulltext'/(args.sha+'.txt')).read_text()
        for hit in list(re.finditer(args.pattern, text, re.I))[:args.limit]:
            print(hit.start(), repr(text[max(0,hit.start()-200):hit.end()+700]))
    elif args.command == 'policy':
        from status_families import GENERIC_FALLBACK
        path = ROOT/'schema/status_map.json'
        policy = json.loads(path.read_text())
        policy['generic_fallback'] = GENERIC_FALLBACK
        payload = json.dumps(policy, ensure_ascii=False, indent=2, sort_keys=True)+'\n'
        for suffix in ('yaml', 'json'):
            (ROOT/'schema'/('status_map.'+suffix)).write_text(payload)
    elif args.command in ('before', 'after'):
        save_census(args.command)
    elif args.command == 'inspect':
        inspect(args.firm, args.pattern, args.limit, not args.include_known)
    else:
        import integration as integration
        integration.LOCAL = LOCAL
        if args.command == 'tests':
            integration.tests('/usr/bin/python3')
        elif args.command == 'checks':
            for name, arguments in (
                    ('findings_check', ['scripts/findings/check.py']),
                    ('status_check', ['scripts/findings/check.py', '--statuses-only']),
                    ('recall_check', ['scripts/findings/recall_push.py', '--verify'])):
                integration.command(name, arguments)
        else:
            getattr(integration, args.command)()


if __name__ == '__main__':
    main()
