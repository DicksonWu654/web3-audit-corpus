#!/usr/bin/env python3
"""Deterministically rebuild firms.csv and the research note from frozen evidence.

Requires pyarrow (reading the supplied Parquet only); no network calls.
python3 -I scripts/registry/build.py
"""
import collections
import csv
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'data/registry'
FIELDS = ['firm_id','name','aliases','website','kind','github_reports_url','website_reports_url',
          'other_reports_url','formats','est_public_report_count','count_evidence_url','count_method',
          'first_report_year','status','chains_focus','in_existing_corpus','existing_corpus_reports',
          'checked_utc','notes']

def norm(s):
    return re.sub(r'[^a-z0-9]', '', (s or '').lower())

def urlkey(u):
    u = urllib.parse.unquote(u or '').replace('http://','https://').rstrip('/')
    u = u.replace('www.sourcehat.com','sourcehat.com').replace('solidity.finance','sourcehat.com')
    u = re.sub(r'(github\.com/[^/]+/[^/]+)/(?:blob|raw)/[^/]+/', r'\1/blob/HEAD/', u)
    u = re.sub(r'raw\.githubusercontent\.com/([^/]+/[^/]+)/[^/]+/',r'github.com/\1/blob/HEAD/',u)
    return u.split('?')[0].split('#')[0]

def stem(p):
    p = urllib.parse.unquote(p).lower()
    p = re.sub(r'/(?:pdf|md|markdown)/','/',p)
    return re.sub(r'\.(?:pdf|md|html)$','',p)

def selected_paths(c, o):
    rows = []
    allowed = None
    if c.get('report_selection') == 'trailofbits':
        allowed = set()
        for rd in o.get('readmes',[]):
            t = rd.get('text','')
            # Explicit blockchain category and the named blockchain major clients.
            parts = re.findall(r'#### (?:Frax Finance|MobileCoin|Offchain Labs|Reserve Protocol|Scroll|Uniswap)\n(.*?)(?=\n#{2,4} |\Z)', t, re.S)
            parts += re.findall(r'### Blockchain Reviews\n(.*?)(?=\n## |\Z)', t, re.S)
            for block in parts:
                for p in re.findall(r'\]\(([^)]+\.pdf)\)', block, re.I):
                    p=urllib.parse.unquote(p)
                    m=re.search(r'/reviews/(.*)',p)
                    allowed.add('reviews/'+m[1] if m else p.lstrip('./'))
    for tree in o.get('trees',[]):
        if tree.get('status') != 200:
            continue
        for f in tree.get('tree',[]):
            p = f['path']; low=p.lower()
            if re.search(r'(?:^|/)(?:readme|changelog|contributing|license|summary|reports|findings)\.md$',low):
                continue
            if re.search(r'(?:^|/)(?:node_modules|\.git|templates?|assets|images|presentations|slides|papers|logos|training|ctf|first.?flights?)(?:/|\.)',low):
                continue
            if re.search(r'(?:checklist|research_portfolio|audit-template|report-template|certificate|kyc)',low):
                continue
            if allowed is not None:
                accept = p in allowed
            elif c.get('report_path_pattern'):
                accept = bool(re.search(c['report_path_pattern'], p, re.I))
            else:
                accept=low.endswith('.pdf') or bool(re.search(r'(?:^|/)(?:reports?|audits?)/[^/]+\.md$',low))
                # Explicitly named complete Markdown reports, not finding submissions.
                accept=accept or bool(re.search(r'[^/]*(?:audit[-_ ]report|security[-_ ]review|final[-_ ]report)[^/]*\.md$',low))
            if not accept:
                continue
            rows.append(dict(f, repo=tree['repo'],tree_sha=tree['sha'],
                             url='https://github.com/'+tree['repo']+'/blob/'+tree.get('commit','HEAD')+'/'+urllib.parse.quote(p)))
    # Exact same blobs in rebrand/mirror repositories counted once. A PDF/Markdown
    # rendering with identical relative stem is also one report, not two.
    rows.sort(key=lambda r:(0 if r['path'].lower().endswith('.pdf') else 1,r['repo'],r['path']))
    blobs={};stems={};out=[]
    for r in rows:
        k=stem(r['path'])
        if c['firm_id']=='electisec':
            # The site stores Markdown under content/ and PDFs under public/pdf/,
            # with a publisher suffix and minor punctuation differences.
            k=norm(Path(r['path']).stem)
            k=re.sub(r'(?:yaudit|electisec)report$','',k)
        ext=Path(r['path']).suffix.lstrip('.').lower()
        existing=blobs.get(r['sha']) or stems.get(k)
        if existing is not None:
            existing['formats']=sorted(set(existing['formats']+[ext]))
            continue
        r['formats']=[ext]
        blobs[r['sha']]=r;stems[k]=r;out.append(r)
    return sorted(out,key=lambda r:(r['repo'],r['path']))

def read_corpus(candidates, counts):
    path=ROOT/'extracted/audit_analysis/parquet/reports.parquet'
    table=pq.read_table(path)
    rows=table.to_pylist()
    aliases={};repos={};hosts={};basenames=collections.defaultdict(set)
    for c in candidates:
        fid=c['firm_id']
        for s in [c['firm_id'],c['name']]+c.get('aliases','').split(';'):
            if s:aliases[norm(s)]=fid
        for rp in c.get('repos',[]):repos[rp.lower()]=fid
        for k in ['website','website_reports_url']:
            host=urllib.parse.urlsplit(c.get(k,'')).hostname or ''
            if host and not any(x in host for x in ['github','medium.com','notion','google','x.com','twitter']):
                hosts[host.removeprefix('www.')]=fid
        for r in counts[fid]['items']:
            if r.get('path'):
                bn=urllib.parse.unquote(Path(r['path']).name).lower()
                if len(norm(bn))>=18 and bn not in ['smart contract audit report.pdf','audit report.pdf','report.pdf','audit.pdf']:
                    basenames[bn].add(fid)
    manual={'abdk':'abdk-consulting','ackee':'ackee-blockchain','informal':'informalsystems',
            'sigmaprime':'sigma-prime','runtimeverification':'runtime-verification','oaksecurity':'oak-security',
            'pashov':'pashov-audit-group','yaudit':'electisec','teamomega':'teamomega','verilog':'verilog-solutions',
            'consensys':'consensys-diligence','paladin':'paladinsec','hatsfinance':'hats-finance',
            'shieldifysecurity':'shieldify','cdsecurity':'cd-security','trailofbits':'trail-of-bits',
            'enigmadark':'enigma-dark','dapporg':'dapp-org'}
    aliases.update(manual)
    matched=collections.defaultdict(list);reason=collections.Counter();unattributed=collections.Counter()
    for r in rows:
        try:raw=json.loads(r.get('raw_record_json') or '{}')
        except ValueError:raw={}
        if not isinstance(raw,dict):raw={}
        fid=None;why=None
        # Prefer real report URLs over a collector's source label.
        urls=[r.get('report_url'),raw.get('report_url'),raw.get('download_url'),raw.get('raw_url')]
        for u in urls:
            if not isinstance(u,str) or not u.startswith('http'):continue
            parsed=urllib.parse.urlsplit(u);parts=urllib.parse.unquote(parsed.path).strip('/').split('/')
            if 'github' in parsed.netloc and len(parts)>=2:
                rp='/'.join(parts[:2]).lower()
                if rp in repos:fid=repos[rp];why='publisher_report_repository';break
            host=(parsed.hostname or '').removeprefix('www.')
            if host in hosts:fid=hosts[host];why='publisher_report_domain';break
        if not fid:
            # Auditor is supported for future schema revisions; today's file uses publisher.
            labels=[r.get('auditor'),raw.get('auditor'),r.get('publisher'),raw.get('publisher')]
            for label in labels:
                if isinstance(label,str) and norm(label) in aliases:
                    fid=aliases[norm(label)];why='explicit_auditor_or_publisher';break
        if not fid and r['source']=='shenyimings/FORGE-Artifacts':
            bn=urllib.parse.unquote((r.get('source_record_id') or '').rsplit('/',1)[-1])
            bn=re.sub(r'\.json$','',bn).lower()
            if len(basenames.get(bn,set()))==1:fid=next(iter(basenames[bn]));why='unique_report_filename_in_publisher_tree'
        if not fid and norm(r['source']) in aliases and r['source'] not in ['monethic','nearbuilders','anza-xyz','sui-foundation']:
            fid=aliases[norm(r['source'])];why='direct_publisher_source'
        if fid in counts:
            matched[fid].append(dict(r,match_method=why));reason[why]+=1
        else:unattributed[r['source']]+=1
    info={'parquet_rows':len(rows),'parquet_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
          'schema_has_auditor':'auditor' in table.column_names,'schema_has_publisher':'publisher' in table.column_names,
          'attribution_methods':dict(sorted(reason.items())),'unattributed_by_source':dict(sorted(unattributed.items()))}
    seed_counts=json.loads((ROOT/'extracted/audit_analysis/exports/coverage.json').read_text())
    assert seed_counts['counts']['reports']==len(rows),'Parquet/seed coverage mismatch'
    info['coverage_json_report_rows']=seed_counts['counts']['reports']
    info['seed_sha256']={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in [ROOT/'extracted/audit_analysis/exports/source_registry.json',
                                  ROOT/'extracted/audit_analysis/exports/coverage.json']}
    return matched,info


def main():
    candidates=json.loads((ROOT/'scripts/registry/candidates.json').read_text())
    observations={r['firm_id']:r for r in map(json.loads,(DATA/'observations.jsonl').read_text().splitlines())}
    listings={r['firm_id']:r for r in json.loads((DATA/'listings.json').read_text())}
    counts={};out=[]
    for c in candidates:
        fid=c['firm_id'];o=observations.get(fid,{})
        items=selected_paths(c,o)
        count={'firm_id':fid,'method':'counted_repo_files' if items else '', 'items':items}
        if c.get('count_exclude'):count.update(method='',items=[])
        # Listing records can include publisher-approved reports hosted outside GitHub.
        if fid in listings and len(listings[fid]['items'])>=len(count['items']):
            count.update(method='counted_listing',items=listings[fid]['items'],pages=listings[fid]['pages'],scope=listings[fid]['scope'])
        counts[fid]=count
    matched,corpus_info=read_corpus(candidates,counts)
    coverage=collections.Counter();status_stats=collections.Counter();kind_stats=collections.Counter()
    for c in candidates:
        fid=c['firm_id'];o=observations.get(fid,{});count=counts[fid];n=len(count['items'])
        r={f:c.get(f,'') for f in FIELDS};r['aliases']=';'.join(dict.fromkeys(filter(None,c.get('aliases','').split(';'))))
        notes=[c.get('notes','').strip()]
        for key in ['github_reports_url','website_reports_url','other_reports_url']:
            # Preserve source URLs even when inaccessible, with status in notes.
            notes.extend('HTTP '+str(u['status'])+': '+u['url'] for u in o.get('urls',[]) if u['field']==key and u['status']!=200)
        good_trees=[t for t in o.get('trees',[]) if t.get('status')==200]
        good_urls=[u for u in o.get('urls',[]) if u['status']==200]
        good_listing=listings.get(fid)
        if good_listing:
            good_urls += good_listing['pages']
            evidence=good_listing['pages'][0]['url']
            # API/CSV listing is itself a valid report-discovery source.
            if evidence not in [r.get(k) for k in ['github_reports_url','website_reports_url','other_reports_url']]:
                r['other_reports_url']=evidence
        if not good_trees and not good_urls:
            notes.append('No report URL verified HTTP 200 today; report source unavailable at the checked locations. See recorded HTTP/DNS failures; availability does not establish that the provider is defunct.')
        if n:
            r['est_public_report_count']=n;r['count_method']=count['method']
            if count['method']=='counted_listing':
                r['count_evidence_url']=count['pages'][0]['url'];notes.append(count.get('scope',''))
            else:
                repos=sorted(set(i['repo'] for i in count['items']))
                r['count_evidence_url']=';'.join('https://api.github.com/repos/'+rp+'/git/trees/'+next(t['sha'] for t in good_trees if t['repo']==rp)+'?recursive=1' for rp in repos)
                notes.append('Measured report artifacts at current tree; identical blobs and matching PDF/MD stems counted once. Versions/translations may remain.')
        else:
            r['est_public_report_count']='';r['count_method']='';r['count_evidence_url']=''
            notes.append('Public-report total unknown; blank is not zero. Marketing audit/client totals are not substituted.')
        formats=set()
        for i in count['items']:
            ext=(i.get('path') or urllib.parse.urlsplit(i['url']).path).rsplit('.',1)[-1].lower()
            formats.update(i.get('formats',[i.get('format') or (ext if ext in ['pdf','md','html'] else 'html')]))
        if c.get('formats'):formats.update(c['formats'].split(';'))
        if formats:r['formats']=';'.join(f for f in ['pdf','md','html'] if f in formats)
        elif good_urls and any('pdf' in u.get('content_type','') or '.pdf' in u['url'] for u in good_urls):r['formats']='pdf'
        # Earliest observed report date, never the company's founding year.
        years=[]
        for i in count['items']:
            text=(i.get('path') or '')+' '+(i.get('date') or '')
            years.extend(int(y) for y in re.findall(r'(?<![A-Za-z0-9])(20[01]\d|202[0-6])(?![A-Za-z0-9])',text))
            m=re.search(r'(?:^|/)(2[0-6])-\d\d-\d\d',text)
            if m:years.append(2000+int(m[1]))
        if years:r['first_report_year']=min(years)
        if r.get('first_report_year'):notes.append('first_report_year is earliest dated report observed, not a claim of the first engagement.')
        readme='\n'.join(m.get('text','') for m in o.get('readmes',[]))
        if not r['chains_focus']:
            focus=[]
            for name,pat in [('EVM',r'\b(?:EVM|Solidity|Ethereum)\b'),('Solana',r'\bSolana\b'),('Cosmos',r'\b(?:Cosmos|CosmWasm)\b'),('NEAR',r'\bNEAR\b'),('Sui',r'\bSui\b'),('Aptos',r'\bAptos\b'),('Starknet',r'\b(?:Starknet|Cairo)\b'),('TON',r'\b(?:TON|FunC|Tact)\b'),('Bitcoin',r'\bBitcoin\b'),('Polkadot',r'\b(?:Polkadot|Substrate)\b'),('Stellar',r'\b(?:Stellar|Soroban)\b'),('Tezos',r'\bTezos\b'),('Algorand',r'\bAlgorand\b')]:
                if re.search(pat,readme):focus.append(name)
            r['chains_focus']=';'.join(focus)
        if r['chains_focus']:notes.append('Chain focus reflects explicit portfolio/README mentions; not an exhaustive capability claim.')
        # Current dated output is evidence of activity, not legal corporate status.
        if not c.get('status') or c['status']=='unknown':r['status']='active' if 2026 in years else 'unknown'
        if r['status']=='active':notes.append('Active inferred from a dated current-year report; legal ownership/status not independently certified.')
        existing=matched.get(fid,[]);r['existing_corpus_reports']=len(existing)
        oldkeys={urlkey(x.get('report_url')) for x in existing if x.get('report_url')}
        newkeys={urlkey(x['url']) for x in count['items']}
        overlap=len(oldkeys & newkeys)
        if not existing:r['in_existing_corpus']='no'
        elif newkeys and overlap==len(newkeys):r['in_existing_corpus']='yes'
        else:r['in_existing_corpus']='partial'
        if existing:notes.append(f"Existing corpus: {len(existing)} raw rows; {len(oldkeys)} distinct nonempty report URLs after Git revision/domain normalization; {overlap} current source identifiers matched. Raw rows are not unique audits.")
        else:notes.append('No attributable Parquet rows found; unattributed legacy extraction rows may still contain this publisher.')
        dates=[u['checked_utc'] for u in good_urls+good_trees if u.get('checked_utc')]
        if not dates:dates=[u['checked_utc'] for u in o.get('urls',[]) if u.get('checked_utc')]
        r['checked_utc']=max(dates) if dates else ''
        notes.append('Discovery: '+';'.join(c.get('discovery_sources',[])))
        r['notes']=' '.join(dict.fromkeys(n for n in notes if n))
        counts[fid]['current_corpus_identifiers_matched']=overlap
        counts[fid]['existing_corpus_rows']=len(existing)
        counts[fid]['existing_attribution_methods']=dict(collections.Counter(x['match_method'] for x in existing))
        hasgh=bool(good_trees)
        hassite=any('github.com/' not in u['url'] and 'githubusercontent.com/' not in u['url'] for u in good_urls)
        bucket=('GitHub repository (with or without website)' if hasgh else
                'Website/API only' if hassite else
                'GitHub organization or report mirror only' if good_urls else 'No verified report source')
        coverage[bucket]+=1;status_stats[r['in_existing_corpus']]+=1;kind_stats[r['kind']]+=1
        out.append(r)
    out.sort(key=lambda r:r['firm_id'])
    with (ROOT/'registry/firms.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=FIELDS);w.writeheader();w.writerows(out)
    (DATA/'counts.jsonl').write_text(''.join(json.dumps(counts[k],ensure_ascii=False,sort_keys=True)+'\n' for k in sorted(counts)))
    ranked=sorted([r for r in out if r['est_public_report_count']!=''],key=lambda r:(-r['est_public_report_count'],r['firm_id']))
    measured=[r for r in ranked if r['count_method'] in ['counted_repo_files','counted_listing']]
    # Solo portfolios often republish their firm's reports; bounty submissions are not audits.
    industry=[r for r in ranked if r['kind'] in ['firm','collective','contest_platform']]
    raw_total=sum(r['est_public_report_count'] for r in industry)
    blobs=[i['sha'] for r in industry for i in counts[r['firm_id']]['items'] if i.get('sha')]
    duplicate_blobs=len(blobs)-len(set(blobs))
    baseline=raw_total-duplicate_blobs
    # Explicit sensitivity assumptions, NOT a statistical confidence interval.
    # Allow revisions/translations, unmeasured large directories, and missing long-tail publishers.
    scenarios={
        'low':{'artifact_retention':0.75,'unmeasured_large_publishers':4000,'unseen_long_tail':1000},
        'central':{'artifact_retention':0.85,'unmeasured_large_publishers':8000,'unseen_long_tail':3000},
        'high':{'artifact_retention':0.95,'unmeasured_large_publishers':16000,'unseen_long_tail':8000},
    }
    for s in scenarios.values():s['reports']=round((baseline*s['artifact_retention']+s['unmeasured_large_publishers']+s['unseen_long_tail'])/1000)*1000
    missing=[r for r in ranked if r['in_existing_corpus']=='no' and r['kind'] in ['firm','collective']][:40]
    stats={'rows':len(out),'kinds':dict(kind_stats),'source_coverage':dict(coverage),
           'corpus_coverage':dict(status_stats),'measured_rows':len(measured),
           'top60_measured':sum(r['count_method'] in ['counted_repo_files','counted_listing'] for r in ranked[:60]),
           'all_measured_artifacts':sum(r['est_public_report_count'] for r in ranked),
           'publisher_artifact_sum':raw_total,'cross_publisher_identical_blobs':duplicate_blobs,
           'publisher_artifact_baseline':baseline,'industry_scenarios':scenarios,
           'top40_absent_firms':len(missing),'corpus':corpus_info}
    (DATA/'summary.json').write_text(json.dumps(stats,indent=2,sort_keys=True)+'\n')
    write_note(out,ranked,missing,stats,counts)
    print(json.dumps(stats,indent=2,sort_keys=True))


def write_note(rows,ranked,missing,s,counts):
    discovery=json.loads((DATA/'discovery.json').read_text())
    date=max(r['checked_utc'][:10] for r in rows if r['checked_utc'])
    lines=[f'# Web3 auditing publisher census — {date}', '',
      f'The registry contains **{s["rows"]} publishers and auditor portfolios**. **{s["top60_measured"]} of the highest 60 numeric report counts are measured** from current repository trees or public listing records. Counts are report artifacts, not a verified number of unique audit engagements. Blank counts mean unknown, not zero.', '',
      'The census is a discovery frame, not a ranking of audit quality or an assertion of completeness. Provider brands, solo auditors, collectives, contest platforms and bounty platforms are explicitly distinguished. Source availability was checked on the date above. A failed endpoint is retained with its failure in notes, rather than treated as evidence that a firm is defunct.', '',
      '## Sources and method','',
      '1. Read the supplied `source_registry.json`, `coverage.json` and every report row in `reports.parquet`. The current Parquet schema has `publisher`, not `auditor`; the builder supports embedded auditor fields, publisher labels and report domains/repositories. Unique, sufficiently specific report filenames can link otherwise unattributed FORGE records to a measured publisher tree. No code in `extracted/` was run.',
      '2. Search the live web and GitHub repository search for publisher archives (`audits`, `reports`, `publications`) and solo portfolios. The community lists are discovery leads; sources are checked independently. Rebrands and duplicates are merged with aliases. The KALOS README explicitly identifies the previous HAECHI AUDIT brand. Electisec/yAudit, Softstack/Chainsulting and SourceHat/Solidity Finance are kept as single publishers.',
      f'3. Snapshot [DeFiLlama protocols](https://api.llama.fi/protocols): {len(discovery["defillama"]["protocols"]):,} protocol records. The bulk endpoint exposes the audit flag but did not expose audit links in this snapshot. Query the first {len(discovery["defillama-details"]["items"])} audited protocol detail records in API order for `audit_links`; retain all returned links as discovery evidence. These client-side archives supplement publisher sources but are not counted as auditing firms.',
      '4. Use anonymous `curl` GETs with redirects, recording UTC timestamp, HTTP status, final URL, content type, byte count and SHA-256. GitHub recursive tree API results are used only if untruncated; a clean-config bare filtered Git retrieval supplies complete trees when the anonymous API is unavailable. No remote code, project configuration, hooks, dependency installers or JavaScript was executed. A successful URL check establishes accessibility, not report quality or redistribution rights.',
      '5. Count report PDFs and explicitly identified Markdown/HTML reports. Exclude README files, findings submissions, templates, logos, papers, presentations, KYC certificates and training paths. Use publisher-specific path restrictions for mixed repositories, including Trail of Bits blockchain README sections and SRLabs blockchain folders. Deduplicate identical Git blobs across a publisher’s repositories and identical PDF/Markdown filename stems. Distinct report revisions and translations may remain. Preserve the selected paths/blob IDs in `data/registry/counts.jsonl`.',
      '6. Measure website publishers separately: enumerate every SourceHat project page and its nested public reports; enumerate every Quantstamp certificate page; count Hacken API report links excluding proof of reserves; count unique Omniscia report URLs from the site’s clients CSV; count public report links on ChainSecurity, Cantina and Neodyme listings; decode published Code4rena report objects and OpenZeppelin entries explicitly categorized Security Audits; count stable OtterSec report links and report cells in Spearbit’s portfolio tables. Embedded JSON is parsed without executing JavaScript. Counts for sampled listings are lower bounds on what the publisher may have released elsewhere. Repository and listing totals are never simply added for the same firm.', '',
      'Primary and discovery sources (accessed '+date+'):', '',
      '- [0xNazgul Blockchain Security Audit List](https://github.com/0xNazgul/Blockchain-Security-Audit-List) and [solo audit report list](https://github.com/chinmay-farkya/solo-audit-reports). Historical lists can contain dead links; inclusion is not a current endorsement.',
      '- [DeFiLlama API](https://api.llama.fi/protocols) and per-protocol `https://api.llama.fi/protocol/{slug}` responses; [GitHub repository search](https://github.com/search?q=audits&type=repositories), with result metadata frozen in discovery evidence.',
      '- [Hacken public Audits API documentation](https://docs.hacken.io/rest-apis/get-audits/), [Hacken records](https://hacken.io/api/audits), [Quantstamp certificates](https://certificate.quantstamp.com/), [SourceHat audit API](https://api.sourcehat.com/audit_list/?all=1), [Omniscia listing data](https://omniscia.io/assets/data/clients.csv).',
      '## Coverage','', '| Verified report-source category | Publishers |','|---|---:|']
    for k in ['GitHub repository (with or without website)','Website/API only','GitHub organization or report mirror only','No verified report source']:lines.append(f'| {k} | {s["source_coverage"].get(k,0)} |')
    lines += ['', 'The repository category requires a successfully enumerated tree. Organization/profile pages and third-party report mirrors are separate discovery sources, not evidence of a verified publisher repository.']
    lines += ['', '| Kind | Rows |','|---|---:|']
    for k,v in sorted(s['kinds'].items()):lines.append(f'| {k} | {v} |')
    lines += ['',f'Numeric measured counts: **{s["measured_rows"]}**. Existing-corpus status: '+', '.join(f'**{v} {k}**' for k,v in sorted(s['corpus_coverage'].items()))+'.', '',
      f'The supplied Parquet has **{s["corpus"]["parquet_rows"]:,} raw report rows**. Attribution matched **{sum(s["corpus"]["attribution_methods"].values()):,}** rows; **{sum(s["corpus"]["unattributed_by_source"].values()):,}** remain unattributed. `existing_corpus_reports` is the exact number of attributed Parquet rows, including metadata-only rows and duplicates. It is not a unique-report or acquired-PDF count. Some collector labels describe the collector rather than the report’s author; report-source identity takes precedence.', '',
      '`yes` means every identifier in the measured current source is present among normalized corpus report URLs; `partial` means at least one row is attributable but current-source completeness is not established; `no` means no attributable row. An absence is provisional because unattributed legacy records can hide a firm. Git revision URLs and the Solidity Finance/SourceHat domains are normalized for comparison. Solo auditors can appear within platform or firm reports already in the corpus.', '',
      '`first_report_year` is the earliest report date observed in counted paths or listing records. Undated repositories remain blank; years are not inferred from founding dates. `status=active` is inferred only when a counted report carries the current year; otherwise legal status is left unknown unless separately established. `chains_focus` records explicit public portfolio mentions; blank means not established.', '',
      '## Industry-wide public report estimate','',
      f'The measured entries contain **{s["all_measured_artifacts"]:,}** report artifacts including solo portfolios. Restricting to firms, collectives and contest platforms gives **{s["publisher_artifact_sum"]:,}**; removing **{s["cross_publisher_identical_blobs"]:,}** identical Git blobs shared across those publishers leaves a working observed baseline of **{s["publisher_artifact_baseline"]:,}**. This is neither an exact unique-engagement total nor a strict industry lower bound: residual revisions, translations, mixed-scope material and reposts can inflate it, while private reports, removed reports and undiscovered sources are absent.', '',
      f'A provisional industry estimate is **about {s["industry_scenarios"]["central"]["reports"]:,} public security audit reports**, with a sensitivity range of **{s["industry_scenarios"]["low"]["reports"]:,}–{s["industry_scenarios"]["high"]["reports"]:,}**. This is a planning scenario, **not a statistical confidence interval**. The assumptions below are explicit analyst choices, not measurements of the missing population. They account for missing publishers and artifact duplication.', '',
      '| Scenario | Retain observed artifacts | Unmeasured large publishers | Unseen long tail | Rounded report estimate |','|---|---:|---:|---:|---:|']
    for name,a in s['industry_scenarios'].items():lines.append(f'| {name} | {a["artifact_retention"]:.0%} | {a["unmeasured_large_publishers"]:,} | {a["unseen_long_tail"]:,} | {a["reports"]:,} |')
    lines += ['', 'Formula: `round_to_1000(observed_baseline × retention + unmeasured_large_publishers + unseen_long_tail)`. Solo portfolio counts and bounty findings are excluded from this estimate because they frequently duplicate commissioned or contest reports. This census cannot justify a narrower uncertainty interval without report-level deduplication, systematic sampling of unknown publishers and enumeration of the remaining large directories.', '',
      '## Highest-yield firms absent from attributable corpus rows','',
      'Ranked by measured accessible report artifacts. These are firms and collectives with `in_existing_corpus=no`, not contest or bounty platforms. Lower-ranked candidates can have substantial undated or unlisted work; no count is guessed. The absence caveat above applies to every row.', '',
      '| Rank | Firm | Measured reports | Method | Report source |','|---:|---|---:|---|---|']
    for i,r in enumerate(missing,1):
        u=r['github_reports_url'] or r['website_reports_url'] or r['other_reports_url']
        lines.append(f'| {i} | {r["name"]} | {r["est_public_report_count"]:,} | {r["count_method"]} | [source]({u}) |')
    lines += ['', '## Highest measured counts','', '| Rank | Publisher | Kind | Count | Count evidence |','|---:|---|---|---:|---|']
    for i,r in enumerate(ranked[:60],1):lines.append(f'| {i} | {r["name"]} | {r["kind"]} | {r["est_public_report_count"]:,} | [evidence]({r["count_evidence_url"].split(";")[0]}) |')
    gaps=[r for r in rows if 'No report URL verified HTTP 200 today' in r['notes']]
    lines += ['', '## Availability and remaining gaps','',
      'The following rows have no report source that returned HTTP 200 in the recorded checks. Notes preserve each failed lead. They remain in the frame because historical firm lists or public portfolios establish the auditor identity; availability and legal operating status should be revisited before acquisition.', '', '| Publisher | Checked lead |','|---|---|']
    for r in gaps:
        u=r['github_reports_url'] or r['website_reports_url'] or r['other_reports_url'] or r['website']
        lines.append(f'| {r["name"]} | [lead]({u}) |')
    lines += ['', 'The frame undercovers regional/non-English firms, closed or acquired practices, small solo auditors without public standalone reports, client-only publication and recently launched auditors. It deliberately omits protocol foundations and client audit archives as firm rows. General security consultancies and economic-risk providers are flagged in notes; their full research libraries are not counted as Web3 audits. Immunefi Markdown submissions are individual findings and are not counted as audit reports. No claim is made that every report link inside a reachable listing is itself downloadable.', '',
      '## Reproduction','',
      'Install `pyarrow` in an isolated environment for the build (the collection scripts use only the Python standard library plus host curl/Git). Then:', '',
      '```sh', 'python3 -I scripts/registry/prepare.py', 'python3 -I scripts/registry/build.py', 'python3 -I scripts/registry/validate.py', '```', '',
      'Those commands replay frozen evidence and are deterministic. A live refresh uses `collect.py --refresh --cache local-cache/tmp/new-registry-cache` and `measure_listings.py`; `collect.py --only firm-id --refresh` limits a recheck. Existing curl cache entries preserve their original access timestamps, so use a new cache directory for a fresh date. Inspect changed publisher identities, aliases and path rules before publishing a refreshed registry. Anonymous API limits and HTTP throttles must be respected; no account credentials are required.', '',
      'Evidence lives outside `docs/` and `registry/`: `discovery.json` holds discovery leads, `observations.jsonl` holds HTTP/tree observations, `listings.json` holds enumerated listing URLs, `counts.jsonl` holds the exact selected artifacts and `summary.json` holds all generated statistics. The original `extracted/` inputs remain untouched. Public accessibility does not establish permission to redistribute report originals.', '']
    (ROOT/'docs/research/firm_registry.md').write_text('\n'.join(lines))

if __name__=='__main__':main()
