#!/usr/bin/env python3
"""Build the curated CSV and research inventory table from captured measurements.

Offline: python3 -I scripts/aggregators/build_registry.py
Checks:  python3 -I scripts/aggregators/build_registry.py --check
Editorial facts are intentionally separate from network collection. Review them
when refreshing measurements; a changed number does not refresh legal analysis.
"""
import argparse
import collections
import csv
import io
import json
import pathlib
import re

HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
D=json.loads((HERE/'derived_measurements.json').read_text())
R=json.loads((HERE/'repo_measurements.json').read_text())
U=json.loads((HERE/'urls.json').read_text())
DAY='2026-10-20'
GH_RATE='GitHub REST unauthenticated core 60 requests/hour/IP; search has a separate lower bucket (observed 10/minute). Honor response headers and pagination; clone/raw delivery have separate abuse controls.'
UNKNOWN_RATE='No numeric public limit verified. Use a small cached crawl, honor robots/terms and Retry-After, and stop on 401/403/429; request a bulk export for scale.'
HF_RATE='Hugging Face Hub/API, resolver and dataset-viewer use separate plan-dependent buckets; honor RateLimit/Retry-After. No fixed limit verified for this dataset.'
NO_LICENSE='No root content redistribution licence found in the inspected source. Public access is not a republication grant; third-party reports retain their own rights.'
rows=[]

def add(id,name,url,owner,kind,*,size='',unit='',status='measured',method='',key='',
        dates='Not established; do not infer from upload time.',firms='Not established.',
        fields='',originals='',access='',rate=UNKNOWN_RATE,terms=NO_LICENSE,
        mirror='link_and_summarize',updated='No source-wide update timestamp exposed; accessed '+DAY,
        quality='',priority='supplement',evidence='',reason='',date_origin=''):
    rows.append(dict(source_id=id,name=name,url=url,maintainer=owner,source_kind=kind,
        measured_size=size,size_unit=unit,size_status=status,unmeasured_reason=reason,
        measurement_method=method,measurement_key=key,accessed_at=DAY,
        date_coverage=dates,date_origin=date_origin,firm_coverage=firms,fields_available=fields,
        originals_included=originals,access_method=access,rate_limits=rate,
        licence_and_terms=terms,public_release_policy=mirror,last_updated=updated,
        quality_issues=quality,ingestion_priority=priority,evidence_urls=evidence or url))

def repo_row(id,name,repo,kind,**kw):
    d=R[repo]
    kw.setdefault('updated',d.get('commit_date','Unknown: GitHub API rate limited; see measurement snapshot.'))
    kw.setdefault('access','Read-only GitHub REST trees and raw files; git clone possible, but no repository code was run.')
    kw.setdefault('rate',GH_RATE)
    kw.setdefault('method','Pinned GitHub API tree; count blob paths in the stated subtree, never repository size_kb.')
    kw.setdefault('evidence','https://github.com/'+repo+'; '+d.get('commit_url','https://api.github.com/repos/'+repo+'/commits/HEAD'))
    add(id,name,'https://github.com/'+repo,repo.split('/')[0],kind,**kw)

a=D['archive']
repo_row('gcf_archive','Audit Report Archive','gcf3711/audit-report-archive','cross_firm_report_catalog',
    size=a['records'],unit='catalog URLs; NOT unique audit engagements',key='archive',
    method='Sum arrays in all pinned data/catalog/*.json; normalize GitHub revisions separately; compare downloaded hashes and HF siblings.',
    dates='2015 through 2026-10-15 among syntactically valid catalog dates; target 2016-2026 partly covered.',
    date_origin='Best-effort catalog date. Generic GitHub scraper prefers filename date, then oldest commit touching the file; the latter is a publication proxy, not audit completion.',
    firms='46 nonempty source catalogs; Broad firms plus Code4rena/Sherlock/Cantina/Hats; not an industry census.',
    fields='source/firm key; project; title; date; report_url; download_url; listing_url; file_type; local_path; sha256; size_bytes; downloaded_at; extra(repo/path/commit); separate partial chain/language/category enrichment. Findings/severity not extracted.',
    originals='Git repository: metadata/indexes only. Separate HF mirror has '+str(D['archive_hf']['report_files'])+' report files (PDF/HTML/MD); do not assume README mirror count.',
    terms='No root LICENSE detected; HF card license:other. Maintainer says copyright remains with firms. Technical availability of HF files does not authorize public redistribution.',
    quality=f"{a['records']} URLs collapse to {a['revision_normalized_urls']} revision-normalized URL keys; {a['with_local_path']} local paths but {a['sha256_records']} hashed/download-timestamp records and {a['unique_sha256']} unique hashes. {a['invalid_nonempty_dates']} syntactically malformed nonempty dates. Origin links not re-downloaded; no completeness guarantee.",
    priority='primary_index_after_dedup',evidence='https://github.com/gcf3711/audit-report-archive; https://huggingface.co/datasets/gcf3711/audit-report-archive; '+a['catalog_url_template'])



repo_row('forge','FORGE Artifacts','shenyimings/FORGE-Artifacts','academic_report_and_findings_dataset',
    size=D['shenyimings/FORGE-Artifacts']['dataset/results']['files'],unit='per-report result JSON files',key='shenyimings/FORGE-Artifacts',
    method='Resolve dataset/results subtree independently because recursive root tree was truncated.',
    dates='Historical reports used by ICSE 2026 paper; original corpus cutoff/date extrema not normalized here. Separate curated extension covers Dec 2024-Feb 2026.',
    date_origin='Result metadata/original report; dataset or publication date is not audit date.',
    firms='Paper reports 47 security teams; EVM/Solidity-focused, not all Web3.',
    fields='Project metadata; vulnerability title/description/severity/location/recommendation; CWE hierarchy; report path; source-code mappings. Firm/date/chain completeness needs validation.',
    originals='Report PDFs distributed separately via linked Google Drive or R2; not in inspected result subtree. External bulk archive availability/content not tested.',
    terms='Root MIT (Yiming Shen, 2025) covers contributed software/annotations to extent owned; original audit PDFs and copied contract code need their own rights review.',
    mirror='conditional_licenced_annotations_only',
    quality='Paper claims 27,497 findings and 81,390 Solidity files from 6,454 reports; these finding/code counts were not independently recomputed. LLM extraction/CWE mapping can introduce errors; root-tree file count is truncated.',priority='primary_historical_findings',
    evidence='https://github.com/shenyimings/FORGE-Artifacts; https://arxiv.org/abs/2506.18795')

fc=D['shenyimings/FORGE-Curated']
repo_row('forge_curated','FORGE Curated','shenyimings/FORGE-Curated','academic_report_and_findings_dataset',
    size=fc['dataset-curated/findings']['files']+fc['dataset-curated/findings-without-source']['files'],unit='per-report finding JSON files',key='shenyimings/FORGE-Curated',
    method='Independent report/findings/findings-without-source subtree trees, all untruncated.',
    dates='December 2024-February 2026 (maintainer statement).',date_origin='Original report date; JSON report path may contain month.',
    firms='11 report directories: Ackee-Blockchain, BlockSec, Cantina, ChainSecurity, Consensys_Diligence, MixBytes, OpenZeppelin, Sherlock, TrailofBits, Zellic, Zenith.',
    fields='Report path; firm via directory; project; findings with severity/description/location/CWE/recommendation; code mappings; some reports without source. Chain not a universal normalized field.',
    originals='253 PDFs plus 70 report Markdown files (and a README); 208 finding JSONs with source and 115 without. HF mirror explicitly says incomplete/unmaintained.',
    terms='Root Apache-2.0; retain licence/notices and per-contract licences. Does not establish a grant from every audit-report owner.',
    mirror='conditional_licenced_annotations_only',
    quality='README claims 2,469 findings and 619 vulnerability-file pairs; do not confuse these with report count. Original and curated FORGE may overlap. Resolve truncated root via targeted trees.',priority='primary_recent_findings',
    evidence='https://github.com/shenyimings/FORGE-Curated; https://huggingface.co/datasets/Seuilping/FORGE-Curated')

z=D['zaevlad']
add('zaevlad','Audit Findings Dataset','https://huggingface.co/datasets/Zaevlad/audit-findings-dataset','Zaevlad','cross_platform_findings_dataset',
    size=z['file_count'],unit='Hub files; finding row total not independently measured',status='partial_measurement',key='zaevlad',
    method='Pinned Hub metadata and viewer schema. Size API has failed config-size job and returns zero placeholder; card claims 23,625 findings.',
    dates='Scraped contest filenames include dates, but no authoritative audit-date column; exact range not established.',date_origin='Infer only from a validated source filename/link; upload on 2026-08-31 is not report date.',
    firms='Multiple contest sources; explicit firm/source roster absent from table schema.',fields='id; file_name; bug_title; bug_desc; bug_poc; bug_rec; bug_sev; bug_sev_raw; bug_weight; bug_full. Firm/project/date/chain require reconstruction.',
    originals='One Parquet and raw CSV, no original PDFs.',access='HF dataset files or dataset viewer/API; no login required in this run.',rate=HF_RATE,
    terms='Card license:other and explicitly says underlying third-party report authorship/licences are unclear.',mirror='link_and_summarize',updated=z['last_modified'],
    quality='Card warns of duplicates, placeholders for most PoCs, uncertain severity mappings and scraping artifacts; bug_weight measures writeup thoroughness with coarse severity, not severity itself.',priority='secondary_findings_only',
    evidence='https://huggingface.co/datasets/Zaevlad/audit-findings-dataset; '+U['zaevlad_hf_size']+'; '+U['zaevlad_card'])

repo_row('lisabench','LISA-Bench','agentlisa/bench','cross_platform_vulnerability_benchmark',
    size=D['agentlisa/bench']['json_files'],unit='vulnerability JSON files',key='agentlisa/bench',
    dates='2016-2024 (README claim); date completeness not verified.',date_origin='Source report linked in Source field; table schema lacks a dedicated date.',
    firms='README: 10 audit platforms, including Code4rena, OpenZeppelin, Halborn, Sherlock and Trail of Bits; 584 protocols claimed.',
    fields='Observed JSON keys Title, Content, Impact, Source, Code. Dedicated firm/project/date/chain fields absent in sample; source URL must be resolved.',
    originals='JSON findings with code context and source links; no report PDFs.',terms='Root MIT (Agent LISA, 2025); underlying report/code rights still need per-source verification.',
    mirror='conditional_licenced_annotations_only',quality='Dataset unit is vulnerability, not audit. README verification/completeness claims were not independently reproduced. Source code is copied context, not necessarily a complete audited revision.',priority='historical_findings_supplement')

repo_row('defihacklabs','DeFiHackLabs','SunWeb3Sec/DeFiHackLabs','incident_reproduction_corpus',
    size=D['SunWeb3Sec/DeFiHackLabs']['extensions']['.sol'],unit='Solidity files under src/test; NOT audit reports',key='SunWeb3Sec/DeFiHackLabs',
    dates='Incident path years observed 2017-2026; historical cases are backfilled.',date_origin='Exploit/incident date from README/path, not audit or repository commit date.',
    firms='No audit-firm census; cross-project, cross-chain incidents.',fields='Incident name/date; exploit/transaction/address references; chain/RPC context; exploit mechanism and source links. Firm/severity not standardized.',
    originals='Executable reproduction code and incident links, no audit PDFs.',terms='Root Apache-2.0 for contributed material; external articles/code retain own licences.',
    mirror='conditional_licenced_original_material',quality='Multiple tests may represent one incident; no-failure audits absent; incident/exploit selection bias. Never add these files to audit annual totals.',priority='incident_join_only')

df=D['defillama']
add('defillama','DeFiLlama audit_links','https://api.llama.fi/protocols','DefiLlama','protocol_metadata_aggregator',
    size=df['unique_audit_links'],unit='distinct audit_links URLs in protocols response',key='defillama',
    method='Count protocols with nonempty audit_links and distinct string URLs in live /protocols JSON.',
    dates='Current protocol metadata; linked reports can be historical. No normalized audit dates.',date_origin='Follow each audit_links target; listedAt is protocol listing time and is not audit date.',
    firms='Cross-firm, selected by listed protocols; audit firm usually absent as a normalized field.',
    fields='id/name/project; chain/chains; audits flag; audit_links; github/url/category. Audit date, finding severity and firm require following links. Parent /protocol/aave lacks audit_links; use child/list records.',
    originals='Links only; may point to a directory, marketing page, PDF or another aggregator.',access='Public REST /protocols; protocol details vary by parent/child endpoint. Git adapters alone are not the complete protocol metadata source.',
    terms='No content/database redistribution grant verified for API audit metadata. Adapter code licences, if any, do not grant rights to linked reports.',
    quality=f"{df['protocols']} protocols; {df['protocols_with_audit_links']} with links; {df['audit_link_occurrences']} occurrences. Links are not necessarily one report each; stale links, parent/child duplication and survival/listing bias.",
    priority='primary_gap_discovery',evidence='https://api.llama.fi/protocols; https://api-docs.defillama.com/; https://api.llama.fi/protocol/aave')

c=D['code4rena_api']
add('code4rena','Code4rena reports and all listed audits','https://code4rena.com/reports','Code4rena / code-423n4','contest_reports_and_metadata',
    size=c['unique_ids'],unit='audit engagement IDs across all advertised API pages',key='code4rena_api',
    method='GET /api/v1/audits?perPage=100&page=N through lastPage; require unique IDs == advertised total. Separately enumerate report sitemap and structured report list.',
    dates='Audit starts 2021-02-17 through 2026-04-24; publication years 2021-2026; platform winding down.',
    date_origin='startTime/endTime for contest cohorts; report list date for publication. One report date is prose with original and mitigation publication dates.',
    firms='Code4rena platform plus independent wardens; sponsor is the audited client, not the auditing firm.',
    fields='uid; contestId; slug; sponsor/org; auditType; status; codeAccess; startTime/endTime; reportExpectedBy; repo/findingsRepo; league; reward. Reports: publication date, canonical H/M/L/QA/G findings and issue links.',
    originals='412 published HTML report entries/sitemap URLs; findings GitHub repositories and occasional PDFs. No generic reports repo found at code-423n4/reports or Code4rena/reports (404).',
    access='Public website JSON API; sitemap; read report HTML; per-contest code-423n4/*-findings GitHub repos/issues/data. Public clone misses issue bodies unless exported; paginate API.',
    rate=UNKNOWN_RATE+' GitHub: '+GH_RATE,
    terms='Current C4 terms reserve content/report rights and grant limited personal use; no general public bulk-republication licence established. Inspect any contest-specific grant separately.',
    mirror='link_and_summarize',
    quality=f"{c['audit_types']} types; only 412 report records. Never equate all {c['unique_ids']} engagements or raw issues with unique valid contests/findings. Legacy status values are incomplete; query-string /audits?page=2 returned the first page, so use the JSON API.",
    priority='primary_contest_source',evidence='https://code4rena.com/api/v1/audits?perPage=100&page=1; https://code4rena.com/reports; https://code4rena.com/sitemap.xml; https://github.com/code-423n4; https://docs.code4rena.com/legal/terms-of-service')

repo_row('sherlock_reports','Sherlock report archive','sherlock-protocol/sherlock-reports','platform_pdf_reports',
    size=D['sherlock-protocol/sherlock-reports']['extensions']['.pdf'],unit='PDFs under audits/ only',key='sherlock-protocol/sherlock-reports',
    dates='Audit filenames include 2022-2026.',date_origin='Dated report filename/cover and README audit month; prefer report completion date and retain both if different.',
    firms='Sherlock and named lead senior auditors, with project/client in index.',fields='Project; report filename/date; lead senior auditor; PDF findings/severity/remediation. Chain/language mostly in report text.',
    originals='Audit PDFs included; separate coverage-agreements/ PDFs are insurance/legal documents.',
    quality='Repository-wide count 304 PDFs includes agreements; audits/ has 266. Includes focused reviews and repeat projects; deduplicate versions and match contest IDs. Not every contest has a PDF.',priority='primary_contest_reports')

s=D['sherlock_api']
add('sherlock_judging','Sherlock contest API and judging repositories','https://audits.sherlock.xyz/contests','Sherlock / sherlock-audit','contest_metadata_and_issue_exports',
    size=s['public_records'],unit='public contest records; all API records include private engagements',key='sherlock_api',
    method='Public API per_page=100, all pages, unique IDs checked against advertised total. Separate GitHub search for judging in repository name.',
    dates='Public contest starts 2022-08-29 through 2026-07-20.',date_origin='API starts_at/ends_at Unix timestamps in UTC; report publication date separate. Repo name YYYY-MM is a fallback label, not an exact date.',
    firms='Sherlock platform; researchers and lead auditors are separate actor roles.',fields='Contest id/title; status/type/private; starts_at/ends_at; reward/token; detail endpoint includes judging_repo_name, report and submitted-issue counts; judging issue title/body/labels/comments and duplicate links. Chain/language from scope/detail.',
    originals='Public judging repos/issues/exports; related PDF reports in sherlock-reports.',
    access='https://mainnet-contest.sherlock.xyz/contests?per_page=100&page=N and /contests/{id}; GitHub sherlock-audit/*-judging trees/issues. No authenticated/private findings accessed.',
    rate=UNKNOWN_RATE+' GitHub: '+GH_RATE,
    terms='No universal content redistribution licence verified across judging repos; code/source licence does not imply issue/report licence.',
    quality=f"{s['unique_ids']} total API IDs, {s['public_records']} public; GitHub search returns 230 judging repos, not a contest census. New judging versions/engine can publish elsewhere. Submitted issue counts include duplicates/invalids.",
    priority='primary_contest_source',evidence='https://mainnet-contest.sherlock.xyz/contests?per_page=100&page=1; https://github.com/sherlock-audit; https://github.com/sherlock-audit/2023-02-gmx-judging')

ca=D['cantina_api']
add('cantina','Cantina security reviews and competitions','https://cantina.xyz/security-reviews','Spearbit Labs Inc. / Cantina','platform_reports_and_contest_metadata',
    size=D['cantina_reports']['managed_review_records'],unit='structured managed-review records; competition inventory separate',key='cantina_reports; cantina_api',
    method='Decode inert server Flight cantinaManaged array; count distinct CDN PDFs. Read /api/v0/competitions and partition by kind.',
    dates='Competitions from 2023-11-13 through 2026-10-06; managed review timeline and PDF month vary, including older Spearbit work.',
    date_origin='Managed timeline.start/end is engagement period; competition timeframe is start/end; PDF filename month is secondary; publication date often not separately stated.',
    firms='Cantina/Spearbit and named researchers; private reviews and public competitions overlap with older Spearbit portfolio.',
    fields='Review id/client/title/kind/timeline; categories; severity counts and fixed/acknowledged; PDF URL; repoLinks; commitHashes; team. Competition id/timeframe/status/kind/company/reward/totalFindings. Chain varies.',
    originals='489 distinct PDF URLs plus report/portfolio pages in captured review listing; individual report pages may expose HTML findings.',
    access='Server-rendered listing data and CDN PDFs; unauthenticated /api/v0/competitions returns metadata, including some private placeholders. Do not access private reports.',
    terms='General terms identify Spearbit Labs Inc.; rights to deliverables granted to Cantina do not grant visitors a public mirror licence.',
    quality=f"Review records and PDFs are different units. API has {ca['competition_records']} IDs: {ca['kind_counts']}; private rows may lack name/timeframe. totalFindings is submitted reports, not unique accepted vulnerabilities. Earlier third-party census has fewer rows.",
    priority='primary_contest_and_review_source',evidence='https://cantina.xyz/security-reviews; https://cantina.xyz/api/v0/competitions; https://cantina.xyz/terms/general')



add('hats','Hats Finance audit competitions','https://github.com/hats-finance','Hats Finance','contest_repositories_and_reports',
    status='unmeasured',reason='App endpoint timed out and org repository API hit unauthenticated quota. Name search for token 0x returns only 8 indexed matches and is not a substring-complete repository census.',
    key='hats_vault_repos; url_measurements.hats_audits; archive.per_source.hatsfinance',
    method='Failed app/org enumeration; inspect known report.md links and secondary archive. Archive contains 36 report URLs, not a verified platform total.',
    dates='Secondary archived report dates 2023-12-04 through 2025-03-19; full coverage unverified.',date_origin='Report competition period/vault timestamps; final report publication date retained separately.',
    firms='Hats competitions, sponsors and lead auditors; not conventional firm-wide coverage.',fields='Repository/project; vault address; competition period; final report.md; issue title/body/labels/duplicates; severity and payouts when published. Chain from vault/scope.',
    originals='Final report.md and issue discussions in project-vault repositories; some linked PDFs.',access='Per-project hats-finance/{project}-0x{vault}, report.md and Issues; app.hats.finance. No generic hats-finance/audits repository found.',rate=GH_RATE,
    terms='Per-project contract licences vary; no blanket report/issue republication grant verified.',
    quality='Unfinalized competitions can have no report.md. A code repository or vault is not automatically a completed contest. Sparse search indexing cannot establish denominator.',
    priority='contest_gap_fill',evidence='https://github.com/hats-finance; https://github.com/hats-finance/ether-fi-0x36c3b77853dec9c4a237a692623293223d4b9bc4/blob/master/report.md; https://docs.hats.finance/for-security-researchers/becoming-a-lead-auditor')

add('secure3','Secure3 public contests and reports','https://secure3.io/contest/','Secure3','contest_portal',
    status='unmeasured',reason='Official docs link /reports but it returned 404; /contest redirects to the home page. No complete report listing obtained; tested candidate GitHub report repository unavailable.',
    key='url_measurements.secure3_reports_current; url_measurements.secure3_contests',method='Live portal paths checked against official FAQ.',
    dates='Exact public date coverage not established; ongoing platform. FAQ claims over 200 contests, not a measured public-report total.',
    date_origin='Contest start/end and report finalization when public; landing-page or docs update time is not report date.',
    firms='Secure3 organized reviews; some engagements private.',fields='Expected contest/project/time/reward/status; published reports contain findings/severity. Full export/schema and chain completeness unverified.',
    originals='Some public report/PDF links historically; no current bulk collection verified.',access='Official site/app and docs; JS-backed listing or export from operator needed.',
    terms='No public bulk redistribution grant found in accessible docs; private reports need sponsor authorization.',quality='Do not confuse Secure3 with Sec3 (sec3-service/reports). Archive claim that report repo was deleted is secondary evidence; 404 alone does not prove deletion.',
    priority='operator_export_or_gap_fill',evidence='https://docs.secure3.io/faqs; https://secure3.io/contest/; https://secure3.io/reports')

im=D['immunefi_report_index']
add('immunefi','Immunefi audit competitions / Boosts','https://immunefi.com/audit-competition/','Immunefi','contest_listings_and_report_archive',
    size=D['immunefi_competitions']['distinct_matches'],unit='distinct competition listing slugs',key='immunefi_competitions; immunefi_report_index',
    method='Unique audit-competition slugs in listing; separately parse public reports GitBook llms.txt.',
    dates='Competitions/Boosts from 2023 through 2026; older incident/bounty disclosure posts are a different population.',
    date_origin='Competition start/end in program information page; public disclosure/report date stored separately.',firms='Immunefi competitions and participating researchers; sponsor/client and external reviewers separate.',
    fields='Slug/project; competition period; status/prize; chains/assets/scope; report submission id/title/severity/status/duplicate and reward where disclosed.',
    originals=f"Public report Markdown/HTML at reports.immunefi.com; {im['markdown_links']} distinct index links ({im['top_level_pages']} top-level, {im['nested_pages']} nested). Some external PDF summaries.",
    access='Public listings; /boost/ redirects to audit-competition listing; GitBook llms.txt and .md report pages. No universal public export of private bug bounty submissions.',
    terms='No general open licence verified on report archive; program-specific disclosure and ownership rules apply. Public contest reports do not authorize release of confidential bounty submissions.',
    quality='Boost is a legacy competition label, not another engagement to double count. Nested report pages include invalid and duplicate submissions; index page count is not accepted finding count.',
    priority='primary_contest_source',evidence='https://immunefi.com/audit-competition/; https://immunefi.com/boost/; https://reports.immunefi.com/llms.txt')

hk=D['hacken']
add('hacken','Hacken public audits API and portal','https://hacken.io/api/audits','Hacken OÜ','firm_report_and_findings_api',
    size=hk['audits'],unit='audit records in public API response',key='hacken',
    method='Count full public JSON array, distinct client names and issues arrays.',dates='2019-02-05 through 2026-10-15 in audit_date.',
    date_origin='API audit_date ISO timestamp; report/cover date should resolve any completion-versus-publication ambiguity.',firms='Hacken only; API has '+str(hk['clients'])+' distinct client_name strings.',
    fields='audit_name/client_name/audit_date/audit_type; repository/commit/assets; labels; platforms; languages; report_link; issues(status,severity,name); audited_contracts(chain,chainId,address,repo,commit,filePath,contractName).',
    originals='Metadata plus issue summaries and report links; HTML/PDF reports at target URLs.',
    access='Documented unauthenticated GET https://hacken.io/api/audits, no parameters; portal plain curl was 403 but API succeeded.',
    terms='API docs explicitly allow unauthenticated access but do not provide an open redistribution licence for all reports/findings.',
    quality='API '+str(hk['findings'])+' issue-array entries; site counter reports larger totals (2,177 audits, 1,185 companies, 16,861 vulnerabilities). Counters and public API have different populations; findings summaries omit full descriptions.',
    priority='primary_targeted_gap_fill',evidence='https://hacken.io/api/audits; https://docs.hacken.io/rest-apis/get-audits/; https://hacken.io/audits/reports/')


repo_row('slowmist','SlowMist public report repository','slowmist/Knowledge-Base','firm_report_portal',
    size=D['slowmist/Knowledge-Base']['extensions']['.pdf'],unit='PDF paths under open-report* only',key='slowmist/Knowledge-Base',
    dates='Historical/current; filenames lack consistent machine-readable dates, so exact report range not measured.',date_origin='Report cover/final date; certificate verification date or Git commit not interchangeable.',firms='SlowMist; blockchain, applications and smart contracts across ecosystems.',
    fields='Project/firm via report; scope, audit date, findings/severity/remediation in PDF or certificate image. Chain/language require extraction.',
    originals='331 PDFs and 281 JPGs under open-report/open-report-V2; images may be certificates rather than complete reports.',
    quality='Root 337 PDFs includes unrelated material. Bilingual versions and certificates can duplicate engagements; no normalized findings table.',priority='primary_targeted_gap_fill')

repo_row('l2beat','L2BEAT project audit references','l2beat/l2beat','ecosystem_audit_link_registry',
    size=D['l2beat']['project_ts_files'],unit='project TypeScript config files; NOT audit count',key='l2beat',
    dates='Current L2/L3/bridge registry with historical linked audits; report date range not established.',date_origin='Project audit entry publishedOn/date where provided or original report; listedAt and deployment timestamps are different.',
    firms='Cross-firm within Ethereum scaling/bridge ecosystem; not all Web3 projects.',fields='Project; audit title/url/auditor/date where configured; scope/version; technology/risks; chain type. Per-finding severity absent.',
    originals='Audit links and metadata; source repo is a website/configuration monorepo, not a report PDF archive.',
    terms='Root MIT for contributed source/configuration, retain licence and notices. Linked report copyrights unaffected.',mirror='conditional_licenced_metadata_only',
    quality='297 config files include templates/utilities/multiple files per project; cannot equate file count with projects or audits. Incomplete ecosystem/publication selection.',priority='ecosystem_gap_discovery',
    evidence='https://github.com/l2beat/l2beat; https://l2beat.com/scaling/projects/arbitrum; https://l2beat.com/faq')

add('etherscan','Etherscan audit references / contract tags','https://etherscan.io/','Etherscan','contract_audit_reference_metadata',
    status='unmeasured',reason='Candidate audited-contract listing returned 403 and no documented public audit-tag census/export endpoint was identified. Audited-address counts would not equal audit reports.',
    key='url_measurements.etherscan_audits',method='Public documentation and terms checked; no bulk collection under restrictive terms.',
    dates='Contract-address references can link historical reports; date range not available as an audit corpus.',date_origin='Submitted report date/original report. Contract verification time, deployment time and address-label update are not audit dates.',
    firms='Any auditor whose report a contract/project owner submits; opt-in and Ethereum/address-level bias.',fields='Contract address/project label; submitted audit report link/date/auditor where available; Ethereum chain inferred. No normalized finding/severity export verified.',
    originals='Links/contract audit metadata, not a report archive.',access='Contract Code tab Contract Security Audit and supported API/authorized exports; no undocumented audit-tag enumeration claimed.',
    terms='Current terms prohibit automated scraping except narrow search indexing and prohibit dataset creation/AI uses and reproduction of labels/API/CSV data without prior written permission.',
    mirror='permission_required',quality='One report can cover many contract addresses; audit label is not evidence of audit scope, final date or complete findings.',priority='permissioned_provenance_check_only',
    evidence='https://kb.etherscan.com/navigating-the-contract-code-tab; https://etherscan.io/terms; https://etherscan.io/contractsVerified?filter=Audited')

repo_row('dappscan','DAppSCAN','InPlusLab/DAppSCAN','academic_report_and_weakness_dataset',
    size=D['InPlusLab/DAppSCAN']['DAppSCAN-source']['extensions']['.pdf'],unit='original PDF paths in complete source subtree',key='/'.join(('InPlusLab', 'DAppSCAN')),
    method='Resolve DAppSCAN-source subtree; root recursive tree truncated. Count PDFs separately from source/bytecode annotations.',
    dates='Historical pre-publication snapshot; paper 2023 with later revisions; exact audit date range not normalized.',date_origin='Original PDF or Audit_and_Repository_link.xlsx source link; paper/repo date is not audit date.',
    firms='Paper: 29 security teams; README and paper use different filtered populations.',fields='Spreadsheet File Name/Audit Company/Project Name/Audit Report Link/Code Repository; PDF findings and severity; source/bytecode SWC mappings. Audit date/chain not uniform columns.',
    originals='Original PDFs plus spreadsheet, contract source, SWC labels and bytecode.',
    quality='806 PDF paths observed versus README 608 reports and paper 1,199 reports: different populations/versions, not evidence of 806 distinct audits. Root tree truncation would miss reports.',priority='primary_historical_report_supplement',
    evidence='https://github.com/InPlusLab/DAppSCAN; https://arxiv.org/abs/2305.08456')

add('giant','GiAnt Corpus paper','https://arxiv.org/abs/2606.07363','Xiaoting Zhang and coauthors','academic_findings_dataset',
    status='unmeasured',reason='Paper abstract/HTML provides corpus claims but no public dataset download/repository URL located in inspected paper; cannot enumerate current artifact.',
    key='url_measurements.giant_paper; url_measurements.giant_html',method='arXiv abstract/HTML and outbound artifact link search.',
    dates='Paper 2026-06-05; historical Code4rena reports, exact report cutoff unverified.',date_origin='Original Code4rena report publication/contest period; arXiv date is publication of the study.',firms='Code4rena only.',
    fields='Paper describes structured severity/title/description/code context/impact/mitigation data; downloadable schema not verified; no chain census.',
    originals='388 report inputs and 7,711 findings claimed by paper; originals/download not independently verified.',access='Paper readable; request artifact or locate an author-issued release before ingestion.',
    terms='Paper arXiv nonexclusive distribution licence is not an open data licence; underlying reports separately governed.',
    quality='LLM extraction and LLM-as-judge quality claims; selected Code4rena report sample cannot improve industry denominator.',priority='artifact_followup',evidence='https://arxiv.org/abs/2606.07363; https://arxiv.org/html/2606.07363v1')

b=D['c4audit_reports_download']
add('c4audit','C4Audit (Zenodo)','https://zenodo.org/records/17571170','Luciana Silva / Janio Rosa da Silva','academic_contest_report_dataset',
    size=b['json_files'],unit='parsed report JSON files in Reports ZIP',key='c4audit_reports_download',
    method='Download immutable version Reports ZIP to /tmp; verify Zenodo MD5; inspect bounded JSON in memory, excluding __MACOSX and .DS_Store.',
    dates='Report filename months 2021-04 through 2025-08.',date_origin='Report id month is contest slug, not exact publication date; resolve source report metadata.',firms='Code4rena only.',
    fields='report_title; scope contracts/lines_solidity/repositories; issues(issue_id,title,severity,description,vulnerable_code_links). Checked sample lacks standalone audit date/firm/chain.',
    originals='Parsed report JSON; separate repository source and metrics ZIPs; no original PDF archive.',access='Versioned Zenodo REST/files and DOI; three downloadable ZIPs.',
    terms='Zenodo record CC-BY-4.0; attribute creators, DOI and modifications. Underlying copied Code4rena findings/contract source need separate rights review.',mirror='conditional_licenced_annotations_only',
    updated=D['c4audit']['modified'],quality=f"{b['json_files']} JSONs contain {b['issues_in_top_level_issues_arrays']} issue-array entries; parser artifacts/missing severities and report-scope mismatches possible. Claimed metadata fields exceed checked sample. Not an independent audit population.",
    priority='contest_parsing_supplement',evidence='https://zenodo.org/records/17571170; https://zenodo.org/api/records/17571170')

add('scar','SCAR audit report crawlers','https://github.com/IlhamQasse/SCAR','Ilham Qasse, Po-Yu Tseng, Mohammad Hamdaqa, Gísli Hjálmtýsson','academic_cross_firm_report_pipeline',
    status='unmeasured',reason='Repository identified via paper PDF hyperlink; GitHub tree measurement then hit core rate limit. Public root listing exposes crawlers/analysis, but complete downloadable dataset/API endpoint was not verified.',
    key='repo_measurements.IlhamQasse/SCAR',method='Paper and canonical GitHub root inspected read-only; no crawler/build execution.',
    dates='Study published 2026-07-05; exact historical report range/current artifact freshness unknown.',date_origin='Source report dates normalized by crawlers; study/repo date is not report date.',
    firms='Quantstamp, ConsenSys Diligence, OpenZeppelin, Code4rena.',fields='Paper describes project metadata, audit scope, dates, finding title/body/type/severity/remediation, code refs and platform extensions; live artifact schema not enumerated.',
    originals='Paper describes PDF/HTML/JSON inputs and unified JSON/API; report files/export availability not verified.',access='Canonical GitHub source; paper describes API but no operational endpoint verified. Request authors’ dataset/export.',
    terms='Paper CC-BY-4.0; repository/data licence not verified. Paper licence does not license underlying report content.',
    updated='Paper 2026-07-05; repository latest commit unmeasured (403).',quality='Paper describes over a thousand projects and nearly fifteen thousand findings; do not present as measured live totals. Root listing currently emphasizes crawler code.',
    priority='promising_export_followup',evidence='https://github.com/IlhamQasse/SCAR; https://doi.org/10.1145/3803437.3806435; https://opinvisindi.is/bitstreams/ed65305a-afc8-466a-b9dd-8da9081fe898/download')

kg=D['kaggle_audit_download']
add('kaggle_audit','Kaggle Smart Contract Audit Reports Dataset','https://www.kaggle.com/datasets/shivam017arora/smart-contract-audit-reports-dataset','Shivam Arora / shivam017arora','academic_dataset_derivative',
    size=kg['rows'],unit='CSV rows in downloaded version',key='kaggle_audit_download',
    method='Anonymous Kaggle REST download; inspect single bounded kaggle.csv in memory with CSV parser.',dates='2023-06-14 release derived from DAppSCAN; exact report date range lost.',
    date_origin='No date column; reconstruct from source DAppSCAN/report text if possible.',firms='DAppSCAN-derived multi-firm subset, not an additional independent source population.',
    fields='sol; report; summary. Firm/project/date/severity/chain not explicit columns.',originals='Contract text and extracted report text with model summaries; no original PDFs.',
    access='Anonymous Kaggle metadata/list/download API worked; 4,141,544-byte ZIP, 18,363,179-byte CSV.',
    terms='Kaggle listing declares GNU Free Documentation License 1.3; verify uploader authority and source DAppSCAN/report rights. Dataset-host label does not cure third-party rights.',
    mirror='conditional_uploader_and_upstream_rights',updated='2023-06-14T18:51:37.373Z',
    quality='Only 241 rows; PDF extraction and model refine summaries lose provenance and may hallucinate. Not all Kaggle smart-contract vulnerability sets are audit reports.',priority='low_priority_derivative',
    evidence=U['kaggle_audit_metadata']+'; '+U['kaggle_discovery']+'; https://www.kaggle.com/datasets/shivam017arora/smart-contract-audit-reports-dataset')

msc=D['hf_audits_reasons'];splits=msc['card']['dataset_info']['splits']
add('hf_audits_reasons','HF Audits with Reasons and Recommendations','https://huggingface.co/datasets/msc-smart-contract-auditing/audits-with-reasons','msc-smart-contract-auditing','finding_code_training_pairs',
    size=sum(s['num_examples'] for s in splits),unit='card-declared train+test rows',status='publisher_metadata',key='hf_audits_reasons',
    method='Pinned Hub card split statistics (not independently re-read Parquet rows).',dates='2024-06-28 snapshot; original report date range absent.',date_origin='No audit-date column.',
    firms='Original firm/project identifiers absent from table; cannot establish per-firm coverage.',fields='code; description; recommendation; type; functionality. Some no-vulnerability controls; no explicit firm/project/date/severity/chain.',
    originals='Parquet code/text pairs only.',access='HF public dataset API/files and dataset viewer.',rate=HF_RATE,
    terms='Hub card declares MIT; original snippets/report text ownership/provenance not established.',mirror='conditional_uploader_and_upstream_rights',updated=msc['last_modified'],
    quality='Training/code examples are not full audits; inferred commentary and negative examples contaminate a finding census. Weak provenance prevents annual firm counts.',priority='exclude_from_audit_denominator',evidence=U['hf_audits_reasons'])

nyx=D['hf_nyx']
add('hf_nyx','SPECA vulnerability reports','https://huggingface.co/datasets/NyxFoundation/vulnerability-reports','Nyx Foundation','cross_platform_findings_dataset',
    size=D['hf_nyx_size']['size']['dataset']['num_rows'],unit='dataset-viewer rows',key='hf_nyx_size',method='HF dataset-server size endpoint, successful split aggregation.',
    dates='Snapshot 2026-05-08; contest identifiers contain historical months. Exact report range not independently normalized.',date_origin='source_url/contest report metadata; scraped_at is ingestion time, not audit date.',
    firms='Dataset viewer indicates three source platforms; Code4rena visible in samples. Complete firm coverage not independently enumerated.',
    fields='id; source_platform; contest; issue_id; severity; title; description; source_url; domain; scraped_at. Dedicated report date/chain absent.',
    originals='Parquet finding text/source URLs; no PDFs.',access='HF public dataset files/API/viewer.',rate=HF_RATE,
    terms='Hub card declares MIT. Upstream platform issue/report rights remain separately applicable; do not assume permission to relicense copied findings.',mirror='conditional_uploader_and_upstream_rights',updated=nyx['last_modified'],
    quality='High/Medium-only sample; selected report/issue snapshot, duplicates and incomplete source URLs possible. scraped_at is a single collection date.',priority='secondary_contest_findings',evidence=U['hf_nyx']+'; '+U['hf_nyx_size']+'; https://huggingface.co/datasets/NyxFoundation/vulnerability-reports')

repo_row('contest_census','Cross-platform audit contest census','munimtechnologies/audit-contest-ai-rules','cross_platform_contest_metadata',
    size=len(D['contest_census']),unit='CSV tables; see research note for per-platform row counts',key='contest_census',
    method='Parse every data/*.csv at pinned commit; count rows and kind values. No third-party collector scripts executed.',
    dates='Code4rena 2021-2024 findings repos; Sherlock 2022-2026; Cantina/Immunefi 2023-2026; snapshot around 2026-10-15.',
    date_origin='start/end columns from platform APIs/pages; preserve acquisition date and source-specific kind filters.',
    firms='Code4rena, Sherlock, Cantina, Immunefi, HackenProof; platform activity, not private audit-firm output.',
    fields='Contest IDs/slugs; sponsor/title; start/end/year; kind/access; prize/token; submissions; unique H/M and raw severity counts where available; KYC, source methods and limitations. No complete chain/firm roster.',
    originals='CSV/JSONL metadata and analytical summaries; not a report-body/PDF archive.',terms='Root Apache-2.0; retain notices and provenance. Platform-derived data remains subject to upstream terms; reuse aggregate analyses rather than assuming full report rights.',
    mirror='conditional_licenced_metadata_only',quality='AI-authored, non-peer-reviewed census; scopes differ between tables. Cantina census 125 differs from live API 126 public; Code4rena census excludes later eras.',priority='primary_contest_metadata_seed')

repo_row('nazgul','Blockchain Security Audit List','0xNazgul/Blockchain-Security-Audit-List','firm_directory',
    size=R['0xNazgul/Blockchain-Security-Audit-List']['file_count'],unit='Markdown directory file; NOT report total',key='repo_measurements.0xNazgul/Blockchain-Security-Audit-List',
    dates='Firm-directory snapshot last commit 2025-01-14; linked archives span varied dates.',date_origin='No report dates; resolve linked firm archives.',firms='Multi-firm and solo auditor directory, incomplete and manually curated.',
    fields='Firm/auditor name; website/social links; public report location. No normalized project/date/severity/chain.',originals='Links only.',
    quality='Useful for firm discovery and missing-source checks, not an audit inventory; stale/renamed firms and report paths.',priority='firm_gap_discovery')

add('ashutosh_archive','All Smartcontract Audit Reports research corpus','https://github.com/ashutoshshah1/all-smartcontract-audit-reports','ashutoshshah1','cross_firm_link_and_contest_analysis',
    status='unmeasured',reason='Candidate discovered late; GitHub core API quota exhausted before pinned tree/count could be obtained. README claims 5,358 public audit links and 402 analyzed Code4rena reports; claims not independently counted.',
    key='repo_measurements.ashutoshshah1/all-smartcontract-audit-reports',method='Live GitHub root README and metadata failure recorded; no code executed.',
    dates='README data snapshot 2026-02-28; exact historical dates unverified.',date_origin='Review research_output schema/source dates before reuse; proxy statistics are not audit completion dates.',
    firms='Cross-firm link inventory plus Code4rena-focused judged-report analysis; actual roster unverified.',fields='Research outputs claim audit links, severity totals and contest statistics; firm/project/date/chain schema needs artifact review.',
    originals='README says cache excluded; mainly research data/scripts/charts, not verified original PDFs.',access='Public GitHub; pinned metadata/count followup after rate limit.',rate=GH_RATE,
    quality='Severity numbers/acceptance proxies can count submission or aggregated category totals rather than unique findings; provenance/licence not verified.',priority='candidate_followup')

repo_row('smartbugs','SmartBugs Curated (negative control)','smartbugs/smartbugs-curated','non_audit_vulnerability_benchmark',
    size=R['smartbugs/smartbugs-curated']['directories']['dataset'],unit='dataset paths; NOT audit reports',key='repo_measurements.smartbugs/smartbugs-curated',
    dates='Historical synthetic/curated examples; no audit-date coverage.',date_origin='No relevant audit date.',firms='No firm report coverage.',
    fields='Contract source; vulnerability category; vulnerable lines; source/author annotations; no normalized firm/project/report date/severity/chain.',
    originals='Solidity examples and vulnerability labels, not original audit reports.',terms='Root Apache-2.0; respect source-specific notices.',mirror='conditional_licenced_original_material',
    quality='Excluded from audit counts. Similar Slither-audited HF datasets contain automated tool labels, not professional audit engagements.',priority='exclude_from_audit_denominator')

repo_row('sec3','Sec3 public reports (distinct from Secure3)','Sec3-Service/reports','firm_report_portal',
    size=R['Sec3-Service/reports']['pdf_paths_count'],unit='PDF paths',key='repo_measurements.Sec3-Service/reports',
    dates='README report years 2022-2026; exact date coverage from per-report index/cover.',date_origin='README audit month and PDF cover; prefer stated completion date.',firms='Sec3; predominantly Solana plus Solidity.',
    fields='Project; date/month; platform/type; PDF findings/severity/remediation; no cross-firm metadata.',originals='PDFs included with README index.',
    quality='Client publication consent limits coverage. Similar brand names cause false joins with Secure3; do not merge firms.',priority='non_evm_gap_fill',evidence='https://github.com/sec3-service/reports; https://sec3.dev/audits')

add('hackenproof','HackenProof DualDefense audit programs','https://hackenproof.com/audit-programs','HackenProof','audit_program_metadata',
    size=D['contest_census']['data/hackenproof_programs_fetched.csv']['rows'],unit='program rows in pinned third-party census; not live report total',status='secondary_index',
    key='contest_census.data/hackenproof_programs_fetched.csv',method='Count pinned census CSV rows; live portal availability independently checked (HTTP 200).',
    dates='Census includes 2025-2026 programs; exact historical start range not independently normalized.',date_origin='Program start_date/end_date; disclosure/final report date separate.',
    firms='HackenProof organized DualDefense programs; sponsors and Hacken firm audits are distinct roles.',
    fields='Program slug/name/kind/status; start/end; bounty range; paid amount; submissions/hackers; source page; AI-rule flag. Finding severity/scope/chain from program pages, no universal report export verified.',
    originals='Program metadata/rules and selected disclosures; no complete PDF/findings archive verified.',access='Public paginated portal and individual programs; census provides a reusable metadata seed.',
    terms='No blanket open content licence verified for portal; census Apache-2.0 covers contributed metadata/code only to extent owned.',
    quality='Do not merge with Hacken private audits. Program maximum prize, paid amount, submissions and accepted unique findings are different measures; ongoing bounty programs are not time-bounded audit contests.',
    priority='contest_metadata_supplement',evidence='https://hackenproof.com/audit-programs; https://github.com/munimtechnologies/audit-contest-ai-rules')

repo_row('trailofbits','Trail of Bits public reviews','trailofbits/publications','firm_bulk_report_repository',
    size=D['trailofbits_reviews']['pdf_paths'],unit='PDF paths under reviews/; includes non-Web3 work',key='trailofbits_reviews',
    dates='Historical public reviews through 2026; Web3 subset must be filtered separately.',date_origin='README review month and report cover/final date; filename is secondary.',
    firms='Trail of Bits; broad software security work, including blockchain/cryptography.',
    fields='Project; review date/month; effort/team where indexed; PDF findings/severity/scope/remediation; chain/language from report.',
    originals='Original PDF security reviews; separate repository folders contain presentations/research and are excluded from measured review paths.',
    terms='First-party publisher repository has CC-BY-SA-4.0 LICENSE. Preserve attribution, licence link, modification notices and ShareAlike for adaptations; inspect individual reports for excluded/third-party material and file-specific notices.',
    mirror='mirror_covered_reports_with_cc_by_sa_conditions',
    quality='460 review PDFs are not 460 Web3 audits: filter project/domain, revisions and followups. gcf contains many commit-specific URLs for these paths. A collection does not require unrelated metadata to be relicensed, but adapted report content must satisfy ShareAlike.',
    priority='licensed_originals_and_historical_gap_fill',
    evidence='https://github.com/trailofbits/publications; '+R['trailofbits/publications']['documents']['LICENSE']['request']['url'])

def render_csv():
    stream=io.StringIO(newline='')
    writer=csv.DictWriter(stream,fieldnames=list(rows[0]),lineterminator='\n')
    writer.writeheader();writer.writerows(rows)
    return stream.getvalue()

def inventory_table():
    lines=['| Source | Snapshot size / unit | Public-release policy |','|---|---|---|']
    for r in rows:
        size=(f"{r['measured_size']:,}" if isinstance(r['measured_size'],int) else str(r['measured_size']))
        label=(size+' '+r['size_unit']) if size else 'Unmeasured: '+r['unmeasured_reason']
        lines.append('| ['+r['name']+']('+r['url']+') | '+label.replace('|','/')+' | '+r['public_release_policy']+' |')
    return '\n'.join(lines)

def validate():
    assert len(rows)>=20
    assert len({r['source_id'] for r in rows})==len(rows)
    required=['date_coverage','date_origin','firm_coverage','fields_available','originals_included',
              'access_method','rate_limits','licence_and_terms','last_updated','quality_issues','evidence_urls']
    for r in rows:
        assert all(r[k] for k in required),r['source_id']
        assert r['measured_size']!='' or r['unmeasured_reason'],r['source_id']
        assert r['url'].startswith('https://')
    assert D['code4rena_api']['pagination_complete']
    assert D['sherlock_api']['pagination_complete']
    assert D['archive']['records']>=D['archive']['revision_normalized_urls']>=D['archive']['unique_sha256']
    stream=io.StringIO(render_csv());assert len(list(csv.DictReader(stream)))==len(rows)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    validate()
    csvpath=ROOT/'registry/aggregators.csv'
    mdpath=ROOT/'docs/research/aggregators.md'
    content=mdpath.read_text()
    start='<!-- INVENTORY:BEGIN -->';end='<!-- INVENTORY:END -->'
    assert content.count(start)==content.count(end)==1
    updated=content.split(start)[0]+start+'\n\n'+inventory_table()+'\n\n'+end+content.split(end)[1]
    if args.check:
        assert csvpath.read_text()==render_csv(),'CSV is stale'
        assert content==updated,'Markdown inventory table is stale'
    else:
        csvpath.parent.mkdir(parents=True,exist_ok=True);csvpath.write_text(render_csv());mdpath.write_text(updated)
    statuses=collections.Counter(r['size_status'] for r in rows)
    print(json.dumps(dict(sources=len(rows),size_statuses=dict(statuses),check=args.check),sort_keys=True))

if __name__=='__main__':main()
