# Methods

The release joins public report provenance, engagement identities, finding occurrences and derived annotations. The snapshot is 2026-10-22. The published outputs contain 12,767 industry engagements, 12,774 publisher participations, 13,522 report files and 175,640 finding occurrences.

## Collection and provenance

Scope comes from the publisher registry. It covers firms, collectives and contest platforms with public report portfolios. Discovery sources supply candidate URLs; acquired original bytes establish report identity. Collectors use public publisher repositories, websites and official contest listings, respect robots.txt, identify requests and limit each host to at most one collection request per second. They retain refusals and failures. Logins, paywalls and browser challenges remain access boundaries.

Each acquired file has a SHA-256 digest, byte count, public URL, retrieval time, source kind and listing URL. GitHub links retain commit-pinned permalinks. A content-addressed local cache holds originals for extraction; the public release contains links and digests. Originals are never re-hosted. URL discovery and collection counts are distinct from confirmed engagement counts.

Hacken coverage combines public audit API metadata and public copies. API records and copies are matched before counting; API-only engagements retain metadata with findings left unobserved. Immunefi coverage distinguishes metadata-only boards from public report files. Terms-restricted sources retain metadata, links and engagement severity totals, with no per-finding rows or finding text released.

## Engagements and dates

One engagement is one publicly evidenced review by one publisher. Exact bytes, source-explicit alternate renderings, report-family evidence, audited scope and supported identity anchors merge revisions, translations and PDF/Markdown copies. Independent rounds stay separate. Per-scope reports, including Cantina reports, remain separate when their audited scope differs. Disjoint implementation scope blocks unsafe merges. Joint audits share an industry ID and retain one publisher participation per firm.

Audit year uses an explicit completion date, then report issue date. Official contest end dates qualify for contest engagements. Publication dates form an independent series. Filename, crawl and Git timestamps remain discovery hints. Conflicting eligible years stay unknown, as do missing years. Eligible dates keep their source assertion, precision and locator. The latest year is year to date without annualisation.

## Audit types

Each engagement receives one audit type: token-only, protocol, infrastructure, wallet or account, NFT or game, or other or unclear. Rules use reported scope; an AI-assisted pass handles weak or unclear evidence and requires a supported quote and confidence threshold. Held-out accuracy is 71.9% on 210 engagements across 64 publishers. The stratified sample oversamples unclear and token candidates, so its accuracy describes that sample. Other or unclear records preserve insufficient or conflicting evidence.

## Parsing and selection

PDF text is extracted with layout preservation and page boundaries. Sparse or image-only pages use OCR with diagnostic receipts. Markdown retains headings and fenced code; HTML becomes text with scripts and style removed. Report-specific parsers identify formal finding sections, titles, printed IDs, severity, status, bodies and page spans. Layout fingerprints choose grammars; unknown layouts remain flagged. Printed summary counts are an independent diagnostic and never manufacture findings.

The statistics select one initial formal-finding stream per publisher engagement: primary relationship before revisions or supporting documents, current parser output before legacy imports, PDF before Markdown/HTML, then stable document ID. Fix reviews, alternate translations and later finding phases remain additional occurrences. An empty parser stream establishes zero only with explicit zero counts for every required summary bucket. Other empty results stay unobserved.

Release text follows publisher notices. Restricted bodies use `text_withheld='publisher_notice'` and `body_text_status='publisher_notice'`. Oversized bodies are bounded and flagged; credentials and personal contact details are masked with redaction metadata. Oak Security bodies are exact contiguous verbatim excerpts with attribution and a source link; excerpt cuts carry `body_truncated=true`. Required character changes within a kept Oak span trigger `oak_transform_required` withholding. Normalised titles and annotations are separate from verbatim body text.

## Severity and status crosswalks

[schema/severity_map.json](schema/severity_map.json) maps publisher labels to `critical`, `high`, `medium`, `low`, `info`, `gas` and `unknown`. Publisher definitions and supported policy eras take precedence over familiar spellings. Missing or unresolved labels stay unknown. Original strings are retained.

[schema/status_map.json](schema/status_map.json) maps explicit remediation assertions to `fixed`, `partially_fixed`, `acknowledged`, `unresolved` and `not_stated`. A recommendation or future fix does not establish completed remediation. Publisher-specific definitions resolve labels such as closed or not fixed. Scope, validity disputes and unlabeled prose stay separate. Recorded status describes the report at publication.

## Taxonomy and classifier

[schema/taxonomy.yaml](schema/taxonomy.yaml) defines root-cause groups and leaves with inclusion rules and tie-breaks. Each finding receives one primary supported root cause; quality and gas remain distinct from security classes. Thin evidence produces `unclassified.insufficient_evidence`.

The frozen taxonomy prompt hash includes example excerpts; the published taxonomy omits those excerpts.

Both the extraction gold labels and taxonomy annotations were made by LLM annotators from the original documents or supplied finding excerpts. Three LLM annotators labelled the taxonomy sample independently. Independent annotations provide measured cross-model agreement. The evaluation measures agreement with model reference labels.

Unclassified means selected initial formal findings assigned `unclassified.insufficient_evidence` because the supplied evidence did not support a taxonomy leaf: **3,093 of 162,293 (1.9%)**. The **1,020** selected findings with a null class are recorded separately as unlabelled.

Production classification uses normalised title and the first 3,000 body characters, medium reasoning effort, frozen prompts and content-key receipts. The content key binds publisher, title, excerpt and taxonomy inputs; changed source bytes invalidate stale labels. One retry or top-up pass handles incomplete responses. Validation checks one allowed leaf per item, finite confidence, complete indices and evidence receipts. Confidence is an uncalibrated model score.

## Evaluation

The held-out extraction set contains 150 documents across 61 publishers. One non-audit document is excluded from scoring; previous-audit rechecks are removed from the finding denominator. Recall uses reference findings; precision uses predicted findings. Severity and status agreement use matched findings. The set was held out from parser development.

| Measure | Agreement | Matched / reference | Wilson 95% CI |
|---|---|---|---|
| Finding recall | 96.12% | 1,833 / 1,907 | 95.2%-96.9% |
| Finding precision | 99.24% | 1,833 / 1,847 | 98.7%-99.5% |
| Severity | 98.69% | 1,809 / 1,833 | 98.1%-99.1% |
| Fix status | 93.67% | 1,717 / 1,833 | 92.5%-94.7% |

The taxonomy sample contains 300 findings labelled independently by 3 LLM annotators. Pairwise agreement ranges from 74.67% to 80.33% at leaf level and 83.67% to 86.00% at group level. The production classifier agrees with the majority on 84.23% of leaves (Wilson 95% CI 79.5%-88.0%) and 87.76% of groups (Wilson 95% CI 83.5%-91.1%), using only items with a majority. Model families can share errors; agreement provides a reproducible reference comparison.

Confirmed completion/issue-year coverage is **12,578/12,767 (98.5%)** of industry engagements. This is a full-release coverage proportion. Wilson 95% intervals accompany binomial sample measurements with recorded numerators and denominators; pairwise ranges retain the reported values where exact numerators are unavailable.

Independent engagement samples compare source-supported years and publishers to the final database. Publisher-stratified samples use unequal selection weights. Scores describe samples; layout variation, OCR errors and ambiguous class boundaries remain. All recorded measurements and denominators follow:

| Area | Metric | Value | Numerator | Denominator | Wilson 95% CI |
|---|---|---|---|---|---|
| findings_extraction | gold_documents | 150 |  |  |  |
| findings_extraction | gold_publishers | 61 |  |  |  |
| findings_extraction | gold_findings | 1907 |  |  |  |
| findings_extraction | recall | 0.961196 | 1833 | 1907 | 95.2%-96.9% |
| findings_extraction | precision | 0.99242 | 1833 | 1847 | 98.7%-99.5% |
| findings_extraction | severity_accuracy | 0.986907 | 1809 | 1833 | 98.1%-99.1% |
| findings_extraction | status_accuracy | 0.936716 | 1717 | 1833 | 92.5%-94.7% |
| engagements | year_accuracy_v6 | 0.99 | 198 | 200 | 96.4%-99.7% |
| engagements | firm_accuracy_v6 | 1 | 200 | 200 | 98.1%-100.0% |
| engagements | year_accuracy_v5 | 1 | 300 | 300 | 98.7%-100.0% |
| engagements | firm_accuracy_v5 | 1 | 300 | 300 | 98.7%-100.0% |
| engagements | confirmed_year_coverage | 0.985196 | 12578 | 12767 | 98.3%-98.7% |
| taxonomy | annotators | 3 |  |  |  |
| taxonomy | annotated_findings | 300 |  |  |  |
| taxonomy | pairwise_iaa_leaf_min | 0.746667 | 224 | 300 | 69.5%-79.3% |
| taxonomy | pairwise_iaa_leaf_max | 0.803333 | 241 | 300 | 75.5%-84.4% |
| taxonomy | pairwise_iaa_group_min | 0.836667 | 251 | 300 | 79.1%-87.4% |
| taxonomy | pairwise_iaa_group_max | 0.86 | 258 | 300 | 81.6%-89.5% |
| taxonomy | classifier_leaf_vs_majority | 0.842294 | 235 | 279 | 79.5%-88.0% |
| taxonomy | classifier_group_vs_majority | 0.877622 | 251 | 286 | 83.5%-91.1% |

## Link checks

The link-check snapshot contains 14,306 distinct digest/URL links, of which 14,155 (98.9%) were reachable. HEAD requests use short GET fallbacks, robots-aware redirects, per-host pacing and retry backoff. GitHub checks compare pinned tree objects with original Git blob digests. Failed links receive archive lookups. Reachability includes landing pages and can overstate document availability on hosts serving soft 404s. Independent text extraction matched finding titles and body prefixes for 299/300 sampled findings (99.7%; Wilson 95% CI 98.1-99.9%).

## Coverage survey

A separate survey rebuilt public publisher listings for the recent publication window and sampled older entries from the largest listings. Matching uses URLs, repository paths, blob identity and filenames, then weaker title/date evidence. The following is the survey snapshot before follow-up collection; it measures recall within the surveyed listings:

| Sample | In scope | In dataset | Recall | Strong matches | Missing |
|---|---|---|---|---|---|
| random | 150 | 146 | 97.3% | 146 | 4 |
| window | 559 | 536 | 95.9% | 526 | 23 |

Public listings, archive gaps, access refusals and missing usable publication dates limit coverage. Collection coverage per publisher is published in `firms.csv`; a null percentage means not measured. Selective disclosure and missing public reports limit this collection. Finding counts and recorded statuses describe report scope and publisher labelling practice.

Known coverage gaps include Trust Security: 3 confirmed audits, 0 selected findings and collection coverage not measured. Immunefi has 59 collected reports and 60 confirmed engagements. Measured collection coverage is Fuzzland 86%, Theori 12%, Three Sigma 100%, Veridise 82%. Collection coverage is unmeasured for Secure3. Collection totals and confirmed engagement totals reflect different stages of the evidence pipeline.

Cyfrin and CodeHawks were removed at their request on 2026-10-28.

## Rebuilding

Use Python 3.11 or newer with the pinned dependencies in the public `requirements.txt`. `make test` runs offline tests with synthetic fixtures. `make demo` builds a synthetic website. Release assets are downloaded separately; verify `CHECKSUMS.sha256` before use.

Acquire public originals through `scripts/collect/`, build report and engagement identities using `scripts/build/` and `scripts/phase3/`, extract findings using `scripts/findings/`, and prepare and validate classification inputs using `scripts/classify/`. Supply model responses through a separately managed service. Frozen prompts, response validation and usage-error guards are included. Local caches, reference labels and extraction receipts are separately acquired inputs with recorded versions.

To rebuild the agent formats from the downloaded database, run `python3 -B -I scripts/release/agent_formats.py --release release --out build/agent-formats`. To prepare the database edition from an existing release, run `python3 -B -I scripts/release/build_database_release.py --release release --out build/database-release`. The latter preserves source tables, filters the descriptive statistics through an explicit table contract, removes incident measurements from quality outputs, and regenerates checksums. It requires the source release's unpacked `stats/` folder. The output directory must be empty.

The public source export contains data preparation code, schemas, synthetic fixtures, descriptive tables and database documentation. The research analysis is released separately. Fix the cutoff when reproducing a published snapshot. Agent formats use only the released finding text and preserve text availability, attribution and licence fields.
