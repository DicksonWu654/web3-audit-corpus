# Data dictionary: web3-audit-corpus release

`scripts/release/build_database_release.py` prepares the database edition from existing release tables.
The release includes stable UTF-8 CSV, Parquet, deterministic gzip and ZIP files, and `CHECKSUMS.sha256`.
Original report bytes remain with their publishers.

Conventions: empty CSV cells are null; booleans are `true`/`false`; list-valued cells are compact JSON
arrays; identifiers are stable hashes. A hashed report uses its original SHA-256 as `report_id`; an unhashed
source uses `unhashed:<SHA-256 of URL>`. `firm_id` is the stable Tier A registry id and `name`/`firm` is a
curated public display name. The scope registry defines the release population.

## firms.csv

One row per Tier A publisher. `firm_id` is the stable registry id; `name` is the curated display name;
`kind` is `firm`, `collective`, or `contest_platform`; `website` is the public publisher site;
`reports_listed` and `reports_collected` are collector counts; `coverage_pct` is the measured coverage
percentage. When a publisher does not expose comparable counts, `coverage_note` gives the reason. The year,
engagement, report, and finding columns are release counts.

`coverage` distinguishes `public_portfolio`, `lower_bound_third_party_public_copies`, and
`public_sca_api_plus_third_party_copies`. The flag accompanies descriptive publisher counts. Mirror-file and API-record
populations have null `coverage_pct` when their counts cannot support a coverage percentage.

## reports.csv

One row per distinct source file. `report_id` and `sha256` identify the original bytes; `url` is the public
canonical link; `permalink` is a commit-pinned GitHub link; `archive_url` is a web archive copy when needed.
`link_status` and `link_checked_at` are joined from `link-check input table`. `file_type`, `pages`,
`source_kind`, `doc_kind`, `document_role`, `title`, `engagement_ids`, `firm_ids`, and `alternate_urls`
describe the source and its uses. No report file is redistributed.

`text_withheld=publisher_terms` and `body_text_status=publisher_terms` mark a report whose collection host terms prohibit automated access, copying or mining, or whose robots rules disallowed its path. The report metadata, SHA-256, dates, audit type and public link remain. No finding row or finding text from that report is released. A permitted alternate source is used only after original SHA-256 or documented content-equivalence verification; those reports release normally. Publisher notice and licence restrictions remain separately identified.

## engagements.csv

One row per publisher engagement. `industry_engagement_id` groups joint audits; `review_mode` is
`firm_review` or `contest`; date fields preserve stated completion or publication evidence; `findings_count`
is the selected initial finding count and is null when unobserved; `findings_released` counts every released
finding row for the engagement; `report_ids` lists all source files.

`findings_critical`, `findings_high`, `findings_medium`, `findings_low`, `findings_info`, `findings_gas`, and `findings_unknown` are nullable integer severity counts from the selected initial stream. Their sum is `findings_count` for an observed stream. A validated zero stream has seven zeros; an unobserved stream has null counts. These engagement-level counts remain available when publisher terms withhold the underlying finding rows.

`findings_withheld` counts all occurrence rows withheld under the terms policy for this engagement. `initial_findings_withheld` counts the withheld selected initial rows. `text_withheld=publisher_terms` and `body_text_status=publisher_terms` identify engagements linked to at least one restricted report; another permitted report can still supply releasable rows. `findings_released` counts only rows present in the public findings table.

`audit_type` describes the audited scope, independently of publisher and review format. Every engagement,
including metadata-only records, has one label and `audit_type_basis=rule|llm|abstain`.
Confident rules remain authoritative; unclear or weak rule evidence receives the frozen
AI-assisted pass. Prompt, input, output and launch hashes are retained in the
local receipts and the engagement's evidence. Inadequate or conflicting evidence is an
explicit `other_or_unclear` abstention. Strict builds require every requested model result. An explicitly enabled uncached-abstention build records missing results as `other_or_unclear` with `audit_type_basis=abstain` and preserves input receipts.
Token-only engagements remain in the default counts for every publisher.

| `audit_type` | Scope |
| --- | --- |
| `token_only` | A single fungible token contract, including ERC-20, BEP-20 or SPL mint/burn/tax/vesting-only logic. Broader application or DeFi logic is excluded from this label. |
| `protocol` | DeFi or application logic, including a token reviewed alongside broader protocol functionality. |
| `infrastructure` | L1/L2 clients, bridges, zero-knowledge circuits, cryptography and node software. |
| `wallet_or_account` | Wallets, smart accounts and multiparty computation account/key systems. |
| `nft_or_game` | NFT or game scope. |
| `other_or_unclear` | Other scope, insufficient evidence, or conflicting scope signals; an explicit abstention. |

Classify the behavior under review: lending, yield or capital-allocation systems remain `protocol`
when NFTs represent financial positions. NFT minting, collectibles and game logic use `nft_or_game`.
A multisig administrator or a reference to a user's wallet does not make an application a wallet audit;
vesting wallets remain token release scope. Cryptographic primitives use `infrastructure`, while wallet
signing and custody systems use `wallet_or_account`. Incomplete or conflicting parent scopes abstain.

Rules use report/project titles, initial pages and scope sections of cached source text, finding titles,
chain/language fields, and Hacken API scope fields when present. Report availability affects the evidence available for the same scope definitions. The source label receipt is bound to the database snapshot when a sidecar supplies
labels for a database built before these columns existed.

## findings.parquet and findings.csv.gz

Both files contain the same finding rows. Contract columns include `finding_uid`, engagement/report/firm ids,
publisher `finding_id`, `title`, original `severity_original` and display `status_original` (letter spacing normalised), frozen canonical
`severity` and `status`, vulnerability taxonomy fields, `body_text`, page span, and `extraction_variant`.
Extension columns are `source`, `finding_phase`, `ordinal`, `selected_for_stats`, `body_text_status`,
`text_withheld`, `body_text_redactions`, `body_truncated`, `text_attribution`, `text_license`,
`text_license_url`, and `text_source_url`.

`selected_for_stats=true` identifies released rows belonging to the selected initial stream. Engagement severity analyses can additionally use the permitted aggregate counts from terms-restricted reports. `body_text_status` values on released finding rows are `not_in_gold_label`, `not_in_source`, `oak_transform_required`, `present`, `publisher_notice`. The value `publisher_terms` appears on report/engagement metadata only, because no finding row from such a source is released. `body_text` is cut at the next finding in the same
document using ordered `body_span` offsets, then at report tails headed appendix, disclaimer, about the firm,
methodology, severity definitions, legal/contact notices, or repeated page headers/footers. It is capped at
15,000 characters. A capped value has `body_truncated=true` and normally ends with
`[truncated; see the linked report]`. Oak text uses only an external site note: it never receives an inserted
marker. For Oak, `body_truncated` also flags a boundary, tail or page-furniture cut.

Publisher rights notices are scanned across every confirmed report using the reviewed patterns in
`scripts/release/common.py`. A report carrying an explicit no-reproduction, no-distribution, or confidential
notice has no released body text: retained finding metadata has `body_text=null` and `text_withheld=publisher_notice`. This notice handling is separate from publisher_terms, which removes entire finding rows.
The matched excerpt (at most 200 characters), firm, report SHA-256, and pattern name are recorded in
`RIGHTS_WITHHELD.csv`. Oak Security report text is CC BY-ND 4.0, whose section 2(a)(1)(A) permits sharing in
whole or in part. Oak bodies are exact contiguous excerpts; cleanup may cut at page furniture, but never
join the text before and after it. Only required character changes inside the kept span (including masking
or title repair) cause `text_withheld=oak_transform_required`. A title requiring a change is withheld too.
Every Oak row carries publisher attribution, the licence name/URL, and its report source URL in the four
`text_*` rights fields. Other publishers currently have null rights fields. The site displays Oak attribution
and licensing beside the source link and keeps its truncation note outside the quoted body.

Before release, text and titles are masked for AWS/GCP keys, API keys, password-bearing database URIs,
third-party tokens, private keys, mnemonics, personal email addresses, and phone numbers. Replacements are
`[REDACTED-CREDENTIAL]`, `[REDACTED-KEY]`, `[REDACTED-EMAIL]`, and `[REDACTED-PHONE]` respectively.
Role addresses such as `security@` and `info@` remain. `body_text_redactions` counts each class for that row;
release diagnostics aggregate these counts. A bare 64-hex value is preserved: storage slots, role hashes,
transaction hashes and Merkle roots have valid public uses. Hex key masking requires an adjacent
private-key label/assignment (`private key`, `privateKey`, `PRIVATE_KEY`, `pk`, `priv`, or `--private-key`),
a `new Wallet(...)` constructor, `vm.addr(...)`/`vm.rememberKey(...)` argument, or a line assigning `.env`
`KEY=`. PEM private-key blocks and labelled mnemonics are also masked. Unlabelled English BIP39 phrases
are detected from the 2,048-word list and entropy checksum (12, 15, 18, 21 or 24 words), including quoted
JSON values and line-wrapped phrases. Unlabelled candidates require at least eight distinct words within
a run of at most 48 words; this preserves repetitive “Pass” checklist cells and full word lists. Explicitly
labelled phrases are masked independently. This check never derives an account or uses a network service.

The 20 public Hardhat/Anvil account keys remain unchanged, including in private-key contexts. These are
derived from the documented mnemonic (`test` eleven times followed by `junk`) at `m/44'/60'/0'/0/i`, i=0..19;
they are public development fixtures. Sources: [Hardhat accounts](https://v2.hardhat.org/hardhat-network/docs/reference#accounts)
and [Anvil reference](https://getfoundry.sh/anvil/reference/). the release diagnostics reports the legacy matcher
count on the same publishable source text, the current private-key replacement count, and 20 seeded random
contexts each for masked keys and retained hex values; the audit contexts never reproduce a key value.

Four public mnemonic fixtures are also preserved: the Hardhat/Anvil default above, Ganache CLI's
`candy maple … sweet treat` default, and BIP39's `abandon … about` and `legal winner … yellow` test vectors.
They are public development/test fixtures. Sources:
[Ganache CLI](https://github.com/trufflesuite/ganache-cli),
[BIP39 test vectors](https://github.com/trezor/python-mnemonic/blob/v0.21/vectors.json).
The English list is vendored from [python-mnemonic v0.21](https://github.com/trezor/python-mnemonic/tree/v0.21),
accessed 2026-10-23; its MIT licence is retained in `scripts/release/BIP39_WORDLIST_LICENSE.txt`.

Titles use a conservative repair only when extraction produced a long, mostly single-letter sequence (for example
`R e e n t r a n c y` → `Reentrancy`). Punctuated runs are joined and word boundaries are inferred from normal
corpus prose using a deterministic word-frequency model. Rare technical identifiers may retain imperfect
word boundaries. Normal titles are unchanged. Normalised titles are retained separately from verbatim body text.

Severity and status use the frozen resolver modules and maps in `scripts/findings/severity_resolve.py`,
`scripts/findings/status_resolve.py`, and `schema/severity_map.json` and `schema/status_map.json`. This mapping is kept fixed so published
statistics and evaluation labels remain comparable across rebuilds; recorded remediation labels describe report assertions at publication.

Held-out gold documents (150 reports from 61 publishers) were skipped by production parsers. Their LLM-annotated
labels supply metadata-only finding rows (`source=gold_label`, `selected_for_stats=false`, null body).

## quality.csv

Columns are `metric`, `value`, `numerator`, `denominator`, `ci_low`, `ci_high`, `sample`, `source`, and
`area`. Any private source path is replaced by `held-out evaluation set (150 reports, 61 publishers), see
METHODS.md#quality`. Gold labels and taxonomy annotations were produced by three independent LLM annotators; cross-model agreement is measured in the quality rows.

## audits-markdown.zip

One UTF-8 Markdown file for every row in `reports.csv`, plus root `README.md` and `INDEX.csv`.
Paths are `<firm_id>/<audit_year or unknown>/<project-slug>-<report_id[:8]>.md`. Slugs are ASCII, lower case and limited to 100 characters.

YAML front matter contains `firm` (display name), `firm_id`, `project`, `audit_year`, `audit_date_min`, `audit_date_max`, `audit_date_basis`, `audit_type`, `languages`, `chains` (from `chain_families`), `original_url` (permalink preferred), `report_id`, `engagement_id`, `severity_counts` and `finding_records`. The front matter uses the report's canonical engagement. Each finding section retains its own engagement ID. Severity counts describe the released rows in that file, including metadata-only rows; they differ from selected initial engagement totals.

Each `##` section includes the finding UID, printed ID, title, severity, recorded status, vulnerability group/leaf, text availability, truncation, redaction and four text-rights fields. Permitted `body_text` is copied character for character between body markers. An unavailable body has a line pointing to the original report. Extra notes and metadata sit outside the verbatim body. Reports without released findings still have a file with zero finding records.

`INDEX.csv` columns: `path`, `report_id`, `engagement_id`, `firm_id`, `firm`, `project`, `audit_year`, `original_url`, `finding_records`, `full_text_records`. There is one index row per report Markdown file. `full_text_records` counts nonempty bodies permitted by the availability rule.

## findings.jsonl.gz

One UTF-8 JSON object per row in `findings.parquet`, preserving all source columns and their types. Added fields: `firm`, `project`, `audit_year` (integer or null), `audit_date_min`, `audit_date_max`, `audit_date_basis`, `audit_type`, `languages` (array), `chains` (array) and `original_url`. Joins use the finding's engagement and firm IDs, and its report ID. Objects are sorted by report Markdown path and finding UID. Gzip has a fixed timestamp and no source filename.

Both agent formats emit a body only when `text_withheld` is empty and `body_text_status='present'`. Other JSON bodies are null. `text_attribution`, `text_license`, `text_license_url` and `text_source_url` retain the exact Parquet values, including nulls and Oak Security terms. These formats add no finding text from originals or other caches.

## stats.zip and STATS_SCHEMA.csv

Unpack `stats.zip` to obtain the descriptive `stats/*.csv` tables. `STATS_SCHEMA.csv` defines every table's key columns, full column order and denominator notes. It is also available in the source repository as `docs/STATS_SCHEMA.csv`. Statistics cover counts by publisher, audit/publication year, severity, vulnerability class, audited scope and review mode, physical PDF pages, first/last observed years and collection coverage class. Finding tables select initial formal streams and can include permitted engagement-level counts from reports whose finding rows are withheld. Unknown and unobserved values stay explicit. Percentages, means and medians describe the recorded population.

## Other release files

`taxonomy.yaml` defines vulnerability groups and leaves with source-linked examples. `quality.csv` records data extraction and annotation measurements and denominators. `RIGHTS_WITHHELD.csv` records report-notice evidence and release decisions. `LICENSE-DATA.md` describes derived-data licensing and publisher text rights. `release_summary.json` records the version, snapshot date, year-to-date flag, database counts, body availability counts and descriptive table inventory. `CHECKSUMS.sha256` covers every other asset and unpacked statistics CSV.

## Limits

AI-assisted extraction and annotation may contain errors. Finding rows are occurrences and can repeat across revisions. Use `selected_for_stats` and engagement IDs for selected initial streams. Missing bodies, labels and years remain unknown. Always check the original report before using a finding as audit evidence. See [AGENTS_GUIDE.md](AGENTS_GUIDE.md), [RIGHTS.md](RIGHTS.md) and [the methods](../METHODS.md).
