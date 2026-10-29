# Corpus schema reference

[corpus.sql](corpus.sql) defines the relational database tables, constraints and
views. The public release column reference is [DATA_DICTIONARY.md](../docs/DATA_DICTIONARY.md).

## Tables

| Table | Key and contents |
|---|---|
| `publishers` | `publisher_id`; firm or contest-platform identity, display name, report listings and registry metadata. |
| `documents` | `document_id`; source report occurrences, publisher, public URL, original digest, format, metadata, rights and provenance. Unique on `(source_tag, source_record_id)`. |
| `engagements` | `engagement_id`; publisher, project, engagement kind, identity status and supporting evidence. Confirmed rows require an `industry_engagement_id`. |
| `engagement_documents` | `(engagement_id, document_id)`; links documents to engagements with a `primary`, `revision`, `translation`, `alternate` or `supporting` role. Each document has at most one link. |
| `document_exclusions` | `document_id`; reason and evidence for excluding a document from engagement identity. |
| `engagement_identity_crosswalk` | `previous_engagement_id`; maps merged identities to their retained engagement and records the basis. |
| `findings` | `finding_id`; source finding occurrences, parent document, title, original and normalised severity/status, narratives, categories and evidence. Unique on `(source_tag, source_record_id)`. |
| `date_claims` | `claim_id`; date assertions targeting exactly one document, engagement or finding, with role, precision, authority and evidence. |
| `contests` | `contest_id`; official contest identity, sponsor, dates, format, report link, published finding totals and optional document/engagement links. Unique on `(publisher_id, platform_contest_id)`. |
| `import_sources` | `source_file`; input snapshot digest, byte size and reconciliation counts. `source_rows = imported_rows + excluded_scope_rows + duplicate_rows`. |

## Field conventions

IDs are stable strings. Foreign keys retain publisher, document and engagement
relationships. `source_tag`, `source_record_id` and `source_locator` identify the
input occurrence. `source_record_sha256` hashes its canonical source-row JSON;
`documents.sha256` identifies original report bytes when available.

`provenance`, `evidence`, `relationships` and `field_state` hold JSON receipts,
source assertions and reasons for missing values. A null value records absence
or uncertainty; an explicit observed count can be zero. Narratives and raw labels
preserve source wording, subject to the published rights and redaction rules.

| Field | Values |
|---|---|
| `publisher_kind` | `firm`, `contest_platform` |
| `doc_kind` | `audit_report`, `fix_review`, `contest_report`, `formal_verification`, `non_report`, `unknown` |
| `identity_status` | `provisional`, `confirmed`, `excluded` |
| `engagement_kind` | `audit`, `contest`, `formal_verification`, `other` |
| `severity` | `critical`, `high`, `medium`, `low`, `info`, `gas`, `unknown` |
| `status` | `fixed`, `partially_fixed`, `acknowledged`, `unresolved`, `not_stated` |
| Date `precision` | `year`, `month`, `day`, `none` |
| Date `role` | `audit_start`, `audit_completion`, `report_issue`, `publication`, `retest`, `filename_hint`, `catalog`, `other` |

## Views and dates

`counted_engagements` selects confirmed identities. `industry_engagements` exposes
their distinct industry IDs. `engagement_years` selects eligible publisher audit
completion claims before report issue claims; conflicting best-priority years
produce a null year and `year_conflict=true`. `engagement_publication_years`
provides the separate publication series. Dates retain their stated ISO precision.

## Crosswalks and taxonomy

[severity_map.yaml](severity_map.yaml) and [severity_map.json](severity_map.json)
provide the publisher/era severity crosswalk. [status_map.json](status_map.json)
defines remediation labels and ordered fallback rules. Mapping receipts retain
the original label, selected policy/era and evidence.

[taxonomy.yaml](taxonomy.yaml) defines vulnerability groups, leaves, inclusion and
exclusion rules, tie-breaks and released finding examples. Examples contain
`finding_uid` and `public_url`. The taxonomy matches the release artifact.

See [the methods](../METHODS.md#severity-and-status-crosswalks) for mapping and
selection rules and [the data dictionary](../docs/DATA_DICTIONARY.md) for release
fields, selection flags and text availability states.
