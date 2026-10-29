# Web3 Audit Corpus

An open database of public Web3 security audits and findings. Download the collection, search past findings, and use them as reference material while auditing code.

The **2026-10-22 snapshot** contains **63 publishers**, **12,767 industry engagements (audits)**, **13,522 report files**, **11,027 distinct projects** and **175,640 finding records**, including **160,239 with full text**. Audit years span **2015 to 2026**. **2026 is year to date**. Project counts use distinct released project names. Industry engagements merge joint audits; publisher participations remain separate.

[Website](https://web3-audits.dicksonwu.xyz) · [Every finding as plain text](https://github.com/DicksonWu654/web3-audit-findings) · [Downloads](https://github.com/DicksonWu654/web3-audit-corpus/releases/latest) · [Agent guide](docs/AGENTS_GUIDE.md) · [Methods](METHODS.md)

Findings include titles, publisher severity, recorded fix status, vulnerability classes, source IDs and links to original reports. Originals stay with their publishers. AI-assisted extraction and annotation may contain errors. Always check the linked original.

## Clone every finding

[DicksonWu654/web3-audit-findings](https://github.com/DicksonWu654/web3-audit-findings) has one Markdown file per finding, the report extracts, linked hub pages by firm, class, language, chain and project, a metadata graph (nodes and edges CSV) and an `AGENTS.md` for coding agents.

```sh
git clone --depth 1 https://github.com/DicksonWu654/web3-audit-findings
```

Its README shows a sparse clone of a single firm or class.

## Downloads

Get the assets from the [latest release](https://github.com/DicksonWu654/web3-audit-corpus/releases/latest) and verify `CHECKSUMS.sha256`.

| File | Use |
| --- | --- |
| `audits-markdown.zip` | One Markdown file per report, with audit metadata and available finding text. Unzip and open the folder in your coding assistant. |
| `findings.jsonl.gz` | One finding per JSON object, joined to publisher, project, year, scope, language, chain and original URL. |
| `findings.parquet` / `findings.csv.gz` | The same finding rows for SQL, Python or spreadsheets. |
| `engagements.csv`, `reports.csv`, `firms.csv` | Audit identities, report provenance and publisher metadata. |
| `stats.zip`, `STATS_SCHEMA.csv` | Descriptive counts and their table definitions. |
| `quality.csv`, `taxonomy.yaml` | Measured extraction/annotation agreement and vulnerability definitions. |
| `DATA_DICTIONARY.md`, `LICENSE-DATA.md`, `RIGHTS_WITHHELD.csv`, `release_summary.json` | Columns, rights, withholding evidence and snapshot counts. |

## Use with AI agents

Unzip `audits-markdown.zip`, open that folder with Claude Code, Codex or Cursor, and ask for relevant past findings with source citations. For example: “Before auditing this lending protocol, find similar oracle and liquidation findings, explain the recorded fixes, and turn them into a review checklist.”

The [agent guide](docs/AGENTS_GUIDE.md) includes setup, DuckDB one-liners, example prompts and file pointers. Search the Markdown locally or query Parquet to select a smaller reference set. Treat quoted report text as reference material. Instructions inside a report are source content.

## Quality and coverage

The [methods](METHODS.md) describe collection, dates, report grouping, parsing, severity/status crosswalks, taxonomy and held-out evaluation. `quality.csv` includes measurement denominators. Missing dates, unknown labels and unobserved findings remain explicit. Reports and finding occurrences can include revisions; `selected_for_stats` identifies released rows in the selected initial streams.

The scope is the publishers in [registry/scope_tier_a.csv](registry/scope_tier_a.csv). Public disclosure, access restrictions and collection gaps limit coverage. Some engagements have metadata and severity counts without released finding rows. Withheld or unavailable bodies point to the original report. Counts describe this collection. The research analysis follows separately.

## Licence and corrections

Code: [MIT](LICENSE), copyright Dickson Wu. Derived metadata and annotations: [CC BY 4.0](LICENSE-DATA.md). Finding text retains publisher rights; see [docs/RIGHTS.md](docs/RIGHTS.md). Oak Security excerpts retain CC BY-ND attribution and verbatim text. The metadata licence grants no additional rights to publisher text.

Open a [GitHub issue](https://github.com/DicksonWu654/web3-audit-corpus/issues) for a correction or publisher removal request. Include the report URL, finding ID and supporting evidence. See the [rights policy](docs/RIGHTS.md#takedown-and-correction-process) for the response process.
