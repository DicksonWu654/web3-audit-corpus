# Data licence

## Derived metadata and annotations: CC BY 4.0

Derived report, publisher and engagement metadata, normalised severity and status, vulnerability annotations, the taxonomy, selection flags, page spans, quality measurements and aggregate statistics are licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).

Attribution: “Web3 Audit Corpus, Dickson Wu, https://github.com/DicksonWu654/web3-audit-corpus”. State changes when adapting these derived data and retain links to the original sources.

## Quoted finding text and original reports

Finding titles, body text and verbatim publisher labels remain the copyright of the publishers identified in `firm_id`. They are quoted from publicly released audit reports for research, criticism and commentary so findings can be searched, classified and studied. Each finding links its source. The CC BY grant covers this project's derived data; publishers' text remains subject to their own rights and notices.

Where a publisher's explicit notice forbids reproduction, finding bodies are withheld (`text_withheld='publisher_notice'`, `body_text_status='publisher_notice'`) and metadata plus a source link remain. Original reports are linked, never re-hosted. Report-specific licences govern the quoted text. See [docs/RIGHTS.md](docs/RIGHTS.md) for decisions and requests.

**Oak Security:** © Oak Security. Reports carry [CC BY-ND 4.0](https://creativecommons.org/licenses/by-nd/4.0/). Reproduced finding bodies are verbatim extracted text, with publisher attribution and a link to the report. Bodies requiring modification are withheld in full. Normalised annotations are separate fields.

**Trail of Bits:** © Trail of Bits, Inc. The canonical source is the [Trail of Bits Publications repository](https://github.com/trailofbits/publications). Report-specific no-reproduction notices govern withholding. This project retains attribution, metadata and canonical source links. Restrictive report notices govern withholding of body text.

**Kudelski Security / Nagravision and ChainLight / Theori:** bodies carrying explicit reproduction, distribution or confidentiality restrictions are withheld pending permission.


## Redactions and requests

Release text masks credentials, non-test private keys, unknown mnemonics and personal contact details found in public reports; redaction and truncation flags identify changes. Known test keys and phrases in proof-of-concept examples are public test material; never fund them. Oak's verbatim policy uses withholding wherever a body would need changes.

Publishers can request correction or removal through a [GitHub issue](https://github.com/DicksonWu654/web3-audit-corpus/issues). Requests are acknowledged within seven days; requested finding text is withheld within seven days while the request is reviewed. Metadata and source links remain unless their correction or removal is also warranted. The next hosted build and release incorporate the correction; the issue records affected versions and completion.

## Warranty

Data is provided as is, with measured sample agreement in `quality.csv`. Automated extraction and classification can contain errors. Incident scope labels are AI-assisted judgements reported in aggregate. Users should read the source report and assess its scope before relying on a finding.
