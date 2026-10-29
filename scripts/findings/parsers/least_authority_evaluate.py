"""Local development evaluation for Least Authority, iosiro and Informal Systems.

Run parsers first, then: python3 scripts/findings/parsers/least_authority_evaluate.py --write
No network, source execution or holdout text reads. ID checks are independent source
heading/index checks, not gold recall or independently reviewed semantic accuracy.
"""
import argparse
from collections import Counter,defaultdict
import importlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import ROOT,read_snapshot,holdouts,digest,write_json
from core import Report

FIRMS=('least-authority','iosiro','informalsystems')
# Generated once from date-spread development PDFs/pages; hashes remain fixed.
SAMPLES = {'least-authority': ['90583c2409b5da39420e3baec8e63eba209a344bad67bb7a063a8121610cde0b', '37c1e112861ae2240f6996d6ecc8bf3d6149c71760e0ef817a9cf9745de579e9', '92210f84c6f341721c8b5d83744419bd0f387fafbb0ed6214d02b81564cb79ec', 'a24ae20d8d26c8823a8f7b4b3f7652f1e834b40be265a22a9195bed71e346bfe', '31d15f38e9a7d2bbed74a5657d10b6640d79264b0636e4bc46aa0f427b9b5ca5', '87dd31309031472f3056274530fc0c4ba914dec19fe80f5fd88cf7833440bdb4', 'b0bfd26cc4c56ffac7981b2ca33644886d8e6ba520e99a536e96a16abce71e4a', '9c1b32f390dadbbcc81ef861e7f77261fbea2b0d0b62fed7dfc6ba3ced3be164', '4b53c6c01777b3fed2897fb75ee4b9749c3d798b7c082606679d7bb9726587f9', '2216485e2a8edb9f34c47731bfd535d3c6e64af3903e4b2845ef8c6ff29cc221', '9fd409fa2037d4d01ed051cd24fe67afffefdae30028a540acbf3190bd77275d', '3e44976af4af2d3605b16df2bdd0bbd1df01d688f465bd06f34276ca7920aa37', 'c2d92f49fdbc51247b94674163390f41cfe9104f72b56a77ae24e2ec19aff586', '8988c14290ceb885147d7e86aa87d53188c3cad0ae8750279419b3f3ad82b7b1', 'a54cf4cd686a930854bcdb98fe5cbcc93f0367b7f90537d267b23bde6f8b8901'], 'iosiro': ['73f2ab839f9a45e06c61bb0a081fe16028bf9aafb933d4b48440896bd7ae4742', 'fc48fd5153252c34c9a552b778f32a85134d214a3978c0e42e7fbb7a3325af5c', 'a0edddae846a309fbf4feefd9160f2219e99fb12cd9be231ae4ff5c92e0dd2bf', '03cac9d18fdde2a811d6be27af6a60fb54f5675bc28c1712d3e8fe59fb2a53e2', 'fa2f5e5df2061437b03c24c7a507639b00019a36335ae0ccef25c495cdc145c3', '87501124bd6b11eb7fc0d91b3af7890c15f33aa793f5ec60bf9fe0c744c5af0d', 'cd7c5ddc4fe973df0c7e9ef6d62b218ee0b4cdd1efa0e61d77c8505ccd4462ec', '89f5b6040dfb94914e54eb97d776facde5ab812ebf11740096f34087a85b6d99', '91f5fdc61e26e9a64ef4d437d182723f03884f60d196ac2c17c2148f0509e60d', 'ea1f798fc9cfd828567af2af9fcae86fa226b9b99557f2a1f6879d95046d52db', '0d8a07f36f72547fb5cc3905e2e80e3e8cd7e583b97ce9a7f43b68b05f687f99', '06f35ead595139f1cfe138288359bd8838e8936a3305cfaff14912163da9a24c', '01826e30d72c22b06a176b177d79e471217365213d30af71c239c2ef35a31534', '714cca3f861104526a84c4481e57bdd5fa2da49a82d6083d56e80c3589d4907c', '6d4abe6b123218f8fcc7ad24508137c4ea47513b3f8a816464958f706bc6d42b'], 'informalsystems': ['6c458bfcca468ac23f1f69f4a0bfb6bd58774dd706c681ef8c4b9a3e3a128fad', '82c37122c69523d7b4395bcb706dd0092cd9558bc8d13a8404bb8ae43ee8d12b', '0b844eab85855b7fd6c9c3bea606f1293a4b70fcd8579e661431d14bcef943cf', '004f1277b00290a2216660e9aba2169c6511c1c477395f513220c8e0966b97f1', '6271e310cec1266f93709e774fa4dab89cce4611736b01432fe951a58de7c74e', 'c80417e7ee34a1e06eac0392cc9fe0dd099bdd16708d60b18eb60eaada627e67', '073fa92b0742a0dbffc66d68ad113ba86de591ece44dc7a9752ecd266b745b53', '8844f7b4432420ad6cbf919a88581f3ed3ac3ce1c0ba53cc27ba3e4cf0e219b6', '752279b7394c4429a37989300d5faa5c45b8ec6633da0f80b728ebf4e45e61f9', '24cc19ba36005ef22cd58bbfa69f2613cb809b214569e2b74f0740bf6209a19e', '5091b3b599da62b1c45d6b89a04c30d23ec1a80dc3b1e90ef4d5883becccc4d0', '45ad098afcb44eba7ef7dbf7f98daf8ab0ab7a60fdc84888474b193d0cb8e1b3', '6208331e2b52eea29a6a8bce0449ca05d13d4ac1921e33afbe743a2de3c2c349', 'ee58da11f399ef2473ed708d095591ba794d6a9fe8ae97d7efb3a7471b950cd7', '5bf611ff6e0b1bd83355c246e4ae35fefe4a94f89315a41d8dfcd9b531f444f1']}

def source_ids(report):
    if report.firm=='least-authority':
        return sorted(set(re.findall(r'(?m)^\s*((?:Known\s+)?Issue\s+[A-Z]{1,3}|Suggestion\s+\d+)\s*:',report.text)))
    if report.firm=='iosiro':
        out=[];root=None
        for line in report.text.splitlines():
            top=re.match(r'^#\s+(\d+)\.?\s+(.*)',line)
            if top:root=top[1] if 'findings' in top[2].lower() else None
            m=re.match(r'^#{3,6}\s+(\d+\.\d+\.\d+)\.?\s',line)
            if m and root and m[1].startswith(root+'.'):out.append(m[1])
        for m in re.finditer(r'<h[1-6]\b[^>]*>\s*<strong>(IO-[A-Z0-9-]+)</strong>',report.text,re.I):out.append(m[1])
        return out
    # IF identifiers on standalone heading lines and the explicit ID field.
    # Repeated in indexes/overview prose are excluded by requiring exact line shape.
    out=[]
    for line in report.text.splitlines():
        m=re.fullmatch(r'\s*(?:ID\s*:?\s+)?(IF-[A-Z0-9_-]+)\s*',line)
        if m:out.append(m[1])
        else:
            m=re.match(r'^\s*(IF-[A-Z0-9_-]+):\s*\S',line)
            if m:out.append(m[1])
    return out

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--write',action='store_true');args=ap.parse_args()
    docs=read_snapshot();blocked=holdouts();by=defaultdict(list)
    for d in docs:
        if d['row']['firm_id'] in FIRMS:by[d['row']['firm_id']].append(d)
    for firm in FIRMS:
        module=importlib.import_module('parsers.'+firm.replace('-','_'))
        findings=[json.loads(line) for line in (ROOT/'data/findings'/f'{firm}.jsonl').read_text().splitlines()]
        actual=defaultdict(list)
        for r in findings:actual[r['sha256']].append(r)
        checked={};samples=[];residual=[];ids_total=ids_recovered=id_docs=id_matches=span_errors=0
        for d in by[firm]:
            sha=d['row']['sha256']
            if sha in blocked:raise RuntimeError('Holdout evaluation denied')
            if sha in checked:continue
            text=(ROOT/'local-cache/fulltext'/f'{sha}.txt').read_text()
            meta=json.loads((ROOT/'local-cache/fulltext'/f'{sha}.pages.json').read_text())
            report=Report(text,meta,firm)
            printed=source_ids(report)
            parsed=[r['publisher_finding_id'] for r in actual[sha] if r['record_kind']=='formal_finding' and r['publisher_finding_id']]
            if firm in {'least-authority','informalsystems'}:
                expected=Counter(set(printed));observed=Counter(set(parsed))
            else:expected=Counter(printed);observed=Counter(parsed)
            missing=list((expected-observed).elements());extra=list((observed-expected).elements())
            if expected:
                id_docs+=1;ids_total+=sum(expected.values());ids_recovered+=sum((expected&observed).values())
                id_matches+=not missing and not extra
                if missing or extra:residual.append({'sha256':sha,'filename':d['row']['filename'],'missing_printed_ids':missing,'extra_parsed_ids':extra})
            for r in actual[sha]:
                span=r['body_span'];body=text[span['start']:span['end']]
                span_errors+=body!=r['body_text'] or not (0<=span['start']<span['end']<=len(text)) or span['text_sha256']!=digest(text.encode())
            if sha in SAMPLES[firm]:
                subset=actual[sha]; summary=getattr(module,'printed_counts',lambda r:None)(report)
                samples.append({'sha256':sha,'filename':d['row']['filename'],'date_hint':d['row'].get('date_hint'),'text_sha256':digest(text.encode()),'characters':len(text),'pages':len(meta['pages']),'printed_ids':printed,'parsed_ids':parsed,'findings':len(subset),'severity_counts':dict(Counter(r['severity'] for r in subset)),'first_title':subset[0]['title'] if subset else None,'last_title':subset[-1]['title'] if subset else None,'printed_summary':summary})
            checked[sha]=True
        stats=json.loads((ROOT/'data/findings/validation'/f'{firm}.json').read_text())
        diagnostics=[json.loads(x) for x in (ROOT/'data/findings/validation'/f'{firm}.jsonl').read_text().splitlines()]
        result={'firm_id':firm,'evaluation_kind':'development_source_structure_not_gold','holdout_texts_opened':0,'inspected_samples':samples,'inspected_distinct_fulltexts':len(samples),'source_id_document_matches':id_matches,'source_id_comparable_documents':id_docs,'source_id_document_agreement_percent':round(100*id_matches/id_docs,2) if id_docs else None,'source_printed_ids':ids_total,'recovered_printed_ids':ids_recovered,'source_id_completeness_percent':round(100*ids_recovered/ids_total,2) if ids_total else None,'source_id_residuals':residual,'body_span_errors':span_errors,'parser_run':stats,'record_kind_counts':dict(Counter(r['record_kind'] for r in findings)),'unknown_severity_rows':sum(r['severity']=='unknown' for r in findings),'summary_mismatches':[r for r in diagnostics if r['validation']=='mismatch'],'limitations':LIMITATIONS[firm]}
        if len(samples)<15:raise RuntimeError('Fewer than fifteen retained inspected samples')
        if span_errors:raise RuntimeError('Body span errors')
        if args.write:write_json(ROOT/'data/findings/validation'/f'{firm}_development.json',result)
        print(json.dumps({k:v for k,v in result.items() if k not in {'inspected_samples','summary_mismatches','parser_run','source_id_residuals'}},sort_keys=True))

LIMITATIONS={
 'least-authority':['ID completeness compares distinct printed Issue/Suggestion IDs from indexes and headings; Issue F in the Ethereum 2.0 report is marked Invalid Issue in the summary without a detail card, and is not fabricated.','No numeric severity aggregate summaries; most older cards do not print a severity and remain unknown.','Known Issue cards remain separately identified; Verification labels supply publisher statuses.'],
 'iosiro':['Four aggregate mismatches are retained. Three aggregates include code-quality advice as informational, whereas those advice rows print no risk label; advice stays recommendation/unknown. Infinex accounts summary prints seven low issues but six low detail cards.','Source sometimes repeats a printed ID on distinct titles; both occurrences remain. Unnumbered closed issues keep null printed IDs.'],
 'informalsystems':['Namada Governance & PGF prints conditional severity cards (whitelisted versus arbitrary transactions) and twelve detail cards against a seven-item numeric summary; conditional severities remain unknown.','Ripple XRPL EVM summary prints zero medium and two low; IF-FINDING-002 explicitly prints Medium, yielding one medium and one low in details.','Many Markdown artifacts are coverage/issue-link/summary files without detailed findings; no formal rows are manufactured. Unrated Skip description cards remain unknown.']}

if __name__=='__main__':main()
