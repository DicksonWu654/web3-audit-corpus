"""Enumerate every Phase 4d source, generated interchange and local review artifact."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT,read_snapshot


def main():
    sources={
        'schema/README.md','scripts/analysis/model.py','scripts/classify/common.py',
        'scripts/findings/parsers/__init__.py','scripts/findings/run.py','scripts/findings/check.py',
        'scripts/findings/pipeline.py','scripts/findings/severity_review.py',
        *('scripts/findings/'+name+'.py' for name in ('variants','layout_support','badge_ocr','layout_ocr','variants_study','variants_report','variants_files','test_variants')),
    }
    for p in (ROOT/'scripts/findings/parsers').glob('*.py'):
        if '\nVARIANTS' in p.read_text():sources.add(str(p.relative_to(ROOT)))
    generated={'data/findings/summary.json','data/findings/check.json','data/findings/_unknown_layouts.jsonl',
               'data/fulltext/extractions.jsonl','docs/phase4/variants.md','docs/phase4/variants_files_written.txt'}
    for firm in {d['row']['firm_id'] for d in read_snapshot()}:
        generated.add(f'data/findings/{firm}.jsonl')
        generated.add(f'data/findings/validation/{firm}.json')
        generated.add(f'data/findings/validation/{firm}.jsonl')
    generated.update(str(p.relative_to(ROOT)) for p in (ROOT/'data/findings/variants').rglob('*') if p.is_file())
    local={str(p.relative_to(ROOT)) for p in (ROOT/'local-cache/phase4d').rglob('*') if p.is_file()}
    for backup in (ROOT/'local-cache/phase4d/pre_ocr').glob('*.pages.json'):
        sha=backup.name.removesuffix('.pages.json')
        local.update((f'local-cache/fulltext/{sha}.txt',f'local-cache/fulltext/{sha}.pages.json'))
    logs={str(p) for p in Path('/tmp').glob('p4d-*') if p.is_file()}
    sources={p for p in sources if (ROOT/p).exists()}
    generated={p for p in generated if (ROOT/p).exists() or p.endswith('variants_files_written.txt')}
    lines=['# Phase 4d files written','', 'Source files:']+sorted(sources)+['','Generated corpus and reports:']+sorted(generated)+['','Local OCR, render and baseline artifacts (gitignored):']+sorted(local)+['','Temporary inspection/test/run logs:']+sorted(logs)+['','Interpreter bytecode caches are machine-local and excluded.','']
    (ROOT/'docs/phase4/variants_files_written.txt').write_text('\n'.join(lines))
    print({'source_files':len(sources),'generated_files':len(generated),'local_artifacts':len(local),'temporary_logs':len(logs)})

if __name__=='__main__':main()
