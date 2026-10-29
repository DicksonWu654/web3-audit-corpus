"""Read cached original text, with bounded offline extraction when absent."""
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess

from audit_types.common import file_sha
from audit_types.rules import BOILER, SCOPE, local_text


class PlainHTML(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []; self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1
        elif not self.hidden and tag in ('p', 'div', 'br', 'h1', 'h2', 'h3', 'li'):
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden-1)

    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)


def overview(text):
    """Discard contents entries; retain source order, never search by class label."""
    clean = re.sub(r'(?m)^(#{1,5}[^\n]+?)#+[ \t]*$', r'\1', text[:100000])
    clean = re.sub(r'(?im)^(#{1,5}[ \t]+)introduction[ \t]*$', r'\1Project overview', clean)
    parts = []
    for match in list(SCOPE.finditer(clean))[:30]:
        chunk = clean[match.end():match.end()+4000]
        boundary = re.search(r'(?m)^\s*#{1,5}[ \t]+', chunk)
        if boundary:
            chunk = chunk[:boundary.start()]
        lines = [line.strip() for line in chunk.splitlines()
                 if not BOILER.search(line) and not re.search(r'\.{4}|─{4}', line)]
        prose = '\n'.join(lines).strip()
        # TOC matches generally lead to headings/page numbers, not sentences.
        if len(re.findall(r'\b\w+\b', prose[:900])) < 35 or not re.search(
                r'\b(?:is|are|was|were|provides?|implements?|allows?|enables?|contracts?|protocol|system)\b', prose[:900], re.I):
            continue
        if prose and prose not in parts:
            parts.append(prose)
    if parts:
        return '\n\n'.join(parts)[:3000]
    lines = [line for line in text[:24000].splitlines()
             if not BOILER.search(line) and not re.search(r'\.{4}|─{4}', line)]
    return '\n'.join(lines).strip()[:3000]


def model_source(root, doc):
    root = Path(root).resolve()
    text, receipt = local_text(root, doc)
    if not text and doc.get('local_path') and doc.get('sha256'):
        original = (root/doc['local_path']).resolve()
        if original.is_relative_to(root/'local-cache') and original.is_file():
            if file_sha(original) != doc['sha256']:
                raise ValueError('Original checksum mismatch: ' + doc['document_id'])
            path = root/'local-cache/audit-types/llm-v1/text'/(doc['sha256']+'.txt')
            command = ['pdftotext', '-f', '1', '-l', '12', '-layout', str(original), '-'] if doc.get('file_format') == 'pdf' else None
            if path.exists():
                text = path.read_text()
            elif doc.get('file_format') == 'pdf':
                try:
                    result = subprocess.run(command, capture_output=True, timeout=60, check=False)
                    text = result.stdout.decode('utf-8', errors='replace') if result.returncode == 0 else ''
                except (OSError, subprocess.TimeoutExpired):
                    text = ''
            elif doc.get('file_format') in ('html', 'md') and original.stat().st_size <= 20000000:
                text = original.read_text(errors='replace')
                if doc['file_format'] == 'html':
                    parser = PlainHTML(); parser.feed(text); text = ''.join(parser.parts)
            if text:
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_text(text)
                receipt = dict(path=str(path.relative_to(root)), sha256=file_sha(path),
                               original_sha256=doc['sha256'], extraction='offline_original_first_12_pages' if doc['file_format']=='pdf' else 'offline_original',
                               command=command)
    return overview(text), dict(receipt, original_sha256=doc.get('sha256'))
