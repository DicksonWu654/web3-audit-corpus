"""Data-only decoding of Halborn's public Next.js Flight report payloads."""
from html.parser import HTMLParser
import hashlib
import json
import re

VERSION = 'halborn-website-flight-v2'
MARKER = '## Halborn Website Finding Records'

class RichText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip = [], 0
    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style', 'noscript', 'svg'}:
            self.skip += 1
        if self.skip:
            return
        if tag in {'p', 'div', 'section', 'pre', 'blockquote', 'tr', 'br', 'ul', 'ol'} or re.fullmatch(r'h[1-6]', tag):
            self.parts.append('\n')
        elif tag == 'li':
            self.parts.append('\n- ')
        elif tag in {'td', 'th'}:
            self.parts.append(' | ')
        elif tag == 'img':
            attrs = dict(attrs)
            self.parts.append('[Image: ' + attrs.get('alt', '') + (' ' + attrs['src'] if attrs.get('src') else '') + ']')
        elif tag == 'a':
            href = dict(attrs).get('href')
            if href:
                self.parts.append('[' + href + '] ')
    def handle_endtag(self, tag):
        if tag in {'script', 'style', 'noscript', 'svg'}:
            self.skip = max(0, self.skip - 1)
        if not self.skip and tag in {'p', 'div', 'pre', 'li', 'tr', 'blockquote'}:
            self.parts.append('\n')
    def handle_data(self, value):
        if not self.skip:
            self.parts.append(value)

def rich_text(value):
    if value is None or value == '$undefined':
        return ''
    if not isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    parser = RichText()
    parser.feed(value)
    return re.sub(r'\n[ \t]*\n(?:[ \t]*\n)+', '\n\n', ''.join(parser.parts)).strip()

def flight_records(html):
    """Read JSON push arguments; T lengths count UTF-8 bytes, not characters."""
    chunks = []
    for match in re.finditer(r'self\.__next_f\.push\((.*?)\)</script>', html, re.S):
        try:
            value = json.loads(match[1])
        except (ValueError, TypeError):
            continue
        if isinstance(value, list) and len(value) > 1 and value[0] == 1 and isinstance(value[1], str):
            chunks.append(value[1])
    stream = ''.join(chunks).encode('utf-8')
    records, errors, pos = {}, [], 0
    while pos < len(stream):
        if stream[pos:pos + 1] == b'\n':
            pos += 1
            continue
        head = re.match(rb'([0-9a-f]*):', stream[pos:])
        if not head:
            errors.append({'kind': 'invalid_flight_record', 'offset': pos})
            break
        key = head[1].decode()
        pos += head.end()
        long = re.match(rb'T([0-9a-f]+),', stream[pos:])
        if long:
            size = int(long[1], 16)
            pos += long.end()
            end = pos + size
            if end > len(stream):
                errors.append({'kind': 'truncated_flight_string', 'record': key})
                break
            records[key] = stream[pos:end].decode('utf-8')
            pos = end
        else:
            end = stream.find(b'\n', pos)
            if end < 0:
                end = len(stream)
            try:
                records[key] = json.loads(stream[pos:end])
            except ValueError:
                pass  # Module, hint, error and debug records are not report JSON.
            pos = end + 1
    return records, errors

def objects(value, path=''):
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from objects(child, path + '/' + key)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from objects(child, path + '/' + str(i))

def resolve(value, records, unresolved, seen=()):
    if isinstance(value, str):
        if value == '$undefined':
            return None
        if value.startswith('$$'):
            return value[1:]
        match = re.fullmatch(r'\$([0-9a-f]+)((?::[^:]+)*)', value)
        if not match:
            return value
        if value in seen or match[1] not in records:
            unresolved.add(value)
            return value
        target = records[match[1]]
        try:
            for part in match[2].split(':')[1:]:
                if isinstance(target, list):
                    target = target[3] if part == 'props' and target[0] == '$' else target[int(part)]
                else:
                    target = target[part]
        except (KeyError, IndexError, ValueError, TypeError):
            unresolved.add(value)
            return value
        return resolve(target, records, unresolved, seen + (value,))
    if isinstance(value, list):
        return [resolve(v, records, unresolved, seen) for v in value]
    if isinstance(value, dict):
        return {k: resolve(v, records, unresolved, seen) for k, v in value.items()}
    return value

def extract(html):
    """Return a deterministic finding-text supplement and body provenance."""
    records, errors = flight_records(html)
    candidates = [(key + path, obj) for key, value in records.items() for path, obj in objects(value)
                  if isinstance(obj.get('findings'), list) and ('reportType' in obj or 'reportSlug' in obj)]
    unique = {}
    for path, obj in candidates:
        unique.setdefault(obj.get('id') or obj.get('reportSlug') or path, (path, obj))
    meta = {'version': VERSION, 'source': 'public_next_f_flight_json', 'reports': [],
            'findings': [], 'unresolved_references': [], 'issues': errors}
    sections, unresolved = [], set()
    for path, raw in unique.values():
        report = resolve(raw, records, unresolved)
        meta['reports'].append({k: report.get(k) for k in ('id', 'name', 'shortTitle', 'company', 'reportType', 'reportSlug', 'engagementSlug', 'date_start', 'date_end', 'publicReportFromNexus')})
        for index, finding in enumerate(report['findings']):
            ident = finding.get('halIndex') or finding.get('identifier') or index + 1
            ident = f'HAL-{int(ident):02d}' if str(ident).isdigit() else str(ident)
            title = re.sub(r'\s+', ' ', rich_text(finding.get('title'))).strip()
            # Nexus initializes unused BVSS grades to Informational even when
            # this finding uses CVSS or the risk/likelihood matrix. A scored
            # BVSS finding has its own nonempty bvss_score (including zero).
            if finding.get('bvss_score') not in (None, ''):
                severity_field = 'bvss_grade'
            else:
                severity_field = next((k for k in ('cvss_grade','risk_likelihood_grade','bvss_grade') if finding.get(k)), 'bvss_grade')
            severity = finding.get(severity_field) or ''
            if isinstance(severity, list):
                severity = ', '.join(str(s) for s in severity)
            lines = [f'### {ident} {title}', f'Severity: {severity}', f'Status: {finding.get("remediationState") or ""}', '']
            provenance = {'identifier': ident, 'source_id': finding.get('id'), 'json_path': path + '/findings/' + str(index), 'severity_field':severity_field, 'severity_original':severity, 'fields': {}}
            for key, label in (('description', 'Description'), ('remediation', 'Recommendation'), ('remediationComment', 'Remediation'), ('poc', 'Proof of Concept')):
                body = rich_text(finding.get(key))
                original = raw['findings'][index].get(key)
                provenance['fields'][key] = {'present': bool(body), 'source_reference': original if isinstance(original, str) and re.fullmatch(r'\$[0-9a-f]+(?::.*)?', original) else None,
                    'text_sha256': hashlib.sha256(body.encode()).hexdigest(), 'characters': len(body)}
                if body:
                    lines += ['#### ' + label, body, '']
            provenance['has_public_description'] = provenance['fields']['description']['present']
            meta['findings'].append(provenance)
            sections.append('\n'.join(lines).rstrip())
    meta['unresolved_references'] = sorted(unresolved)
    meta['finding_count'] = len(sections)
    return ('\n\n' + MARKER + '\n\n' + '\n\n'.join(sections) + '\n' if unique else ''), meta

def applies(row):
    return row.get('firm_id') == 'halborn' and row.get('source_kind') == 'website' and row.get('file_format') == 'html'

def needs_retry(row, previous):
    return applies(row) and previous.get('halborn_website', {}).get('version') != VERSION
