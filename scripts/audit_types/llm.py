"""Frozen offline scope classifier contract, content cache and rule/LLM merger.

No model calls here. run_llm.py is the only launcher. Original text and prompts
stay under local-cache; public labels contain receipts and links, not excerpts.
"""
from collections import Counter
import json
from pathlib import Path
import re

from audit_types.common import file_sha, TYPES
from audit_types.rules import canonical, classify_document, digest
from audit_types.validation_compat import source_hashes_match

VERSION = 'audit-types-llm-v1'
MODEL = 'gpt-6.1-sol'
EFFORT = 'medium'
PROVIDER = 'model CLI-lb'
SCOPE_CHARS = 3000
FINDING_LIMIT = 15
BATCH_SIZE = 20
MIN_CONFIDENCE = .80
# Frozen before held-out review; changing the prompt requires a new version.
PROMPT_SHA256 = '2284a08e0dfb3f4911a996b1a071db5d53910f8e92f9ae873e05e251e5a924e3'
HERE = Path(__file__).resolve().parent


def work(root):
    return Path(root) / 'local-cache/audit-types/llm-v1'


def read_jsonl(path):
    with Path(path).open() as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def write_json(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n')


def write_frozen(path, text):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() != text:
        raise ValueError('Refusing to replace frozen artifact: ' + str(path))
    if not path.exists():
        path.write_text(text)


def config():
    if file_sha(HERE / 'prompt_v1.txt') != PROMPT_SHA256:
        raise ValueError('Frozen prompt changed; create a new version')
    return dict(version=VERSION, model=MODEL, effort=EFFORT, provider=PROVIDER,
                prompt_sha256=PROMPT_SHA256, scope_chars=SCOPE_CHARS,
                finding_limit=FINDING_LIMIT, min_confidence=MIN_CONFIDENCE)


def source_hashes():
    return {name: file_sha(HERE / name) for name in
            ('llm.py', 'run_llm.py', 'run.py', 'rules.py', 'source.py', 'prompt_v1.txt')}


def selection_reason(row):
    """Freeze before held-out review; do not tune from held-out errors.

    Confident = bounded token evidence, multiple explicit scope components, or
    the same classification from substantive scope with identity fields masked.
    Category-only API labels and project/title-only keyword matches are weak.
    Every unclear engagement is eligible, including missing-source records.
    """
    if row['audit_type'] == 'other_or_unclear':
        return 'rule_unclear'
    decisions = row['decisions']
    docs = {d['document_id']: d for d in row['inputs']['documents']}
    strong = {'bounded_token_scope', 'multiple_transport_components',
              'multiple_application_scope_components',
              'hacken_api_bounded_token_scope',
              'hacken_api_multiple_transport_components',
              'hacken_api_multiple_application_scope_components'}
    if not decisions:
        return 'weak_no_decisions'
    for decision in decisions:
        if decision['audit_type'] != row['audit_type']:
            return 'weak_inconsistent_evidence'
        if decision['basis'] in strong:
            continue
        doc = docs.get(decision.get('document_id'))
        if not doc:
            return 'weak_api_categories_or_name'
        masked = dict(doc, title='', project='', filename='', first_pages='', finding_titles=[])
        if (len(doc.get('scope_text', '').strip()) < 160 or
                classify_document(masked)[0] != row['audit_type']):
            return 'weak_identity_or_short_scope'
    return None


def payload(row):
    """No rule label or gold is exposed to the model; all source reports retained.

    Scope is the first 3,000 Unicode characters per source report. Finding titles
    have a global 15-title budget, with deterministic round-robin across reports.
    Text hashes bind excerpts to cached extractions from local originals.
    """
    documents = sorted(row['inputs']['documents'], key=lambda d: d['document_id'])
    titles = []
    groups = [list(dict.fromkeys(d.get('llm_finding_titles', d.get('finding_titles')) or [])) for d in documents]
    for n in range(max(map(len, groups), default=0)):
        for group in groups:
            if n < len(group) and group[n] not in titles and len(titles) < FINDING_LIMIT:
                titles.append(group[n])
        if len(titles) >= FINDING_LIMIT:
            break
    return dict(project=row.get('project'), publisher=row['publisher_id'],
                reports=[dict(title=d.get('title'), project=d.get('project'),
                              filename=d.get('filename'), public_url=d.get('public_url'),
                              scope_overview=(d.get('llm_scope_text', d.get('scope_text')) or d.get('first_pages') or '')[:SCOPE_CHARS],
                              scope_files=d.get('scope_files') or [],
                              chains=d.get('chains') or [], languages=d.get('languages') or [],
                              text_receipt=d.get('llm_text_receipt', d.get('text_receipt'))) for d in documents],
                finding_titles=titles, hacken_api=row['inputs']['api'])


def content_key(value):
    return digest(dict(config=config(), input=value))


def batch_prompt(items):
    return (HERE / 'prompt_v1.txt').read_text() + canonical([
        dict(i=i, **item['payload']) for i, item in enumerate(items, 1)]) + '\n'


def prepare(root, input_path, database_sha256):
    root = Path(root); base = work(root)
    groups = {}; reasons = Counter(); confirmed_before = Counter(); total = 0
    for row in read_jsonl(input_path):
        total += 1
        if row['identity_status'] == 'confirmed':
            confirmed_before[row['audit_type']] += 1
        reason = selection_reason(row)
        if not reason:
            continue
        reasons[reason] += 1
        value = payload(row); key = content_key(value)
        item = groups.setdefault(key, dict(content_key=key, payload_sha256=digest(value),
                                           payload=value, engagements=[]))
        item['engagements'].append(dict(engagement_id=row['engagement_id'],
                                       rule_input_sha256=row['input_sha256'], reason=reason))
    items = [groups[key] for key in sorted(groups)]
    batches = []
    for n in range(0, len(items), BATCH_SIZE):
        chunk = items[n:n+BATCH_SIZE]; prompt = batch_prompt(chunk)
        import hashlib
        ident = hashlib.sha256(prompt.encode()).hexdigest()
        path = base / 'prompts' / (ident + '.txt')
        write_frozen(path, prompt)
        batch = dict(batch_id=ident, prompt=str(path.relative_to(root)),
                     items=chunk, output=str((base/'outputs'/(ident+'.jsonl')).relative_to(root)))
        write_frozen(base/'batches'/(ident+'.json'), canonical(batch) + '\n')
        batches.append(batch)
    manifest = dict(version=VERSION, config=config(), source_hashes=source_hashes(),
                    database_sha256=database_sha256, rule_inputs=str(Path(input_path).relative_to(root)),
                    rule_inputs_sha256=file_sha(input_path), engagements=total,
                    confirmed_before=dict(confirmed_before), selected=sum(reasons.values()),
                    unique_inputs=len(items), reasons=dict(reasons), batches=batches)
    manifest_path = base / 'manifest.json'
    serialized = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    write_frozen(base/'manifests'/(digest(manifest)+'.json'), serialized)
    # Old immutable plans/batches remain replayable; active snapshot may advance.
    manifest_path.write_text(serialized)
    return manifest


def under(root, value):
    path = (Path(root) / value).resolve()
    if not path.is_relative_to(work(root).resolve()):
        raise ValueError('LLM artifact path escapes owned local store')
    return path


def load_manifest(root):
    manifest = json.loads((work(root) / 'manifest.json').read_text())
    if manifest['version'] != VERSION or manifest['config'] != config() or not source_hashes_match(manifest['source_hashes'], source_hashes()):
        raise ValueError('Frozen classifier configuration/source changed; do not launch')
    if file_sha(under(root, manifest['rule_inputs'])) != manifest['rule_inputs_sha256']:
        raise ValueError('Frozen rule inputs changed')
    seen = set()
    for batch in manifest['batches']:
        if file_sha(under(root, batch['prompt'])) != batch['batch_id']:
            raise ValueError('Frozen prompt changed')
        if under(root, batch['prompt']).read_text() != batch_prompt(batch['items']):
            raise ValueError('Prompt/index mapping changed')
        for item in batch['items']:
            key = item['content_key']
            if key in seen or key != content_key(item['payload']) or item['payload_sha256'] != digest(item['payload']):
                raise ValueError('Invalid content-key mapping')
            seen.add(key)
    return manifest


def norm(text):
    return re.sub(r'\s+', ' ', str(text)).strip()


def evidence_strings(value):
    """Evidence must quote functional source fields, not attribution or receipts."""
    result = [value.get('project') or ''] + value['finding_titles']
    for doc in value['reports']:
        result += [doc.get('title') or '', doc.get('project') or '',
                   doc.get('filename') or '', doc['scope_overview']] + doc['scope_files']
    for api in value['hacken_api']:
        result += [api.get('audit_name') or '', canonical(api.get('scope_parameters') or {}),
                   canonical(api.get('audited_contracts') or []), canonical(api.get('labels') or [])]
    return result


def parse_answers(path, batch):
    def no_duplicate_keys(pairs):
        output = {}
        for key, value in pairs:
            if key in output:
                raise ValueError('Duplicate JSON key')
            output[key] = value
        return output
    answers = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        answer = json.loads(line, object_pairs_hook=no_duplicate_keys)
        if not isinstance(answer, dict) or set(answer) != {'i', 'audit_type', 'confidence', 'evidence_quote', 'rationale'}:
            raise ValueError('Invalid answer schema')
        i = answer['i']; conf = answer['confidence']; quote = answer['evidence_quote']; why = answer['rationale']
        if type(i) is not int or i in answers or not 1 <= i <= len(batch['items']):
            raise ValueError('Duplicate or foreign answer index')
        if (answer['audit_type'] not in TYPES or type(conf) not in (int, float) or not 0 <= conf <= 1 or
                not isinstance(quote, str) or len(quote) > 240 or not isinstance(why, str) or not why.strip() or len(why.split()) > 35):
            raise ValueError('Invalid answer values')
        if answer['audit_type'] != 'other_or_unclear':
            strings = evidence_strings(batch['items'][i-1]['payload'])
            if len(norm(quote)) < 8 or not any(norm(quote) in norm(s) for s in strings):
                # Keep the model's answer intact for provenance. Only this
                # engagement abstains; schema/index/completeness stay strict.
                answer['abstention_reason'] = 'unverifiable_quote'
        answers[i] = answer
    if set(answers) != set(range(1, len(batch['items'])+1)):
        raise ValueError('Incomplete batch; no partial cache promotion')
    return answers


def receipt_path(root, batch):
    return work(root) / 'receipts' / (batch['batch_id'] + '.json')


def promote(root, batch, receipt):
    """Only successfully validated CLI output can populate the content cache."""
    output = under(root, batch['output']); rp = receipt_path(root, batch)
    if receipt['exit_code'] != 0 or receipt['status'] != 'validated' or receipt['config'] != config():
        raise ValueError('Unsuccessful or incompatible launch receipt')
    if (receipt['prompt_sha256'] != batch['batch_id'] or receipt['output_sha256'] != file_sha(output) or
            receipt['log_sha256'] != file_sha(under(root, receipt['log']))):
        raise ValueError('Launch receipt hashes do not match')
    answers = parse_answers(output, batch)
    write_json(rp, receipt)
    for i, item in enumerate(batch['items'], 1):
        value = dict(content_key=item['content_key'], payload_sha256=item['payload_sha256'],
                     config=config(), answer=answers[i], batch_id=batch['batch_id'],
                     output=batch['output'], output_sha256=file_sha(output),
                     receipt=str(rp.relative_to(root)), receipt_sha256=file_sha(rp))
        write_json(work(root)/'cache'/(item['content_key']+'.json'), value)


class Merger:
    def __init__(self, root, require_complete=True, manifest=None):
        self.root = Path(root); self.require_complete = require_complete
        self.manifest = manifest if manifest is not None else (load_manifest(root) if (work(root)/'manifest.json').exists() else None)
        self.verified_batches = {}; self.used = Counter(); self.pending = []

    def cached(self, value):
        key = content_key(value); path = work(self.root)/'cache'/(key+'.json')
        if not path.exists():
            return None
        record = json.loads(path.read_text())
        if record['config'] != config() or record['content_key'] != key or record['payload_sha256'] != digest(value):
            raise ValueError('Invalid input cache receipt: ' + key)
        ident = record['batch_id']
        if ident not in self.verified_batches:
            rp = under(self.root, record['receipt']); receipt = json.loads(rp.read_text())
            batch = json.loads((work(self.root)/'batches'/(ident+'.json')).read_text())
            if (batch['batch_id'] != ident or under(self.root, batch['prompt']).read_text() != batch_prompt(batch['items']) or
                    any(i['content_key'] != content_key(i['payload']) for i in batch['items'])):
                raise ValueError('Invalid immutable cache batch mapping')
            output = under(self.root, record['output'])
            if (file_sha(rp) != record['receipt_sha256'] or receipt['status'] != 'validated' or receipt['exit_code'] != 0 or
                    receipt['config'] != config() or receipt['output_sha256'] != file_sha(output) or
                    receipt['prompt_sha256'] != ident or file_sha(under(self.root, batch['prompt'])) != ident or
                    receipt['log_sha256'] != file_sha(under(self.root, receipt['log']))):
                raise ValueError('Cache launch/output receipt changed')
            self.verified_batches[ident] = (batch, parse_answers(output, batch), file_sha(rp), file_sha(output))
        batch, answers, rsha, osha = self.verified_batches[ident]
        if record['receipt_sha256'] != rsha or record['output_sha256'] != osha:
            raise ValueError('Cache receipt differs from validated batch')
        index = next((i for i, item in enumerate(batch['items'], 1) if item['content_key'] == key), None)
        if index is None or record['answer'] != answers[index]:
            raise ValueError('Cache answer differs from raw CLI output')
        return record, file_sha(path)

    def merge(self, row):
        result = dict(row, rule_audit_type=row['audit_type'], rule_audit_type_basis=row['audit_type_basis'],
                      merge_version=VERSION, llm_selection=selection_reason(row))
        if not result['llm_selection']:
            result['audit_type_basis'] = 'rule'
        else:
            found = self.cached(payload(row))
            if not found:
                self.pending.append(row['engagement_id'])
                if self.require_complete:
                    raise ValueError('Eligible engagement has no validated LLM cache; prepare/run LLM pass: ' + row['engagement_id'])
                result.update(audit_type='other_or_unclear', audit_type_basis='abstain', llm_status='pending')
            else:
                cached, sha = found; answer = cached['answer']
                accepted = (answer['audit_type'] != 'other_or_unclear' and
                            answer['confidence'] >= MIN_CONFIDENCE and not answer.get('abstention_reason'))
                result.update(audit_type=answer['audit_type'] if accepted else 'other_or_unclear',
                              audit_type_basis='llm' if accepted else 'abstain', llm_status='complete',
                              llm_receipt=dict(config=config(), content_key=cached['content_key'],
                                               cache_sha256=sha, receipt_sha256=cached['receipt_sha256'],
                                               output_sha256=cached['output_sha256'],
                                               confidence=answer['confidence'], model_audit_type=answer['audit_type']))
                if answer.get('abstention_reason'):
                    result['llm_receipt']['reason'] = answer['abstention_reason']
        self.used[result['audit_type_basis']] += 1
        return result


def status(root):
    merger = Merger(root, require_complete=False)
    if not merger.manifest:
        raise ValueError('Prepare the LLM pass first')
    before = Counter(); after = Counter(); reasons = Counter(); firms = {}
    for row in read_jsonl(under(root, merger.manifest['rule_inputs'])):
        merged = merger.merge(row)
        if row['identity_status'] == 'confirmed':
            before[row['audit_type']] += 1; after[merged['audit_type']] += 1
            reasons[merged.get('llm_status', 'rule')] += 1
            pid = row['publisher_id']
            counts = firms.setdefault(pid, Counter()); counts['engagements'] += 1
            counts['token_only_before'] += row['audit_type'] == 'token_only'
            counts['token_only_after'] += merged['audit_type'] == 'token_only'
    total = sum(before.values()); pending = len(merger.pending)
    return dict(config=config(), engagements=merger.manifest['engagements'],
                selected=merger.manifest['selected'], unique_inputs=merger.manifest['unique_inputs'],
                batches=len(merger.manifest['batches']), pending=pending,
                confirmed_engagements=total, before=dict(before),
                after=dict(after) if not pending else None,
                confirmed_basis=dict(reasons), target_unclear_share=.15,
                remaining_unclear_share=after['other_or_unclear']/total if total and not pending else None,
                top_firms=[dict(dict(publisher_id=pid, **counts),
                                token_only_after=counts['token_only_after'] if not pending else None,
                                token_only_share_before=counts['token_only_before']/counts['engagements'],
                                token_only_share_after=counts['token_only_after']/counts['engagements'] if not pending else None)
                           for pid, counts in sorted(firms.items(), key=lambda kv: (-kv[1]['engagements'], kv[0]))])
