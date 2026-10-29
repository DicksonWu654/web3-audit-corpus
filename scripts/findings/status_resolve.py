"""Standalone, standard-library publisher/era remediation status resolver.

Import has no I/O or repository imports. Copy this module and pass policy_path
to use the exported JSON. Original strings are returned verbatim in receipts.
"""
from __future__ import annotations
from functools import lru_cache
import hashlib
import json
import logging
from pathlib import Path
import re
import unicodedata

STATUSES = ('fixed', 'partially_fixed', 'acknowledged', 'unresolved', 'not_stated')
RESOLVER_VERSION = 'status-canon-v2'
LOGGER = logging.getLogger('findings.status')


@lru_cache(maxsize=8192)
def canonicalize_label(value):
    """Remove presentation, preserving negation, qualifiers and combinations."""
    text = unicodedata.normalize('NFKC', value).casefold().strip()
    text = re.sub(r'[\u200b\ufeff\u202a-\u202e\u2066-\u2069]', '', text)
    text = re.sub(r'(?<=\w)-\s*\n\s*(?=\w)', '', text)
    while text:
        previous = text
        text = re.sub(r'^[\W_]+', '', text)
        text = re.sub(r'^\d+(?:\.\d+)*(?:[\s.)\]:\-–—]+|$)', '', text)
        text = re.sub(r'^(?:[ivxlcdm]+|[a-z])[.)\]:]\s+(?=\S)', '', text)
        if text == previous: break
    text = re.sub(r'[\[(]\s*\d+\s*[\])]\s*$', '', text)
    return re.sub(r'[\W_]+', '', text)


status_key = canonicalize_label


@lru_cache(maxsize=4)
def status_policy(path=None):
    path = Path(path) if path else Path(__file__).resolve().parents[2] / 'schema/status_map.json'
    payload = path.read_bytes()
    policy = json.loads(payload)
    for family in policy.get('generic_fallback', {}).get('rules', []):
        if family['normalized'] not in STATUSES or not family.get('rationale'):
            raise ValueError('Invalid generic status family: ' + family['id'])
        re.compile(family['regex'])
        if family.get('exclude_regex'):
            re.compile(family['exclude_regex'])
    index = {}
    for publisher, entry in policy['publishers'].items():
        eras = []
        for era in entry['eras']:
            labels = {}
            for label, mapping in sorted(era['labels'].items()):
                if mapping['normalized'] not in STATUSES or not mapping.get('rationale'):
                    raise ValueError(f'Invalid status mapping: {publisher}: {label!r}')
                key = canonicalize_label(label)
                if key in labels and labels[key]['normalized'] != mapping['normalized']:
                    raise ValueError(f'Conflicting status aliases: {publisher}: {key!r}')
                # Receipts reference policy evidence; never duplicate a firm's
                # entire alias census or long definition quote on every row.
                compact = {k:v for k,v in mapping.items() if k not in {'observed_labels', 'evidence'}}
                compact['evidence'] = [{k:v for k,v in e.items() if k != 'quote'} for e in mapping.get('evidence', [])]
                labels[key] = compact | {'original_label': label}
            eras.append((era, labels))
        index[publisher] = eras
    return policy, index, hashlib.sha256(payload).hexdigest()


def select_status_era(publisher, *, sha256=None, date=None, report_text=None, policy_path=None):
    _, index, _ = status_policy(policy_path)
    eras = index.get(publisher, [])
    selected = []
    if report_text is not None and any(e.get('definition_regex') for e,_ in eras):
        text = re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', report_text))
        selected = [e['id'] for e, _ in eras if e.get('definition_regex') and re.search(e['definition_regex'], text, re.I)]
    if not selected:
        selected = [e['id'] for e, _ in eras if sha256 and sha256 in e.get('document_sha256s', [])]
    if not selected and date:
        selected = [e['id'] for e, _ in eras if e.get('date_range') and
                    (not e['date_range'].get('from') or date >= e['date_range']['from']) and
                    (not e['date_range'].get('to') or date <= e['date_range']['to'])]
    if not selected:
        selected = [e['id'] for e, _ in eras if e.get('default')]
    return selected[0] if len(selected) == 1 else '<ambiguous>'


@lru_cache(maxsize=4096)
def _log_unmapped(publisher, value, reason):
    LOGGER.warning('Unmapped status publisher=%s label=%r reason=%s', publisher, value, reason)


def generic_status(value, policy):
    """Match words rather than the punctuation-free exact-label lookup key."""
    if not isinstance(value, str):
        return None
    text = unicodedata.normalize('NFKC', value).casefold()
    text = re.sub(r'[\u200b\ufeff\u202a-\u202e\u2066-\u2069]', '', text)
    text = text.replace('’', "'")
    # Preserve word boundaries in spelling variants such as not-fixed and
    # partially_fixed before removing Markdown decoration. Otherwise a
    # following 'fixed in ...' could be misread as a positive assertion.
    text = re.sub(r'(?<=\w)[_-]+(?=\w)', ' ', text)
    text = re.sub(r'[*_`]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'^[\W_]+', '', text)
    text = re.sub(r'^\d+(?:\.\d+)*[.)\]:-]?\s+', '', text)
    if policy.get('generic_fallback', {}).get('ambiguous_regex') and re.search(
            policy['generic_fallback']['ambiguous_regex'], text):
        return None
    for family in policy.get('generic_fallback', {}).get('rules', []):
        if re.search(family['regex'], text) and not (
                family.get('exclude_regex') and re.search(family['exclude_regex'], text)):
            return dict(normalized=family['normalized'], mapped=True,
                        rule='generic_' + family['id'], rationale=family['rationale'],
                        basis='generic_status_fallback')
    return None


def status_mapping(value, publisher=None, *, era=None, sha256=None, date=None,
                   report_text=None, log=True, policy_path=None):
    policy, index, fingerprint = status_policy(policy_path)
    key = canonicalize_label(value) if isinstance(value, str) else None
    receipt = {'policy': policy['policy'], 'map_sha256': fingerprint,
               'resolver': RESOLVER_VERSION, 'publisher': publisher, 'era': None,
               'input': value, 'raw': value, 'canonical_label': key,
               'normalized': 'not_stated', 'mapped': False}
    if value is None or isinstance(value, str) and not value.strip():
        return receipt | {'mapped': True, 'rule': 'missing_status',
                          'rationale': 'No source status assertion was extracted.'}
    era = era if era is not None else select_status_era(publisher, sha256=sha256, date=date,
                                                       report_text=report_text, policy_path=policy_path)
    selected = [(e, labels) for e, labels in index.get(publisher, []) if e['id'] == era]
    reason = 'publisher_not_in_crosswalk' if publisher not in index else 'era_not_resolved'
    listed_mapping = None
    if len(selected) == 1:
        entry, labels = selected[0]
        receipt['era'] = entry['id']
        if key in labels:
            mapping = labels[key]
            listed = mapping.get('review_state') == 'listed_unresolved'
            if not listed:
                return receipt | mapping | {'mapped': True, 'listed': False}
            listed_mapping = mapping
        reason = 'label_not_in_publisher_era'
    if publisher is None and key:
        labels = {canonicalize_label(label): bucket for label, bucket in policy['unscoped_labels'].items()}
        if key in labels:
            return receipt | {'normalized': labels[key], 'mapped': True, 'rule': 'unscoped_schema_vocabulary'}
    # An unresolved era may contain conflicting native semantics. Do not guess
    # past an ambiguous publisher-era selection; unknown publishers can still
    # use the explicit, publisher-independent assertions.
    if len(selected) == 1 or publisher not in index:
        fallback = generic_status(value, policy)
        if fallback:
            return receipt | fallback | {'fallback_from': 'listed_unresolved' if listed_mapping else reason}
    if listed_mapping:
        return receipt | listed_mapping | {'mapped': False, 'listed': True}
    if log: _log_unmapped(publisher, value, reason)
    return receipt | {'reason': reason}


def status(value, publisher=None, **kwargs):
    return status_mapping(value, publisher, **kwargs)['normalized']


resolve_status = status
