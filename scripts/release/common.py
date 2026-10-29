"""Shared helpers for the release export (`make release`) and site data (`make site-data`).

Everything here is deterministic: no wall-clock times, sorted outputs, compact JSON with
sorted keys, gzip with mtime=0. Inputs are treated as untrusted data and never executed.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import importlib.util
import io
import json
import math
import re
import html
import unicodedata
import ipaddress
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
csv.field_size_limit(2**31 - 1)  # finding bodies can exceed the 128 KiB default
TIER_A_GROUPS = {'firm', 'contest_platform'}
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info', 'gas', 'unknown')
STATUSES = ('fixed', 'partially_fixed', 'acknowledged', 'unresolved', 'not_stated')
AUDIT_TYPES = ('token_only', 'protocol', 'infrastructure', 'wallet_or_account', 'nft_or_game', 'other_or_unclear')
CERTIK = 'certik'
# Publisher-request exclusions are permanent release policy.  These IDs are
# removed before any public table, site, agent format or export is built.
EXCLUDED_AT_PUBLISHER_REQUEST = frozenset({'cyfrin', 'codehawks'})
EXCLUDED_PUBLISHER_HOST_SUFFIXES = ('cyfrin.io', 'solodit.xyz')
EXCLUDED_PUBLISHER_HOSTS = frozenset({'solodit.cyfrin.io'})
OAK_FIRMS = {'oak-security', 'oak'}
OAK_LICENSE = 'CC BY-ND 4.0'
OAK_LICENSE_URL = 'https://creativecommons.org/licenses/by-nd/4.0/'
TEXT_RIGHTS_FIELDS = ('text_attribution', 'text_license', 'text_license_url', 'text_source_url')
INCIDENT_ATTRIBUTION = 'DeFiHackLabs (Apache-2.0, © SunWeb3Sec contributors), DeFiLlama and SlowMist Hacked'

# Analysis tables that are aggregates (safe to publish as stats/*.csv). Row-level extracts
# (finding_streams, engagements, incident_matches, report_pages, cadence pairs/eligibility,
# review-mode rows, official contest rows, diagnostics, input manifest) are excluded.
STATS_TABLES = (
    'cadence_identity_rules', 'concentration_year', 'contests_year', 'engagements_dimensions',
    'engagements_year', 'entrants_last_observed_year', 'findings_by_firm', 'findings_firm_year',
    'findings_overall', 'findings_year', 'firm_audit_types', 'firm_counts', 'firm_first_last_year',
    'firm_momentum', 'firm_momentum_excluding_token_only', 'firm_momentum_aggregate', 'firm_shares_year', 'incident_precision',
    'key_results', 'reaudit_cadence_year', 'report_pages_year', 'review_modes_year', 'run_summary',
    'top20_firms', 'vulnerability_class_coverage', 'vulnerability_class_inputs',
    'vulnerability_class_shares_year', 'vulnerability_classes_year', 'vulnerability_leaves',
)


V120_STATS_TABLES = ('projection_2026', 'projection_2026_firms', 'projection_2026_hypotheses', 'publisher_coverage_class', 'self_reported_volume', 'trends_2026_ai_branding', 'trends_2026_ai_firms', 'trends_2026_ai_mentions', 'trends_2026_ai_quotes', 'trends_2026_ai_same_window', 'trends_2026_ai_year', 'trends_2026_ai_yield', 'trends_2026_audit_types', 'trends_2026_breaks', 'trends_2026_class_changes', 'trends_2026_classes', 'trends_2026_client_membership', 'trends_2026_clients', 'trends_2026_contest_inputs', 'trends_2026_contest_prizes', 'trends_2026_contests', 'trends_2026_date_coverage', 'trends_2026_ecosystem_changes', 'trends_2026_ecosystems', 'trends_2026_findings', 'trends_2026_firm_concentration', 'trends_2026_firms', 'trends_2026_fix_rates', 'trends_2026_fix_rates_firms', 'trends_2026_headlines', 'trends_2026_inputs', 'trends_2026_lag_selection_tests', 'trends_2026_lag_severity', 'trends_2026_lag_severity_pairs', 'trends_2026_market_context', 'trends_2026_monthly', 'trends_2026_publication_lags', 'trends_2026_publication_speed', 'trends_2026_publication_speed_firms', 'trends_2026_quarterly', 'trends_2026_report_size', 'trends_2026_severity_changes', 'trends_2026_severity_groups', 'trends_2026_severity_quarter', 'trends_2026_severity_shift_share', 'trends_2026_severity_year')
STATS_TABLES += tuple(name for name in V120_STATS_TABLES if name not in STATS_TABLES)


def audit_type_counts(engagements):
    """Count publisher engagements, retaining every type including explicit abstentions."""
    counts = {kind: 0 for kind in AUDIT_TYPES}
    for row in engagements:
        kind = row.get('audit_type')
        if kind not in counts:
            raise ValueError(f'Invalid audit_type for {row.get("engagement_id")}: {kind!r}')
        if row.get('audit_type_basis') not in ('rule', 'llm', 'abstain'):
            raise ValueError(f'Invalid or missing audit_type_basis for {row.get("engagement_id")}')
        counts[kind] += 1
    return counts


def audit_type_table_errors(engagements, mix_rows, count_rows):
    """Reconcile aggregate scope tables with the actual exported publisher engagements."""
    by_firm = {}
    for row in engagements:
        by_firm.setdefault(row.get('firm_id') or row['publisher_id'], []).append(row)
    expected = {firm: audit_type_counts(rows) for firm, rows in by_firm.items()}
    errors, seen_mix, seen_counts = [], set(), set()

    def matches(row, key, value):
        try:
            return abs(float(row[key]) - value) <= 1e-12
        except (KeyError, TypeError, ValueError):
            return False

    for row in mix_rows:
        firm, kind = row.get('firm_id') or row.get('publisher_id'), row.get('audit_type')
        key = (firm, kind)
        if firm not in expected or kind not in AUDIT_TYPES or key in seen_mix:
            errors.append(f'firm_audit_types has an unexpected or duplicate row: {key}')
            continue
        seen_mix.add(key)
        total = sum(expected[firm].values())
        if not all(matches(row, field, value) for field, value in
                   (('engagements', expected[firm][kind]), ('denominator', total),
                    ('share', expected[firm][kind] / total))):
            errors.append(f'firm_audit_types differs from engagement labels: {firm}/{kind}')
    if seen_mix != {(firm, kind) for firm in expected for kind in AUDIT_TYPES}:
        errors.append('firm_audit_types does not cover every released publisher and type')
    for row in count_rows:
        firm = row.get('firm_id') or row.get('publisher_id')
        if firm not in expected or firm in seen_counts:
            errors.append(f'firm_counts has an unexpected or duplicate row: {firm}')
            continue
        seen_counts.add(firm)
        counts = expected[firm]
        total, token = sum(counts.values()), counts['token_only']
        if not all(matches(row, field, value) for field, value in
                   (('engagements', total), ('token_only_engagements', token),
                    ('engagements_excluding_token_only', total - token), ('token_only_share', token / total),
                    ('other_or_unclear_engagements', counts['other_or_unclear']))):
            errors.append(f'firm_counts differs from engagement labels: {firm}')
    if seen_counts != set(expected):
        errors.append('firm_counts does not cover every released publisher')
    return errors


def momentum_table_errors(engagements, firms, tables, as_of):
    """Recount both completion populations and prevent unsupported trend labels."""
    import datetime as dt
    from collections import Counter
    errors = []
    cutoff = dt.date.fromisoformat(str(as_of))
    previous = cutoff.replace(year=2025)
    names = {'all': 'firm_momentum', 'excluding_token_only': 'firm_momentum_excluding_token_only'}
    publishers = {r['firm_id']: r for r in firms}
    totals = {}

    def true(value):
        return str(value).lower() == 'true'

    def number(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def lower_bound_coverage(publisher):
        return 'lower_bound' in str(publisher.get('coverage') or '').strip().lower()

    def sca_api_coverage(publisher):
        return publisher.get('coverage') == 'public_sca_api_plus_third_party_copies'

    for population, name in names.items():
        rows = tables.get(name, [])
        if not rows:
            errors.append(name + ' is missing')
            continue
        by_id = {r['firm_id']: r for r in rows}
        if len(by_id) != len(rows) or set(by_id) != set(publishers):
            errors.append(name + ' publisher population differs')
        expected = {pid: Counter(dict(y2024=0,y2025=0,h1_2025=0,h1_2026=0,same_period_2025=0,ytd_2026=0)) for pid in publishers}
        for row in engagements:
            pid = row['firm_id']
            if population == 'excluding_token_only' and row['audit_type'] == 'token_only':
                continue
            if publishers[pid]['kind'] != 'contest_platform' and (row.get('engagement_kind') == 'contest' or row.get('review_mode') == 'contest'):
                continue
            if row.get('audit_date_basis') != 'audit_completion' or true(row.get('audit_year_conflict')):
                continue
            try:
                lo, hi = (dt.date.fromisoformat(row[key]) for key in ('audit_date_min','audit_date_max'))
            except (TypeError, ValueError):
                continue
            for key, end in (('y2024', dt.date(2024,12,31)), ('y2025', dt.date(2025,12,31)),
                             ('h1_2025', dt.date(2025,6,30)), ('h1_2026', min(cutoff, dt.date(2026,6,30))),
                             ('same_period_2025', previous), ('ytd_2026', cutoff)):
                expected[pid][key] += dt.date(end.year,1,1) <= lo <= hi <= end
        for pid, row in by_id.items():
            if pid not in expected:
                continue
            counts = expected[pid]
            counts['h1_change'] = counts['h1_2026']-counts['h1_2025']
            counts['ytd_change'] = counts['ytd_2026']-counts['same_period_2025']
            counts['y2024_y2025_change'] = counts['y2025']-counts['y2024']
            if any(number(row.get(key)) != value for key, value in counts.items()):
                errors.append(name + ' completion count differs: ' + pid)
            if row.get('primary_comparison') != '2024_vs_2025' or row.get('label_basis') != '2024_vs_2025':
                errors.append(name + ' primary window is not 2024 versus 2025: ' + pid)
            if not true(row.get('h1_provisional')):
                errors.append(name + ' H1 must remain provisional: ' + pid)
            withheld = true(row.get('label_withheld'))
            if (row.get('momentum') == 'withheld') != withheld:
                errors.append(name + ' withholding flags differ: ' + pid)
            actual, cohort = (number(row.get(key)) for key in ('publication_actual_pairs_2025','publication_completion_cohort_2025'))
            lower = float(row.get('publication_2025_unpublished_share_lower') or 0)
            after = number(row.get('publication_2025_after_snapshot_count')) or 0
            strong = bool(cohort and ((actual and actual >= 20 and actual/cohort >= .5 and lower >= .1 and lower*cohort >= 5)
                                     or (after >= 5 and after/cohort >= .1)))
            coverage_lower_bound = lower_bound_coverage(publishers[pid])
            expected_withheld = strong or coverage_lower_bound
            if withheld != expected_withheld or true(row.get('publication_2025_strong_delay_evidence')) != strong:
                errors.append(name + ' unsupported categorical label withholding: ' + pid)
            expected_status = ('coverage_lower_bound' if coverage_lower_bound else
                               'withheld_strong_2025_delay_evidence' if strong else
                               'observed_public_completions')
            if row.get('label_status') != expected_status:
                errors.append(name + ' label status differs: ' + pid)
            volume = max(counts['y2024'],counts['y2025']) >= 10
            if true(row.get('min_volume_ok')) != volume:
                errors.append(name + ' annual minimum volume differs: ' + pid)
            delta = counts['y2024_y2025_change']
            directional = volume and abs(delta) >= 5 and (not counts['y2024'] or abs(delta)*100 >= 25*counts['y2024'])
            label = row.get('momentum')
            first = number(row.get('first_known_year'))
            if not withheld:
                if label == 'new':
                    valid = first == 2025 and counts['y2025'] >= 10
                elif label == 'inactive':
                    valid = first is not None and first < 2025 and counts['y2025'] == 0
                else:
                    expected_label = ('rising' if delta > 0 else 'declining') if directional else 'steady'
                    valid = label == expected_label and not (first == 2025 and counts['y2025'] >= 10)
                if not valid:
                    errors.append(name + ' unsupported annual categorical label: ' + pid)
            for field, change, baseline in (('y2024_y2025_change_pct',delta,counts['y2024']),
                                            ('h1_change_pct',counts['h1_change'],counts['h1_2025']),
                                            ('ytd_change_pct',counts['ytd_change'],counts['same_period_2025'])):
                value = row.get(field)
                if (baseline and (value in ('',None) or abs(float(value)-change/baseline*100) > .00001)) or (not baseline and value not in ('',None)):
                    errors.append(name + ' percentage differs: ' + pid + ':' + field)
        firm_ids = [pid for pid,r in publishers.items() if r['kind'] != 'contest_platform']
        total = Counter()
        for pid in firm_ids:
            total.update(expected[pid])
        totals[population] = total
    aggregate_rows = tables.get('firm_momentum_aggregate', [])
    if len(aggregate_rows) != 2 or {r.get('population') for r in aggregate_rows} != set(names):
        errors.append('firm_momentum_aggregate needs both populations')
    for row in aggregate_rows:
        if row.get('aggregate') != 'all_firms':
            errors.append('unexpected momentum aggregate')
        if row.get('label_basis') != '2024_vs_2025' or not true(row.get('h1_provisional')):
            errors.append('momentum aggregate comparison flags differ')
        for key, value in totals.get(row.get('population'), {}).items():
            if number(row.get(key)) != value:
                errors.append('momentum aggregate count differs: ' + key)
        expected_lower_bound = ','.join(sorted(pid for pid, publisher in publishers.items()
                                             if publisher.get('kind') != 'contest_platform' and lower_bound_coverage(publisher)))
        if (row.get('lower_bound_publishers') or '') != expected_lower_bound:
            errors.append('momentum aggregate lower-bound publisher flag differs')
        expected_sca_api = ','.join(sorted(pid for pid, publisher in publishers.items()
                                          if publisher.get('kind') != 'contest_platform' and sca_api_coverage(publisher)))
        if (row.get('sca_api_publishers') or '') != expected_sca_api:
            errors.append('momentum aggregate SCA/API publisher flag differs')
    if all(tables.get(name) for name in names.values()):
        left, right = ({r['firm_id']: r for r in tables[name]} for name in names.values())
        for pid in set(left) & set(right):
            for key in ('momentum_uncertain','publication_coverage_evidence','publication_lag_max_upper_days',
                        'h1_coverage_uncertain','publication_2025_likely_unpublished_share','publication_2025_strong_delay_evidence'):
                if left[pid].get(key) != right[pid].get(key):
                    errors.append('token exclusion changes publisher coverage evidence: ' + pid)
    return errors

# Strings that would reveal this machine or its private caches. Fails anywhere, including quoted text.
OWN_MACHINE_PATTERNS = (str(Path.home()), 'local-cache', '/tmp/model-run', 'web3-audit-corpus/data/',
                        'local-reference-inputs/', '\\\\wsl')
# Generic local-path markers. Fail in metadata columns; publisher-quoted text (finding body/title
# and the verbatim severity/status labels) legitimately quotes paths such as /home/user or /tmp/x.
GENERIC_LOCAL_PATTERNS = ('/home/', '/tmp/', '/Users/', '/mnt/', '/root/', 'file:///', 'C:\\Users\\')
QUOTED_TEXT_FIELDS = {'body_text', 'title', 'severity_original', 'status_original', 'project', 'report_title'}

# Curated public display names.  IDs remain stable keys; these names are the labels shown to readers.
DISPLAY_NAMES = {
    'trail-of-bits': 'Trail of Bits', 'chainsecurity': 'ChainSecurity', 'halborn': 'Halborn',
    'consensys': 'ConsenSys Diligence', 'consensys-diligence': 'ConsenSys Diligence',
    'kudelski-security': 'Kudelski Security', 'kudelski': 'Kudelski Security',
    'chainlight': 'ChainLight', 'oak-security': 'Oak Security', 'oak': 'Oak Security',
    'asymmetric-research': 'Asymmetric Research', 'fuzzland': 'Fuzzland', 'theori': 'Theori',
    'three-sigma': 'Three Sigma', 'secure3': 'Secure3', 'hats-finance': 'Hats Finance',
    'trust-security': 'Trust Security', 'pashov-audit-group': 'Pashov Audit Group',
    'sherlock': 'Sherlock', 'code4rena': 'Code4rena', 'cantina': 'Cantina',
    'spearbit': 'Spearbit', 'spearbit-diligence': 'Spearbit', 'immunefi': 'Immunefi',
    'openzeppelin': 'OpenZeppelin', 'consensys-diligence': 'ConsenSys Diligence',
    'quantstamp': 'Quantstamp', 'zellic': 'Zellic', 'sigma-prime': 'Sigma Prime',
    'ottersec': 'OtterSec', 'peckshield': 'PeckShield',
    'certora': 'Certora', 'runtime-verification': 'Runtime Verification',
    'least-authority': 'Least Authority', 'ncc-group': 'NCC Group', 'slowmist': 'SlowMist',
    'blocksec': 'BlockSec', 'veridise': 'Veridise', 'informalsystems': 'Informal Systems',
    'mixbytes': 'MixBytes', 'statemind': 'Statemind', 'ackee-blockchain': 'Ackee Blockchain',
    'hexens': 'Hexens', 'dedaub': 'Dedaub', 'abdk-consulting': 'ABDK Consulting',
    'nethermind': 'Nethermind', 'guardianaudits': 'Guardian Audits', 'three-sigma': 'Three Sigma',
    'verichains': 'Verichains', 'neodyme': 'Neodyme', 'sec3': 'Sec3', 'decurity': 'Decurity',
    'pessimistic': 'Pessimistic', 'oxorio': 'Oxorio', 'composable-security': 'Composable Security',
    'coinspect': 'Coinspect', 'chainlight': 'ChainLight', 'theori': 'Theori', 'iosiro': 'Iosiro',
    'solidified': 'Solidified', 'electisec': 'Electisec', 'trust-security': 'Trust Security',
    'code4rena-zenith': 'Zenith', 'asymmetric-research': 'Asymmetric Research',
    'movebit': 'MoveBit', 'scalebit': 'ScaleBit', 'bailsec': 'BailSec', 'zokyo': 'Zokyo',
    'fuzzland': 'Fuzzland', 'obsidian-audits': 'Obsidian Audits', 'teamomega': 'Team Omega',
    'codespect': 'CodeSpect', 'shieldify': 'Shieldify', 'cantina': 'Cantina', 'code4rena': 'Code4rena',
    'sherlock': 'Sherlock', 'hats-finance': 'Hats Finance',
    'secure3': 'Secure3', 'certik': 'CertiK',
}

# Reviewed publisher notices.  A match with a report's extracted text withholds all finding text.
NOTICE_PATTERNS = (
    ('confidentiality_notice', re.compile(
        r'(?is)\bconfidentiality\s+notice\b.{0,450}\bthis\s+report\s+may\s+contain\b'
        r'.{0,100}\bprivileged\s+and\s+confidential\b.{0,1800}\bstrictly\s+prohibited\b')),
    ('no_reproduction_distribution', re.compile(r'(?is)may not be reproduced.{0,180}(?:distributed|distribution).{0,180}(?:express written permission|written permission)')),
    ('no_distribution_written_consent', re.compile(r'(?is)(?:reproduction|distribution|distributing).{0,180}(?:strictly prohibited|prohibited).{0,180}(?:prior written consent|written consent)')),
    # A bare occurrence in finding prose (for example, "confidential data")
    # is not a publisher restriction.  Require a notice phrase, a legal
    # disclosure/reproduction term, or a repeated page header/footer marker.
    ('confidential', re.compile(
        r'(?is)(?:\bnotice\s+of\s+confidentiality\b|'
        r'\b(?:this|the)\s+(?:audit\s+)?(?:report|document)\b.{0,100}\bconfidential\b|'
        r'\bconfidential\b.{0,180}(?:not\s+to\s+(?:copy|disclose|disseminate)|'
        r'(?:are\s+)?not\s+to\s+be\s+provided|without\s+our\s+authorization|'
        r'may\s+not|prohibited|intended\s+(?:solely|only)|permission|consent|'
        r'disclos|distribut|reproduc)|'
        r'^\s*confidential\s*$|'
        r'^.{0,100}\bconfidential\b.{0,60}\bp\.?\s*\d[\d\s]*/\s*\d)', re.M)),
    ('no_reproduction', re.compile(r'(?is)(?:no|not|may not be)\s+(?:be\s+)?reproduced.{0,180}(?:without|permission|consent)')),
    ('no_distribution', re.compile(r'(?is)(?:no|not|may not be)\s+(?:be\s+)?distributed.{0,180}(?:without|permission|consent)')),
    ('no_disclosure_without_consent',re.compile(r'(?is)\bthis\s+report\s+may\s+not\s+be\s+transmitted\s*,?\s*disclosed.{0,240}\bwithout\b.{0,100}\bwritten\s+consent\b')),
    ('conditional_public_disclosure',re.compile(r'(?is)\b(?:this\s+document|the\s+report)\b.{0,280}\bconfidential\b.{0,360}\bdisclosed\s+publicly\s+after\s+all\s+vulnerabilities\s+(?:are\s+)?fixed\b.{0,90}\bdecision\s+of\s+(?:the\s+)?Customer\b')),
)
BIDI_CONTROL_RE = re.compile(r'[\u200e\u200f\u202a-\u202e\u2066-\u2069]')

ROLE_EMAIL_PREFIXES = {'security', 'info', 'admin', 'support', 'contact', 'hello', 'legal', 'privacy', 'abuse', 'dev'}
EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")
# Require a phone-shaped grouping.  This avoids treating dates, CVSS scores,
# years, and numeric identifiers as personal phone numbers.
PHONE_RE = re.compile(
    r"(?<![\w])(?:"
    r"\+\d{1,3}(?:[\s.-]\(?\d{2,4}\)?){2,4}|"
    r"\(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}|"
    r"\d{1,3}[\s.-]\d{3}[\s.-]\d{4}"
    r")(?![\w])"
)
CREDENTIAL_RES = (
    ('webhook_secret', re.compile(r'\bwhsec_[A-Za-z0-9_=-]{8,}\b')),
    ('avalanche_private_key', re.compile(r'\bPrivateKey-[A-Za-z0-9]{8,}\b')),
    ('aws_access_key', re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|(?i:\b(?:aws[_ -]?secret[_ -]?access[_ -]?key|secret[_ -]?access[_ -]?key)\s*[=:]\s*[A-Za-z0-9/+=]{20,})')),
    ('gcp_api_key', re.compile(r'\bAIza[0-9A-Za-z_\-]{30,}\b')),
    ('api_key', re.compile(r'(?i)\b(?:api[_ -]?key|apikey|access[_ -]?token|client[_ -]?secret|token|secret)[=:]\s*["\']?[A-Za-z0-9_\-./+=]{16,}["\']?|\b(?:infura|alchemy|moralis|quicknode)\.(?:io|com)/(?:v[23]/)?[A-Za-z0-9_\-]{16,}')),
    ('db_uri_password', re.compile(r'(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/@:]+:[^\s/@]+@[^\s]+')),
    ('github_token', re.compile(r'\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9]{20,}\b')),
    ('github_fine_grained_token', re.compile(r'\bgithub_pat_[A-Za-z0-9_]{22,}\b')),
    ('slack_token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b')),
    ('stripe_key', re.compile(r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b')),
    ('npm_token', re.compile(r'\bnpm_[A-Za-z0-9]{20,}\b')),
    ('sendgrid_key', re.compile(r'\bSG\.[A-Za-z0-9_-]{16,}\b')),
    ('jwt', re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b')),
    ('generic_bearer', re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}')),
)
PRIVATE_KEY_RE = re.compile(
    r'(?P<pem>-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?'
    r'-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)'
    r'|(?P<prefix>'
    r'\b\w*private[\s_-]*key\b(?:\s*["\'`]?\s*(?:[:=]|\bis\b)\s*["\'`]?|\s+["\'`]?)'
    r'|\b(?:crypto\.)?HexToECDSA\s*\(\s*["\'`]?'
    r'|(?<![\w-])(?:pk|priv)\b\s*["\']?\s*[:=]\s*["\']?'
    r'|\bnew\s+(?:[\w$]+\.)*Wallet\s*\(\s*["\']?'
    r'|\bvm\.(?:addr|rememberKey)\s*\(\s*(?:uint256\s*\(\s*)?["\']?'
    r'|(?m:^[ \t]*(?:export[ \t]+)?(?-i:KEY)[ \t]*=[ \t]*["\']?)'
    r')(?P<key>(?:0x)?[0-9a-f]{64})(?![0-9a-f])',
    re.I | re.S,
)
HEX64_RE = re.compile(r'(?i)(?<![0-9a-f])(?:0x)?[0-9a-f]{64}(?![0-9a-f])')
MNEMONIC_RE = re.compile(r'''(?ix)\b(?:mnemonic|seed[\ _-]phrase)["']?\s*[:=]\s*["']?
    (?P<phrase>(?:[a-z]+(?:\s+|(?=["']|$))){12,24})''')
# English BIP39 word list from trezor/python-mnemonic v0.21 (MIT; licence
# alongside the data), retrieved 2026-10-23. No wallet/crypto dependency needed.
# https://github.com/trezor/python-mnemonic/tree/v0.21
BIP39_WORDS = tuple((Path(__file__).parent / 'bip39_english.txt').read_text(encoding='utf-8').split())
BIP39_INDEX = {word: i for i, word in enumerate(BIP39_WORDS)}
BIP39_TOKEN_RE = re.compile(r'\b[a-z]+\b', re.I)
PUBLIC_TEST_MNEMONICS = {
    tuple(('test ' * 11 + 'junk').split()): 'Hardhat/Anvil documented development default',
    tuple('candy maple cake sugar pudding cream honey rich smooth crumble sweet treat'.split()): 'Ganache CLI documented development default',
    tuple(('abandon ' * 11 + 'about').split()): 'BIP39 public zero-entropy test vector',
    tuple('legal winner thank year wave sausage worth useful legal winner thank yellow'.split()): 'BIP39 public test vector',
}


def bip39_valid(words):
    """Recognize a complete mnemonic using its entropy checksum, without deriving keys."""
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    value = 0
    for word in words:
        if word not in BIP39_INDEX:
            return False
        value = (value << 11) | BIP39_INDEX[word]
    checksum_bits = len(words) // 3
    entropy_bits = len(words) * 11 - checksum_bits
    entropy = (value >> checksum_bits).to_bytes(entropy_bits // 8, 'big')
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    return value & ((1 << checksum_bits) - 1) == expected


def mask_bip39(text):
    """Mask checksum-valid unlabelled phrases, preserving documented public fixtures."""
    spans = []
    run = []

    def finish():
        # A long word list or repeated audit checklist cells are not evidence
        # of a secret. Labelled phrases are handled independently above.
        if len(run) > 48 and len({token.group().lower() for token in run}) > 32:
            return
        start = 0
        words = [token.group().lower() for token in run]
        while len(words) - start >= 12:
            public = next((phrase for phrase in PUBLIC_TEST_MNEMONICS
                           if tuple(words[start:start + len(phrase)]) == phrase), None)
            if public:
                start += len(public)
                continue
            length = next((n for n in (24, 21, 18, 15, 12)
                           if start + n <= len(words) and len(set(words[start:start + n])) >= 8
                           and bip39_valid(words[start:start + n])), None)
            if length:
                spans.append((run[start].start(), run[start + length - 1].end()))
                start += length
            else:
                start += 1

    for token in BIP39_TOKEN_RE.finditer(text):
        if token.group().lower() not in BIP39_INDEX:
            if len(run) >= 12:
                finish()
            run = []
            continue
        if run and not re.fullmatch(r'[\s,]+', text[run[-1].end():token.start()]):
            if len(run) >= 12:
                finish()
            run = []
        run.append(token)
    if len(run) >= 12:
        finish()
    for left, right in reversed(spans):
        text = text[:left] + '[REDACTED-KEY]' + text[right:]
    return text, len(spans)

# Hardhat/Anvil public defaults: mnemonic "test" eleven times + "junk",
# BIP-32 path m/44'/60'/0'/0/i, i=0..19. Public fixtures, never funded secrets.
# Sources: https://v2.hardhat.org/hardhat-network/docs/reference#accounts
# and https://getfoundry.sh/anvil/reference/ (default mnemonic and derivation path).
PUBLIC_TEST_KEYS = {
    'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    '59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
    '5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a',
    '7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6',
    '47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a',
    '8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba',
    '92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e',
    '4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356',
    'dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97',
    '2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6',
    'f214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897',
    '701b615bbdfb9de65240bc28bd21bbc0d996645a3dd57e7b12bc2bdf6f192c82',
    'a267530f49f8280200edf313ee7af6b827f2a8bce2897751d06a843f644967b1',
    '47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942dd',
    'c526ee95bf44d8fc405a158bb884d9d1238d99f0612e9f33d006bb0789009aaa',
    '8166f546bab6da521a8369cab06c5d2b9e46670292d85c875ee9ec20e84ffb61',
    'ea6c44ac03bff858b476bba40716402b03e41b8e97e276d1baec7c37d42484a0',
    '689af8efa8c651a91ad287602527f3af2fe9f6501a7ac4b061667b5a93e037fd',
    'de9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0',
    'df57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e',
}

def display_name(firm_id, fallback=None):
    value = DISPLAY_NAMES.get(str(firm_id).lower()) or fallback or firm_id
    if value and str(value).isupper():
        return str(value).title()
    return value

TITLE_WORD_RE = re.compile(r'[A-Za-z]{2,}')
SPACED_TITLE_RUN_RE = re.compile(r'(?<!\S)(?:[A-Za-z]\s+)+[A-Za-z](?!\S)')
SPACED_TITLE_DIGITS_RE = re.compile(r'(?<!\S)(?:\d\s+)+\d(?!\S)')
TITLE_COMMON_WORDS = ('a', 'i', 'the', 'is', 'of', 'in', 'to', 'and', 'or', 'as', 'an',
                      'be', 'by', 'for', 'may', 'not', 'it', 'on', 'with', 'this',
                      'that', 'these', 'can')


def is_letter_spaced_title(value):
    """Require a long, mostly single-letter lowercase run, not an acronym list."""
    if not isinstance(value, str):
        return False
    parts = value.strip().split()
    singles = [p for p in parts if len(p) == 1 and p.isalpha()]
    return (len(parts) >= 8 and len(singles) >= max(8, math.ceil(len(parts) * .7))
            and sum(p.islower() for p in singles) >= 3)


def title_word_ranks(counts):
    """Stable language model from normal corpus prose; no external dictionary."""
    ranks = {word: i + 1 for i, (word, _) in enumerate(
        sorted(counts.items(), key=lambda pair: (-pair[1], pair[0])))}
    ranks.update({word: 1 for word in TITLE_COMMON_WORDS})
    return ranks


def _segment_title_run(token, ranks):
    if not ranks:
        return token
    lower = token.lower()
    best = [(float('inf'), ()) for _ in range(len(token) + 1)]
    best[0] = (0.0, ())
    for end in range(1, len(token) + 1):
        for start in range(max(0, end - 28), end):
            rank = ranks.get(lower[start:end])
            if rank is None:
                continue
            score = best[start][0] + math.log(rank + 1) + 2.5
            if score < best[end][0]:
                best[end] = (score, best[start][1] + ((start, end),))
    if not best[-1][1]:
        return token
    return ' '.join(token[start:end] for start, end in best[-1][1])


def repair_title_spacing(value, word_ranks=None):
    """Repair long letter-spaced extraction runs while preserving punctuation."""
    if not is_letter_spaced_title(value):
        return value, False
    def replace(match):
        run = ''.join(match.group().split())
        return _segment_title_run(run, word_ranks)
    repaired = SPACED_TITLE_RUN_RE.sub(replace, value.strip())
    repaired = SPACED_TITLE_DIGITS_RE.sub(lambda m: ''.join(m.group().split()), repaired)
    repaired = re.sub(r'\s+([,.!?;:)\]\}])', r'\1', repaired)
    repaired = re.sub(r'([({\[])\s+', r'\1', repaired)
    repaired = re.sub(r'(?<=\w)\s+([’\'][A-Za-z])', r'\1', repaired)
    repaired = re.sub(r'\s+-\s+', '-', repaired)
    return repaired, repaired != value


def find_notice_before_review(text):
    if not text:
        return None
    # Some PDFs insert bidirectional formatting marks between every word of
    # their legal notice, in place of spaces.  Treat the marks as separators.
    if BIDI_CONTROL_RE.search(text):
        text = re.sub(r'\s+', ' ', BIDI_CONTROL_RE.sub(' ', text))
    # Most reports do not contain any rights language.  Gate each reviewed
    # expression with a cheap case-insensitive substring check so the full
    # report scan does not run five bounded-dot regexes over every character.
    # The gates are deliberately broader than the expressions: they only skip
    # a pattern when one of its required words cannot occur at all.
    lowered = text.lower()
    gates = {
        'confidentiality_notice': ('confidentiality', 'prohibited'),
        'no_reproduction_distribution': ('reproduc', 'distribut', 'written permission'),
        'no_distribution_written_consent': ('prohibit', 'consent'),
        'confidential': ('confidential',),
        'no_reproduction': ('reproduc',),
        'no_distribution': ('distribut',),
    }
    for name, pattern in NOTICE_PATTERNS[:6]:
        if name == 'confidential':
            # Confidentiality appears in ordinary vulnerability prose and in
            # taxonomy labels.  Inspect only the local contexts around the
            # keyword and accept explicit notice language or a page header /
            # footer marker.
            if 'confidential' not in lowered:
                continue
            # A short heading such as ``Notice of confidentiality`` is an
            # explicit publisher notice even when the body text below it does
            # not repeat the word "confidential".
            notice_heading = re.search(r'(?im)^\s*notice\s+of\s+confidentiality\s*$', text)
            if notice_heading:
                return name, re.sub(r'\s+', ' ', notice_heading.group(0)).strip()[:200]
            marker = re.search(r'(?im)^\s*confidential\s*$', text)
            if marker:
                return name, re.sub(r'\s+', ' ', marker.group(0)).strip()[:200]
            for line in text.splitlines():
                line_lower = line.lower()
                if 'confidential' in line_lower and re.search(r'\bp\.?\s*\d[\d\s]*/\s*\d', line_lower):
                    return name, re.sub(r'\s+', ' ', line).strip()[:200]
            explicit = re.search(
                r'(?is)\b(?:this|the)\s+(?:audit\s+)?(?:report|document)\b.{0,80}?'
                r'\b(?:is|remains)\s+confidential\b', text)
            if explicit:
                return name, re.sub(r'\s+', ' ', explicit.group(0)).strip()[:200]
            terms = ('not to copy', 'not to be provided', 'without our authorization',
                     'may not', 'prohibited', 'intended solely', 'intended only',
                     'permission', 'consent', 'disclos', 'distribut', 'reproduc')
            for match in re.finditer(r'(?i)\bconfidential\b', text):
                window_start = max(0, match.start() - 80)
                window_end = min(len(text), match.end() + 200)
                window = text[window_start:window_end]
                if any(term in window.lower() for term in terms):
                    return name, re.sub(r'\s+', ' ', window).strip()[:200]
            continue
        if not all(word in lowered for word in gates[name]):
            continue
        m = pattern.search(text)
        if m:
            excerpt = re.sub(r'\s+', ' ', m.group(0)).strip()[:200]
            return name, excerpt
    return None

def interleaved_notice(text):
    """Match a legal heading and restriction within a bounded token window.

    PDF columns can insert other-column words between successive notice words.
    Require ordered heading tokens plus a disclosure restriction nearby; never
    combine evidence across pages or across an entire report.
    """
    for heading in re.finditer(r'(?i)\bnotice\b', text):
        page = text[heading.start():heading.start() + 2040].split('\f', 1)[0]
        tokens = list(re.finditer(r"[a-z]+", page.lower()))
        for i, token in enumerate(tokens):
            if token.group() != 'notice':
                continue
            end = min(len(tokens), i + 24)
            of = next((j for j in range(i + 1, end) if tokens[j].group() == 'of'), None)
            conf = next((j for j in range((of or end) + 1, end)
                         if tokens[j].group() == 'confidentiality'), None)
            if conf is None or tokens[conf].end() - token.start() > 240:
                continue
            window = page[token.start():min(len(page), tokens[conf].end() + 1800)]
            compact = re.sub(r'\s+', ' ', window)
            # A contiguous heading itself is an explicit notice. Interleaved
            # headings also require the operative restriction in this window.
            if re.match(r'(?i)notice\s+of\s+confidentiality\b', compact):
                return 'confidential', compact[:200]
            words = re.findall(r'[a-z]+', compact.lower())
            wanted = iter(('not', 'to', 'be', 'disclosed', 'distributed'))
            current = next(wanted)
            for word in words[:180]:
                if word == current:
                    current = next(wanted, None)
                    if current is None:
                        return 'confidential', compact[:200]
    return None


def find_notice(text):
    """Recognize legal notices locally, preserving page boundaries and PDF ligatures."""
    if not text:
        return None
    text = unicodedata.normalize('NFKC', BIDI_CONTROL_RE.sub(' ', text)).replace('\r\n', '\n').replace('\r', '\n')
    if not re.search(r'(?i)confidential|reproduc|distribut|transmitted|disclosed\s+publicly', text):
        return None
    compact = re.sub(r'\s+', ' ', text)
    for name, pattern in NOTICE_PATTERNS[:1]:
        match = pattern.search(compact)
        if match:
            return name, match.group()[:200]
    if re.search(r'(?i)\bnotice\b', text):
        found = interleaved_notice(text)
        if found:
            return found
    # A notice governs the publication/deliverable. Confidential token/data
    # vocabulary alone supplies no evidence of a publisher restriction.
    header = None
    for stamp in re.finditer(r'(?im)^[ \t\f]*(?:(?:client[ \t]+)?confidential)[ \t]*$', text):
        label = stamp.group().strip()
        previous = text[:stamp.start()].splitlines()
        # Lowercase prose wrapped onto its own line still belongs to the
        # preceding sentence (NCC FROST: "keep secret values confidential").
        if label == label.lower() and previous and previous[-1].strip():
            continue
        header = re.sub(r'\s+', ' ', label)[:200]
        break
    for line in text.splitlines():
        if len(line) >= 220 or 'confidential' not in line.lower():
            continue
        footer = re.search(r'(?i)\bconfidential(?:[ \t]+\d+)?[ \t]*$', line) and ('@' in line or re.search(r'(?i)\bclient[ \t]+confidential\b', line))
        if re.search(r'(?i)\bconfidential\b', line) and (footer or re.search(r'(?i)\bp\.?\s*\d[\d\s]*/\s*\d|\bpage\s+\d|©', line)):
            header = re.sub(r'\s+', ' ', line).strip()[:200]
            break
    explicit = re.search(
        r'(?is)\b(?:this|the|our)\s+(?:audit\s+|security\s+)?'
        r'(?:report|document|publication|assessment)\b[^.;]{0,240}\b'
        r'(?:is|remains|contains)\s+(?:(?:strictly|highly)\s+)?confidential\b'
        r'|\bdeliverables?\b[^.\n]{0,100}\b(?:are|is)\s+confidential\b', text)
    legal = re.compile(r'(?i)\b(?:this|the|our)\s+(?:audit\s+|security\s+)?(?:report|document|publication|assessment)\b|\bdeliverables?\b|\b(?:disclaimer|copyright|legal notice|notice of confidentiality)\b')
    # Bounded keyword windows keep scanning linear in large code-heavy reports.
    windows = [text[max(0, m.start()-350):m.end()+500]
               for m in re.finditer(r'(?i)reproduc(?:ed|tion)|distribut(?:ed|ion|ing)|transmitted|disclosed\s+publicly', text)]
    for name, pattern in NOTICE_PATTERNS:
        if name == 'confidentiality_notice':
            continue
        if name == 'confidential':
            if explicit or header:
                return name, re.sub(r'\s+', ' ', explicit.group()).strip()[:200] if explicit else header
            continue
        for window in windows:
            match = pattern.search(window)
            if not match or not legal.search(window):
                continue
            if name == 'no_distribution' and not re.search(r'(?i)\b(?:permission|consent)\b', match.group()):
                continue
            return name, re.sub(r'\s+', ' ', match.group()).strip()[:200]
    return None


def join_credential_wraps(text):
    """Join PDF continuation glyphs and credential-shaped physical line wraps."""
    text = re.sub(r'[ \t]+c[ \t]*\n[ \t]*(?:,→[ \t]*)?', '', text)
    text = re.sub(r'[ \t]*\n?[ \t]*,→[ \t]*', '', text)
    # Only join unmarked wraps within recognizable token/URL contexts.
    wrapped = re.compile(r'(?i)((?:https?://[^\s]*?(?:alchemy|infura|moralis|quicknode)[^\s]*|\beyJ[A-Za-z0-9_.-]+|\bBearer[ \t\r\n]+[A-Za-z0-9_.-]+))\n(?:[ \t]*\n)*[ \t]*([A-Za-z0-9_.-]{8,})(?=[ \t]+--|[ \t]*\n|$)')
    while True:
        joined = wrapped.sub(r'\1\2', text)
        if joined == text:
            return text
        text = joined


def clean_metadata_name(value, *, url=None, project=False, fallback_hint=None):
    """Conservative presentation repair with a publisher filename/slug fallback."""
    original = value
    value = re.sub(r'\s+', ' ', re.sub(r'<[^>]*>', ' ', unicodedata.normalize('NFKC', html.unescape(value or '')))).strip()
    if project:
        value = re.sub(r'(?i)\s+(?:audit\s+)?findings\s*&?\s*$', '', value).strip()
    bad = (not value or len(value) > 240 or re.search(
        r'(?i)\.{3,}|…{2,}|(?:\.\s*){5,}|submit an inquiry|message on telegram|testing,? computer.aided|'
        r'has indicated is|detrimental for the client|risk that the client|'
        r'^about this report\b|^security framework$|^scope of the$|^\(Solidity part\)$|^audit en$|'
        r'SLOWIMIST|PESSIMISTIC SEGURITY|^\(?A,\s*zokyo$|^®S\b|'
        r'^(?:tools? used|repository\s*\(link\)\s*platform|review|smart contract security|summary)$|'
        r"^[“”‘’\"']*(?:january|february|march|april|may|june|july|august|september|october|november|december)\s+version[“”‘’\"']*$|"
        r'^(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sept?(?:ember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?\s*[’\']?\d{2,4}$|'
        r'^(?:has indicated is low-impact|financial impact\.|financial implications for client|for client.{1,4}reputation)|'
        r'to (?:moderate|high|low) financial impact|(?:^|\b)(?:disclaimer|table of contents)\b|'
        r'^(?:\d+[.\s]+)?(?:audit methodology|introduction to the audit|executive summary|'
        r'introduction|contents|confidential|security assessment|security audit report|audit report|smart contract audit)[\s.\d…]*$', value))
    if bad:
        hint, _ = clean_metadata_name(fallback_hint) if fallback_hint else (None, False)
        if hint:
            return hint, hint != original
        value = None
        path = unquote(urlsplit(url or '').path).rstrip('/').split('/')
        for part in reversed(path):
            slug = re.sub(r'(?i)\.(?:pdf|md|html?)$', '', part)
            slug = re.sub(r'[_-]+', ' ', slug).strip()
            slug = re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', html.unescape(slug))).strip()
            if not slug or re.fullmatch(r'[a-fA-F0-9]{24,}|\d+|(?i:report|audit(?: en)?|index|readme|review|blob|head|main|master|reports|audits|solidity|pdf|contests)', slug):
                continue
            value = slug
            break
        if value and (len(value) > 180 or re.search(r'(?i)submit an inquiry|disclaimer|methodology', value)):
            value = None
    return value, value != original


ANNOTATORS_PUBLIC = 'Three LLM annotators labelled the same findings independently.'
PUBLIC_SOURCE_NAMES = {'phase4': 'report_extraction', 'phase4_supplemental': 'supplemental_extraction'}


def public_summary(value):
    """Use publication vocabulary for nested summary keys and source labels."""
    if isinstance(value, dict):
        return {PUBLIC_SOURCE_NAMES.get(str(k), str(k).replace('phase4', 'finding_records')):
                public_summary(v) for k, v in value.items()
                if k not in {'title_examples', 'private_key_redacted_contexts', 'private_key_preserved_contexts'}}
    if isinstance(value, list):
        return [public_summary(v) for v in value]
    if isinstance(value, str):
        return PUBLIC_SOURCE_NAMES.get(value, value.replace('phase4', 'finding_records'))
    return value


def display_status(value):
    """Join letter-spaced status labels using the small, fixed display vocabulary."""
    if not isinstance(value, str):
        return value
    labels = ('partially resolved', 'partially fixed', 'acknowledged', 'not fixed',
              'not resolved', 'not stated', 'unresolved', 'resolved', 'addressed',
              'mitigated', 'accepted', 'pending', 'fixed', 'open', 'informational', 'info')
    for label in labels:
        letters = ''.join(label.split())
        pattern = r'(?i)(?<!\w)' + r'\s*'.join(re.escape(ch) for ch in letters) + r'(?!\w)'
        def replace(match):
            raw = match.group()
            if not re.search(r'(?<=\w)\s+(?=\w)', raw) or raw.lower() == label:
                return raw
            return label.upper() if raw.replace(' ', '').isupper() else label.title()
        value = re.sub(pattern, replace, value)
    return value


def taxonomy_examples(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == 'examples' and isinstance(value, list):
                yield from value
            else:
                yield from taxonomy_examples(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from taxonomy_examples(value)


def clean_taxonomy(obj, released_uids):
    """Publish example links only; stale examples and all quoted text are removed."""
    counts = {'examples_before': 0, 'stale_examples_removed': 0, 'excerpts_removed': 0}
    def clean(value):
        if isinstance(value, list):
            return [clean(v) for v in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, val in value.items():
            if key != 'examples':
                result[key] = clean(val)
                continue
            examples = []
            for example in val:
                counts['examples_before'] += 1
                counts['excerpts_removed'] += int('excerpt' in example)
                if example.get('finding_uid') not in released_uids:
                    counts['stale_examples_removed'] += 1
                    continue
                # Titles are publisher text too. Example links suffice.
                examples.append({k: v for k, v in example.items() if k not in ('excerpt', 'title')})
            result[key] = examples
        return result
    return clean(obj), counts


def wilson(numerator, denominator):
    if not denominator:
        return None, None
    z = 1.959963984540054
    p = numerator / denominator
    d = 1 + z*z / denominator
    center = (p + z*z / (2*denominator)) / d
    half = z * math.sqrt(p*(1-p)/denominator + z*z/(4*denominator*denominator)) / d
    return max(0.0, center-half), min(1.0, center+half)

SECRET_FIELD = r'(?:api[_ -]?key|refresh[_ -]?token|access[_ -]?token|client[_ -]?secret|secret)'
QUOTED_SECRET_RE = re.compile(
    r'(?is)(?P<prefix>\b' + SECRET_FIELD + r'["\']?\s*[:=]\s*)'
    r'(?P<quote>["\'`])(?P<value>(?:(?!(?P=quote)).){1,8192})(?P=quote)')
ENV_SECRET_RE = re.compile(
    r'(?im)^(?P<prefix>[ \t]*(?:export[ \t]+)?' + SECRET_FIELD + r'[ \t]*=[ \t]*)'
    r'(?P<value>[A-Za-z0-9_./+=-]+)(?=[ \t]*(?:[;#]|\r?$))')
TOKEN_CONTEXT_RE = re.compile(
    r'(?i)\b(?:' + SECRET_FIELD + r')["\']?\s*[:=][ \t]*|'
    r'\bauthorization\s*:[ \t]*(?:Bearer[ \t]*)?|'
    r'\[REDACTED-CREDENTIAL\]|(?=\beyJ[A-Za-z0-9_-]{8,})')
TOKEN_LINE_RE = re.compile(r'[A-Za-z0-9_./+=@|®ë,→\s-]+\Z')


def credential_block_end(text, start):
    """Consume only adjacent encoded-token lines, including OCR separators."""
    cursor, end = start, start
    for _ in range(32):
        line_end = text.find('\n', cursor, min(len(text), start + 16384))
        if line_end < 0:
            line_end = min(len(text), start + 16384)
        line = text[cursor:line_end]
        if end > start and line.strip().upper() == 'FINDINGS & TECH DETAILS':
            cursor = line_end + 1
            continue
        # Env/cookie delimiters terminate a token even on the first line.
        stop = re.search(r'''[;"'`<>\[\]{}]''', line)
        if stop:
            line = line[:stop.start()]
        if not line.strip():
            if stop or line_end == len(text):
                break
            cursor = line_end + 1
            continue
        compact = re.sub(r'[\së®@|,→]', '', line)
        chunks = re.findall(r'[A-Za-z0-9_+/=-]+', line)
        tokenish = (TOKEN_LINE_RE.fullmatch(line) and len(compact) >= 16
                    and (max(map(len, chunks), default=0) >= 12 or len(compact) >= 32)
                    and (any(c.isdigit() for c in compact) or
                         (sum(c.isupper() for c in compact) >= 4 and sum(c.islower() for c in compact) >= 4)))
        # Dot-only wrap lines join two substantial segments; OCR commonly
        # emits an extra continuation glyph before the dot.
        if compact in ('.', '-') and end > start:
            tokenish = True
        if not tokenish:
            break
        end = cursor + len(line.rstrip())
        if stop or line_end == len(text):
            break
        cursor = line_end + 1
    return end


def mask_context_credentials(text):
    counts = {}
    def quoted(match):
        if match['value'].startswith('[REDACTED-') or not match['value'].strip():
            return match.group()
        counts['secret_field'] = counts.get('secret_field', 0) + 1
        return match['prefix'] + match['quote'] + '[REDACTED-CREDENTIAL]' + match['quote']
    text = QUOTED_SECRET_RE.sub(quoted, text)
    def env(match):
        counts['secret_field'] = counts.get('secret_field', 0) + 1
        return match['prefix'] + '[REDACTED-CREDENTIAL]'
    text = ENV_SECRET_RE.sub(env, text)
    spans = []
    for match in TOKEN_CONTEXT_RE.finditer(text):
        start = match.end()
        end = credential_block_end(text, start)
        if end > start:
            spans.append((start, end))
    # Merge overlapping contexts (for example an env value starting eyJ).
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        text = text[:start] + '[REDACTED-CREDENTIAL]' + text[end:]
    if merged:
        counts['credential_continuation'] = len(merged)
    return text, counts


def mask_text(text):
    """Mask credentials and personal contact data, returning text and per-class counts."""
    if not text:
        return text, {}
    counts = {}
    # Normalize only when an actual redaction follows; unchanged Oak excerpts
    # must remain character-for-character identical to the source.
    original = text
    lowered = text.lower()
    if any(marker in lowered for marker in ('bearer', 'alchemy', 'infura', 'moralis', 'quicknode',
                                           'eyj', 'api_key', 'token=', 'secret=', 'ghp_', 'private')):
        text = join_credential_wraps(text)
    if any(marker in lowered for marker in ('apikey', 'api_key', 'api-key', 'secret', 'token',
                                            'authorization', 'redacted-credential', 'eyj')):
        text, counts = mask_context_credentials(text)
    def sub(pattern, repl, cls, value):
        value, n = pattern.subn(repl, value)
        if n: counts[cls] = counts.get(cls, 0) + n
        return value
    lower = text.lower()
    # Most finding bodies contain none of these markers.  Avoid running ten
    # broad regular expressions over ordinary prose in that common case.
    credential_markers = {
        'webhook_secret': 'whsec_', 'avalanche_private_key': 'privatekey-',
        'aws_access_key': ('akia', 'asia', 'aws_secret_access_key', 'secret_access_key'),
        'gcp_api_key': 'aiza', 'api_key': ('api_key', 'api-key', 'apikey', 'access_token', 'token=', 'secret=',
                                            'infura.', 'alchemy.', 'moralis.', 'quicknode.'),
        'db_uri_password': ('postgres://', 'postgresql://', 'mysql://', 'mongodb://', 'mongodb+srv://', 'redis://'),
        'github_token': ('ghp_', 'gho_', 'ghs_', 'ghr_'), 'github_fine_grained_token': 'github_pat_',
        'slack_token': 'xox', 'stripe_key': ('sk_live_', 'sk_test_', 'rk_live_', 'rk_test_'),
        'npm_token': 'npm_', 'sendgrid_key': 'sg.', 'jwt': 'eyj', 'generic_bearer': 'bearer',
    }
    for cls, pattern in CREDENTIAL_RES:
        marker = credential_markers[cls]
        if (any(m in lower for m in marker) if isinstance(marker, tuple) else marker in lower):
            text = sub(pattern, '[REDACTED-CREDENTIAL]', cls, text)
            lower = text.lower()
    if '[REDACTED-CREDENTIAL]' in text:
        text, extra = mask_context_credentials(text)
        for cls, count in extra.items():
            counts[cls] = counts.get(cls, 0) + count
    if any(marker in lower for marker in ('private', '-----begin ', '0x', 'wallet', 'vm.', 'pk', 'priv', 'key')):
        def key_sub(m):
            raw = m.group('key')
            if raw and raw.lower().removeprefix('0x') in PUBLIC_TEST_KEYS:
                return m.group(0)
            counts['private_key'] = counts.get('private_key', 0) + 1
            return (m.group('prefix') or '') + '[REDACTED-KEY]'
        text = PRIVATE_KEY_RE.sub(key_sub, text)
        lower = text.lower()
    if any(marker in lower for marker in ('mnemonic', 'seed phrase', 'seed_phrase', 'seed-phrase')):
        def mnemonic_sub(m):
            words = tuple(m.group('phrase').lower().split())
            if any(words[:len(phrase)] == phrase for phrase in PUBLIC_TEST_MNEMONICS):
                return m.group(0)
            counts['mnemonic'] = counts.get('mnemonic', 0) + 1
            return '[REDACTED-KEY]'
        text = MNEMONIC_RE.sub(mnemonic_sub, text)
    if text.count(' ') + text.count('\n') + text.count('\t') >= 11:
        text, n = mask_bip39(text)
        if n:
            counts['mnemonic'] = counts.get('mnemonic', 0) + n
    if '@' in text:
        def email_sub(m):
            addr = m.group(0)
            if re.match(r'(?i)v\d+\.\d+\.\d+(?:[-+]|$)', addr.split('@', 1)[1]):
                return addr  # Go module cache path: module@v1.2.3/platform
            local = addr.split('@', 1)[0].lower()
            if local in ROLE_EMAIL_PREFIXES or local.startswith(tuple(x + '+' for x in ROLE_EMAIL_PREFIXES)):
                return addr
            counts['personal_email'] = counts.get('personal_email', 0) + 1
            return '[REDACTED-EMAIL]'
        text = EMAIL_RE.sub(email_sub, text)
    if any(ch.isdigit() for ch in text):
        ipv6_spans = []
        for match in re.finditer(r'(?i)(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]+', text):
            try:
                ipaddress.IPv6Address(match.group())
                ipv6_spans.append(match.span())
            except ValueError:
                pass
        def phone_sub(match):
            if any(a < match.end() and match.start() < b for a, b in ipv6_spans):
                return match.group()
            if re.search(r'(?i)validators\s+count\s*\([^)]*$', text[max(0, match.start()-80):match.start()]):
                return match.group()
            counts['phone'] = counts.get('phone', 0) + 1
            return '[REDACTED-PHONE]'
        text = PHONE_RE.sub(phone_sub, text)
    if re.search(r'(?i)\bwhois\b|\bregistrant\b', text):
        def name_sub(match):
            if match['name'].strip() == '[REDACTED-NAME]':
                return match.group()
            counts['personal_name'] = counts.get('personal_name', 0) + 1
            return match['prefix'] + '[REDACTED-NAME]'
        text = re.sub(r'(?im)^(?P<prefix>[ \t]*(?:(?:registrant|admin|tech)[ -])?(?:name|person)[ \t]*:[ \t]*)(?P<name>[^\n]+)', name_sub, text)
    return (text if counts else original), counts

def report_tail_offset(text):
    if not text:
        return None
    # A finding span can include the report's closing sections.  Keep the
    # boundary conservative: these headings are only treated as tails when
    # they occupy a complete (short) extracted line.
    marker = re.compile(
        r'(?im)^[ \t\f]*(?:\#{1,6}[ \t]+)?(?:(?:\d+|[A-Z])[.)]?[ \t]+)?(?:appendix(?:\s+[a-z0-9][^\n]{0,72})?|'
        r'disclaimers?(?:\s+[^\n]{0,72})?|about (?:the )?firm(?:\s+[^\n]{0,72})?|'
        r'methodology(?:\s+[^\n]{0,72})?|severity definitions?(?:\s+[^\n]{0,72})?|'
        r'severity legend(?:\s+[^\n]{0,72})?|contact us(?:\s+[^\n]{0,72})?|'
        r'legal notice(?:\s+[^\n]{0,72})?)\s*:?[ \t]*$')
    matches = list(marker.finditer(text))
    # PDF extraction can join a closing page's heading to its entire legal
    # paragraph. The page boundary supplies the heading context in that case.
    matches.extend(re.finditer(r'(?im)^[ \t]*\f[ \t]*(?:disclaimers?|appendix\s+[a-z0-9])\b', text))
    # Trail of Bits uses lettered appendix names without the word Appendix.
    matches.extend(re.finditer(
        r'(?im)^[ \t\f]*[A-Z][.][ \t]+(?:Vulnerability Classifications?|'
        r'Android Heap Dump|Non[–-]Security[–-]Related Findings|Fix Log|Code Maturity|Code Quality)[ \t]*$', text))
    return min((m.start() for m in matches), default=None)


def strip_report_tail(text, *, contiguous=False):
    if not text:
        return text
    offset = report_tail_offset(text)
    if offset is not None:
        text = text[:offset].rstrip()
    if contiguous:
        # Keep one contiguous span. Never join text across removed page furniture
        # or normalize its line endings: Oak excerpts retain every kept character.
        spans = []
        for pattern in (r'(?m)^\s*\f\s*$', r'(?m)^\s*\d{1,4}\s*$'):
            spans.extend(m.span() for m in re.finditer(pattern, text))
        lines = text.splitlines(keepends=True)
        counts = {}
        for line in lines:
            s = line.strip()
            if 3 <= len(s) <= 120:
                key = re.sub(r'\d+', '#', re.sub(r'\s+', ' ', s))
                counts[key] = counts.get(key, 0) + 1
        offset = 0
        for line in lines:
            s = line.strip()
            key = re.sub(r'\d+', '#', re.sub(r'\s+', ' ', s))
            lower = s.lower()
            signal = (s.startswith(('©', '(c)')) or 'all rights reserved' in lower or
                      'http' in lower or 'www.' in lower or 'page ' in lower or
                      ' | ' in s or s.isupper())
            if counts.get(key, 0) >= 3 and signal:
                spans.append((offset, offset + len(line)))
            offset += len(line)
        start = 0
        for left, right in sorted(spans):
            if left > start and text[start:left].strip():
                return text[start:left].rstrip()
            start = max(start, right)
        return text[start:]
    # Form-feed and a line containing only a small integer are page separators
    # emitted by PDF text extractors.  They are never useful finding prose and
    # otherwise make Hexens page footers appear in hundreds of bodies.
    text = re.sub(r'(?m)^\s*\f\s*$', '', text)
    text = re.sub(r'(?m)^\s*\d{1,4}\s*$', '', text)
    # Repeated page footers/headers often carry a page number, so compare a
    # normalized form with digits replaced.  Require a footer/header signal to
    # avoid deleting repeated source-code lines from a finding.
    lines = text.splitlines()
    if lines:
        freq = {}
        keyed = []
        for line in lines:
            s = line.strip()
            key = re.sub(r'\d+', '#', re.sub(r'\s+', ' ', s))
            keyed.append((line, s, key))
            if 3 <= len(s) <= 120:
                freq[key] = freq.get(key, 0) + 1
        repeated = set()
        for line, s, key in keyed:
            if freq.get(key, 0) < 3:
                continue
            lower = s.lower()
            signal = (s.startswith(('©', '(c)')) or 'all rights reserved' in lower or
                      'http' in lower or 'www.' in lower or 'page ' in lower or
                      ' | ' in s or s.isupper())
            if signal:
                repeated.add(key)
        if repeated:
            text = '\n'.join(line for line, _, key in keyed if key not in repeated).rstrip()
    return text

def cap_body(text, cap=15000):
    if not text or len(text) <= cap:
        return text, False
    marker = '[truncated; see the linked report]'
    keep = max(0, cap - len(marker) - 1)
    return text[:keep].rstrip() + '\n' + marker, True


def load_module(name, path):
    """Load one standalone repository module by file path (avoids sys.path name clashes)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_csv(path):
    with open(path, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def scope_rows(root=ROOT):
    return {r['firm_id']: r for r in read_csv(Path(root) / 'registry/scope_tier_a.csv')}


def tier_a(root=ROOT):
    """Firm ids in Tier A scope (firm and contest-platform groups)."""
    return {fid for fid, r in scope_rows(root).items() if r['scope_group'] in TIER_A_GROUPS}


def certik_released(root=ROOT):
    """CertiK counts as released only once the scope registry moves it into a Tier A group."""
    row = scope_rows(root).get(CERTIK)
    return bool(row) and row['scope_group'] in TIER_A_GROUPS


def is_excluded_publisher(value):
    return isinstance(value, str) and value.casefold() in EXCLUDED_AT_PUBLISHER_REQUEST


def is_excluded_url(value):
    """Return true for publisher-request URLs, including Cyfrin GitHub paths."""
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip()
    try:
        parts = urlsplit(text if '://' in text else 'https://' + text)
    except ValueError:
        return False
    host = (parts.hostname or '').casefold().rstrip('.')
    if host in EXCLUDED_PUBLISHER_HOSTS:
        return True
    if host == 'solodit.xyz' or host.endswith('.solodit.xyz'):
        return True
    if host == 'cyfrin.io' or host.endswith('.cyfrin.io'):
        return True
    if host in {'github.com', 'raw.githubusercontent.com', 'api.github.com'}:
        pieces = [p for p in parts.path.split('/') if p]
        if host == 'api.github.com' and pieces and pieces[0].casefold() == 'repos':
            pieces = pieces[1:]
        return bool(pieces and pieces[0].casefold() in {'cyfrin', 'solodit'})
    if host == 'solodit.io' or host.startswith('solodit.') or '.solodit.' in host:
        return True
    return False


def contains_excluded_url(value):
    """Recursively inspect URL/evidence metadata without scanning finding prose."""
    if isinstance(value, str):
        if value.lstrip().startswith(('{', '[')):
            try:
                return contains_excluded_url(json.loads(value))
            except ValueError:
                pass
        return is_excluded_url(value) or any(is_excluded_url(url) for url in re.findall(r'https?://[^\s<>\[\]"\x27]+', value, re.I))
    if isinstance(value, dict):
        return any(contains_excluded_url(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(contains_excluded_url(v) for v in value)
    return False


def remove_excluded_links(text):
    """Remove excluded reference links from another publisher's own prose."""
    if not text:
        return text, 0
    count = 0
    def replace(match):
        nonlocal count
        if is_excluded_url(match.group()):
            count += 1
            return '[link removed at publisher request]'
        return match.group()
    result = re.sub(r'https?://[^\s<>\[\]"\x27]+', replace, text, flags=re.I)
    return result, count


def allowed_firms(root=ROOT, include_certik=False):
    return tier_a(root) - EXCLUDED_AT_PUBLISHER_REQUEST


def cell(value):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (list, dict, tuple)):
        return dumps(value)
    return str(value)


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def csv_bytes(columns, rows):
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator='\n')
    writer.writerow(columns)
    for row in rows:
        extra = set(row) - set(columns)
        if extra:
            raise ValueError(f'Unexpected columns {sorted(extra)}')
        writer.writerow([cell(row.get(c)) for c in columns])
    return buf.getvalue().encode('utf-8')


def write_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_bytes(data)
    tmp.replace(path)
    return path


def write_csv(path, columns, rows):
    return write_bytes(path, csv_bytes(columns, rows))


def write_json(path, obj):
    return write_bytes(path, dumps(obj).encode('utf-8'))


def gzip_deterministic(data):
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0, compresslevel=9) as f:
        f.write(data)
    return buf.getvalue()


def sha256_file(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def notice_source(root, sha):
    """Read complete notice evidence, falling back to a hash-verified original."""
    root = Path(root)
    cached = root / 'local-cache/fulltext' / (sha + '.txt')
    if cached.is_file():
        raw = cached.read_bytes()
        return raw.decode('utf-8', errors='replace'), hashlib.sha256(raw).hexdigest(), 'cached_text'
    for extension in ('pdf', 'md', 'html', 'txt', 'other'):
        path = root / 'local-cache/originals' / sha[:2] / (sha + '.' + extension)
        if not path.is_file():
            continue
        if sha256_file(path) != sha:
            raise ValueError('notice original checksum mismatch: ' + sha)
        if extension == 'pdf':
            import fitz
            with fitz.open(path) as doc:
                text = '\f'.join(page.get_text() for page in doc)
        else:
            if extension == 'other':
                # The Google Docs text export is stored under the collector's
                # generic extension. Only accept actual UTF-8 text here.
                raw = path.read_bytes()
                if b'\x00' in raw:
                    return None, None, 'unavailable'
                try:
                    text = raw.decode('utf-8-sig')
                except UnicodeDecodeError:
                    return None, None, 'unavailable'
            else:
                text = path.read_text(encoding='utf-8', errors='replace')
            if extension == 'html':
                text = html.unescape(re.sub(r'<[^>]+>', ' ', text))
        return text, sha256_text(text), 'original_' + extension
    return None, None, 'unavailable'


GITHUB_BLOB = re.compile(r'^https://github\.com/([^/]+)/([^/]+)/blob/([0-9a-f]{40})/(.+)$')
GITHUB_RAW = re.compile(r'^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([0-9a-f]{40})/(.+)$')
WAYBACK = re.compile(r'^https?://web\.archive\.org/web/(\d+)[a-z_]*/(https?://.+)$')


def link_fields(public_url):
    """Return (url, permalink, archive_url, url_basis) for a recorded public report link.

    url: the publisher's canonical public link. GitHub blobs pinned at a commit are published
    as the branch-head link (`blob/HEAD/...`, which follows the default branch) with the pinned
    blob as permalink. Wayback captures publish the original URL with the capture as archive_url.
    """
    if not public_url:
        return None, None, None, 'missing'
    m = WAYBACK.match(public_url)
    if m:
        url, permalink, _, _ = link_fields(m.group(2))
        return url, permalink, public_url, 'archive_original'
    m = GITHUB_BLOB.match(public_url)
    if m:
        owner, repo, _, path = m.groups()
        return f'https://github.com/{owner}/{repo}/blob/HEAD/{path}', public_url, None, 'github_head'
    m = GITHUB_RAW.match(public_url)
    if m:
        owner, repo, commit, path = m.groups()
        return public_url, f'https://github.com/{owner}/{repo}/blob/{commit}/{path}', None, 'github_raw_pinned'
    return public_url, None, None, 'publisher_link'


def load_link_status(path):
    """Optional link-check join table (docs/release/link_status.csv)."""
    path = Path(path)
    if not path.exists():
        return {}, {}
    by_pair, by_sha = {}, {}
    for r in read_csv(path):
        sha = (r.get('sha256') or r.get('report_id') or '').strip()
        url = (r.get('url') or '').strip()
        if sha and url:
            by_pair[(sha, url)] = r
        if sha:
            by_sha.setdefault(sha, r)
    return by_pair, by_sha
