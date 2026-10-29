"""Reviewed heading profiles for ungraded ToB narrative summary deliverables.

These profiles are pinned to original SHA-256, never selected by parsed counts.
The publisher supplies complete narratives but no severity labels. Titles were
transcribed from the report bodies; repeated fix-review headings are excluded.
"""
import re
import unicodedata
from core import Candidate, set_status_claim

# SHA-256 -> (body section, last body section, publisher heading titles).
PROFILES = {
    'aaef2eb5188943c05ecacd3a6c7573e083c348d0e7d8cf78630a3f9e8cc24986': (
        'Summary of Findings', None, (
            'Forget-and-Forgive Issues in Resharing',
            'Duplicate Ring-Pedersen Parameters',
            'Missing Validation in the PRM Proofs',
            'Redundant PRM Proof',
        )),
    '4281cc667cc5c6f2f61a67cd6a1a09ae6fa7f5f03efd14598643726f91d57987': (
        'Summary of Findings', 'A. Algorithm Diagrams', (
            'The specification contains only limited analysis',
            'The access pattern does not depend on the full dataset',
            'The use of a fixed dataset would allow precomputations to be useful forever',
            'The initial mixing value comes from a small subset of 128-byte values',
            'Result of 64-bit multiplication does not rely on all input bits',
            'The specification is outdated and incomplete and contains errors',
            'Issues in the implementation',
        )),
    '29506d8eca78deea27605baf3bd31e7f548f70e60d5413ada551955ee2d95ea8': (
        'Summary of Findings', None, (
            '1. Compromised kraken.com server could phish users’ mobile wallet backups [Resolved]',
            '2. Password failure counter resets when providing an empty password [Resolved]',
            '3. Error handling is not specific [Resolved]',
            '4. Users may share passkeys with friends and family',
        )),
    '17dccbf464c72a4d92046086b3e8401b5393c9215799b434311000361ac6bb0f': (
        'Findings', 'A. Missing Input Validation', (
            '1. Inconsistency between batcher and operator can lead to denial of service',
            '2. The SDK silently ignores incorrect inclusion proofs from the batcher',
            '3. Batcher does not perform sufficient input validation',
            '4. Issues in operator Dockerfile',
            '5. Null pointer dereference in the Operator codebase can lead to denial of service',
            '6. Keystore encryption is malleable',
            '7. Outdated dependencies',
            '8. No enforcement of strong passwords for keystores',
            '9. Missing ecrecover result validation',
            '10. Missing events in Solidity contracts',
            '11. Front-running createNewTask leads to loss of funds',
            '12. Inconsistency in the balance unlocking mechanism',
            '13. Usage of storage gaps in upgradeable contracts',
            '14. Usage of block count instead of block timestamp',
        )),
}


def matching_view(text):
    """Remove presentation controls/ligatures, retaining original offset mapping."""
    chars, offsets = [], []
    for index, char in enumerate(text):
        if unicodedata.category(char) == 'Cf':
            continue
        for visible in unicodedata.normalize('NFKC', char):
            chars.append(visible)
            offsets.append(index)
    return ''.join(chars), offsets


def heading_pattern(title):
    # Digits and punctuation can be split by line breaks in the PDF text layer.
    parts = re.findall(r'\w+|[^\w\s]', title)
    normal = r'\s*'.join(re.escape(part) for part in parts)
    # The bidi PDF text layer sometimes paints the first character after the
    # first wrapped line ("he use ...\nT\nforever", or ". Password ...\n2").
    # Match the displaced character explicitly; never accept an omitted one.
    tail = [re.escape(p) for p in re.findall(r'\w+|[^\w\s]', title[1:])]
    shifted = [r'\s*'.join(tail[:n]) + r'\s*\n[ \t]*' + re.escape(title[0]) +
               r'[ \t]*(?:\n\s*' + r'\s*'.join(tail[n:]) + ')' for n in range(1, len(tail))]
    return r'^[ \t\f]*(?:' + '|'.join([normal, *shifted]) + r')[ \t]*$'


def parse(report):
    profile = PROFILES.get(report.meta.get('sha256'))
    if not profile:
        return []
    text, offsets = matching_view(report.text)
    section, stop, titles = profile
    sections = list(re.finditer(heading_pattern(section), text, re.M))
    if not sections:
        raise ValueError('Reviewed narrative section missing')
    start = sections[0].end()
    end = len(text)
    if stop:
        boundary = re.search(heading_pattern(stop), text[start:], re.M)
        if not boundary:
            raise ValueError('Reviewed narrative end boundary missing')
        end = start + boundary.start()
    matches = []
    cursor = start
    for title in titles:
        match = re.search(heading_pattern(title), text[cursor:end], re.M)
        if not match:
            raise ValueError('Reviewed narrative heading missing: ' + title)
        first, last = cursor + match.start(), cursor + match.end()
        matches.append((title, first, last))
        cursor = last
    candidates = []
    for index, (title, first, last) in enumerate(matches):
        a = offsets[first]
        b = offsets[matches[index + 1][1]] if index + 1 < len(matches) else (offsets[end] if end < len(offsets) else len(report.text))
        native = re.match(r'^(\d+)\.\s*', title)
        c = Candidate(a, title, severity_raw=None, printed_id=native[1] if native else None,
                      end=b, method='unrated-narrative-detail', confidence=.95,
                      evidence={'source_section': section, 'severity_basis': 'publisher_does_not_assign_severity',
                                'heading_profile_original_sha256': report.meta['sha256'],
                                'heading_span': {'start': a, 'end': offsets[last - 1] + 1,
                                                 'text': report.text[a:offsets[last - 1] + 1]},
                                'status_reader_complete': True})
        verdict = re.search(r'\[(Resolved|Unresolved|Acknowledged)\]', report.text[a:offsets[last - 1] + 1])
        if verdict:
            set_status_claim(report, c, verdict, a, 'trail_of_bits_narrative_heading')
        candidates.append(c)
    return candidates
