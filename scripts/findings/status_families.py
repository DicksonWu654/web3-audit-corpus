"""Build-time generic status families, derived from the non-holdout census.

Runtime consumers read these from status_map.json/json, keeping the resolver
standalone. Order is policy: qualifications and negations precede fix claims.
"""

ACTION = r'(?:fix(?:ed)?|resolv(?:e|ed)|address(?:ed)?|remediat(?:e|ed)|mitigat(?:e|ed)|patch(?:ed)?|implement(?:ed)?)'
DONE = r'(?:fixed|resolved|solved|addressed|remediated|mitigated|patched|corrected)'
QUALIFIER = (r'\b(?:not|never|no longer)\s+(?:\w+\s+){0,2}' + DONE + r'\b|'
             r'\b(?:should|could|can|may|might|must|will|would|to|being|yet to)\s+(?:be\s+)?(?:\w+\s+){0,2}' + DONE + r'\b|'
             r'\b(?:partially|partly|mostly|largely|partial)\s+(?:verified|fixed|resolved|solved|addressed|remediated|mitigated)\b|'
             r'\b(?:unverified|not (?:verified|retested))\b')


def rule(name, normalized, regex, rationale, examples, exclude=None):
    value = dict(id=name, normalized=normalized, regex=regex,
                 rationale=rationale, corpus_examples=examples)
    if exclude:
        value['exclude_regex'] = exclude
    return value


GENERIC_FALLBACK = dict(
    basis='Non-holdout status_original census; see METHODS.md#severity-and-status-crosswalks.',
    precedence='Resolved publisher/era labels win. Review placeholders and lookup misses may use these ordered families. Bare Closed/Verified/Invalid remain publisher-specific.',
    ambiguous_regex=r'\b(?:fixed|resolved|addressed)\s*/\s*acknowledged\b|\b(?:fixed|resolved|addressed)\b[^.;]{0,120}[.;][^.;]{0,60}\backnowledged\b',
    rules=[
        rule('partial_remediation', 'partially_fixed',
             r'\b(?:partially|partly|mostly|largely|almost all|partial)\s+(?:fixed|resolved|solved|addressed|remediated|mitigated|implemented)\b|\bprimary concern addressed\b',
             'The source explicitly qualifies completed remediation as partial.',
             ['LARGELY RESOLVED', 'Confirmed; Partially fixed, by adding claimed_amount, current_slot to increase the difficulty of random'],
             r'\b(?:not|never|will|would|could|should|can|may|might|to)\s+(?:be\s+)?(?:partially|partly|mostly|largely|partial)\b'),
        rule('incomplete_remediation', 'unresolved',
             r'^(?:not|not yet)\s+(?:been\s+)?'+DONE+r'\b|\b(?:is|was|were|has been|have been|remains?)\s+not\s+(?:yet\s+)?'+DONE+r'\b',
             'A statement that repair has not occurred does not establish a decision to accept the risk.',
             ['Not fixed', 'Not-fixed in Version 5', 'The issue was not resolved.']),
        rule('no_fix_decision', 'acknowledged',
             r'\b(?:(?:will|would|shall)\s+not\s+(?:be\s+)?'+ACTION+r'|won[\x27]?t\s+(?:be\s+)?'+ACTION+r'|not\s+(?:going\s+to\s+|to\s+|be\s+)?'+ACTION+r'|no\s+fix(?:ed)?)\b|'
             r'\b(?:decided|chose|choose)\s+(?:to\s+)?not\s+to\s+'+ACTION+r'\b|'
             r'\b(?:leave|keep|left|kept)\b.{0,60}\bas is\b|\b(?:accept(?:ed)? (?:the )?risk|risk accepted)\b',
             'An explicit no-fix or risk-acceptance assertion records acknowledgement, not completed repair.',
             ['decided not to patch', 'The Skip team has decided not to address this issue', 'not fix.']),
        rule('pending_remediation', 'unresolved',
             r'\b(?:not yet|yet to be|to be|will be|being)\s+(?:fully\s+)?'+DONE+r'\b|'
             r'\b(?:will|plan(?:s|ned)? to)\s+(?:fix|resolve|address|remediate|mitigate)\b|'
             r'^(?:resolution in progress|not done,? yet|still vulnerable|future release|temporarily unresolved|暂未修复)(?:\b|[.;:]|$)',
             'Planned, in-progress or explicitly incomplete work does not establish a completed fix.',
             ['Resolution in Progress', 'Not done, yet', 'To be addressed in future release', 'FUTURE RELEASE']),
        rule('completed_label', 'fixed',
             r'^(?:'+DONE+r'|implemented(?: a fix)?|fix implemented|externally resolved)(?:\s*(?:$|[.;:,!–—-])|\s+(?:in|on|at|by|via|with|for|to|as|before|after|code|using|following)\b)',
             'A completed-remediation label may include a version, commit, PR, client or explanatory suffix.',
             ['FIXED    – in commit 28a4153', 'Fixed — 2543fb2', 'Mitigated', 'Externally Resolved'], QUALIFIER),
        rule('completed_assertion', 'fixed',
             r'\b(?:has been|have been|had been|has|have|was|were|is|are)\s+(?:(?:already|properly|fully|promptly)\s+)?(?:(?:confirmed|conformed|acknowledged)\s+and\s+)?'+DONE+r'\b|'
             r'\b'+DONE+r'\s+(?:the|this)\s+(?:issue|finding|bug)\b|'
             r'\b'+DONE+r'\s+(?:in|on|at|by|via|with)\s+\S|\bimplemented a fix\b',
             'A source status sentence explicitly asserts completed correction or names its implementation.',
             ['This has been properly addressed.', 'Issue addressed by implementing method 1 in commit:#3a4239f .', 'The issues has been fixed.', 'Introduced in commit 5158cb. Fixed in commit 13b767.'], QUALIFIER),
        rule('implemented_recommendation', 'fixed',
             r'\b(?:our (?:second )?recommendations?|a (?:check|fix))\s+(?:has been|have been|was|were)\s+(?:implemented|added)\b|'
             r'\b(?:code change|mitigation of .{1,100})\s+(?:is |was )?verified\b|'
             r'^removed\s*[–—-]?\s*(?:at|in|by|via)\s+(?:commit\s+)?[a-f0-9]{6,64}\b|'
             r'^реализовано в\s+https?://|^已修复$',
             'The status explicitly records an implemented recommendation/check or verified code change.',
             ['Our recommendations were implemented', 'A check was added in https://github.com/api3dao/api3-dao/pull/277', 'Code change verified in version 1.1.1 -rc1', '已修复', 'REMOVED     – at 18474eabd96a6dda2abb39e90493d95e2cb5da9a'],
             r'\b(?:not|never|should|could|can|may|might|will|would)\s+(?:be\s+)?(?:implemented|added|verified)\b'),
        rule('acknowledgement', 'acknowledged',
             r'\b(?:acknowledged|confirmed|confirms)\b|^(?:known issue|ignored|已确认|已忽略)(?:$|[.;:,，])|'
             r'\b(?:team|client|project team)\s+(?:is|are)\s+aware\b|\b(?:expected and accepted|this is intended|this is a design choice)\b',
             'Confirmation, acknowledgement or an explicit ignored disposition alone does not assert repair.',
             ['Potential optimizations acknowledged, no actions would be taken to reduce code bloat.', 'The issue has confirmed by the team.', 'Confirmed; The project team will use multi-signature wallet for Owner.', '已确认'],
             r'\b(?:not|never|un)\s*(?:confirmed|acknowledged)\b|\b(?:could|should|can|may|might|must|to)\s+(?:be\s+)?(?:confirmed|acknowledged)\b'),
        rule('unresolved_label', 'unresolved',
             r'^(?:unresolved|unaddressed|open|pending|reported|new|in progress|externally reported)(?:$|[.;:,!]|\s+(?:in|on|at|by|via)\b)',
             'A standalone open/pending label records outstanding remediation.',
             ['Externally Reported']),
    ])
