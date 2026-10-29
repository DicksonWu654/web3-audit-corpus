"""Versioned conservative scope rules. Publisher names are never classification features."""
import hashlib
import json
from pathlib import Path
import re

VERSION = 'audit-types-v4'


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def obj(value):
    return json.loads(value) if isinstance(value, str) and value else value or {}


def words(value):
    # Split Solidity CamelCase names before matching function/scope vocabulary.
    value = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1 \2', str(value or ''))
    value = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', value).replace('_', ' ').replace('-', ' ')
    return re.sub(r'(?i)\bvesting\s+wallet\b', 'vesting', value)


PATTERNS = {
    'infrastructure': r'\b(?:bridg(?:e|es|ing)|cross.chain|light client|consensus|validator (?:client|node)|node (?:software|client|implementation)|blockchain client|execution client|consensus client|rollup|zero.knowledge|zk.?snark|zk.?stark|zk.?proof|zk.?circuit|cryptograph(?:y|ic)|signature scheme|elliptic curve|precompil(?:e|ed)|p2p network|tendermint|cometbft|ibc|prover|verifier circuit|hypercore|corewriter|genesis|ante handlers?|chain to halt|layer.?1 network|rippled)\b',
    'wallet_or_account': r'\b(?:wallet|smart account|account abstraction|erc.?4337|erc.?7579|erc.?7702|multi.party computation|mpc|multisig|multi.signature|passkey|session key|paymaster|entrypoint)\b',
    'nft_or_game': r'\b(?:nft|erc.?721|erc.?1155|non.fungible|soulbound|gamefi|gaming|game|marketplace|collectibles?)\b',
    'protocol': r'\b(?:vault|erc.?4626|liquidity|lending|borrowing|borrower|lender|collateral|liquidat(?:ion|or)|amm|dex|decentralized exchange|swap|staking|staked|restaking|yield|farming|farm|oracle|auction|perpetual|derivative|option|insurance|governance|dao|escrow|orderbook|order book|margin|rebalanc(?:e|ing)|cdp|stablecoin protocol|money market|rewards? (?:distributor|distribution|pool)|launchpad|crowdsale|crowdinvesting|token sale|settlement sale|settlementsale|multisend|multi send|auto renew|auto renewal|payment (?:processor|contract|system)|mass.transaction|rotating (?:credit|savings)|rosca|verify nonce|verifynonce|core writer)\b',
}
RX = {k: re.compile(v, re.I) for k, v in PATTERNS.items()}
TOKEN = re.compile(r'\b(?:erc.?20|bep.?20|spl token|token (?:contract|implementation)|(?:mint|burn|tax|vesting)(?:ing)?(?:.only)?|tokenomics)\b', re.I)
LIBRARY = re.compile(r'(?:^|/)(?:interfaces?|libraries|lib|utils|dependencies|openzeppelin)(?:/|$)|^(?:I[A-Z]\w*|Safe\w*|Ownable\w*|Context|Address|Enumerable\w*|Reentrancy\w*|Pausable\w*|AccessControl\w*|Initializable|Upgradeable\w*|ERC20(?:Burnable|Pausable|Permit|Upgradeable)?|IERC\w*)\.(?:sol|rs)$')
SCOPE = re.compile(r'(?im)^[ \t]*(?:\d+(?:\.\d+)*[.)]?[ \t]*)?(?:#{1,5}[ \t]*)?(?:audit scope|scope(?: of (?:the )?(?:audit|review|work))?|in.scope|contracts? (?:in scope|audited)|project (?:overview|summary)|system overview|executive summary|overview|about (?:the )?project|system description)[ \t]*[:|\n]')
BOILER = re.compile(r'(?i)(?:we (?:have|are|provide|offer)|our (?:team|audits|clients|services)|about (?:the auditor|hacken|certik|halborn|zellic)|(?:security|auditing) firm|(?:specializ|expertise|experience)\w* (?:in|with)|disclaimer|no guarantee|no warranties|not (?:an? )?endorsement)')


def local_text(root, doc):
    """Use source-pinned complete text first; only read existing local caches."""
    meta = obj(doc.get('metadata'))
    candidates = []
    for key in ('date_text_receipt', 'text_receipt'):
        receipt = meta.get(key) or {}
        if receipt.get('text_snapshot'):
            candidates.append((Path(root) / receipt['text_snapshot'], receipt.get('text_sha256')))
    sha = doc.get('sha256')
    if sha and re.fullmatch('[a-f0-9]{64}', sha):
        candidates += [(Path(root) / 'local-cache' / folder / (sha + '.txt'), None)
                       for folder in ('fulltext', 'date-text', 'text')]
    for path, expected in candidates:
        if not path.resolve().is_relative_to(Path(root).resolve() / 'local-cache') or not path.is_file():
            continue
        raw = path.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        if expected and actual != expected:
            continue
        text = raw.decode('utf-8', errors='replace')
        # Some inherited extracts encode physical line breaks literally.
        text = text.replace('\\n', '\n') if text.count('\\n') > text.count('\n') else text
        return text, dict(path=str(path.relative_to(root)), sha256=actual)
    return '', dict(status='text_unavailable')


def document_input(root, doc, finding_titles=()):
    meta = obj(doc.get('metadata'))
    text, receipt = local_text(root, doc)
    identity = meta.get('project_identity') or {}
    files = sorted(set(identity.get('scope_files') or identity.get('scope_assets') or []))
    # First pages and explicit scope/overview sections are evidence, not a
    # search across the report's generic threat checklists or recommendations.
    first = '\n'.join(text.split('\f')[:6])[:18000]
    # Publisher HTML sometimes appends an anchor '#' to headings. Strip only
    # that marker for section detection; retain the exact text hash above.
    section_text = re.sub(r'(?m)^(#{1,5}[^\n]+?)#+[ \t]*$', r'\1', text[:60000])
    section_text = re.sub(r'(?im)^(#{1,5}[ \t]+)introduction[ \t]*$', r'\1Project overview', section_text)
    sections = []
    for m in list(SCOPE.finditer(section_text))[:8]:
        chunk = section_text[m.end():m.end() + 2600]
        boundary = re.search(r'(?m)^[ \t]{0,5}#{1,5}[ \t]+', chunk)
        sections.append(chunk[:boundary.start()] if boundary else chunk)
    fallback = re.split(r'(?im)^[ \t#]*(?:critical|high|medium|low) severity\b|^[ \t#]*findings(?:\s+and\s+recommendations)?[ \t]*$', first)[0][:7000]
    informative = '\n'.join(line for line in ('\n'.join(sections) or fallback).splitlines()
                            if not BOILER.search(line))
    report_headings = re.findall(r'(?m)^#{2,5}[ \t]+([^\n]{8,160})', text[:120000])
    numbered_findings = re.findall(r'(?m)^[ \t]*(?:\[(?:[HMLICG]-?\d+)\]|(?:Issue[ \t]+)?[HMLICG]-\d+)[ \t:]+([^\n]{8,160})', text[:120000])
    return dict(document_id=doc['document_id'], public_url=doc.get('public_url'),
                title=doc.get('title'), project=doc.get('project'), filename=doc.get('filename'),
                scope_files=files, scope_text=informative[:18000], first_pages=first[:18000],
                finding_titles=sorted(set(t for t in list(finding_titles) + report_headings + numbered_findings if t))[:100],
                chains=obj(doc.get('chains')), languages=obj(doc.get('languages')), text_receipt=receipt)


def hits(text):
    text = re.sub(r'(?i)vesting\s*wallet', 'vesting', words(text))
    return {k: sorted(set(m[0].lower() for m in r.finditer(text)))[:12] for k, r in RX.items()}


def classify_document(doc):
    return classify_scope_v2(doc)


def classify_scope_v1(doc):
    title = ' '.join(str(doc.get(k) or '') for k in ('title', 'project', 'filename'))
    files = doc.get('scope_files') or []
    custom = [f for f in files if not LIBRARY.search(f)]
    # One category may have several signals; distinct categories are ambiguous.
    strong = hits(title + '\n' + '\n'.join(custom))
    scope = hits(doc.get('scope_text', ''))
    # A reference to a user's wallet is not an audit of wallet software.
    if not re.search(r'(?i)wallet (?:software|implementation|application|contract)|(?:smart|hardware|mobile|browser|crypto) wallet|multisig|multi.signature|smart account|account abstraction|erc.?4337|mpc|multi.party computation|paymaster|entrypoint|session key|passkey', doc.get('scope_text', '')):
        scope['wallet_or_account'] = []
    findings = hits('\n'.join(doc.get('finding_titles', [])))
    supported = {k for k in RX if strong[k] or scope[k]}
    scope_text = doc.get('scope_text', '')
    token_hint = bool(re.search(r'(?i)\b(?:erc.?20|bep.?20|spl token|fungible token|standard coin|token contract|vesting)\b', words(title + '\n' + scope_text)))
    # A project called "X Token" or an imported ERC20 alone never suffices.
    only_token = bool(re.search(r'(?i)\b(?:single|only|one)\s+(?:\w+\s+){0,2}token\s+contract|\btoken.only\b|\b(?:erc.?20|bep.?20|spl)\s+token\s+(?:contract|implementation)\b', doc.get('scope_text', '')))
    token_title = bool(re.search(r'(?i)\btoken\b|vesting|erc.?20|bep.?20', words(title)))
    single = len(custom) == 1
    token_files = bool(custom) and all(re.search(r'(?i)token|erc20|bep20|vesting', Path(f).stem) for f in custom)
    # Vesting/tax/burn contracts associated with a single token stay token scope.
    multiple_contracts = bool(re.search(r'(?i)\b(?:[2-9]|[1-9][0-9]+|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)\s+(?:smart\s+)?contracts?\b', scope_text))
    contract_language = not custom or all(re.search(r'\.(?:sol|rs|move|cairo)$', f) for f in custom)
    bounded = (single and (token_title or token_files)) or (only_token and len(custom) <= 1)
    if token_hint and not supported and not any(findings.values()) and bounded and not multiple_contracts and contract_language:
        return 'token_only', 'bounded_token_scope', dict(custom_scope_files=custom, token_explicit=only_token)
    if len(supported) == 1:
        label = next(iter(supported))
        return label, 'explicit_functional_scope', dict(signals=strong[label] + scope[label])
    # Protocol components within infrastructure/wallet/game scopes are normal;
    # require explicit primary title/file evidence before choosing the parent.
    primary = [k for k in ('infrastructure', 'wallet_or_account', 'nft_or_game') if strong[k]]
    if len(primary) == 1 and supported <= {primary[0], 'protocol'}:
        return primary[0], 'primary_scope_with_application_components', dict(signals=strong[primary[0]])
    return 'other_or_unclear', 'conflicting_scope_signals' if supported else 'insufficient_scope_evidence', dict(candidate_types=sorted(supported), custom_scope_files=custom[:30])


def classify_scope_v2(doc):
    """Audited behavior precedes asset representation, project branding and helpers.

    Rules were refined on the explicitly reviewed sample. Evaluation reports this
    as in-sample; it is not an independent human or held-out accuracy estimate.
    """
    title = words(' '.join(str(doc.get(k) or '') for k in ('title', 'filename')))
    project = words(doc.get('project'))
    files = [f for f in doc.get('scope_files', []) if not LIBRARY.search(f)]
    names = words('\n'.join(files))
    first_lines = [line for line in doc.get('first_pages', '').splitlines() if not BOILER.search(line)]
    body = words(doc.get('scope_text', '') + '\n' + '\n'.join(first_lines))
    findings = words('\n'.join(doc.get('finding_titles', [])))
    text = title + '\n' + project + '\n' + names + '\n' + body
    text = re.sub(r'(?i)\bgame theory\b|\bvesting\s*wallet\b', 'vesting', text)
    evidence = dict(custom_scope_files=files[:30], chains=doc.get('chains') or [], languages=doc.get('languages') or [])

    def found(pattern, source=text):
        m = re.search(pattern, source, re.I)
        return m[0] if m else None

    finance = r'\b(?:vaults?|lending|loans?|borrow(?:ing|er)?|collateral|liquidat(?:ion|e)|stake|staking|staked|restaking|yield|liquidity|swaps?|exchanges?|margin|auction|governance|voting|bonding curve|perpetual|insurance|crowdsale|crowdinvesting|campaign|erc.?4626|erc.?7540|fund administration|credit|repay(?:ment)?|farm(?:ing)?|auto renewal|multisend|multi send|deleverag(?:ing|e)|tranch(?:e|es)|price.feed|oracles?|escrow)\b'
    finance_names = [f for f in files if found(finance, words(f))]
    finance_title = found(finance, title)
    finance_project = found(finance, project)
    finance_body = found(r'\b(?:lending protocol|liquid staking|staking protocol|collateralized|credit (?:vault|delegation)|investment strateg(?:y|ies)|investment platform|fund administration|(?:swap|exchange|trading|vault|lending|staking) (?:contract|protocol|system|platform)|token distribution platform|repaying loans|bonding curve|automated yield|capital deployment|money market|vesting factory|vesting manager|voting power|pre.?sale|withdrawal queue|stablecoin (?:and|system)|decentralized exchange|dollar.cost averaging|payment (?:system|processor|contract))\b', body)
    title_token = found(r'\btoken\b|erc.?20|bep.?20', title + '\n' + project)
    finance_signal = finance_title or (finance_project if not title_token else None) or (finance_names and finance_names[0]) or finance_body

    infra_pattern = r'\b(?:bridge|bridges|bridging|cross.chain|crosschain|consensus|blockchain client|node software|execution client|consensus client|rollup|zk.?rollup|zk.?evm|zk.?vm|zero.knowledge|circuit|cryptograph(?:ic|y)|signature scheme|elliptic curve|precompile|tendermint|cometbft|hyperlane|rippled|snarkos|openvm|corewriter|hypercore)\b'
    infra_title = found(infra_pattern, title)
    infra_project = found(infra_pattern, project)
    infra_names = [f for f in files if found(infra_pattern, words(f))]
    infra_body = found(r'\b(?:cross.chain (?:messages?|messaging|communication|tokens?|transfers?|swap)|bridge contracts?|bridg(?:ed|ing) (?:bitcoin|price information)|consensus (?:protocol|mechanism|algorithm)|blockchain client|appchain modules|cosmos.?sdk|go.ethereum|zero.knowledge (?:proof|circuit|rollup)|elliptic curve|signature (?:scheme|generation|verification routines)|cryptographic (?:review|library|functions)|block propagation|chain (?:to halt|halts?)|ante handlers?|p2p gossip|layer.?1 network|zk.?vm|zk.?evm)\b', body)
    infra_signal = infra_title or infra_project or (infra_names and infra_names[0]) or infra_body
    # Genesis, general signing and a token named BridgeERC20 are insufficient.
    basic_bridge_token = bool(files) and all(found(r'(?:bridge.?erc.?20|token|safemath|erc20)', words(Path(f).stem)) for f in files)
    if basic_bridge_token and not found(r'cross.chain|gateway|messenger|relay|bridge (?:protocol|contract|system)', body):
        infra_signal = None

    wallet_pattern = r'\b(?:wallet|smart account|account abstraction|erc.?4337|erc.?7579|erc.?7702|mpc|multisig|multi.signature|paymaster|session keys?|passkey)\b'
    wallet_title = found(wallet_pattern, title)
    wallet_names = [f for f in files if found(r'wallet[^\n]*\.sol|smart.?account|multisig|paymaster|ownership.?module|account.?logic|account.?proxy|account.?creator', words(f))]
    wallet_body = found(r'\b(?:smart.contract wallets?|smart wallets?|wallet (?:application|software|extension)|account abstraction|erc.?4337|eip.?3074|non.custodial.{0,30}wallet|programmable multisig|multi.signature wallet|multi signature wallet|paymaster|session keys?|wallet smart contract|(?:android|mobile|browser|mpc) wallet)\b', body)
    wallet_signal = wallet_title or (wallet_names and wallet_names[0]) or wallet_body
    if found(r'wallet (?:and|android)|wallet\(', title):
        wallet_signal = wallet_title
    wallet_token = found(r'\b(?:supply.?controller|wallet.?token|wallet tokens)\b', body + '\n' + findings)
    if wallet_token and files and all(found(r'wallet\.sol', f) for f in files):
        wallet_signal = None

    nft_title = found(r'\b(?:nft|erc.?721|erc.?1155|soulbound|gaming|games?|collectibles?)\b', title)
    nft_names = [f for f in files if found(r'nft|erc.?721|erc.?1155|candy.?machine', words(f))]
    nft_body = found(r'\b(?:non.fungible|nft marketplace|nft (?:minting|collection|contract)|video game|betting|prize (?:game|pool)|game (?:round|contract)|erc.?721|erc.?1155|soulbound)\b', body)
    nft_project = found(r'\b(?:nft|gaming|games?|collectibles?)\b', project)
    nft_signal = nft_title or (nft_names and nft_names[0]) or nft_body or nft_project
    if found(r'\b(?:winner|prize)\b', names) and found(r'\b(?:buy.?package|set.?winner|claim.?prize)\b', names):
        nft_signal = 'prize_game_scope'

    # Explicit parent functions determine specialty. Specialized titles can
    # include ordinary finance, but separately named parent scopes abstain.
    explicit_parents = [kind for kind, signal in (('infrastructure', infra_title), ('wallet_or_account', wallet_title)) if signal]
    if len(explicit_parents) > 1:
        return 'other_or_unclear', 'several_explicit_parent_scopes', evidence
    if wallet_title and nft_title and found(r'\band\b', title):
        return 'other_or_unclear', 'several_explicit_parent_scopes', evidence
    if infra_title and not basic_bridge_token:
        # A BridgeOracle price adapter does not transport data or assets.
        if not found(r'bridge\s+oracle|bridgeoracle', title):
            return 'infrastructure', 'explicit_infrastructure_target', dict(evidence, signal=infra_title)
    if wallet_title and not wallet_token:
        if not (finance_title and found(r'swap|aggregator|margin|vault|staking|finance', title)):
            if found(r'fasset', title) and found(r'smart account', title):
                return 'other_or_unclear', 'several_explicit_parent_scopes', evidence
            return 'wallet_or_account', 'explicit_wallet_target', dict(evidence, signal=wallet_title)
    if infra_body and found(r'cosmos.?sdk|consensus|node|cryptograph|circuit|appchain|p2p|go.ethereum', str(infra_body)):
        return 'infrastructure', 'client_or_cryptographic_implementation', dict(evidence, signal=infra_body)
    if infra_names and len(infra_names) >= 2 and not wallet_title:
        return 'infrastructure', 'multiple_transport_components', dict(evidence, signal=infra_names[:6])
    if len(finance_names) >= 2 and not infra_title:
        return 'protocol', 'multiple_application_scope_components', dict(evidence, signal=finance_names[:6])
    if wallet_signal and not wallet_token:
        if not finance_signal or (wallet_names and len(wallet_names) > len(finance_names)):
            if not infra_signal or len(wallet_names) >= len(infra_names):
                return 'wallet_or_account', 'account_implementation_scope', dict(evidence, signal=wallet_signal)
    if infra_signal:
        if not finance_signal or infra_names or found(r'consensus|node|cryptograph|circuit|zkvm|zkevm|rippled|appchain|p2p', str(infra_signal)):
            return 'infrastructure', 'infrastructure_implementation_scope', dict(evidence, signal=infra_signal)
    if finance_signal:
        # NFT issuance/marketplace audits can include an auction; financial
        # collateral, lending and yield take precedence over position tokens.
        financial_behavior = found(r'lend|borrow|collateral|liquidat|staking|staked|yield|vault|farm|margin|credit|liquidity|swap|allocation|capital deployment|distribution platform|bonding curve|stablecoin', title + '\n' + names + '\n' + str(finance_body or ''))
        if not nft_signal or financial_behavior:
            return 'protocol', 'application_behavior_scope', dict(evidence, signal=finance_signal)
    if nft_signal:
        return 'nft_or_game', 'explicit_nft_or_game_behavior', dict(evidence, signal=nft_signal)
    # Reuse the bounded-token guard after the parent behavior checks. Additional
    # filenames in source scope prevent incomplete metadata from proving one.
    label, basis, detail = classify_scope_v1(doc)
    if label == 'token_only':
        language_values = doc.get('languages') or []
        if isinstance(language_values, str):
            language_values = [language_values]
        if isinstance(language_values, list) and language_values:
            allowed = {'solidity', 'vyper', 'rust', 'move', 'cairo', 'scrypt', 'func', 'tact', 'michelson', 'haskell'}
            if not any(str(value).lower() in allowed for value in language_values):
                return 'other_or_unclear', 'language_does_not_establish_token_contract_scope', evidence
        source_files = set(re.findall(r'\b[A-Za-z][A-Za-z0-9_]*\.sol\b', body))
        custom_source = [f for f in source_files if not LIBRARY.search(f)]
        if len(custom_source) > max(1, len(files)):
            return 'other_or_unclear', 'source_scope_contains_additional_contracts', dict(evidence, source_files=sorted(custom_source))
        return label, basis, detail
    return 'other_or_unclear', 'insufficient_or_conflicting_scope_evidence', evidence


def api_input(record):
    return {k: record.get(k) for k in ('report_link', 'audit_name', 'client_name', 'audit_type', 'audited_contracts', 'scope_parameters', 'scope_signals', 'labels', 'languages', 'platforms')}


def classify_api(api):
    scope = api.get('scope_parameters') or {}
    assets = scope.get('assets_audited') or api.get('audited_contracts') or []
    if not all(isinstance(a, str) for a in assets):
        assets = [canonical(a) for a in assets]
    title = str(api.get('audit_name') or '')
    doc = dict(title=title, project='', filename='', scope_files=assets,
               scope_text='\n'.join(assets) + '\n' + ' '.join(api.get('labels') or []), finding_titles=[])
    label, basis, details = classify_document(doc)
    # Publisher category fields are explicit scope metadata, unlike a keyword
    # embedded in report prose. Never promote the unvalidated scope_class_hint.
    typed = hits('\n'.join(api.get('labels') or []))
    category = None
    if typed['infrastructure'] and not typed['wallet_or_account']:
        category = 'infrastructure'
    elif typed['wallet_or_account'] and not typed['infrastructure']:
        category = 'wallet_or_account'
    elif typed['protocol'] and not typed['infrastructure'] and not typed['wallet_or_account']:
        category = 'protocol'
    elif typed['nft_or_game'] and not any(typed[k] for k in ('protocol', 'infrastructure', 'wallet_or_account')):
        category = 'nft_or_game'
    if category:
        if label in {'other_or_unclear', category}:
            return category, 'hacken_api_explicit_scope_categories', dict(signals=typed[category], assets_audited=assets,
                                                                         chains=api.get('platforms') or [], languages=api.get('languages') or [])
        return 'other_or_unclear', 'hacken_api_categories_conflict_with_assets', dict(category=category, asset_type=label)
    # Unvalidated API scope_class_hint is recorded, never taken as gold truth.
    if label == 'other_or_unclear':
        return label, 'hacken_api_' + basis, details
    return label, 'hacken_api_' + basis, details


def classify_engagement(engagement, documents, apis=()):
    decisions = [dict(document_id=d['document_id'], audit_type=t, basis=b, evidence=e)
                 for d in documents for t, b, e in [classify_document(d)]]
    decisions += [dict(source_url=a['report_link'], audit_type=t, basis=b, evidence=e)
                  for a in apis for t, b, e in [classify_api(a)]]
    known = {d['audit_type'] for d in decisions if d['audit_type'] != 'other_or_unclear'}
    unknown_docs = [d for d in decisions if d['audit_type'] == 'other_or_unclear' and d.get('document_id')]
    if len(known) == 1 and not unknown_docs:
        label = next(iter(known)); basis = 'consistent_scope_evidence'
    else:
        label = 'other_or_unclear'
        basis = 'conflicting_or_incomplete_report_scopes' if known else 'insufficient_scope_evidence'
    inputs = dict(project=engagement.get('project'), publisher_id=engagement['publisher_id'], documents=documents, api=list(apis))
    return dict(engagement_id=engagement['engagement_id'], publisher_id=engagement['publisher_id'], project=engagement.get('project'),
                identity_status=engagement.get('identity_status'), audit_type=label,
                audit_type_basis=VERSION + ':' + basis, input_sha256=digest(inputs), decisions=decisions,
                public_urls=sorted({d['public_url'] for d in documents if d.get('public_url')} | {a['report_link'] for a in apis}),
                inputs=inputs)
