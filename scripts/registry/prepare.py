#!/usr/bin/env python3
"""Build initial candidates from frozen discovery plus explicit curated additions.

Discovery is only a lead. collect.py verifies publishers; build.py audits counts.
"""
import json,re,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
D=ROOT/'data/registry'
D.mkdir(parents=True,exist_ok=True)

def slug(s):return re.sub('[^a-z0-9]+','-',s.lower()).strip('-')

def repo_url(s):
 m=re.match(r'https://github.com/([^/]+/[^/#?]+)',s)
 return m.group(1) if m else ''

def main():
 freeze=D/'discovery.json'
 if freeze.exists():discovery=json.loads(freeze.read_text())
 else:
  discovery={}
  for k,f,u in [('nazgul','nazgul.md','https://github.com/0xNazgul/Blockchain-Security-Audit-List'),('solo-list','solo-list.md','https://github.com/chinmay-farkya/solo-audit-reports'),('defillama','defillama-protocols.json','https://api.llama.fi/protocols')]:
   b=(Path('local-cache/tmp/firm-registry')/f).read_bytes();discovery[k]={'url':u,'access_date':'2026-10-20','sha256':hashlib.sha256(b).hexdigest(),'text':b.decode()}
  for f in sorted(Path('local-cache/tmp/firm-registry').glob('search-*.json')):
   x=json.loads(f.read_text())
   if x.get('items'):
    discovery[f.stem]={'url':'https://api.github.com/search/repositories','access_date':'2026-10-20','items':[{k:v.get(k) for k in ['full_name','html_url','description','homepage','stargazers_count','fork','default_branch']} for v in x['items']]}
  freeze.write_text(json.dumps(discovery,ensure_ascii=False,indent=2)+'\n')
 rows={};byrepo={}
 def add(name,website='',reports='',kind='firm',aliases='',notes='',source='curated live-search lead',**kw):
  rp=repo_url(reports)
  key=byrepo.get(rp.lower()) if rp else None
  key=key or slug(name)
  if key not in rows:rows[key]={'firm_id':key,'name':name,'aliases':aliases,'website':website,'kind':kind,'repos':[],'status':'unknown','notes':notes,'discovery_sources':[source]}
  r=rows[key]
  if rp and rp.split('/')[1] not in ('repositories',):
   if rp.lower() not in [s.lower() for s in r['repos']]:r['repos'].append(rp)
   r['github_reports_url']=reports
   byrepo[rp.lower()]=key
  elif reports:
   field='github_reports_url' if reports.startswith('https://github.com/') else 'website_reports_url'
   r[field]=reports
  if website:r['website']=website
  if source not in r['discovery_sources']:r['discovery_sources'].append(source)
  r.update(kw)
  return r
 text=discovery['nazgul']['text'];solo=False
 for line in text.splitlines():
  if line.startswith('## Solo'):solo=True
  if not line.startswith('| ['):continue
  links=re.findall(r'\[([^]]+)\]\(([^)]+)\)',line)
  if not links:continue
  name,web=links[0]
  reports=links[1][1] if len(links)>1 else (web if 'github.com' in web else '')
  add(name,web,reports,'solo' if solo else 'firm',source=discovery['nazgul']['url'])
 for line in discovery['solo-list']['text'].splitlines():
  m=re.match(r'\d+\. (.*?) - (https://github.com/\S+)',line)
  if m:add(m[1],m[2],m[2],'solo',source=discovery['solo-list']['url'])
 # Explicit publisher leads. URLs are validated, not accepted on name alone.
 firms='''
Accretion|accretion-xyz/audit-reports|https://accretion.xyz
Adevar Labs|AdevarLabs/audit-reports|https://adevarlabs.com
AstraSec|astrasecai/audit-reports|https://astrasec.ai
AuditOne|auditone/audit-reports|https://auditone.io
AuditBase||https://www.auditbase.com
AuditAce|Audit-Ace/Audits-Smart-Contracts|https://audit-ace.com
AuditRate|AuditRateTech/Smart-Contract-Audits|https://auditrate.tech
Blaize Security|blaize-security/blaize-security-audits|https://blaize.tech
BitsLab||https://bitslab.xyz
Code4rena||https://code4rena.com
Cantina||https://cantina.xyz
Code4rena Zenith||https://www.zenith.security
Cyberscope|cyberscope-io/audits|https://www.cyberscope.io
Coinscope|coinscope-co/audits|https://www.coinscope.co
ContractWolf|ContractWolf/smart-contract-audits|https://contractwolf.io
ContractChecker|ContractChecker/audits|https://contractchecker.io
CFG Ninja|CFG-NINJA/audits|https://cfg.ninja
CODESPECT|CODESPECT-security/audit-reports|https://codespect.net
Cairo Security Clan|Cairo-Security-Clan/Audit-Portfolio|https://cairosecurityclan.com
DefiMoon|DefiMoonOrg/Audits|https://defimoon.org
Dapp.org|dapphub/dapp-audits|https://dapp.org
Enigma Dark|EnigmaDark/audits|https://enigmadark.com
Electisec|electisec/Reports|https://electisec.com
EtherAuthority|EtherAuthority/Audit|https://etherauthority.io
Fairyproof|fairyproof/Reports|https://fairyproof.com
FYEO|fyeo-io/public-audit-reports|https://www.fyeo.io
GoSec Labs|GoSec-Labs/Audit-Reports|https://goseclabs.com
HAECHI Audit|HAECHI-LABS/audits|https://audit.haechi.io
Hashlock|Hashlock/audits|https://hashlock.com
Immunefi|immunefi-team/Past-Audit-Competitions|https://immunefi.com
Hats Finance||https://hats.finance
HackenProof||https://hackenproof.com
HackerOne||https://www.hackerone.com
Bugcrowd||https://www.bugcrowd.com
Hacken||https://hacken.io
KirinSec|KirinSec/SecurityAudit|https://kirinsec.com
LianGoSec|LianGoSec/Reports|https://liangosec.com
Line1|Line1-io/Security-Audits|https://line1.io
Monethic|Monethic/audits|https://monethic.io
MoveBit|movebit/Sampled-Audit-Reports|https://movebit.xyz
ScaleBit|scalebit/Sampled-Audit-Reports|https://scalebit.xyz
TonBit|TonBitSec/Sampled-Audit-Reports|https://tonbit.xyz
Neodyme|neodyme-labs/audits|https://neodyme.io
Offside Labs|offside-labs/security-reports|https://offside.io
Obsidian Audits|ObsidianAudits/audits|https://obsidianaudits.com
Optimum|optimumsec/security-audits|https://optimumsec.xyz
Phage Security|phage-security/audits|https://phagesecurity.com
Recon|Recon-Fuzz/audits|https://getrecon.xyz
Red4Sec|Red4Sec/Reports|https://red4sec.com
Robust|robust-app/audits|https://robust.net
Salus|salusec/Salus-audit|https://salusec.io
Sentnl|sentnl/audits|https://sentnl.io
Shred Security|Shred-Security/audits|https://www.shredsecurity.io
SRLabs|srlabs/audit-reports|https://srlabs.de
SpyWolf|SpyWolfNetwork/Smart_Contract_Audits|https://spywolf.co
Safe Edges|Safe-Edges/Audit-Portfolio|https://safeedges.in
Softstack|softstack/Smart-Contract-Security-Audits|https://softstack.io
SourceHat||https://sourcehat.com
Tenset Security|tenset-security/audits|https://www.tensetsecurity.com
Torii Security|Torii-Security/audits|https://torii.security
Valix|valixconsulting/audit-reports|https://valix.io
Valar Solutions|valar-solutions/valar-solutions-audit-reports|https://valar.solutions
Winter Solutions|winter-sols/Smart-Contract-Security-Audits|https://www.winter-solutions.com
Hack-a-Chain|hack-a-chain/security-audits|https://hackachain.com
White Hat DAO|WhiteHatDAO/Smart-Contract-Security-Audits-by-White-Hat-DAO|https://whitehatdao.com
Kudelski Security||https://kudelskisecurity.com
NCC Group||https://www.nccgroup.com
Quarkslab||https://quarkslab.com
Cure53||https://cure53.de
X41 D-Sec||https://x41-dsec.de
RedGuild|redguild/audits|https://theredguild.org
Secureum||https://secureum.xyz
Ambit||https://ambitlabs.io
SakaSec|SakaSecurity/SakaSecurity-Audit-Reports|https://sakasec.com
SecureDApp||https://securedapp.io
SolidityScan||https://solidityscan.com
Sayfer||https://sayfer.io
BlockAudit|Block-Audit-Report/Audits|https://blockaudit.report
AuditBlock|AuditBlock/Audit-Reports|https://auditblock.io
AfterDark Labs|afterdarklabs/audit-reports|https://afterdarklabs.io
KubixSquare|KubixSquare/AuditReports|https://kubixsquare.com
DetecBox|Detectbox/audit-reports|https://detectbox.io
BCFG Audit|BCFG-Audit/Smart_Contract_Security_Audits|https://bcfgaudit.com
0xSafe|0xsafe/smart-contract-audits|https://0xsafe.io
Sublime Security|SublimeGroupSecurity/security_audits|https://sublimesecurity.io
Gecko Security|Gecko-Security/audits|https://gecko.security
Veracity Security|veracity-security/audits|https://veracitysecurity.com
Refious Security|refious-security/audits|https://refious.xyz
DP Security|DP-Security/audits|https://dp-security.org
Elevate Software|Ethereal-Labs-Development/smart-contract-audits|https://elevatesoftware.dev
'''
 for line in firms.strip().splitlines():
  name,rp,web=line.split('|');add(name,web,'https://github.com/'+rp if rp else '')
 solos='''
0x52|IAm0x52/audit-portfolio
Hans|HansIEA/security-portfolio
Kann|Kann-Audits/Kann-Audits
Naman|namx05/audits
0xSimao|0xsimao/audits
0xVolodya|0xVolodya/audits
0xRajkumar|0xRajkumar/audits
Al-Qa'qa'|Al-Qa-qa/audits
Zigtur|zigtur/audits
Zaskoh|zaskoh/audits
Juancito|juancito-dev/audits
0xEVom|0xEVom/audits
0xCuriousApple|0xcuriousapple/curiousapple-audits
JMariadlcs|JMariadlcs/audits
0xMahdiRostami|0xmahdirostami/audits
Oot2k|Oot2k/AuditPortfolio
MrPotatoMagic|mrpotatomagic/audit-portfolio
CarrotSmuggler|carrotsmuggler/carotsmuggler-audit-portfolio
0xDamian|0xDamian/audit-portfolio
Lodelux|lodelux/audit-portfolio
0xRiazaka|0xriazaka/Audit-Portfolio
Faris|farismln/audit-portfolio
Kadenzipfel|kadenzipfel/audit-portfolio
0xRizwan|0xRizwan/Audit-Portfolio
Smacaud|Smacaud/Audits-portfolio
Vladimir Lavrenenko|vlavrenenko-ethers/audits-portfolio
Konstantin Velev|konstantinvelev/audit-portfolio
T1MOH|T1MOH593/audits
0x23r0|0x23r0/audits
Draiakoo|Draiakoo/AuditReports
Zaryab|zaryab2000/Smart-Contracts_Audit_Reports
0xNirlin|0xnirlin/Audit-Reports-
10amBear|10ambear/audit-reports
Leeftk|leeftk/audit-reports
0xJuaan|0xjuaan/audits
TradMod|TradMod/Security-Audits
JCsec|jcsec-security/smart-contract-audits
Daniel VF|danielvf/audits
cmichel|cmichel/audits
Dacian|devdacian/audits
Hickuphh3|hickuphh3/audits
Riley Holterhus|RileyHolterhus/audits
0xLeastwood|0xleastwood/audits
0xSanson|0xSanson/audits
0xStalin|0xStalin-eth/audits
0xPsuedoPandit|0xPsuedoPandit/audits
0xDjango|0xDjango/audits
0xImmeas|0ximmeas/audits
0xRobocop|0xRobocop/audits
Picodes|Picodes/audits
ChaseTheLight|ChaseTheLight01/audits
Trust|Trust1995/Trust
Mikhail|88Mikhail88/audits
'''
 for line in solos.strip().splitlines():
  name,rp=line.split('|');add(name,'https://github.com/'+rp.split('/')[0],'https://github.com/'+rp,'solo')
 # Existing-source names are discovery leads, not publishers in their own right.
 seeds=json.loads((ROOT/'extracted/audit_analysis/exports/source_registry.json').read_text())
 for s in seeds:
  if s['source'] in ['anza-xyz','sui-foundation','nearbuilders','monethic']:continue
  if not s['record_counts']['reports']:continue
  for u in s.get('source_urls',[]):
   rp=repo_url(u)
   if rp and ('github.com' in u) and s['source'] not in ('gcf3711/audit-report-archive','shenyimings/FORGE-Artifacts','code4rena'):
    if rp.lower() not in byrepo:add(s['source'],'','https://github.com/'+rp,source='extracted/audit_analysis/exports/source_registry.json')
    break
 # Merge known aliases/rebrands and subsidiary programs, preserving source leads.
 merges={'chainsulting':'softstack','solidity-finance':'sourcehat','yaudit':'electisec','yacademy':'electisec','guardian-solidity-lab':'guardianaudits','guardian-audits':'guardianaudits','chain-safe':'chainsafe','chain-security':'chainsecurity','pessemistic':'pessimistic','bail-security':'bailsec','jakub-wojciechowski':'kudelski-security','solidityscan':'credshields','blaize':'blaize-security'}
 for old,new in merges.items():
  if old not in rows:continue
  a=rows.pop(old)
  if new not in rows:a['firm_id']=new;rows[new]=a;continue
  b=rows[new];b['aliases']=';'.join(filter(None,[b.get('aliases',''),a['name'],a.get('aliases','')]))
  for rp in a['repos']:
   if rp.lower() not in [x.lower() for x in b['repos']]:b['repos'].append(rp)
  b['discovery_sources']+=a['discovery_sources']
 # Exclude a training community, not a report publisher.
 rows.pop('secureum',None)
 for r in rows.values():
  r['discovery_sources']=sorted(set(r['discovery_sources']))
  if r['name'] in ['Spearbit','Pashov Audit Group','Recon','Cairo Security Clan','Obsidian Audits','Kann']:r['kind']='collective'
  if r['name'] in ['Code4rena','Cantina','Sherlock','Hats Finance']:r['kind']='contest_platform'
  if r['name'] in ['Immunefi','HackenProof','HackerOne','Bugcrowd']:r['kind']='bug_bounty_platform'
 curation=json.loads((ROOT/'scripts/registry/curation.json').read_text())
 for old,new in curation['merge'].items():
  if old not in rows:continue
  a=rows.pop(old);b=rows[new]
  b['aliases']=';'.join(filter(None,[b.get('aliases',''),a['name'],a.get('aliases','')]))
  b['repos']=list(dict.fromkeys(b['repos']+a['repos']))
  b['discovery_sources']=sorted(set(b['discovery_sources']+a['discovery_sources']))
 for k in curation['exclude']:rows.pop(k,None)
 for r in curation['add']:rows[r['firm_id']]=r
 for k,v in curation['update'].items():
  if k in rows:rows[k].update(v)
 (ROOT/'scripts/registry/candidates.json').write_text(json.dumps(sorted(rows.values(),key=lambda r:r['firm_id']),ensure_ascii=False,indent=2)+'\n')
 print('candidates',len(rows))

if __name__=='__main__':main()
