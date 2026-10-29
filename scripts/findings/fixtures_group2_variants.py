"""Small synthetic transcriptions of non-holdout group 2 layout structures.

No report body or held-out text is embedded. Real year/era receipts are generated
separately by variants_group2.py from the holdout-filtered corpus.
"""
BODY='\nDescription: The affected operation permits an unauthorized state change.\nRecommendation: Validate the caller before changing the state.\n'
FIXTURES={}

def add(name,firm,variant,text,pid=None,risk=None,state=None,count=1):
    FIXTURES[name]=dict(firm=firm,variant_id=firm+'/'+variant,text=text,
                        expected=[] if count==0 else [(pid,risk,state)])

add('peckshield_pve','peckshield','v2019_pve_cards','PeckShield Audit Report\n3.1 Improper permission check\n\n• ID: PVE-001    • Target: Vault\n• Severity: High\n'+BODY+'Status This issue has been fixed in the reviewed commit.\n','PVE-001','High','fixed')
add('peckshield_review','peckshield','v2020_security_review','PeckShield Security Review\n2.1 PVE-001: Improper permission check\n• Severity: Low\n'+BODY+'• Status: This issue had been addressed by validating the caller.\n','PVE-001','Low','resolved')
add('peckshield_chinese','peckshield','v2019_chinese','3.1 权限检查\nID: PVE-001\n危害性：高危\n'+BODY+'状态：已修复\n','PVE-001','高危','fixed')
add('peckshield_compliance','peckshield','v2021_compliance','PeckShield Audit Report\n2.2 Key Findings\nOverall, no ERC20 compliance issues were found.\n'+BODY,count=0)
add('spearbit_numbered','spearbit','v2021_numbered','5.1 High Risk\n5.1.1 Improper permission check\nSeverity: High Risk\n'+BODY+'Spearbit: Fix verified.\n','5.1.1','High Risk','fixed')
add('spearbit_crypto','spearbit','v2023_cryptography','Protocol Documentation / White Paper Review\n\nIncorrect domain separation (Minor)\n'+BODY+'Spearbit: Acknowledged.\n',None,'Minor','acknowledged')
add('spearbit_upgrade','spearbit','v2025_upgrade_assessment','5.1 Upgrade Proposal #17 validation\nSeverity: Informational\n'+BODY+'Spearbit: Verified.\n','5.1','Informational','resolved')
add('spearbit_inherited','spearbit','v2023_section_severity','5.1 Low Risk\n5.1.1 Improper permission check\nContext: Vault.rs\n'+BODY+'Spearbit: Fixed.\n','5.1.1','Low Risk','fixed')
add('spearbit_clean','spearbit','v2023_clean_review',"5 Review result\nAfter reviewing the PR, we don't see any security issues with this minor change.\n"+BODY,count=0)
add('blocksec_index','blocksec','v2021_index_risk','Chapter 2 Findings\nID    Severity    Description\n1     Medium      Improper permission check\n2.1 Software Security\n2.1.1 Improper permission check\nStatus Confirmed and fixed.\n'+BODY,'2.1.1','Medium','fixed')
add('blocksec_fields','blocksec','v2022_severity_fields','2.1 Software Security\n2.1.1 Improper permission check\n\nSeverity High\nStatus Confirmed\n'+BODY,'2.1.1','High','open')
add('blocksec_version','blocksec','v2025_version_fields','2.1 Security Issue\n2.1.1 Improper permission check\n\nSeverity Medium\nStatus Fixed in Version 2\nIntroduced by Version 1\n'+BODY,'2.1.1','Medium','fixed')
add('blocksec_nested','blocksec','v2022_nested','2.1 Security Issues\n2.1.1 Software Security\n2.1.1.1 Improper permission check\n\nSeverity High\nStatus Partially Fixed\n'+BODY,'2.1.1.1','High','partial')
add('least_reported','least-authority','v2017_reported','Issue A: Improper permission check    Reported:\nIssue A: Improper permission check\nLocation\nVault\nSynopsis\n'+BODY+'Status\nUnresolved\n','Issue A',None,'open')
add('least_status_cards','least-authority','v2019_status_cards','Issue A: Improper permission check\nLocation\nVault\nSynopsis\n'+BODY+'Status\nUnresolved\nVerification\nResolved\n','Issue A',None,'resolved')
add('least_risk_index','least-authority','v2026_risk_index','Issue A: Improper permission check    High    Resolved\nIssue A: Improper permission check\nLocation\nVault\nSynopsis\n'+BODY+'Status\nUnresolved\nVerification\nResolved\n','Issue A','High','resolved')
add('least_narrative','least-authority','v2015_narrative','# Ethereum Analysis: Gas Economics and Proof of Work\n'+BODY,count=0)
add('pessimistic_titled','pessimistic','v2020_titled','Security Analysis by Pessimistic\nMedium severity issues .................... 5\nImproper permission check (fixed) .................... 5\nAbstract\nManual analysis\nMedium severity issues\nImproper permission check (fixed)\n'+BODY,None,'Medium severity issues','fixed')
add('pessimistic_ids','pessimistic','v2022_severity_ids','Security Analysis by Pessimistic\nManual analysis\nMedium severity issues\nM01. Improper permission check (fixed)\n'+BODY,'M01','M','fixed')
add('pessimistic_visual','pessimistic','v2025_visual_cards','SECURITY\nPESSIMISTIC\nM01 Improper permission check\nStatus: Fixed\n'+BODY,'M01','M','fixed')
add('iosiro_numbered','iosiro','v2017_numbered','# 5. Open Findings\n## 5.1 High risk\n### 5.1.1 Improper permission check\n'+BODY,'5.1.1','High','open')
add('iosiro_html','iosiro','v2024_native_html','<h2><strong>IO-TST-001</strong> Improper permission check</h2>\n<table class="metadata"><tr><td class="rating-high">High</td><td class="status-closed">Closed</td></tr></table>\n<p>'+BODY+'</p>','IO-TST-001','High','acknowledged')
add('iosiro_classless','iosiro','v2026_classless_html',
    '<h1>Code quality improvement suggestions</h1>\n<p>Code improvement suggestions without security implications are listed below.</p>\n'
    '<table><tr><th>ID</th><th>Location</th><th>Suggestion</th></tr>'
    '<tr><td>IO-TST-002</td><td>Vault.sol</td><td>Validate the caller before changing the state.</td></tr></table>\n',
    'IO-TST-002',None,None)
add('iosiro_short','iosiro','v2018_short_review','iosiro\n### Findings\nNo substantial issues were found during the audit.\n'+BODY,count=0)
add('decurity_risk','decurity','v2023_risk_level','5.1. Improper permission check\nRisk Level: High\nStatus: The vulnerability has been acknowledged by the customer, no fixes will be made.\n'+BODY,'5.1','High','acknowledged')
add('decurity_details','decurity','v2021_details','4 DETAILS\n4.1.1 Improper permission check\nSummary:\n'+BODY+'Status: Not fixed\n','4.1.1',None,'open')
add('decurity_verification','decurity','v2022_verification','3.1 [High] Improper permission check\n'+BODY+'Status: Fixed\n','3.1','High','fixed')
add('decurity_clean','decurity','v2024_clean','The Decurity team\n3. Summary\nAs a result of this work, we have not discovered any security issues.\n'+BODY,count=0)
add('coinspect_inline','coinspect','v2016_inline_risk','ZEC-01 Improper permission check\nTotal Risk    High | Impact: High | Likelihood: Low | Effort to Fix: Medium\n'+BODY+'Status\nFixed\n','ZEC-01','High','fixed')
add('coinspect_grid','coinspect','v2018_risk_grid','TST-01 Improper permission check\n  Total Risk       Impact       Location\n   High             Low        Vault\n'+BODY+'Status\nFixed\n','TST-01','High','fixed')
add('coinspect_status_risk','coinspect','v2024_status_risk','TST-01 Improper permission check\nStatus            Risk\nResolved          High\n'+BODY+'Resolution\nFixed\n','TST-01','High','fixed')
add('coinspect_clean','coinspect','v2020_clean_review','1. Executive Summary\nNo security issues were identified.\n'+BODY,count=0)
add('composable_sections','composable-security','v2022_section_cards','5.1. Improper permission check\nSeverity\nHIGH\n'+BODY+'Status\n2022-11-01\nFIXED\n','5.1','HIGH','fixed')
add('composable_commits','composable-security','v2023_commit_cards','[TST-abcd123-H01] Improper permission check\nHIGH FIXED\n'+BODY,'TST-abcd123-H01','HIGH','fixed')
add('composable_consultation','composable-security','v2025_consultation','Security consultation summary\n'+BODY,count=0)
add('secure3_chart','secure3','v2022_chart_cards','Code Assessment Findings\nTST-1: Improper permission check\nCategory    Severity    Code Reference    Status\nLogical     High        Vault.sol         Fixed\n'+BODY,'TST-1','High','fixed')
add('secure3_competitive','secure3','v2023_competitive','TST-1:Improper permission check\nCategory    Severity    Client Response    Contributor\nLogical     High        Declined           Researcher\nCode Reference\nVault.sol\n'+BODY,'TST-1','High','other')
