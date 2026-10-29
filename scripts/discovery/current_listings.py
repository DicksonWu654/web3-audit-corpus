#!/usr/bin/env python3
"""Capture same-day registry tree/listing evidence for discovery subtraction.

No network, checkout, hooks, repository imports, or report downloads. Public
registry HTTP caches are normalized into a durable, independently rerunnable
snapshot. Existing filtered bare Git trees are read with all helpers disabled.
python3 -I scripts/discovery/current_listings.py
"""
from __future__ import annotations
import csv
import hashlib
import html
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
from urllib.parse import urlsplit,urljoin,unquote

ROOT=Path(__file__).resolve().parents[2]
H=runpy.run_path(str(ROOT/'scripts/discovery/common.py'))
CACHE=Path('local-cache/tmp/firm-registry-cache')

def repo_name(url):
    u=urlsplit(url)
    parts=u.path.strip('/').split('/')
    return '/'.join(parts[:2]) if u.hostname=='github.com' and len(parts)>=2 and parts[0] not in ('orgs',) else None

def main():
    existing=H['OUT']/'current_listings.json'
    if not CACHE.exists():
        if existing.exists(): print('Using retained current_listings.json');return
        raise SystemExit('Registry snapshot unavailable; run collection before comparison.')
    firms={r['firm_id']:r for r in csv.DictReader((ROOT/'registry/firms.csv').open())}
    meta_by_url={}
    for p in CACHE.glob('*.json'):
        try:m=json.loads(p.read_text())
        except ValueError:continue
        if isinstance(m,dict) and m.get('status')==200 and m.get('url'):
            bp=p.with_suffix('.body')
            if bp.exists() and hashlib.sha256(bp.read_bytes()).hexdigest()==m.get('sha256'):
                meta_by_url[m['url']]=(m,bp)
    result={}
    for fid,s in H['scope']().items():
        r=firms.get(fid,s); repos=[]
        for field in ('github_reports_url',):
            for url in r.get(field,'').split(';'):
                repo=repo_name(url)
                if repo:repos.append(repo)
        record={'repos':[],'website_urls':[],'website_pages':[],'listing_items':[]}
        for repo in sorted(set(repos)):
            url='https://api.github.com/repos/'+repo+'/git/trees/HEAD?recursive=1'
            m,bp=meta_by_url.get(url,({},None)); tree=json.loads(bp.read_bytes()) if bp else {}
            if tree.get('tree') and not tree.get('truncated'):
                record['repos'].append({'repo':repo,'paths':[n['path'] for n in tree['tree'] if n['type']=='blob'],
                                        'tree_sha':tree['sha'],'checked_utc':m.get('checked_utc'),
                                        'evidence_url':url,'complete':True,'response_sha256':m['sha256']})
                continue
            bare=CACHE/(repo.replace('/','__')+'.git')
            if bare.exists():
                env={k:os.environ[k] for k in ('PATH','LANG') if k in os.environ}
                env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0',GIT_NO_LAZY_FETCH='1')
                base=['git','-c','credential.helper=','-c','core.hooksPath=/dev/null',
                      '-c','core.fsmonitor=false','-c','core.pager=cat','--git-dir='+str(bare)]
                commit=subprocess.check_output(base+['rev-parse','HEAD'],env=env).decode().strip()
                paths=subprocess.check_output(base+['ls-tree','-rz','HEAD'],env=env)
                names=[x.split(b'\t',1)[1].decode() for x in paths.split(b'\0') if x and b' blob ' in x]
                record['repos'].append({'repo':repo,'paths':names,'commit':commit,'complete':True,
                                        'evidence_url':'https://github.com/'+repo+'/tree/'+commit,
                                        'checked_utc':'2026-10-20 (registry capture)', 'method':'existing_bare_tree_no_network'})
            else:record['repos'].append({'repo':repo,'complete':False,'reason':'registry tree unavailable'})
        for field in ('website_reports_url','other_reports_url'):
            for url in r.get(field,'').split(';'):
                pair=meta_by_url.get(url)
                if not pair:continue
                m,bp=pair
                text=html.unescape(bp.read_text(errors='replace').replace('\\/','/').replace('\\"','"'))
                urls=set(re.findall(r'https?://[^\s<>"\x27\\]+',text))
                urls.update(urljoin(url,l) for l in re.findall(r'(?:href|src)=["\x27]([^"\x27]+)',text))
                record['website_urls']+=sorted(u for u in urls if H['public_url'](u))
                record['website_pages'].append({'url':url,'checked_utc':m.get('checked_utc'),'response_sha256':m['sha256'],
                                                'scope':'links in captured landing page; pagination not certified'})
        result[fid]=record
    for listing in json.loads((ROOT/'data/registry/listings.json').read_text()):
        if listing['firm_id'] in result:
            result[listing['firm_id']]['listing_items']=listing.get('items',[])
    H['write_json'](existing,result)
    print(json.dumps({'firms':len(result),'complete_repos':sum(x.get('complete',False) for r in result.values() for x in r['repos']),
                      'paths':sum(len(x.get('paths',[])) for r in result.values() for x in r['repos'])}))

if __name__=='__main__':main()
