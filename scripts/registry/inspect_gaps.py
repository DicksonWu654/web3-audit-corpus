#!/usr/bin/env python3
"""Read-only homepage inspection for stale report sources; outputs leads for review."""
import concurrent.futures,html,importlib.util,json,re
from pathlib import Path
from urllib.parse import urljoin
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('registry_collect',Path(__file__).with_name('collect.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
cache=Path('local-cache/tmp/firm-registry-cache');cache.mkdir(exist_ok=True)
rows=json.loads((ROOT/'scripts/registry/candidates.json').read_text())
obs={r['firm_id']:r for r in map(json.loads,(ROOT/'data/registry/observations.jsonl').read_text().splitlines())}
def go(c):
 o=obs[c['firm_id']]
 if any(t.get('status')==200 for t in o.get('trees',[])) or any(u['status']==200 for u in o.get('urls',[])):return None
 if not c.get('website'):return None
 meta,b=m.http(c['website'],cache);text=b.decode(errors='replace')
 title=re.search(r'<title[^>]*>(.*?)</title>',text,re.I|re.S)
 links=[]
 for u in re.findall(r'href=[\"\']([^\"\']+)',text,re.I):
  if re.search('report|portfolio|publications|audits|our-work',u,re.I):links.append(urljoin(meta['final_url'],html.unescape(u)))
 r={'firm_id':c['firm_id'],'homepage':meta,'title':html.unescape(title[1]) if title else '', 'report_leads':sorted(set(links))}
 return r
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as e:out=[r for r in e.map(go,rows) if r]
(ROOT/'data/registry/gaps.json').write_text(json.dumps(out,indent=2)+'\n')
for r in out:print(r['firm_id'],r['homepage']['status'],r['title'],r['report_leads'][:8],flush=True)
