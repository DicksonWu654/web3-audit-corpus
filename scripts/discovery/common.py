"""Phase 2d data-only HTTP helpers. No credentials or upstream code execution."""
from __future__ import annotations
import csv
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import time
import threading
import urllib.error
import urllib.parse as up
import urllib.request as ur
import urllib.robotparser

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'data/discovery'
CACHE = ROOT / 'local-cache/discovery-cache'
UA = 'web3-audit-corpus-discovery/1.0 (public audit metadata research)'

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def scope():
    with (ROOT / 'registry/scope_tier_a.csv').open() as f:
        return {r['firm_id']: r for r in csv.DictReader(f) if r['firm_id'] != 'certik'}

def norm(s):
    return re.sub('[^a-z0-9]', '', str(s or '').lower())

EXTRA = {
    'trail-of-bits':['Trail of Bits','TrailOfBits'], 'consensys-diligence':['Consensys','ConsenSys Diligence','Diligence'],
    'chainsecurity':['Chain Security'], 'sigma-prime':['SigmaPrime','sigp'],
    # DAppSCAN spells this explicit author label with a Cyrillic е; preserve
    # that exact source-specific alias rather than broad confusable folding.
    'runtime-verification':['RuntimeVerification','Runtime_Vеrification'], 'ackee-blockchain':['Ackee','AckeeBlockchain'],
    'informalsystems':['Informal Systems','Informal'], 'abdk-consulting':['ABDK'],
    'pashov-audit-group':['Pashov'], 'guardianaudits':['Guardian','Guardian Audits'],
    'ncc-group':['NCC','NCCGroup'], 'kudelski-security':['Kudelski'],
    'least-authority':['LeastAuthority'], 'three-sigma':['ThreeSigma','3Sigma'],
    'composable-security':['Composable'], 'chainlight':['ChainLight'],
    'electisec':['yAudit','yAudit.dev','Electisec'], 'teamomega':['Omega','OmegaAudits','Team Omega'],
    'obsidian-audits':['Obsidian'], 'code4rena-zenith':['Zenith'],
    'trust-security':['Trust Security','Trust1995'], 'asymmetric-research':['Asymmetric Research'],
    'hats-finance':['HatsFinance','Hats Finance'], 'secure3':['Secure3Audit'],
    'code4rena':['Code423n4','Code-423n4'], 'nethermind':['Nethermind Security'],
    'oxorio':['Oxor'], 'theori':['Theori'], 'fuzzland':['Fuzzland'],
    'macro':['0xMacro'],
}

def aliases():
    result = {}
    for fid, r in scope().items():
        for a in [fid, r['name'], *EXTRA.get(fid, [])]:
            if a:
                result[norm(a)] = fid
    return result

def firm_name(value):
    return aliases().get(norm(value))

def named_firms(value):
    """Match complete author tokens, including CamelCase, in an actual filename.

    Joining all letters makes security-audit and preliminary-audit look like
    yAudit. Keep word boundaries and never match that accidental suffix.
    """
    raw=up.unquote(str(value or '')).rstrip('/').rsplit('/',1)[-1]
    hits=set()
    for fid,r in scope().items():
        for alias in [fid,r['name'],*EXTRA.get(fid,[])]:
            if len(norm(alias))<5:continue
            words=re.findall(r'[A-Za-z0-9]+',alias)
            if not words:continue
            pattern=r'[\s_.-]*'.join(re.escape(w) for w in words)
            for m in re.finditer(pattern,raw,re.I):
                start,end=m.span()
                before=start==0 or not raw[start-1].isalnum() or (raw[start].isupper() and raw[start-1].islower())
                after=end==len(raw) or not raw[end].isalnum() or (raw[end].isupper() and raw[end-1].islower())
                if before and after:hits.add(fid)
    return hits

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp=path.with_name(path.name+f'.{os.getpid()}.{threading.get_ident()}.tmp')
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + '\n')
    tmp.replace(path)

def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp=path.with_name(path.name+f'.{os.getpid()}.{threading.get_ident()}.tmp')
    with tmp.open('w') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n')
    tmp.replace(path)

class NoRedirect(ur.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def public_url(url):
    try:u = up.urlsplit(url)
    except ValueError:return False
    if u.scheme not in ('https', 'http') or not u.hostname or u.username or u.password:
        return False
    if u.hostname.lower() in ('localhost','metadata.google.internal') or u.hostname.endswith(('.local','.internal')):
        return False
    try:
        return ipaddress.ip_address(u.hostname).is_global
    except ValueError:
        return True

def _one(url, method='GET', limit=64_000_000, timeout=20):
    if not public_url(url):
        return {'url':url,'status':0,'error':'non-public URL refused','checked_utc':now()}, b''
    CACHE.mkdir(parents=True, exist_ok=True)
    host = up.urlsplit(url).netloc.lower()
    lockpath = Path('/tmp') / ('web3-phase2d-host-' + hashlib.sha256(host.encode()).hexdigest())
    with lockpath.open('a+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        lock.seek(0)
        try: last = float(lock.read() or 0)
        except ValueError: last = 0
        time.sleep(max(0, 1.05 - (time.time() - last)))
        lock.seek(0); lock.truncate(); lock.write(str(time.time())); lock.flush()
        request = ur.Request(url, method=method, headers={'User-Agent':UA,'Accept':'application/json, text/plain, text/html;q=0.9, */*;q=0.8'})
        try:
            response = ur.build_opener(NoRedirect).open(request, timeout=timeout)
        except urllib.error.HTTPError as e:
            response = e
        except Exception as e:
            return {'url':url,'status':0,'error':type(e).__name__,'checked_utc':now()}, b''
        with response:
            data = b'' if method == 'HEAD' else response.read(limit + 1)
            meta = {'url':url, 'status':response.code,'checked_utc':now(),
                    'headers':{k.lower():v for k,v in response.headers.items() if k.lower() in
                    ('location','content-type','retry-after','x-ratelimit-remaining','x-ratelimit-reset')}}
            if len(data) > limit:
                meta['error']='body exceeds bound'; data=b''
            return meta,data

def fetch(url, method='GET', refresh=False, robots=True, limit=64_000_000, timeout=20, _hops=0):
    CACHE.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256((method + ' ' + url).encode()).hexdigest()
    meta_path, body_path = CACHE / (key+'.json'), CACHE / (key+'.body')
    if not refresh and meta_path.exists() and (method == 'HEAD' or body_path.exists()):
        return json.loads(meta_path.read_text()), b'' if method == 'HEAD' else body_path.read_bytes()
    if _hops>6:
        return {'url':url,'status':0,'error':'redirect limit','checked_utc':now()},b''
    if robots:
        u = up.urlsplit(url)
        robot_url = up.urlunsplit((u.scheme,u.netloc,'/robots.txt','',''))
        rm, rb = fetch(robot_url, robots=False, timeout=timeout, limit=2_000_000)
        allowed = rm['status'] in (404,410)
        if rm['status'] == 200:
            parser=urllib.robotparser.RobotFileParser(); parser.parse(rb.decode(errors='replace').splitlines())
            allowed=parser.can_fetch(UA,url)
        if not allowed:
            meta={'url':url,'status':0,'error':'robots_disallowed' if rm['status']==200 else 'robots_unavailable',
                  'robots_status':rm['status'],'checked_utc':now()}
            write_json(meta_path,meta); body_path.write_bytes(b''); return meta,b''
    meta, data = _one(url, method, limit, timeout)
    chain=[]; destination=url
    while meta['status'] in (301,302,303,307,308) and len(chain)<6:
        loc=meta.get('headers',{}).get('location')
        if not loc: break
        chain.append({'url':destination,'status':meta['status']})
        destination=up.urljoin(destination,loc)
        meta,data=fetch(destination,method=method,robots=robots,limit=limit,timeout=timeout,_hops=_hops+1)
        break  # Recursive fetch retains and checks each subsequent redirect.
    if chain:
        meta={**meta,'url':url,'effective_url':meta.get('effective_url',destination),
              'redirects':chain+meta.get('redirects',[])}
    meta['bytes']=len(data); meta['sha256']=hashlib.sha256(data).hexdigest() if method=='GET' else None
    write_json(meta_path,meta)
    if method != 'HEAD': body_path.write_bytes(data)
    return meta,data

def get_json(url, **kw):
    m,b=fetch(url,**kw)
    try: d=json.loads(b)
    except (ValueError,UnicodeDecodeError): d=None
    return m,d

def repo_tree(repo, prefix=''):
    base='https://api.github.com/repos/'+repo
    cm,c=get_json(base+'/commits/HEAD')
    if not isinstance(c,dict) or 'sha' not in c:
        return {'repo':repo,'error':'commit unavailable','request':cm},[]
    commit=c['sha']; sha=commit
    if prefix:
        for part in prefix.strip('/').split('/'):
            tm,t=get_json(base+'/git/trees/'+sha)
            nodes=(t or {}).get('tree',[])
            node=next((n for n in nodes if n['path']==part and n['type']=='tree'),None)
            if not node: return {'repo':repo,'commit':commit,'error':'subtree missing','prefix':prefix},[]
            sha=node['sha']
    tm,t=get_json(base+'/git/trees/'+sha+'?recursive=1')
    meta={'repo':repo,'commit':commit,'prefix':prefix,'request':tm,
          'truncated':t.get('truncated') if isinstance(t,dict) else None}
    if not isinstance(t,dict) or 'tree' not in t:
        meta['error']='tree unavailable'; return meta,[]
    if t.get('truncated'): meta['error']='truncated tree; partial enumeration'
    return meta,[{**n,'path':(prefix.rstrip('/')+'/' if prefix else '')+n['path']} for n in t['tree'] if n['type']=='blob']

def raw_url(repo, commit, path):
    return 'https://raw.githubusercontent.com/'+repo+'/'+commit+'/'+up.quote(path,safe='/')
