#!/usr/bin/env python3
"""Collect original rendered report HTML from Fuzzland's public Notion index.

Requires an existing Playwright CLI installation (no automatic installation).
Use WEB_BATCH2_PLAYWRIGHT_CLI=/path/to/playwright-cli.js if not on PATH/cache.
The browser is fresh, has no persisted login, and only accesses publisher Notion hosts.
"""
from web_batch2_common import *
import os
import shutil
import subprocess
import uuid
import unicodedata

FINDING_MARKER = r'\[(?:Critical|High|Medium|Low|Info(?:rmational)?|Gas)\]'

METHOD = 'Full rendered Notion index and paginated anonymous public-page metadata; collect original PDF attachments or full rendered report HTML.'
NOTES = 'Canonical listing is docs.fuzz.land. Publisher-linked docs.fuzz.land and fuzzland.notion.site aliases are supported: verified cached snapshots are reused, then the listing URL is tried before its alternate alias. No dates are invented when the index has none. HTML shells are rejected; private No access entries are explicitly skipped, and named pages that deny anonymous read or block file crawling are documented failures.'


def expected_blocks(records,page_id):
    queue,seen,result=[page_id],set(),[]
    while queue:
        block_id=queue.pop()
        if block_id in seen:
            continue
        seen.add(block_id)
        block=records.get(block_id,{})
        if block_id!=page_id and block.get('type')=='page':
            continue
        queue.extend(block.get('content',[]))
        props=block.get('properties',{})
        fields=list(props.values()) if block.get('type')=='table_row' else [props.get('title',[])]
        language=''.join(p[0] for p in props.get('language',[]) if p)
        for rich in fields:
            value=''.join(p[0] for p in rich if p and isinstance(p[0],str))
            if value and (len(value)>=60 or block.get('type')=='code') and '‣' not in value:
                expected={'block_id':block_id,'text':value,'diagram':language.lower()=='mermaid'}
                sequence=[]
                has_equation=False
                for part in rich:
                    equations=[a[1] for a in part[1] if a and a[0]=='e' and len(a)>1] if len(part)>1 else []
                    sequence.append(equations[0] if equations else part[0])
                    has_equation=has_equation or bool(equations)
                if has_equation:
                    expected['rendered_sequence']=sequence
                result.append(expected)
    return result


def compact_text(value):
    return ''.join(c for c in value if not c.isspace() and unicodedata.category(c) not in ('So','Cf') and c!='\ufe0f')


def missing_blocks(html,expected):
    dom=DOM(html)
    text=compact_text(dom.root.visible_text())
    blocks={n.attrs['data-block-id']:n for n in dom.all() if 'data-block-id' in n.attrs}
    missing=[]
    for block in expected:
        node=blocks.get(block['block_id'])
        if block.get('rendered_sequence'):
            # Notion substitutes an inline-equation placeholder with KaTeX,
            # whose MathML annotation preserves the publisher's original TeX.
            rendered=compact_text(node.visible_text()) if node else ''
            position=0
            for piece in block['rendered_sequence']:
                value=compact_text(piece)
                found=rendered.find(value,position)
                if found<0:
                    missing.append(block)
                    break
                position=found+len(value)
            continue
        if compact_text(block['text']) in text:
            continue
        if block['diagram'] and node and any(True for _ in node.all('svg')):
            continue
        missing.append(block)
    return missing


class NotionBrowser:
    def __init__(self):
        time.sleep(1.05)  # Separate the metadata HTTP phase from browser traffic.
        self.session='web-batch2-fuzzland-'+uuid.uuid4().hex[:10]
        supplied = os.environ.get('WEB_BATCH2_PLAYWRIGHT_CLI')
        if supplied:
            self.cli = ['node', supplied] if supplied.endswith('.js') else [supplied]
        elif shutil.which('playwright-cli'):
            self.cli = [shutil.which('playwright-cli')]
        else:
            candidates = sorted(Path.home().glob('.npm/_npx/*/node_modules/@playwright/cli/playwright-cli.js'))
            if not candidates:
                raise RuntimeError('An installed Playwright CLI is required; no package was installed automatically.')
            self.cli = ['node', str(candidates[-1])]
        self.env = dict(os.environ, XDG_CACHE_HOME='local-cache/tmp/web-batch2-browser-cache', NO_UPDATE_NOTIFIER='1')
        self.command('open', 'about:blank')
        self.run(r'''async (page) => {
          const context=page.context(), hosts=new Set(["docs.fuzz.land","fuzzland.notion.site"]), queues=new Map(), running=new Set(), last=new Map(), cache=new Map();
          context.__auditRequests=[];
          context.__auditAssetCache=cache;
          context.__auditPending=0;
          context.__auditContentPending=0;
          await page.setViewportSize({width:1280,height:30000});
          const browserAgent=await page.evaluate(()=>navigator.userAgent);
          await context.setExtraHTTPHeaders({"User-Agent":browserAgent+" "+''' + json.dumps(UA) + r'''});
          async function pump(host) {
            if(running.has(host)) return;
            running.add(host);
            const queue=queues.get(host);
            while(queue.length) {
              queue.sort((a,b)=>a.priority-b.priority);
              const task=queue.shift(), {route,req,key,content}=task;
              try {
                if(req.failure()) { await route.abort(); continue; }
                await new Promise(resolve=>setTimeout(resolve,Math.max(0,1050-(Date.now()-(last.get(host)||0)))));
                last.set(host,Date.now());
                const started=new Date().toISOString();
                const response=await route.fetch({maxRedirects:0,timeout:90000});
                const headers=response.headers();
                delete headers["content-encoding"]; delete headers["content-length"]; delete headers["transfer-encoding"];
                const result={status:response.status(),headers,body:await response.body()};
                context.__auditRequests.push({url:req.url(),method:req.method(),status:response.status(),retrieved_utc:started});
                if(["script","stylesheet"].includes(req.resourceType())) cache.set(key,result);
                await route.fulfill(result);
              } catch(e) { try { await route.abort(); } catch(e) {} }
              finally { context.__auditPending--; if(content) context.__auditContentPending--; task.done(); }
            }
            running.delete(host);
          }
          await context.route("**/*", async route => {
            const req=route.request(), u=new URL(req.url());
            const host=u.hostname;
            if(!hosts.has(host) || ["image","font","media"].includes(req.resourceType())) return route.abort();
            if((req.headers()["purpose"]||req.headers()["sec-purpose"]||"").includes("prefetch")) return route.abort();
            const key=u.pathname.startsWith("/_assets/")?u.pathname:req.url();
            if(cache.has(key)) return route.fulfill(cache.get(key));
            const content=/\/api\/v3\/(?:loadPage|syncRecord|getPublicPage|queryCollection)/.test(u.pathname);
            context.__auditPending++;
            if(content) context.__auditContentPending++;
            if(!queues.has(host)) queues.set(host,[]);
            return new Promise(done=>{
              // Background metadata retries must not starve application scripts.
              const priority=req.isNavigationRequest()?0:content?1:req.resourceType()==="script"?2:req.resourceType()==="stylesheet"?3:4;
              queues.get(host).push({route,req,key,content,done,priority});
              void pump(host);
            });
          });
          return {configured:true};
        }''')
        asset_path=CACHE/'browser-assets.json'
        if asset_path.exists():
            self.run(r'''async(page)=>{
              const node=await page.addScriptTag({path:'''+json.dumps(str(asset_path))+r''',type:"application/json"});
              const raw=await node.textContent();
              const assets=JSON.parse(raw.split("\n//# sourceURL=")[0]);
              for(const [path,body] of Object.entries(assets)) {
                if(/^\/_assets\/[^/?]+\.js$/.test(path)) page.context().__auditAssetCache.set(path,{status:200,headers:{"content-type":"application/javascript"},body});
              }
              await node.evaluate(n=>n.remove()); return {loaded:true};
            }''')

    def save_assets(self):
        assets=self.run(r'''async(page)=>{
          const out={};
          for(const [path,r] of page.context().__auditAssetCache) {
            if(/^\/_assets\/[^/?]+\.js$/.test(path)&&r.status===200) out[path]=typeof r.body==="string"?r.body:r.body.toString("utf8");
          }
          return out;
        }''')
        write_json(CACHE/'browser-assets.json',assets)

    def command(self, *args):
        result = subprocess.run(self.cli + ['-s='+self.session] + list(args), cwd='/tmp', env=self.env,
                                capture_output=True, text=True, timeout=240)
        if result.returncode or '### Error' in result.stdout:
            raise RuntimeError('Playwright CLI: ' + (result.stdout + result.stderr)[-2000:])
        return result.stdout

    def run(self, code):
        output = self.command('run-code', code)
        match = re.search(r'### Result\n(.*?)(?:\n###|\Z)', output, re.S)
        if not match:
            raise RuntimeError('No Playwright result: ' + output[-1000:])
        return json.loads(match[1])

    def capture(self, url, listing=False, expected=()):
        self.run('async (page) => { await page.goto(' + json.dumps(url) + ', {waitUntil:"commit",timeout:90000}); return {navigated:true}; }')
        last, stable, reloaded = None, 0, False
        for attempt in range(100):
            self.run('''async(page)=>{ const height=await page.evaluate(()=>Math.max(...[...document.querySelectorAll(".notion-scroller")].map(n=>n.scrollHeight),innerHeight));
              const current=page.viewportSize(); if(height>current.height+50 && current.height<200000) await page.setViewportSize({width:1280,height:Math.min(200000,height+500)}); return true; }''')
            result = self.run('''async (page) => {
              return {url:page.url(), text:await page.locator("body").innerText(), html:await page.content(),
                links:await page.locator("a[href]").evaluateAll(nodes=>nodes.map(n=>({url:n.href,text:n.innerText}))),
                requests:page.context().__auditRequests,pending:page.context().__auditPending,
                contentPending:page.context().__auditContentPending,
                emptyPages:await page.locator(".notion-page-block, .notion-page-mention-token__title").evaluateAll(nodes=>nodes.filter(n=>!n.innerText.trim()).length),
                slots:await page.locator("[data-virtual-item-slot]").count(),
                emptySlots:await page.locator("[data-virtual-item-slot]").evaluateAll(nodes=>nodes.filter(n=>!n.querySelector("[data-block-id]")).length)};
            }''')
            text = result['text']
            missing=missing_blocks(result['html'],expected) if expected else []
            ready = (('Below are the security reports' in text) if listing is True else (len(text)>60) if listing else
                     bool(re.search(r'Executive Summary|Invariant Development|Summary of Findings', text, re.I)) or
                     (bool(expected) and len(text)>500 and bool(re.search(FINDING_MARKER,text,re.I))) or
                     (len(text)>500 and bool(re.search(r'Overview|Scope',text,re.I)) and bool(re.search(r'Findings|Auditing Process|Vulnerability Severity',text,re.I))))
            stable = stable + 1 if text == last else 0
            if stable>=3 and re.search(r'This page couldn.t be found|You.re offline',text):
                if reloaded:
                    raise RuntimeError('Public Notion browser page unavailable: '+url)
                self.run('async(page)=>{await page.reload({waitUntil:"commit"});return true;}')
                reloaded=True
                stable=0
            if ready and not missing and stable >= 3 and result['emptySlots'] == 0 and result['emptyPages']==0 and result['contentPending'] == 0:
                if not listing:
                    assert re.search(r'[0-9a-f]{32}',result['url'])[0]==re.search(r'[0-9a-f]{32}',url)[0], 'Rendered page URL changed during capture'
                return result
            last = text
            if attempt % 6 == 0:
                print(f'fuzzland: waiting for rendered content ({attempt}): {url}; text chars={len(text)}; missing source blocks={len(missing)}', flush=True)
            time.sleep(3)
        raise RuntimeError('Notion did not render complete report/index content: ' + url + '; missing source blocks='+str(len(missing))+'; last text: ' + (last or '')[:300])


BROWSER = None
RESUME_INDEX = False


def browser():
    global BROWSER
    if BROWSER is None:
        BROWSER = NotionBrowser()
    return BROWSER


def close_browser():
    global BROWSER
    if BROWSER is not None:
        BROWSER.save_assets()
        BROWSER.command('close')
        BROWSER=None
        time.sleep(1.05)


def page_records(fetch,url):
    page_id=uuid.UUID(re.search(r'([0-9a-f]{32})(?:[?#/]|$)',url)[1])
    base='https://docs.fuzz.land/api/v3/'
    public=fetch.public_notion_json(base+'getPublicPageData',{'type':'block-space','name':'page','blockId':str(page_id),
        'spaceDomain':'docs.fuzz.land','requestedOnPublicDomain':True,'requestedOnExternalDomain':True})
    if public.get('requireLogin') or public.get('publicAccessRole')!='reader':
        raise RuntimeError('Notion does not expose anonymous public read access: '+url)
    records,cursor,chunk={}, {'stack':[]},0
    while True:
        data=fetch.public_notion_json(base+'loadPageChunk',{'pageId':str(page_id),'limit':1000,'cursor':cursor,
                                                         'chunkNumber':chunk,'verticalColumns':False})
        for key,value in data.get('recordMap',{}).get('block',{}).items():
            value=value.get('value',{})
            records[key]=value.get('value',value)
        cursor=data.get('cursor',{})
        if not cursor.get('stack'):
            break
        chunk+=1
        if chunk>100:
            raise RuntimeError('Notion page chunk pagination did not terminate: '+url)
    return records


def prepare_originals(fetch,entry):
    """Read public source metadata before rendering; cache real PDF attachments."""
    records=page_records(fetch,entry['public_url'])
    if not hasattr(fetch,'notion_expected'):
        fetch.notion_expected={}
    page_id=str(uuid.UUID(re.search(r'[0-9a-f]{32}',entry['public_url'])[0]))
    fetch.notion_expected[entry['public_url']]=expected_blocks(records,page_id)
    pdfs=[]
    for key,value in records.items():
        if value.get('type') not in ('file','pdf'):
            continue
        props=value.get('properties',{})
        source=''.join(x[0] for x in props.get('source',[]) if x)
        filename=''.join(x[0] for x in props.get('title',[]) if x)
        if '.pdf' in source.lower() or filename.lower().endswith('.pdf'):
            pdfs.append((key,source,filename))
    if not pdfs:
        return [entry]
    results=[]
    for key,source,filename in pdfs:
        e=dict(entry,expected_format='pdf',filename_hint=filename,
               notes='Original PDF attachment on the public Notion page; file block '+key+'. Expiring download URLs are not used as public URLs.')
        if len(pdfs)>1:
            e['public_url'] += '#'+key.replace('-','')
        try:
            signed=fetch.public_notion_json('https://docs.fuzz.land/api/v3/getSignedFileUrls',
                {'urls':[{'url':source,'permissionRecord':{'table':'block','id':key}}],'cacheTime':3600},fresh=True)
            urls=signed.get('signedUrls') or signed.get('signed_urls') or []
            if not urls or not isinstance(urls[0],str):
                raise RuntimeError('No anonymous public download URL for PDF attachment: '+filename)
            try:
                meta,body=fetch.get(urls[0],fresh=True)
            except Exception as exc:
                reason='robots.txt disallows PDF crawling' if 'robots.txt disallows' in str(exc) else type(exc).__name__
                raise RuntimeError(reason+' on '+urlsplit(urls[0]).netloc+': '+filename) from exc
            if meta['status']!=200 or not body.startswith(b'%PDF-'):
                raise RuntimeError(f"PDF attachment download failed: HTTP {meta['status']}: {filename}")
            fetch.payloads[e['public_url']] = (meta,body)
        except Exception as exc:
            e['preparation_error']=str(exc)
        results.append(e)
    return results


def rendered_page(url, listing=False, expected=(), cached_only=False):
    folder = CACHE / 'rendered'
    key = hashlib.sha256(url.encode()).hexdigest()
    meta_path, html_path = folder/(key+'.json'), folder/(key+'.html')
    if meta_path.exists() and html_path.exists() and '--refresh' not in sys.argv and (not listing or RESUME_INDEX):
        value=json.loads(meta_path.read_text())
        if not listing or value.get('retrieved_utc','')[:10]==utc()[:10]:
            value['html']=html_path.read_text()
            requested_id=re.search(r'[0-9a-f]{32}',url)[0]
            actual_id=re.search(r'[0-9a-f]{32}',value.get('url',''))
            if actual_id and actual_id[0]==requested_id and not missing_blocks(value['html'],expected):
                return value
    if cached_only:
        return None
    value=browser().capture(url, listing, expected)
    value['retrieved_utc']=utc()
    folder.mkdir(parents=True,exist_ok=True)
    html_path.write_text(value['html'])
    write_json(meta_path,{k:v for k,v in value.items() if k!='html'})
    return value


def enumerate_reports(fetch):
    global BROWSER
    url = 'https://docs.fuzz.land/'
    fetch._policy(url)
    fetch._policy('https://fuzzland.notion.site/')
    folder = CACHE / 'rendered'
    folder.mkdir(parents=True, exist_ok=True)
    if RESUME_INDEX:
        rendered=json.loads((folder/'fuzzland-index.json').read_text())
        assert rendered['retrieved_utc'][:10]==utc()[:10], 'Resume requires a live index snapshot from today'
        rendered['html']=(folder/'fuzzland-index.html').read_text()
    else:
        rendered = browser().capture(url, listing=True)
        rendered['retrieved_utc']=utc()
        (folder / 'fuzzland-index.html').write_text(rendered['html'])
        write_json(folder / 'fuzzland-index.json', {k:v for k,v in rendered.items() if k!='html'})
    # Separate metadata HTTP and browser-rendering phases so both use the same
    # host budget without simultaneous request schedulers.
    close_browser()
    entries, sources = [], [url]
    for link in rendered['links']:
        if link['text'].strip()=='No access':
            entries.append(item(link['url'].split('?')[0],url,'No access','','','Private/nonpublic page',
                                skip_reason='Publisher marks this entry No access; private pages are outside public-report scope. No login attempted.'))
            continue
        if not re.search(r'\breports?\b', link['text'], re.I):
            continue
        if urlsplit(link['url']).netloc not in ('docs.fuzz.land', 'fuzzland.notion.site'):
            raise RuntimeError('New report host needs robots review: ' + link['url'])
        target=link['url'].split('?')[0]
        e=item(target, url, link['text'], re.sub(r' (?:Audit|Auditing|Invariant Dev) Report$', '', link['text']), '',
                            'Invariant development' if 'Invariant' in link['text'] else 'Security audit',
                            notes='Original browser-rendered public Notion HTML; application bootstrap alone is not collected.')
        try:
            entries.extend(prepare_originals(fetch,e))
        except Exception as exc:
            e['preparation_error']=str(exc)
            entries.append(e)
        print('fuzzland: source metadata '+target,flush=True)
    assert entries, 'Empty rendered Fuzzland index'
    fetch.evidence.extend(rendered['requests'])
    return entries, sources


def resolve_report(fetch, entry):
    url = entry['public_url']
    if entry.get('preparation_error'):
        raise RuntimeError(entry['preparation_error'])
    if url in fetch.payloads:
        return entry
    canonical='https://fuzzland.notion.site/'+re.search(r'[0-9a-f]{32}',url)[0]
    fetch._policy(canonical)
    expected=fetch.notion_expected[url]
    custom='https://docs.fuzz.land/'+re.search(r'[0-9a-f]{32}',url)[0]
    targets=list(dict.fromkeys([url,canonical,custom]))
    rendered=None
    for target in targets:
        rendered=rendered_page(target,expected=expected,cached_only=True)
        if rendered is not None:
            break
    if rendered is None:
        for target in targets:
            try:
                rendered=rendered_page(target,expected=expected)
                break
            except RuntimeError:
                if target==targets[-1]:
                    raise
    entry['public_url']=rendered['url']
    entry['filename_hint']=entry['title_hint']+'.html'
    entry['notes'] += '; Original listing link: '+url
    fetch.payloads[entry['public_url']] = ({'status':200, 'content_type':'text/html', 'retrieved_utc':rendered['retrieved_utc']}, rendered['html'].encode())
    fetch.evidence.extend(rendered['requests'])
    return entry


def gap_main():
    from web_dedaub import Reconcile
    g = Reconcile('fuzzland')
    url = 'https://docs.fuzz.land/'
    shell = g.fetch.text(url, fresh=True)
    root_id = re.search(r'"pageId":"([0-9a-f-]{36})"', shell)[1]
    root_url = url + root_id.replace('-', '')
    g.fetch.refresh = True
    records = page_records(g.fetch, root_url)
    g.fetch.refresh = False
    root = records[root_id]
    entries, section = {}, ''
    for block_id in root['content']:
        block = records.get(block_id, {})
        rich = block.get('properties', {}).get('title', [])
        title = ''.join(p[0] for p in rich if p)
        if block.get('type') == 'sub_header':
            section = title
            continue
        targets = []
        if block.get('type') == 'page':
            targets.append(block_id)
        if block.get('type') == 'alias':
            targets.append(block['format']['alias_pointer']['id'])
        for part in rich:
            for annotation in part[1] if len(part)>1 else []:
                if annotation and annotation[0] == 'p':
                    targets.append(annotation[1])
        for target in targets:
            page = records.get(target, {})
            title = ''.join(p[0] for p in page.get('properties', {}).get('title', []) if p)
            e = item(url + target.replace('-', ''), url, title or 'No access', title,
                     notes='Live anonymous index page metadata; section: ' + section)
            e['index_block_id'] = block_id
            e['index_section'] = section
            if not title:
                e['skip_reason'] = 'Unnamed No access/private placeholder; no public audit report identified. No private page requested.'
            elif not re.search(r'\breports?\b', title, re.I):
                raise RuntimeError('New named publication requires scope classification: ' + title)
            entries.setdefault(target, e)
    assert entries, 'No report references in public index'
    for e in entries.values():
        if e.get('skip_reason'):
            g.exclude(e, e['skip_reason'], 'private_placeholder')
            continue
        row, error = g.find(e), ''
        if row is None:
            try:
                g.fetch.refresh = True
                prepared = prepare_originals(g.fetch, e)
                g.fetch.refresh = False
                assert len(prepared) == 1, 'Multiple report attachments need separate acquisition receipts'
                ready = resolve_report(g.fetch, prepared[0])
                meta, body = g.fetch.payloads[ready['public_url']]
                ready['expected_format'] = 'pdf' if body.startswith(b'%PDF') else 'html'
                row = g.save(ready, meta, body)
            except Exception as exc:
                error = str(exc)
            finally:
                g.fetch.refresh = False
        g.report(e, row, error)
    gaps = [r for r in g.receipts if 'remaining_gap' in r]
    excluded = len(entries) - sum(r['classification']=='audit_report' for r in g.receipts)
    g.finish([url, root_url], [
        'Full live anonymous public index block tree, including alias pointers and rich-text page references, read through the same public read API used by the publisher frontend. Pagination exhausted; no application shell counted as a report.',
        f'Index references: {len(entries)}; {excluded} unnamed/private placeholders excluded from the public audit-report denominator. Named reports that deny anonymous access remain explicit gaps.',
        'Existing complete rendered HTML originals verified by SHA-256 and matched by Notion page ID. Missing pages checked live; requireLogin/publicAccessRole denials stop before loading content. PDF-attachment robots rules honored; signed download URLs are never published in receipts.'
    ], f'{excluded} private placeholders excluded; {len(gaps)} named report gaps remain (anonymous access or attachment robots policy).')


if __name__ == '__main__':
    try:
        gap_main()
    finally:
        close_browser()
