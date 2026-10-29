#!/usr/bin/env node
// Exercise the real loader against raw gzip, HTTP-decoded gzip and plain JSON.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import {gzipSync} from 'node:zlib';
import {test} from 'node:test';

const source=fs.readFileSync(new URL('../src/assets/js/data.js',import.meta.url),'utf8');
const nativeFetch=globalThis.fetch;
const expected={name:'café',nested:[1,true,null]};
const json=JSON.stringify(expected);

for(const mode of ['plain','gzip','content-encoding']){
 test(mode,async()=>{
  const requests=[];
  let badAttempts=0,brokenAttempts=0;
  const server=http.createServer((req,res)=>{
   requests.push(req.url);
   if(req.url==='/config.json'){
    res.setHeader('Content-Type','application/json');
    res.end(JSON.stringify({data_path:'dataset',...(mode==='plain'?{}:{data_compression:'gzip'})}));
    return;
   }
   if(req.url.includes('optional')){res.writeHead(404);res.end();return;}
   if(req.url.includes('retry')&&badAttempts++===0){res.writeHead(503);res.end();return;}
   if(req.url.includes('broken')&&brokenAttempts++===0){res.end(mode==='plain'?'{':Buffer.from([0x1f,0x8b]));return;}
   if(mode==='content-encoding')res.setHeader('Content-Encoding','gzip');
   res.end(mode==='plain'?json:gzipSync(json));
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  globalThis.fetch=(url,...args)=>nativeFetch(new URL(url,`http://127.0.0.1:${server.address().port}/`),...args);
  try{
   // A unique module URL gives each host configuration its own original caches.
   const {getJSON}=await import('data:text/javascript;base64,'+Buffer.from(source+'\n// '+mode).toString('base64'));
   const suffix=mode==='plain'?'':'.gz';
   const [first,second]=await Promise.all([getJSON('nested/file.json'),getJSON('nested/file.json')]);
   assert.deepEqual(first,expected);
   assert.strictEqual(first,second);
   assert.strictEqual(await getJSON('nested/file.json'),first);
   assert.equal(requests.filter(p=>p==='/dataset/nested/file.json'+suffix).length,1);
   assert.equal(await getJSON('optional.json',{optional:true}),null);
   assert.equal(await getJSON('optional.json',{optional:true}),null);
   assert.equal(requests.filter(p=>p.includes('optional')).length,1);
   await assert.rejects(getJSON('retry.json'),{message:'Could not load retry.json (HTTP 503)'});
   assert.deepEqual(await getJSON('retry.json'),expected);
   await assert.rejects(getJSON('broken.json'));
   assert.deepEqual(await getJSON('broken.json'),expected);
   assert.equal(requests.filter(p=>p==='/config.json').length,1);
   assert.ok(requests.filter(p=>p!=='/config.json').every(p=>p.endsWith('.json'+suffix)));
  }finally{
   globalThis.fetch=nativeFetch;
   await new Promise(r=>server.close(r));
  }
 });
}
