import {chromium} from 'playwright';import assert from 'node:assert/strict';import {createServer} from 'node:http';import fs from 'node:fs/promises';import os from 'node:os';import path from 'node:path';import {fileURLToPath} from 'node:url';
const base=path.dirname(fileURLToPath(import.meta.url)),extension=path.resolve(base,'../../browser-extension');
const profile=await fs.mkdtemp(path.join(os.tmpdir(),'sentinella-web-test-'));
const server=createServer((request,response)=>{response.writeHead(200,{'Content-Type':'text/html'});response.end('<!doctype html><title>Harmless fixture</title><p>Sentinella browser fixture</p>');});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const port=server.address().port;
let context;let checks=0;function check(value,name){assert.ok(value,name);checks++;console.log('PASS: '+name);}
try{
 context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`,'--host-resolver-rules=MAP *.test 127.0.0.1','--no-proxy-server']});
 let worker=context.serviceWorkers()[0];if(!worker)worker=await context.waitForEvent('serviceworker');const id=new URL(worker.url()).hostname;
 const options=await context.newPage();await options.goto(`chrome-extension://${id}/options.html`);
 await options.locator('#enabled').check();await options.locator('#blocked').fill('bad.test');await options.locator('#save').click();await options.waitForFunction(()=>document.getElementById('status').textContent.includes('1 domini'));
 const browserErrors=await worker.evaluate(()=>chrome.declarativeNetRequest.getDynamicRules());check(browserErrors.length===1,'browser accepts generated native rules');
 async function blocked(host){const p=await context.newPage();try{await p.goto(`http://${host}:${port}/`,{timeout:10000});return false;}catch(e){if(!String(e.message).includes('ERR_BLOCKED_BY_CLIENT'))throw e;return true;}finally{await p.close();}}
 check(await blocked('bad.test'),'configured domain blocked before navigation');check(await blocked('sub.bad.test'),'subdomain blocked');check(!(await blocked('notbad.test')),'similar unrelated domain remains accessible');
 await options.locator('#allowed').fill('bad.test');await options.locator('#save').click();await options.waitForFunction(()=>!document.getElementById('save').disabled);check(!(await blocked('bad.test')),'explicit exception allows the domain');
 await options.locator('#allowed').fill('');await options.locator('#blocked').fill('new.test');await options.locator('#save').click();await options.waitForFunction(()=>!document.getElementById('save').disabled);check(!(await blocked('bad.test')),'removed block no longer applies');check(await blocked('new.test'),'replacement list is effective');
 await options.locator('#enabled').uncheck();await options.locator('#save').click();await options.waitForFunction(()=>!document.getElementById('save').disabled);check(!(await blocked('new.test')),'user disabling the test extension configuration removes its rules');
 console.log(`RESULT: ${checks} browser checks passed. Isolated temporary profile; local harmless HTTP fixtures; no personal browser modified.`);
}finally{await context?.close();await new Promise(resolve=>server.close(resolve));const full=path.resolve(profile);if(path.dirname(full)!==path.resolve(os.tmpdir())||!path.basename(full).startsWith('sentinella-web-test-'))throw new Error('Unsafe test cleanup');await fs.rm(full,{recursive:true,force:true});}
