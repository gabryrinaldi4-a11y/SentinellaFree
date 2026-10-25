import {parseDomains, createRules} from './rules.mjs';
const FEED='https://hole.cert.pl/domains/v2/domains.txt';
let serial=Promise.resolve();
function exclusive(action) { const next=serial.then(action); serial=next.catch(()=>{}); return next; }
async function downloadFeed() {
  const response=await fetch(FEED,{credentials:'omit',cache:'no-store',redirect:'error',signal:AbortSignal.timeout(30000)});
  if(!response.ok || Number(response.headers.get('content-length')||0)>8*1024*1024) throw new Error('Lista CERT non disponibile o troppo grande.');
  const reader=response.body.getReader(); const decoder=new TextDecoder('utf-8',{fatal:true}); let size=0,text='';
  try { for(;;) { const {done,value}=await reader.read(); if(done)break; size+=value.length; if(size>8*1024*1024)throw new Error('Lista oltre 8 MiB.'); text+=decoder.decode(value,{stream:true}); } text+=decoder.decode(); }
  finally { await reader.cancel().catch(()=>{}); }
  const domains=parseDomains(text); if(domains.length<10)throw new Error('Lista CERT vuota o anomala: regole precedenti mantenute.');
  return domains;
}
async function apply(config, refresh) {
  const saved=await chrome.storage.local.get(['feedDomains','feedUpdated']);
  let domains=saved.feedDomains||[], updated=saved.feedUpdated||null;
  if(config.enabled && config.useCert && refresh) { domains=await downloadFeed(); updated=new Date().toISOString(); }
  if(config.enabled && config.useCert && !domains.length)throw new Error('Aggiorna prima la lista CERT o disattiva quella sorgente.');
  const blocked=config.enabled ? [...new Set([...parseDomains(config.blocked||''),...(config.useCert?domains:[])])] : [];
  if(config.enabled&&!blocked.length)throw new Error('Nessun dominio da bloccare: configura un elenco prima di attivare il filtro.');
  const rules=createRules(blocked,config.enabled?parseDomains(config.allowed||''):[]);
  const old=await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:old.map(x=>x.id),addRules:rules});
  await chrome.storage.local.set({config,feedDomains:domains,feedUpdated:updated,status:{enabled:config.enabled,domains:blocked.length,rules:rules.length,feedUpdated:updated,error:null}});
  await chrome.storage.local.remove('lastError');
  await chrome.alarms.clear('cert-refresh');
  if(config.enabled && config.useCert && config.autoUpdate) await chrome.alarms.create('cert-refresh',{periodInMinutes:5});
  await chrome.action.setBadgeText({text:config.enabled?'ON':''});
}
chrome.action.onClicked.addListener(()=>chrome.runtime.openOptionsPage());
async function reportError(error){await chrome.storage.local.set({lastError:String(error.message)});await chrome.action.setBadgeText({text:'!'});}
chrome.runtime.onMessage.addListener((message,sender,reply)=>{
  if(sender.id!==chrome.runtime.id || sender.url!==chrome.runtime.getURL('options.html') || message?.action!=='save')return;
  exclusive(()=>apply(message.config,Boolean(message.refresh))).then(()=>reply({ok:true})).catch(async error=>{await reportError(error);reply({ok:false,error:String(error.message)});}); return true;
});
chrome.alarms.onAlarm.addListener(alarm=>{if(alarm.name==='cert-refresh')exclusive(async()=>{const {config}=await chrome.storage.local.get('config'); if(config?.enabled&&config.useCert&&config.autoUpdate)await apply(config,true);}).catch(reportError);});
chrome.runtime.onStartup.addListener(()=>exclusive(async()=>{const {config}=await chrome.storage.local.get('config');if(config)await apply(config,Boolean(config.enabled&&config.useCert&&config.autoUpdate));}).catch(reportError));
