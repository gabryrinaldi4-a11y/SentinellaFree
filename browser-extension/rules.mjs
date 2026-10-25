export const MAX_DOMAINS = 250000;
export const TYPES = ['main_frame','sub_frame','stylesheet','script','image','font','object','xmlhttprequest','ping','csp_report','media','websocket','webtransport','webbundle','other'];
export function normalizeDomain(input) {
  const value = String(input).trim();
  if (!value || value.length > 253 || /[\s/@:*?#%\[\]\\]/.test(value)) throw new Error('Inserisci solo nomi di dominio, senza URL o caratteri jolly.');
  const host = new URL('https://' + value).hostname.toLowerCase().replace(/\.$/,'');
  if (host.length > 253 || host === 'localhost' || /^\d+(\.\d+){3}$/.test(host) || !host.includes('.') || host.split('.').some(x => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))) throw new Error('Dominio non valido.');
  return host;
}
export function parseDomains(text) {
  if (typeof text !== 'string' || text.length > 8 * 1024 * 1024) throw new Error('Elenco oltre 8 MiB.');
  const set = new Set();
  for (const line of text.split(/\r?\n/)) {
    const value = line.trim(); if (!value || value.startsWith('#')) continue;
    set.add(normalizeDomain(value)); if (set.size > MAX_DOMAINS) throw new Error('Troppi domini; elenco precedente mantenuto.');
  }
  return [...set].sort();
}
export function createRules(blocked, allowed) {
  if (blocked.length + allowed.length > MAX_DOMAINS) throw new Error('Troppi domini.');
  let id = 1; const rules = [];
  for (const [values, action, priority] of [[allowed,'allow',2],[blocked,'block',1]]) {
    const domains = [...new Set(values.map(normalizeDomain))].sort();
    for (let index = 0; index < domains.length; index += 200)
      rules.push({id:id++,priority,action:{type:action},condition:{requestDomains:domains.slice(index,index+200),resourceTypes:TYPES}});
  }
  return rules;
}
