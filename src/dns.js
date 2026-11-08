'use strict';
// DNS-Filter-Server (AdGuard-ähnlich): UDP+TCP, Filterlisten in AdGuard-/Hosts-Syntax,
// Ausnahmeregeln, eigene Regeln, DNS-Umleitungen, SafeSearch, CNAME-Cloaking-Schutz,
// Cache, DoH/UDP-Upstreams, Abfrage-Log und Statistik.
const dgram = require('dgram');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const { EventEmitter } = require('events');
const { httpRequest, CidrMatcher, atomicWrite, ensureDir, stripV4Mapped } = require('./util');

const QT = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, NULL: 10, HTTPS: 65, ANY: 255 };
const QT_NAME = Object.fromEntries(Object.entries(QT).map(([k, v]) => [v, k]));

// ===================== DNS-Paket-Helfer =====================
function parseQuery(buf) {
  if (buf.length < 12) return null;
  const flags = buf.readUInt16BE(2);
  if (flags & 0x8000) return null; // Antworten ignorieren
  if (buf.readUInt16BE(4) < 1) return null;
  let off = 12;
  const labels = [];
  for (;;) {
    if (off >= buf.length) return null;
    const len = buf[off];
    if (len === 0) { off++; break; }
    if (len & 0xc0) return null;
    if (off + 1 + len > buf.length) return null;
    labels.push(buf.toString('latin1', off + 1, off + 1 + len));
    off += 1 + len;
    if (labels.length > 127) return null;
  }
  if (off + 4 > buf.length) return null;
  return {
    id: buf.readUInt16BE(0), flags, opcode: (flags >> 11) & 15,
    qname: labels.join('.').toLowerCase(), qtype: buf.readUInt16BE(off), qclass: buf.readUInt16BE(off + 2), qend: off + 4,
  };
}

function skipName(buf, off) {
  while (off < buf.length) {
    const len = buf[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2;
    off += 1 + len;
  }
  return -1;
}

function readName(buf, off) {
  const labels = [];
  let jumps = 0;
  while (off < buf.length) {
    const len = buf[off];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= buf.length || ++jumps > 20) return null;
      off = ((len & 0x3f) << 8) | buf[off + 1];
      continue;
    }
    if (off + 1 + len > buf.length) return null;
    labels.push(buf.toString('latin1', off + 1, off + 1 + len));
    off += 1 + len;
  }
  return labels.join('.').toLowerCase();
}

// Besucht alle Resource Records (Answer, Authority, Additional)
function walkRRs(buf, fn) {
  if (buf.length < 12) return false;
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  const ns = buf.readUInt16BE(8);
  const total = an + ns + buf.readUInt16BE(10);
  let off = 12;
  for (let i = 0; i < qd; i++) {
    off = skipName(buf, off);
    if (off < 0 || off + 4 > buf.length) return false;
    off += 4;
  }
  for (let i = 0; i < total; i++) {
    off = skipName(buf, off);
    if (off < 0 || off + 10 > buf.length) return false;
    const rdlen = buf.readUInt16BE(off + 8);
    if (off + 10 + rdlen > buf.length) return false;
    fn({ type: buf.readUInt16BE(off), ttlOff: off + 4, rdOff: off + 10, rdlen, section: i < an ? 'an' : i < an + ns ? 'ns' : 'ar' });
    off += 10 + rdlen;
  }
  return true;
}

function minTtl(buf) {
  let min = Infinity;
  if (!walkRRs(buf, (r) => { if (r.type !== 41 && r.section !== 'ar') min = Math.min(min, buf.readUInt32BE(r.ttlOff)); })) return null;
  return min === Infinity ? null : min;
}

function capTtl(buf, cap) {
  walkRRs(buf, (r) => {
    if (r.type === 41) return;
    if (buf.readUInt32BE(r.ttlOff) > cap) buf.writeUInt32BE(cap, r.ttlOff);
  });
}

function bufToIp6(b) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(b.readUInt16BE(i).toString(16));
  try { return new URL(`http://[${g.join(':')}]`).hostname.slice(1, -1); } catch (_) { return g.join(':'); }
}

function extractAnswers(buf) {
  const out = { cnames: [], ips: [] };
  walkRRs(buf, (r) => {
    if (r.section !== 'an') return;
    if (r.type === QT.CNAME) { const n = readName(buf, r.rdOff); if (n) out.cnames.push(n); }
    else if (r.type === QT.A && r.rdlen === 4) out.ips.push([...buf.subarray(r.rdOff, r.rdOff + 4)].join('.'));
    else if (r.type === QT.AAAA && r.rdlen === 16) out.ips.push(bufToIp6(buf.subarray(r.rdOff, r.rdOff + 16)));
  });
  return out;
}

function ednsInfo(buf, q) {
  const none = { present: false, size: 512, do: false };
  const n = buf.readUInt16BE(6) + buf.readUInt16BE(8) + buf.readUInt16BE(10);
  let off = q.qend;
  for (let i = 0; i < n; i++) {
    off = skipName(buf, off);
    if (off < 0 || off + 10 > buf.length) return none;
    if (buf.readUInt16BE(off) === 41) return { present: true, size: Math.max(512, buf.readUInt16BE(off + 2)), do: (buf.readUInt32BE(off + 4) & 0x8000) !== 0 };
    off += 10 + buf.readUInt16BE(off + 8);
  }
  return none;
}

function ipv6ToBuf(s) {
  const parse = (part) => (part ? part.split(':').flatMap((g) => {
    if (g.includes('.')) { const b = g.split('.').map(Number); return [(b[0] << 8) | b[1], (b[2] << 8) | b[3]]; }
    return [parseInt(g, 16)];
  }) : []);
  let groups;
  const dbl = s.indexOf('::');
  if (dbl >= 0) {
    const head = parse(s.slice(0, dbl));
    const tail = parse(s.slice(dbl + 2));
    groups = [...head, ...new Array(Math.max(0, 8 - head.length - tail.length)).fill(0), ...tail];
  } else groups = parse(s);
  const b = Buffer.alloc(16);
  groups.slice(0, 8).forEach((g, i) => b.writeUInt16BE(g & 0xffff, i * 2));
  return b;
}

function rr(type, ttl, rdata) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(0xc00c, 0); h.writeUInt16BE(type, 2); h.writeUInt16BE(1, 4); h.writeUInt32BE(ttl, 6); h.writeUInt16BE(rdata.length, 10);
  return Buffer.concat([h, rdata]);
}
const rrA = (ip, ttl) => rr(QT.A, ttl, Buffer.from(ip.split('.').map(Number)));
const rrAAAA = (ip, ttl) => rr(QT.AAAA, ttl, ipv6ToBuf(ip));

function buildReply(buf, q, rcode, answers = [], tc = false) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(q.id, 0);
  h.writeUInt16BE(0x8000 | (q.flags & 0x0100) | 0x0080 | (tc ? 0x0200 : 0) | (rcode & 15), 2);
  h.writeUInt16BE(1, 4);
  h.writeUInt16BE(answers.length, 6);
  return Buffer.concat([h, buf.subarray(12, q.qend), ...answers]);
}

function buildQuery(name, type) {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(crypto.randomBytes(2).readUInt16BE(0), 0);
  h.writeUInt16BE(0x0100, 2);
  h.writeUInt16BE(1, 4);
  const parts = name.split('.').filter(Boolean).map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')]));
  const tail = Buffer.alloc(5);
  tail.writeUInt16BE(type, 1);
  tail.writeUInt16BE(1, 3);
  return Buffer.concat([h, ...parts, tail]);
}

// ===================== Regel-Parser (AdGuard-/Hosts-Syntax) =====================
const HOST_RE = /^[a-z0-9_*]([a-z0-9_*.-]*[a-z0-9_*])?$/i;
const HOSTS_LINE_RE = /^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+([^#]+)/;
const SKIP_HOSTS = new Set(['localhost', 'localhost.localdomain', 'local', 'broadcasthost', '0.0.0.0']);

function wildcardToRegex(pat, suffix) {
  const body = pat.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[a-z0-9_.-]*');
  return new RegExp(suffix ? `^(?:.*\\.)?${body}$` : `^${body}$`, 'i');
}

function parseRule(raw) {
  let line = raw.trim();
  if (!line || line[0] === '!' || line[0] === '#' || line[0] === '[') return null;
  let allow = false;
  if (line.startsWith('@@')) { allow = true; line = line.slice(2); }
  let pattern = line;
  let modStr = '';
  const rm = line.match(/^(\/.+\/)\$([^/]+)$/);
  if (rm) { pattern = rm[1]; modStr = rm[2]; }
  else if (!(line.startsWith('/') && line.endsWith('/') && line.length > 2)) {
    const i = line.lastIndexOf('$');
    if (i > 0) { pattern = line.slice(0, i); modStr = line.slice(i + 1); }
  }
  let important = false;
  let types = null;
  for (const m of modStr.split(',').filter(Boolean)) {
    if (m === 'important') important = true;
    else if (/^dnstype=[A-Za-z0-9|]+$/.test(m)) types = m.slice(8).toUpperCase().split('|');
    else return null; // nicht unterstützter Modifikator → Regel ignorieren
  }
  if (pattern.length > 2 && pattern.startsWith('/') && pattern.endsWith('/')) {
    try { return { allow, kind: 'regex', regex: new RegExp(pattern.slice(1, -1), 'i'), value: pattern, important, types }; } catch (_) { return null; }
  }
  let kind = 'suffix';
  let body = pattern;
  if (body.startsWith('||')) body = body.slice(2);
  else if (body.startsWith('|')) { kind = 'exact'; body = body.slice(1); }
  body = body.replace(/\^\|?$/, '').replace(/\|$/, '').toLowerCase();
  if (!body || !HOST_RE.test(body)) return null; // URL-Pfad-Regeln sind für DNS irrelevant
  if (body.includes('*')) return { allow, kind: 'regex', regex: wildcardToRegex(body, kind === 'suffix'), value: pattern, important, types };
  return { allow, kind, value: body, important, types };
}

function parseLine(raw) {
  const hm = HOSTS_LINE_RE.exec(raw.trim());
  if (hm) {
    const out = [];
    for (const d of hm[1].trim().split(/\s+/)) {
      const dl = d.toLowerCase();
      if (SKIP_HOSTS.has(dl) || dl.startsWith('ip6-') || !HOST_RE.test(dl)) continue;
      out.push({ allow: false, kind: 'exact', value: dl, important: false, types: null });
    }
    return out;
  }
  const r = parseRule(raw);
  return r ? [r] : [];
}

class Filter {
  constructor() {
    this.blockSuffix = new Map(); this.blockExact = new Map();
    this.allowSuffix = new Map(); this.allowExact = new Map();
    this.impSuffix = new Map(); this.impExact = new Map();
    this.regex = []; this.typed = [];
    this.count = 0;
    this.names = []; this.cats = [];
  }
  addList(name, category) { this.names.push(name); this.cats.push(category); return this.names.length - 1; }
  add(rule, li) {
    this.count++;
    if (rule.types) { this.typed.push({ ...rule, list: li }); return; }
    if (rule.kind === 'regex') { if (this.regex.length < 5000) this.regex.push({ ...rule, list: li }); return; }
    const sfx = rule.kind === 'suffix';
    const m = rule.allow ? (sfx ? this.allowSuffix : this.allowExact)
      : rule.important ? (sfx ? this.impSuffix : this.impExact)
        : (sfx ? this.blockSuffix : this.blockExact);
    if (!m.has(rule.value)) m.set(rule.value, li);
  }
  _lookup(exactMap, suffixMap, cands) {
    if (exactMap.has(cands[0])) return { list: exactMap.get(cands[0]), rule: cands[0] };
    for (const c of cands) if (suffixMap.has(c)) return { list: suffixMap.get(c), rule: `||${c}^` };
    return null;
  }
  _special(domain, tname, allow) {
    for (const r of this.typed) {
      if (r.allow !== allow || !r.types.includes(tname)) continue;
      if (this._ruleHit(r, domain)) return { list: r.list, rule: `${r.value}$dnstype=${r.types.join('|')}` };
    }
    for (const r of this.regex) {
      if (r.allow === allow && r.regex.test(domain)) return { list: r.list, rule: r.value };
    }
    return null;
  }
  _ruleHit(r, d) {
    if (r.kind === 'regex') return r.regex.test(d);
    if (r.kind === 'exact') return d === r.value;
    return d === r.value || d.endsWith(`.${r.value}`);
  }
  match(domain, qtype) {
    const labels = domain.split('.');
    const cands = [];
    for (let i = 0; i < labels.length; i++) cands.push(labels.slice(i).join('.'));
    const tname = QT_NAME[qtype] || String(qtype);
    const wrap = (action, h) => ({ action, list: this.names[h.list], category: this.cats[h.list], rule: h.rule });
    let h = this._lookup(this.impExact, this.impSuffix, cands);
    if (h) return wrap('block', h);
    h = this._lookup(this.allowExact, this.allowSuffix, cands) || this._special(domain, tname, true);
    if (h) return wrap('allow', h);
    h = this._lookup(this.blockExact, this.blockSuffix, cands) || this._special(domain, tname, false);
    if (h) return wrap('block', h);
    return null;
  }
}

const BROWSER_DOH_CANARIES = new Set(['use-application-dns.net', 'mask.icloud.com', 'mask-h2.icloud.com']);

// Wiederverwendete TLS-Verbindungen zu DoH-Servern: spart bei jeder Abfrage den TLS-Handshake (oft 50–150 ms)
const DOH_AGENT = new https.Agent({ keepAlive: true, keepAliveMsecs: 30000, maxSockets: 8, maxFreeSockets: 4, timeout: 60000 });

// ===================== Upstream-Abfragen =====================
function queryUdp(host, port, buf, timeout = 2500) {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket(net.isIPv6(host) ? 'udp6' : 'udp4');
    const t = setTimeout(() => { try { s.close(); } catch (_) { /* egal */ } reject(new Error('Timeout')); }, timeout);
    const fail = (e) => { clearTimeout(t); try { s.close(); } catch (_) { /* egal */ } reject(e); };
    s.once('message', (m) => {
      clearTimeout(t);
      try { s.close(); } catch (_) { /* egal */ }
      if (m.length >= 12 && m.readUInt16BE(0) === buf.readUInt16BE(0)) resolve(m); else reject(new Error('ID passt nicht'));
    });
    s.once('error', fail);
    s.send(buf, port, host, (e) => { if (e) fail(e); });
  });
}

function queryTcp(host, port, buf, timeout = 4000) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    let acc = Buffer.alloc(0);
    const t = setTimeout(() => { s.destroy(); reject(new Error('Timeout')); }, timeout);
    s.on('connect', () => { const l = Buffer.alloc(2); l.writeUInt16BE(buf.length, 0); s.write(Buffer.concat([l, buf])); });
    s.on('data', (d) => {
      acc = Buffer.concat([acc, d]);
      if (acc.length >= 2 && acc.length >= 2 + acc.readUInt16BE(0)) { clearTimeout(t); s.destroy(); resolve(acc.subarray(2, 2 + acc.readUInt16BE(0))); }
    });
    s.on('error', (e) => { clearTimeout(t); reject(e); });
    s.on('close', () => { clearTimeout(t); reject(new Error('Verbindung geschlossen')); });
  });
}

const SAFE_SEARCH = {
  'www.google.com': 'forcesafesearch.google.com', 'google.com': 'forcesafesearch.google.com',
  'www.bing.com': 'strict.bing.com', 'duckduckgo.com': 'safe.duckduckgo.com',
  'www.youtube.com': 'restrict.youtube.com', 'm.youtube.com': 'restrict.youtube.com', 'youtube.com': 'restrict.youtube.com',
  'www.youtube-nocookie.com': 'restrict.youtube.com',
};

// "1.2.3.4", "1.2.3.4:5353", "2001:db8::1", "[2001:db8::1]:5353"
function parseUpstream(str) {
  const s = String(str).trim();
  let m = /^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$/.exec(s);
  if (!m) m = /^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?$/.exec(s);
  if (!m && net.isIPv6(s)) m = [s, s, undefined];
  if (!m || !net.isIP(m[1])) throw new Error(`Upstream "${s}" nicht verständlich`);
  return { host: m[1], port: m[2] ? parseInt(m[2], 10) : 53 };
}

// ===================== Server =====================
class DnsServer extends EventEmitter {
  constructor({ cfg, log, dataDir }) {
    super();
    this.cfg = cfg;
    this.log = log;
    this.dataDir = dataDir;
    this.filter = new Filter();
    this.listStatus = {};
    this.cache = new Map();
    this.qlog = [];
    this.rate = new Map();
    this.ssCache = new Map();
    this.up = [];
    this.udp = null;
    this.tcp = null;
    this.running = false;
    this.timers = [];
    this.stats = { total: 0, blocked: 0, ads: 0, cached: 0, errors: 0, refused: 0, started: Date.now() };
    this.hours = new Map();
    this.top = { domains: new Map(), blocked: new Map(), clients: new Map() };
    this.lastUpstreamWarn = 0;
  }

  d() { return this.cfg().dns; }

  configure() {
    const c = this.cfg();
    const d = c.dns;
    this.upstreams = d.upstreams.map((u) => String(u).trim()).filter(Boolean);
    this.up = this.upstreams.map((url) => ({ url, fails: 0, until: 0, last_ms: null, ok: null }));
    this.allow = new CidrMatcher(d.allowed_clients && d.allowed_clients.length ? d.allowed_clients : [...require('./wireguard').effectiveLan(c), '127.0.0.0/8', '::1/128']);
    this.rewrites = new Map(Object.entries(d.rewrites || {}).map(([k, v]) => [k.toLowerCase().replace(/\.$/, ''), String(v)]));
    this.cache.clear();
    this.rebuildFilter();
  }

  async start() {
    this.configure();
    await this.listen();
    this.running = true;
    this.updateLists(false).catch((e) => this.log.warn(`Listen-Update: ${e.message}`));
    this.timers.push(setInterval(() => this.updateLists(false).catch(() => {}), 30 * 60 * 1000));
    this.timers.push(setInterval(() => this.housekeeping(), 60000));
    this.probeUpstreams();
    this.timers.push(setInterval(() => this.probeUpstreams(), 5 * 60 * 1000));
    this.timers.forEach((t) => t.unref && t.unref());
  }

  async reload() {
    const d = this.d();
    const addr = this.udp && this.udp.address();
    this.configure();
    if (d.enabled && (!this.running || !addr || addr.port !== d.port || addr.address !== d.bind)) {
      await this.stop(true);
      await this.listen();
      this.running = true;
    } else if (!d.enabled && this.running) await this.stop(true);
  }

  listen() {
    const d = this.d();
    if (!d.enabled) { this.log.info('DNS-Filter ist deaktiviert'); return Promise.resolve(); }
    const udp = dgram.createSocket({ type: net.isIPv6(d.bind) ? 'udp6' : 'udp4' });
    const tcp = net.createServer((sock) => this.onTcp(sock));
    const bindUdp = new Promise((res, rej) => { udp.once('error', rej); udp.bind(d.port, d.bind, () => { udp.removeListener('error', rej); res(); }); });
    const bindTcp = new Promise((res, rej) => { tcp.once('error', rej); tcp.listen(d.port, d.bind, () => { tcp.removeListener('error', rej); res(); }); });
    return Promise.all([bindUdp, bindTcp]).then(() => {
      this.udp = udp;
      this.tcp = tcp;
      udp.on('message', (msg, rinfo) => {
        this.handle(msg, { address: rinfo.address }).then((r) => {
          if (!r) return;
          const q = parseQuery(msg);
          const lim = q ? ednsInfo(msg, q).size : 512;
          try { udp.send(r.length > lim && q ? buildReply(msg, q, 0, [], true) : r, rinfo.port, rinfo.address); } catch (_) { /* Socket beim Beenden schon zu */ }
        }).catch(() => {});
      });
      udp.on('error', (e) => this.log.error(`DNS-UDP: ${e.message}`));
      tcp.on('error', (e) => this.log.error(`DNS-TCP: ${e.message}`));
      this.log.info(`DNS-Filter lauscht auf ${d.bind}:${d.port} (UDP/TCP)`);
    }).catch((e) => {
      try { udp.close(); } catch (_) { /* egal */ }
      try { tcp.close(); } catch (_) { /* egal */ }
      if (e.code === 'EADDRINUSE') throw new Error(`Port ${d.port} ist belegt (läuft systemd-resolved/dnsmasq/AdGuard Home? Siehe README)`);
      throw e;
    });
  }

  onTcp(sock) {
    sock.setTimeout(8000);
    let acc = Buffer.alloc(0);
    sock.on('data', async (chunk) => {
      acc = Buffer.concat([acc, chunk]);
      if (acc.length > 131072) { sock.destroy(); return; }
      while (acc.length >= 2) {
        const len = acc.readUInt16BE(0);
        if (acc.length < 2 + len) break;
        const msg = acc.subarray(2, 2 + len);
        acc = acc.subarray(2 + len);
        const r = await this.handle(msg, { address: sock.remoteAddress || '' }).catch(() => null);
        if (r && !sock.destroyed) { const o = Buffer.alloc(2); o.writeUInt16BE(r.length, 0); sock.write(Buffer.concat([o, r])); }
      }
    });
    sock.on('error', () => {});
    sock.on('timeout', () => sock.destroy());
  }

  async stop(keepTimers = false) {
    this.running = false;
    if (!keepTimers) { this.timers.forEach(clearInterval); this.timers = []; }
    await new Promise((r) => { if (this.udp) { try { this.udp.close(r); } catch (_) { r(); } } else r(); });
    await new Promise((r) => { if (this.tcp) { try { this.tcp.close(() => r()); } catch (_) { r(); } } else r(); });
    this.udp = null;
    this.tcp = null;
  }

  // ---------- Filterlisten ----------
  rebuildFilter() {
    const t0 = Date.now();
    const d = this.d();
    const f = new Filter();
    for (const l of d.lists) {
      if (!l.enabled || !/^[a-z0-9_-]+$/i.test(l.id)) continue;
      const file = path.join(this.dataDir, 'lists', `${l.id}.txt`);
      let text;
      try { text = fs.readFileSync(file, 'utf8'); } catch (_) { continue; }
      const li = f.addList(l.name, l.category || 'other');
      const before = f.count;
      for (const line of text.split('\n')) for (const r of parseLine(line)) f.add(r, li);
      this.listStatus[l.id] = { ...(this.listStatus[l.id] || {}), rules: f.count - before, loaded: Date.now() };
    }
    const ci = f.addList('Eigene Regeln', 'custom');
    for (const line of d.custom_rules || []) for (const r of parseLine(line)) f.add(r, ci);
    this.filter = f;
    this.log.info(`DNS-Filter: ${f.count} Regeln geladen (${Date.now() - t0} ms)`);
  }

  async updateLists(force) {
    const d = this.d();
    const dir = path.join(this.dataDir, 'lists');
    ensureDir(dir);
    let changed = false;
    let failed = 0;
    for (const l of d.lists) {
      if (!l.enabled || !/^[a-z0-9_-]+$/i.test(l.id)) continue;
      const file = path.join(dir, `${l.id}.txt`);
      let age = Infinity;
      try { age = Date.now() - fs.statSync(file).mtimeMs; } catch (_) { /* noch nicht geladen */ }
      if (!force && age < d.list_update_hours * 3600000) continue;
      if (!force && age !== Infinity && this.listStatus[l.id] && this.listStatus[l.id].tried && Date.now() - this.listStatus[l.id].tried < 15 * 60000) continue;
      this.listStatus[l.id] = { ...(this.listStatus[l.id] || {}), tried: Date.now() };
      try {
        const r = await httpRequest(l.url, { timeout: 40000, maxBytes: 80 * 1024 * 1024 });
        if (r.status !== 200) throw new Error(`HTTP ${r.status}`);
        atomicWrite(file, r.body, 0o644);
        this.listStatus[l.id] = { ...this.listStatus[l.id], updated: Date.now(), error: null };
        changed = true;
      } catch (e) {
        failed++;
        this.listStatus[l.id] = { ...this.listStatus[l.id], error: e.message };
        this.log.warn(`Filterliste "${l.name}" konnte nicht geladen werden: ${e.message}`);
      }
    }
    if (changed) this.rebuildFilter();
    return { changed, failed };
  }

  // ---------- Abfragen ----------
  clientAllowed(ip) { return this.allow.has(ip); }

  rateLimited(ip) {
    const lim = this.d().rate_limit_qps;
    if (!lim) return false;
    const s = Math.floor(Date.now() / 1000);
    let r = this.rate.get(ip);
    if (!r || r.s !== s) {
      if (r && r.n > lim) this.emit('flood', { ip, qps: r.n });
      r = { s, n: 0 };
      this.rate.set(ip, r);
    }
    r.n++;
    return r.n > lim;
  }

  rewriteFor(d) {
    if (this.rewrites.has(d)) return this.rewrites.get(d);
    const labels = d.split('.');
    for (let i = 1; i < labels.length; i++) {
      const w = `*.${labels.slice(i).join('.')}`;
      if (this.rewrites.has(w)) return this.rewrites.get(w);
    }
    return null;
  }

  answerIp(buf, q, ip, ttl) {
    if (net.isIPv4(ip) && q.qtype === QT.A) return buildReply(buf, q, 0, [rrA(ip, ttl)]);
    if (net.isIPv6(ip) && q.qtype === QT.AAAA) return buildReply(buf, q, 0, [rrAAAA(ip, ttl)]);
    return buildReply(buf, q, 0, []);
  }

  blockReply(buf, q) {
    const mode = this.d().blocking_mode;
    if (mode === 'nxdomain') return buildReply(buf, q, 3);
    if (mode === 'refused') return buildReply(buf, q, 5);
    if (q.qtype === QT.A) return buildReply(buf, q, 0, [rrA('0.0.0.0', 10)]);
    if (q.qtype === QT.AAAA) return buildReply(buf, q, 0, [rrAAAA('::', 10)]);
    return buildReply(buf, q, 0, []);
  }

  async handle(buf, client) {
    const q = parseQuery(buf);
    if (!q) return null;
    const ip = stripV4Mapped(client.address);
    const rec = { t: Date.now(), c: ip, d: q.qname, qt: QT_NAME[q.qtype] || String(q.qtype), s: 'allowed', ms: 0 };
    const t0 = process.hrtime.bigint();
    let reply;
    try {
      if (!this.clientAllowed(ip)) { rec.s = 'refused'; reply = buildReply(buf, q, 5); }
      else if (this.rateLimited(ip)) return null;
      else if (q.opcode !== 0) reply = buildReply(buf, q, 4);
      else if (q.qclass !== 1) { rec.s = 'refused'; reply = buildReply(buf, q, 5); }
      else reply = await this.resolve(buf, q, rec);
    } catch (e) {
      rec.s = 'error';
      rec.r = e.message;
      reply = buildReply(buf, q, 2);
    }
    rec.ms = Math.round(Number(process.hrtime.bigint() - t0) / 1e5) / 10;
    rec.rc = reply[3] & 15;
    this.account(rec);
    return reply;
  }

  async resolve(buf, q, rec) {
    const d = this.d();
    const dom = q.qname;

    const rw = dom ? this.rewriteFor(dom) : null;
    if (rw) { rec.s = 'rewritten'; rec.r = `Umleitung → ${rw}`; return this.answerIp(buf, q, rw, 60); }

    if (d.safe_search && SAFE_SEARCH[dom] && (q.qtype === QT.A || q.qtype === QT.AAAA)) {
      try {
        const ips = (await this.resolveHost(SAFE_SEARCH[dom])).filter(net.isIPv4);
        if (ips.length) {
          rec.s = 'rewritten';
          rec.r = `SafeSearch → ${SAFE_SEARCH[dom]}`;
          return buildReply(buf, q, 0, q.qtype === QT.A ? ips.map((i) => rrA(i, 300)) : []);
        }
      } catch (_) { /* normal weiter */ }
    }

    if (d.disable_browser_doh && BROWSER_DOH_CANARIES.has(dom) && (q.qtype === QT.A || q.qtype === QT.AAAA || q.qtype === QT.HTTPS)) {
      rec.s = 'blocked'; rec.r = 'Browser-DoH-Schutz (Werbefilter nicht umgehbar)'; rec.cat = 'other';
      return buildReply(buf, q, 3);
    }
    const m = dom ? this.filter.match(dom, q.qtype) : null;
    if (m && m.action === 'block') {
      rec.s = 'blocked'; rec.r = `${m.list}: ${m.rule}`; rec.cat = m.category;
      return this.blockReply(buf, q);
    }
    if (m && m.action === 'allow') rec.r = `Erlaubt: ${m.list}: ${m.rule}`;

    const e = ednsInfo(buf, q);
    const key = `${dom}|${q.qtype}|${e.present ? 1 : 0}${e.do ? 'd' : ''}`;
    const cc = d.cache;
    if (cc.enabled) {
      const hit = this.cache.get(key);
      const nowMs = Date.now();
      if (hit && hit.exp > nowMs) {
        const out = Buffer.from(hit.buf);
        out.writeUInt16BE(q.id, 0);
        capTtl(out, Math.max(1, Math.round((hit.exp - nowMs) / 1000)));
        rec.s = 'cached';
        // Prefetch: läuft der Eintrag bald ab und wird er genutzt, im Hintergrund erneuern
        if (hit.exp - nowMs < hit.ttl * 100 && !hit.refreshing) this.refresh(key, buf, q, dom, m);
        return out;
      }
      // Abgelaufen, aber kürzlich: sofort (mit kurzer TTL) beantworten und im Hintergrund erneuern
      if (hit && cc.serve_stale !== false && nowMs - hit.exp < (cc.stale_max_s || 600) * 1000 && (hit.buf[3] & 15) === 0) {
        const out = Buffer.from(hit.buf);
        out.writeUInt16BE(q.id, 0);
        capTtl(out, 5);
        rec.s = 'cached'; rec.r = 'veraltet, wird erneuert';
        if (!hit.refreshing) this.refresh(key, buf, q, dom, m);
        return out;
      }
      if (hit && !hit.refreshing) this.cache.delete(key);
    }

    const { reply, upstream } = await this.forward(buf);
    rec.u = upstream;

    // CNAME-Cloaking: Ziel einer CNAME-Kette steht auf einer Blockliste → ganze Antwort blockieren
    if (!(m && m.action === 'allow')) {
      for (const cn of extractAnswers(reply).cnames) {
        const cm = this.filter.match(cn, q.qtype);
        if (cm && cm.action === 'block') {
          rec.s = 'blocked'; rec.r = `CNAME ${cn} – ${cm.list}: ${cm.rule}`; rec.cat = cm.category;
          return this.blockReply(buf, q);
        }
      }
    }

    this.cacheStore(key, reply);
    reply.writeUInt16BE(q.id, 0);
    return reply;
  }

  cacheStore(key, reply) {
    const cc = this.d().cache;
    const rcode = reply[3] & 15;
    if (!cc.enabled || !(rcode === 0 || rcode === 3) || (reply[2] & 0x02)) return;
    let ttl = minTtl(reply);
    if (ttl === null) ttl = 60;
    ttl = Math.min(cc.max_ttl, Math.max(cc.min_ttl, ttl));
    this.cache.set(key, { buf: Buffer.from(reply), exp: Date.now() + ttl * 1000, ttl });
    if (this.cache.size > cc.max_entries) this.cache.delete(this.cache.keys().next().value);
  }

  // Erneuert einen Cache-Eintrag im Hintergrund (Prefetch / Serve-Stale)
  refresh(key, buf, q, dom, m) {
    const hit = this.cache.get(key);
    if (hit) hit.refreshing = true;
    this.forward(Buffer.from(buf)).then(({ reply }) => {
      if (!(m && m.action === 'allow')) {
        for (const cn of extractAnswers(reply).cnames) {
          const cm = this.filter.match(cn, q.qtype);
          if (cm && cm.action === 'block') { this.cache.delete(key); return; }
        }
      }
      this.cacheStore(key, reply);
    }).catch(() => { const h = this.cache.get(key); if (h) h.refreshing = false; });
  }

  async resolveHost(name) {
    const hit = this.ssCache.get(name);
    if (hit && hit.exp > Date.now()) return hit.ips;
    const { reply } = await this.forward(buildQuery(name, QT.A));
    const ips = extractAnswers(reply).ips;
    this.ssCache.set(name, { ips, exp: Date.now() + 300000 });
    return ips;
  }

  // Einzelabfrage an einen Upstream; pflegt Latenz- und Fehlerstatistik
  async askUp(u, buf) {
    const t0 = Date.now();
    try {
      let reply;
      if (u.url.startsWith('https://')) reply = await this.queryDoh(u.url, buf);
      else {
        const { host, port } = parseUpstream(u.url);
        reply = await queryUdp(host, port, buf);
        if (reply[2] & 0x02) reply = await queryTcp(host, port, buf);
      }
      const ms = Date.now() - t0;
      u.fails = 0; u.until = 0; u.ok = true;
      u.last_ms = u.last_ms == null ? ms : Math.round(u.last_ms * 0.7 + ms * 0.3); // gleitender Mittelwert
      return { reply, upstream: u.url };
    } catch (e) {
      u.fails++; u.ok = false;
      u.until = Date.now() + Math.min(60000, 5000 * u.fails);
      throw e;
    }
  }

  // Schnellster Upstream zuerst; antwortet er langsam, wird parallel der nächste gefragt ("Hedging"),
  // die erste gültige Antwort gewinnt.
  forward(buf) {
    const now = Date.now();
    let order = this.up.filter((u) => u.until <= now);
    if (!order.length) order = [...this.up];
    // Ungemessene zuerst (damit sie gemessen werden), dann nach Latenz
    order.sort((x, y) => (x.last_ms == null ? -1 : x.last_ms) - (y.last_ms == null ? -1 : y.last_ms));
    if (!order.length) return Promise.reject(new Error('Kein Upstream-DNS-Server konfiguriert'));
    return new Promise((resolve, reject) => {
      let idx = 0; let pending = 0; let done = false; let timer = null;
      const started = new Map(); // u -> Startzeit, solange Antwort aussteht
      let lastErr = new Error('Alle Upstream-DNS-Server fehlgeschlagen');
      const launch = () => {
        if (done || idx >= order.length) return false;
        const u = order[idx++];
        pending++;
        started.set(u, Date.now());
        clearTimeout(timer);
        if (idx < order.length) timer = setTimeout(launch, Math.max(120, Math.min(1000, (u.last_ms || 60) * 2.5)));
        this.askUp(u, buf).then((r) => {
          pending--;
          started.delete(u);
          if (done) return;
          done = true; clearTimeout(timer);
          // Wer noch nicht geantwortet hat, ist mindestens so langsam wie die bisherige Wartezeit
          for (const [w, t0] of started) w.last_ms = Math.max(w.last_ms || 0, Date.now() - t0);
          resolve(r);
        }, (e) => {
          pending--;
          started.delete(u);
          lastErr = e;
          if (done) return;
          if (!launch() && pending === 0) {
            done = true; clearTimeout(timer);
            if (Date.now() - this.lastUpstreamWarn > 60000) {
              this.lastUpstreamWarn = Date.now();
              this.log.warn(`Alle Upstream-DNS-Server fehlgeschlagen: ${lastErr.message}`);
            }
            reject(lastErr);
          }
        });
        return true;
      };
      launch();
    });
  }

  // Hält die Latenzwerte aktuell, damit immer der schnellste Server zuerst gefragt wird
  probeUpstreams() {
    const q = buildQuery('.', QT.NS || 2);
    for (const u of this.up) { if (u.until <= Date.now()) this.askUp(u, q).catch(() => {}); }
  }

  async queryDoh(url, buf) {
    const host = new URL(url).hostname;
    const bootstrap = (this.d().bootstrap || {})[host];
    const r = await httpRequest(url, {
      method: 'POST', body: buf, ip: bootstrap || null, timeout: 4000, maxBytes: 70000, agent: DOH_AGENT,
      headers: { 'Content-Type': 'application/dns-message', Accept: 'application/dns-message' },
    });
    if (r.status !== 200 || r.body.length < 12) throw new Error(`DoH HTTP ${r.status}`);
    const out = Buffer.from(r.body);
    out.writeUInt16BE(buf.readUInt16BE(0), 0);
    return out;
  }

  // ---------- Statistik ----------
  bump(map, key) {
    map.set(key, (map.get(key) || 0) + 1);
    if (map.size > 20000) for (const [k, v] of map) if (v <= 1) map.delete(k);
  }

  account(rec) {
    const st = this.stats;
    st.total++;
    if (rec.s === 'blocked') { st.blocked++; if (rec.cat === 'ads') st.ads++; }
    else if (rec.s === 'cached') st.cached++;
    else if (rec.s === 'error') st.errors++;
    else if (rec.s === 'refused') st.refused++;
    const hk = Math.floor(rec.t / 3600000) * 3600000;
    let h = this.hours.get(hk);
    if (!h) { h = { total: 0, blocked: 0 }; this.hours.set(hk, h); }
    h.total++;
    if (rec.s === 'blocked') h.blocked++;
    this.bump(rec.s === 'blocked' ? this.top.blocked : this.top.domains, rec.d);
    this.bump(this.top.clients, rec.c);
    const d = this.d();
    if (d.log_queries) {
      this.qlog.push(rec);
      const max = d.log_memory || 5000;
      if (this.qlog.length > max * 1.2) this.qlog.splice(0, this.qlog.length - max);
    }
    this.emit('query', rec);
  }

  housekeeping() {
    const now = Date.now();
    for (const [k, v] of this.rate) if (now - v.s * 1000 > 5000) this.rate.delete(k);
    for (const [k, v] of this.cache) if (v.exp < now) this.cache.delete(k);
    for (const k of this.hours.keys()) if (now - k > 48 * 3600000) this.hours.delete(k);
  }

  topN(map, n = 10) { return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([name, count]) => ({ name, count })); }

  getStats() {
    const st = this.stats;
    const now = Date.now();
    const base = Math.floor(now / 3600000) * 3600000;
    const hours = [];
    for (let i = 23; i >= 0; i--) { const t = base - i * 3600000; const h = this.hours.get(t) || { total: 0, blocked: 0 }; hours.push({ t, ...h }); }
    return {
      running: this.running, total: st.total, blocked: st.blocked, ads: st.ads, cached: st.cached, errors: st.errors, refused: st.refused,
      blocked_pct: st.total ? Math.round((st.blocked / st.total) * 1000) / 10 : 0,
      started: st.started, hours,
      top_domains: this.topN(this.top.domains), top_blocked: this.topN(this.top.blocked), top_clients: this.topN(this.top.clients),
      rules: this.filter.count, cache_size: this.cache.size,
      upstreams: this.up.map((u) => ({ url: u.url, ok: u.ok, ms: u.last_ms, fails: u.fails })),
      lists: this.d().lists.map((l) => ({ id: l.id, name: l.name, enabled: l.enabled, category: l.category, ...(this.listStatus[l.id] || {}) })),
    };
  }

  queryLog(limit = 200, { q = '', status = '' } = {}) {
    const f = q.toLowerCase();
    const out = [];
    for (let i = this.qlog.length - 1; i >= 0 && out.length < limit; i--) {
      const r = this.qlog[i];
      if (status && r.s !== status) continue;
      if (f && !(r.d.includes(f) || r.c.includes(f))) continue;
      out.push(r);
    }
    return out;
  }

  // Für den "Domain testen"-Dialog
  check(domain, type = 'A') {
    const dom = String(domain).toLowerCase().replace(/\.$/, '');
    const rw = this.rewriteFor(dom);
    if (rw) return { domain: dom, result: 'rewritten', detail: `→ ${rw}` };
    const m = this.filter.match(dom, QT[type.toUpperCase()] || 1);
    if (!m) return { domain: dom, result: 'allowed', detail: 'Keine Regel trifft zu' };
    return { domain: dom, result: m.action === 'block' ? 'blocked' : 'allowed', detail: `${m.list}: ${m.rule}`, category: m.category };
  }
}

module.exports = { DnsServer, Filter, parseRule, parseLine, parseQuery, buildReply, buildQuery, extractAnswers, QT, QT_NAME };
