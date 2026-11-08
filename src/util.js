'use strict';
// Gemeinsame Hilfsfunktionen (keine externen Abhängigkeiten)
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { execFile } = require('child_process');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function isObj(x) { return x !== null && typeof x === 'object' && !Array.isArray(x); }

function deepMerge(base, over) {
  const out = Array.isArray(base) ? base.slice() : { ...base };
  if (!isObj(over)) return out;
  for (const [k, v] of Object.entries(over)) {
    if (isObj(v) && isObj(out[k])) out[k] = deepMerge(out[k], v);
    else out[k] = v;
  }
  return out;
}

const clone = (o) => JSON.parse(JSON.stringify(o));

function ensureDir(dir, mode = 0o755) {
  fs.mkdirSync(dir, { recursive: true, mode });
}

function atomicWrite(file, data, mode = 0o600) {
  ensureDir(path.dirname(file));
  const tmp = `${file}.tmp${process.pid}`;
  fs.writeFileSync(tmp, data, { mode });
  fs.renameSync(tmp, file);
}

// Führt ein Programm aus. Wirft nie, liefert {code, stdout, stderr}.
function run(cmd, args = [], opts = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: opts.timeout || 30000, maxBuffer: opts.maxBuffer || 32 * 1024 * 1024, env: opts.env || process.env }, (err, stdout, stderr) => {
      let code = 0;
      if (err) code = typeof err.code === 'number' ? err.code : (err.killed ? 124 : 127);
      resolve({ code, stdout: String(stdout || ''), stderr: String(stderr || ''), error: err || null });
    });
  });
}

async function commandExists(cmd) {
  const r = await run('sh', ['-c', `command -v ${cmd}`], { timeout: 5000 });
  return r.code === 0 && r.stdout.trim().length > 0;
}

// HTTP(S)-Request mit Größenlimit, Timeout und Redirects (nur GET).
// opts.ip: verbindet direkt zu dieser IP, TLS-Servername/Host-Header bleiben der Hostname (Bootstrap für DoH).
function httpRequest(urlStr, opts = {}) {
  const { method = 'GET', headers = {}, body = null, timeout = 15000, maxBytes = 64 * 1024 * 1024, redirects = 5, ip = null, agent = null } = opts;
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch (e) { return reject(e); }
    const lib = u.protocol === 'https:' ? https : http;
    const h = { 'User-Agent': 'netguard/1.0', ...headers };
    let payload = body;
    if (payload !== null && typeof payload !== 'string' && !Buffer.isBuffer(payload)) {
      payload = JSON.stringify(payload);
      h['Content-Type'] = h['Content-Type'] || 'application/json';
    }
    if (payload !== null) h['Content-Length'] = Buffer.byteLength(payload);
    const hostname = u.hostname.replace(/^\[|\]$/g, '');
    const o = {
      method, headers: h, path: u.pathname + u.search, timeout,
      host: ip || hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
    };
    if (ip) { o.servername = hostname; h.Host = u.host; }
    if (agent) o.agent = agent;
    const req = lib.request(o, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0 && method === 'GET') {
        res.resume();
        return resolve(httpRequest(new URL(res.headers.location, u).toString(), { ...opts, redirects: redirects - 1, ip: null }));
      }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) { req.destroy(new Error('Antwort zu groß')); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('Timeout')));
    req.on('error', reject);
    if (payload !== null) req.write(payload);
    req.end();
  });
}

// ---------- IP-Helfer ----------
const stripV4Mapped = (ip) => (typeof ip === 'string' && ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7)) ? ip.slice(7) : ip);

class CidrMatcher {
  constructor(list = []) {
    this.bl = new net.BlockList();
    this.count = 0;
    this.add(list);
  }
  add(list) {
    for (const item of list) {
      const s = String(item).trim();
      if (!s) continue;
      try {
        const [a, p] = s.split('/');
        const fam = net.isIP(a);
        if (!fam) continue;
        const t = fam === 4 ? 'ipv4' : 'ipv6';
        if (p === undefined) this.bl.addAddress(a, t);
        else this.bl.addSubnet(a, parseInt(p, 10), t);
        this.count++;
      } catch (_) { /* ungültiger Eintrag */ }
    }
    return this;
  }
  has(ip) {
    ip = stripV4Mapped(ip);
    const fam = net.isIP(ip);
    if (!fam) return false;
    try { return this.bl.check(ip, fam === 4 ? 'ipv4' : 'ipv6'); } catch (_) { return false; }
  }
}

const PRIVATE_CIDRS = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4', '::1/128', 'fe80::/10', 'fc00::/7', 'ff00::/8'];
const privateMatcher = new CidrMatcher(PRIVATE_CIDRS);
const isPrivateIp = (ip) => privateMatcher.has(ip);

function localAddresses() {
  const set = new Set(['127.0.0.1', '::1']);
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list || []) set.add(a.address.replace(/%.*$/, ''));
  }
  return set;
}

function hexToIp4(h) {
  const n = parseInt(h, 16);
  return [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255].join('.');
}

function defaultGateway() {
  try {
    const lines = fs.readFileSync('/proc/net/route', 'utf8').split('\n').slice(1);
    for (const l of lines) {
      const f = l.trim().split(/\s+/);
      if (f.length > 7 && f[1] === '00000000' && (parseInt(f[3], 16) & 2)) return { iface: f[0], gw: hexToIp4(f[2]) };
    }
  } catch (_) { /* kein Linux / keine Route */ }
  return null;
}

const validIface = (n) => typeof n === 'string' && /^[a-zA-Z0-9_.:@-]{1,15}$/.test(n);

function toPorts(arr) {
  const out = new Set();
  for (const p of Array.isArray(arr) ? arr : []) {
    const n = parseInt(p, 10);
    if (n >= 1 && n <= 65535) out.add(n);
  }
  return [...out].sort((a, b) => a - b);
}

function splitByFamily(list) {
  const v4 = []; const v6 = [];
  for (const item of list || []) {
    const a = String(item).trim().split('/')[0];
    const f = net.isIP(a);
    if (f === 4) v4.push(String(item).trim());
    else if (f === 6) v6.push(String(item).trim());
  }
  return { v4, v6 };
}

// ---------- Dateien ----------
function tailFile(file, bytes = 256 * 1024) {
  try {
    const st = fs.statSync(file);
    const start = Math.max(0, st.size - bytes);
    const fd = fs.openSync(file, 'r');
    const buf = Buffer.alloc(st.size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    fs.closeSync(fd);
    const lines = buf.toString('utf8').split('\n');
    if (start > 0) lines.shift();
    return lines.filter(Boolean);
  } catch (_) { return []; }
}

function rotateIfBig(file, maxBytes = 10 * 1024 * 1024, keep = 3) {
  try {
    if (fs.statSync(file).size < maxBytes) return;
    for (let i = keep - 1; i >= 1; i--) {
      if (fs.existsSync(`${file}.${i}`)) fs.renameSync(`${file}.${i}`, `${file}.${i + 1}`);
    }
    fs.renameSync(file, `${file}.1`);
  } catch (_) { /* Datei existiert noch nicht */ }
}

function hashFile(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(file);
    s.on('data', (d) => h.update(d));
    s.on('end', () => resolve(h.digest('hex')));
    s.on('error', reject);
  });
}

function formatDuration(sec) {
  sec = Math.round(sec);
  if (sec < 90) return `${sec} s`;
  if (sec < 5400) return `${Math.round(sec / 60)} min`;
  if (sec < 172800) return `${Math.round(sec / 3600)} h`;
  return `${Math.round(sec / 86400)} d`;
}

const asciiFold = (s) => String(s).replace(/ä/g, 'ae').replace(/ö/g, 'oe').replace(/ü/g, 'ue').replace(/Ä/g, 'Ae').replace(/Ö/g, 'Oe').replace(/Ü/g, 'Ue').replace(/ß/g, 'ss').replace(/[^\x20-\x7e]/g, '?');

// Shannon-Entropie eines Strings (Bit pro Zeichen)
function entropy(s) {
  if (!s) return 0;
  const f = new Map();
  for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let e = 0;
  for (const n of f.values()) { const p = n / s.length; e -= p * Math.log2(p); }
  return e;
}

module.exports = {
  sleep, isObj, deepMerge, clone, ensureDir, atomicWrite, run, commandExists, httpRequest,
  stripV4Mapped, CidrMatcher, isPrivateIp, localAddresses, hexToIp4, defaultGateway, validIface,
  toPorts, splitByFamily, tailFile, rotateIfBig, hashFile, formatDuration, asciiFold, entropy,
};
