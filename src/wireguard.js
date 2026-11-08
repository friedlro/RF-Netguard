'use strict';
// WireGuard-VPN-Server: Schlüssel, Teilnehmer (Peers), Schnittstelle und Client-Konfigurationen.
// Voraussetzung auf dem Rechner: Paket "wireguard-tools" (Befehl "wg") und das Kernelmodul wireguard (Standard bei Ubuntu/Debian).
// Die Firewall-Regeln für das VPN (Port, Forwarding, NAT) erzeugt firewall.js anhand der gleichen Konfiguration.
const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const { run, ensureDir, validIface } = require('./util');

const b64 = (buf) => Buffer.from(buf).toString('base64');
const B64_KEY = /^[A-Za-z0-9+/]{43}=$/;

// ---------- Schlüssel (X25519 im WireGuard-Format, ohne "wg genkey") ----------
function genKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  const priv = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32);
  const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { private_key: b64(priv), public_key: b64(pub) };
}
function genPsk() { return b64(crypto.randomBytes(32)); }
function pubFromPriv(privB64) {
  const raw = Buffer.from(privB64, 'base64');
  if (raw.length !== 32) throw new Error('Ungültiger privater Schlüssel');
  // PKCS#8-Hülle für X25519 + 32 Byte Schlüssel
  const der = Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), raw]);
  const pk = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  return b64(crypto.createPublicKey(pk).export({ format: 'der', type: 'spki' }).subarray(-32));
}

// ---------- IPv4-Helfer ----------
const ip2n = (ip) => ip.split('.').reduce((a, o) => ((a << 8) | Number(o)) >>> 0, 0) >>> 0;
const n2ip = (n) => `${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;

function parseAddress(addr) { // "10.66.0.1/24" → { ip, prefix, net, mask, cidr }
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(addr || ''));
  if (!m || !net.isIPv4(m[1])) return null;
  const prefix = Number(m[2]);
  if (prefix < 8 || prefix > 30) return null;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const n = (ip2n(m[1]) & mask) >>> 0;
  return { ip: m[1], prefix, net: n2ip(n), mask, base: n, cidr: `${n2ip(n)}/${prefix}` };
}

// Netz des VPN (z. B. "10.66.0.0/24"), sonst null
function wgSubnet(cfg) { const w = cfg.wireguard; return w && w.enabled ? (parseAddress(w.address) || {}).cidr || null : null; }

// Interne Netze: eigenes LAN plus (optional) das VPN-Netz – hier dürfen die Dienste dieses Rechners erreicht werden
function effectiveLan(cfg) {
  const w = cfg.wireguard;
  const list = [...cfg.lan_cidrs];
  const s = wgSubnet(cfg);
  if (s && w.access_host !== false && !list.includes(s)) list.push(s);
  return list;
}

// IPv4-Netze, die VPN-Clients im LAN erreichen dürfen: explizit (wireguard.lan_routes) oder automatisch die LAN-Netze ab /20 –
// die breiten Standard-Bereiche (10/8, 172.16/12, 192.168/16) würden sonst das lokale Netz der Clients selbst umleiten.
function lanRoutes(cfg) {
  const w = cfg.wireguard;
  const norm = (c) => { const m = /^(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?$/.exec(String(c).trim()); if (!m || !net.isIPv4(m[1])) return null; const p = m[2] === undefined ? 32 : Number(m[2]); return p <= 32 ? { ip: m[1], p } : null; };
  const explicit = (w.lan_routes || []).map(norm).filter(Boolean);
  const list = explicit.length ? explicit : cfg.lan_cidrs.map(norm).filter((x) => x && x.p >= 20);
  return [...new Set(list.map((x) => (x.p === 32 ? `${x.ip}/32` : `${n2ip((ip2n(x.ip) & ((0xffffffff << (32 - x.p)) >>> 0)) >>> 0)}/${x.p}`)))];
}

function nextFreeAddress(w) {
  const a = parseAddress(w.address);
  if (!a) throw new Error('Ungültige VPN-Adresse');
  const used = new Set([ip2n(a.ip), ...w.peers.map((p) => ip2n(String(p.address).split('/')[0]))]);
  const first = a.base + 1; const last = (a.base | (~a.mask >>> 0)) - 1;
  for (let n = first; n <= last; n++) if (!used.has(n >>> 0)) return n2ip(n >>> 0);
  throw new Error('Im VPN-Netz sind keine Adressen mehr frei');
}

const cleanName = (s) => String(s || '').trim().replace(/[^\p{L}\p{N} ._-]/gu, '').slice(0, 40);

// ---------- Konfigurationen ----------
// Serverseitige Datei für "wg setconf" (nur Schlüssel/Peers, ohne Adresse)
function serverConf(w) {
  let s = `[Interface]\nPrivateKey = ${w.private_key}\nListenPort = ${w.listen_port}\n`;
  for (const p of w.peers) {
    if (p.enabled === false) continue;
    s += `\n[Peer]\n# ${cleanName(p.name)}\nPublicKey = ${p.public_key}\n`;
    if (p.preshared_key) s += `PresharedKey = ${p.preshared_key}\n`;
    s += `AllowedIPs = ${String(p.address).split('/')[0]}/32\n`;
  }
  return s;
}

function clientAllowedIps(cfg) {
  const w = cfg.wireguard; const a = parseAddress(w.address);
  if (w.routing.internet) return '0.0.0.0/0, ::/0'; // ::/0 verhindert IPv6-Umgehung des Tunnels
  const nets = [a.cidr];
  if (w.routing.access_lan) nets.push(...lanRoutes(cfg));
  return [...new Set(nets)].join(', ');
}

function clientConf(cfg, peer) {
  const w = cfg.wireguard; const a = parseAddress(w.address);
  if (!peer || !peer.private_key) throw new Error('Unbekannter Teilnehmer');
  const dns = w.client_dns || (cfg.dns.enabled ? a.ip : '');
  const endpoint = w.endpoint || `SERVER-ADRESSE:${w.listen_port}`;
  let s = `[Interface]\n# ${cleanName(peer.name)}\nPrivateKey = ${peer.private_key}\nAddress = ${String(peer.address).split('/')[0]}/32\n`;
  if (dns) s += `DNS = ${dns}\n`;
  if (w.mtu) s += `MTU = ${w.mtu}\n`;
  s += `\n[Peer]\nPublicKey = ${pubFromPriv(w.private_key)}\n`;
  if (peer.preshared_key) s += `PresharedKey = ${peer.preshared_key}\n`;
  s += `AllowedIPs = ${clientAllowedIps(cfg)}\nEndpoint = ${/:\d+$/.test(endpoint) ? endpoint : `${endpoint}:${w.listen_port}`}\n`;
  if (w.keepalive) s += `PersistentKeepalive = ${w.keepalive}\n`;
  return s;
}

// "wg show <if> dump" auswerten
function parseDump(text) {
  const lines = String(text || '').trim().split('\n').filter(Boolean);
  if (!lines.length) return { peers: [] };
  const i = lines[0].split('\t');
  const peers = lines.slice(1).map((l) => {
    const f = l.split('\t');
    return { public_key: f[0], endpoint: f[2] === '(none)' ? '' : f[2], allowed_ips: f[3], latest_handshake: Number(f[4]) * 1000 || 0, rx: Number(f[5]) || 0, tx: Number(f[6]) || 0 };
  });
  return { public_key: i[1], listen_port: Number(i[2]) || 0, peers };
}

class WireGuard {
  constructor({ cfg, log }) { this.cfg = cfg; this.log = log; this.lastError = ''; this.active = false; }

  w() { return this.cfg().wireguard; }

  async available() { return (await run('sh', ['-c', 'command -v wg'], { timeout: 5000 })).code === 0; }

  // Schnittstelle gemäß Konfiguration herstellen (oder entfernen)
  async apply() {
    const w = this.w();
    const ifn = w.interface;
    if (!validIface(ifn)) { this.lastError = 'Ungültiger Schnittstellenname'; return false; }
    if (!w.enabled) { await this.stop(); return true; }
    try {
      if (!(await this.available())) throw new Error('"wg" nicht gefunden – bitte das Paket wireguard-tools installieren (sudo apt install wireguard-tools)');
      if (!B64_KEY.test(w.private_key || '')) throw new Error('Kein Server-Schlüssel vorhanden');
      const a = parseAddress(w.address);
      if (!a) throw new Error('Ungültige VPN-Adresse');
      const runDir = this.cfg().paths.run; ensureDir(runDir, 0o755);
      const file = path.join(runDir, `${ifn}.conf`);
      fs.writeFileSync(file, serverConf(w), { mode: 0o600 });
      let r = await run('ip', ['link', 'show', ifn]);
      if (r.code !== 0) {
        r = await run('ip', ['link', 'add', ifn, 'type', 'wireguard']);
        if (r.code !== 0) throw new Error(`Schnittstelle konnte nicht angelegt werden (Kernelmodul wireguard vorhanden?): ${r.stderr.trim().split('\n')[0]}`);
      }
      r = await run('wg', ['setconf', ifn, file]);
      fs.unlinkSync(file);
      if (r.code !== 0) throw new Error(`wg setconf: ${r.stderr.trim().split('\n')[0]}`);
      r = await run('ip', ['address', 'replace', `${a.ip}/${a.prefix}`, 'dev', ifn]);
      if (r.code !== 0) throw new Error(`Adresse setzen: ${r.stderr.trim().split('\n')[0]}`);
      r = await run('ip', ['link', 'set', 'dev', ifn, 'mtu', String(w.mtu || 1420), 'up']);
      if (r.code !== 0) throw new Error(`Schnittstelle starten: ${r.stderr.trim().split('\n')[0]}`);
      if (w.routing.access_lan || w.routing.internet) { try { fs.writeFileSync('/proc/sys/net/ipv4/ip_forward', '1'); } catch (_) { /* Container */ } }
      this.active = true; this.lastError = '';
      this.log.info(`WireGuard aktiv: ${ifn} ${a.ip}/${a.prefix}, Port ${w.listen_port}/udp, ${w.peers.filter((p) => p.enabled !== false).length} Teilnehmer`);
      return true;
    } catch (e) {
      this.lastError = e.message; this.active = false;
      this.log.error(`WireGuard: ${e.message}`);
      return false;
    }
  }

  async stop() {
    const ifn = this.w().interface;
    if (!validIface(ifn)) return;
    const r = await run('ip', ['link', 'show', ifn]);
    if (r.code === 0) { await run('ip', ['link', 'del', ifn]); this.log.info(`WireGuard-Schnittstelle ${ifn} entfernt`); }
    this.active = false;
  }

  async status() {
    const w = this.w(); const cfg = this.cfg();
    const out = { enabled: !!w.enabled, active: this.active, error: this.lastError, interface: w.interface, tools: await this.available(), public_key: B64_KEY.test(w.private_key || '') ? pubFromPriv(w.private_key) : '', peers: [] };
    let live = { peers: [] };
    if (w.enabled && this.active) { const r = await run('wg', ['show', w.interface, 'dump'], { timeout: 5000 }); if (r.code === 0) live = parseDump(r.stdout); }
    const byKey = new Map(live.peers.map((p) => [p.public_key, p]));
    out.peers = w.peers.map((p) => {
      const l = byKey.get(p.public_key) || {};
      return { id: p.id, name: p.name, address: p.address, enabled: p.enabled !== false, created: p.created, endpoint: l.endpoint || '', latest_handshake: l.latest_handshake || 0, rx: l.rx || 0, tx: l.tx || 0, online: !!l.latest_handshake && Date.now() - l.latest_handshake < 180000 };
    });
    out.lan_routes = lanRoutes(cfg);
    out.subnet = (parseAddress(w.address) || {}).cidr || '';
    out.endpoint_missing = !w.endpoint;
    out.client_allowed_ips = parseAddress(w.address) ? clientAllowedIps(cfg) : '';
    return out;
  }
}

// ---------- Verwaltung der Teilnehmer (arbeiten auf einer Konfigurationskopie) ----------
function ensureServerKey(w) { if (!B64_KEY.test(w.private_key || '')) w.private_key = genKeyPair().private_key; return w; }

function addPeer(cfg, name) {
  const w = ensureServerKey(cfg.wireguard);
  const nm = cleanName(name);
  if (!nm) throw new Error('Bitte einen Namen angeben (z. B. "Handy Roland")');
  if (w.peers.some((p) => p.name.toLowerCase() === nm.toLowerCase())) throw new Error('Diesen Namen gibt es schon');
  if (w.peers.length >= 250) throw new Error('Zu viele Teilnehmer');
  const kp = genKeyPair();
  const peer = { id: crypto.randomBytes(6).toString('hex'), name: nm, address: nextFreeAddress(w), private_key: kp.private_key, public_key: kp.public_key, preshared_key: genPsk(), enabled: true, created: Date.now() };
  w.peers.push(peer);
  return peer;
}

function removePeer(cfg, id) {
  const w = cfg.wireguard; const n = w.peers.length;
  w.peers = w.peers.filter((p) => p.id !== String(id));
  if (w.peers.length === n) throw new Error('Teilnehmer nicht gefunden');
}

module.exports = { lanRoutes, WireGuard, genKeyPair, genPsk, pubFromPriv, parseAddress, wgSubnet, effectiveLan, serverConf, clientConf, clientAllowedIps, parseDump, addPeer, removePeer, ensureServerKey, nextFreeAddress, cleanName, B64_KEY };
