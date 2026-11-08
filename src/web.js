'use strict';
// Web-Oberfläche + JSON-API (TCP mit Passwort/Session) und lokaler Steuer-Socket für die CLI (nur root).
const http = require('http');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');
const { deepMerge, clone, isObj, stripV4Mapped } = require('./util');
const { LEVELS } = require('./firewall');
const wgm = require('./wireguard');

function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `scrypt$${salt}$${crypto.scryptSync(pw, salt, 64).toString('hex')}`;
}

function verifyPassword(pw, stored) {
  if (!stored || typeof pw !== 'string') return false;
  const [t, salt, h] = stored.split('$');
  if (t !== 'scrypt' || !salt || !h) return false;
  const calc = crypto.scryptSync(pw, salt, 64);
  const exp = Buffer.from(h, 'hex');
  return exp.length === calc.length && crypto.timingSafeEqual(calc, exp);
}

const STATIC = { '/': ['index.html', 'text/html; charset=utf-8'], '/index.html': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'], '/logo.svg': ['logo.svg', 'image/svg+xml'], '/favicon.svg': ['logo.svg', 'image/svg+xml'] };

const validCidr = (s) => {
  const [a, p] = String(s).split('/');
  const f = net.isIP(a);
  if (!f) return false;
  if (p === undefined) return true;
  const n = Number(p);
  return Number.isInteger(n) && n >= 0 && n <= (f === 4 ? 32 : 128);
};
const validPort = (p) => Number.isInteger(Number(p)) && Number(p) >= 1 && Number(p) <= 65535;

function validateConfig(c) {
  const err = (m) => { throw new Error(m); };
  for (const k of ['lan_cidrs', 'admin_ips', 'never_ban']) for (const x of c[k]) if (!validCidr(x)) err(`Ungültige Adresse in ${k}: ${x}`);
  if (!validPort(c.web.port)) err('Ungültiger Web-Port');
  if (!validPort(c.dns.port)) err('Ungültiger DNS-Port');
  for (const key of ['allow_in_lan', 'allow_in_wan']) for (const pr of ['tcp', 'udp']) for (const p of c.firewall[key][pr]) if (!validPort(p)) err(`Ungültiger Port in firewall.${key}.${pr}: ${p}`);
  if (!Array.isArray(c.dns.upstreams) || !c.dns.upstreams.length) err('Mindestens ein Upstream-DNS-Server nötig');
  for (const l of c.dns.lists) {
    if (!/^[a-z0-9_-]+$/i.test(l.id || '')) err(`Ungültige Listen-ID: ${l.id}`);
    if (!/^https?:\/\//.test(l.url || '')) err(`Ungültige Listen-URL: ${l.url}`);
  }
  for (const f of c.firewall.threat_feeds.urls) if (!/^https?:\/\//.test(f.url || '')) err(`Ungültige Feed-URL: ${f.url}`);
  for (const [dom, ip] of Object.entries(c.dns.rewrites || {})) if (!net.isIP(String(ip))) err(`Ungültige IP für Umleitung ${dom}`);
  if (!(c.isolation.window_minutes > 0) || !(c.isolation.score_threshold > 0)) err('Ungültige Isolations-Werte');
  const wg = c.wireguard;
  if (wg) {
    if (!/^[A-Za-z][A-Za-z0-9_-]{0,14}$/.test(String(wg.interface || ''))) err('Ungültiger WireGuard-Schnittstellenname (z. B. wg0)');
    if (!validPort(wg.listen_port)) err('Ungültiger WireGuard-Port');
    if (!wgm.parseAddress(wg.address)) err('VPN-Adresse muss die Form 10.66.0.1/24 haben (IPv4, Netzgröße /8 bis /30)');
    if (wg.endpoint && !/^[A-Za-z0-9.-]+(:\d{1,5})?$|^\[[0-9a-fA-F:]+\](:\d{1,5})?$/.test(wg.endpoint)) err('Ungültige öffentliche Adresse (Endpoint) für die Clients');
    for (const r of wg.lan_routes || []) if (!/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(r) || !net.isIP(String(r).split('/')[0]) || Number(String(r).split('/')[1] || 32) > 32) err(`Ungültiges Netz in „Erreichbare LAN-Netze“: ${r}`);
    if (wg.client_dns && !net.isIP(wg.client_dns)) err('Ungültiger DNS-Server für die Clients');
    if (!(Number(wg.mtu) >= 1280 && Number(wg.mtu) <= 1500)) err('MTU muss zwischen 1280 und 1500 liegen');
    if (!(Number(wg.keepalive) >= 0 && Number(wg.keepalive) <= 120)) err('Keepalive muss zwischen 0 und 120 Sekunden liegen');
    if (wg.enabled && wg.interface === 'lo') err('Ungültiger Schnittstellenname');
    if (wg.enabled && wg.listen_port === c.web.port) err('Der WireGuard-Port darf nicht dem Port der Oberfläche entsprechen');
  }
  const hd = c.firewall.hardening;
  if (hd) {
    if (!(Number(hd.conn_limit) >= 0 && Number(hd.conn_limit) <= 100000)) err('Verbindungslimit muss zwischen 0 und 100000 liegen');
    if (!['auto', 'off', 'lan'].includes(hd.icmp)) err('Ungültiger Ping-Modus');
    for (const x of hd.wan_sources || []) if (!validCidr(x)) err(`Ungültige Adresse in „WAN nur für Quellen“: ${x}`);
  }
  const bindOk = (b) => b === '0.0.0.0' || b === '::' || !!net.isIP(String(b));
  if (!bindOk(c.web.bind)) err('Ungültige Bind-Adresse der Oberfläche');
  if (c.dns.bind !== undefined && !bindOk(c.dns.bind)) err('Ungültige Bind-Adresse des DNS-Servers');
  if (!(Number(c.web.session_hours) > 0 && Number(c.web.session_hours) <= 720)) err('Sitzungsdauer muss zwischen 1 und 720 Stunden liegen');
  for (const k of ['watch_paths', 'scan_paths', 'exclude']) if (!Array.isArray(c.antivirus[k]) || c.antivirus[k].some((x) => typeof x !== 'string' || x.includes('\0'))) err(`antivirus.${k} muss eine Liste von Texten sein`);
  if (c.notify && c.notify.webhook && c.notify.webhook.url && !/^https?:\/\//.test(c.notify.webhook.url)) err('Webhook-Adresse muss mit http:// oder https:// beginnen');
  if (!/^\d{2}:\d{2}$/.test(c.antivirus.schedule.time)) err('Scan-Zeit muss HH:MM sein');
  if (c.update.repo && !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(c.update.repo)) err('GitHub-Repository muss die Form benutzer/name haben');
  if (c.update.branch && !/^[A-Za-z0-9._\/-]+$/.test(c.update.branch)) err('Ungültiger Branch-Name');
  if (c.update.url && !/^https?:\/\//.test(c.update.url)) err('Update-Adresse muss mit http:// oder https:// beginnen');
  if (c.update.public_key) { try { const k = require('crypto').createPublicKey(c.update.public_key); if (k.asymmetricKeyType !== 'ed25519') err('Update-Schlüssel muss ein Ed25519-Schlüssel sein'); } catch (e) { if (/Ed25519/.test(e.message)) throw e; err('Update-Schlüssel ist ungültig (PEM-Format erwartet)'); } }
}

class Web {
  constructor({ app }) {
    this.app = app;
    this.sessions = new Map();
    this.fails = new Map();
    this.servers = [];
  }

  cfg() { return this.app.cfg(); }

  async start() {
    const c = this.cfg();
    if (!c.web.enabled) { this.app.log.info('Web-Oberfläche ist deaktiviert'); return; }
    const bind = c.web.password_hash ? c.web.bind : '127.0.0.1';
    if (!c.web.password_hash) this.app.log.warn('Kein Web-Passwort gesetzt: Oberfläche nur lokal erreichbar. Setzen mit: sudo rf-netguard passwd');
    const tcp = http.createServer((req, res) => this.handle(req, res, false));
    tcp.headersTimeout = 15000; tcp.requestTimeout = 60000; tcp.keepAliveTimeout = 5000; tcp.maxHeadersCount = 50; tcp.maxRequestsPerSocket = 1000; // gegen Slowloris
    await new Promise((resolve, reject) => { tcp.once('error', reject); tcp.listen(c.web.port, bind, () => { tcp.removeListener('error', reject); resolve(); }); });
    this.servers.push(tcp);
    this.app.log.info(`Web-Oberfläche: http://${bind}:${c.web.port}`);

    const sock = path.join(c.paths.run, 'control.sock');
    try {
      fs.mkdirSync(c.paths.run, { recursive: true, mode: 0o755 });
      try { fs.unlinkSync(sock); } catch (_) { /* nicht vorhanden */ }
      const local = http.createServer((req, res) => this.handle(req, res, true));
      await new Promise((resolve, reject) => { local.once('error', reject); local.listen(sock, () => { local.removeListener('error', reject); resolve(); }); });
      fs.chmodSync(sock, 0o600);
      this.servers.push(local);
    } catch (e) { this.app.log.warn(`Steuer-Socket nicht verfügbar: ${e.message}`); }
    const t = setInterval(() => { const n = Date.now(); for (const [k, v] of this.sessions) if (v < n) this.sessions.delete(k); }, 600000);
    t.unref();
  }

  stop() { this.servers.forEach((s) => { try { s.close(); } catch (_) { /* egal */ } }); this.servers = []; }

  send(res, code, data, type = 'application/json; charset=utf-8') {
    const body = typeof data === 'string' || Buffer.isBuffer(data) ? data : JSON.stringify(data);
    res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'" });
    res.end(body);
  }

  async handle(req, res, trusted) {
    try {
      const url = new URL(req.url, 'http://x');
      if (url.pathname.startsWith('/api/')) return await this.api(req, res, url, trusted);
      const s = STATIC[url.pathname];
      if (!s) return this.send(res, 404, 'Nicht gefunden', 'text/plain; charset=utf-8');
      return this.send(res, 200, fs.readFileSync(path.join(__dirname, '..', 'ui', s[0])), s[1]);
    } catch (e) {
      this.app.log.warn(`Web: ${e.message}`);
      return this.send(res, 500, { error: e.message });
    }
  }

  readBody(req, limit = 256 * 1024) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let n = 0;
      req.on('data', (c) => { n += c.length; if (n > limit) { reject(new Error('Anfrage zu groß')); req.destroy(); } else chunks.push(c); });
      req.on('end', () => {
        if (!chunks.length) return resolve({});
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (_) { reject(new Error('Ungültiges JSON')); }
      });
      req.on('error', reject);
    });
  }

  sessionOf(req) {
    const m = /(?:^|;\s*)ng_session=([a-f0-9]{64})/.exec(req.headers.cookie || '');
    if (!m) return null;
    const exp = this.sessions.get(m[1]);
    if (!exp || exp < Date.now()) { this.sessions.delete(m[1]); return null; }
    return m[1];
  }

  async api(req, res, url, trusted) {
    const ip = stripV4Mapped(req.socket.remoteAddress || '');
    const method = req.method;
    const route = `${method} ${url.pathname}`;
    const app = this.app;
    const c = this.cfg();

    if (method === 'POST' || method === 'PUT') {
      if (!trusted && !/^application\/json/i.test(req.headers['content-type'] || '')) return this.send(res, 415, { error: 'Content-Type application/json erforderlich' });
    }
    // CSRF/DNS-Rebinding: Anfragen mit fremdem Origin oder fremdem Host-Namen ablehnen (IP-Adressen und der eigene Rechnername sind erlaubt)
    if (!trusted) {
      const host = String(req.headers.host || '').toLowerCase();
      const hn = host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
      if (!(net.isIP(hn) || hn === 'localhost' || hn === os.hostname().toLowerCase() || (c.web.allowed_hosts || []).map((x) => String(x).toLowerCase()).includes(hn) || hn === `${os.hostname().toLowerCase()}.local` || hn.endsWith('.lan') || hn.endsWith('.home') || hn.endsWith('.local') || hn.endsWith('.fritz.box'))) return this.send(res, 400, { error: 'Unerwarteter Host-Name (Schutz vor DNS-Rebinding). Rufe die Oberfläche über die IP-Adresse auf.' });
      const origin = req.headers.origin;
      if (origin && method !== 'GET') { let oh = ''; try { oh = new URL(origin).host.toLowerCase(); } catch (_) { /* ungültig */ } if (oh !== host) return this.send(res, 403, { error: 'Anfrage von fremder Herkunft abgelehnt' }); }
    }
    const bigBody = route === 'POST /api/update/upload'; // nur angemeldete Nutzer dürfen große Update-Dateien senden
    if (bigBody && !trusted && !this.sessionOf(req)) return this.send(res, 401, { error: 'Nicht angemeldet' });
    const body = method === 'GET' ? {} : await this.readBody(req, bigBody ? 64 * 1024 * 1024 : 256 * 1024);

    if (route === 'GET /api/session') {
      return this.send(res, 200, { authenticated: trusted || !!this.sessionOf(req), password_set: !!c.web.password_hash, version: app.version });
    }
    if (route === 'POST /api/login') {
      if (!c.web.password_hash) return this.send(res, 403, { error: 'Es ist noch kein Passwort gesetzt. Auf dem Rechner ausführen: sudo rf-netguard passwd' });
      const f = this.fails.get(ip) || { n: 0, lock: 0 };
      if (f.lock > Date.now()) return this.send(res, 429, { error: 'Zu viele Fehlversuche. Bitte später erneut versuchen.' });
      if (!verifyPassword(body.password, c.web.password_hash)) {
        f.n++;
        if (f.n % 5 === 0) f.lock = Date.now() + 15 * 60000;
        if (this.fails.size > 5000) this.fails.clear();
        this.fails.set(ip, f);
        if (f.n >= 5 && f.n % 5 === 0) {
          app.events.report({ kind: 'attack', severity: 'warn', type: 'web-login-fail', src: ip, ban: f.n >= 10 ? (LEVELS[c.security_level] || LEVELS.normal).ban : 0, msg: `${f.n} fehlgeschlagene Anmeldungen an der RF-NetGuard-Oberfläche von ${ip}` });
        }
        await new Promise((r) => setTimeout(r, 800));
        return this.send(res, 401, { error: 'Falsches Passwort' });
      }
      this.fails.delete(ip);
      const tok = crypto.randomBytes(32).toString('hex');
      const maxAge = Math.round(c.web.session_hours * 3600);
      this.sessions.set(tok, Date.now() + maxAge * 1000);
      res.setHeader('Set-Cookie', `ng_session=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
      return this.send(res, 200, { ok: true });
    }
    if (route === 'POST /api/logout') {
      const t = this.sessionOf(req);
      if (t) this.sessions.delete(t);
      res.setHeader('Set-Cookie', 'ng_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
      return this.send(res, 200, { ok: true });
    }
    if (!trusted && !this.sessionOf(req)) return this.send(res, 401, { error: 'Nicht angemeldet' });

    const q = Object.fromEntries(url.searchParams);
    const ok = (extra = {}) => this.send(res, 200, { ok: true, ...extra });
    const fail = (code, error) => this.send(res, code, { error });

    switch (route) {
      case 'GET /api/status': return this.send(res, 200, await this.status());
      case 'GET /api/events': return this.send(res, 200, app.eventLog.recent(Math.min(1000, parseInt(q.limit, 10) || 200), q.min || 'info', q.q || ''));
      case 'GET /api/traffic': return this.send(res, 200, app.ids.trafficHistory());

      case 'GET /api/dns/stats': return this.send(res, 200, app.dns.getStats());
      case 'GET /api/dns/log': return this.send(res, 200, app.dns.queryLog(Math.min(2000, parseInt(q.limit, 10) || 200), { q: q.q || '', status: q.status || '' }));
      case 'POST /api/dns/check': return this.send(res, 200, app.dns.check(String(body.domain || ''), String(body.type || 'A')));
      case 'POST /api/dns/update-lists': { const r = await app.dns.updateLists(true); app.dns.rebuildFilter(); return ok(r); }

      case 'GET /api/firewall': return this.send(res, 200, await app.fw.status());
      case 'GET /api/firewall/bans': return this.send(res, 200, await app.fw.listBans());
      case 'POST /api/firewall/ban': {
        if (!net.isIP(String(body.ip || ''))) return fail(400, 'Ungültige IP-Adresse');
        const done = await app.fw.ban(body.ip, Math.max(1, Number(body.minutes) || 60) * 60, body.reason || 'manuell (Oberfläche)', 'admin');
        return done ? ok() : fail(400, 'Adresse ist geschützt (Gateway/Admin/eigene IP) oder die Firewall ist nicht aktiv');
      }
      case 'POST /api/firewall/unban': return (await app.fw.unban(String(body.ip || ''))) ? ok() : fail(404, 'Adresse war nicht gesperrt');
      case 'POST /api/firewall/reload': return ok({ applied: await app.fw.apply() });
      case 'POST /api/firewall/update-feeds': await app.fw.updateFeeds(true); return ok();

      case 'POST /api/isolate': return (await app.events.isolate(String(body.reason || 'manuell ausgelöst'))) ? ok() : fail(409, 'Bereits getrennt oder Trennung nicht möglich');
      case 'POST /api/release': {
        const pause = Math.max(0, Math.min(1440, parseInt(body.pause_minutes, 10) || 0));
        const done = await app.events.release(body.by ? String(body.by).slice(0, 40) : 'Oberfläche');
        if (!done) return fail(409, 'Rechner ist nicht getrennt');
        if (pause) app.events.pauseIsolation(pause);
        return ok({ paused_minutes: pause });
      }
      case 'GET /api/update': return this.send(res, 200, app.updater.status());
      case 'POST /api/update/check': try { return ok({ info: await app.updater.check() }); } catch (e) { return fail(400, e.message); }
      case 'POST /api/update/install': try { return ok(await app.updater.installFromManifest()); } catch (e) { return fail(400, e.message); }
      case 'POST /api/update/upload': {
        if (typeof body.bundle !== 'string') return fail(400, 'Update-Datei fehlt');
        try { return ok(await app.updater.installText(body.bundle)); } catch (e) { return fail(400, e.message); }
      }
      case 'POST /api/update/rollback': try { app.updater.rollback(); return ok(); } catch (e) { return fail(400, e.message); }
      case 'POST /api/isolation/pause': return ok({ until: app.events.pauseIsolation(Math.max(0, parseInt(body.minutes, 10) || 0)) });
      case 'POST /api/protection/off': await app.events.protection(false, 'Oberfläche'); return ok();
      case 'POST /api/protection/on': await app.events.protection(true, 'Oberfläche'); return ok();

      case 'POST /api/av/scan': { if (app.av.scanStatus.running) return fail(409, 'Ein Scan läuft bereits'); app.av.fullScan(Array.isArray(body.paths) ? body.paths : null, 'manuell').catch(() => {}); return ok(); }
      case 'GET /api/av/quarantine': return this.send(res, 200, app.av.listQuarantine());
      case 'POST /api/av/restore': return ok({ target: app.av.restoreQuarantine(String(body.id)) });
      case 'POST /api/av/delete': app.av.removeQuarantine(String(body.id)); return ok();
      case 'POST /api/av/selftest': return this.send(res, 200, await app.av.selftest());
      case 'POST /api/ids/accept-listeners': return ok({ ports: app.ids.acceptListeners() });

      case 'GET /api/config': {
        const out = clone(c);
        out.web.password_set = !!out.web.password_hash;
        out.web.password_hash = '';
        out.wireguard.private_key = ''; // Schlüssel verlassen den Rechner nur als Client-Konfiguration
        out.wireguard.peers = out.wireguard.peers.map((p) => ({ id: p.id, name: p.name, address: p.address, enabled: p.enabled !== false, created: p.created }));
        return this.send(res, 200, out);
      }
      case 'GET /api/wireguard': return this.send(res, 200, await app.wg.status());
      case 'POST /api/wireguard/peer': {
        const next = clone(c);
        try {
          const peer = wgm.addPeer(next, body.name);
          next.wireguard.enabled = next.wireguard.enabled; // Aktivierung nur über die Einstellungen
          config.save(next); app.setConfig(next);
          if (next.wireguard.enabled) await app.wg.apply();
          return ok({ id: peer.id, name: peer.name, address: peer.address });
        } catch (e) { return fail(400, e.message); }
      }
      case 'POST /api/wireguard/peer/delete': {
        const next = clone(c);
        try { wgm.removePeer(next, body.id); } catch (e) { return fail(404, e.message); }
        config.save(next); app.setConfig(next);
        if (next.wireguard.enabled) await app.wg.apply();
        return ok();
      }
      case 'POST /api/wireguard/peer/toggle': {
        const next = clone(c); const p = next.wireguard.peers.find((x) => x.id === String(body.id));
        if (!p) return fail(404, 'Teilnehmer nicht gefunden');
        p.enabled = body.enabled === true;
        config.save(next); app.setConfig(next);
        if (next.wireguard.enabled) await app.wg.apply();
        return ok();
      }
      case 'GET /api/wireguard/peer/config': {
        const p = c.wireguard.peers.find((x) => x.id === String(q.id));
        if (!p) return fail(404, 'Teilnehmer nicht gefunden');
        res.setHeader('Content-Disposition', `attachment; filename="${(wgm.cleanName(p.name).replace(/\s+/g, '-') || 'vpn')}.conf"`);
        return this.send(res, 200, wgm.clientConf(c, p), 'text/plain; charset=utf-8');
      }
      case 'PUT /api/config': {
        if (!isObj(body)) return fail(400, 'Ungültige Konfiguration');
        const merged = config.normalize(deepMerge(clone(config.DEFAULTS), body));
        merged.paths = c.paths;
        merged.web.password_hash = c.web.password_hash;
        // WireGuard-Schlüssel und Teilnehmer werden nur über die eigenen Routen verwaltet, nie über die Konfiguration
        merged.wireguard.private_key = c.wireguard.private_key;
        merged.wireguard.peers = c.wireguard.peers;
        if (merged.wireguard.enabled) wgm.ensureServerKey(merged.wireguard);
        delete merged.web.password_set;
        try { validateConfig(merged); } catch (e) { return fail(400, e.message); }
        config.save(merged);
        app.setConfig(merged);
        await app.reload();
        return ok();
      }
      case 'POST /api/notify/test': return this.send(res, 200, await app.notifier.test());
      case 'POST /api/password': {
        const np = String(body.new || '');
        if (np.length < 10) return fail(400, 'Das neue Passwort muss mindestens 10 Zeichen haben');
        if (!trusted && !verifyPassword(body.old, c.web.password_hash)) return fail(403, 'Altes Passwort falsch');
        const next = clone(c);
        next.web.password_hash = hashPassword(np);
        config.save(next);
        app.setConfig(next);
        this.sessions.clear();
        return ok();
      }
      case 'POST /api/reload': await app.reload(); return ok();
      case 'POST /api/restart': {
        app.eventLog.add({ kind: 'info', severity: 'info', type: 'restart', msg: 'RF-NetGuard wird auf Anforderung neu gestartet' });
        ok({ restarting: true });
        setTimeout(() => {
          const { spawn } = require('child_process');
          // Unter systemd: sauber über systemctl (Restart=always fängt sonst auch ab); ohne systemd beendet sich der Dienst nur
          if (process.env.INVOCATION_ID && !process.env.NETGUARD_NO_SYSTEMD) { try { spawn('systemctl', ['restart', 'netguard'], { detached: true, stdio: 'ignore' }).unref(); return; } catch (_) { /* weiter */ } }
          app.stop('Neustart angefordert');
        }, 400);
        return;
      }
      case 'POST /api/reboot': {
        if (body.confirm !== true) return fail(400, 'Bestätigung fehlt');
        app.eventLog.add({ kind: 'info', severity: 'warn', type: 'reboot', msg: 'Rechner wird auf Anforderung neu gestartet' });
        ok({ rebooting: true });
        setTimeout(() => {
          if (process.env.NETGUARD_NO_REBOOT) return; // Tests
          const { spawn } = require('child_process');
          try { app.state.flush(); } catch (_) { /* egal */ }
          try { spawn('systemctl', ['reboot'], { detached: true, stdio: 'ignore' }).unref(); } catch (_) { try { spawn('reboot', [], { detached: true, stdio: 'ignore' }).unref(); } catch (e) { app.log.error(`Neustart nicht möglich: ${e.message}`); } }
        }, 800);
        return;
      }
      default: return fail(404, 'Unbekannte API');
    }
  }

  async status() {
    const app = this.app;
    const c = this.cfg();
    const d = app.state.data;
    const dns = app.dns.getStats();
    const tr = app.ids.trafficHistory();
    return {
      version: app.version, hostname: os.hostname(), uptime: Math.round(process.uptime()), time: Date.now(),
      mode: c.mode, level: c.security_level,
      isolation: { isolated: !!d.isolated, since: d.isolated_at, reason: d.isolated_reason, score: app.events.currentScore(), threshold: c.isolation.score_threshold, enabled: c.isolation.enabled, paused_until: d.isolation_paused_until > Date.now() ? d.isolation_paused_until : 0, keep_lan_access: c.isolation.keep_lan_access !== false },
      protection_off: !!d.protection_off,
      update_available: app.updater ? app.updater.available() : null,
      firewall: await app.fw.status(),
      dns: { running: dns.running, total: dns.total, blocked: dns.blocked, blocked_pct: dns.blocked_pct, cached: dns.cached, rules: dns.rules, hours: dns.hours },
      av: app.av.status(),
      events24h: app.eventLog.counts(24 * 3600 * 1000),
      traffic: tr.length ? tr[tr.length - 1] : null,
      notify_channels: app.notifier.channels(),
    };
  }
}

module.exports = { Web, hashPassword, verifyPassword, validateConfig };
