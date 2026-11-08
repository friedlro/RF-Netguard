'use strict';
// Updates: signierte Update-Pakete (.ngupdate) prüfen, sichern, einspielen, Dienst neu starten,
// Funktion prüfen und bei Problemen automatisch zurückrollen. Konfiguration, Daten und Logs liegen
// außerhalb des Programmverzeichnisses und bleiben unberührt.
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const config = require('./config');
const { run, httpRequest, ensureDir, sleep } = require('./util');

const hasCmd = (c) => spawnSync('sh', ['-c', `command -v ${c}`], { stdio: 'ignore' }).status === 0;

const APP_DIR = process.env.NETGUARD_APP_DIR || path.resolve(__dirname, '..');
const MAX_BUNDLE = 30 * 1024 * 1024;
const KEEP_BACKUPS = 3;
const ITEMS = ['src', 'ui', 'deploy', 'test', 'tools', 'package.json', 'README.md', 'config.example.json'];

function cmpVer(a, b) {
  const pa = String(a).split('.').map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

const validVersion = (v) => /^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(String(v));
const readVersion = (dir) => { try { return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')).version; } catch (_) { return null; } };
const signedText = (version, sha256) => Buffer.from(`netguard-update\n${version}\n${sha256}`);
const rmrf = (p) => { try { fs.rmSync(p, { recursive: true, force: true }); } catch (_) { /* egal */ } };

// ---------- Paketformat ----------
function parseBundle(input) {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input);
  let j;
  try { j = JSON.parse(text); } catch (_) { throw new Error('Keine gültige Update-Datei (.ngupdate)'); }
  if (!j || j.format !== 1 || !validVersion(j.version) || typeof j.data !== 'string' || typeof j.sha256 !== 'string' || typeof j.sig !== 'string') throw new Error('Update-Datei hat ein unbekanntes Format');
  const tar = Buffer.from(j.data, 'base64');
  if (tar.length < 100 || tar.length > MAX_BUNDLE) throw new Error('Update-Datei hat eine ungültige Größe');
  if (crypto.createHash('sha256').update(tar).digest('hex') !== j.sha256) throw new Error('Prüfsumme der Update-Datei stimmt nicht (beschädigt oder verändert)');
  return { version: j.version, notes: String(j.notes || '').slice(0, 4000), sha256: j.sha256, sig: j.sig, tar };
}

// Vertrauenswürdige Schlüssel: der eingebaute Release-Schlüssel (außer update.builtin_key=false) und optional ein eigener
function trustedKeys(cfg) {
  const u = (cfg && cfg.update) || {};
  const keys = [];
  if (u.builtin_key !== false) keys.push(require('./update-key'));
  if (u.public_key) keys.push(u.public_key);
  return keys;
}

// Signatur gegen die vertrauenswürdigen Schlüssel (Ed25519) prüfen; liefert false, wenn gar kein Schlüssel vorhanden ist
function verifyBundle(b, keys) {
  const list = (Array.isArray(keys) ? keys : [keys]).filter(Boolean);
  if (!list.length) return false;
  let ok = false;
  for (const pem of list) {
    try {
      if (crypto.verify(null, signedText(b.version, b.sha256), crypto.createPublicKey(pem), Buffer.from(b.sig, 'base64'))) { ok = true; break; }
    } catch (_) { /* ungültiger Schlüssel oder Signatur: nächster */ }
  }
  if (!ok) throw new Error('Signatur der Update-Datei ist ungültig – Update wird NICHT installiert');
  return true;
}

// ---------- Entpacken & Prüfen ----------
async function extractTar(tarBuf, stageDir) {
  ensureDir(stageDir, 0o700);
  const file = path.join(stageDir, 'update.tar.gz');
  fs.writeFileSync(file, tarBuf, { mode: 0o600 });
  const names = await run('tar', ['-tzf', file]);
  const verbose = await run('tar', ['-tzvf', file]);
  if (names.code !== 0 || verbose.code !== 0) throw new Error('Das Update-Archiv ist beschädigt');
  const list = names.stdout.split('\n').filter(Boolean);
  if (!list.length || list.length > 5000) throw new Error('Das Update-Archiv hat eine ungültige Anzahl Dateien');
  for (const n of list) {
    if (n.startsWith('/') || n.split('/').includes('..') || !(n === 'netguard' || n.startsWith('netguard/'))) throw new Error(`Unzulässiger Pfad im Update-Archiv: ${n.slice(0, 80)}`);
  }
  let total = 0;
  for (const l of verbose.stdout.split('\n').filter(Boolean)) {
    if (!/^[-d]/.test(l)) throw new Error('Das Update-Archiv enthält Links oder Sonderdateien und wird abgelehnt');
    total += parseInt(l.split(/\s+/)[2], 10) || 0;
  }
  if (total > 120 * 1024 * 1024) throw new Error('Das Update-Archiv ist entpackt zu groß');
  const x = await run('tar', ['-xzf', file, '-C', stageDir, '--no-same-owner', '--no-same-permissions']);
  if (x.code !== 0) throw new Error(`Entpacken fehlgeschlagen: ${x.stderr.trim().slice(0, 200)}`);
  fs.unlinkSync(file);
  return path.join(stageDir, 'netguard');
}

async function preflight(root, expectedVersion) {
  for (const f of ['package.json', 'src/index.js', 'src/config.js', 'ui/index.html']) if (!fs.existsSync(path.join(root, f))) throw new Error(`Im Update fehlt ${f}`);
  const v = readVersion(root);
  if (!validVersion(v)) throw new Error('Das Update enthält keine gültige Version');
  if (expectedVersion && v !== expectedVersion) throw new Error(`Versionsangabe (${expectedVersion}) passt nicht zum Inhalt (${v})`);
  for (const f of fs.readdirSync(path.join(root, 'src')).filter((x) => x.endsWith('.js'))) {
    const r = await run(process.execPath, ['--check', path.join(root, 'src', f)]);
    if (r.code !== 0) throw new Error(`Syntaxfehler im Update (${f}): ${r.stderr.split('\n')[0]}`);
  }
  // Die neue Version muss die bestehende Konfiguration laden und starten können
  const smoke = await run(process.execPath, ['-e', `const c=require(${JSON.stringify(path.join(root, 'src/config'))});c.load();require(${JSON.stringify(path.join(root, 'src/index.js'))});`], { timeout: 30000 });
  if (smoke.code !== 0) throw new Error(`Die neue Version startet nicht mit der vorhandenen Konfiguration: ${(smoke.stderr || '').trim().split('\n').slice(-2).join(' ').slice(0, 300)}`);
  return v;
}

// ---------- Einspielen mit Rollback ----------
function backupsDir(appDir) { return path.join(path.dirname(appDir), 'netguard-backups'); }

function listBackups(appDir) {
  const d = backupsDir(appDir);
  try { return fs.readdirSync(d).map((n) => ({ name: n, dir: path.join(d, n), t: fs.statSync(path.join(d, n)).mtimeMs })).sort((a, b) => b.t - a.t); } catch (_) { return []; }
}

const SERVICE_FILE = '/etc/systemd/system/netguard.service';

// Wartet, bis der Dienst über seinen Steuer-Socket meldet, dass genau diese Version läuft
async function waitHealthy(version, sock, tries = 45) {
  for (let i = 0; i < tries; i++) {
    await sleep(i === 0 ? 300 : 1000);
    const ok = await new Promise((resolve) => {
      const rq = http.request({ socketPath: sock, path: '/api/status', method: 'GET', timeout: 2000 }, (res) => {
        const c = []; res.on('data', (d) => c.push(d));
        res.on('end', () => { try { resolve(res.statusCode === 200 && JSON.parse(Buffer.concat(c).toString()).version === version); } catch (_) { resolve(false); } });
      });
      rq.on('error', () => resolve(false)); rq.on('timeout', () => { rq.destroy(); resolve(false); }); rq.end();
    });
    if (ok) return true;
  }
  return false;
}

function defaultHooks() {
  const sysd = !process.env.NETGUARD_NO_SYSTEMD && hasCmd('systemctl') && fs.existsSync('/run/systemd/system');
  return {
    async restart() {
      if (!sysd) return true;
      return (await run('systemctl', ['restart', 'netguard'])).code === 0;
    },
    async health(version) {
      if (!sysd) return true;
      return waitHealthy(version, path.join(config.load().paths.run, 'control.sock'), 45);
    },
    syncService(appDir) {
      if (!sysd) return null;
      const src = path.join(appDir, 'deploy', 'netguard.service');
      try {
        const cur = fs.existsSync(SERVICE_FILE) ? fs.readFileSync(SERVICE_FILE, 'utf8') : null;
        const nw = fs.readFileSync(src, 'utf8');
        if (cur === nw) return null;
        fs.writeFileSync(SERVICE_FILE, nw);
        return cur;
      } catch (_) { return null; }
    },
    async reloadUnits() { if (sysd) await run('systemctl', ['daemon-reload']); },
    restoreService(content) { if (sysd && content != null) try { fs.writeFileSync(SERVICE_FILE, content); } catch (_) { /* egal */ } },
  };
}

async function installFrom(appDir, stageRoot, hooks, log = () => {}) {
  const from = readVersion(appDir) || '?';
  const to = readVersion(stageRoot);
  const bak = path.join(backupsDir(appDir), `${from}-${new Date().toISOString().replace(/[:.]/g, '-')}`);
  ensureDir(backupsDir(appDir), 0o700);
  fs.cpSync(appDir, bak, { recursive: true });
  const next = `${appDir}.new`; const old = `${appDir}.old`;
  rmrf(next); rmrf(old);
  ensureDir(next, 0o755);
  for (const it of ITEMS) { const s = path.join(stageRoot, it); if (fs.existsSync(s)) fs.cpSync(s, path.join(next, it), { recursive: true }); }
  fs.renameSync(appDir, old);
  fs.renameSync(next, appDir);
  log(`Programmdateien getauscht (${from} → ${to}), Sicherung: ${bak}`);

  const oldService = hooks.syncService(appDir);
  if (oldService !== null) await hooks.reloadUnits();
  const restarted = await hooks.restart();
  const healthy = restarted && await hooks.health(to);
  if (healthy) {
    rmrf(old);
    for (const b of listBackups(appDir).slice(KEEP_BACKUPS)) rmrf(b.dir);
    return { ok: true, from, to, backup: bak };
  }
  // Zurückrollen
  log('Neue Version startet nicht – es wird auf die vorherige Version zurückgestellt');
  rmrf(`${appDir}.failed`);
  fs.renameSync(appDir, `${appDir}.failed`);
  fs.renameSync(old, appDir);
  if (oldService !== null) { hooks.restoreService(oldService); await hooks.reloadUnits(); }
  await hooks.restart();
  const back = await hooks.health(from);
  rmrf(`${appDir}.failed`);
  return { ok: false, from, to, rolledBack: back, backup: bak, error: back ? 'Die neue Version hat nicht richtig gestartet. Die vorherige Version läuft wieder.' : 'Die neue Version hat nicht gestartet und die vorherige konnte nicht bestätigt werden – bitte prüfen: journalctl -u netguard' };
}

// ---------- Gesamtablauf ----------
// opts: { source (Datei/URL/Verzeichnis), cli, fromWeb, force, unsigned, appDir, hooks, log }
async function performUpdate(opts) {
  const log = opts.log || (() => {});
  const appDir = opts.appDir || APP_DIR;
  const hooks = opts.hooks || defaultHooks();
  const cfg = config.load();
  const key = trustedKeys(cfg);
  const dataDir = cfg.paths.data;
  const stageBase = path.join(dataDir, 'update', `stage-${Date.now()}`);
  const started = Date.now();
  const finish = (res) => {
    try {
      ensureDir(path.join(dataDir, 'update'), 0o700);
      fs.writeFileSync(path.join(dataDir, 'update-result.json'), JSON.stringify({ time: Date.now(), took_s: Math.round((Date.now() - started) / 1000), from: res.from, to: res.to, ok: !!res.ok, message: res.message || res.error || '', reported: false }));
    } catch (_) { /* egal */ }
    rmrf(stageBase);
    return res;
  };
  let stageRoot; let expected = null;
  try {
    let src = opts.source;
    let buf = null;
    if (/^https?:\/\//.test(src)) {
      log(`Lade ${src} …`);
      const r = await httpRequest(src, { timeout: 60000, maxBytes: MAX_BUNDLE });
      if (r.status !== 200) throw new Error(`Download fehlgeschlagen (HTTP ${r.status})`);
      buf = r.body;
    } else if (fs.existsSync(src) && fs.statSync(src).isDirectory()) {
      if (!opts.cli) throw new Error('Verzeichnisse sind nur per Kommandozeile erlaubt');
      if (key.length && !opts.unsigned) throw new Error('Ein Schlüssel ist hinterlegt: unsignierte Verzeichnisse/Archive werden nur mit --unsigned installiert');
      stageRoot = fs.existsSync(path.join(src, 'netguard', 'package.json')) ? path.join(src, 'netguard') : src;
    } else if (fs.existsSync(src)) {
      buf = fs.readFileSync(src);
    } else throw new Error(`Quelle nicht gefunden: ${src}`);

    if (buf) {
      const isGzip = buf[0] === 0x1f && buf[1] === 0x8b;
      let tar; let signed = false;
      if (isGzip) {
        if (!opts.cli) throw new Error('Nur signierte Update-Dateien (.ngupdate) sind über die Oberfläche erlaubt');
        if (key.length && !opts.unsigned) throw new Error('Ein Schlüssel ist hinterlegt: unsignierte Archive werden nur mit --unsigned installiert');
        tar = buf; log('Hinweis: unsigniertes Archiv (lokal als root installiert)');
      } else {
        const b = parseBundle(buf);
        signed = verifyBundle(b, key);
        if (!signed && !(opts.cli && !opts.fromWeb)) throw new Error('Es ist kein Update-Schlüssel hinterlegt – nur per Kommandozeile installierbar (netguard update-key <datei>)');
        if (!signed) log('Hinweis: kein Update-Schlüssel hinterlegt – Signatur nicht geprüft');
        else log('Signatur geprüft: gültig');
        tar = b.tar; expected = b.version;
      }
      stageRoot = await extractTar(tar, stageBase);
    }
    const to = await preflight(stageRoot, expected);
    const from = readVersion(appDir);
    const c = cmpVer(to, from);
    if (c === 0 && !opts.force) return finish({ ok: true, from, to, unchanged: true, message: `Bereits auf Version ${from}` });
    if (c < 0 && !opts.force) throw new Error(`Das Update (${to}) ist älter als die installierte Version (${from}) – mit --force erzwingen`);
    log(`Installiere ${from} → ${to} …`);
    const r = await installFrom(appDir, stageRoot, hooks, log);
    return finish({ ...r, message: r.ok ? `Auf Version ${to} aktualisiert` : r.error });
  } catch (e) {
    return finish({ ok: false, from: readVersion(appDir), to: expected, message: e.message, error: e.message });
  } finally {
    if (opts.cleanup) rmrf(opts.cleanup);
  }
}

async function rollbackLast(opts = {}) {
  const appDir = opts.appDir || APP_DIR;
  const hooks = opts.hooks || defaultHooks();
  const cur = readVersion(appDir);
  const b = listBackups(appDir).find((x) => readVersion(x.dir) && x.dir);
  if (!b) return { ok: false, message: 'Keine Sicherung vorhanden' };
  const stage = path.join(os.tmpdir(), `ngrb-${Date.now()}`);
  fs.cpSync(b.dir, stage, { recursive: true });
  try {
    const to = await preflight(stage, null);
    const r = await installFrom(appDir, stage, hooks, opts.log);
    const cfg = config.load();
    try { fs.writeFileSync(path.join(cfg.paths.data, 'update-result.json'), JSON.stringify({ time: Date.now(), from: cur, to, ok: r.ok, message: r.ok ? `Auf Version ${to} zurückgestellt` : r.error, reported: false })); } catch (_) { /* egal */ }
    return { ...r, message: r.ok ? `Auf Version ${to} zurückgestellt` : r.error };
  } catch (e) { return { ok: false, message: e.message }; } finally { rmrf(stage); }
}

// ---------- Prüfung auf neue Version ----------
async function checkManifest(url, current) {
  if (!/^https?:\/\//.test(url || '')) throw new Error('Keine Update-Adresse eingestellt');
  const r = await httpRequest(url, { timeout: 15000, maxBytes: 200000 });
  if (r.status !== 200) throw new Error(`Update-Adresse nicht erreichbar (HTTP ${r.status})`);
  let m;
  try { m = JSON.parse(r.body.toString('utf8')); } catch (_) { throw new Error('Die Update-Adresse liefert kein gültiges latest.json'); }
  if (!validVersion(m.version) || typeof m.url !== 'string') throw new Error('latest.json ist unvollständig');
  return { latest: m.version, notes: String(m.notes || '').slice(0, 4000), bundle_url: new URL(m.url, url).toString(), newer: cmpVer(m.version, current) > 0 };
}

// ---------- Daemon-Seite ----------
class Updater {
  constructor({ cfg, log, eventLog, dataDir, canAuto }) {
    this.cfg = cfg; this.log = log; this.eventLog = eventLog; this.dataDir = dataDir;
    this.info = null; this.timer = null; this.busy = false;
    this.launch = (args) => launchDetached(args, this.log);
    this.canAuto = canAuto || (() => true);
  }

  current() { return readVersion(APP_DIR); }

  start() {
    this.reportResult();
    const tick = () => { if (this.cfg().update.url) this.check().then(() => this.autoInstall()).catch((e) => this.log.warn(`Update-Prüfung: ${e.message}`)); };
    setTimeout(tick, 60000).unref();
    this.timer = setInterval(tick, Math.max(1, this.cfg().update.check_hours || 24) * 3600000);
    this.timer.unref();
  }

  stop() { clearInterval(this.timer); }

  // Ergebnis eines Updates aus der vorigen Programmversion einmalig melden
  reportResult() {
    const f = path.join(this.dataDir, 'update-result.json');
    try {
      const r = JSON.parse(fs.readFileSync(f, 'utf8'));
      if (r.reported) return;
      r.reported = true; fs.writeFileSync(f, JSON.stringify(r));
      if (r.unchanged) return;
      this.eventLog.add({ kind: 'info', severity: r.ok ? 'info' : 'high', type: r.ok ? 'update-done' : 'update-failed', msg: r.ok ? `Update erfolgreich: ${r.from} → ${r.to}` : `Update fehlgeschlagen (${r.from} → ${r.to || '?'}): ${r.message}` });
    } catch (_) { /* kein Ergebnis */ }
  }

  lastResult() { try { return JSON.parse(fs.readFileSync(path.join(this.dataDir, 'update-result.json'), 'utf8')); } catch (_) { return null; } }

  async check() {
    const c = this.cfg().update;
    const r = await checkManifest(c.url, this.current());
    const prev = this.info && this.info.latest;
    this.info = { ...r, checked: Date.now() };
    if (r.newer && prev !== r.latest) this.eventLog.add({ kind: 'info', severity: 'info', type: 'update-available', msg: `Neue RF-NetGuard-Version ${r.latest} verfügbar (installiert: ${this.current()})` });
    return this.info;
  }

  // Automatisches Update: nur signierte Versionen, nicht bei Netztrennung, und jede Version höchstens einmal (kein Endlos-Versuch bei Fehlschlag)
  async autoInstall() {
    const c = this.cfg().update;
    if (!c.auto_install || this.busy || !this.available() || !this.hasKey() || !this.canAuto()) return false;
    const v = this.available(); const mark = path.join(this.dataDir, 'update-auto-tried');
    try { if (fs.readFileSync(mark, 'utf8').trim() === v) return false; } catch (_) { /* noch nie versucht */ }
    try { fs.writeFileSync(mark, v); } catch (_) { /* egal */ }
    this.eventLog.add({ kind: 'info', severity: 'info', type: 'update-auto', msg: `Automatisches Update auf ${v} wird installiert` });
    try { await this.installFromManifest(); return true; } catch (e) {
      this.eventLog.add({ kind: 'info', severity: 'warn', type: 'update-failed', msg: `Automatisches Update auf ${v} nicht möglich: ${e.message}` });
      return false;
    }
  }

  available() { return this.info && this.info.newer ? this.info.latest : null; }

  hasKey() { return trustedKeys(this.cfg()).length > 0; }

  stageIncoming(text) {
    const dir = path.join(this.dataDir, 'update'); ensureDir(dir, 0o700);
    const file = path.join(dir, `incoming-${Date.now()}.ngupdate`);
    fs.writeFileSync(file, text, { mode: 0o600 });
    return file;
  }

  // Signatur schon hier prüfen, damit Fehler sofort in der Oberfläche erscheinen
  verifyText(text) {
    if (!this.hasKey()) throw new Error('Es ist kein Update-Schlüssel hinterlegt. Über die Oberfläche werden nur signierte Updates installiert (Einstellungen → Updates).');
    const b = parseBundle(text);
    verifyBundle(b, trustedKeys(this.cfg()));
    if (cmpVer(b.version, this.current()) <= 0) throw new Error(`Version ${b.version} ist nicht neuer als die installierte (${this.current()})`);
    return b;
  }

  async installText(text) {
    if (this.busy) throw new Error('Ein Update läuft bereits');
    const b = this.verifyText(text);
    const file = this.stageIncoming(text);
    this.busy = true; setTimeout(() => { this.busy = false; }, 5 * 60000).unref();
    this.launch(['update', file, '--from-web', '--cleanup']);
    return { version: b.version };
  }

  async installFromManifest() {
    const info = this.info && this.info.newer ? this.info : await this.check();
    if (!info.newer) throw new Error('Es ist keine neuere Version verfügbar');
    const r = await httpRequest(info.bundle_url, { timeout: 60000, maxBytes: MAX_BUNDLE });
    if (r.status !== 200) throw new Error(`Download fehlgeschlagen (HTTP ${r.status})`);
    return this.installText(r.body.toString('utf8'));
  }

  rollback() {
    if (this.busy) throw new Error('Ein Update läuft bereits');
    if (!listBackups(APP_DIR).length) throw new Error('Keine Sicherung vorhanden');
    this.busy = true; setTimeout(() => { this.busy = false; }, 5 * 60000).unref();
    this.launch(['rollback']);
  }

  status() {
    return { version: this.current(), url: this.cfg().update.url, has_key: this.hasKey(), info: this.info, available: this.available(), last: this.lastResult(), backups: listBackups(APP_DIR).length };
  }
}

// Der Update-Vorgang muss den Dienst überleben, den er neu startet: eigene systemd-Einheit bzw. abgekoppelter Prozess
function launchDetached(args, log) {
  const node = process.execPath; const cli = path.join(APP_DIR, 'src', 'index.js');
  if (!process.env.NETGUARD_NO_SYSTEMD && hasCmd('systemd-run') && fs.existsSync('/run/systemd/system')) {
    const unit = `netguard-update-${Date.now()}`;
    const p = spawn('systemd-run', ['--unit', unit, '--collect', '--quiet', node, cli, ...args], { stdio: 'ignore', detached: true });
    p.on('error', (e) => log.error(`Update-Start: ${e.message}`)); p.unref();
  } else {
    const p = spawn(node, [cli, ...args], { stdio: 'ignore', detached: true });
    p.on('error', (e) => log.error(`Update-Start: ${e.message}`)); p.unref();
  }
}

module.exports = { trustedKeys, waitHealthy, APP_DIR, cmpVer, parseBundle, verifyBundle, extractTar, preflight, installFrom, performUpdate, rollbackLast, checkManifest, listBackups, Updater, signedText, readVersion, validVersion };
