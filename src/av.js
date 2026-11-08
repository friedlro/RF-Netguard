'use strict';
// Virenschutz auf Basis von ClamAV (clamd bevorzugt, sonst clamscan):
// Echtzeit-Überwachung per inotify, geplante Vollscans, Quarantäne, Beenden laufender Schadprozesse.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { run, commandExists, ensureDir, hashFile } = require('./util');

// Standard-Testmuster (harmlos) – bewusst zusammengesetzt, damit diese Datei selbst nicht als "Virus" gemeldet wird
const EICAR = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}', '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!', '$H+H*'].join('');
const FOUND_RE = /^(.*): (.+) FOUND$/;
const TMP_DIRS = ['/tmp/', '/var/tmp/', '/dev/shm/'];

function streamRun(cmd, args, onLine, timeoutMs) {
  return new Promise((resolve) => {
    let p;
    try { p = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { resolve({ code: 127, error: e.message }); return; }
    let buf = '';
    let err = '';
    const t = setTimeout(() => { try { p.kill('SIGKILL'); } catch (_) { /* egal */ } }, timeoutMs);
    p.stdout.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) { const l = buf.slice(0, i); buf = buf.slice(i + 1); onLine(l); }
    });
    p.stderr.on('data', (d) => { err = (err + d).slice(-2000); });
    p.on('error', (e) => { clearTimeout(t); resolve({ code: 127, error: e.message }); });
    p.on('close', (code) => { clearTimeout(t); if (buf) onLine(buf); resolve({ code, stderr: err }); });
  });
}

class Antivirus {
  constructor({ cfg, log, events, state, dataDir }) {
    this.cfg = cfg;
    this.log = log;
    this.events = events;
    this.state = state;
    this.qdir = path.join(dataDir, 'quarantine');
    this.engine = null;
    this.version = '';
    this.queue = new Set();
    this.watchers = new Map();
    this.debounce = new Map();
    this.timers = [];
    this.flushing = false;
    this.scanStatus = { running: false, started: 0, paths: [], found: 0, source: '' };
    this.stopped = false;
    this.truncated = false;
  }

  c() { return this.cfg().antivirus; }

  async detectEngine() {
    const c = this.c();
    this.engine = null;
    const hasClamd = await commandExists('clamdscan');
    const hasScan = await commandExists('clamscan');
    if (hasClamd && c.engine !== 'clamscan') {
      const r = await run('clamdscan', ['--ping', '1:1'], { timeout: 10000 });
      if (r.code === 0) this.engine = { kind: 'clamd', bin: 'clamdscan' };
    }
    if (!this.engine && hasScan && c.engine !== 'clamd') this.engine = { kind: 'clamscan', bin: 'clamscan' };
    if (this.engine) {
      const v = await run(this.engine.bin, ['--version'], { timeout: 10000 });
      this.version = v.stdout.trim().split('\n')[0];
    } else this.version = '';
    return this.engine;
  }

  async start() {
    const c = this.c();
    this.stopped = false;
    if (!c.enabled) { this.log.info('Virenschutz ist deaktiviert'); return; }
    ensureDir(this.qdir, 0o700);
    await this.detectEngine();
    if (!this.engine) {
      this.log.warn('ClamAV nicht gefunden (Paket "clamav"/"clamav-daemon" installieren) – Virenschutz inaktiv');
      this.events.report({ kind: 'info', severity: 'warn', type: 'av-missing', msg: 'ClamAV ist nicht installiert oder nicht erreichbar – Virenscan inaktiv' });
    } else this.log.info(`Virenschutz: ${this.engine.kind} (${this.version})`);

    if (c.realtime) this.startWatch().catch((e) => this.log.warn(`Echtzeit-Überwachung: ${e.message}`));
    const flushMs = () => (this.engine && this.engine.kind === 'clamd' ? 2000 : 20000);
    const loop = () => {
      if (this.stopped) return;
      this.flush().catch(() => {}).finally(() => { const t = setTimeout(loop, flushMs()); t.unref(); this.timers.push(t); });
    };
    loop();
    const sched = setInterval(() => this.checkSchedule().catch(() => {}), 60000);
    const redetect = setInterval(() => { if (!this.engine || this.engine.kind === 'clamscan') this.detectEngine().catch(() => {}); }, 300000);
    sched.unref(); redetect.unref();
    this.timers.push(sched, redetect);
  }

  stop() {
    this.stopped = true;
    this.timers.forEach((t) => { clearInterval(t); clearTimeout(t); });
    this.timers = [];
    for (const w of this.watchers.values()) { try { w.close(); } catch (_) { /* egal */ } }
    this.watchers.clear();
    for (const t of this.debounce.values()) clearTimeout(t);
    this.debounce.clear();
  }

  async restart() { this.stop(); await this.start(); }

  // ---------- Echtzeit-Überwachung ----------
  isExcluded(p) {
    if (p === this.qdir || p.startsWith(`${this.qdir}/`)) return true;
    const wrapped = `/${p}/`;
    return this.c().exclude.some((x) => wrapped.includes(`/${x}/`));
  }

  async watchTree(root, scanExisting) {
    const max = this.c().watch_max_dirs;
    const stack = [[root, 0]];
    let n = 0;
    while (stack.length) {
      if (this.watchers.size >= max) { if (!this.truncated) { this.truncated = true; this.log.warn(`Echtzeit-Überwachung auf ${max} Verzeichnisse begrenzt (watch_max_dirs)`); } break; }
      const [dir, depth] = stack.pop();
      if (this.isExcluded(dir)) continue;
      if (!this.watchers.has(dir)) {
        try {
          const w = fs.watch(dir, { persistent: false }, (ev, name) => this.onFsEvent(dir, name));
          w.on('error', () => { this.watchers.delete(dir); });
          this.watchers.set(dir, w);
        } catch (e) {
          if (e.code === 'ENOSPC') { this.log.warn('inotify-Limit erreicht – fs.inotify.max_user_watches erhöhen'); break; }
          continue;
        }
      }
      let ents;
      try { ents = await fs.promises.readdir(dir, { withFileTypes: true }); } catch (_) { continue; }
      for (const e of ents) {
        const full = path.join(dir, e.name);
        if (e.isDirectory() && depth < 12) stack.push([full, depth + 1]);
        else if (scanExisting && e.isFile()) this.considerFile(full);
      }
      if (++n % 200 === 0) await new Promise((r) => setImmediate(r));
    }
  }

  async startWatch() {
    for (const root of this.c().watch_paths) {
      if (fs.existsSync(root)) await this.watchTree(root, false);
    }
    this.log.info(`Echtzeit-Virenüberwachung: ${this.watchers.size} Verzeichnisse`);
  }

  onFsEvent(dir, name) {
    if (!name || this.stopped) return;
    const full = path.join(dir, String(name));
    if (this.isExcluded(full)) return;
    clearTimeout(this.debounce.get(full));
    const t = setTimeout(() => { this.debounce.delete(full); this.checkPath(full).catch(() => {}); }, 1500);
    t.unref();
    this.debounce.set(full, t);
  }

  async checkPath(full) {
    let st;
    try { st = await fs.promises.lstat(full); } catch (_) { return; }
    if (st.isDirectory()) { await this.watchTree(full, true); return; }
    if (st.isFile()) this.considerFile(full, st);
  }

  considerFile(full, st) {
    try { st = st || fs.lstatSync(full); } catch (_) { return; }
    if (!st.isFile() || st.size === 0 || st.size > this.c().max_file_mb * 1024 * 1024) return;
    this.queue.add(full);
    if (this.c().flag_elf_in_tmp && TMP_DIRS.some((d) => full.startsWith(d)) && (st.mode & 0o111)) this.checkElf(full);
  }

  checkElf(full) {
    try {
      const fd = fs.openSync(full, 'r');
      const b = Buffer.alloc(4);
      fs.readSync(fd, b, 0, 4, 0);
      fs.closeSync(fd);
      if (b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46) {
        this.events.report({ kind: 'info', severity: 'warn', type: 'suspicious-binary', msg: `Ausführbare Programmdatei in temporärem Verzeichnis angelegt: ${full}`, details: { file: full } });
      }
    } catch (_) { /* weg */ }
  }

  // ---------- Scannen ----------
  async scanFiles(files) {
    if (!this.engine || !files.length) return [];
    const found = [];
    const base = this.engine.kind === 'clamd' ? ['--fdpass', '--no-summary', '--infected', '--stdout'] : ['--no-summary', '--infected', '--stdout'];
    for (let i = 0; i < files.length; i += 100) {
      const chunk = files.slice(i, i + 100);
      const r = await run(this.engine.bin, [...base, '--', ...chunk], { timeout: 600000 });
      for (const l of r.stdout.split('\n')) { const m = FOUND_RE.exec(l); if (m) found.push({ file: m[1], sig: m[2] }); }
      if (r.code === 2 && !found.length && r.stderr) this.log.debug(`${this.engine.bin}: ${r.stderr.trim().slice(0, 200)}`);
    }
    return found;
  }

  async flush() {
    if (this.flushing || !this.queue.size || !this.engine) return;
    this.flushing = true;
    try {
      const files = [...this.queue].slice(0, 200);
      files.forEach((f) => this.queue.delete(f));
      const existing = files.filter((f) => fs.existsSync(f));
      for (const hit of await this.scanFiles(existing)) await this.onInfected(hit.file, hit.sig, 'realtime');
    } finally { this.flushing = false; }
  }

  killRunning(file) {
    const killed = [];
    if (!this.c().kill_malicious_processes) return killed;
    let pids = [];
    try { pids = fs.readdirSync('/proc').filter((n) => /^\d+$/.test(n)); } catch (_) { return killed; }
    for (const pid of pids) {
      let exe;
      try { exe = fs.readlinkSync(`/proc/${pid}/exe`); } catch (_) { continue; }
      if (exe === file || exe === `${file} (deleted)`) {
        const n = Number(pid);
        if (n > 1 && n !== process.pid) { try { process.kill(n, 'SIGKILL'); killed.push(n); } catch (_) { /* weg */ } }
      }
    }
    return killed;
  }

  async onInfected(file, sig, source) {
    const c = this.c();
    const killed = this.killRunning(file);
    let result;
    try {
      if (c.action === 'quarantine') result = `in Quarantäne verschoben (${await this.quarantine(file, sig, source)})`;
      else if (c.action === 'delete') { fs.unlinkSync(file); result = 'gelöscht'; } else result = 'nur gemeldet';
    } catch (e) { result = `Aktion fehlgeschlagen: ${e.message}`; }
    const actions = [`Datei ${result}`];
    if (killed.length) actions.push(`laufende Prozesse beendet: ${killed.join(', ')}`);
    const realtime = source === 'realtime';
    return this.events.report({
      kind: killed.length || realtime ? 'compromise' : 'info', subject: 'host',
      severity: killed.length ? 'critical' : (realtime ? 'high' : 'warn'),
      score: killed.length ? 100 : (realtime ? 40 : 0),
      type: 'malware-found', actions,
      msg: `Schadsoftware gefunden: ${sig} in ${file}`, details: { file, signature: sig, source },
    });
  }

  async fullScan(paths, source = 'manuell') {
    const c = this.c();
    if (this.scanStatus.running) return { error: 'Ein Scan läuft bereits' };
    if (!this.engine) await this.detectEngine();
    if (!this.engine) return { error: 'ClamAV ist nicht installiert' };
    const list = (paths && paths.length ? paths : c.scan_paths).filter((p) => typeof p === 'string' && fs.existsSync(p));
    if (!list.length) return { error: 'Keine gültigen Scan-Pfade' };
    this.scanStatus = { running: true, started: Date.now(), paths: list, found: 0, source };
    const args = this.engine.kind === 'clamd'
      ? ['--fdpass', '--no-summary', '--infected', '--stdout', '--', ...list]
      : ['-r', '--no-summary', '--infected', '--stdout', `--max-filesize=${c.max_file_mb}M`, `--max-scansize=${c.max_file_mb * 4}M`,
        `--exclude-dir=^${this.qdir}`, ...c.exclude.map((x) => `--exclude-dir=/${x.replace(/[.+?^${}()|[\]\\]/g, '\\$&')}(/|$)`), '--', ...list];
    this.log.info(`Vollscan gestartet (${source}): ${list.join(', ')}`);
    const hits = [];
    const res = await streamRun(this.engine.bin, args, (l) => { const m = FOUND_RE.exec(l); if (m) { hits.push({ file: m[1], sig: m[2] }); this.scanStatus.found = hits.length; } }, 6 * 3600 * 1000);
    for (const h of hits) if (!this.isExcluded(h.file)) await this.onInfected(h.file, h.sig, source);
    const sum = { time: Date.now(), duration_s: Math.round((Date.now() - this.scanStatus.started) / 1000), infected: hits.length, paths: list, source, ok: res.code === 0 || res.code === 1, error: res.code > 1 ? (res.stderr || res.error || `Exit ${res.code}`) : null };
    this.state.data.last_scan = sum;
    this.state.save();
    this.scanStatus = { running: false, started: 0, paths: [], found: 0, source: '', last: sum };
    this.log.info(`Vollscan beendet: ${hits.length} Funde in ${sum.duration_s} s`);
    this.events.report({ kind: 'info', severity: hits.length ? 'warn' : 'info', type: 'av-scan', msg: `Vollscan beendet (${source}): ${hits.length} Funde, ${sum.duration_s} s${sum.error ? ` – Fehler: ${String(sum.error).slice(0, 120)}` : ''}` });
    return sum;
  }

  async checkSchedule() {
    const s = this.c().schedule;
    if (!s.enabled || !this.c().enabled || this.scanStatus.running) return;
    const now = new Date();
    const hhmm = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
    const day = now.toDateString();
    if (hhmm === s.time && this._lastDay !== day) { this._lastDay = day; await this.fullScan(null, 'geplant'); }
  }

  // ---------- Quarantäne ----------
  async quarantine(file, sig, source = '') {
    ensureDir(this.qdir, 0o700);
    const st = fs.lstatSync(file);
    if (!st.isFile()) throw new Error('keine reguläre Datei');
    const id = `${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
    const dest = path.join(this.qdir, `${id}.bin`);
    let sha = null;
    try { sha = await hashFile(file); } catch (_) { /* egal */ }
    try { fs.renameSync(file, dest); } catch (e) {
      if (e.code !== 'EXDEV') throw e;
      fs.copyFileSync(file, dest);
      fs.unlinkSync(file);
    }
    try { fs.chmodSync(dest, 0o000); } catch (_) { /* egal */ }
    fs.writeFileSync(path.join(this.qdir, `${id}.json`), JSON.stringify({ id, original: file, signature: sig, time: Date.now(), size: st.size, mode: st.mode & 0o7777, uid: st.uid, gid: st.gid, sha256: sha, source }), { mode: 0o600 });
    return id;
  }

  listQuarantine() {
    const out = [];
    let names = [];
    try { names = fs.readdirSync(this.qdir); } catch (_) { return out; }
    for (const n of names) {
      if (!n.endsWith('.json')) continue;
      try { out.push(JSON.parse(fs.readFileSync(path.join(this.qdir, n), 'utf8'))); } catch (_) { /* kaputt */ }
    }
    return out.sort((a, b) => b.time - a.time);
  }

  metaFor(id) {
    if (!/^[a-z0-9-]+$/.test(String(id))) throw new Error('Ungültige ID');
    return JSON.parse(fs.readFileSync(path.join(this.qdir, `${id}.json`), 'utf8'));
  }

  restoreQuarantine(id) {
    const m = this.metaFor(id);
    const src = path.join(this.qdir, `${m.id}.bin`);
    let target = path.resolve(String(m.original));
    const exists = (p) => { try { fs.lstatSync(p); return true; } catch (_) { return false; } }; // lstat: auch kaputte Symlinks zählen
    if (exists(target)) target += '.restored';
    for (let i = 1; exists(target); i++) target = `${m.original}.restored${i}`;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    // O_EXCL|O_NOFOLLOW: schreibt nie durch einen untergeschobenen Symlink an eine fremde Stelle (Root-Rechte!)
    const fd = fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeSync(fd, fs.readFileSync(src)); try { fs.fchmodSync(fd, m.mode & 0o666); fs.fchownSync(fd, m.uid, m.gid); } catch (_) { /* egal */ } } finally { fs.closeSync(fd); }
    this.removeQuarantine(id);
    return target;
  }

  removeQuarantine(id) {
    const m = this.metaFor(id);
    for (const ext of ['bin', 'json']) { try { fs.unlinkSync(path.join(this.qdir, `${m.id}.${ext}`)); } catch (_) { /* weg */ } }
  }

  // ---------- Selbsttest mit dem harmlosen EICAR-Testmuster ----------
  async selftest() {
    if (!this.engine) await this.detectEngine();
    if (!this.engine) return { ok: false, error: 'ClamAV ist nicht installiert oder nicht erreichbar' };
    const f = `/tmp/netguard-selftest-${crypto.randomBytes(4).toString('hex')}.com`;
    fs.writeFileSync(f, EICAR, { mode: 0o600 });
    try {
      const hits = await this.scanFiles([f]);
      return hits.length ? { ok: true, engine: this.engine.kind, signature: hits[0].sig } : { ok: false, engine: this.engine.kind, error: 'Testmuster wurde NICHT erkannt (Signaturen aktuell? freshclam ausführen)' };
    } finally { try { fs.unlinkSync(f); } catch (_) { /* evtl. schon in Quarantäne */ } }
  }

  status() {
    return {
      enabled: this.c().enabled, engine: this.engine ? this.engine.kind : null, version: this.version,
      realtime: this.c().realtime, watched_dirs: this.watchers.size, queue: this.queue.size,
      scan: this.scanStatus, last_scan: this.state.data.last_scan, quarantine: this.listQuarantine().length,
      action: this.c().action,
    };
  }
}

module.exports = { Antivirus, EICAR };
