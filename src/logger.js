'use strict';
// Programm-Log (stdout/Datei) und Ereignis-Log (JSON-Lines + Ringpuffer)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { ensureDir, rotateIfBig, tailFile } = require('./util');

const SEV = { info: 0, warn: 1, high: 2, critical: 3 };

class Logger {
  constructor(dir, { toFile = true, debug = false } = {}) {
    this.dir = dir;
    this.toFile = toFile;
    this.debugOn = debug || !!process.env.NETGUARD_DEBUG;
    this.file = path.join(dir, 'netguard.log');
    if (toFile) { try { ensureDir(dir, 0o750); } catch (_) { this.toFile = false; } }
  }
  _w(level, msg) {
    const line = `${new Date().toISOString()} [${level}] ${msg}`;
    console.log(line);
    if (this.toFile) {
      try { rotateIfBig(this.file, 5 * 1024 * 1024, 2); fs.appendFileSync(this.file, line + '\n'); } catch (_) { this.toFile = false; }
    }
  }
  info(m) { this._w('info', m); }
  warn(m) { this._w('warn', m); }
  error(m) { this._w('error', m); }
  debug(m) { if (this.debugOn) this._w('debug', m); }
}

class EventLog {
  constructor(dir, max = 2000) {
    this.max = max;
    this.file = path.join(dir, 'events.jsonl');
    this.ring = [];
    try { ensureDir(dir, 0o750); } catch (_) { /* ignorieren */ }
    for (const l of tailFile(this.file, 768 * 1024).slice(-max)) {
      try { this.ring.push(JSON.parse(l)); } catch (_) { /* kaputte Zeile */ }
    }
  }
  add(ev) {
    ev.id = ev.id || crypto.randomBytes(5).toString('hex');
    ev.ts = ev.ts || Date.now();
    this.ring.push(ev);
    if (this.ring.length > this.max) this.ring.splice(0, this.ring.length - this.max);
    try { rotateIfBig(this.file, 10 * 1024 * 1024, 3); fs.appendFileSync(this.file, JSON.stringify(ev) + '\n'); } catch (_) { /* nur Speicher */ }
    return ev;
  }
  recent(limit = 200, minSev = 'info', filter = '') {
    const min = SEV[minSev] || 0;
    const f = filter ? filter.toLowerCase() : '';
    const out = [];
    for (let i = this.ring.length - 1; i >= 0 && out.length < limit; i--) {
      const e = this.ring[i];
      if ((SEV[e.severity] || 0) < min) continue;
      if (f && !JSON.stringify(e).toLowerCase().includes(f)) continue;
      out.push(e);
    }
    return out;
  }
  counts(sinceMs) {
    const c = { info: 0, warn: 0, high: 0, critical: 0 };
    const since = Date.now() - sinceMs;
    for (let i = this.ring.length - 1; i >= 0; i--) {
      const e = this.ring[i];
      if (e.ts < since) break;
      c[e.severity] = (c[e.severity] || 0) + 1;
    }
    return c;
  }
}

module.exports = { Logger, EventLog, SEV };
