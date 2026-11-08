'use strict';
// Persistenter Laufzeit-Zustand (Isolation, Sperrliste, Baselines)
const fs = require('fs');
const path = require('path');
const { atomicWrite, ensureDir } = require('./util');

class State {
  constructor(dir) {
    ensureDir(dir, 0o750);
    this.file = path.join(dir, 'state.json');
    this.data = {
      isolated: false, isolated_at: 0, isolated_reason: '', downed_ifaces: [],
      bans: [], ban_meta: {}, baseline: { listeners: null, integrity: {}, arp: {}, devices: {} },
      notify_queue: [], last_scan: null, last_feed_update: 0,
    };
    try {
      const d = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      this.data = { ...this.data, ...d, baseline: { ...this.data.baseline, ...(d.baseline || {}) } };
    } catch (_) { /* erster Start */ }
    this._t = null;
  }
  save() {
    if (this._t) return;
    this._t = setTimeout(() => { this._t = null; this.flush(); }, 500);
    if (this._t.unref) this._t.unref();
  }
  flush() {
    try { atomicWrite(this.file, JSON.stringify(this.data), 0o600); } catch (_) { /* Platte voll o.ä. */ }
  }
}

module.exports = { State };
