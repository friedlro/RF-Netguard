'use strict';
// Zentrale Ereignis-/Bedrohungs-Engine: protokolliert, benachrichtigt, sperrt Angreifer
// und trennt den Rechner vom Netz, wenn die Kompromittierungs-Punkte zu hoch werden.
const { SEV } = require('./logger');
const { localAddresses } = require('./util');

class Events {
  constructor({ cfg, log, eventLog, notifier, state }) {
    this.cfg = cfg;
    this.log = log;
    this.eventLog = eventLog;
    this.notifier = notifier;
    this.state = state;
    this.fw = null; // wird nach dem Erzeugen der Firewall gesetzt
    this.scores = []; // {ts, score, type}
    this.clientScores = new Map(); // ip -> [{ts, score}]
    this.isolating = false;
  }

  /**
   * ev: { kind: 'attack'|'compromise'|'info', severity, type, msg, src?, subject?: 'host'|'client',
   *       score?, ban?: seconds, details? }
   */
  async report(ev) {
    ev.severity = SEV[ev.severity] !== undefined ? ev.severity : 'info';
    ev.kind = ev.kind || 'info';
    ev.actions = ev.actions || [];
    const cfg = this.cfg();

    // Angreifer von außen sperren
    if (ev.ban && ev.src && this.fw) {
      try {
        const ok = await this.fw.ban(ev.src, ev.ban, ev.type, 'auto');
        if (ok) ev.actions.push(`${ev.src} für ${Math.round(ev.ban / 60)} min gesperrt`);
      } catch (e) { this.log.warn(`Sperre fehlgeschlagen: ${e.message}`); }
    }

    this.eventLog.add(ev);
    const lvl = { info: 'info', warn: 'warn', high: 'warn', critical: 'error' }[ev.severity];
    this.log[lvl](`[${ev.severity}] ${ev.type}: ${ev.msg}`);

    // Bewertung für Netztrennung
    let isolate = null;
    if (ev.kind === 'compromise' && ev.score > 0) {
      const subject = ev.subject || 'host';
      const winMs = cfg.isolation.window_minutes * 60000;
      const now = Date.now();
      if (subject === 'host' || (ev.src && localAddresses().has(ev.src))) {
        this.scores.push({ ts: now, score: ev.score, type: ev.type });
        this.scores = this.scores.filter((s) => now - s.ts <= winMs);
        const total = this.scores.reduce((a, s) => a + s.score, 0);
        if (cfg.isolation.enabled && !this.isolationPaused() && total >= cfg.isolation.score_threshold && !this.state.data.isolated) {
          isolate = `Bedrohungswert ${total}/${cfg.isolation.score_threshold} in ${cfg.isolation.window_minutes} min (zuletzt: ${ev.type})`;
        }
      } else if (ev.src && cfg.isolation.quarantine_clients && this.fw) {
        const arr = (this.clientScores.get(ev.src) || []).filter((s) => now - s.ts <= winMs);
        arr.push({ ts: now, score: ev.score });
        this.clientScores.set(ev.src, arr);
        const total = arr.reduce((a, s) => a + s.score, 0);
        if (total >= cfg.isolation.score_threshold) {
          const ok = await this.fw.ban(ev.src, 3600, `Client kompromittiert: ${ev.type}`, 'auto').catch(() => false);
          if (ok) {
            ev.actions.push(`LAN-Gerät ${ev.src} 1 h in Quarantäne (gesperrt)`);
            this.clientScores.delete(ev.src);
          }
        }
      }
    }

    // Benachrichtigung zuerst – danach erst trennen (sonst käme die Nachricht nicht mehr raus)
    if (isolate) {
      ev.actions.push('Rechner wird vom Netz getrennt');
      await this.notifier.send(ev, { wait: true, noCooldown: true }).catch(() => {});
      await this.isolate(isolate, ev);
    } else {
      this.notifier.send(ev).catch(() => {});
    }
    return ev;
  }

  async isolate(reason, trigger) {
    if (this.isolating || this.state.data.isolated || !this.fw) return false;
    this.isolating = true;
    try {
      const ok = await this.fw.isolate(reason);
      if (ok) {
        const ev = this.eventLog.add({
          kind: 'info', severity: 'critical', type: 'isolated',
          msg: `Rechner vom Netz getrennt: ${reason}`, details: trigger ? { trigger: trigger.type, src: trigger.src } : undefined,
        });
        this.log.error(ev.msg);
        // Falls die erste Nachricht nicht durchkam, liegt sie in der Warteschlange und geht nach Freigabe raus
        this.notifier.send(ev, { noCooldown: true }).catch(() => {});
      }
      return ok;
    } finally { this.isolating = false; }
  }

  // Automatische Trennung zeitweise aussetzen (z. B. nach Fehlalarm), Ereignisse werden weiter protokolliert und gemeldet
  isolationPaused() {
    const d = this.state.data;
    return !!d.protection_off || (d.isolation_paused_until || 0) > Date.now();
  }

  pauseIsolation(minutes) {
    const d = this.state.data;
    d.isolation_paused_until = minutes > 0 ? Date.now() + Math.min(minutes, 24 * 60) * 60000 : 0;
    this.state.save();
    const ev = this.eventLog.add({ kind: 'info', severity: 'warn', type: 'isolation-paused', msg: minutes > 0 ? `Automatische Netztrennung für ${Math.min(minutes, 24 * 60)} min ausgesetzt` : 'Automatische Netztrennung wieder aktiv' });
    this.log.warn(ev.msg);
    return d.isolation_paused_until;
  }

  async protection(on, by = 'manuell') {
    if (!this.fw) return false;
    const ok = on ? await this.fw.protectionOn() : await this.fw.protectionOff();
    this.scores = [];
    const ev = this.eventLog.add({ kind: 'info', severity: on ? 'warn' : 'high', type: on ? 'protection-on' : 'protection-off', msg: on ? `Schutz wieder eingeschaltet (${by})` : `Firewall und automatische Netztrennung ausgeschaltet (${by})` });
    this.log.warn(ev.msg);
    this.notifier.send(ev, { noCooldown: true }).catch(() => {});
    return ok !== undefined;
  }

  async release(by = 'manuell') {
    if (!this.fw) return false;
    const ok = await this.fw.release();
    if (ok) {
      this.scores = [];
      const ev = this.eventLog.add({ kind: 'info', severity: 'warn', type: 'released', msg: `Netztrennung aufgehoben (${by})` });
      this.log.warn(ev.msg);
      this.notifier.send(ev, { noCooldown: true }).catch(() => {});
      this.notifier.flush().catch(() => {});
    }
    return ok;
  }

  currentScore() {
    const winMs = this.cfg().isolation.window_minutes * 60000;
    const now = Date.now();
    return this.scores.filter((s) => now - s.ts <= winMs).reduce((a, s) => a + s.score, 0);
  }
}

module.exports = { Events };
