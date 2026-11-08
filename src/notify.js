'use strict';
// Benachrichtigungen: Telegram, ntfy, E-Mail (SMTP), Webhook
const net = require('net');
const os = require('os');
const tls = require('tls');
const { httpRequest, asciiFold } = require('./util');
const { SEV } = require('./logger');

const LABEL = { info: 'INFO', warn: 'WARNUNG', high: 'HOCH', critical: 'KRITISCH' };

// ---------- minimaler SMTP-Client ----------
function smtpSend(o) {
  return new Promise((resolve, reject) => {
    let sock = null;
    let buf = '';
    let waiting = null;
    let lines = [];
    let done = false;
    const timer = setTimeout(() => fail(new Error('SMTP-Timeout')), o.timeout || 20000);
    function fail(e) { if (done) return; done = true; clearTimeout(timer); try { sock && sock.destroy(); } catch (_) { /* egal */ } reject(e); }
    function onData(d) {
      buf += d;
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 2);
        lines.push(line);
        if (/^\d{3}( |$)/.test(line)) {
          const r = { code: parseInt(line.slice(0, 3), 10), text: lines.join('\n') };
          lines = [];
          if (waiting) { const w = waiting; waiting = null; w(r); }
        }
      }
    }
    const attach = (s) => { sock = s; s.setEncoding('utf8'); s.on('data', onData); s.on('error', fail); };
    const reply = () => new Promise((r) => { waiting = r; });
    const cmd = async (c, ok) => {
      if (c !== null) sock.write(c + '\r\n');
      const r = await reply();
      if (!String(r.code).startsWith(ok)) throw new Error(`SMTP: ${r.text}`);
      return r;
    };
    const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
    (async () => {
      const host = o.host;
      const port = o.port || (o.secure === 'tls' ? 465 : 587);
      const connected = new Promise((res, rej) => {
        const s = o.secure === 'tls'
          ? tls.connect({ host, port, servername: host }, () => res(s))
          : net.connect({ host, port }, () => res(s));
        s.once('error', rej);
      });
      attach(await connected);
      await cmd(null, '2');
      const me = os.hostname() || 'netguard';
      await cmd(`EHLO ${me}`, '2');
      if (o.secure === 'starttls') {
        await cmd('STARTTLS', '2');
        sock.removeListener('data', onData);
        const t = tls.connect({ socket: sock, servername: host });
        await new Promise((res, rej) => { t.once('secureConnect', res); t.once('error', rej); });
        attach(t);
        await cmd(`EHLO ${me}`, '2');
      }
      if (o.user) await cmd(`AUTH PLAIN ${b64(`\0${o.user}\0${o.pass || ''}`)}`, '2');
      const rcpts = String(o.to).split(/[,;\s]+/).filter(Boolean);
      const from = (String(o.from).match(/<([^>]+)>/) || [null, o.from])[1];
      await cmd(`MAIL FROM:<${from}>`, '2');
      for (const r of rcpts) await cmd(`RCPT TO:<${r}>`, '2');
      await cmd('DATA', '3');
      const body = (b64(o.text).match(/.{1,76}/g) || []).join('\r\n');
      const msg = [
        `From: ${o.from}`, `To: ${rcpts.join(', ')}`,
        `Subject: =?UTF-8?B?${b64(o.subject)}?=`, `Date: ${new Date().toUTCString()}`,
        'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', body,
      ].join('\r\n');
      sock.write(`${msg}\r\n.\r\n`);
      const r = await reply();
      if (r.code !== 250) throw new Error(`SMTP: ${r.text}`);
      try { sock.write('QUIT\r\n'); } catch (_) { /* egal */ }
      done = true;
      clearTimeout(timer);
      sock.end();
      resolve();
    })().catch(fail);
  });
}

class Notifier {
  constructor({ cfg, log, state }) {
    this.cfg = cfg; // Funktion -> aktuelle Config
    this.log = log;
    this.state = state;
    this.last = new Map(); // Schlüssel -> letzter Versand
    this.timer = setInterval(() => this.flush().catch(() => {}), 120000);
    if (this.timer.unref) this.timer.unref();
  }

  stop() { clearInterval(this.timer); }

  channels() {
    const n = this.cfg().notify;
    const c = [];
    if (n.telegram.enabled && n.telegram.bot_token && n.telegram.chat_id) c.push('telegram');
    if (n.ntfy.enabled && n.ntfy.topic) c.push('ntfy');
    if (n.email.enabled && n.email.host && n.email.to) c.push('email');
    if (n.webhook.enabled && n.webhook.url) c.push('webhook');
    return c;
  }

  format(ev) {
    const n = this.cfg().notify;
    const host = n.label || os.hostname();
    const lines = [
      `RF-NetGuard ${LABEL[ev.severity] || ev.severity} – ${host}`,
      ev.msg,
      '',
      `Typ: ${ev.type}`,
    ];
    if (ev.src) lines.push(`Quelle: ${ev.src}`);
    lines.push(`Zeit: ${new Date(ev.ts || Date.now()).toLocaleString('de-AT')}`);
    if (ev.actions && ev.actions.length) lines.push(`Maßnahmen: ${ev.actions.join('; ')}`);
    if (ev.details) {
      const d = typeof ev.details === 'string' ? ev.details : JSON.stringify(ev.details);
      lines.push(`Details: ${d.slice(0, 600)}`);
    }
    return { title: `RF-NetGuard ${LABEL[ev.severity] || ev.severity}: ${ev.type} (${host})`, text: lines.join('\n') };
  }

  async sendVia(ch, ev) {
    const n = this.cfg().notify;
    const { title, text } = this.format(ev);
    if (ch === 'telegram') {
      const t = n.telegram;
      const r = await httpRequest(`${t.api_base.replace(/\/$/, '')}/bot${t.bot_token}/sendMessage`, {
        method: 'POST', body: { chat_id: t.chat_id, text, disable_web_page_preview: true }, timeout: 10000,
      });
      if (r.status !== 200) throw new Error(`Telegram HTTP ${r.status}: ${r.body.toString().slice(0, 120)}`);
    } else if (ch === 'ntfy') {
      const t = n.ntfy;
      const prio = ev.severity === 'critical' ? 'urgent' : ev.severity === 'high' ? 'high' : 'default';
      const headers = { Title: asciiFold(title), Priority: prio, Tags: ev.severity === 'critical' ? 'rotating_light,shield' : 'warning,shield' };
      if (t.token) headers.Authorization = `Bearer ${t.token}`;
      const r = await httpRequest(`${t.server.replace(/\/$/, '')}/${encodeURIComponent(t.topic)}`, { method: 'POST', headers, body: text, timeout: 10000 });
      if (r.status >= 300) throw new Error(`ntfy HTTP ${r.status}`);
    } else if (ch === 'email') {
      const t = n.email;
      await smtpSend({ host: t.host, port: t.port, secure: t.secure, user: t.user, pass: t.pass, from: t.from || t.user, to: t.to, subject: title, text });
    } else if (ch === 'webhook') {
      const t = n.webhook;
      const r = await httpRequest(t.url, { method: 'POST', headers: t.headers || {}, body: { event: ev, text, title }, timeout: 10000 });
      if (r.status >= 300) throw new Error(`Webhook HTTP ${r.status}`);
    }
  }

  // Sendet an alle Kanäle. opts.force umgeht Schwelle/Cooldown, opts.wait wartet auf Zustellung.
  async send(ev, opts = {}) {
    const n = this.cfg().notify;
    if (!opts.force) {
      if ((SEV[ev.severity] || 0) < (SEV[n.min_severity] || 0)) return { sent: 0, skipped: 'severity' };
      const key = `${ev.type}|${ev.src || ev.subject_id || ''}`;
      const last = this.last.get(key) || 0;
      if (Date.now() - last < n.cooldown_s * 1000 && !opts.noCooldown) return { sent: 0, skipped: 'cooldown' };
      this.last.set(key, Date.now());
      if (this.last.size > 2000) this.last.clear();
    }
    const chans = this.channels();
    if (!chans.length) return { sent: 0, skipped: 'no-channel' };
    const job = (async () => {
      let ok = 0;
      const errors = [];
      await Promise.all(chans.map(async (ch) => {
        try { await this.sendVia(ch, ev); ok++; } catch (e) { errors.push(`${ch}: ${e.message}`); }
      }));
      if (!ok && !opts.force) this.enqueue(ev);
      if (errors.length) this.log.warn(`Benachrichtigung fehlgeschlagen (${errors.join(' | ')})`);
      return { sent: ok, errors };
    })();
    return opts.wait ? Promise.race([job, new Promise((r) => setTimeout(() => r({ sent: 0, errors: ['Timeout'] }), 12000))]) : job.catch(() => ({ sent: 0 }));
  }

  enqueue(ev) {
    const q = this.state.data.notify_queue;
    q.push({ ev, tries: 0 });
    if (q.length > 50) q.shift();
    this.state.save();
  }

  // Wiederholt fehlgeschlagene Nachrichten (z.B. nach Aufhebung der Netztrennung)
  async flush() {
    const q = this.state.data.notify_queue;
    if (!q.length || !this.channels().length) return;
    const pending = q.splice(0, q.length);
    for (const item of pending) {
      item.tries++;
      const r = await this.send(item.ev, { force: true });
      if (!r.sent && item.tries < 8) q.push(item);
    }
    this.state.save();
  }

  async test() {
    const ev = { type: 'test', severity: 'high', msg: 'Dies ist eine Testnachricht von RF-NetGuard. Benachrichtigungen funktionieren.', ts: Date.now() };
    const chans = this.channels();
    if (!chans.length) return { ok: false, error: 'Kein Benachrichtigungskanal konfiguriert/aktiviert.' };
    const res = {};
    await Promise.all(chans.map(async (ch) => {
      try { await this.sendVia(ch, ev); res[ch] = 'ok'; } catch (e) { res[ch] = e.message; }
    }));
    return { ok: Object.values(res).some((v) => v === 'ok'), channels: res };
  }
}

module.exports = { Notifier, smtpSend };
