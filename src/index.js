#!/usr/bin/env node
'use strict';
// RF-NetGuard – Hauptprogramm (Daemon) und Kommandozeile
const fs = require('fs');
const http = require('http');
const path = require('path');
const readline = require('readline');
const config = require('./config');
const { ensureDir } = require('./util');
const { Logger, EventLog } = require('./logger');
const { State } = require('./state');
const { Notifier } = require('./notify');
const { Events } = require('./events');
const { Firewall, flushAll } = require('./firewall');
const { DnsServer } = require('./dns');
const { Ids } = require('./ids');
const { Antivirus } = require('./av');
const { Web, hashPassword } = require('./web');
const update = require('./update');

const VERSION = require('../package.json').version;

class App {
  constructor() { this.version = VERSION; this.config = null; }

  cfg() { return this.config; }
  setConfig(c) { this.config = c; }

  init() {
    this.config = config.load();
    const p = this.config.paths;
    ensureDir(p.data, 0o750);
    ensureDir(p.log, 0o750);
    ensureDir(p.run, 0o755);
    const cfg = () => this.config;
    this.log = new Logger(p.log);
    this.eventLog = new EventLog(p.log);
    this.state = new State(p.data);
    this.notifier = new Notifier({ cfg, log: this.log, state: this.state });
    this.events = new Events({ cfg, log: this.log, eventLog: this.eventLog, notifier: this.notifier, state: this.state });
    this.fw = new Firewall({ cfg, log: this.log, state: this.state, events: this.events });
    this.events.fw = this.fw;
    this.dns = new DnsServer({ cfg, log: this.log, dataDir: p.data });
    this.ids = new Ids({ cfg, log: this.log, events: this.events, fw: this.fw, state: this.state, dns: this.dns });
    this.av = new Antivirus({ cfg, log: this.log, events: this.events, state: this.state, dataDir: p.data });
    this.updater = new update.Updater({ cfg, log: this.log, eventLog: this.eventLog, dataDir: p.data, canAuto: () => !this.state.data.isolated });
    this.web = new Web({ app: this });
  }

  async start() {
    this.init();
    const c = this.config;
    this.log.info(`RF-NetGuard ${VERSION} startet (Modus: ${c.mode}, Sicherheitsstufe: ${c.security_level})`);

    process.on('uncaughtException', (e) => this.log.error(`Unerwarteter Fehler: ${e.stack || e.message}`));
    process.on('unhandledRejection', (e) => this.log.error(`Unbehandelter Fehler: ${e && e.stack ? e.stack : e}`));
    for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => this.stop(sig));
    process.on('SIGHUP', () => { this.log.info('SIGHUP: Konfiguration wird neu geladen'); this.config = config.load(); this.reload().catch((e) => this.log.error(e.message)); });

    // Firewall zuerst – schützt, bevor irgendein Dienst Anfragen annimmt
    try { await this.fw.start(); } catch (e) { this.log.error(`Firewall: ${e.message}`); }
    try { await this.dns.start(); } catch (e) {
      this.log.error(`DNS-Filter: ${e.message}`);
      this.events.report({ kind: 'info', severity: 'high', type: 'dns-error', msg: `DNS-Filter konnte nicht starten: ${e.message}` });
    }
    for (const [name, p] of [['Angriffserkennung', this.ids.start()], ['Virenschutz', this.av.start()], ['Web', this.web.start()]]) {
      try { await p; } catch (e) { this.log.error(`${name}: ${e.message}`); }
    }
    this.eventLog.add({ kind: 'info', severity: 'info', type: 'startup', msg: `RF-NetGuard ${VERSION} gestartet` });
    if (this.state.data.isolated) {
      this.log.warn(`ACHTUNG: Rechner ist vom Netz getrennt seit ${new Date(this.state.data.isolated_at).toLocaleString('de-AT')} – Freigabe: sudo rf-netguard release`);
    }
    this.notifier.flush().catch(() => {});
    this.updater.start();
  }

  async reload() {
    this.fw.refreshProtected();
    await this.fw.loadFeedCache();
    await this.fw.apply();
    await this.dns.reload().catch((e) => this.log.error(`DNS-Reload: ${e.message}`));
    await this.ids.restart();
    await this.av.restart();
    this.fw.scheduleAutoRelease();
    this.log.info('Konfiguration neu geladen');
  }

  stop(sig) {
    this.log.info(`${sig}: RF-NetGuard wird beendet (Firewall-Regeln bleiben im Kernel aktiv)`);
    try { this.ids.stop(); this.av.stop(); this.fw.stop(); this.web.stop(); this.updater.stop(); this.notifier.stop(); this.state.flush(); } catch (_) { /* egal */ }
    this.dns.stop().catch(() => {}).finally(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  }
}

// ===================== Kommandozeile =====================
function ctl(method, p, body) {
  return new Promise((resolve, reject) => {
    const sock = path.join(config.load().paths.run, 'control.sock');
    const req = http.request({ socketPath: sock, path: p, method, headers: { 'Content-Type': 'application/json' } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (_) { /* kein JSON */ }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('error', reject);
    req.end(body ? JSON.stringify(body) : undefined);
  });
}

function promptHidden(q) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) {
      const rl = readline.createInterface({ input: process.stdin });
      rl.once('line', (l) => { rl.close(); resolve(l); });
      return;
    }
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(q)) process.stdout.write(s); else process.stdout.write('*'); };
    rl.question(q, (a) => { rl.close(); process.stdout.write('\n'); resolve(a); });
  });
}

const fmtTime = (t) => (t ? new Date(t).toLocaleString('de-AT') : '–');

async function daemonOrDie() {
  try { return await ctl('GET', '/api/status'); } catch (_) {
    console.error('RF-NetGuard-Dienst läuft nicht (oder kein Zugriff). Start: sudo systemctl start netguard');
    process.exit(1);
  }
}

async function cli(cmd, args) {
  switch (cmd) {
    case 'status': {
      const r = await daemonOrDie();
      const s = r.json;
      console.log(`RF-NetGuard ${s.version} auf ${s.hostname} – Modus ${s.mode}, Stufe ${s.level}`);
      console.log(s.isolation.isolated ? `⚠  VOM NETZ GETRENNT seit ${fmtTime(s.isolation.since)}: ${s.isolation.reason}\n   Freigabe: sudo rf-netguard release` : `Netzverbindung: normal (Bedrohungswert ${s.isolation.score}/${s.isolation.threshold})`);
      if (s.protection_off) console.log('⚠  SCHUTZ AUS (Firewall + Auto-Trennung manuell ausgeschaltet) – einschalten: sudo rf-netguard protection on');
      if (s.isolation.paused_until) console.log(`Automatische Netztrennung pausiert bis ${fmtTime(s.isolation.paused_until)}`);
      console.log(`Firewall: ${s.firewall.applied ? 'aktiv' : 'NICHT aktiv'}, ${s.firewall.bans} gesperrte Adressen, ${s.firewall.threat_entries} Bedrohungs-IPs`);
      console.log(`DNS-Filter: ${s.dns.running ? 'läuft' : 'aus'}, ${s.dns.total} Abfragen, ${s.dns.blocked} blockiert (${s.dns.blocked_pct} %), ${s.dns.rules} Regeln`);
      console.log(`Virenschutz: ${s.av.engine ? `${s.av.engine} (${s.av.version})` : 'nicht verfügbar'}, ${s.av.watched_dirs} Verzeichnisse überwacht, ${s.av.quarantine} in Quarantäne`);
      console.log(`Ereignisse (24 h): ${s.events24h.critical} kritisch, ${s.events24h.high} hoch, ${s.events24h.warn} Warnungen`);
      console.log(`Benachrichtigung: ${s.notify_channels.length ? s.notify_channels.join(', ') : 'kein Kanal eingerichtet'}`);
      break;
    }
    case 'events': {
      const r = await daemonOrDie();
      const e = await ctl('GET', `/api/events?limit=${parseInt(args[0], 10) || 30}&min=${args[1] || 'info'}`);
      void r;
      for (const ev of e.json.reverse()) console.log(`${fmtTime(ev.ts)}  [${ev.severity.padEnd(8)}] ${ev.type}: ${ev.msg}`);
      break;
    }
    case 'isolate': {
      await daemonOrDie();
      const r = await ctl('POST', '/api/isolate', { reason: args.join(' ') || 'manuell per Kommandozeile' });
      console.log(r.status === 200 ? 'Rechner wurde vom Netz getrennt. Freigabe: sudo rf-netguard release' : `Fehler: ${r.json && r.json.error}`);
      break;
    }
    case 'release': {
      let done = false;
      const pi = args.indexOf('--pause');
      const pause = pi >= 0 ? parseInt(args[pi + 1], 10) || 0 : 0;
      try { const r = await ctl('POST', '/api/release', { by: 'Kommandozeile', pause_minutes: pause }); done = r.status === 200; if (!done) console.log(r.json && r.json.error); } catch (_) {
        // Daemon läuft nicht: direkt aufräumen
        const { run } = require('./util');
        await run('nft', ['delete', 'table', 'inet', 'netguard_iso']);
        const c = config.load();
        const st = new State(c.paths.data);
        for (const n of st.data.downed_ifaces || []) await run('ip', ['link', 'set', 'dev', n, 'up']);
        Object.assign(st.data, { isolated: false, isolated_at: 0, isolated_reason: '', downed_ifaces: [] });
        st.flush();
        done = true;
      }
      if (done) console.log(pause ? `Netztrennung aufgehoben. Automatische Trennung ${pause} min ausgesetzt.` : 'Netztrennung aufgehoben.');
      break;
    }
    case 'bans': { await daemonOrDie(); const r = await ctl('GET', '/api/firewall/bans'); for (const b of r.json) console.log(`${b.ip.padEnd(40)} noch ${Math.round((b.expires || 0) / 60)} min  ${b.reason || ''}`); if (!r.json.length) console.log('Keine gesperrten Adressen.'); break; }
    case 'ban': { await daemonOrDie(); const r = await ctl('POST', '/api/firewall/ban', { ip: args[0], minutes: parseInt(args[1], 10) || 60, reason: 'manuell (CLI)' }); console.log(r.status === 200 ? 'Gesperrt.' : `Fehler: ${r.json.error}`); break; }
    case 'unban': { await daemonOrDie(); const r = await ctl('POST', '/api/firewall/unban', { ip: args[0] }); console.log(r.status === 200 ? 'Sperre aufgehoben.' : `Fehler: ${r.json.error}`); break; }
    case 'scan': { await daemonOrDie(); const r = await ctl('POST', '/api/av/scan', { paths: args.length ? args : null }); console.log(r.status === 200 ? 'Scan gestartet (Fortschritt: netguard status / Oberfläche).' : `Fehler: ${r.json.error}`); break; }
    case 'selftest': { await daemonOrDie(); const r = await ctl('POST', '/api/av/selftest'); console.log(r.json.ok ? `Virenscanner funktioniert (${r.json.engine}, Signatur: ${r.json.signature}).` : `Selbsttest fehlgeschlagen: ${r.json.error}`); break; }
    case 'test-notify': { await daemonOrDie(); const r = await ctl('POST', '/api/notify/test'); console.log(JSON.stringify(r.json, null, 2)); break; }
    case 'accept-listeners': { await daemonOrDie(); const r = await ctl('POST', '/api/ids/accept-listeners'); console.log(`${r.json.ports} offene Ports als normal übernommen.`); break; }
    case 'restart': {
      await daemonOrDie();
      if (args.includes('--reboot')) { const r = await ctl('POST', '/api/reboot', { confirm: true }); console.log(r.status === 200 ? 'Rechner wird neu gestartet …' : `Fehler: ${r.json && r.json.error}`); break; }
      const r = await ctl('POST', '/api/restart'); console.log(r.status === 200 ? 'RF-NetGuard wird neu gestartet …' : `Fehler: ${r.json && r.json.error}`); break;
    }
    case 'reload': { await daemonOrDie(); await ctl('POST', '/api/reload'); console.log('Konfiguration neu geladen.'); break; }
    case 'protection': {
      if (!['on', 'off'].includes(args[0])) { console.log('Verwendung: rf-netguard protection on|off'); break; }
      await daemonOrDie();
      const r = await ctl('POST', `/api/protection/${args[0]}`);
      console.log(r.status === 200 ? (args[0] === 'off' ? 'Firewall und automatische Netztrennung sind AUS. Wieder einschalten: sudo rf-netguard protection on' : 'Schutz ist wieder eingeschaltet.') : `Fehler: ${r.json && r.json.error}`);
      break;
    }
    case 'pause-isolation': {
      await daemonOrDie();
      const r = await ctl('POST', '/api/isolation/pause', { minutes: parseInt(args[0], 10) || 0 });
      console.log(r.status === 200 ? (parseInt(args[0], 10) > 0 ? `Automatische Netztrennung ${parseInt(args[0], 10)} min ausgesetzt.` : 'Automatische Netztrennung wieder aktiv.') : `Fehler: ${r.json && r.json.error}`);
      break;
    }
    case 'update': {
      const log = (m) => console.log(m);
      if (args.includes('--check')) {
        const cfg = config.load();
        try {
          if (update.githubMode(cfg)) { const g = await update.checkGithub(cfg, update.readVersion(update.APP_DIR)); console.log(g.newer ? `Neue Version ${g.latest} verfügbar (installiert: ${update.readVersion(update.APP_DIR)}). Installieren: sudo rf-netguard update` : `RF-NetGuard ist aktuell (${update.readVersion(update.APP_DIR)}).`); break; }
          const r = await update.checkManifest(cfg.update.url, update.readVersion(update.APP_DIR));
          console.log(r.newer ? `Neue Version ${r.latest} verfügbar (installiert: ${update.readVersion(update.APP_DIR)}).\n${r.notes}\nInstallieren: sudo rf-netguard update ${r.bundle_url}` : `RF-NetGuard ist aktuell (${update.readVersion(update.APP_DIR)}).`);
        } catch (e) { console.error(`Fehler: ${e.message}`); process.exit(1); }
        break;
      }
      const src = args.find((a) => !a.startsWith('--'));
      if (!src || args.includes('--github')) {
        // Einfachster Weg: "sudo rf-netguard update" holt die neueste Version von GitHub
        const r = await update.performUpdate({ github: true, cli: true, fromWeb: args.includes('--from-web'), force: args.includes('--force'), log });
        console.log(r.ok ? `✓ ${r.message}` : `✗ Update fehlgeschlagen: ${r.message}`);
        process.exit(r.ok ? 0 : 1);
      }
      const r = await update.performUpdate({ source: src, cli: true, fromWeb: args.includes('--from-web'), force: args.includes('--force'), unsigned: args.includes('--unsigned'), cleanup: args.includes('--cleanup') ? src : null, log });
      console.log(r.ok ? `✓ ${r.message}` : `✗ Update fehlgeschlagen: ${r.message}`);
      process.exit(r.ok ? 0 : 1);
      break;
    }
    case 'rollback': {
      const r = await update.rollbackLast({ log: (m) => console.log(m) });
      console.log(r.ok ? `✓ ${r.message}` : `✗ ${r.message}`);
      process.exit(r.ok ? 0 : 1);
      break;
    }
    case 'update-key': {
      const f = args[0];
      if (!f) { console.log('Verwendung: sudo rf-netguard update-key <öffentlicher-schluessel.pem>   (oder "-" = Standardeingabe; "off" = entfernen)'); break; }
      const c = config.load();
      if (f === 'off') c.update.public_key = '';
      else {
        const pem = f === '-' ? fs.readFileSync(0, 'utf8') : fs.readFileSync(f, 'utf8');
        const k = require('crypto').createPublicKey(pem);
        if (k.asymmetricKeyType !== 'ed25519') { console.error('Es wird ein Ed25519-Schlüssel erwartet.'); process.exit(1); }
        c.update.public_key = k.export({ type: 'spki', format: 'pem' });
      }
      config.save(c);
      console.log(f === 'off' ? 'Update-Schlüssel entfernt.' : 'Update-Schlüssel gespeichert. Signierte Updates können jetzt auch über die Oberfläche installiert werden.');
      try { await ctl('POST', '/api/reload'); } catch (_) { /* Dienst läuft nicht */ }
      break;
    }
    case 'firewall-off': {
      const res = await flushAll();
      for (const r of res) console.log(`${r.table}: ${r.removed ? 'entfernt' : 'nicht vorhanden'}`);
      console.log('Hinweis: Der Dienst legt die Regeln beim nächsten Start/Reload neu an. Dauerhaft aus: sudo systemctl disable --now netguard');
      break;
    }
    case 'passwd': {
      const p1 = process.env.NETGUARD_PASSWORD || await promptHidden('Neues Web-Passwort (min. 10 Zeichen): ');
      if (p1.length < 10) { console.error('Passwort zu kurz.'); process.exit(1); }
      if (!process.env.NETGUARD_PASSWORD && p1 !== await promptHidden('Wiederholen: ')) { console.error('Passwörter stimmen nicht überein.'); process.exit(1); }
      try {
        const r = await ctl('POST', '/api/password', { new: p1 });
        if (r.status !== 200) throw new Error(r.json && r.json.error);
      } catch (e) {
        if (/kurz|Passwort/.test(e.message)) { console.error(e.message); process.exit(1); }
        const c = config.load();
        c.web.password_hash = hashPassword(p1);
        config.save(c);
      }
      console.log('Passwort gesetzt. Beim nächsten Start/Reload gilt es auch für die Oberfläche (Daemon neu starten, falls diese bisher nur lokal erreichbar war).');
      break;
    }
    case 'setup': await require('./setup').runSetup({ yes: args.includes('--yes') }); break;
    case 'version': console.log(VERSION); break;
    default:
      console.log(`RF-NetGuard ${VERSION}
Verwendung: rf-netguard <Befehl>

  status               Zustand von Firewall, DNS, Virenschutz, Netztrennung
  events [n] [stufe]   letzte Ereignisse (stufe: info|warn|high|critical)
  isolate [Grund]      Rechner sofort vom Netz trennen
  release [--pause min] Netztrennung aufheben (optional danach Auto-Trennung pausieren)
  pause-isolation <min> Auto-Trennung für min Minuten aussetzen (0 = wieder aktiv)
  protection on|off    Firewall + Auto-Trennung dauerhaft aus-/einschalten (Fehlalarm/Wartung)
  bans | ban <ip> [min] | unban <ip>
  scan [pfad…]         Virenscan starten
  selftest             Virenscanner mit Testmuster prüfen
  test-notify          Testnachricht senden
  accept-listeners     aktuell offene Ports als normal übernehmen
  reload               Konfiguration neu laden
  passwd               Web-Passwort setzen
  setup [--yes]        Einrichtungs-Assistent
  update <datei|url>   Update einspielen (--check = nach neuer Version suchen, --force, --unsigned)
  rollback             auf die vorherige Programmversion zurückstellen
  update-key <datei>   öffentlichen Schlüssel für signierte Updates hinterlegen
  firewall-off         NOTFALL: alle RF-NetGuard-Firewallregeln entfernen
  run                  Daemon im Vordergrund starten (wird von systemd genutzt)`);
  }
}

if (require.main === module) {
  const [cmd = 'help', ...args] = process.argv.slice(2);
  if (cmd === 'run') {
    new App().start().catch((e) => { console.error(e); process.exit(1); });
  } else {
    cli(cmd, args).then(() => process.exit(0)).catch((e) => { console.error(`Fehler: ${e.message}`); process.exit(1); });
  }
}

module.exports = { App };
