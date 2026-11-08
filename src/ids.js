'use strict';
// Angriffs- und Kompromittierungs-Erkennung:
//  - Kernel-Firewall-Log (Portscans, Flut-/Brute-Force-Sperren, C2-Kontakte)
//  - SSH-Anmeldungen (Brute-Force, Erfolg nach Fehlversuchen)
//  - Prozesse (Miner, Reverse-Shells, dateilose Prozesse), ausgehende Verbindungen
//  - neue Listener, Datei-Integrität, Traffic-Anomalien, ARP-Spoofing, DNS-Anomalien
const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { LEVELS } = require('./firewall');
const { localAddresses, CidrMatcher, isPrivateIp, defaultGateway, entropy, commandExists, hashFile, hexToIp4 } = require('./util');

const SHELLS = new Set(['bash', 'sh', 'dash', 'zsh', 'ksh', 'csh', 'tcsh', 'nc', 'ncat', 'netcat', 'socat']);
const REVSHELL_CMD = [
  { re: /\/dev\/tcp\/(\d{1,3}(?:\.\d{1,3}){3})\/\d+/, ipGroup: 1 },
  { re: /\b(?:nc|ncat|netcat)\b[^|;&]*\s-[a-z]*[ec]\s/i },
  { re: /\bsocat\b[^|;&]*\bexec:/i },
  { re: /pty\.spawn\s*\(/ },
];
const MINER_CMD = /stratum\+(?:tcp|ssl):\/\/|--donate-level/i;

const normIp = (ip) => {
  if (!ip) return ip;
  if (net.isIPv6(ip)) { try { return new URL(`http://[${ip}]`).hostname.slice(1, -1); } catch (_) { return ip; } }
  return ip;
};

function ip6FromBuf(b) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(b.readUInt16BE(i).toString(16));
  return normIp(g.join(':'));
}

function hexToIp6(h) {
  const b = Buffer.alloc(16);
  for (let i = 0; i < 4; i++) b.writeUInt32LE(parseInt(h.substr(i * 8, 8), 16) >>> 0, i * 4);
  const mapped = b.subarray(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
  return mapped ? [...b.subarray(12)].join('.') : ip6FromBuf(b);
}

function readNetTable(file, v6) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (_) { return []; }
  const out = [];
  for (const l of text.split('\n').slice(1)) {
    const f = l.trim().split(/\s+/);
    if (f.length < 10) continue;
    const [la, lp] = f[1].split(':');
    const [ra, rp] = f[2].split(':');
    out.push({
      local: v6 ? hexToIp6(la) : hexToIp4(la), lport: parseInt(lp, 16),
      remote: v6 ? hexToIp6(ra) : hexToIp4(ra), rport: parseInt(rp, 16),
      state: f[3], uid: parseInt(f[7], 10), inode: f[9],
    });
  }
  return out;
}

const pidList = () => { try { return fs.readdirSync('/proc').filter((n) => /^\d+$/.test(n)); } catch (_) { return []; } };
const readFirst = (f) => { try { return fs.readFileSync(f, 'utf8').trim(); } catch (_) { return ''; } };

function inodeMap() {
  const map = new Map();
  for (const pid of pidList()) {
    let fds;
    try { fds = fs.readdirSync(`/proc/${pid}/fd`); } catch (_) { continue; }
    for (const fd of fds) {
      let l;
      try { l = fs.readlinkSync(`/proc/${pid}/fd/${fd}`); } catch (_) { continue; }
      if (l.startsWith('socket:[')) map.set(l.slice(8, -1), Number(pid));
    }
  }
  return map;
}

const NG_RE = /NG-([A-Z0-9-]+)\s/;
// Am Zeilenende verankert: ein Angreifer kann über den Benutzernamen sonst eine fremde Adresse in die Zeile schmuggeln (\"x from 8.8.8.8 port 1\")
const SSH_FAIL = /Failed (?:password|publickey|keyboard-interactive\/pam) for (?:invalid user )?(.+) from ([0-9a-fA-F:.]+) port \d+(?: ssh\d)?\s*$/;
const SSH_OK = /Accepted (\S+) for (.+) from ([0-9a-fA-F:.]+) port \d+(?: ssh\d)?(?::.*)?\s*$/;

class Ids {
  constructor({ cfg, log, events, fw, state, dns }) {
    this.cfg = cfg;
    this.log = log;
    this.events = events;
    this.fw = fw;
    this.state = state;
    this.dns = dns;
    this.timers = [];
    this.children = new Set();
    this.stopped = false;
    this.scan = new Map();
    this.recentBan = new Map();
    this.sshFail = new Map();
    this.cooldowns = new Map();
    this.seenProc = new Set();
    this.alertedListeners = new Set();
    this.dnsMal = new Map();
    this.dnsDga = new Map();
    this.dnsTun = new Map();
    this.traffic = [];
    this.trafficPrev = null;
    this.trafficEwma = 0;
    this.txHigh = 0; this.rxHigh = 0; this.spikeHigh = 0;
    this.kernelLogMode = null;
    this.dnsHandler = (rec) => this.onDns(rec);
  }

  level() { return LEVELS[this.cfg().security_level] || LEVELS.normal; }
  lan() { return new CidrMatcher(this.cfg().lan_cidrs); }

  cool(key, ms) {
    const now = Date.now();
    if ((this.cooldowns.get(key) || 0) > now) return false;
    this.cooldowns.set(key, now + ms);
    return true;
  }

  rep(ev) { return this.events.report(ev).catch((e) => this.log.warn(`Ereignis-Fehler: ${e.message}`)); }

  safe(name, fn) {
    return () => { Promise.resolve().then(fn).catch((e) => this.log.warn(`IDS ${name}: ${e.message}`)); };
  }

  every(name, sec, fn) {
    const t = setInterval(this.safe(name, fn), sec * 1000);
    if (t.unref) t.unref();
    this.timers.push(t);
  }

  async start() {
    const c = this.cfg().ids;
    this.stopped = false;
    if (!c.enabled) { this.log.info('Angriffserkennung ist deaktiviert'); return; }
    this.startKernelLog();
    if (c.ssh_bruteforce.enabled) this.startSshLog();
    if (this.dns) this.dns.on('query', this.dnsHandler);
    if (this.dns) this.dns.on('flood', (f) => { if (this.cool(`dnsflood|${f.ip}`, 600000)) this.rep({ kind: 'attack', severity: 'warn', type: 'dns-flood', src: f.ip, msg: `DNS-Flut von ${f.ip} (${f.qps} Abfragen/s)` }); });
    if (c.processes.enabled) this.every('Prozesse', c.processes.interval_s, () => this.scanProcesses());
    if (c.connections.enabled) this.every('Verbindungen', c.connections.interval_s, () => this.scanConnections());
    if (c.listeners.enabled) this.every('Listener', c.listeners.interval_s, () => this.scanListeners());
    if (c.integrity.enabled) this.every('Integrität', c.integrity.interval_s, () => this.scanIntegrity());
    if (c.traffic.enabled) this.every('Traffic', c.traffic.interval_s, () => this.scanTraffic());
    if (c.arp.enabled) this.every('ARP', 15, () => this.scanArp());
    this.every('Aufräumen', 60, () => this.cleanup());
    // Erste Durchläufe sofort (Baselines lernen)
    setTimeout(this.safe('Listener', () => c.listeners.enabled && this.scanListeners()), 3000).unref();
    setTimeout(this.safe('Integrität', () => c.integrity.enabled && this.scanIntegrity()), 5000).unref();
    setTimeout(this.safe('ARP', () => c.arp.enabled && this.scanArp()), 4000).unref();
    this.log.info('Angriffserkennung gestartet');
  }

  stop() {
    this.stopped = true;
    this.timers.forEach(clearInterval);
    this.timers = [];
    for (const p of this.children) { try { p.kill(); } catch (_) { /* egal */ } }
    this.children.clear();
    if (this.dns) this.dns.removeListener('query', this.dnsHandler);
  }

  async restart() { this.stop(); await this.start(); }

  cleanup() {
    const now = Date.now();
    const win = this.cfg().ids.portscan.window_s * 1000;
    for (const [k, v] of this.scan) if (now - v.first > win * 2) this.scan.delete(k);
    for (const [k, v] of this.recentBan) if (v < now) this.recentBan.delete(k);
    for (const [k, v] of this.cooldowns) if (v < now) this.cooldowns.delete(k);
    for (const [k, v] of this.sshFail) { const a = v.filter((t) => now - t < 3600000); if (a.length) this.sshFail.set(k, a); else this.sshFail.delete(k); }
    for (const m of [this.dnsMal, this.dnsDga, this.dnsTun]) for (const [k, v] of m) { const a = v.filter((t) => now - t < 600000); if (a.length) m.set(k, a); else m.delete(k); }
  }

  // ---------- Log-Leser ----------
  follow(cmd, args, onLine) {
    const spawnIt = () => {
      if (this.stopped) return;
      let p;
      try { p = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'ignore'] }); } catch (e) { this.log.warn(`${cmd}: ${e.message}`); return; }
      this.children.add(p);
      let buf = '';
      p.stdout.on('data', (d) => {
        buf += d;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const l = buf.slice(0, i);
          buf = buf.slice(i + 1);
          try { onLine(l); } catch (e) { this.log.debug(`Zeilenfehler: ${e.message}`); }
        }
        if (buf.length > 65536) buf = '';
      });
      p.on('error', () => {});
      p.on('close', () => { this.children.delete(p); if (!this.stopped) { const t = setTimeout(spawnIt, 5000); t.unref(); } });
    };
    spawnIt();
  }

  async startKernelLog() {
    if (await commandExists('journalctl')) { this.kernelLogMode = 'journal'; this.follow('journalctl', ['-k', '-f', '-n', '0', '-o', 'cat'], (l) => this.onKernelLine(l)); return; }
    for (const f of ['/var/log/kern.log', '/var/log/syslog', '/var/log/messages']) {
      if (fs.existsSync(f)) { this.kernelLogMode = f; this.follow('tail', ['-F', '-n', '0', f], (l) => this.onKernelLine(l)); return; }
    }
    this.log.warn('Kein Kernel-Log gefunden: Portscan-/C2-Erkennung über Firewall-Log nicht verfügbar');
  }

  async startSshLog() {
    if (await commandExists('journalctl')) { this.follow('journalctl', ['-f', '-n', '0', '-o', 'cat', '-u', 'ssh', '-u', 'sshd', '-u', 'ssh.service'], (l) => this.onSshLine(l)); return; }
    for (const f of ['/var/log/auth.log', '/var/log/secure']) {
      if (fs.existsSync(f)) { this.follow('tail', ['-F', '-n', '0', f], (l) => this.onSshLine(l)); return; }
    }
  }

  // ---------- Firewall-Log ----------
  onKernelLine(line) {
    // Nur echte Kernel-Meldungen: in Textdateien (syslog) könnten sonst andere Programme/Benutzernamen Zeilen mit "NG-…" einschmuggeln
    if (this.kernelLogMode !== 'journal' && !/\bkernel:/.test(line)) return;
    if (!/\bIN=\S*\s+OUT=/.test(line)) return;
    const m = NG_RE.exec(line);
    if (!m) return;
    const f = {};
    for (const kv of line.matchAll(/\b(SRC|DST|PROTO|SPT|DPT)=(\S*)/g)) f[kv[1]] = kv[2];
    const src = normIp(f.SRC);
    const dst = normIp(f.DST);
    const tag = m[1];
    const L = this.level();
    const now = Date.now();

    if (tag === 'DROP') {
      if (!src || !dst || /^(22[4-9]|23\d)\./.test(dst) || dst === '255.255.255.255' || /^ff/i.test(dst)) return; // Multicast/Broadcast ignorieren
      const win = this.cfg().ids.portscan.window_s * 1000;
      let r = this.scan.get(src);
      if (!r || now - r.first > win) { r = { first: now, ports: new Set(), n: 0 }; this.scan.set(src, r); }
      r.ports.add(`${f.PROTO}/${f.DPT || '-'}`);
      r.n++;
      if (r.ports.size >= L.scan && !(this.recentBan.get(src) > now)) {
        this.recentBan.set(src, now + L.ban * 1000);
        this.scan.delete(src);
        this.rep({
          kind: 'attack', severity: 'warn', type: 'portscan', src, ban: L.ban,
          msg: `Portscan von ${src}: ${r.ports.size} verschiedene Ports in ${Math.round((now - r.first) / 1000)} s`,
          details: { ports: [...r.ports].slice(0, 20) },
        });
      }
    } else if (tag.startsWith('BAN-')) {
      if (!src || !this.cool(`ban|${src}`, 60000)) return;
      const why = tag === 'BAN-SYNFLOOD' ? 'SYN-Flut' : 'Brute-Force (Verbindungsrate)';
      this.fw.noteBan(src, why, 'kernel');
      this.recentBan.set(src, now + L.ban * 1000);
      this.rep({ kind: 'attack', severity: 'warn', type: tag === 'BAN-SYNFLOOD' ? 'syn-flood' : 'conn-bruteforce', src, msg: `${src} wurde automatisch gesperrt: ${why}` });
    } else if (tag === 'THREAT-IN') {
      if (src && this.cool(`threat|${src}`, 600000)) this.rep({ kind: 'attack', severity: 'info', type: 'threat-inbound', src, msg: `Verbindungsversuch von bekannter Bedrohungs-IP ${src} blockiert (Port ${f.DPT || '?'})` });
    } else if (tag === 'C2OUT') {
      if (!src || !dst || !this.cool(`c2|${src}|${dst}`, 300000)) return;
      const host = localAddresses().has(src);
      this.rep({
        kind: 'compromise', subject: host ? 'host' : 'client', severity: 'high', type: 'c2-contact', score: 60, src,
        msg: `${host ? 'Dieser Rechner' : `Gerät ${src}`} versuchte, bekannten Botnet-/Malware-Server ${dst}:${f.DPT || '?'} zu kontaktieren (blockiert)`,
        details: { dst, dport: f.DPT, proto: f.PROTO },
      });
    } else if (tag === 'BADPORT') {
      if (!src || !dst || !this.cool(`bad|${src}|${dst}|${f.DPT}`, 300000)) return;
      const host = localAddresses().has(src);
      this.rep({ kind: 'compromise', subject: host ? 'host' : 'client', severity: 'warn', type: 'bad-port-out', score: 20, src, msg: `Ausgehende Verbindung ${src} → ${dst}:${f.DPT} auf verdächtigem Port blockiert` });
    }
  }

  // ---------- SSH ----------
  onSshLine(line) {
    const L = this.level();
    const win = this.cfg().ids.ssh_bruteforce.window_s * 1000;
    const now = Date.now();
    let m = SSH_FAIL.exec(line);
    if (m) {
      const ip = normIp(m[2]);
      const arr = (this.sshFail.get(ip) || []).filter((t) => now - t < win);
      arr.push(now);
      this.sshFail.set(ip, arr);
      if (arr.length >= L.brute && !(this.recentBan.get(ip) > now)) {
        this.recentBan.set(ip, now + L.ban * 1000);
        this.rep({ kind: 'attack', severity: 'warn', type: 'ssh-bruteforce', src: ip, ban: L.ban, msg: `SSH-Brute-Force von ${ip}: ${arr.length} fehlgeschlagene Anmeldungen (Benutzer: ${m[1]})` });
      }
      return;
    }
    m = SSH_OK.exec(line);
    if (m) {
      const ip = normIp(m[3]);
      const fails = (this.sshFail.get(ip) || []).filter((t) => now - t < 3600000).length;
      if (fails >= 3) {
        this.sshFail.delete(ip);
        this.rep({
          kind: 'compromise', subject: 'host', severity: 'critical', type: 'ssh-login-after-bruteforce', score: 70, src: ip, ban: L.ban,
          msg: `Erfolgreiche SSH-Anmeldung von ${ip} (Benutzer ${m[2]}) nach ${fails} Fehlversuchen – möglicher Einbruch`,
        });
      } else if (!this.lan().has(ip) && !isPrivateIp(ip) && !this.fw.isProtected(ip)) {
        this.rep({ kind: 'info', severity: 'warn', type: 'ssh-login-external', src: ip, msg: `SSH-Anmeldung von externer Adresse ${ip} (Benutzer ${m[2]}, ${m[1]})` });
      }
    }
  }

  // ---------- Prozesse ----------
  judgeProcess({ exe, comm, cmd }) {
    const p = this.cfg().ids.processes;
    const clean = exe.replace(/ \(deleted\)$/, '');
    const base = path.basename(clean).toLowerCase();
    const lc = comm.toLowerCase();
    if ((p.ignore_names || []).includes(comm)) return null;
    if (p.miner_names.some((n) => n.toLowerCase() === lc || n.toLowerCase() === base) || MINER_CMD.test(cmd)) {
      return { type: 'cryptominer', severity: 'critical', score: 80, kill: true, msg: `Krypto-Miner erkannt: ${clean} (${comm})` };
    }
    if (exe.startsWith('/memfd:')) return { type: 'fileless-process', severity: 'critical', score: 80, kill: true, msg: `Dateiloser Prozess (memfd) läuft: ${comm}` };
    for (const r of REVSHELL_CMD) {
      const m = r.re.exec(cmd);
      if (!m) continue;
      if (r.ipGroup && (isPrivateIp(m[r.ipGroup]) || m[r.ipGroup].startsWith('127.'))) continue;
      return { type: 'reverse-shell', severity: 'critical', score: 100, kill: true, msg: `Reverse-Shell-Muster in Prozess ${comm}: ${cmd.slice(0, 160)}` };
    }
    const dirs = p.suspicious_dirs || [];
    if (dirs.some((d) => clean.startsWith(`${d}/`)) && !(p.ignore_paths || []).some((ip) => clean.startsWith(ip))) {
      return { type: 'process-from-tmp', severity: 'warn', score: 20, kill: false, msg: `Prozess läuft aus temporärem Verzeichnis: ${clean}` };
    }
    return null;
  }

  killPid(pid) {
    if (pid <= 1 || pid === process.pid || pid === process.ppid) return false;
    try { process.kill(pid, 'SIGKILL'); return true; } catch (_) { return false; }
  }

  async scanProcesses() {
    const pc = this.cfg().ids.processes;
    const alive = new Set();
    for (const pid of pidList()) {
      const n = Number(pid);
      if (n === process.pid || n === 1 || n === process.ppid) continue;
      let exe;
      try { exe = fs.readlinkSync(`/proc/${pid}/exe`); } catch (_) { continue; }
      const key = `${pid}:${exe}`;
      alive.add(key);
      if (this.seenProc.has(key)) continue;
      const comm = readFirst(`/proc/${pid}/comm`);
      let cmd = '';
      try { cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim(); } catch (_) { /* weg */ }
      const v = this.judgeProcess({ exe, comm, cmd });
      if (!v) continue;
      const actions = [];
      if (v.kill && pc.kill && this.killPid(n)) actions.push(`Prozess ${n} beendet`);
      this.rep({
        kind: 'compromise', subject: 'host', severity: v.severity, type: v.type, score: v.score, actions,
        msg: v.msg, details: { pid: n, exe, cmd: cmd.slice(0, 200) },
      });
    }
    this.seenProc = alive;
  }

  // ---------- Verbindungen ----------
  async scanConnections() {
    const c = this.cfg().ids.connections;
    const lan = this.lan();
    const conns = [...readNetTable('/proc/net/tcp', false), ...readNetTable('/proc/net/tcp6', true)];
    const external = (ip) => ip && !lan.has(ip) && !isPrivateIp(ip);
    const est = conns.filter((x) => x.state === '01' && external(x.remote));
    const syn = conns.filter((x) => x.state === '02' && external(x.remote));

    for (const x of est) {
      if (this.fw.threatMatcher.has(x.remote) && this.cool(`c2conn|${x.remote}`, 600000)) {
        this.rep({
          kind: 'compromise', subject: 'host', severity: 'high', type: 'c2-connection', score: 60, src: x.local,
          msg: `Aktive Verbindung zu bekanntem Botnet-/Malware-Server ${x.remote}:${x.rport}`, details: { remote: x.remote, rport: x.rport },
        });
      }
    }
    if (est.length) {
      const map = inodeMap();
      for (const x of est) {
        const pid = map.get(x.inode);
        if (!pid) continue;
        const comm = readFirst(`/proc/${pid}/comm`);
        if (SHELLS.has(comm) && this.cool(`rs|${pid}`, 300000)) {
          const actions = [];
          if (this.cfg().ids.processes.kill && this.killPid(pid)) actions.push(`Prozess ${pid} beendet`);
          this.rep({
            kind: 'compromise', subject: 'host', severity: 'critical', type: 'reverse-shell', score: 100, actions,
            msg: `Shell-Prozess "${comm}" (PID ${pid}) hat eine Verbindung nach außen zu ${x.remote}:${x.rport} – typisch für eine Reverse-Shell`,
            details: { pid, remote: x.remote, rport: x.rport },
          });
        }
      }
    }
    const distinct = new Set(syn.map((x) => x.remote)).size;
    if (distinct >= c.syn_sent_threshold && this.cool('outscan', 600000)) {
      this.rep({ kind: 'compromise', subject: 'host', severity: 'high', type: 'outbound-scan', score: 60, msg: `${distinct} gleichzeitige Verbindungsversuche zu verschiedenen externen Adressen – möglicher Wurm/Scanner auf diesem Rechner` });
    }
  }

  // ---------- Listener ----------
  currentListeners() {
    const set = new Map();
    const push = (proto, x) => {
      if (x.local.startsWith('127.') || x.local === '::1') return;
      set.set(`${proto}:${x.lport}`, x);
    };
    for (const x of readNetTable('/proc/net/tcp', false)) if (x.state === '0A') push('tcp', x);
    for (const x of readNetTable('/proc/net/tcp6', true)) if (x.state === '0A') push('tcp', x);
    for (const f of ['/proc/net/udp', '/proc/net/udp6']) for (const x of readNetTable(f, f.endsWith('6'))) if (x.state === '07' && x.lport < 32768) push('udp', x);
    return set;
  }

  acceptListeners() {
    this.state.data.baseline.listeners = [...this.currentListeners().keys()];
    this.alertedListeners.clear();
    this.state.save();
    return this.state.data.baseline.listeners.length;
  }

  async scanListeners() {
    const cur = this.currentListeners();
    const base = this.state.data.baseline.listeners;
    if (!base) { this.acceptListeners(); this.log.info(`Listener-Baseline gelernt (${cur.size} offene Ports)`); return; }
    const known = new Set(base);
    let map = null;
    for (const [key, x] of cur) {
      if (known.has(key) || this.alertedListeners.has(key)) continue;
      this.alertedListeners.add(key);
      map = map || inodeMap();
      const pid = map.get(x.inode);
      const name = pid ? readFirst(`/proc/${pid}/comm`) : 'unbekannt';
      this.rep({
        kind: 'compromise', subject: 'host', severity: 'warn', type: 'new-listener', score: 15,
        msg: `Neuer offener Port ${key} (Prozess: ${name}) – nicht Teil der gelernten Basis`, details: { pid, bind: x.local },
      });
    }
  }

  // ---------- Datei-Integrität ----------
  async hashPath(p) {
    let st;
    try { st = fs.statSync(p); } catch (_) { return 'missing'; }
    if (st.isDirectory()) {
      const parts = [];
      for (const n of fs.readdirSync(p).sort()) { try { const s = fs.statSync(path.join(p, n)); parts.push(`${n}:${s.size}:${Math.floor(s.mtimeMs)}`); } catch (_) { /* weg */ } }
      return crypto.createHash('sha256').update(parts.join('\n')).digest('hex');
    }
    if (st.size > 20 * 1024 * 1024) return `big:${st.size}:${Math.floor(st.mtimeMs)}`;
    try { return await hashFile(p); } catch (_) { return 'unreadable'; }
  }

  async scanIntegrity() {
    const base = this.state.data.baseline.integrity;
    const learning = Object.keys(base).length === 0;
    for (const p of this.cfg().ids.integrity.files) {
      const h = await this.hashPath(p);
      if (!(p in base)) { base[p] = h; continue; }
      if (base[p] === h) continue;
      const was = base[p];
      base[p] = h;
      if (learning) continue;
      if (p === '/etc/ld.so.preload' && h !== 'missing') {
        this.rep({ kind: 'compromise', subject: 'host', severity: 'critical', type: 'ld-preload', score: 70, msg: '/etc/ld.so.preload wurde angelegt/geändert – typisches Rootkit-Merkmal' });
      } else {
        this.rep({
          kind: 'compromise', subject: 'host', severity: 'warn', type: 'integrity-change', score: 10,
          msg: `${p} wurde ${h === 'missing' ? 'gelöscht' : was === 'missing' ? 'neu angelegt' : 'geändert'}`,
        });
      }
    }
    this.state.save();
  }

  // ---------- Traffic ----------
  readNetDev() {
    let text;
    try { text = fs.readFileSync('/proc/net/dev', 'utf8'); } catch (_) { return null; }
    const gw = defaultGateway();
    let rx = 0; let tx = 0;
    for (const l of text.split('\n').slice(2)) {
      const [name, rest] = l.split(':');
      if (!rest) continue;
      const n = name.trim();
      if (n === 'lo') continue;
      if (!(fs.existsSync(`/sys/class/net/${n}/device`) || (gw && gw.iface === n))) continue;
      const f = rest.trim().split(/\s+/).map(Number);
      rx += f[0]; tx += f[8];
    }
    return { t: Date.now(), rx, tx };
  }

  async scanTraffic() {
    const c = this.cfg().ids.traffic;
    const cur = this.readNetDev();
    if (!cur) return;
    const prev = this.trafficPrev;
    this.trafficPrev = cur;
    if (!prev || cur.t <= prev.t || cur.rx < prev.rx || cur.tx < prev.tx) return;
    const dt = (cur.t - prev.t) / 1000;
    const rxM = ((cur.rx - prev.rx) * 8) / dt / 1e6;
    const txM = ((cur.tx - prev.tx) * 8) / dt / 1e6;
    this.traffic.push({ t: cur.t, rx: Math.round(rxM * 100) / 100, tx: Math.round(txM * 100) / 100 });
    if (this.traffic.length > 720) this.traffic.shift();

    this.txHigh = txM > c.tx_alert_mbit ? this.txHigh + 1 : 0;
    this.rxHigh = rxM > c.rx_alert_mbit ? this.rxHigh + 1 : 0;
    const spike = this.trafficEwma > 0 && txM > 20 && txM > this.trafficEwma * c.spike_factor;
    this.spikeHigh = spike ? this.spikeHigh + 1 : 0;
    if (!spike) this.trafficEwma = this.trafficEwma ? this.trafficEwma * 0.99 + txM * 0.01 : txM;

    if (this.txHigh >= 3 && this.cool('txhigh', 600000)) {
      this.rep({ kind: 'compromise', subject: 'host', severity: 'warn', type: 'traffic-out-high', score: 20, msg: `Ungewöhnlich hoher ausgehender Datenverkehr: ${txM.toFixed(0)} Mbit/s (Schwelle ${c.tx_alert_mbit})` });
    } else if (this.spikeHigh >= 6 && this.cool('txspike', 600000)) {
      this.rep({ kind: 'compromise', subject: 'host', severity: 'warn', type: 'traffic-out-spike', score: 20, msg: `Ausgehender Datenverkehr ${txM.toFixed(0)} Mbit/s – ein Vielfaches des üblichen Wertes (~${this.trafficEwma.toFixed(1)} Mbit/s)` });
    }
    if (this.rxHigh >= 3 && this.cool('rxhigh', 600000)) {
      this.rep({ kind: 'attack', severity: 'warn', type: 'traffic-in-flood', msg: `Sehr hoher eingehender Datenverkehr: ${rxM.toFixed(0)} Mbit/s – mögliche Überlastungs-Attacke (DDoS)` });
    }
  }

  // ---------- ARP ----------
  async scanArp() {
    let text;
    try { text = fs.readFileSync('/proc/net/arp', 'utf8'); } catch (_) { return; }
    const entries = new Map();
    for (const l of text.split('\n').slice(1)) {
      const f = l.trim().split(/\s+/);
      if (f.length < 6 || f[2] !== '0x2' || f[3] === '00:00:00:00:00:00') continue;
      entries.set(f[0], f[3].toLowerCase());
    }
    const b = this.state.data.baseline;
    const gw = defaultGateway();
    if (gw && entries.has(gw.gw)) {
      const mac = entries.get(gw.gw);
      const prev = b.arp[gw.gw];
      if (prev && prev !== mac && this.cool('arpgw', 600000)) {
        this.rep({ kind: 'attack', severity: 'high', type: 'arp-gateway-change', msg: `MAC-Adresse des Gateways ${gw.gw} hat sich von ${prev} auf ${mac} geändert – mögliches ARP-Spoofing / Man-in-the-Middle` });
      }
      b.arp[gw.gw] = mac;
    }
    const first = Object.keys(b.devices).length === 0;
    for (const [ip, mac] of entries) {
      if (b.devices[mac]) { b.devices[mac].ip = ip; continue; }
      if (Object.keys(b.devices).length >= 500) break;
      b.devices[mac] = { ip, first: Date.now() };
      if (!first && this.cfg().ids.arp.new_device_alert) this.rep({ kind: 'info', severity: 'warn', type: 'new-device', src: ip, msg: `Neues Gerät im Netzwerk: ${ip} (${mac})` });
    }
    this.state.save();
  }

  // ---------- DNS-Analyse ----------
  onDns(rec) {
    const d = this.cfg().ids.dns;
    const now = Date.now();
    const client = rec.c;
    const isHost = localAddresses().has(client);
    const subject = isHost ? 'host' : 'client';
    const note = (map, key) => { const a = (map.get(key) || []).filter((t) => now - t < 600000); a.push(now); map.set(key, a); return a; };

    if (rec.s === 'blocked' && rec.cat === 'malware') {
      const a = note(this.dnsMal, client);
      if (a.length >= d.malware_hits_threshold && this.cool(`dnsmal|${client}`, 900000)) {
        this.rep({ kind: 'compromise', subject, severity: 'high', type: 'dns-malware-hits', score: 40, src: client, msg: `${isHost ? 'Dieser Rechner' : client}: ${a.length} Abfragen bekannter Malware-/Phishing-Domains in 10 min (zuletzt ${rec.d})` });
      }
      return;
    }
    const labels = rec.d.split('.');
    if (d.dga && rec.rc === 3 && labels.length >= 2) {
      const sld = labels[labels.length - 2];
      if (sld.length >= 10 && entropy(sld) >= 3.1) {
        const a = note(this.dnsDga, client).filter((t) => now - t < 60000);
        if (a.length >= 12 && this.cool(`dga|${client}`, 900000)) {
          this.rep({ kind: 'compromise', subject, severity: 'high', type: 'dns-dga', score: 60, src: client, msg: `${isHost ? 'Dieser Rechner' : client}: viele Abfragen zufällig aussehender, nicht existierender Domains (${rec.d}) – typisch für Malware (DGA)` });
        }
      }
    }
    if (d.tunneling && (rec.d.length >= 100 || labels.some((l) => l.length >= 50)) && labels.length >= 2) {
      const key = `${client}|${labels.slice(-2).join('.')}`;
      const a = note(this.dnsTun, key).filter((t) => now - t < 60000);
      if (a.length >= 20 && this.cool(`tun|${key}`, 900000)) {
        this.rep({ kind: 'compromise', subject, severity: 'high', type: 'dns-tunnel', score: 60, src: client, msg: `${isHost ? 'Dieser Rechner' : client}: auffällig lange DNS-Abfragen an ${labels.slice(-2).join('.')} – mögliches DNS-Tunneling/Datenabfluss` });
      }
    }
  }

  trafficHistory() { return this.traffic; }
}

module.exports = { Ids, readNetTable, hexToIp6, normIp };
