'use strict';
// Einrichtungs-Assistent: erzeugt /etc/netguard/config.json
const os = require('os');
const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const readline = require('readline');
const config = require('./config');
const { defaultGateway, clone } = require('./util');
const { readNetTable } = require('./ids');
const { hashPassword } = require('./web');

function ipv4Network(a, prefix) {
  const o = a.split('.').map(Number);
  const n = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const m = (n & mask) >>> 0;
  return `${m >>> 24}.${(m >>> 16) & 255}.${(m >>> 8) & 255}.${m & 255}/${prefix}`;
}

function detectLan() {
  const gw = defaultGateway();
  if (!gw) return null;
  for (const a of os.networkInterfaces()[gw.iface] || []) {
    if (a.family === 'IPv4' && a.cidr) { const [ip, p] = a.cidr.split('/'); return { iface: gw.iface, ip, cidr: ipv4Network(ip, parseInt(p, 10)) }; }
  }
  return null;
}

async function runSetup({ yes = false } = {}) {
  const interactive = !yes && process.stdin.isTTY;
  const rl = interactive ? readline.createInterface({ input: process.stdin, output: process.stdout }) : null;
  const ask = (q, def = '') => new Promise((resolve) => {
    if (!rl) return resolve(def);
    rl.question(`${q}${def !== '' ? ` [${def}]` : ''}: `, (a) => resolve(a.trim() === '' ? def : a.trim()));
  });
  const askYn = async (q, def = true) => /^(j|y)/i.test(await ask(`${q} (j/n)`, def ? 'j' : 'n'));
  const hidden = (q) => new Promise((resolve) => {
    const r2 = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    r2._writeToOutput = (s) => { if (s.includes(q)) process.stdout.write(s); else process.stdout.write('*'); };
    r2.question(q, (a) => { r2.close(); process.stdout.write('\n'); resolve(a); });
  });

  const cfg = config.load();
  console.log('\n=== RF-NetGuard Einrichtung ===\n');

  const lan = detectLan();
  if (lan) {
    console.log(`Erkanntes Netzwerk: ${lan.cidr} (Schnittstelle ${lan.iface}, diese Maschine: ${lan.ip})`);
    if (!cfg.lan_cidrs.includes(lan.cidr)) cfg.lan_cidrs = [lan.cidr, ...cfg.lan_cidrs];
  }

  const mode = await ask('Betriebsmodus: "host" = schützt diesen Rechner, "gateway" = Rechner ist Router/Gateway des Netzes', cfg.mode);
  cfg.mode = mode === 'gateway' ? 'gateway' : 'host';
  const lvl = await ask('Sicherheitsstufe (low / normal / high / paranoid)', cfg.security_level);
  cfg.security_level = ['low', 'normal', 'high', 'paranoid'].includes(lvl) ? lvl : 'normal';

  // Admin-Adresse: aktuelle SSH-Verbindung nie aussperren
  const ssh = (process.env.SSH_CLIENT || '').split(' ')[0];
  const admins = new Set(cfg.admin_ips);
  if (ssh && net.isIP(ssh)) {
    if (await askYn(`Du bist per SSH von ${ssh} verbunden. Diese Adresse immer erreichbar halten (empfohlen)?`, true)) admins.add(ssh);
  }
  const extra = await ask('Weitere Admin-Adressen/-Netze, die immer Zugriff haben und nie gesperrt werden (Komma-getrennt, leer = keine)', '');
  for (const x of extra.split(',').map((s) => s.trim()).filter(Boolean)) admins.add(x);
  cfg.admin_ips = [...admins];

  // Bereits offene Ports nicht versehentlich aussperren
  const listening = new Set();
  for (const x of [...readNetTable('/proc/net/tcp', false), ...readNetTable('/proc/net/tcp6', true)]) {
    if (x.state === '0A' && !x.local.startsWith('127.') && x.local !== '::1') listening.add(x.lport);
  }
  listening.delete(53);
  const sshPort = (() => { try { const m = /^\s*Port\s+(\d+)/m.exec(fs.readFileSync('/etc/ssh/sshd_config', 'utf8')); return m ? parseInt(m[1], 10) : 22; } catch (_) { return 22; } })();
  const web = parseInt(await ask('Port der Web-Oberfläche', String(cfg.web.port)), 10) || 8088;
  cfg.web.port = web;
  listening.delete(web);
  const ports = new Set([sshPort, ...cfg.firewall.allow_in_lan.tcp]);
  if (listening.size) {
    const list = [...listening].sort((a, b) => a - b);
    console.log(`\nAktuell auf diesem Rechner offene TCP-Ports: ${list.join(', ')}`);
    if (await askYn('Diese Ports weiterhin aus dem LAN erreichbar lassen?', true)) list.forEach((p) => ports.add(p));
  }
  cfg.firewall.allow_in_lan.tcp = [...ports].sort((a, b) => a - b);
  const wan = await ask('TCP-Ports, die aus dem INTERNET erreichbar sein sollen (Komma-getrennt, leer = keine – empfohlen)', '');
  cfg.firewall.allow_in_wan.tcp = wan.split(',').map((s) => parseInt(s, 10)).filter((n) => n > 0 && n < 65536);

  cfg.dns.enabled = await askYn('DNS-Filter (wie AdGuard) aktivieren?', true);
  cfg.isolation.enabled = await askYn('Rechner bei schwerem Verdacht automatisch vom Netz trennen?', true);

  const notif = await ask('Benachrichtigungen einrichten? (nein / telegram / ntfy / email)', 'nein');
  if (notif === 'telegram') {
    cfg.notify.telegram = { ...cfg.notify.telegram, enabled: true, bot_token: await ask('Telegram Bot-Token'), chat_id: await ask('Telegram Chat-ID') };
  } else if (notif === 'ntfy') {
    cfg.notify.ntfy = { ...cfg.notify.ntfy, enabled: true, server: await ask('ntfy-Server', 'https://ntfy.sh'), topic: await ask('ntfy-Topic (schwer erratbar wählen!)', `netguard-${crypto.randomBytes(6).toString('hex')}`) };
  } else if (notif === 'email') {
    cfg.notify.email = { enabled: true, host: await ask('SMTP-Server'), port: parseInt(await ask('SMTP-Port', '587'), 10), secure: await ask('Verschlüsselung (starttls / tls / none)', 'starttls'), user: await ask('SMTP-Benutzer'), pass: await ask('SMTP-Passwort'), from: await ask('Absender'), to: await ask('Empfänger') };
  }

  let generated = null;
  if (!cfg.web.password_hash) {
    let pw = '';
    if (interactive) {
      pw = await hidden('Passwort für die Web-Oberfläche (min. 10 Zeichen, leer = zufällig erzeugen): ');
      if (pw && pw.length < 10) { console.log('Zu kurz – es wird ein zufälliges Passwort erzeugt.'); pw = ''; }
    }
    if (!pw) { pw = crypto.randomBytes(12).toString('base64url'); generated = pw; }
    cfg.web.password_hash = hashPassword(pw);
  }
  if (rl) rl.close();

  config.save(cfg);
  console.log(`\nKonfiguration gespeichert: ${config.configPath()}`);
  if (generated) console.log(`\n>>> Web-Passwort (nur jetzt sichtbar, bitte notieren): ${generated}\n`);
  if (cfg.mode === 'gateway') console.log('Hinweis Gateway-Modus: IP-Forwarding muss aktiv sein (net.ipv4.ip_forward=1).');
  return clone(cfg);
}

module.exports = { runSetup, detectLan };
