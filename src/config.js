'use strict';
// Standard-Konfiguration und Laden/Speichern der config.json
const fs = require('fs');
const path = require('path');
const { deepMerge, clone, atomicWrite, ensureDir } = require('./util');

const DEFAULTS = {
  version: 1,
  // host: schützt nur diesen Rechner (+ DNS-Filter für das LAN)
  // gateway: Rechner ist Router/Gateway des Netzes (Forward-Filter, NAT, DNS-Zwang)
  mode: 'host',
  // low | normal | high | paranoid
  security_level: 'normal',
  lan_cidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', 'fe80::/10', 'fc00::/7'],
  wan_interface: 'auto',
  // Diese Adressen haben immer Zugriff und werden nie gesperrt (z.B. dein Admin-PC)
  admin_ips: [],
  never_ban: [],
  paths: { data: '/var/lib/netguard', log: '/var/log/netguard', run: '/run/netguard' },

  web: { enabled: true, bind: '0.0.0.0', port: 8088, password_hash: '', session_hours: 12, allowed_hosts: [] },

  // Programm-Updates
  // Standard: Updates direkt aus dem Repository: source = auto (GitLite, sonst GitHub) | gitlite | github; branch gilt für beide. Optional: url = eigene latest.json mit signierten Paketen (public_key/builtin_key)
  // builtin_key = eingebauten Schlüssel der offiziellen Releases vertrauen
  update: { source: 'auto', gitlite_url: 'https://gitlite.bicolor-bull.ts.net/r/rf-netguard', repo: 'friedlro/RF-Netguard', branch: 'main', url: '', public_key: '', builtin_key: true, check_hours: 6, auto_install: true },
  firewall: {
    enabled: true,
    allow_in_lan: { tcp: [22], udp: [] },
    allow_in_wan: { tcp: [], udp: [] },
    bruteforce_ports: [22, 21, 23, 3389, 5900],
    block_out_tcp_ports: [23, 2323, 4444, 5555, 6667, 6697, 31337],
    // Nur bei Stufe "paranoid": ausgehend erlaubte Ports
    outbound_allow: { tcp: [22, 53, 80, 443, 465, 587, 853, 993], udp: [53, 123, 443] },
    log_drops: true,
    harden_sysctl: true,
    threat_feeds: {
      enabled: true,
      update_hours: 12,
      urls: [
        { name: 'Feodo Tracker (Botnet-C2)', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', enabled: true },
        { name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop.txt', enabled: true },
        { name: 'Emerging Threats Compromised', url: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', enabled: true },
      ],
    },
    gateway: { nat: false, force_dns: true },
    // Zusätzliche Absicherung
    hardening: {
      anti_spoofing: true,      // Pakete mit unmöglicher Absenderadresse (0.0.0.0/8, 127/8, Multicast, 240/4, eigene Adresse) verwerfen
      block_private_wan: false, // Absender aus privaten Netzen (RFC1918) auf der WAN-Schnittstelle verwerfen – nur aktivieren, wenn der Rechner direkt am Internet hängt!
      drop_fragments: false,    // fragmentierte Pakete verwerfen (selten legitim, häufig für Umgehungsversuche)
      conn_limit: 0,            // gleichzeitige neue Verbindungen je Absender (0 = aus, empfohlen 100–300)
      icmp: 'auto',             // Ping von außen: auto (nach Sicherheitsstufe) | off (nie antworten) | lan (nur aus dem LAN)
      wan_sources: [],          // WAN-Ports (allow_in_wan) nur für diese Adressen/Netze öffnen (leer = für alle)
      ssh_lan_only: false,      // Port 22 nie aus dem Internet erreichbar machen, auch wenn er unter allow_in_wan steht
      block_dot_doq: false,     // ausgehend DNS-over-TLS/QUIC (Port 853) sperren, damit Geräte den DNS-Filter nicht umgehen
    },
  },
  // WireGuard-VPN-Server (Teilnehmer werden in der Oberfläche unter „VPN“ verwaltet)
  wireguard: {
    enabled: false,
    interface: 'wg0',
    listen_port: 51820,
    address: '10.66.0.1/24',    // VPN-Netz; dieser Rechner hat die erste Adresse
    endpoint: '',               // öffentliche Adresse/DynDNS-Name für die Clients, z. B. vpn.example.org (Port wird ergänzt)
    client_dns: '',             // leer = der DNS-Filter dieses Rechners (falls aktiv)
    mtu: 1420,
    keepalive: 25,
    allow_wan_port: true,       // UDP-Port in der Firewall für das Internet öffnen
    access_host: true,          // VPN-Teilnehmer dürfen die Dienste dieses Rechners nutzen (Oberfläche, SSH, DNS-Filter)
    lan_routes: [],             // Netze im LAN, die Clients erreichen dürfen (leer = automatisch: LAN-Netze ab /20), z. B. 192.168.1.0/24
    routing: { access_lan: true, internet: false, peers_isolated: true },
    private_key: '',
    peers: [],
  },

  dns: {
    enabled: true,
    bind: '0.0.0.0',
    port: 53,
    upstreams: ['https://dns.quad9.net/dns-query', 'https://cloudflare-dns.com/dns-query', '9.9.9.9', '1.1.1.1'],
    bootstrap: { 'dns.quad9.net': '9.9.9.9', 'cloudflare-dns.com': '1.1.1.1', 'dns.google': '8.8.8.8', 'dns.adguard-dns.com': '94.140.14.14' },
    // null_ip: 0.0.0.0 / :: | nxdomain | refused
    blocking_mode: 'null_ip',
    cache: { enabled: true, max_entries: 20000, min_ttl: 30, max_ttl: 3600, serve_stale: true, stale_max_s: 600 },
    lists: [
      { id: 'adguard', name: 'AdGuard DNS-Filter (Werbung & Tracker)', url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt', enabled: true, category: 'ads' },
      { id: 'urlhaus', name: 'URLhaus (Malware-Domains)', url: 'https://urlhaus.abuse.ch/downloads/hostfile/', enabled: true, category: 'malware' },
      { id: 'phishing-army', name: 'Phishing Army (Phishing)', url: 'https://phishing.army/download/phishing_army_blocklist.txt', enabled: true, category: 'malware' },
      { id: 'hagezi-pro', name: 'HaGeZi Pro (Werbung, Tracker, Telemetrie – empfohlen)', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt', enabled: true, category: 'ads' },
      { id: 'hagezi-proplus', name: 'HaGeZi Pro++ (strenger, kann einzelne Seiten stören)', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt', enabled: false, category: 'ads' },
      { id: 'oisd-big', name: 'OISD Big (Werbung, Tracker, Malware)', url: 'https://big.oisd.nl/', enabled: false, category: 'ads' },
      { id: 'stevenblack', name: 'StevenBlack Unified Hosts', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', enabled: false, category: 'ads' },
      { id: 'adult', name: 'Erwachsenen-Inhalte (StevenBlack)', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts', enabled: false, category: 'adult' },
      { id: 'gambling', name: 'Glücksspiel (StevenBlack)', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts', enabled: false, category: 'gambling' },
    ],
    list_update_hours: 24,
    // Browser (Firefox, Safari/iCloud Private Relay) fragen zuerst diese Namen; NXDOMAIN schaltet deren eigenes DNS-over-HTTPS ab,
    // das den Werbefilter sonst umgehen würde.
    disable_browser_doh: true,
    // AdGuard-Syntax: ||beispiel.org^   @@||erlaubt.org^   /regex/   0.0.0.0 host
    custom_rules: [],
    // Lokale DNS-Namen: { "nas.home": "192.168.1.10" }
    rewrites: {},
    safe_search: false,
    // leer = nur lan_cidrs + localhost dürfen den DNS-Server nutzen
    allowed_clients: [],
    rate_limit_qps: 500,
    log_queries: true,
    log_memory: 5000,
  },

  ids: {
    enabled: true,
    ssh_bruteforce: { enabled: true, window_s: 300 },
    portscan: { window_s: 60 },
    processes: {
      enabled: true, interval_s: 20, kill: true,
      miner_names: ['xmrig', 'xmr-stak', 'minerd', 'cpuminer', 'kdevtmpfsi', 'kinsing', 'ethminer', 'cgminer', 'bfgminer', 'nbminer', 't-rex', 'lolminer'],
      suspicious_dirs: ['/tmp', '/dev/shm', '/var/tmp'],
      ignore_paths: ['/tmp/.mount_'],
      ignore_names: [],
    },
    connections: { enabled: true, interval_s: 10, syn_sent_threshold: 80 },
    listeners: { enabled: true, interval_s: 30 },
    integrity: {
      enabled: true, interval_s: 60,
      files: ['/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers', '/etc/sudoers.d', '/etc/ssh/sshd_config', '/etc/hosts', '/etc/crontab', '/etc/cron.d', '/etc/ld.so.preload', '/etc/rc.local', '/root/.ssh/authorized_keys'],
    },
    traffic: { enabled: true, interval_s: 5, tx_alert_mbit: 300, rx_alert_mbit: 600, spike_factor: 8 },
    arp: { enabled: true, new_device_alert: false },
    dns: { dga: true, tunneling: true, malware_hits_threshold: 5 },
  },

  antivirus: {
    enabled: true,
    engine: 'auto', // auto | clamd | clamscan
    realtime: true,
    watch_paths: ['/tmp', '/var/tmp', '/dev/shm', '/home', '/root', '/var/www', '/srv', '/opt'],
    watch_max_dirs: 15000,
    exclude: ['node_modules', '.cache', '.git', '.npm', '.local/share/Trash', 'proc', 'sys'],
    scan_paths: ['/home', '/root', '/tmp', '/var/tmp', '/var/www', '/srv', '/opt', '/usr/local'],
    schedule: { enabled: true, time: '03:30' },
    // quarantine | delete | report
    action: 'quarantine',
    max_file_mb: 100,
    kill_malicious_processes: true,
    flag_elf_in_tmp: true,
  },

  notify: {
    // info | warn | high | critical
    min_severity: 'high',
    cooldown_s: 600,
    label: '',
    telegram: { enabled: false, bot_token: '', chat_id: '', api_base: 'https://api.telegram.org' },
    ntfy: { enabled: false, server: 'https://ntfy.sh', topic: '', token: '' },
    email: { enabled: false, host: '', port: 587, secure: 'starttls', user: '', pass: '', from: '', to: '' },
    webhook: { enabled: false, url: '', headers: {} },
  },

  isolation: {
    enabled: true,
    // Summe der Kompromittierungs-Punkte innerhalb des Zeitfensters, ab der der Rechner getrennt wird
    score_threshold: 100,
    window_minutes: 15,
    // zusätzlich Netzwerk-Interfaces auf "down" setzen (Interfaces des internen Netzes bleiben oben, solange keep_lan_access gilt)
    hard_disconnect: false,
    // Das interne Netz (lan_cidrs) behält während der Trennung Zugriff auf diesen Rechner (Web-Oberfläche, SSH, …),
    // damit man bei Fehlalarm freigeben oder abschalten kann. Internet/Gateway-Weiterleitung bleiben gesperrt.
    keep_lan_access: true,
    // admin_ips bleiben während der Trennung erreichbar
    allow_admin: true,
    // 0 = bleibt getrennt, bis manuell freigegeben
    auto_release_minutes: 0,
    // Kompromittierte LAN-Geräte (Gateway/DNS-Modus) sperren
    quarantine_clients: true,
  },
};

const LEVELS = ['low', 'normal', 'high', 'paranoid'];

function configPath() { return process.env.NETGUARD_CONFIG || '/etc/netguard/config.json'; }

function normalize(cfg) {
  // Umstellung auf GitLite: frühere Installationen hatten 'github' als Standard → einmalig auf 'auto' (GitLite zuerst, GitHub als Ausweichquelle)
  if (cfg.update && !cfg.update.source_migrated) { if (cfg.update.source === 'github') cfg.update.source = 'auto'; cfg.update.source_migrated = true; }
  if (cfg.wireguard && !Array.isArray(cfg.wireguard.peers)) cfg.wireguard.peers = [];
  if (cfg.firewall && cfg.firewall.hardening && !['auto', 'off', 'lan'].includes(cfg.firewall.hardening.icmp)) cfg.firewall.hardening.icmp = 'auto';
  // Frühere Versionen trugen die GitHub-Releases-Adresse als Standard ein: jetzt gilt leer = direkt von GitHub
  if (cfg.update && cfg.update.url === 'https://github.com/friedlro/RF-Netguard/releases/latest/download/latest.json') cfg.update.url = '';
  if (!LEVELS.includes(cfg.security_level)) cfg.security_level = 'normal';
  if (!['host', 'gateway'].includes(cfg.mode)) cfg.mode = 'host';
  if (!['null_ip', 'nxdomain', 'refused'].includes(cfg.dns.blocking_mode)) cfg.dns.blocking_mode = 'null_ip';
  if (!['quarantine', 'delete', 'report'].includes(cfg.antivirus.action)) cfg.antivirus.action = 'quarantine';
  if (!['info', 'warn', 'high', 'critical'].includes(cfg.notify.min_severity)) cfg.notify.min_severity = 'high';
  for (const k of ['admin_ips', 'never_ban', 'lan_cidrs']) if (!Array.isArray(cfg[k])) cfg[k] = clone(DEFAULTS[k]);
  if (!Array.isArray(cfg.dns.lists)) cfg.dns.lists = clone(DEFAULTS.dns.lists);
  // Neue Standardlisten in bestehende Konfigurationen übernehmen (Listen, die der Nutzer hat, bleiben unverändert)
  for (const l of DEFAULTS.dns.lists) if (!cfg.dns.lists.some((x) => x.id === l.id)) cfg.dns.lists.push(clone(l));
  if (!Array.isArray(cfg.dns.custom_rules)) cfg.dns.custom_rules = [];
  return cfg;
}

function load(file = configPath()) {
  let user = {};
  try {
    user = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') throw new Error(`Konfiguration ${file} ist ungültig: ${e.message}`);
  }
  return normalize(deepMerge(clone(DEFAULTS), user));
}

function save(cfg, file = configPath()) {
  ensureDir(path.dirname(file), 0o700);
  atomicWrite(file, JSON.stringify(cfg, null, 2) + '\n', 0o600);
}

module.exports = { DEFAULTS, LEVELS, configPath, load, save, normalize };
