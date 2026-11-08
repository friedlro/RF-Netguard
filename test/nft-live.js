'use strict';
// Lädt die echten Regeln in den Kernel. NUR im eigenen Netzwerk-Namespace ausführen:
//   sudo unshare -n node test/nft-live.js
const fs = require('fs'); const os = require('os'); const path = require('path');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ngl-'));
process.env.NETGUARD_CONFIG = path.join(tmp, 'c.json');
const config = require('../src/config');
const { Firewall, flushAll } = require('../src/firewall');
const { run } = require('../src/util');
(async () => {
  if (fs.readFileSync('/proc/net/dev', 'utf8').split('\n').slice(2).filter(Boolean).some((l) => !/^\s*lo:/.test(l))) { console.error('Abbruch: nicht in eigenem Netzwerk-Namespace (unshare -n): es gibt echte Schnittstellen.'); process.exit(2); }
  const cfg = config.load();
  Object.assign(cfg.paths, { data: tmp, log: tmp, run: tmp });
  cfg.admin_ips = ['192.0.2.7']; cfg.firewall.threat_feeds.enabled = false;
  const state = { data: { bans: [], ban_meta: {}, isolated: false, downed_ifaces: [] }, save() {}, flush() {} };
  const log = { info() {}, warn: console.log, error: console.log, debug() {} };
  const fw = new Firewall({ cfg: () => cfg, log, state, events: { report() {} } });
  let fails = 0; const ck = (n, c) => { console.log(c ? '  ✓' : '  ✗', n); if (!c) fails++; };
  ck('apply', await fw.apply());
  ck('Tabelle vorhanden', (await run('nft', ['list', 'table', 'inet', 'netguard'])).code === 0);
  ck('ban', await fw.ban('203.0.113.50', 600, 'test', 'test'));
  ck('ban sichtbar', (await fw.listBans()).some((b) => b.ip === '203.0.113.50'));
  ck('Admin nicht sperrbar', !(await fw.ban('192.0.2.7', 600, 'x', 'x')));
  ck('unban', await fw.unban('203.0.113.50'));
  ck('isolate', await fw.isolate('Test'));
  const iso = await run('nft', ['list', 'table', 'inet', 'netguard_iso']);
  ck('Iso-Tabelle', iso.code === 0);
  ck('Iso lässt LAN herein', /ip saddr @lan4 accept/.test(iso.stdout));
  ck('release', await fw.release());
  ck('Iso-Tabelle weg', (await run('nft', ['list', 'table', 'inet', 'netguard_iso'])).code !== 0);
  ck('Schutz aus', await fw.protectionOff());
  ck('Tabelle weg bei Schutz aus', (await run('nft', ['list', 'table', 'inet', 'netguard'])).code !== 0);
  ck('Schutz an', await fw.protectionOn());
  ck('Tabelle wieder da', (await run('nft', ['list', 'table', 'inet', 'netguard'])).code === 0);
  for (const lvl of ['low', 'high', 'paranoid']) { cfg.security_level = lvl; ck(`apply ${lvl}`, await fw.apply()); }
  cfg.mode = 'gateway'; cfg.firewall.gateway.nat = true; ck('apply gateway+nat', await fw.apply());
  // Zusätzliche Härtung + WireGuard-Regeln
  cfg.mode = 'host'; cfg.security_level = 'normal';
  Object.assign(cfg.firewall.hardening, { anti_spoofing: true, drop_fragments: true, conn_limit: 150, icmp: 'lan', wan_sources: ['198.51.100.0/24', '2001:db8::/32'], ssh_lan_only: true, block_dot_doq: true });
  cfg.firewall.allow_in_wan.tcp = [22, 443];
  ck('apply Härtung (alle Optionen)', await fw.apply());
  const rs = (await run('nft', ['list', 'table', 'inet', 'netguard'])).stdout;
  ck('Härtung: Verbindungslimit-Regel geladen', /connlimit4/.test(rs) && /ct count over 150/.test(rs));
  ck('Härtung: WAN-Ports nur für Quellen', /ip saddr @wansrc4 tcp dport 443 accept/.test(rs) && !/dport 22 accept/.test(rs.replace(/@lan4[^\n]*/g, '')));
  ck('Härtung: Fragmente/Spoofing', /frag-off/.test(rs) && /127\.0\.0\.0\/8/.test(rs));
  cfg.firewall.hardening.icmp = 'off'; ck('apply icmp off', await fw.apply());
  cfg.wireguard.enabled = true; cfg.wireguard.private_key = 'x'; cfg.wireguard.routing = { access_lan: true, internet: false, peers_isolated: true };
  ck('apply WireGuard (LAN-Zugriff)', await fw.apply());
  let rs2 = (await run('nft', ['list', 'table', 'inet', 'netguard'])).stdout;
  ck('WG: Port offen, Forward-Kette, Peers getrennt', /udp dport 51820 accept/.test(rs2) && /chain forward/.test(rs2) && /iifname "wg0" oifname "wg0" counter/.test(rs2) && !/iifname "wg0" accept/.test(rs2));
  cfg.wireguard.lan_routes = ['192.168.1.0/24']; await fw.apply(); rs2 = (await run('nft', ['list', 'table', 'inet', 'netguard'])).stdout;
  ck('WG: LAN-Zugriff nur auf freigegebene Netze', /iifname "wg0" ip daddr 192\.168\.1\.0\/24 accept/.test(rs2));
  ck('WG: NAT für VPN-Netz', /masquerade/.test((await run('nft', ['list', 'table', 'ip', 'netguard_nat'])).stdout));
  cfg.wireguard.routing = { access_lan: true, internet: true, peers_isolated: false }; cfg.wireguard.access_host = false;
  ck('apply WireGuard (Full-Tunnel)', await fw.apply());
  rs2 = (await run('nft', ['list', 'table', 'inet', 'netguard'])).stdout;
  ck('WG: Full-Tunnel erlaubt alles aus dem VPN', /iifname "wg0" accept/.test(rs2));
  cfg.mode = 'gateway'; cfg.firewall.hardening.block_private_wan = true; ck('apply Gateway+WG+Härtung', await fw.apply());
  ck('isolate mit VPN', await fw.isolate('Test')); ck('release mit VPN', await fw.release());
  cfg.wireguard.enabled = false; cfg.mode = 'host';
  await flushAll();
  ck('flushAll', (await run('nft', ['list', 'table', 'inet', 'netguard'])).code !== 0);
  process.exit(fails ? 1 : 0);
})();
