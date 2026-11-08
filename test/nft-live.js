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
  await flushAll();
  ck('flushAll', (await run('nft', ['list', 'table', 'inet', 'netguard'])).code !== 0);
  process.exit(fails ? 1 : 0);
})();
