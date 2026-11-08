'use strict';
// Hilfsprogramm für test/netns-live.sh: wendet echte RF-NetGuard-Regeln im aktuellen Netzwerk-Namespace an.
const fs = require('fs'); const os = require('os'); const path = require('path');
const dir = process.env.NG_TEST_DIR || fs.mkdtempSync(path.join(os.tmpdir(), 'ngn-'));
process.env.NETGUARD_CONFIG = path.join(dir, 'c.json');
const config = require('../src/config');
const { Firewall } = require('../src/firewall');
const { State } = require('../src/state');
(async () => {
  const cfg = config.load();
  Object.assign(cfg.paths, { data: dir, log: dir, run: dir });
  cfg.lan_cidrs = ['192.168.50.0/24']; cfg.admin_ips = []; cfg.web.port = 8088;
  cfg.firewall.allow_in_lan.tcp = [22]; cfg.firewall.threat_feeds.enabled = false; cfg.firewall.harden_sysctl = false;
  cfg.isolation.keep_lan_access = process.env.KEEP_LAN !== '0';
  const log = { info() {}, warn() {}, error: console.error, debug() {} };
  const state = new State(dir);
  const fw = new Firewall({ cfg: () => cfg, log, state, events: { report() {} } });
  const cmd = process.argv[2];
  let ok = true;
  if (cmd === 'apply') ok = await fw.apply();
  else if (cmd === 'isolate') ok = await fw.isolate('Test');
  else if (cmd === 'release') ok = await fw.release();
  else if (cmd === 'off') ok = await fw.protectionOff();
  state.flush();
  process.exit(ok ? 0 : 1);
})();
