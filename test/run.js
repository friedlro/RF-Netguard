'use strict';
// Selbsttests ohne Root und ohne Netzwerkzugriff (außer Loopback).
// Aufruf: node test/run.js
const assert = require('assert');
const dgram = require('dgram');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ngtest-'));
process.env.NETGUARD_CONFIG = path.join(tmp, 'config.json');

const dnsmod = require('../src/dns');
const config = require('../src/config');
const { hashPassword, verifyPassword } = require('../src/web');
const { Firewall, LEVELS, parseFeed } = require('../src/firewall');

let pass = 0; let failn = 0;
const tests = [];
const test = (name, fn) => tests.push([name, fn]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- DNS-Regeln ----------
test('Regelparser: AdGuard-Syntax', () => {
  const P = dnsmod.parseRule;
  assert.deepStrictEqual(P('||ads.example.com^').kind, 'suffix');
  assert.strictEqual(P('@@||ok.example.com^').allow, true);
  assert.strictEqual(P('||x.org^$important').important, true);
  assert.deepStrictEqual(P('||x.org^$dnstype=AAAA').types, ['AAAA']);
  assert.strictEqual(P('! Kommentar'), null);
  assert.strictEqual(P('||x.org^$badmodifier'), null);
  assert.strictEqual(P('/track[0-9]+\\.net/').kind, 'regex');
  assert.strictEqual(P('||*.cdn.example.com^').kind, 'regex');
  assert.deepStrictEqual(dnsmod.parseLine('0.0.0.0 evil.example').map((r) => r.value), ['evil.example']);
  assert.deepStrictEqual(dnsmod.parseLine('127.0.0.1 localhost'), []);
});

function filterOf(rules) {
  const f = new dnsmod.Filter();
  const li = f.addList('t', 'x');
  for (const r of rules) for (const p of dnsmod.parseLine(r)) f.add(p, li);
  return f;
}

test('Filter: Block, Ausnahme, important, Subdomains', () => {
  const f = filterOf(['||ads.example.com^', '@@||good.ads.example.com^', '||bad.org^$important', '@@||bad.org^', '/^tracker[0-9]+\\./']);
  assert.strictEqual(f.match('ads.example.com', 1).action, 'block');
  assert.strictEqual(f.match('x.y.ads.example.com', 1).action, 'block');
  assert.strictEqual(f.match('good.ads.example.com', 1).action, 'allow');
  assert.strictEqual(f.match('bad.org', 1).action, 'block'); // important schlägt Ausnahme
  assert.strictEqual(f.match('tracker12.foo.com', 1).action, 'block');
  assert.strictEqual(f.match('example.com', 1), null);
  assert.strictEqual(f.match('notads.example.com', 1), null);
  assert.strictEqual(f.match('badxads.example.com', 1), null);
});

test('Paketaufbau/-parser', () => {
  const q = dnsmod.buildQuery('www.Example.com', 1);
  const p = dnsmod.parseQuery(q);
  assert.strictEqual(p.qname, 'www.example.com');
  assert.strictEqual(p.qtype, 1);
  assert.strictEqual(dnsmod.parseQuery(Buffer.alloc(5)), null);
  const bad = Buffer.from(q); bad[12] = 0xff; // ungültiges Label
  assert.strictEqual(dnsmod.parseQuery(bad), null);
});

// ---------- DNS-Server mit Fake-Upstream ----------
test('DNS-Server: blocken, umleiten, weiterleiten, cachen', async () => {
  const UP = 25354; const SRV = 25353;
  let upstreamHits = 0;
  const up = dgram.createSocket('udp4');
  up.on('message', (msg, r) => {
    upstreamHits++;
    const q = dnsmod.parseQuery(msg);
    const ans = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x01, 0x2c, 0, 4, 1, 2, 3, 4]);
    up.send(dnsmod.buildReply(msg, q, 0, [ans]), r.port, r.address);
  });
  await new Promise((r) => up.bind(UP, '127.0.0.1', r));

  const cfg = config.load();
  cfg.dns.bind = '127.0.0.1'; cfg.dns.port = SRV; cfg.dns.upstreams = [`127.0.0.1:${UP}`];
  cfg.dns.lists = []; cfg.dns.custom_rules = ['||blocked.test^'];
  cfg.dns.rewrites = { 'nas.home': '192.168.1.10' };
  const log = { info() {}, warn() {}, error() {}, debug() {} };
  const dns = new dnsmod.DnsServer({ cfg: () => cfg, log, dataDir: tmp });
  dns.configure();
  await dns.listen(); dns.running = true;

  const ask = (name, type = 1) => new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    const t = setTimeout(() => { s.close(); reject(new Error('Timeout')); }, 3000);
    s.on('message', (m) => { clearTimeout(t); s.close(); resolve(m); });
    s.send(dnsmod.buildQuery(name, type), SRV, '127.0.0.1');
  });
  const lastIp = (m) => [...m.subarray(m.length - 4)].join('.');
  try {
    let r = await ask('blocked.test');
    assert.strictEqual(r.readUInt16BE(2) & 15, 0);
    assert.strictEqual(lastIp(r), '0.0.0.0');
    r = await ask('sub.blocked.test');
    assert.strictEqual(lastIp(r), '0.0.0.0');
    r = await ask('nas.home');
    assert.strictEqual(lastIp(r), '192.168.1.10');
    assert.strictEqual(upstreamHits, 0);
    r = await ask('fine.example');
    assert.strictEqual(lastIp(r), '1.2.3.4');
    assert.strictEqual(upstreamHits, 1);
    r = await ask('fine.example');
    assert.strictEqual(lastIp(r), '1.2.3.4');
    assert.strictEqual(upstreamHits, 1, 'zweite Antwort muss aus dem Cache kommen');
    cfg.dns.blocking_mode = 'nxdomain';
    r = await ask('blocked.test');
    assert.strictEqual(r.readUInt16BE(2) & 15, 3);
    const st = dns.getStats();
    assert.ok(st.blocked >= 3 && st.total >= 6 && st.cached >= 1);
    assert.strictEqual(dns.check('blocked.test').result, 'blocked');
    assert.strictEqual(dns.check('x.example').result, 'allowed');
  } finally { await dns.stop(); up.close(); }
});

// ---------- Updates ----------
const crypto = require('crypto');
const upd = require('../src/update');
const PROJECT = path.resolve(__dirname, '..');
const UPD_ITEMS = ['src', 'ui', 'deploy', 'test', 'tools', 'package.json', 'README.md', 'config.example.json'];

function mkStage(version, mutate) { // Kopie des Projekts mit anderer Version, optional verändert
  const dir = fs.mkdtempSync(path.join(tmp, 'stage-'));
  for (const it of UPD_ITEMS) fs.cpSync(path.join(PROJECT, it), path.join(dir, 'netguard', it), { recursive: true });
  const pj = path.join(dir, 'netguard', 'package.json');
  const j = JSON.parse(fs.readFileSync(pj, 'utf8')); j.version = version; fs.writeFileSync(pj, JSON.stringify(j));
  if (mutate) mutate(path.join(dir, 'netguard'));
  return dir;
}
function mkBundle(stageDir, version, privKey, opts = {}) {
  const tf = path.join(stageDir, 'u.tar.gz');
  spawnSync('tar', ['-czf', tf, '-C', stageDir, 'netguard']);
  const tar = fs.readFileSync(tf);
  const sha256 = crypto.createHash('sha256').update(tar).digest('hex');
  const sig = crypto.sign(null, upd.signedText(version, sha256), privKey).toString('base64');
  return JSON.stringify({ format: 1, version: opts.claimVersion || version, notes: 'Test', sha256, sig, data: tar.toString('base64') });
}
const keyA = crypto.generateKeyPairSync('ed25519'); const keyB = crypto.generateKeyPairSync('ed25519');
const pubPem = (k) => k.publicKey.export({ type: 'spki', format: 'pem' });
function withKey(pem) { const c = config.load(); c.update.public_key = pem || ''; c.update.builtin_key = false; c.update.url = ''; Object.assign(c.paths, { data: path.join(tmp, 'updata'), log: path.join(tmp, 'uplog'), run: path.join(tmp, 'uprun') }); config.save(c); }
function mkApp(version) { // "installiertes" Programmverzeichnis
  const root = fs.mkdtempSync(path.join(tmp, 'opt-')); const app = path.join(root, 'netguard');
  for (const it of UPD_ITEMS) fs.cpSync(path.join(PROJECT, it), path.join(app, it), { recursive: true });
  const pj = path.join(app, 'package.json'); const j = JSON.parse(fs.readFileSync(pj, 'utf8')); j.version = version; fs.writeFileSync(pj, JSON.stringify(j));
  return app;
}
const okHooks = (calls = []) => ({ async restart() { calls.push('restart'); return true; }, async health(v) { calls.push(`health:${v}`); return true; }, syncService() { return null; }, async reloadUnits() {}, restoreService() {} });
const logq = () => {};

test('Update: Versionsvergleich', () => {
  assert.strictEqual(upd.cmpVer('1.10.0', '1.9.9'), 1);
  assert.strictEqual(upd.cmpVer('1.0.0', '1.0.0'), 0);
  assert.strictEqual(upd.cmpVer('0.9.9', '1.0.0'), -1);
});

test('Auto-Updater: installiert automatisch, aber nur wenn erlaubt, signiert und je Version einmal', async () => {
  const c = config.load(); c.update.auto_install = true; c.update.builtin_key = true; c.update.public_key = '';
  const dir = path.join(tmp, 'autodata'); fs.mkdirSync(dir, { recursive: true });
  const events = []; let iso = false; let installs = 0;
  const u = new upd.Updater({ cfg: () => c, log: { info() {}, warn() {}, error() {} }, eventLog: { add: (e) => events.push(e) }, dataDir: dir, canAuto: () => !iso });
  u.installFromManifest = async () => { installs++; if (installs === 1) throw new Error('kaputt'); return {}; };
  assert.strictEqual(await u.autoInstall(), false, 'ohne gefundenes Update nichts tun');
  u.info = { newer: true, latest: '99.0.0' };
  iso = true; assert.strictEqual(await u.autoInstall(), false, 'bei Netztrennung nicht'); assert.strictEqual(installs, 0);
  iso = false; c.update.auto_install = false; assert.strictEqual(await u.autoInstall(), false, 'abgeschaltet'); assert.strictEqual(installs, 0);
  c.update.auto_install = true; assert.strictEqual(await u.autoInstall(), false, 'Fehlschlag gemeldet'); assert.strictEqual(installs, 1);
  assert.ok(events.some((e) => e.type === 'update-failed'));
  assert.strictEqual(await u.autoInstall(), false, 'dieselbe Version nicht erneut'); assert.strictEqual(installs, 1);
  u.info = { newer: true, latest: '99.0.1' }; assert.strictEqual(await u.autoInstall(), true, 'neue Version wird versucht'); assert.strictEqual(installs, 2);
});

test('Update: eingebauter Release-Schlüssel ist gültig und fremde Signaturen werden trotzdem abgelehnt', () => {
  const builtin = require('../src/update-key');
  assert.strictEqual(crypto.createPublicKey(builtin).asymmetricKeyType, 'ed25519');
  const cfg = config.load(); cfg.update.builtin_key = true; cfg.update.public_key = '';
  assert.deepStrictEqual(upd.trustedKeys(cfg), [builtin]);
  cfg.update.builtin_key = false; assert.deepStrictEqual(upd.trustedKeys(cfg), []);
  cfg.update.public_key = pubPem(keyB); assert.strictEqual(upd.trustedKeys(cfg).length, 1);
  const b = upd.parseBundle(mkBundle(mkStage('1.9.0'), '1.9.0', keyA.privateKey));
  assert.throws(() => upd.verifyBundle(b, [builtin]), /Signatur/, 'mit fremdem Schlüssel signiert → abgelehnt');
  assert.ok(upd.verifyBundle(b, [builtin, pubPem(keyA)]), 'eigener Zusatzschlüssel funktioniert');
  assert.strictEqual(upd.verifyBundle(b, []), false);
});

test('Update: Release-Werkzeug erzeugt gültig signiertes Paket; Manipulation und falscher Schlüssel werden erkannt', () => {
  const dir = fs.mkdtempSync(path.join(tmp, 'rel-'));
  let r = spawnSync(process.execPath, [path.join(PROJECT, 'tools/release.js'), 'keygen', dir], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stderr);
  r = spawnSync(process.execPath, [path.join(PROJECT, 'tools/release.js'), 'build', '--key', path.join(dir, 'release-key.pem'), '--out', dir, '--notes', 'Hallo'], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stderr);
  const file = path.join(dir, `rf-netguard-${upd.readVersion(PROJECT)}.ngupdate`);
  assert.strictEqual(spawnSync(process.execPath, [path.join(PROJECT, 'tools/release.js'), 'verify', file, path.join(dir, 'release-key.pub')]).status, 0);
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'latest.json'), 'utf8'));
  assert.strictEqual(manifest.version, upd.readVersion(PROJECT));
  const pub = fs.readFileSync(path.join(dir, 'release-key.pub'), 'utf8');
  const b = upd.parseBundle(fs.readFileSync(file));
  assert.ok(upd.verifyBundle(b, pub));
  assert.throws(() => upd.verifyBundle(b, pubPem(keyB)), /Signatur/);
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.throws(() => upd.parseBundle(JSON.stringify({ ...j, data: Buffer.concat([Buffer.from(j.data, 'base64'), Buffer.from('x')]).toString('base64') })), /Prüfsumme/);
  const rolled = upd.parseBundle(JSON.stringify({ ...j, version: '9.9.9' }));
  assert.throws(() => upd.verifyBundle(rolled, pub), /Signatur/, 'geänderte Versionsnummer darf nicht durchgehen');
});

test('Update: signiertes Update wird eingespielt, gesichert, Konfiguration bleibt', async () => {
  withKey(pubPem(keyA));
  const app = mkApp('1.0.0');
  const stage = mkStage('1.2.0');
  const calls = [];
  const bundle = path.join(tmp, 'ok.ngupdate'); fs.writeFileSync(bundle, mkBundle(stage, '1.2.0', keyA.privateKey));
  const r = await upd.performUpdate({ source: bundle, cli: true, appDir: app, hooks: okHooks(calls), log: logq });
  assert.ok(r.ok, r.message);
  assert.strictEqual(upd.readVersion(app), '1.2.0');
  assert.deepStrictEqual(calls, ['restart', 'health:1.2.0']);
  assert.strictEqual(upd.listBackups(app).length, 1);
  assert.strictEqual(upd.readVersion(upd.listBackups(app)[0].dir), '1.0.0');
  assert.ok(!fs.existsSync(`${app}.old`) && !fs.existsSync(`${app}.new`));
  const res = JSON.parse(fs.readFileSync(path.join(tmp, 'updata', 'update-result.json'), 'utf8'));
  assert.ok(res.ok && res.to === '1.2.0');
  // gleiche Version nochmal: nichts passiert
  const again = await upd.performUpdate({ source: bundle, cli: true, appDir: app, hooks: okHooks(), log: logq });
  assert.ok(again.unchanged);
  // Rollback auf die Sicherung
  const rb = await upd.rollbackLast({ appDir: app, hooks: okHooks(), log: logq });
  assert.ok(rb.ok, rb.message);
  assert.strictEqual(upd.readVersion(app), '1.0.0');
});

test('Update: Neue Version startet nicht → automatisch zurückgerollt', async () => {
  withKey(pubPem(keyA));
  const app = mkApp('1.0.0');
  const bundle = path.join(tmp, 'bad-health.ngupdate'); fs.writeFileSync(bundle, mkBundle(mkStage('1.3.0'), '1.3.0', keyA.privateKey));
  const calls = [];
  const hooks = { ...okHooks(calls), async health(v) { calls.push(`health:${v}`); return v === '1.0.0'; } };
  const r = await upd.performUpdate({ source: bundle, cli: true, appDir: app, hooks, log: logq });
  assert.strictEqual(r.ok, false);
  assert.ok(r.rolledBack, 'Rollback muss bestätigt sein');
  assert.strictEqual(upd.readVersion(app), '1.0.0');
  assert.deepStrictEqual(calls, ['restart', 'health:1.3.0', 'restart', 'health:1.0.0']);
  assert.ok(!fs.existsSync(`${app}.failed`) && !fs.existsSync(`${app}.old`));
});

test('Update: Syntaxfehler, falsche Signatur, Pfad-Tricks, Links und Downgrade werden abgelehnt (Programm bleibt unverändert)', async () => {
  withKey(pubPem(keyA));
  const app = mkApp('1.0.0');
  const attempt = async (name, content, opts = {}) => {
    const f = path.join(tmp, `${name}.ngupdate`); fs.writeFileSync(f, content);
    const r = await upd.performUpdate({ source: f, cli: true, appDir: app, hooks: okHooks(), log: logq, ...opts });
    assert.strictEqual(r.ok, false, `${name} wurde fälschlich akzeptiert`);
    assert.strictEqual(upd.readVersion(app), '1.0.0', `${name} hat das Programm verändert`);
    return r.message;
  };
  assert.match(await attempt('syntax', mkBundle(mkStage('1.4.0', (root) => fs.appendFileSync(path.join(root, 'src/util.js'), '\n}}} kaputt')), '1.4.0', keyA.privateKey)), /Syntaxfehler/);
  assert.match(await attempt('wrongkey', mkBundle(mkStage('1.4.0'), '1.4.0', keyB.privateKey)), /Signatur/);
  assert.match(await attempt('claimver', mkBundle(mkStage('1.4.0'), '1.4.0', keyA.privateKey, { claimVersion: '1.5.0' })), /Signatur/);
  assert.match(await attempt('older', mkBundle(mkStage('0.9.0'), '0.9.0', keyA.privateKey)), /älter/);
  assert.match(await attempt('noconfig', mkBundle(mkStage('1.4.0', (root) => fs.writeFileSync(path.join(root, 'src/config.js'), "throw new Error('kaputt');")), '1.4.0', keyA.privateKey)), /startet nicht|Syntax/);
  // Archiv mit ../ und Symlink (per Python gebaut)
  const evil = fs.mkdtempSync(path.join(tmp, 'evil-'));
  const py = `import tarfile,io,sys
t=tarfile.open(sys.argv[1],'w:gz')
d=b'x'*200
for n in sys.argv[2:]:
    if n=='link':
        i=tarfile.TarInfo('netguard/l');i.type=tarfile.SYMTYPE;i.linkname='/etc/passwd';t.addfile(i)
    else:
        i=tarfile.TarInfo(n);i.size=len(d);t.addfile(i,io.BytesIO(d))
t.close()`;
  for (const [name, entries] of [['dotdot', ['netguard/package.json', 'netguard/../evil.txt']], ['abs', ['/tmp/evil.txt']], ['link', ['netguard/package.json', 'link']], ['outside', ['other/file']]]) {
    const tf = path.join(evil, `${name}.tar.gz`);
    assert.strictEqual(spawnSync('python3', ['-c', py, tf, ...entries]).status, 0);
    const tar = fs.readFileSync(tf); const sha256 = crypto.createHash('sha256').update(tar).digest('hex');
    const sig = crypto.sign(null, upd.signedText('1.6.0', sha256), keyA.privateKey).toString('base64');
    const msg = await attempt(name, JSON.stringify({ format: 1, version: '1.6.0', notes: '', sha256, sig, data: tar.toString('base64') }));
    assert.match(msg, /Unzulässig|Links|beschädigt/, `${name}: ${msg}`);
  }
  assert.ok(!fs.existsSync(path.join(tmp, 'evil.txt')) && !fs.existsSync('/tmp/evil.txt'));
});

test('Update: unsignierte Pakete nur lokal und nur ohne hinterlegten Schlüssel; Weboberfläche verlangt Signatur', async () => {
  const stage = mkStage('1.7.0');
  const tf = path.join(tmp, 'plain.tar.gz'); spawnSync('tar', ['-czf', tf, '-C', stage, 'netguard']);
  let app = mkApp('1.0.0');
  withKey(pubPem(keyA));
  let r = await upd.performUpdate({ source: tf, cli: true, appDir: app, hooks: okHooks(), log: logq });
  assert.ok(!r.ok && /Schlüssel/.test(r.message), 'mit Schlüssel kein unsigniertes Archiv');
  r = await upd.performUpdate({ source: tf, cli: false, fromWeb: true, appDir: app, hooks: okHooks(), log: logq });
  assert.ok(!r.ok, 'Weboberfläche darf kein unsigniertes Archiv installieren');
  withKey('');
  r = await upd.performUpdate({ source: tf, cli: true, appDir: app, hooks: okHooks(), log: logq });
  assert.ok(r.ok, r.message);
  assert.strictEqual(upd.readVersion(app), '1.7.0');
  // signiertes Bundle ohne hinterlegten Schlüssel: per Web verboten, lokal erlaubt
  app = mkApp('1.0.0');
  const b = path.join(tmp, 'nokey.ngupdate'); fs.writeFileSync(b, mkBundle(mkStage('1.8.0'), '1.8.0', keyA.privateKey));
  r = await upd.performUpdate({ source: b, cli: true, fromWeb: true, appDir: app, hooks: okHooks(), log: logq });
  assert.ok(!r.ok && /Schlüssel/.test(r.message));
  r = await upd.performUpdate({ source: b, cli: true, appDir: app, hooks: okHooks(), log: logq });
  assert.ok(r.ok, r.message);
});

test('Update: Update-Prüfung über latest.json und Web-Schnittstelle', async () => {
  withKey(pubPem(keyA));
  const bundleText = mkBundle(mkStage('9.0.0'), '9.0.0', keyA.privateKey);
  const srv = http.createServer((req, res) => {
    if (req.url === '/latest.json') res.end(JSON.stringify({ version: '9.0.0', notes: 'Neu', url: 'netguard-9.0.0.ngupdate' }));
    else if (req.url === '/netguard-9.0.0.ngupdate') res.end(bundleText);
    else { res.statusCode = 404; res.end(); }
  });
  await new Promise((r) => srv.listen(25399, '127.0.0.1', r));
  try {
    const m = await upd.checkManifest('http://127.0.0.1:25399/latest.json', '1.1.0');
    assert.ok(m.newer && m.latest === '9.0.0' && m.bundle_url === 'http://127.0.0.1:25399/netguard-9.0.0.ngupdate');
    const same = await upd.checkManifest('http://127.0.0.1:25399/latest.json', '9.0.0');
    assert.strictEqual(same.newer, false);
    await assert.rejects(upd.checkManifest('http://127.0.0.1:25399/nix.json', '1.0.0'), /404/);

    const launched = [];
    const c = config.load(); c.update.url = 'http://127.0.0.1:25399/latest.json'; c.update.public_key = pubPem(keyA);
    const u = new upd.Updater({ cfg: () => c, log: { info() {}, warn() {}, error() {} }, eventLog: { add() {} }, dataDir: path.join(tmp, 'updata') });
    u.launch = (args) => launched.push(args);
    const info = await u.check();
    assert.ok(info.newer && u.available() === '9.0.0');
    const res = await u.installFromManifest();
    assert.strictEqual(res.version, '9.0.0');
    assert.deepStrictEqual(launched[0].slice(0, 1), ['update']);
    assert.ok(launched[0].includes('--from-web') && launched[0].includes('--cleanup'));
    u.busy = false;
    assert.throws(() => u.verifyText(mkBundle(mkStage('9.0.0'), '9.0.0', keyB.privateKey)), /Signatur/);
    assert.throws(() => u.verifyText(mkBundle(mkStage('0.0.1'), '0.0.1', keyA.privateKey)), /nicht neuer/);
    c.update.public_key = '';
    assert.throws(() => u.verifyText(bundleText), /kein Update-Schlüssel/);
  } finally { srv.close(); }
});

// ---------- Werbeblocker ----------
test('Werbeblocker: Listen-Migration, Browser-DoH-Schutz, HTTPS-Abfragen, Werbezähler', async () => {
  // Alte Konfiguration ohne neue Listen bekommt sie nachgetragen, eigene Einstellungen bleiben
  const old = { dns: { lists: [{ id: 'adguard', name: 'AdGuard', url: 'https://x.invalid/f.txt', enabled: false, category: 'ads' }] } };
  const f = path.join(tmp, 'old.json'); fs.writeFileSync(f, JSON.stringify(old));
  const c = config.load(f);
  assert.ok(c.dns.lists.some((l) => l.id === 'hagezi-pro' && l.enabled), 'HaGeZi Pro wird ergänzt');
  assert.strictEqual(c.dns.lists.find((l) => l.id === 'adguard').enabled, false, 'Nutzereinstellung bleibt');
  assert.strictEqual(c.dns.lists.filter((l) => l.id === 'adguard').length, 1);

  const SRV = 25383;
  const cfg = config.load();
  cfg.dns.bind = '127.0.0.1'; cfg.dns.port = SRV; cfg.dns.lists = []; cfg.dns.upstreams = ['127.0.0.1:1'];
  cfg.dns.custom_rules = [];
  cfg.dns.lists = [{ id: 'testads', name: 'Testliste', url: 'https://x.invalid/', enabled: true, category: 'ads' }];
  fs.mkdirSync(path.join(tmp, 'lists'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'lists', 'testads.txt'), '||ads.example.net^\n||tracker.example.net^\n');
  const dns = new dnsmod.DnsServer({ cfg: () => cfg, log: { info() {}, warn() {}, error() {}, debug() {} }, dataDir: tmp });
  dns.configure(); await dns.listen(); dns.running = true;
  const ask = (name, type) => new Promise((resolve, reject) => { const s = dgram.createSocket('udp4'); const t = setTimeout(() => { s.close(); reject(new Error('Timeout')); }, 3000); s.on('message', (m) => { clearTimeout(t); s.close(); resolve(m); }); s.send(dnsmod.buildQuery(name, type), SRV, '127.0.0.1'); });
  try {
    let r = await ask('use-application-dns.net', 1);
    assert.strictEqual(r.readUInt16BE(2) & 15, 3, 'Firefox-Canary muss NXDOMAIN liefern');
    r = await ask('mask.icloud.com', 28);
    assert.strictEqual(r.readUInt16BE(2) & 15, 3);
    // HTTPS-Record (Typ 65) einer Werbe-Domain: leere Antwort, keine Umgehung
    cfg.dns.disable_browser_doh = true;
    r = await ask('ads.example.net', 65);
    assert.strictEqual(r.readUInt16BE(2) & 15, 0);
    assert.strictEqual(r.readUInt16BE(6), 0, 'keine Antwort-Records');
    r = await ask('ads.example.net', 1);
    assert.strictEqual([...r.subarray(r.length - 4)].join('.'), '0.0.0.0');
    assert.ok(dns.getStats().ads >= 2, 'Werbezähler zählt Kategorie ads');
  } finally { await dns.stop(); }
});

// ---------- Latenz ----------
test('DNS-Latenz: langsamer Upstream wird per Hedging umgangen, schnellster zuerst, Serve-Stale', async () => {
  const mkUp = (port, delay) => { const u = dgram.createSocket('udp4'); u.hits = 0; u.on('message', (msg, r) => { u.hits++; setTimeout(() => { const q = dnsmod.parseQuery(msg); const ans = Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 2, 0, 4, 9, 9, 9, 9]); try { u.send(dnsmod.buildReply(msg, q, 0, [ans]), r.port, r.address); } catch (_) { /* schon geschlossen */ } }, delay); }); return new Promise((r) => u.bind(port, '127.0.0.1', () => r(u))); };
  const slow = await mkUp(25374, 700); const fast = await mkUp(25375, 5);
  const cfg = config.load();
  cfg.dns.bind = '127.0.0.1'; cfg.dns.port = 25373; cfg.dns.lists = []; cfg.dns.custom_rules = [];
  cfg.dns.upstreams = ['127.0.0.1:25374', '127.0.0.1:25375']; // langsamer steht vorn
  cfg.dns.cache.min_ttl = 1; cfg.dns.cache.max_ttl = 2;
  const dns = new dnsmod.DnsServer({ cfg: () => cfg, log: { info() {}, warn() {}, error() {}, debug() {} }, dataDir: tmp });
  dns.configure(); await dns.listen(); dns.running = true;
  const ask = (name) => new Promise((resolve, reject) => { const s = dgram.createSocket('udp4'); const t0 = Date.now(); const t = setTimeout(() => { s.close(); reject(new Error('Timeout')); }, 3000); s.on('message', (m) => { clearTimeout(t); s.close(); resolve({ m, ms: Date.now() - t0 }); }); s.send(dnsmod.buildQuery(name, 1), 25373, '127.0.0.1'); });
  try {
    const r1 = await ask('a.example');
    assert.ok(r1.ms < 450, `1. Abfrage trotz langsamem Upstream zu langsam: ${r1.ms} ms`);
    await ask('b.example'); await sleep(50);
    // Nach der Messung wird der schnelle Server direkt zuerst gefragt
    const before = slow.hits;
    const r2 = await ask('c.example');
    assert.ok(r2.ms < 100, `schnellster Upstream muss zuerst gefragt werden: ${r2.ms} ms`);
    assert.strictEqual(slow.hits, before, 'langsamer Server darf nicht mehr zuerst gefragt werden');
    // Serve-Stale: abgelaufener Eintrag wird sofort beantwortet
    await sleep(2300);
    const r3 = await ask('c.example');
    assert.ok(r3.ms < 30, `abgelaufener Eintrag muss sofort kommen: ${r3.ms} ms`);
    assert.strictEqual([...r3.m.subarray(r3.m.length - 4)].join('.'), '9.9.9.9');
  } finally { await dns.stop(); slow.close(); fast.close(); }
});

// ---------- Firewall-Regelwerk ----------
test('Regelwerk wird erzeugt, Level unterscheiden sich', () => {
  const mk = (level, mode) => {
    const cfg = config.load();
    cfg.security_level = level; cfg.mode = mode; cfg.admin_ips = ['192.168.1.5'];
    cfg.firewall.allow_in_lan.tcp = [22, 8088];
    const fw = new Firewall({ cfg: () => cfg, log: { info() {}, warn() {}, error() {}, debug() {} }, state: { data: { bans: [], ban_meta: {}, isolated: false }, save() {} }, events: {} });
    return fw.buildRuleset ? fw.buildRuleset() : null;
  };
  const a = mk('low', 'host'); const b = mk('paranoid', 'gateway');
  assert.ok(a && b, 'buildRuleset liefert Text');
  assert.ok(a.includes('table inet netguard'));
  assert.ok(a.includes('192.168.1.5'));
  assert.notStrictEqual(a, b);
  assert.ok(LEVELS.low.ban < LEVELS.paranoid.ban);
});

test('Netztrennung lässt das interne Netz herein (keep_lan_access)', () => {
  const mk = (keep) => { const cfg = config.load(); cfg.isolation.keep_lan_access = keep; cfg.admin_ips = ['203.0.113.7'];
    const fw = new Firewall({ cfg: () => cfg, log: { info() {}, warn() {}, error() {}, debug() {} }, state: { data: { bans: [], ban_meta: {}, isolated: false }, save() {} }, events: {} });
    return fw.buildIsolation(); };
  const on = mk(true); const off = mk(false);
  assert.ok(/ip saddr @lan4 accept/.test(on) && /192\.168\.0\.0\/16/.test(on));
  assert.ok(/ip daddr @lan4 ct state \{ established, related \} accept/.test(on), 'ausgehend nur Antworten ins LAN');
  assert.ok(/forward[\s\S]*counter drop/.test(on), 'Weiterleitung (Internet fürs LAN) bleibt gesperrt');
  assert.ok(!/@lan4/.test(off));
  assert.ok(/@admin4/.test(on));
});

test('Feed-Parser', () => {
  const items = parseFeed('# c\n1.2.3.4\n5.6.7.0/24 ; SBL1\n999.1.1.1\nfoo\n10.0.0.1\n');
  assert.ok(items.includes('1.2.3.4') && items.includes('5.6.7.0/24'));
  assert.ok(!items.includes('999.1.1.1') && !items.includes('foo'));
});

test('nft akzeptiert Regelwerk (falls nft vorhanden), lehnt Unsinn ab', () => {
  const nftc = (text) => { const f = path.join(tmp, 'x.nft'); fs.writeFileSync(f, text); return spawnSync('nft', ['-c', '-f', f], { encoding: 'utf8' }); };
  if (spawnSync('nft', ['--version']).status !== 0) return 'übersprungen (kein nft)';
  const good = nftc('table inet ngtest {\n  chain c {\n    type filter hook input priority 0; policy accept;\n  }\n}\n');
  if (good.status !== 0) return `übersprungen (nft nicht nutzbar: ${String(good.stderr).trim().slice(0, 70)})`;
  const bad = nftc('table inet ngtest {\n  chain c {\n    ip saddr bogus drop\n  }\n}\n');
  assert.notStrictEqual(bad.status, 0, 'nft -c muss kaputte Regeln ablehnen');
  const cfg = config.load();
  cfg.admin_ips = ['192.168.1.5'];
  const fw = new Firewall({ cfg: () => cfg, log: { info() {}, warn() {}, error() {}, debug() {} }, state: { data: { bans: [], ban_meta: {}, isolated: false }, save() {} }, events: {} });
  for (const level of ['low', 'normal', 'high', 'paranoid']) for (const mode of ['host', 'gateway']) {
    cfg.security_level = level; cfg.mode = mode;
    const r = nftc(fw.buildRuleset());
    assert.strictEqual(r.status, 0, `${level}/${mode}: ${r.stderr}`);
  }
  return null;
});

// ---------- Passwort ----------
test('Passwort-Hash', () => {
  const h = hashPassword('geheimes-passwort');
  assert.ok(verifyPassword('geheimes-passwort', h));
  assert.ok(!verifyPassword('falsch', h));
  assert.ok(!verifyPassword('x', ''));
});

// ---------- Bedrohungslogik, Benachrichtigung, Netztrennung, Web-API ----------
test('Angriff → Sperre; Kompromittierung → erst Nachricht, dann Netztrennung; Web-API', async () => {
  // Fake-Telegram
  const sent = [];
  const tg = http.createServer((req, res) => {
    const c = []; req.on('data', (d) => c.push(d));
    req.on('end', () => { sent.push({ url: req.url, body: JSON.parse(Buffer.concat(c).toString()), t: Date.now() }); res.end('{"ok":true}'); });
  });
  await new Promise((r) => tg.listen(25355, '127.0.0.1', r));

  const dir = path.join(tmp, 'app');
  const c0 = config.load();
  Object.assign(c0.paths, { data: path.join(dir, 'data'), log: path.join(dir, 'log'), run: path.join(dir, 'run') });
  c0.update.public_key = ''; c0.update.url = ''; c0.update.builtin_key = false;
  c0.web.port = 25356; c0.web.bind = '127.0.0.1'; c0.web.password_hash = hashPassword('testpasswort-123');
  c0.dns.enabled = false; c0.antivirus.enabled = false; c0.ids.enabled = false; c0.firewall.enabled = false;
  c0.notify.telegram = { enabled: true, bot_token: 'TOK', chat_id: '42', api_base: 'http://127.0.0.1:25355' };
  c0.notify.min_severity = 'warn';
  config.save(c0);

  const { App } = require('../src/index.js');
  assert.ok(App, 'App muss exportiert sein');
  const app = new App();
  app.init();
  // Fake-Firewall: protokolliert Aufrufe, schickt nichts an den Kernel
  const calls = [];
  const fake = {
    async ban(ip, s, why) { calls.push(['ban', ip, s, why]); return true; },
    async unban() { return true; },
    async isolate(reason) { calls.push(['isolate', reason, Date.now()]); app.state.data.isolated = true; app.state.data.isolated_at = Date.now(); app.state.data.isolated_reason = reason; return true; },
    async release() { calls.push(['release']); app.state.data.isolated = false; return true; },
    async status() { return { enabled: true, applied: true, bans: 0, threat_entries: 0, feeds: [] }; },
    async listBans() { return []; },
    async protectionOff() { app.state.data.protection_off = true; calls.push(['off']); return true; },
    async protectionOn() { app.state.data.protection_off = false; calls.push(['on']); return true; },
    noteBan() {}, refreshProtected() {}, isProtected() { return false; },
  };
  app.fw = fake; app.events.fw = fake;

  try {
    // 1) Angriff von außen → Sperre
    await app.events.report({ kind: 'attack', severity: 'warn', type: 'portscan', src: '203.0.113.9', ban: 3600, msg: 'Portscan' });
    assert.deepStrictEqual(calls[0].slice(0, 3), ['ban', '203.0.113.9', 3600]);
    assert.ok(app.eventLog.recent(10, 'info').some((e) => e.type === 'portscan'));
    await sleep(100);

    // 2) Kompromittierung unter Schwellwert → keine Trennung
    await app.events.report({ kind: 'compromise', subject: 'host', severity: 'high', type: 'c2-contact', score: 60, msg: 'C2' });
    assert.ok(!calls.some((x) => x[0] === 'isolate'));
    // 3) zweites Ereignis überschreitet 100 → Nachricht VOR Trennung
    await app.events.report({ kind: 'compromise', subject: 'host', severity: 'critical', type: 'reverse-shell', score: 60, msg: 'Reverse-Shell' });
    const iso = calls.find((x) => x[0] === 'isolate');
    assert.ok(iso, 'Netztrennung muss ausgelöst werden');
    const last = sent[sent.length - 1];
    assert.ok(last && /Reverse-Shell/.test(last.body.text), 'Telegram-Nachricht zum Auslöser');
    assert.ok(last.t <= iso[2], 'Nachricht muss vor der Trennung gesendet sein');
    assert.strictEqual(sent[0].url, '/botTOK/sendMessage');

    // 4) Web-API
    await app.web.start();
    const req = (method, p, body, cookie) => new Promise((resolve, reject) => {
      const r = http.request({ host: '127.0.0.1', port: 25356, path: p, method, headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) } }, (res) => {
        const c = []; res.on('data', (d) => c.push(d));
        res.on('end', () => { let j = null; try { j = JSON.parse(Buffer.concat(c).toString()); } catch (_) { /* html */ } resolve({ status: res.statusCode, json: j, headers: res.headers, raw: Buffer.concat(c).toString() }); });
      });
      r.on('error', reject); r.end(body ? JSON.stringify(body) : undefined);
    });
    assert.strictEqual((await req('GET', '/api/status')).status, 401);
    const bad = await req('POST', '/api/login', { password: 'falsch' });
    assert.strictEqual(bad.status, 401);
    const login = await req('POST', '/api/login', { password: 'testpasswort-123' });
    assert.strictEqual(login.status, 200);
    const cookie = String(login.headers['set-cookie']).split(';')[0];
    assert.ok(/HttpOnly/.test(String(login.headers['set-cookie'])));
    const st = await req('GET', '/api/status', null, cookie);
    assert.strictEqual(st.status, 200);
    assert.strictEqual(st.json.isolation.isolated, true);
    const cfgr = await req('GET', '/api/config', null, cookie);
    assert.strictEqual(cfgr.json.web.password_hash, '', 'Passwort-Hash darf nicht ausgeliefert werden');
    assert.strictEqual(st.json.isolation.keep_lan_access, true);
    // Fehlalarm: Freigabe mit Pause der Auto-Trennung
    const rel = await req('POST', '/api/release', { pause_minutes: 30 }, cookie);
    assert.strictEqual(rel.status, 200);
    assert.ok(calls.some((x) => x[0] === 'release'));
    assert.ok((await req('GET', '/api/status', null, cookie)).json.isolation.paused_until > Date.now());
    const nIso = calls.filter((x) => x[0] === 'isolate').length;
    await app.events.report({ kind: 'compromise', subject: 'host', severity: 'critical', type: 'reverse-shell', score: 100, msg: 'Wieder da' });
    assert.strictEqual(calls.filter((x) => x[0] === 'isolate').length, nIso, 'während der Pause darf nicht erneut getrennt werden');
    assert.ok(app.eventLog.recent(5, 'info').some((e) => e.msg === 'Wieder da'), 'Ereignis wird trotzdem protokolliert');
    await req('POST', '/api/isolation/pause', { minutes: 0 }, cookie);
    // Schutz komplett aus / an
    assert.strictEqual((await req('POST', '/api/protection/off', {}, cookie)).status, 200);
    assert.strictEqual((await req('GET', '/api/status', null, cookie)).json.protection_off, true);
    await app.events.report({ kind: 'compromise', subject: 'host', severity: 'critical', type: 'reverse-shell', score: 100, msg: 'Bei Schutz aus' });
    assert.strictEqual(calls.filter((x) => x[0] === 'isolate').length, nIso, 'bei ausgeschaltetem Schutz keine Trennung');
    assert.strictEqual((await req('POST', '/api/protection/on', {}, cookie)).status, 200);
    assert.strictEqual((await req('GET', '/api/status', null, cookie)).json.protection_off, false);
    // Gesundheitsprüfung nach Update gegen den echten Steuer-Socket
    const sock = path.join(app.config.paths.run, 'control.sock');
    assert.strictEqual(await upd.waitHealthy(app.version, sock, 3), true, 'laufender Dienst muss als gesund erkannt werden');
    assert.strictEqual(await upd.waitHealthy('99.0.0', sock, 1), false, 'falsche Version darf nicht als gesund gelten');
    assert.strictEqual(await upd.waitHealthy(app.version, path.join(tmp, 'gibtsnicht.sock'), 1), false);
    // Update-Schnittstelle: Status, Upload ohne Schlüssel wird abgelehnt
    const us = await req('GET', '/api/update', null, cookie);
    assert.strictEqual(us.status, 200);
    assert.strictEqual(us.json.has_key, false);
    const up = await req('POST', '/api/update/upload', { bundle: '{}' }, cookie);
    assert.strictEqual(up.status, 400);
    assert.match(up.json.error, /Schlüssel/);
    assert.strictEqual((await req('POST', '/api/update/rollback', {}, cookie)).status, 400, 'ohne Sicherung kein Rollback');
    const appjs = await req('GET', '/app.js');
    assert.ok(appjs.raw.includes('https://paypal.me/RolandFriedl'), 'Spenden-Link muss in der Oberfläche enthalten sein');
    const page = await req('GET', '/');
    assert.strictEqual(page.status, 200);
    assert.ok(/default-src 'self'/.test(String(page.headers['content-security-policy'])));
    // CSRF: Formular-Content-Type wird abgelehnt
    const csrf = await new Promise((resolve) => {
      const r = http.request({ host: '127.0.0.1', port: 25356, path: '/api/isolate', method: 'POST', headers: { 'Content-Type': 'text/plain', Cookie: cookie } }, (res) => { res.resume(); resolve(res.statusCode); });
      r.end('{}');
    });
    assert.strictEqual(csrf, 415);
  } finally {
    try { app.web.stop(); app.notifier.stop(); } catch (_) { /* egal */ }
    tg.close();
  }
});

(async () => {
  for (const [name, fn] of tests) {
    try {
      const r = await fn();
      if (typeof r === 'string' && r) { console.log(`  ~ ${name}: ${r}`); }
      else console.log(`  ✓ ${name}`);
      pass++;
    } catch (e) { failn++; console.log(`  ✗ ${name}\n      ${e.stack.split('\n').slice(0, 8).join('\n      ')}`); }
  }
  console.log(`\n${pass} bestanden, ${failn} fehlgeschlagen`);
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) { /* egal */ }
  process.exit(failn ? 1 : 0);
})();
