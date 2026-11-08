#!/usr/bin/env node
'use strict';
// Release-Werkzeug (läuft auf deinem Entwicklungsrechner, NICHT auf dem Firewall-Server):
//   node tools/release.js keygen [ordner]                Schlüsselpaar erzeugen (einmalig)
//   node tools/release.js build --key release-key.pem [--notes "Text"] [--out dist]
//   node tools/release.js verify <datei.ngupdate> <release-key.pub>
// Der private Schlüssel (release-key.pem) bleibt geheim und gehört NICHT auf den Server.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const ITEMS = ['src', 'ui', 'deploy', 'test', 'tools', 'docs', 'package.json', 'README.md', 'LICENSE', 'CHANGELOG.md', 'SECURITY.md', 'config.example.json'];
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const text = (v, sha) => Buffer.from(`netguard-update\n${v}\n${sha}`);

function keygen(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const priv = path.join(dir, 'release-key.pem'); const pub = path.join(dir, 'release-key.pub');
  if (fs.existsSync(priv)) { console.error(`${priv} existiert bereits – wird nicht überschrieben.`); process.exit(1); }
  fs.writeFileSync(priv, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(pub, publicKey.export({ type: 'spki', format: 'pem' }));
  console.log(`Privater Schlüssel (GEHEIM, sicher aufbewahren): ${priv}\nÖffentlicher Schlüssel: ${pub}\n\nAuf dem Firewall-Server hinterlegen:\n  sudo rf-netguard update-key release-key.pub`);
}

function build() {
  const keyFile = arg('--key');
  if (!keyFile) { console.error('Angabe fehlt: --key release-key.pem'); process.exit(1); }
  // PEM tolerant einlesen: Beim Einfügen als GitHub-Secret gehen Zeilenumbrüche oft verloren – Inhalt neu umbrechen
  const raw = fs.readFileSync(keyFile, 'utf8');
  const m = /-----BEGIN ([A-Z ]+)-----([\s\S]*?)-----END \1-----/.exec(raw.replace(/\\n/g, '\n'));
  const pem = m ? `-----BEGIN ${m[1]}-----\n${m[2].replace(/[^A-Za-z0-9+/=]/g, '').match(/.{1,64}/g).join('\n')}\n-----END ${m[1]}-----\n` : raw;
  let priv;
  try { priv = crypto.createPrivateKey(pem); } catch (e) { console.error(`Privater Schlüssel nicht lesbar (${e.message.split('\n')[0]}). Erwartet wird der komplette Inhalt von release-key.pem (-----BEGIN PRIVATE KEY----- … -----END PRIVATE KEY-----).`); process.exit(1); }
  if (priv.asymmetricKeyType !== 'ed25519') { console.error('Der Schlüssel muss ein Ed25519-Schlüssel sein.'); process.exit(1); }
  const pubOk = require('./../src/update-key');
  if (crypto.createPublicKey(priv).export({ type: 'spki', format: 'pem' }).trim() !== pubOk.trim()) console.warn('WARNUNG: Der Schlüssel passt nicht zum eingebauten öffentlichen Schlüssel (src/update-key.js) – Installationen würden das Update ablehnen.');
  const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version;
  const out = path.resolve(arg('--out', path.join(ROOT, 'dist')));
  fs.mkdirSync(out, { recursive: true });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ngrel-'));
  try {
    for (const it of ITEMS) { const s = path.join(ROOT, it); if (fs.existsSync(s)) fs.cpSync(s, path.join(tmp, 'netguard', it), { recursive: true }); }
    const tarFile = path.join(tmp, 'u.tar.gz');
    execFileSync('tar', ['-czf', tarFile, '--owner=0', '--group=0', '--numeric-owner', '--sort=name', '-C', tmp, 'netguard']);
    const tar = fs.readFileSync(tarFile);
    const sha256 = crypto.createHash('sha256').update(tar).digest('hex');
    const sig = crypto.sign(null, text(version, sha256), priv).toString('base64');
    const bundle = { format: 1, version, notes: arg('--notes', ''), sha256, sig, data: tar.toString('base64') };
    const name = `rf-netguard-${version}.ngupdate`;
    fs.writeFileSync(path.join(out, name), JSON.stringify(bundle));
    fs.writeFileSync(path.join(out, 'latest.json'), JSON.stringify({ version, notes: bundle.notes, url: name }, null, 2) + '\n');
    console.log(`Fertig: ${path.join(out, name)}\n        ${path.join(out, 'latest.json')}\n\nBeide Dateien in denselben Ordner auf einen Webserver legen (z. B. Nextcloud-Freigabe, GitHub-Release, eigener Server).\nAuf dem Firewall-Server als Update-Adresse die URL der latest.json eintragen (Einstellungen → Updates).\nOder direkt: sudo rf-netguard update ${name}`);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}

function verify(file, pubFile) {
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  const tar = Buffer.from(j.data, 'base64');
  const sha = crypto.createHash('sha256').update(tar).digest('hex');
  const ok = sha === j.sha256 && crypto.verify(null, text(j.version, j.sha256), crypto.createPublicKey(fs.readFileSync(pubFile)), Buffer.from(j.sig, 'base64'));
  console.log(ok ? `Signatur gültig (Version ${j.version})` : 'SIGNATUR UNGÜLTIG');
  process.exit(ok ? 0 : 1);
}

const cmd = process.argv[2];
if (cmd === 'keygen') keygen(process.argv[3] || '.');
else if (cmd === 'build') build();
else if (cmd === 'verify') verify(process.argv[3], process.argv[4]);
else console.log('Verwendung:\n  node tools/release.js keygen [ordner]\n  node tools/release.js build --key release-key.pem [--notes "Text"] [--out dist]\n  node tools/release.js verify <datei.ngupdate> <release-key.pub>');
