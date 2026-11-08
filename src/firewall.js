'use strict';
// Firewall auf Basis von nftables: Regelwerk-Generator, Sperrlisten (mit Ablauf),
// Bedrohungs-IP-Feeds, Kernel-Härtung und Netztrennung (Isolation).
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const {
  run, httpRequest, ensureDir, atomicWrite, CidrMatcher, isPrivateIp, localAddresses, defaultGateway,
  stripV4Mapped, toPorts, splitByFamily, validIface,
} = require('./util');
const { effectiveLan, parseAddress, lanRoutes } = require('./wireguard');

// Parameter je Sicherheitsstufe (auch vom IDS genutzt)
const LEVELS = {
  low: { ban: 600, syn: 100, synBurst: 200, icmp: 20, scan: 30, brute: 10, bfRate: 12, outbound: 'accept', badPorts: false },
  normal: { ban: 3600, syn: 50, synBurst: 100, icmp: 10, scan: 15, brute: 6, bfRate: 6, outbound: 'accept', badPorts: false },
  high: { ban: 86400, syn: 25, synBurst: 50, icmp: 2, scan: 8, brute: 4, bfRate: 4, outbound: 'accept', badPorts: true },
  paranoid: { ban: 604800, syn: 10, synBurst: 20, icmp: 0, scan: 4, brute: 3, bfRate: 3, outbound: 'restricted', badPorts: true },
};

const SYSCTL = {
  'net/ipv4/tcp_syncookies': '1',
  'net/ipv4/conf/all/rp_filter': '2',
  'net/ipv4/conf/default/rp_filter': '2',
  'net/ipv4/conf/all/accept_redirects': '0',
  'net/ipv4/conf/default/accept_redirects': '0',
  'net/ipv6/conf/all/accept_redirects': '0',
  'net/ipv6/conf/default/accept_redirects': '0',
  'net/ipv4/conf/all/accept_source_route': '0',
  'net/ipv6/conf/all/accept_source_route': '0',
  'net/ipv4/icmp_echo_ignore_broadcasts': '1',
  'net/ipv4/icmp_ignore_bogus_error_responses': '1',
};

function ipv4Network(a, prefix) {
  const o = a.split('.').map(Number);
  let n = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  n = (n & mask) >>> 0;
  return `${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

// Liest IP-/CIDR-Listen (eine Adresse je Zeile, Kommentare mit # oder ;)
function parseFeed(text) {
  const out = new Set();
  for (const raw of text.split('\n')) {
    const tok = raw.trim().split(/[\s;#,]/)[0];
    if (!tok) continue;
    const [a, p] = tok.split('/');
    if (!net.isIPv4(a)) continue;
    const prefix = p === undefined ? 32 : parseInt(p, 10);
    if (!(prefix >= 8 && prefix <= 32)) continue; // zu große Netze nie sperren
    if (isPrivateIp(a)) continue; // niemals eigene/private Adressen sperren
    out.add(prefix === 32 ? a : `${ipv4Network(a, prefix)}/${prefix}`);
  }
  return [...out];
}

const fmtSet = (a) => (a.length === 1 ? String(a[0]) : `{ ${a.join(', ')} }`);

class Firewall {
  constructor({ cfg, log, state, events }) {
    this.cfg = cfg;
    this.log = log;
    this.state = state;
    this.events = events;
    this.threat = [];
    this.threatMatcher = new CidrMatcher([]);
    this.feedStatus = {};
    this.protectedM = new CidrMatcher([]);
    this.applied = false;
    this.timers = [];
    this.releaseTimer = null;
  }

  paths() {
    const p = this.cfg().paths;
    return { run: p.run, data: p.data, feeds: path.join(p.data, 'feeds') };
  }

  level() { return LEVELS[this.cfg().security_level] || LEVELS.normal; }

  // ---------- Schutz vor Selbst-Aussperrung ----------
  refreshProtected() {
    const c = this.cfg();
    const list = ['127.0.0.0/8', '::1/128', ...localAddresses(), ...c.admin_ips, ...c.never_ban];
    const gw = defaultGateway();
    if (gw) list.push(gw.gw);
    for (const u of c.dns.upstreams) { const m = String(u).match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/); if (m) list.push(m[1]); }
    for (const ip of Object.values(c.dns.bootstrap || {})) list.push(ip);
    this.protectedM = new CidrMatcher(list);
  }

  isProtected(ip) { return this.protectedM.has(ip); }

  wanIface() {
    const w = this.cfg().wan_interface;
    if (w && w !== 'auto' && validIface(w)) return w;
    const gw = defaultGateway();
    return gw && validIface(gw.iface) ? gw.iface : null;
  }

  // ---------- Regelwerk ----------
  buildRuleset() {
    const cfg = this.cfg();
    const fw = cfg.firewall;
    const L = this.level();
    const gateway = cfg.mode === 'gateway';
    const lan = splitByFamily(effectiveLan(cfg)); // LAN + (optional) VPN-Netz: dürfen die Dienste dieses Rechners nutzen
    const lanPure = splitByFamily(cfg.lan_cidrs); // nur echtes LAN (für Weiterleitung im Gateway-Modus)
    const adm = splitByFamily(cfg.admin_ips);
    const hd = { anti_spoofing: true, block_private_wan: false, drop_fragments: false, conn_limit: 0, icmp: 'auto', wan_sources: [], ssh_lan_only: false, block_dot_doq: false, ...(fw.hardening || {}) };
    const wg = cfg.wireguard && cfg.wireguard.enabled && validIface(cfg.wireguard.interface) && parseAddress(cfg.wireguard.address) ? cfg.wireguard : null;
    const wgIf = wg ? wg.interface : null;
    const wgRouting = !!(wg && (wg.routing.access_lan || wg.routing.internet));
    const wgLan = wg ? lanRoutes(cfg) : [];
    const wanIf = this.wanIface();
    const now = Date.now();
    const ban4 = []; const ban6 = [];
    for (const b of this.state.data.bans || []) {
      const rem = Math.floor((b.until - now) / 1000);
      if (rem > 5 && !this.isProtected(b.ip)) (net.isIPv4(b.ip) ? ban4 : ban6).push(`${b.ip} timeout ${rem}s`);
    }
    const hasThreat = fw.threat_feeds.enabled && this.threat.length > 0;

    const lanTcp = toPorts([...fw.allow_in_lan.tcp, cfg.web.enabled ? cfg.web.port : 0]);
    const lanUdp = toPorts(fw.allow_in_lan.udp);
    const wanTcp = toPorts(fw.allow_in_wan.tcp).filter((p) => !(hd.ssh_lan_only && p === 22));
    const wanUdp = toPorts(fw.allow_in_wan.udp);
    const brute = toPorts(fw.bruteforce_ports).filter((p) => lanTcp.includes(p) || wanTcp.includes(p));
    const dnsPort = toPorts([cfg.dns.port])[0] || 53;
    const badPorts = toPorts(fw.block_out_tcp_ports);

    const sets = [];
    const mk = (name, type, flags, elems) => sets.push(
      `\tset ${name} {\n\t\ttype ${type}\n\t\tflags ${flags}\n${flags.includes('interval') ? '\t\tauto-merge\n' : ''}\t\tsize 131072\n${elems.length ? `\t\telements = { ${elems.join(', ')} }\n` : ''}\t}`,
    );
    mk('blacklist', 'ipv4_addr', 'timeout', ban4);
    mk('blacklist6', 'ipv6_addr', 'timeout', ban6);
    mk('lan4', 'ipv4_addr', 'interval', lan.v4);
    mk('lan6', 'ipv6_addr', 'interval', lan.v6);
    if (adm.v4.length) mk('admin4', 'ipv4_addr', 'interval', adm.v4);
    if (adm.v6.length) mk('admin6', 'ipv6_addr', 'interval', adm.v6);
    if (hasThreat) mk('threat4', 'ipv4_addr', 'interval', this.threat.slice(0, 60000));
    const wsrc = splitByFamily(hd.wan_sources || []);
    if (wsrc.v4.length) mk('wansrc4', 'ipv4_addr', 'interval', wsrc.v4);
    if (wsrc.v6.length) mk('wansrc6', 'ipv6_addr', 'interval', wsrc.v6);
    const connLimit = Math.max(0, parseInt(hd.conn_limit, 10) || 0);
    if (connLimit) {
      sets.push('\tset connlimit4 {\n\t\ttype ipv4_addr\n\t\tflags dynamic\n\t\tsize 65535\n\t}', '\tset connlimit6 {\n\t\ttype ipv6_addr\n\t\tflags dynamic\n\t\tsize 65535\n\t}');
    }

    const b4 = `add @blacklist { ip saddr timeout ${L.ban}s }`;
    const b6 = `add @blacklist6 { ip6 saddr timeout ${L.ban}s }`;

    // ----- input -----
    const inp = ['iifname "lo" accept'];
    if (adm.v4.length) inp.push('ip saddr @admin4 accept');
    if (adm.v6.length) inp.push('ip6 saddr @admin6 accept');
    // Schnellpfad: Sperrliste (Hash-Lookup), dann sofort bestehende Verbindungen durchlassen.
    // Alle teureren Prüfungen gelten nur noch für neue/ungültige Pakete (weniger Latenz pro Paket).
    inp.push('ip saddr @blacklist counter drop', 'ip6 saddr @blacklist6 counter drop', 'ct state { established, related } accept', 'ct state invalid counter drop');
    // Zusätzliche Härtung (nur für neue Pakete; bestehende Verbindungen sind schon durchgelassen)
    if (hd.anti_spoofing) {
      const own = [...localAddresses()].filter((a) => net.isIPv4(a) && !a.startsWith('127.')).slice(0, 32);
      inp.push('ip saddr { 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4 } counter drop', 'ip6 saddr { ::1, ff00::/8 } counter drop');
      if (own.length) inp.push(`ip saddr ${fmtSet(own)} counter drop`);
    }
    if (hd.block_private_wan && gateway && wanIf) inp.push(`iifname "${wanIf}" ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } counter drop`);
    if (hd.drop_fragments) inp.push('ip frag-off & 0x1fff != 0 counter drop', 'exthdr frag exists counter drop');
    if (connLimit) {
      inp.push(`ip saddr != @lan4 ct state new add @connlimit4 { ip saddr ct count over ${connLimit} } counter drop`, `ip6 saddr != @lan6 ct state new add @connlimit6 { ip6 saddr ct count over ${connLimit} } counter drop`);
    }
    if (hasThreat) inp.push('ip saddr @threat4 limit rate 5/second burst 10 packets log prefix "NG-THREAT-IN " level info', 'ip saddr @threat4 counter drop');
    inp.push(
      'tcp flags & (fin|syn) == fin|syn counter drop',
      'tcp flags & (syn|rst) == syn|rst counter drop',
      'tcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter drop',
      'tcp flags & (fin|psh|urg) == fin|psh|urg counter drop',
      `tcp flags & (fin|syn|rst|ack) == syn ct state new meter ng_syn4 { ip saddr timeout 30s limit rate over ${L.syn}/second burst ${L.synBurst} packets } ${b4} log prefix "NG-BAN-SYNFLOOD " drop`,
      `tcp flags & (fin|syn|rst|ack) == syn ct state new meter ng_syn6 { ip6 saddr timeout 30s limit rate over ${L.syn}/second burst ${L.synBurst} packets } ${b6} log prefix "NG-BAN-SYNFLOOD " drop`,
    );
    if (brute.length) {
      inp.push(
        `tcp dport ${fmtSet(brute)} ct state new meter ng_bf4 { ip saddr timeout 60s limit rate over ${L.bfRate}/minute burst ${L.bfRate} packets } ${b4} log prefix "NG-BAN-BRUTE " drop`,
        `tcp dport ${fmtSet(brute)} ct state new meter ng_bf6 { ip6 saddr timeout 60s limit rate over ${L.bfRate}/minute burst ${L.bfRate} packets } ${b6} log prefix "NG-BAN-BRUTE " drop`,
      );
    }
    if (hd.icmp === 'lan') {
      if (lan.v4.length) inp.push('ip saddr @lan4 icmp type echo-request limit rate 20/second burst 40 packets accept');
      if (lan.v6.length) inp.push('ip6 saddr @lan6 icmpv6 type echo-request limit rate 20/second burst 40 packets accept');
    } else if (hd.icmp !== 'off' && L.icmp > 0) {
      inp.push(
        `icmp type echo-request limit rate ${L.icmp}/second burst ${L.icmp * 2} packets accept`,
        `icmpv6 type echo-request limit rate ${L.icmp}/second burst ${L.icmp * 2} packets accept`,
      );
    }
    inp.push(
      'icmp type { destination-unreachable, time-exceeded, parameter-problem } accept',
      'icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept',
      'udp sport 67 udp dport 68 accept',
      'udp sport 547 udp dport 546 accept',
    );
    const lanTcpAll = toPorts([...(cfg.dns.enabled ? [dnsPort] : []), ...lanTcp]);
    const lanUdpAll = toPorts([...(cfg.dns.enabled ? [dnsPort] : []), ...lanUdp]);
    for (const [fam, key, setn] of [['ip', 'v4', '@lan4'], ['ip6', 'v6', '@lan6']]) {
      if (!lan[key].length) continue;
      if (lanTcpAll.length) inp.push(`${fam} saddr ${setn} tcp dport ${fmtSet(lanTcpAll)} accept`);
      if (lanUdpAll.length) inp.push(`${fam} saddr ${setn} udp dport ${fmtSet(lanUdpAll)} accept`);
    }
    if (wg && wg.allow_wan_port) inp.push(`udp dport ${wg.listen_port} accept`); // WireGuard: bewusst für alle offen (Schlüssel entscheiden)
    if (wg && wg.access_host === false && cfg.dns.enabled) inp.push(`iifname "${wgIf}" udp dport ${dnsPort} accept`, `iifname "${wgIf}" tcp dport ${dnsPort} accept`);
    const wanRule = (proto, ports) => {
      if (!ports.length) return;
      const set = fmtSet(ports);
      if (!(wsrc.v4.length || wsrc.v6.length)) { inp.push(`${proto} dport ${set} accept`); return; }
      if (wsrc.v4.length) inp.push(`ip saddr @wansrc4 ${proto} dport ${set} accept`);
      if (wsrc.v6.length) inp.push(`ip6 saddr @wansrc6 ${proto} dport ${set} accept`);
    };
    wanRule('tcp', wanTcp); wanRule('udp', wanUdp);
    if (fw.log_drops) inp.push('limit rate 10/second burst 30 packets log prefix "NG-DROP " level info');
    inp.push('counter drop');

    // ----- output -----
    const restricted = L.outbound === 'restricted';
    const out = ['oifname "lo" accept', 'ip daddr @blacklist counter drop', 'ip6 daddr @blacklist6 counter drop'];
    if (hasThreat) out.push('ip daddr @threat4 limit rate 5/second burst 10 packets log prefix "NG-C2OUT " level info', 'ip daddr @threat4 counter drop');
    if (L.badPorts && badPorts.length) {
      for (const [fam, setn] of [['ip', '@lan4'], ['ip6', '@lan6']]) {
        out.push(`${fam} daddr != ${setn} tcp dport ${fmtSet(badPorts)} limit rate 5/second burst 10 packets log prefix "NG-BADPORT " level info`);
        out.push(`${fam} daddr != ${setn} tcp dport ${fmtSet(badPorts)} counter drop`);
      }
    }
    if (hd.block_dot_doq) out.push('ip daddr != @lan4 tcp dport 853 counter drop', 'ip daddr != @lan4 udp dport 853 counter drop', 'ip6 daddr != @lan6 tcp dport 853 counter drop', 'ip6 daddr != @lan6 udp dport 853 counter drop');
    if (restricted) {
      const oa = fw.outbound_allow;
      out.push('ct state { established, related } accept', 'meta l4proto { icmp, ipv6-icmp } accept', 'udp sport 68 udp dport 67 accept', 'udp sport 546 udp dport 547 accept');
      if (lan.v4.length) out.push('ip daddr @lan4 accept');
      if (lan.v6.length) out.push('ip6 daddr @lan6 accept');
      const ot = toPorts(oa.tcp); const ou = toPorts(oa.udp);
      if (ot.length) out.push(`tcp dport ${fmtSet(ot)} accept`);
      if (ou.length) out.push(`udp dport ${fmtSet(ou)} accept`);
      out.push('limit rate 10/second burst 20 packets log prefix "NG-OUTDROP " level info', 'counter drop');
    }

    // ----- forward (Gateway-Modus und/oder WireGuard-Routing) -----
    let fwdChain = '';
    if (gateway || wgRouting) {
      const f = [
        'ip saddr @blacklist counter drop', 'ip daddr @blacklist counter drop',
        'ip6 saddr @blacklist6 counter drop', 'ip6 daddr @blacklist6 counter drop',
        'ct state { established, related } accept', // Schnellpfad für bestehende Verbindungen
        'ct state invalid counter drop',
      ];
      if (hd.anti_spoofing) f.push('ip saddr { 0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4 } counter drop');
      if (hd.block_private_wan && gateway && wanIf) f.push(`iifname "${wanIf}" ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } counter drop`);
      if (hd.drop_fragments) f.push('ip frag-off & 0x1fff != 0 counter drop');
      if (hasThreat) f.push('ip daddr @threat4 limit rate 5/second burst 10 packets log prefix "NG-C2OUT " level info', 'ip daddr @threat4 counter drop', 'ip saddr @threat4 counter drop');
      if (L.badPorts && badPorts.length) {
        f.push(`ip daddr != @lan4 tcp dport ${fmtSet(badPorts)} counter drop`, `ip6 daddr != @lan6 tcp dport ${fmtSet(badPorts)} counter drop`);
      }
      if ((gateway && fw.gateway.force_dns) || hd.block_dot_doq) f.push('ip daddr != @lan4 tcp dport 853 counter drop', 'ip6 daddr != @lan6 tcp dport 853 counter drop', 'ip daddr != @lan4 udp dport 853 counter drop');
      if (wgRouting) {
        f.push(wg.routing.peers_isolated !== false ? `iifname "${wgIf}" oifname "${wgIf}" counter drop` : `iifname "${wgIf}" oifname "${wgIf}" accept`);
        if (wg.routing.internet) f.push(`iifname "${wgIf}" accept`);
        else if (wg.routing.access_lan && wgLan.length) f.push(`iifname "${wgIf}" ip daddr { ${wgLan.join(', ')} } accept`);
        if (wg.routing.access_lan && wgLan.length) f.push(`oifname "${wgIf}" ip saddr { ${wgLan.join(', ')} } accept`);
      }
      if (gateway) {
        if (lanPure.v4.length) f.push(`ip saddr { ${lanPure.v4.join(', ')} } accept`);
        if (lanPure.v6.length) f.push(`ip6 saddr { ${lanPure.v6.join(', ')} } accept`);
      }
      f.push('meta l4proto { icmp, ipv6-icmp } limit rate 20/second accept', 'counter drop');
      fwdChain = `\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n${f.map((l) => `\t\t${l}`).join('\n')}\n\t}`;
    }

    let script = 'table inet netguard\ndelete table inet netguard\n';
    script += `table inet netguard {\n${sets.join('\n')}\n\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n${inp.map((l) => `\t\t${l}`).join('\n')}\n\t}\n`;
    script += `\n\tchain output {\n\t\ttype filter hook output priority filter; policy ${restricted ? 'drop' : 'accept'};\n${out.map((l) => `\t\t${l}`).join('\n')}\n\t}${fwdChain}\n}\n`;

    // ----- NAT / DNS-Zwang (Gateway) -----
    script += '\ntable ip netguard_nat\ndelete table ip netguard_nat\n';
    const wan = wanIf;
    const natLines = [];
    if (gateway && fw.gateway.force_dns && cfg.dns.enabled && lan.v4.length) {
      const l4 = `{ ${lan.v4.join(', ')} }`;
      natLines.push(`\tchain prerouting {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tip saddr ${l4} fib daddr type != local udp dport 53 redirect to :${dnsPort}\n\t\tip saddr ${l4} fib daddr type != local tcp dport 53 redirect to :${dnsPort}\n\t}`);
    }
    const post = [];
    if (gateway && fw.gateway.nat && wan) post.push(`oifname "${wan}" masquerade`);
    // VPN-Teilnehmer: ins LAN/Internet mit der Adresse dieses Rechners herausgehen (LAN-Geräte kennen den Rückweg ins VPN-Netz meist nicht)
    if (wgRouting) post.push(`ip saddr ${parseAddress(wg.address).cidr} oifname != "${wgIf}" masquerade`);
    if (post.length) natLines.push(`\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n${post.map((l) => `\t\t${l}`).join('\n')}\n\t}`);
    if (natLines.length) script += `table ip netguard_nat {\n${natLines.join('\n')}\n}\n`;
    return script;
  }

  buildIsolation() {
    const cfg = this.cfg();
    const adm = cfg.isolation.allow_admin ? splitByFamily(cfg.admin_ips) : { v4: [], v6: [] };
    let s = 'table inet netguard_iso\ndelete table inet netguard_iso\ntable inet netguard_iso {\n';
    if (adm.v4.length) s += `\tset admin4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { ${adm.v4.join(', ')} }\n\t}\n`;
    if (adm.v6.length) s += `\tset admin6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { ${adm.v6.join(', ')} }\n\t}\n`;
    // Internes Netz bleibt erreichbar: eingehend ist alles aus dem LAN zugelassen (die normale Firewall filtert danach
    // weiterhin nach erlaubten Ports), ausgehend nur Antworten und Nachbarschaftsprotokolle.
    const keep = cfg.isolation.keep_lan_access !== false;
    const lan = keep ? splitByFamily(effectiveLan(cfg)) : { v4: [], v6: [] };
    if (lan.v4.length) s += `\tset lan4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { ${lan.v4.join(', ')} }\n\t}\n`;
    if (lan.v6.length) s += `\tset lan6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t\tauto-merge\n\t\telements = { ${lan.v6.join(', ')} }\n\t}\n`;
    const rules = (dir) => {
      const o = [`${dir === 'in' ? 'iifname' : 'oifname'} "lo" accept`];
      const sd = dir === 'in' ? 'saddr' : 'daddr';
      if (adm.v4.length) o.push(`ip ${sd} @admin4 accept`);
      if (adm.v6.length) o.push(`ip6 ${sd} @admin6 accept`);
      if (dir === 'in') {
        if (lan.v4.length) o.push('ip saddr @lan4 accept');
        if (lan.v6.length) o.push('ip6 saddr @lan6 accept');
      } else {
        if (lan.v4.length) o.push('ip daddr @lan4 ct state { established, related } accept');
        if (lan.v6.length) o.push('ip6 daddr @lan6 ct state { established, related } accept');
      }
      if (keep) o.push('icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept');
      o.push('counter drop');
      return o.map((l) => `\t\t${l}`).join('\n');
    };
    s += `\tchain input {\n\t\ttype filter hook input priority -400; policy accept;\n${rules('in')}\n\t}\n`;
    // Ausgang nach dem Verbindungs-Tracking (Priorität -1), sonst sind "ct state"-Regeln für Antworten wirkungslos
    s += `\tchain output {\n\t\ttype filter hook output priority -1; policy accept;\n${rules('out')}\n\t}\n`;
    s += '\tchain forward {\n\t\ttype filter hook forward priority -400; policy accept;\n\t\tcounter drop\n\t}\n}\n';
    return s;
  }

  async load(script, name) {
    const { run: runDir } = this.paths();
    ensureDir(runDir, 0o755);
    const file = path.join(runDir, name);
    fs.writeFileSync(file, script, { mode: 0o600 });
    const chk = await run('nft', ['-c', '-f', file]);
    if (chk.code !== 0) return { ok: false, error: `nft-Prüfung fehlgeschlagen: ${chk.stderr.trim().split('\n').slice(0, 3).join(' | ')}` };
    const r = await run('nft', ['-f', file]);
    if (r.code !== 0) return { ok: false, error: `nft-Fehler: ${r.stderr.trim().split('\n').slice(0, 3).join(' | ')}` };
    return { ok: true };
  }

  hardenSysctl() {
    const c = this.cfg();
    if (!c.firewall.harden_sysctl) return;
    const vals = { ...SYSCTL };
    if (c.mode === 'host') { vals['net/ipv4/conf/all/send_redirects'] = '0'; vals['net/ipv4/conf/default/send_redirects'] = '0'; }
    for (const [k, v] of Object.entries(vals)) { try { fs.writeFileSync(`/proc/sys/${k}`, v); } catch (_) { /* Kernel/Container ohne Recht */ } }
  }

  async apply() {
    if (this.state.data.protection_off) { this.applied = false; this.log.warn('Schutz ist manuell ausgeschaltet: Firewall-Regeln werden nicht geladen (einschalten: Oberfläche oder sudo rf-netguard protection on)'); return false; }
    if (!this.cfg().firewall.enabled) { this.log.info('Firewall ist deaktiviert (firewall.enabled=false)'); return false; }
    this.refreshProtected();
    await this.syncBans();
    const r = await this.load(this.buildRuleset(), 'ruleset.nft');
    if (!r.ok) {
      this.applied = false;
      this.log.error(`Firewall-Regeln nicht angewendet: ${r.error}`);
      if (this.events) this.events.report({ kind: 'info', severity: 'high', type: 'firewall-error', msg: `Firewall-Regeln konnten nicht geladen werden: ${r.error}` });
      return false;
    }
    this.hardenSysctl();
    this.applied = true;
    this.log.info(`Firewall aktiv (Stufe: ${this.cfg().security_level}, Modus: ${this.cfg().mode}, ${this.threat.length} Bedrohungs-IPs)`);
    return true;
  }

  // ---------- Sperrliste ----------
  async ban(ip, seconds, reason = 'manuell', by = 'auto') {
    if (this.state.data.protection_off) return false;
    ip = stripV4Mapped(String(ip).trim());
    const fam = net.isIP(ip);
    if (!fam) throw new Error('Ungültige IP-Adresse');
    if (this.isProtected(ip)) { this.log.warn(`Sperre für geschützte Adresse ${ip} übersprungen`); return false; }
    const set = fam === 4 ? 'blacklist' : 'blacklist6';
    const secs = Math.max(1, Math.floor(seconds || this.level().ban));
    await run('nft', ['delete', 'element', 'inet', 'netguard', set, `{ ${ip} }`]);
    const r = await run('nft', ['add', 'element', 'inet', 'netguard', set, `{ ${ip} timeout ${secs}s }`]);
    if (r.code !== 0) { this.log.warn(`Sperre ${ip} fehlgeschlagen: ${r.stderr.trim()}`); return false; }
    this.state.data.ban_meta[ip] = { reason, by, ts: Date.now() };
    const bans = this.state.data.bans.filter((b) => b.ip !== ip);
    bans.push({ ip, until: Date.now() + secs * 1000 });
    this.state.data.bans = bans;
    this.state.save();
    this.log.info(`IP ${ip} gesperrt (${Math.round(secs / 60)} min): ${reason}`);
    return true;
  }

  async unban(ip) {
    ip = stripV4Mapped(String(ip).trim());
    const fam = net.isIP(ip);
    if (!fam) throw new Error('Ungültige IP-Adresse');
    const r = await run('nft', ['delete', 'element', 'inet', 'netguard', fam === 4 ? 'blacklist' : 'blacklist6', `{ ${ip} }`]);
    this.state.data.bans = this.state.data.bans.filter((b) => b.ip !== ip);
    delete this.state.data.ban_meta[ip];
    this.state.save();
    return r.code === 0;
  }

  noteBan(ip, reason, by = 'kernel') {
    if (!this.state.data.ban_meta[ip]) { this.state.data.ban_meta[ip] = { reason, by, ts: Date.now() }; this.state.save(); }
  }

  async listBans() {
    const out = [];
    for (const set of ['blacklist', 'blacklist6']) {
      const r = await run('nft', ['-j', 'list', 'set', 'inet', 'netguard', set]);
      if (r.code !== 0) continue;
      let j;
      try { j = JSON.parse(r.stdout); } catch (_) { continue; }
      for (const item of j.nftables || []) {
        const s = item.set;
        if (!s || !Array.isArray(s.elem)) continue;
        for (const e of s.elem) {
          const el = e && e.elem ? e.elem : e;
          const ip = typeof el === 'string' ? el : el && el.val;
          if (typeof ip !== 'string') continue;
          const exp = el && typeof el === 'object' ? (el.expires !== undefined ? el.expires : el.timeout || 0) : 0;
          out.push({ ip, expires: exp, ...(this.state.data.ban_meta[ip] || {}) });
        }
      }
    }
    return out;
  }

  // Übernimmt dynamische (vom Kernel gesetzte) Sperren in den persistenten Zustand
  async syncBans() {
    if (!this.applied && !this.cfg().firewall.enabled) return;
    const list = await this.listBans();
    if (!list.length && !this.applied) return; // Tabelle existiert (noch) nicht → alten Stand behalten
    const now = Date.now();
    this.state.data.bans = list.map((b) => ({ ip: b.ip, until: now + (b.expires || 0) * 1000 }));
    const keep = new Set(list.map((b) => b.ip));
    for (const k of Object.keys(this.state.data.ban_meta)) if (!keep.has(k)) delete this.state.data.ban_meta[k];
    this.state.save();
  }

  // ---------- Bedrohungs-IP-Feeds ----------
  feedFile(i) { return path.join(this.paths().feeds, `feed-${i}.txt`); }

  async loadFeedCache() {
    const fw = this.cfg().firewall;
    if (!fw.threat_feeds.enabled) { this.threat = []; this.threatMatcher = new CidrMatcher([]); return; }
    const all = new Set();
    fw.threat_feeds.urls.forEach((f, i) => {
      if (!f.enabled) return;
      try {
        const items = parseFeed(fs.readFileSync(this.feedFile(i), 'utf8'));
        items.forEach((x) => all.add(x));
        this.feedStatus[f.url] = { ...(this.feedStatus[f.url] || {}), entries: items.length };
      } catch (_) { /* noch nicht geladen */ }
    });
    this.threat = [...all];
    this.threatMatcher = new CidrMatcher(this.threat);
  }

  async updateFeeds(force = false) {
    const fw = this.cfg().firewall;
    if (!fw.threat_feeds.enabled) return { changed: false };
    ensureDir(this.paths().feeds);
    const maxAge = fw.threat_feeds.update_hours * 3600000;
    let changed = false;
    for (const [i, f] of fw.threat_feeds.urls.entries()) {
      if (!f.enabled) continue;
      let age = Infinity;
      try { age = Date.now() - fs.statSync(this.feedFile(i)).mtimeMs; } catch (_) { /* neu */ }
      if (!force && age < maxAge) continue;
      const st = this.feedStatus[f.url] || {};
      if (!force && st.tried && Date.now() - st.tried < 15 * 60000) continue;
      this.feedStatus[f.url] = { ...st, tried: Date.now() };
      try {
        const r = await httpRequest(f.url, { timeout: 30000, maxBytes: 20 * 1024 * 1024 });
        if (r.status !== 200) throw new Error(`HTTP ${r.status}`);
        const items = parseFeed(r.body.toString('utf8'));
        if (!items.length) throw new Error('Liste enthält keine gültigen Einträge');
        atomicWrite(this.feedFile(i), r.body, 0o644);
        this.feedStatus[f.url] = { entries: items.length, updated: Date.now(), error: null };
        changed = true;
      } catch (e) {
        this.feedStatus[f.url] = { ...(this.feedStatus[f.url] || {}), error: e.message };
        this.log.warn(`Bedrohungsliste "${f.name}": ${e.message}`);
      }
    }
    if (changed) {
      await this.loadFeedCache();
      await this.apply();
      this.state.data.last_feed_update = Date.now();
      this.state.save();
    }
    return { changed };
  }

  // ---------- Netztrennung ----------
  async isolate(reason) {
    if (this.state.data.isolated || this.state.data.protection_off) return false;
    const r = await this.load(this.buildIsolation(), 'isolation.nft');
    if (!r.ok) { this.log.error(`Netztrennung fehlgeschlagen: ${r.error}`); return false; }
    const d = this.state.data;
    d.isolated = true; d.isolated_at = Date.now(); d.isolated_reason = reason; d.downed_ifaces = [];
    if (this.cfg().isolation.hard_disconnect) d.downed_ifaces = await this.interfacesDown();
    this.state.flush();
    this.scheduleAutoRelease();
    return true;
  }

  async interfacesDown() {
    const r = await run('ip', ['-o', 'link', 'show', 'up']);
    const cfg = this.cfg();
    const keepLan = cfg.isolation.keep_lan_access !== false;
    const lanM = new CidrMatcher(cfg.lan_cidrs);
    const lanIfaces = new Set();
    if (keepLan) {
      for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
        if ((addrs || []).some((a) => !a.internal && lanM.has(a.address))) lanIfaces.add(name);
      }
    }
    const names = [];
    for (const line of r.stdout.split('\n')) {
      const m = line.match(/^\d+:\s+([^:@\s]+)/);
      if (m && m[1] !== 'lo' && validIface(m[1]) && !lanIfaces.has(m[1])) names.push(m[1]);
    }
    for (const n of names) await run('ip', ['link', 'set', 'dev', n, 'down']);
    return names;
  }

  async release() {
    const d = this.state.data;
    if (!d.isolated) return false;
    await run('nft', ['delete', 'table', 'inet', 'netguard_iso']);
    for (const n of d.downed_ifaces || []) if (validIface(n)) await run('ip', ['link', 'set', 'dev', n, 'up']);
    d.isolated = false; d.isolated_at = 0; d.isolated_reason = ''; d.downed_ifaces = [];
    this.state.flush();
    if (this.releaseTimer) { clearTimeout(this.releaseTimer); this.releaseTimer = null; }
    return true;
  }

  // Fehlalarm / Wartung: Trennung aufheben und alle RF-NetGuard-Regeln entfernen, bis wieder eingeschaltet wird
  async protectionOff() {
    await this.release();
    for (const [fam, t] of [['inet', 'netguard'], ['inet', 'netguard_iso'], ['ip', 'netguard_nat']]) await run('nft', ['delete', 'table', fam, t]);
    this.applied = false;
    this.state.data.protection_off = true;
    this.state.flush();
    return true;
  }

  async protectionOn() {
    this.state.data.protection_off = false;
    this.state.flush();
    return this.apply();
  }

  scheduleAutoRelease() {
    const m = this.cfg().isolation.auto_release_minutes;
    if (this.releaseTimer) { clearTimeout(this.releaseTimer); this.releaseTimer = null; }
    if (!m || !this.state.data.isolated) return;
    const left = this.state.data.isolated_at + m * 60000 - Date.now();
    this.releaseTimer = setTimeout(() => { if (this.events) this.events.release('automatisch nach Ablauf der Wartezeit'); else this.release(); }, Math.max(1000, left));
    if (this.releaseTimer.unref) this.releaseTimer.unref();
  }

  // ---------- Lebenszyklus ----------
  async start() {
    ensureDir(this.paths().run, 0o755);
    this.refreshProtected();
    await this.loadFeedCache();
    await this.apply();
    if (this.state.data.isolated && !this.state.data.protection_off) {
      const r = await this.load(this.buildIsolation(), 'isolation.nft');
      if (r.ok) {
        this.log.warn(`Netztrennung aus früherer Sitzung wieder aktiv (${this.state.data.isolated_reason})`);
        if (this.state.data.downed_ifaces.length) await this.interfacesDown();
        this.scheduleAutoRelease();
      }
    }
    this.timers.push(setInterval(() => this.syncBans().catch(() => {}), 60000));
    this.timers.push(setInterval(() => this.updateFeeds(false).catch(() => {}), 30 * 60000));
    this.timers.forEach((t) => t.unref && t.unref());
    this.updateFeeds(false).catch((e) => this.log.warn(`Feed-Update: ${e.message}`));
  }

  stop() { this.timers.forEach(clearInterval); this.timers = []; if (this.releaseTimer) clearTimeout(this.releaseTimer); }

  async status() {
    const bans = await this.listBans();
    return {
      enabled: this.cfg().firewall.enabled, applied: this.applied, level: this.cfg().security_level, mode: this.cfg().mode,
      bans: bans.length, threat_entries: this.threat.length,
      isolated: !!this.state.data.isolated, isolated_at: this.state.data.isolated_at, isolated_reason: this.state.data.isolated_reason, protection_off: !!this.state.data.protection_off,
      feeds: this.cfg().firewall.threat_feeds.urls.map((f) => ({ name: f.name, url: f.url, enabled: f.enabled, ...(this.feedStatus[f.url] || {}) })),
    };
  }
}

// Notfall: alle RF-NetGuard-Tabellen entfernen (auch ohne laufenden Daemon)
async function flushAll() {
  const res = [];
  for (const [fam, t] of [['inet', 'netguard'], ['inet', 'netguard_iso'], ['ip', 'netguard_nat']]) {
    const r = await run('nft', ['delete', 'table', fam, t]);
    res.push({ table: `${fam} ${t}`, removed: r.code === 0 });
  }
  return res;
}

module.exports = { Firewall, LEVELS, parseFeed, flushAll };
