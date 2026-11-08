'use strict';
// RF-NetGuard-Oberfläche. Alle dynamischen Inhalte werden per textContent eingefügt (kein innerHTML),
// weil z.B. DNS-Namen von außen kontrolliert sein können.
(function () {
  const root = document.getElementById('app');
  const SEV_LABEL = { info: 'Info', warn: 'Warnung', high: 'Hoch', critical: 'Kritisch' };
  const LEVELS = [
    ['low', 'Niedrig – lockere Grenzen, kurze Sperren (10 min)'],
    ['normal', 'Normal – empfohlen (Sperren 1 h)'],
    ['high', 'Hoch – strenge Grenzen, Sperren 24 h, riskante Ausgangsports blockiert'],
    ['paranoid', 'Paranoid – wie Hoch, Sperren 7 d, ausgehend nur erlaubte Ports'],
  ];
  let timer = null;
  let tab = 'overview';
  let status = null;

  // ---------- Hilfsfunktionen ----------
  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (v === true) e.setAttribute(k, '');
      else e.setAttribute(k, v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return e;
  }
  const svgEl = (tag, attrs) => {
    const e = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    return e;
  };
  const fmtTime = (t) => (t ? new Date(t).toLocaleString('de-AT') : '–');
  const fmtNum = (n) => Number(n || 0).toLocaleString('de-AT');
  const fmtDur = (s) => (s < 90 ? `${Math.round(s)} s` : s < 5400 ? `${Math.round(s / 60)} min` : s < 172800 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} d`);

  function toast(msg, bad) {
    const t = h('div', { class: `toast${bad ? ' bad' : ''}` }, msg);
    document.getElementById('toasts').append(t);
    setTimeout(() => t.remove(), bad ? 7000 : 3500);
  }

  async function api(method, path, body) {
    const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin' });
    let j = {};
    try { j = await r.json(); } catch (_) { /* leer */ }
    if (r.status === 401 && path !== '/api/login') { showLogin(); throw new Error('Nicht angemeldet'); }
    if (!r.ok) throw new Error(j.error || r.statusText);
    return j;
  }
  const act = (fn, okMsg) => async (ev) => {
    const b = ev && ev.currentTarget;
    if (b) b.disabled = true;
    try { const r = await fn(); if (okMsg) toast(okMsg); return r; } catch (e) { toast(e.message, true); } finally { if (b) b.disabled = false; }
  };

  const get = (o, p) => p.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
  const set = (o, p, v) => { const ks = p.split('.'); const last = ks.pop(); ks.reduce((a, k) => a[k], o)[last] = v; };
  const splitList = (s, sep) => s.split(sep).map((x) => x.trim()).filter(Boolean);

  // Formularelement, das direkt in ein Konfigurationsobjekt schreibt
  function field(cfg, path, kind, opts = {}) {
    const v = get(cfg, path);
    let el;
    if (kind === 'bool') { el = h('input', { type: 'checkbox' }); el.checked = !!v; el.addEventListener('change', () => set(cfg, path, el.checked)); }
    else if (kind === 'num') { el = h('input', { type: 'number', min: opts.min, max: opts.max, step: opts.step || 1 }); el.value = v; el.addEventListener('input', () => set(cfg, path, Number(el.value))); }
    else if (kind === 'text' || kind === 'password') { el = h('input', { type: kind, autocomplete: 'off' }); el.value = v == null ? '' : v; el.addEventListener('input', () => set(cfg, path, el.value)); }
    else if (kind === 'select') { el = h('select', {}, opts.options.map(([val, label]) => h('option', { value: val }, label))); el.value = v; el.addEventListener('change', () => set(cfg, path, el.value)); }
    else if (kind === 'lines') { el = h('textarea', { rows: opts.rows || 4 }); el.value = (v || []).join('\n'); el.addEventListener('input', () => set(cfg, path, splitList(el.value, '\n'))); }
    else if (kind === 'ports') { el = h('input', { type: 'text' }); el.value = (v || []).join(', '); el.addEventListener('input', () => set(cfg, path, splitList(el.value, /[,\s]+/).map(Number).filter((n) => n > 0 && n < 65536))); }
    else if (kind === 'list') { el = h('input', { type: 'text' }); el.value = (v || []).join(', '); el.addEventListener('input', () => set(cfg, path, splitList(el.value, /[,\s]+/))); }
    else if (kind === 'kv') {
      el = h('textarea', { rows: 3, placeholder: 'nas.home=192.168.1.10\n*.lab.home=192.168.1.20' });
      el.value = Object.entries(v || {}).map(([a, b]) => `${a}=${b}`).join('\n');
      el.addEventListener('input', () => { const o = {}; for (const l of splitList(el.value, '\n')) { const i = l.indexOf('='); if (i > 0) o[l.slice(0, i).trim()] = l.slice(i + 1).trim(); } set(cfg, path, o); });
    }
    return el;
  }
  const row = (label, el, hint) => h('label', { class: 'row' }, h('span', {}, label), el, hint ? h('small', {}, hint) : null);
  const chk = (label, el, hint) => h('label', { class: 'chk' }, el, h('span', {}, label), hint ? h('small', { class: 'muted' }, hint) : null);

  async function saveCfg(cfg) {
    await api('PUT', '/api/config', cfg);
    toast('Gespeichert und angewendet');
  }

  const sevBadge = (s) => h('span', { class: `badge sev-${s}` }, SEV_LABEL[s] || s);

  function barChart(hours) {
    const W = 480; const H = 90;
    const svg = svgEl('svg', { class: 'bars', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none' });
    const max = Math.max(1, ...hours.map((x) => x.total));
    const bw = W / hours.length;
    hours.forEach((x, i) => {
      const th = (x.total / max) * (H - 4);
      const bh = (x.blocked / max) * (H - 4);
      svg.append(svgEl('rect', { class: 'bar', x: i * bw + 1, y: H - th, width: bw - 2, height: th }));
      if (bh > 0) svg.append(svgEl('rect', { class: 'bar bl', x: i * bw + 1, y: H - bh, width: bw - 2, height: bh }));
    });
    return svg;
  }

  function lineChart(samples) {
    const W = 480; const H = 90;
    const svg = svgEl('svg', { class: 'bars', viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none' });
    if (samples.length < 2) return svg;
    const max = Math.max(1, ...samples.map((s) => Math.max(s.rx, s.tx)));
    const pts = (k) => samples.map((s, i) => `${(i / (samples.length - 1)) * W},${H - 3 - (s[k] / max) * (H - 8)}`).join(' ');
    svg.append(svgEl('polyline', { class: 'line-rx', points: pts('rx') }), svgEl('polyline', { class: 'line-tx', points: pts('tx') }));
    return svg;
  }

  // ---------- Anmeldung ----------
  function showLogin(msg) {
    clearInterval(timer);
    const pw = h('input', { type: 'password', placeholder: 'Passwort', autocomplete: 'current-password' });
    const err = h('div', { class: 'err' }, msg || '');
    const go = async () => {
      try { await api('POST', '/api/login', { password: pw.value }); boot(); } catch (e) { err.textContent = e.message; }
    };
    pw.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    root.replaceChildren(h('div', { class: 'card login stack' }, h('div', { class: 'logo' }, h('img', { src: '/logo.svg', alt: '', class: 'logo-img' }), 'RF-Net', h('span', {}, 'Guard')), h('p', { class: 'muted' }, 'Bitte anmelden'), pw, h('button', { onclick: go }, 'Anmelden'), err));
    pw.focus();
  }

  // ---------- Rahmen ----------
  const TABS = [['overview', 'Übersicht'], ['dns', 'DNS-Filter'], ['firewall', 'Firewall'], ['vpn', 'VPN'], ['events', 'Ereignisse'], ['av', 'Virenschutz'], ['settings', 'Einstellungen']];

  async function boot() {
    let s;
    try { s = await api('GET', '/api/session'); } catch (_) { return; }
    if (!s.authenticated) { showLogin(s.password_set ? '' : 'Es ist noch kein Passwort gesetzt. Auf dem Rechner ausführen: sudo rf-netguard passwd'); return; }
    show(tab);
  }

  async function show(t) {
    tab = t;
    clearInterval(timer);
    try { status = await api('GET', '/api/status'); } catch (e) { toast(e.message, true); return; }
    const main = h('main', {});
    root.replaceChildren(
      h('header', { class: 'top' },
        h('div', { class: 'logo' }, h('img', { src: '/logo.svg', alt: '', class: 'logo-img' }), 'RF-Net', h('span', {}, 'Guard')),
        h('span', { class: 'host' }, status.hostname),
        h('span', { class: `pill ${status.isolation.isolated || status.protection_off ? 'bad' : 'ok'}` }, status.protection_off ? 'Schutz AUS' : status.isolation.isolated ? 'Vom Netz getrennt' : status.isolation.paused_until ? 'Geschützt (Auto-Trennung pausiert)' : 'Geschützt'),
        h('div', { class: 'spacer' }),
        h('span', { class: 'muted' }, `v${status.version} · Laufzeit ${fmtDur(status.uptime)}`),
        h('button', { class: 'sec small', onclick: act(async () => { await api('POST', '/api/logout'); showLogin(); }) }, 'Abmelden')),
      h('nav', { class: 'tabs' }, TABS.map(([id, label]) => h('button', { class: id === tab ? 'active' : '', onclick: () => show(id) }, label))),
      main);
    if (status.update_available) {
      main.append(h('div', { class: 'banner info' },
        h('div', {}, h('strong', {}, `Neue Version ${status.update_available} verfügbar`), h('div', { class: 'muted' }, `Installiert: ${status.version}`)),
        h('div', { class: 'spacer' }),
        h('button', { onclick: () => show('settings') }, 'Zu den Updates')));
    }
    if (status.protection_off) {
      main.append(h('div', { class: 'banner' },
        h('div', {}, h('strong', {}, 'Firewall und automatische Netztrennung sind ausgeschaltet'), h('div', {}, 'Dieser Rechner ist derzeit NICHT durch RF-NetGuard-Regeln geschützt. Erkennung und Protokoll laufen weiter.')),
        h('div', { class: 'spacer' }),
        h('button', { onclick: act(async () => { await api('POST', '/api/protection/on'); show(tab); }, 'Schutz eingeschaltet') }, 'Schutz wieder einschalten')));
    }
    if (status.isolation.isolated) {
      const pause = h('select', {}, [['0', 'Auto-Trennung sofort wieder aktiv'], ['30', 'Auto-Trennung 30 min pausieren'], ['60', 'Auto-Trennung 1 h pausieren'], ['240', 'Auto-Trennung 4 h pausieren'], ['1440', 'Auto-Trennung 24 h pausieren']].map(([v, l]) => h('option', { value: v }, l)));
      pause.value = '60';
      main.append(h('div', { class: 'banner' },
        h('div', {}, h('strong', {}, 'Dieser Rechner wurde vom Netz getrennt'), h('div', {}, `${fmtTime(status.isolation.since)} – ${status.isolation.reason}`),
          h('div', { class: 'muted' }, status.isolation.keep_lan_access ? 'Das interne Netz hat weiterhin Zugriff auf diesen Rechner (auch auf diese Oberfläche).' : 'Hinweis: Zugriff aus dem internen Netz ist deaktiviert.')),
        h('div', { class: 'spacer' }),
        pause,
        h('button', { onclick: act(async () => { await api('POST', '/api/release', { pause_minutes: Number(pause.value) }); show(tab); }, 'Freigegeben') }, 'Fehlalarm – Netz freigeben'),
        h('button', { class: 'danger', onclick: act(async () => { if (confirm('Firewall und automatische Netztrennung komplett ausschalten? Der Rechner ist dann ungeschützt, bis du wieder einschaltest.')) { await api('POST', '/api/protection/off'); show(tab); } }) }, 'Schutz ganz ausschalten')));
    }
    const view = { overview: viewOverview, dns: viewDns, firewall: viewFirewall, vpn: viewVpn, events: viewEvents, av: viewAv, settings: viewSettings }[tab];
    const body = h('div', {});
    main.append(body);
    try { await view(body); } catch (e) { if (e.message !== 'Nicht angemeldet') body.append(h('p', { class: 'err' }, e.message)); }
  }

  // Nach Update/Rollback: warten, bis der Dienst wieder antwortet, dann Seite neu laden
  function waitForRestart() {
    clearInterval(timer);
    let n = 0;
    const iv = setInterval(async () => {
      n++;
      try { const r = await fetch('/api/session', { credentials: 'same-origin' }); if (r.ok && n > 4) { clearInterval(iv); location.reload(); } } catch (_) { /* Dienst startet neu */ }
      if (n > 120) { clearInterval(iv); toast('Keine Antwort – bitte Seite neu laden und Update-Ergebnis prüfen', true); }
    }, 2000);
  }

  const auto = (fn, sec = 5) => { clearInterval(timer); timer = setInterval(() => fn().catch(() => {}), sec * 1000); };

  // ---------- Übersicht ----------
  async function viewOverview(body) {
    const draw = async () => {
      const s = await api('GET', '/api/status');
      const ev = await api('GET', '/api/events?limit=12&min=warn');
      const tr = await api('GET', '/api/traffic');
      const grid = h('div', { class: 'grid' },
        h('div', { class: 'card' }, h('h3', {}, 'Netzstatus'),
          h('div', { class: 'big' }, s.isolation.isolated ? 'Getrennt' : 'Verbunden'),
          h('dl', { class: 'kv' }, h('dt', {}, 'Bedrohungswert'), h('dd', {}, `${s.isolation.score} / ${s.isolation.threshold}`), h('dt', {}, 'Auto-Trennung'), h('dd', {}, s.isolation.enabled ? 'aktiv' : 'aus'), h('dt', {}, 'Benachrichtigung'), h('dd', {}, s.notify_channels.length ? s.notify_channels.join(', ') : 'kein Kanal')),
          h('p', {}, s.isolation.isolated
            ? h('button', { onclick: act(async () => { if (confirm('Netztrennung aufheben und die automatische Trennung 1 h pausieren?')) { await api('POST', '/api/release', { pause_minutes: 60 }); show(tab); } }) }, 'Freigeben (Fehlalarm)')
            : h('button', { class: 'danger', onclick: act(async () => { if (confirm('Rechner jetzt vom Netz trennen? Nur lokal/Admin-Adressen bleiben erreichbar.')) { await api('POST', '/api/isolate', { reason: 'manuell über Oberfläche' }); show(tab); } }) }, 'Jetzt vom Netz trennen'))),
        h('div', { class: 'card' }, h('h3', {}, 'Firewall'),
          h('div', { class: 'big' }, s.firewall.applied ? 'Aktiv' : 'Inaktiv'),
          h('dl', { class: 'kv' }, h('dt', {}, 'Stufe'), h('dd', {}, s.level), h('dt', {}, 'Modus'), h('dd', {}, s.mode), h('dt', {}, 'Gesperrte IPs'), h('dd', {}, fmtNum(s.firewall.bans)), h('dt', {}, 'Bedrohungs-IPs'), h('dd', {}, fmtNum(s.firewall.threat_entries)))),
        h('div', { class: 'card' }, h('h3', {}, 'DNS-Filter (24 h)'),
          h('div', { class: 'big' }, fmtNum(s.dns.blocked), h('small', {}, ` von ${fmtNum(s.dns.total)} blockiert (${s.dns.blocked_pct} %)`)), h('div', { class: 'muted' }, `davon Werbung & Tracker: ${fmtNum(s.dns.ads)}`),
          barChart(s.dns.hours), h('div', { class: 'legend' }, h('span', {}, h('i', { class: 'bar' }), 'Abfragen'), h('span', {}, h('i', { class: 'bar bl' }), 'blockiert'))),
        h('div', { class: 'card' }, h('h3', {}, 'Datenverkehr (Mbit/s, letzte Stunde)'),
          h('div', { class: 'big' }, s.traffic ? `${s.traffic.rx.toFixed(1)} ↓ · ${s.traffic.tx.toFixed(1)} ↑` : '–'),
          lineChart(tr), h('div', { class: 'legend' }, h('span', {}, 'grün: Empfang'), h('span', {}, 'blau: Senden'))),
        h('div', { class: 'card' }, h('h3', {}, 'Virenschutz'),
          h('div', { class: 'big' }, s.av.engine ? 'Bereit' : 'Nicht verfügbar'),
          h('dl', { class: 'kv' }, h('dt', {}, 'Engine'), h('dd', {}, s.av.engine ? `${s.av.engine} – ${s.av.version}` : 'ClamAV fehlt'), h('dt', {}, 'Echtzeit'), h('dd', {}, `${fmtNum(s.av.watched_dirs)} Verzeichnisse`), h('dt', {}, 'Quarantäne'), h('dd', {}, fmtNum(s.av.quarantine)), h('dt', {}, 'Letzter Scan'), h('dd', {}, s.av.last_scan ? `${fmtTime(s.av.last_scan.time)} (${s.av.last_scan.infected} Funde)` : 'noch keiner'))),
        h('div', { class: 'card' }, h('h3', {}, 'Ereignisse (24 h)'),
          h('div', { class: 'big' }, fmtNum(s.events24h.critical + s.events24h.high), h('small', {}, ' kritisch/hoch')),
          h('dl', { class: 'kv' }, h('dt', {}, 'Kritisch'), h('dd', {}, s.events24h.critical), h('dt', {}, 'Hoch'), h('dd', {}, s.events24h.high), h('dt', {}, 'Warnungen'), h('dd', {}, s.events24h.warn))));
      body.replaceChildren(grid, h('div', { class: 'card' }, h('h2', {}, 'Letzte Warnungen'), eventsTable(ev, true)));
    };
    await draw();
    auto(draw);
  }

  function eventsTable(list, compact) {
    if (!list.length) return h('p', { class: 'muted' }, 'Keine Ereignisse.');
    return h('div', { class: 'scroll' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Zeit'), h('th', {}, 'Stufe'), h('th', {}, 'Typ'), h('th', {}, 'Meldung'), compact ? null : h('th', {}, 'Maßnahmen'))),
      h('tbody', {}, list.map((e) => h('tr', {}, h('td', {}, fmtTime(e.ts)), h('td', {}, sevBadge(e.severity)), h('td', { class: 'mono' }, e.type), h('td', { class: 'wrap' }, e.msg), compact ? null : h('td', {}, (e.actions || []).join('; ')))))));
  }

  // ---------- DNS ----------
  async function viewDns(body) {
    const [st, cfg] = await Promise.all([api('GET', '/api/dns/stats'), api('GET', '/api/config')]);
    const top = (title, list) => h('div', { class: 'card' }, h('h3', {}, title), list.length ? h('table', {}, h('tbody', {}, list.map((x) => h('tr', {}, h('td', { class: 'wrap' }, x.name), h('td', {}, fmtNum(x.count)))))) : h('p', { class: 'muted' }, 'Noch keine Daten'));

    const q = h('input', { type: 'search', placeholder: 'Domain oder Client filtern' });
    const stSel = h('select', {}, [['', 'alle'], ['blocked', 'blockiert'], ['allowed', 'erlaubt'], ['cached', 'Cache'], ['rewritten', 'umgeleitet'], ['refused', 'abgelehnt'], ['error', 'Fehler']].map(([v, l]) => h('option', { value: v }, l)));
    const logBody = h('tbody', {});
    const loadLog = async () => {
      const rows = await api('GET', `/api/dns/log?limit=150&q=${encodeURIComponent(q.value)}&status=${stSel.value}`);
      logBody.replaceChildren(...rows.map((r) => h('tr', {},
        h('td', {}, new Date(r.t).toLocaleTimeString('de-AT')), h('td', { class: 'mono' }, r.c), h('td', { class: 'wrap' }, r.d), h('td', {}, r.qt),
        h('td', { class: `st-${r.s}` }, r.s), h('td', { class: 'wrap muted' }, r.r || ''), h('td', {}, r.ms))));
    };
    q.addEventListener('input', loadLog); stSel.addEventListener('change', loadLog);

    const domIn = h('input', { type: 'text', placeholder: 'z.B. ads.example.com' });
    const domOut = h('div', { class: 'muted' }, '');
    const check = act(async () => { const r = await api('POST', '/api/dns/check', { domain: domIn.value }); domOut.textContent = `${r.domain}: ${r.result === 'blocked' ? 'BLOCKIERT' : r.result === 'allowed' ? 'erlaubt' : 'umgeleitet'} – ${r.detail}`; });

    const lists = h('div', {}, cfg.dns.lists.map((l, i) => {
      const s = st.lists.find((x) => x.id === l.id) || {};
      return chk(`${l.name}`, field(cfg, `dns.lists.${i}.enabled`, 'bool'), `${s.rules !== undefined ? `${fmtNum(s.rules)} Regeln` : 'nicht geladen'}${s.updated ? `, aktualisiert ${fmtTime(s.updated)}` : ''}${s.error ? `, Fehler: ${s.error}` : ''}`);
    }));

    const TIERS = { standard: ['adguard'], stark: ['adguard', 'hagezi-pro'], maximal: ['adguard', 'hagezi-pro', 'hagezi-proplus', 'oisd-big'] };
    const adIds = ['adguard', 'hagezi-pro', 'hagezi-proplus', 'oisd-big'];
    const isOn = (id) => { const l = cfg.dns.lists.find((x) => x.id === id); return !!(l && l.enabled); };
    const curTier = Object.keys(TIERS).reverse().find((t) => TIERS[t].every(isOn) && adIds.filter((i) => !TIERS[t].includes(i)).every((i) => !isOn(i))) || 'eigene';
    const tierSel = h('select', {}, [['aus', 'Aus – keine Werbefilter'], ['standard', 'Standard – AdGuard'], ['stark', 'Stark – AdGuard + HaGeZi Pro (empfohlen)'], ['maximal', 'Maximal – zusätzlich HaGeZi Pro++ und OISD (kann Seiten stören)'], ['eigene', 'Eigene Auswahl (siehe Listen unten)']].map(([v, l]) => h('option', { value: v }, l)));
    tierSel.value = Object.keys(TIERS).includes(curTier) ? curTier : (adIds.some(isOn) ? 'eigene' : 'aus');
    tierSel.addEventListener('change', () => {
      if (tierSel.value === 'eigene') return;
      for (const l of cfg.dns.lists) if (adIds.includes(l.id)) l.enabled = (TIERS[tierSel.value] || []).includes(l.id);
      lists.querySelectorAll('input[type=checkbox]').forEach((cb, i) => { cb.checked = !!cfg.dns.lists[i].enabled; });
    });

    body.replaceChildren(
      h('div', { class: 'card' }, h('h2', {}, 'Werbeblocker'),
        row('Stärke', tierSel, 'Blockiert Werbe- und Tracking-Domains für alle Geräte im Netz. Danach unten „Speichern“ und „Listen jetzt aktualisieren“.'),
        chk('Browser-eigenes DNS-over-HTTPS abschalten lassen (sonst umgehen Firefox/Safari den Filter)', field(cfg, 'dns.disable_browser_doh', 'bool')),
        h('p', { class: 'muted' }, 'Grenzen: Werbung, die vom selben Server wie der Inhalt kommt (z. B. YouTube), und Werbe-Kästen auf der Seite lassen sich per DNS nicht entfernen – dafür zusätzlich uBlock Origin im Browser nutzen.')),
      h('div', { class: 'grid' },
        h('div', { class: 'card' }, h('h3', {}, 'Abfragen gesamt'), h('div', { class: 'big' }, fmtNum(st.total)), h('div', { class: 'muted' }, `${fmtNum(st.cached)} aus Cache · ${fmtNum(st.rules)} Filterregeln`)),
        h('div', { class: 'card' }, h('h3', {}, 'Blockiert'), h('div', { class: 'big' }, fmtNum(st.blocked), h('small', {}, ` (${st.blocked_pct} %)`)), h('div', { class: 'muted' }, `davon Werbung & Tracker: ${fmtNum(st.ads)}`), barChart(st.hours)),
        h('div', { class: 'card' }, h('h3', {}, 'Upstream-Server'), h('table', {}, h('tbody', {}, st.upstreams.map((u) => h('tr', {}, h('td', { class: 'wrap' }, u.url), h('td', {}, u.ok === null ? '–' : u.ok ? `${u.ms} ms` : 'Fehler'))))))),
      h('div', { class: 'grid' }, top('Häufigste Domains', st.top_domains), top('Häufigste blockierte Domains', st.top_blocked), top('Aktivste Clients', st.top_clients)),
      h('div', { class: 'card stack' }, h('h2', {}, 'Domain testen'), h('div', { class: 'inline' }, domIn, h('button', { onclick: check }, 'Prüfen')), domOut),
      h('div', { class: 'card' }, h('h2', {}, 'Abfrage-Protokoll'), h('div', { class: 'inline' }, q, stSel, h('button', { class: 'sec', onclick: loadLog }, 'Aktualisieren')),
        h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, ['Zeit', 'Client', 'Domain', 'Typ', 'Status', 'Regel / Hinweis', 'ms'].map((x) => h('th', {}, x)))), logBody))),
      h('div', { class: 'card' }, h('h2', {}, 'Filterlisten & Regeln'),
        lists,
        h('div', { class: 'inline' }, h('button', { class: 'sec', onclick: act(async () => { await api('POST', '/api/dns/update-lists'); show('dns'); }, 'Listen aktualisiert') }, 'Listen jetzt aktualisieren')),
        row('Eigene Regeln', field(cfg, 'dns.custom_rules', 'lines', { rows: 6 }), 'AdGuard-Syntax: ||beispiel.org^ blockiert Domain+Subdomains · @@||erlaubt.org^ erlaubt · /regex/ · 0.0.0.0 host'),
        row('Lokale DNS-Namen', field(cfg, 'dns.rewrites', 'kv'), 'name=IP, auch *.domain=IP'),
        row('Blockier-Antwort', field(cfg, 'dns.blocking_mode', 'select', { options: [['null_ip', '0.0.0.0 / :: (Standard)'], ['nxdomain', 'NXDOMAIN'], ['refused', 'REFUSED']] })),
        row('Upstream-DNS (je Zeile)', field(cfg, 'dns.upstreams', 'lines', { rows: 4 }), 'https://… = DNS-over-HTTPS, sonst IP[:Port]'),
        chk('SafeSearch erzwingen (Google, Bing, YouTube, DuckDuckGo)', field(cfg, 'dns.safe_search', 'bool')),
        chk('DNS-Filter aktiv', field(cfg, 'dns.enabled', 'bool')),
        h('p', {}, h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern'))));
    await loadLog();
    auto(loadLog);
  }

  // ---------- Firewall ----------
  async function viewFirewall(body) {
    const [fw, cfg, bans] = await Promise.all([api('GET', '/api/firewall'), api('GET', '/api/config'), api('GET', '/api/firewall/bans')]);
    const ip = h('input', { type: 'text', placeholder: 'IP-Adresse' });
    const mins = h('input', { type: 'number', value: 60, min: 1 });
    const banRows = bans.map((b) => h('tr', {}, h('td', { class: 'mono' }, b.ip), h('td', {}, b.expires ? fmtDur(b.expires) : '–'), h('td', { class: 'wrap' }, b.reason || '–'), h('td', {}, h('button', { class: 'sec small', onclick: act(async () => { await api('POST', '/api/firewall/unban', { ip: b.ip }); show('firewall'); }, 'Sperre aufgehoben') }, 'Entsperren'))));
    body.replaceChildren(
      h('div', { class: 'card' }, h('h2', {}, 'Schutz ein/aus (Fehlalarm, Wartung)'),
        h('p', { class: 'muted' }, fw.protection_off ? 'Die Firewall ist AUSGESCHALTET.' : 'Die Firewall ist eingeschaltet. Bei Fehlalarm kannst du sie hier komplett abschalten – Erkennung und Protokoll laufen weiter.'),
        h('div', { class: 'inline' },
          fw.protection_off
            ? h('button', { onclick: act(async () => { await api('POST', '/api/protection/on'); show('firewall'); }, 'Schutz eingeschaltet') }, 'Schutz einschalten')
            : h('button', { class: 'danger', onclick: act(async () => { if (confirm('Firewall und automatische Netztrennung ausschalten?')) { await api('POST', '/api/protection/off'); show('firewall'); } }) }, 'Schutz ausschalten'),
          h('button', { class: 'sec', onclick: act(async () => { await api('POST', '/api/isolation/pause', { minutes: 60 }); show('firewall'); }, 'Auto-Trennung 1 h pausiert') }, 'Nur Auto-Trennung 1 h pausieren'),
          h('button', { class: 'sec', onclick: act(async () => { await api('POST', '/api/isolation/pause', { minutes: 0 }); show('firewall'); }, 'Auto-Trennung wieder aktiv') }, 'Auto-Trennung wieder aktivieren'))),
      h('div', { class: 'card' }, h('h2', {}, 'Sicherheitsstufe & Modus'),
        row('Sicherheitsstufe', field(cfg, 'security_level', 'select', { options: LEVELS })),
        row('Betriebsmodus', field(cfg, 'mode', 'select', { options: [['host', 'Host – schützt diesen Rechner'], ['gateway', 'Gateway – Rechner ist Router des Netzes']] })),
        row('Eigenes Netz (LAN)', field(cfg, 'lan_cidrs', 'lines', { rows: 3 }), 'Diese Netze gelten als vertrauenswürdig (je Zeile, CIDR)'),
        row('Admin-Adressen', field(cfg, 'admin_ips', 'list'), 'Haben immer Zugriff, werden nie gesperrt (IP oder CIDR, Komma-getrennt)'),
        row('Nie sperren', field(cfg, 'never_ban', 'list')),
        row('Aus dem LAN erreichbar (TCP)', field(cfg, 'firewall.allow_in_lan.tcp', 'ports'), 'z.B. 22, 80, 443 – DNS-Port und Web-Oberfläche sind automatisch freigegeben'),
        row('Aus dem LAN erreichbar (UDP)', field(cfg, 'firewall.allow_in_lan.udp', 'ports')),
        row('Aus dem INTERNET erreichbar (TCP)', field(cfg, 'firewall.allow_in_wan.tcp', 'ports'), 'Nur freigeben, was wirklich öffentlich sein muss'),
        row('Aus dem INTERNET erreichbar (UDP)', field(cfg, 'firewall.allow_in_wan.udp', 'ports')),
        row('Brute-Force-Schutz für Ports', field(cfg, 'firewall.bruteforce_ports', 'ports')),
        row('Ausgehend gesperrte TCP-Ports', field(cfg, 'firewall.block_out_tcp_ports', 'ports'), 'Wirkt ab Stufe „Hoch“ (nur Ziele außerhalb des LAN)'),
        chk('Kernel-Härtung (SYN-Cookies, kein Redirect/Source-Routing)', field(cfg, 'firewall.harden_sysctl', 'bool')),
        chk('Gateway: NAT (Masquerading) aktivieren', field(cfg, 'firewall.gateway.nat', 'bool')),
        chk('Gateway: DNS im Netz auf diesen Filter zwingen', field(cfg, 'firewall.gateway.force_dns', 'bool')),
        chk('Firewall aktiv', field(cfg, 'firewall.enabled', 'bool')),
        h('div', { class: 'inline' }, h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern & anwenden'), h('button', { class: 'sec', onclick: act(() => api('POST', '/api/firewall/reload'), 'Regeln neu geladen') }, 'Regeln neu laden'))),
      h('div', { class: 'card' }, h('h2', {}, 'Erweiterte Absicherung'),
        h('p', { class: 'muted' }, 'Zusätzliche Schutzmaßnahmen. Die Voreinstellungen sind sicher und störungsarm; Optionen mit Hinweis nur bei Bedarf aktivieren.'),
        chk('Gefälschte Absenderadressen verwerfen (Anti-Spoofing)', field(cfg, 'firewall.hardening.anti_spoofing', 'bool'), 'Empfohlen: 0.0.0.0/8, 127/8, Multicast, Reserviertes und die eigene Adresse als Absender von außen.'),
        chk('Fragmentierte Pakete verwerfen', field(cfg, 'firewall.hardening.drop_fragments', 'bool'), 'Selten legitim, oft für Umgehungsversuche genutzt. Kann sehr große DNS-/UDP-Pakete stören.'),
        chk('Private Absender auf der Internet-Schnittstelle verwerfen (nur Gateway-Modus)', field(cfg, 'firewall.hardening.block_private_wan', 'bool'), 'Nur aktivieren, wenn der Rechner direkt am Internet hängt – hinter einem anderen Router würde das dessen Netz aussperren.'),
        chk('Port 22 (SSH) nie aus dem Internet erreichbar machen', field(cfg, 'firewall.hardening.ssh_lan_only', 'bool'), 'Auch wenn 22 oben unter „Aus dem INTERNET erreichbar“ steht.'),
        chk('DNS-over-TLS/QUIC (Port 853) nach außen sperren', field(cfg, 'firewall.hardening.block_dot_doq', 'bool'), 'Verhindert, dass Geräte den DNS-Filter über verschlüsseltes DNS umgehen.'),
        row('Verbindungslimit je Absender', field(cfg, 'firewall.hardening.conn_limit', 'num', { min: 0, max: 100000 }), '0 = aus. Gleichzeitige neue Verbindungen von einer fremden Adresse (empfohlen 100–300). Das eigene LAN ist ausgenommen.'),
        row('Ping von außen', field(cfg, 'firewall.hardening.icmp', 'select', { options: [['auto', 'Nach Sicherheitsstufe'], ['lan', 'Nur aus dem eigenen Netz'], ['off', 'Nie antworten']] })),
        row('Internet-Ports nur für diese Quellen', field(cfg, 'firewall.hardening.wan_sources', 'list'), 'Leer = für alle. Sonst gelten die Freigaben „Aus dem INTERNET erreichbar“ nur für diese Adressen/Netze (Komma-getrennt). Der VPN-Port ist ausgenommen.'),
        h('div', { class: 'inline' }, h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern & anwenden'))),
      h('div', { class: 'card' }, h('h2', {}, 'Bedrohungs-IP-Listen'), h('p', { class: 'muted' }, `${fmtNum(fw.threat_entries)} Adressen aktiv. Verbindungen von/zu diesen Adressen werden blockiert und gemeldet.`),
        ...cfg.firewall.threat_feeds.urls.map((f, i) => { const s = fw.feeds[i] || {}; return chk(f.name, field(cfg, `firewall.threat_feeds.urls.${i}.enabled`, 'bool'), `${s.entries !== undefined ? `${fmtNum(s.entries)} Einträge` : 'nicht geladen'}${s.error ? `, Fehler: ${s.error}` : ''}`); }),
        chk('Bedrohungslisten verwenden', field(cfg, 'firewall.threat_feeds.enabled', 'bool')),
        h('div', { class: 'inline' }, h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern'), h('button', { class: 'sec', onclick: act(async () => { await api('POST', '/api/firewall/update-feeds'); show('firewall'); }, 'Listen aktualisiert') }, 'Jetzt aktualisieren'))),
      h('div', { class: 'card' }, h('h2', {}, `Gesperrte Adressen (${bans.length})`),
        h('div', { class: 'inline' }, ip, h('label', {}, 'für '), mins, h('span', {}, 'Minuten'), h('button', { onclick: act(async () => { await api('POST', '/api/firewall/ban', { ip: ip.value, minutes: Number(mins.value) }); show('firewall'); }, 'Gesperrt') }, 'Sperren')),
        bans.length ? h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, ['Adresse', 'Restdauer', 'Grund', ''].map((x) => h('th', {}, x)))), h('tbody', {}, banRows))) : h('p', { class: 'muted' }, 'Keine gesperrten Adressen.')));
  }

  // ---------- VPN (WireGuard) ----------
  const fmtBytes = (n) => (n >= 1073741824 ? `${(n / 1073741824).toFixed(2)} GB` : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(0)} kB` : `${n} B`);
  async function viewVpn(body) {
    const [wg, cfg] = await Promise.all([api('GET', '/api/wireguard'), api('GET', '/api/config')]);
    const name = h('input', { type: 'text', placeholder: 'Name, z. B. Handy Roland', maxlength: 40 });
    const shown = h('div', {});
    const showConfig = async (id, title) => {
      const r = await fetch(`/api/wireguard/peer/config?id=${encodeURIComponent(id)}`, { credentials: 'same-origin' });
      if (!r.ok) throw new Error('Konfiguration konnte nicht geladen werden');
      const ta = h('textarea', { rows: 12, readonly: 'readonly', class: 'mono' }); ta.value = await r.text();
      shown.replaceChildren(h('div', { class: 'card' }, h('h2', {}, `Client-Konfiguration: ${title}`),
        h('p', { class: 'muted' }, 'Enthält den privaten Schlüssel des Geräts – nur dorthin übertragen (WireGuard-App: „Tunnel aus Datei importieren“ oder Text einfügen) und nicht weitergeben.'),
        ta, h('div', { class: 'inline mt' },
          h('button', { onclick: () => { location.href = `/api/wireguard/peer/config?id=${encodeURIComponent(id)}`; } }, 'Als Datei herunterladen'),
          h('button', { class: 'sec', onclick: act(async () => { ta.select(); try { await navigator.clipboard.writeText(ta.value); toast('Kopiert'); } catch (_) { document.execCommand('copy'); toast('Kopiert'); } }) }, 'Kopieren'),
          h('button', { class: 'sec', onclick: () => shown.replaceChildren() }, 'Schließen'))));
      shown.scrollIntoView({ behavior: 'smooth' });
    };
    const peerRows = wg.peers.map((p) => h('tr', {},
      h('td', {}, p.name), h('td', { class: 'mono' }, p.address),
      h('td', {}, !p.enabled ? h('span', { class: 'muted' }, 'deaktiviert') : p.online ? h('span', { class: 'st-allowed' }, '● verbunden') : p.latest_handshake ? h('span', { class: 'muted' }, `zuletzt ${fmtTime(p.latest_handshake)}`) : h('span', { class: 'muted' }, 'noch nie verbunden')),
      h('td', {}, p.endpoint || '–'), h('td', {}, `${fmtBytes(p.rx)} ↓ · ${fmtBytes(p.tx)} ↑`),
      h('td', {}, h('div', { class: 'inline' },
        h('button', { class: 'sec small', onclick: act(() => showConfig(p.id, p.name)) }, 'Konfiguration'),
        h('button', { class: 'sec small', onclick: act(async () => { await api('POST', '/api/wireguard/peer/toggle', { id: p.id, enabled: !p.enabled }); show('vpn'); }) }, p.enabled ? 'Sperren' : 'Aktivieren'),
        h('button', { class: 'danger small', onclick: act(async () => { if (confirm(`Teilnehmer „${p.name}“ endgültig löschen? Das Gerät verliert den Zugang.`)) { await api('POST', '/api/wireguard/peer/delete', { id: p.id }); show('vpn'); } }) }, 'Löschen')))));
    body.replaceChildren(
      h('div', { class: 'card' }, h('h2', {}, 'WireGuard-VPN'),
        h('p', {}, wg.enabled ? (wg.active ? h('span', { class: 'st-allowed' }, `● aktiv auf ${wg.interface} (${wg.subnet}, Port ${cfg.wireguard.listen_port}/udp)`) : h('span', { class: 'err' }, `Eingeschaltet, aber nicht aktiv: ${wg.error || 'wird gestartet …'}`)) : h('span', { class: 'muted' }, 'Ausgeschaltet')),
        !wg.tools ? h('p', { class: 'err' }, 'Das Programm „wg“ fehlt. Installieren mit: sudo apt install wireguard-tools') : null,
        wg.enabled && wg.endpoint_missing ? h('p', { class: 'err' }, 'Trage unten die öffentliche Adresse (DynDNS-Name oder IP) ein, unter der dein Router/Rechner aus dem Internet erreichbar ist – sonst bekommen die Clients keine gültige Endpoint-Adresse. Am Router muss außerdem der UDP-Port dieses VPNs an diesen Rechner weitergeleitet werden.') : null,
        h('p', {}, h('button', { class: 'sec small', onclick: () => show('vpn') }, 'Status aktualisieren')),
        wg.public_key ? h('dl', { class: 'kv' }, h('dt', {}, 'Server-Schlüssel (öffentlich)'), h('dd', { class: 'mono' }, wg.public_key), h('dt', {}, 'Clients nutzen'), h('dd', { class: 'mono' }, wg.client_allowed_ips)) : null),
      h('div', { class: 'card' }, h('h2', {}, 'Einstellungen'),
        chk('VPN-Server einschalten', field(cfg, 'wireguard.enabled', 'bool')),
        row('Öffentliche Adresse für Clients', field(cfg, 'wireguard.endpoint', 'text'), 'z. B. meinvpn.dyndns.org (der Port wird ergänzt)'),
        row('Port (UDP)', field(cfg, 'wireguard.listen_port', 'num', { min: 1, max: 65535 })),
        row('VPN-Netz', field(cfg, 'wireguard.address', 'text'), 'Adresse dieses Rechners im VPN mit Netzgröße, z. B. 10.66.0.1/24 – darf sich nicht mit deinem LAN überschneiden'),
        row('DNS für Clients', field(cfg, 'wireguard.client_dns', 'text'), 'Leer = DNS-Filter dieses Rechners (Werbeblocker auch unterwegs)'),
        chk('Clients dürfen ins interne Netz (LAN)', field(cfg, 'wireguard.routing.access_lan', 'bool')),
        row('Erreichbare LAN-Netze', field(cfg, 'wireguard.lan_routes', 'list'), `Komma-getrennt, z. B. 192.168.1.0/24. Leer = automatisch (${(wg.lan_routes || []).join(', ') || 'keins – bitte dein LAN eintragen'}). Die breiten Standardbereiche (10/8, 192.168/16) werden bewusst nicht automatisch geroutet.`),
        chk('Gesamten Internetverkehr der Clients über diesen Rechner leiten (Full-Tunnel)', field(cfg, 'wireguard.routing.internet', 'bool'), 'Clients nutzen dann deine Internetverbindung und den DNS-Filter; Gegenstellen sehen deine Adresse.'),
        chk('Clients untereinander trennen', field(cfg, 'wireguard.routing.peers_isolated', 'bool'), 'Empfohlen: VPN-Geräte können sich nicht gegenseitig erreichen.'),
        chk('Clients dürfen Dienste dieses Rechners nutzen (Oberfläche, SSH, DNS)', field(cfg, 'wireguard.access_host', 'bool')),
        chk('UDP-Port in der Firewall für das Internet öffnen', field(cfg, 'wireguard.allow_wan_port', 'bool')),
        row('MTU', field(cfg, 'wireguard.mtu', 'num', { min: 1280, max: 1500 })),
        row('Keepalive (Sekunden)', field(cfg, 'wireguard.keepalive', 'num', { min: 0, max: 120 }), 'Hält die Verbindung hinter NAT offen (25 empfohlen)'),
        h('div', { class: 'inline' }, h('button', { onclick: act(async () => { await saveCfg(cfg); show('vpn'); }) }, 'Speichern & anwenden'))),
      h('div', { class: 'card' }, h('h2', {}, `Teilnehmer (${wg.peers.length})`),
        h('div', { class: 'inline' }, name, h('button', { onclick: act(async () => { const r = await api('POST', '/api/wireguard/peer', { name: name.value }); toast(`„${r.name}“ angelegt (${r.address})`); await show('vpn'); }) }, 'Teilnehmer hinzufügen')),
        wg.peers.length ? h('div', { class: 'scroll mt' }, h('table', {}, h('thead', {}, h('tr', {}, ['Name', 'VPN-Adresse', 'Status', 'Herkunft', 'Datenmenge', ''].map((x) => h('th', {}, x)))), h('tbody', {}, peerRows))) : h('p', { class: 'muted mt' }, 'Noch keine Teilnehmer. Lege für jedes Gerät (Handy, Laptop …) einen Teilnehmer an und importiere die Konfiguration in die WireGuard-App.')),
      shown);
  }

  // ---------- Ereignisse ----------
  async function viewEvents(body) {
    const sev = h('select', {}, [['info', 'alle'], ['warn', 'ab Warnung'], ['high', 'ab Hoch'], ['critical', 'nur kritisch']].map(([v, l]) => h('option', { value: v }, l)));
    const q = h('input', { type: 'search', placeholder: 'Suchen' });
    const holder = h('div', {});
    const load = async () => { holder.replaceChildren(eventsTable(await api('GET', `/api/events?limit=300&min=${sev.value}&q=${encodeURIComponent(q.value)}`), false)); };
    sev.addEventListener('change', load); q.addEventListener('input', load);
    body.replaceChildren(h('div', { class: 'card' }, h('h2', {}, 'Ereignisprotokoll'), h('div', { class: 'inline' }, sev, q, h('button', { class: 'sec', onclick: load }, 'Aktualisieren')), holder));
    await load();
    auto(load, 8);
  }

  // ---------- Virenschutz ----------
  async function viewAv(body) {
    const [cfg, qs, s] = await Promise.all([api('GET', '/api/config'), api('GET', '/api/av/quarantine'), api('GET', '/api/status')]);
    const av = s.av;
    const out = h('div', { class: 'muted' }, '');
    body.replaceChildren(
      h('div', { class: 'grid' },
        h('div', { class: 'card' }, h('h3', {}, 'Engine'), h('div', { class: 'big' }, av.engine || 'fehlt'), h('p', { class: 'muted' }, av.engine ? av.version : 'ClamAV installieren: sudo apt install clamav clamav-daemon')),
        h('div', { class: 'card' }, h('h3', {}, 'Scan'), h('div', { class: 'big' }, av.scan.running ? `läuft (${av.scan.found} Funde)` : 'bereit'),
          h('p', { class: 'muted' }, av.last_scan ? `Letzter Scan: ${fmtTime(av.last_scan.time)} – ${av.last_scan.infected} Funde in ${av.last_scan.duration_s} s` : 'Noch kein Scan'),
          h('div', { class: 'inline' }, h('button', { onclick: act(async () => { await api('POST', '/api/av/scan', {}); show('av'); }, 'Scan gestartet') }, 'Jetzt scannen'),
            h('button', { class: 'sec', onclick: act(async () => { const r = await api('POST', '/api/av/selftest'); out.textContent = r.ok ? `Selbsttest bestanden (${r.engine}, ${r.signature})` : `Selbsttest fehlgeschlagen: ${r.error}`; }) }, 'Selbsttest')), out)),
      h('div', { class: 'card' }, h('h2', {}, `Quarantäne (${qs.length})`),
        qs.length ? h('div', { class: 'scroll' }, h('table', {}, h('thead', {}, h('tr', {}, ['Zeit', 'Datei', 'Signatur', 'Größe', ''].map((x) => h('th', {}, x)))),
          h('tbody', {}, qs.map((q) => h('tr', {}, h('td', {}, fmtTime(q.time)), h('td', { class: 'wrap' }, q.original), h('td', {}, q.signature), h('td', {}, `${fmtNum(q.size)} B`),
            h('td', { class: 'inline' },
              h('button', { class: 'sec small', onclick: act(async () => { if (confirm('Datei wirklich wiederherstellen? Sie enthält Schadsoftware!')) { await api('POST', '/api/av/restore', { id: q.id }); show('av'); } }) }, 'Wiederherstellen'),
              h('button', { class: 'danger small', onclick: act(async () => { if (confirm('Endgültig löschen?')) { await api('POST', '/api/av/delete', { id: q.id }); show('av'); } }) }, 'Löschen'))))))) : h('p', { class: 'muted' }, 'Quarantäne ist leer.')),
      h('div', { class: 'card' }, h('h2', {}, 'Einstellungen'),
        chk('Virenschutz aktiv', field(cfg, 'antivirus.enabled', 'bool')),
        chk('Echtzeit-Überwachung neuer/geänderter Dateien', field(cfg, 'antivirus.realtime', 'bool')),
        chk('Laufende Schadprozesse beenden', field(cfg, 'antivirus.kill_malicious_processes', 'bool')),
        chk('Ausführbare Dateien in /tmp melden', field(cfg, 'antivirus.flag_elf_in_tmp', 'bool')),
        row('Bei Fund', field(cfg, 'antivirus.action', 'select', { options: [['quarantine', 'In Quarantäne verschieben'], ['delete', 'Löschen'], ['report', 'Nur melden']] })),
        chk('Täglicher Vollscan', field(cfg, 'antivirus.schedule.enabled', 'bool')),
        row('Uhrzeit (HH:MM)', field(cfg, 'antivirus.schedule.time', 'text')),
        row('Echtzeit-Überwachung (Verzeichnisse)', field(cfg, 'antivirus.watch_paths', 'lines', { rows: 5 })),
        row('Vollscan (Verzeichnisse)', field(cfg, 'antivirus.scan_paths', 'lines', { rows: 5 })),
        row('Max. Dateigröße (MB)', field(cfg, 'antivirus.max_file_mb', 'num', { min: 1 })),
        h('p', {}, h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern'))));
  }

  // ---------- Einstellungen ----------
  async function viewSettings(body) {
    const [cfg, upd] = await Promise.all([api('GET', '/api/config'), api('GET', '/api/update')]);
    const n = cfg.notify;
    const json = h('textarea', { rows: 16 });
    json.value = JSON.stringify(cfg, null, 2);
    const old = h('input', { type: 'password', autocomplete: 'current-password' });
    const nw = h('input', { type: 'password', autocomplete: 'new-password', placeholder: 'mindestens 10 Zeichen' });
    body.replaceChildren(
      h('div', { class: 'card' }, h('h2', {}, 'Benachrichtigungen'),
        row('Ab Schweregrad senden', field(cfg, 'notify.min_severity', 'select', { options: [['info', 'Info'], ['warn', 'Warnung'], ['high', 'Hoch (empfohlen)'], ['critical', 'Nur kritisch']] })),
        row('Wiederholungssperre (s)', field(cfg, 'notify.cooldown_s', 'num', { min: 0 }), 'Gleiche Meldung höchstens einmal in diesem Zeitraum'),
        row('Bezeichnung', field(cfg, 'notify.label', 'text'), 'Erscheint in der Nachricht (Standard: Hostname)'),
        h('details', { open: n.telegram.enabled }, h('summary', {}, 'Telegram'), chk('aktiv', field(cfg, 'notify.telegram.enabled', 'bool')), row('Bot-Token', field(cfg, 'notify.telegram.bot_token', 'password')), row('Chat-ID', field(cfg, 'notify.telegram.chat_id', 'text'))),
        h('details', { open: n.ntfy.enabled }, h('summary', {}, 'ntfy (Push aufs Handy)'), chk('aktiv', field(cfg, 'notify.ntfy.enabled', 'bool')), row('Server', field(cfg, 'notify.ntfy.server', 'text')), row('Topic', field(cfg, 'notify.ntfy.topic', 'text'), 'Schwer erratbar wählen'), row('Token (optional)', field(cfg, 'notify.ntfy.token', 'password'))),
        h('details', { open: n.email.enabled }, h('summary', {}, 'E-Mail (SMTP)'), chk('aktiv', field(cfg, 'notify.email.enabled', 'bool')), row('Server', field(cfg, 'notify.email.host', 'text')), row('Port', field(cfg, 'notify.email.port', 'num')), row('Verschlüsselung', field(cfg, 'notify.email.secure', 'select', { options: [['starttls', 'STARTTLS (587)'], ['tls', 'TLS (465)'], ['none', 'keine']] })), row('Benutzer', field(cfg, 'notify.email.user', 'text')), row('Passwort', field(cfg, 'notify.email.pass', 'password')), row('Absender', field(cfg, 'notify.email.from', 'text')), row('Empfänger', field(cfg, 'notify.email.to', 'text'))),
        h('details', { open: n.webhook.enabled }, h('summary', {}, 'Webhook'), chk('aktiv', field(cfg, 'notify.webhook.enabled', 'bool')), row('URL', field(cfg, 'notify.webhook.url', 'text'))),
        h('div', { class: 'inline' }, h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern'),
          h('button', { class: 'sec', onclick: act(async () => { const r = await api('POST', '/api/notify/test'); if (r.ok) toast(`Testnachricht gesendet: ${Object.entries(r.channels).map(([k, v]) => `${k}: ${v}`).join(', ')}`); else toast(r.error || `Fehlgeschlagen: ${JSON.stringify(r.channels)}`, true); }) }, 'Testnachricht senden (erst speichern)'))),
      h('div', { class: 'card' }, h('h2', {}, 'Automatische Netztrennung'),
        chk('Rechner bei schwerem Verdacht automatisch vom Netz trennen', field(cfg, 'isolation.enabled', 'bool')),
        row('Schwellwert (Punkte)', field(cfg, 'isolation.score_threshold', 'num', { min: 1 }), 'Reverse-Shell = 100, Krypto-Miner = 80, SSH-Einbruch = 70, Botnet-Kontakt = 60 …'),
        row('Zeitfenster (Minuten)', field(cfg, 'isolation.window_minutes', 'num', { min: 1 })),
        chk('Internes Netz behält während der Trennung Zugriff auf diesen Rechner', field(cfg, 'isolation.keep_lan_access', 'bool'), 'Empfohlen: So kannst du bei Fehlalarm aus dem LAN freigeben oder abschalten'),
        chk('Zusätzlich Netzwerk-Schnittstellen abschalten', field(cfg, 'isolation.hard_disconnect', 'bool'), 'Schnittstellen des internen Netzes bleiben oben, solange der Zugriff aus dem LAN erhalten bleibt'),
        chk('Admin-Adressen bleiben während der Trennung erreichbar', field(cfg, 'isolation.allow_admin', 'bool')),
        row('Automatisch freigeben nach (Minuten)', field(cfg, 'isolation.auto_release_minutes', 'num', { min: 0 }), '0 = bleibt getrennt, bis du freigibst'),
        chk('Kompromittierte LAN-Geräte 1 h sperren', field(cfg, 'isolation.quarantine_clients', 'bool')),
        h('p', {}, h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern'))),
      h('div', { class: 'card' }, h('h2', {}, 'Angriffserkennung'),
        chk('Angriffserkennung aktiv', field(cfg, 'ids.enabled', 'bool')),
        chk('Prozesse überwachen (Miner, Reverse-Shells)', field(cfg, 'ids.processes.enabled', 'bool')),
        chk('Verdächtige Prozesse automatisch beenden', field(cfg, 'ids.processes.kill', 'bool')),
        chk('Ausgehende Verbindungen überwachen', field(cfg, 'ids.connections.enabled', 'bool')),
        chk('Neue offene Ports melden', field(cfg, 'ids.listeners.enabled', 'bool')),
        chk('Wichtige Systemdateien überwachen', field(cfg, 'ids.integrity.enabled', 'bool')),
        chk('Datenverkehr-Anomalien erkennen', field(cfg, 'ids.traffic.enabled', 'bool')),
        chk('ARP-Spoofing erkennen', field(cfg, 'ids.arp.enabled', 'bool')),
        chk('Neue Geräte im Netz melden', field(cfg, 'ids.arp.new_device_alert', 'bool')),
        chk('DNS-Anomalien (DGA, Tunneling) erkennen', field(cfg, 'ids.dns.dga', 'bool')),
        h('div', { class: 'inline' }, h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern'),
          h('button', { class: 'sec', onclick: act(async () => { const r = await api('POST', '/api/ids/accept-listeners'); toast(`${r.ports} offene Ports als normal übernommen`); }) }, 'Aktuell offene Ports als normal übernehmen'))),
      h('div', { class: 'card' }, h('h2', {}, 'Neustart'),
        h('p', { class: 'muted' }, 'Der Dienst-Neustart dauert wenige Sekunden; die Firewall-Regeln bleiben dabei aktiv. Ein Rechner-Neustart trennt alle Verbindungen (auch diese Seite) für etwa eine Minute.'),
        h('div', { class: 'inline' },
          h('button', { onclick: act(async () => { if (confirm('RF-NetGuard jetzt neu starten? Du musst dich danach neu anmelden.')) { await api('POST', '/api/restart'); toast('Neustart …'); waitForRestart(); } }) }, 'RF-NetGuard neu starten'),
          h('button', { class: 'danger', onclick: act(async () => { if (confirm('Den ganzen Rechner jetzt neu starten? Alle Verbindungen werden getrennt.')) { await api('POST', '/api/reboot', { confirm: true }); toast('Rechner startet neu …'); waitForRestart(); } }) }, 'Rechner neu starten'))),
      h('div', { class: 'card' }, h('h2', {}, 'Updates'),
        h('p', {}, `Installierte Version: ${upd.version}`, upd.available ? `  →  neu: ${upd.available}` : ''),
        upd.last ? h('p', { class: upd.last.ok ? 'muted' : 'err' }, `Letztes Update (${fmtTime(upd.last.time)}): ${upd.last.message}`) : null,
        h('p', { class: upd.available ? '' : 'muted' }, upd.available ? `Neue Version ${upd.available} verfügbar – wird bei aktivierter Automatik von selbst installiert.` : 'RF-NetGuard ist auf dem neuesten Stand (Quelle: GitHub).'),
        chk('Updates automatisch installieren (mit Sicherung und automatischem Rollback)', field(cfg, 'update.auto_install', 'bool')),
        h('div', { class: 'inline' },
          h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern'),
          h('button', { class: 'sec', onclick: act(async () => { const r = await api('POST', '/api/update/check'); toast(r.info.newer ? `Neue Version ${r.info.latest} verfügbar` : 'RF-NetGuard ist aktuell'); show('settings'); }) }, 'Nach Updates suchen'),
          upd.available ? h('button', { onclick: act(async () => { if (confirm(`Version ${upd.available} jetzt installieren? Der Dienst wird kurz neu gestartet; bei Problemen wird automatisch zurückgestellt.`)) { await api('POST', '/api/update/install'); toast('Update läuft … Seite lädt in Kürze neu'); waitForRestart(); } }) }, `Jetzt auf ${upd.available} aktualisieren`) : null,
          upd.backups ? h('button', { class: 'sec', onclick: act(async () => { if (confirm('Auf die vorherige Programmversion zurückstellen?')) { await api('POST', '/api/update/rollback'); toast('Rollback läuft …'); waitForRestart(); } }) }, 'Vorherige Version wiederherstellen') : null),
        h('details', {}, h('summary', {}, 'Erweitert (eigener Update-Server, Signaturen, Update-Datei)'),
        row('Eigener Update-Server (latest.json)', field(cfg, 'update.url', 'text'), 'Leer lassen = Updates direkt von GitHub (empfohlen). Nur für selbst gehostete, signierte Pakete.'),
        row('Eigener Schlüssel (optional)', (() => { const ta = h('textarea', { rows: 4, placeholder: '-----BEGIN PUBLIC KEY-----' }); ta.value = cfg.update.public_key || ''; ta.addEventListener('input', () => { cfg.update.public_key = ta.value.trim(); }); return ta; })(), 'Zusätzlich zum eingebauten Schlüssel der offiziellen Releases. Nur für eigene Forks nötig. Es werden ausschließlich signierte Updates installiert.'),
          h('div', { class: 'inline' }, h('button', { onclick: act(() => saveCfg(cfg)) }, 'Speichern')),
        h('div', { class: 'inline mt' },
          (() => {
            const f = h('input', { type: 'file', accept: '.ngupdate', class: 'file' });
            const b = h('button', { class: 'sec', onclick: act(async () => {
              if (!f.files[0]) throw new Error('Bitte zuerst eine .ngupdate-Datei wählen');
              const txt = await f.files[0].text();
              if (confirm('Update-Datei installieren? Der Dienst wird kurz neu gestartet.')) { await api('POST', '/api/update/upload', { bundle: txt }); toast('Update läuft … Seite lädt in Kürze neu'); waitForRestart(); }
            }) }, 'Update-Datei installieren');
            return h('span', { class: 'inline' }, f, b);
          })())),
        h('p', { class: 'muted' }, 'Konfiguration, Regeln, Listen und Protokolle bleiben bei Updates erhalten. Firewall-Regeln bleiben während des Neustarts aktiv.')),
      h('div', { class: 'card' }, h('h2', {}, 'Passwort ändern'), row('Altes Passwort', old), row('Neues Passwort', nw),
        h('button', { onclick: act(async () => { await api('POST', '/api/password', { old: old.value, new: nw.value }); toast('Passwort geändert – bitte neu anmelden'); setTimeout(() => showLogin(), 800); }) }, 'Ändern')),
      h('div', { class: 'card donate' },
        h('h2', {}, 'RF-NetGuard unterstützen'),
        h('p', { class: 'muted' }, 'RF-NetGuard ist kostenlos. Wenn es dir gefällt und dein Netz schützt, freut sich der Entwickler über eine kleine Spende.'),
        h('a', { class: 'btn paypal', href: 'https://paypal.me/RolandFriedl', target: '_blank', rel: 'noopener noreferrer' }, '♥ Spenden mit PayPal')),
      h('details', { class: 'card' }, h('summary', {}, 'Erweitert: komplette Konfiguration (JSON)'), json,
        h('p', {}, h('button', { onclick: act(async () => { let o; try { o = JSON.parse(json.value); } catch (e) { throw new Error(`Ungültiges JSON: ${e.message}`); } await saveCfg(o); show('settings'); }) }, 'JSON speichern'))));
  }

  boot();
})();
