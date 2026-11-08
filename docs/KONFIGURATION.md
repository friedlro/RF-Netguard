# Konfiguration

Datei: `/etc/netguard/config.json` (Vorlage: `config.example.json`). Die meisten Einstellungen sind in der Oberfläche unter *Einstellungen* änderbar;
`sudo rf-netguard reload` lädt Änderungen an der Datei.

| Bereich | Wichtige Schlüssel |
|---|---|
| Allgemein | `mode` (host/gateway), `security_level` (low/normal/high/paranoid), `admin_ips`, `lan_cidrs` |
| Web | `web.bind`, `web.port` (Standard 8088), `web.allowed_hosts`, Passwort über `rf-netguard passwd` |
| Netztrennung | `isolation.score_threshold`, `isolation.window_minutes`, `isolation.keep_lan_access`, `isolation.hard_disconnect`, `isolation.allow_admin`, `isolation.auto_release_minutes` |
| DNS | `dns.lists`, `dns.upstreams`, `dns.cache`, `dns.blocking_mode`, `dns.disable_browser_doh`, `dns.custom_rules`, `dns.rewrites`, `dns.safe_search` |
| Firewall | `firewall.allow_in_lan`, `firewall.allow_in_wan`, `firewall.outbound_allow`, `firewall.threat_feeds`, `firewall.gateway` |
| Härtung | `firewall.hardening.*` (anti_spoofing, drop_fragments, block_private_wan, conn_limit, icmp, wan_sources, ssh_lan_only, block_dot_doq) |
| WireGuard | `wireguard.*` (enabled, endpoint, listen_port, address, routing, lan_routes, client_dns, access_host); Teilnehmer nur über den VPN-Tab |
| Virenschutz | `antivirus.realtime`, `antivirus.watch_paths`, `antivirus.scan_paths`, `antivirus.schedule`, `antivirus.action` |
| Benachrichtigung | `notify.telegram`, `notify.ntfy`, `notify.email`, `notify.webhook`, Mindest-Schweregrad |
| Updates | `update.url` (Standard: GitHub), `update.check_hours`, `update.auto_install`, `update.public_key`, `update.builtin_key` |

Pfade: Konfiguration `/etc/netguard/`, Daten `/var/lib/netguard/`, Logs `/var/log/netguard/` (`events.jsonl`, `netguard.log`), Programm `/opt/netguard/`,
Sicherungen `/opt/netguard-backups/`. Die genauen Schlüssel und Standardwerte stehen in `config.example.json`.
