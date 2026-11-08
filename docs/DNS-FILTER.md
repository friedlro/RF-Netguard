# DNS-Filter und Werbeblocker

## DNS-Regeln (AdGuard-Syntax)
```
||ads.example.com^        blockiert Domain und alle Subdomains
@@||shop.example.com^     Ausnahme (erlaubt)
||x.org^$important        schlägt auch Ausnahmen
||x.org^$dnstype=AAAA     nur für bestimmten Abfragetyp
/^tracker[0-9]+\./        regulärer Ausdruck
||*.cdn.example.com^      Platzhalter
0.0.0.0 evil.example      Hosts-Format
! Kommentar
```
Zusätzlich: lokale Namen (`nas.home=192.168.1.10`), Blockier-Antwort (0.0.0.0 / NXDOMAIN / REFUSED), SafeSearch.
Ob eine Domain blockiert wird, zeigt der Dialog „Domain testen". Listen lassen sich in der Oberfläche ein- und ausschalten;
neue Listen trägst du in `dns.lists` ein.

## Werbeblocker
Der DNS-Filter blockiert Werbe- und Tracking-Domains für **alle Geräte**, die diesen Rechner als DNS-Server nutzen
(Router/DHCP auf die IP des Rechners stellen oder Gateway-Modus). Stärke einstellbar unter *DNS-Filter → Werbeblocker*:

| Stärke | Listen | Regeln (ca.) |
|---|---|---|
| Standard | AdGuard DNS-Filter | 190.000 |
| **Stark (Standard-Einstellung)** | + HaGeZi Pro | 415.000 |
| Maximal | + HaGeZi Pro++, OISD Big | 890.000 (ca. 70 MB RAM) – kann einzelne Seiten stören |

* Betroffene Seite kaputt? Domain unter „Abfrage-Protokoll" suchen und mit `@@||domain.tld^` in „Eigene Regeln" erlauben.
* **Browser-DoH-Schutz:** Firefox und iCloud Private Relay fragen zuerst `use-application-dns.net` bzw. `mask.icloud.com`; RF-NetGuard antwortet mit NXDOMAIN,
  wodurch sie ihr eigenes verschlüsseltes DNS abschalten und den Filter nicht umgehen. Chrome/Edge mit fest eingetragenem DoH-Anbieter („Sicheres DNS") und Smart-TVs mit eigenem DNS musst du
  in deren Einstellungen auf „System-DNS" stellen.
* **Grenzen:** Ein DNS-Filter sperrt nur ganze Domains. Werbung vom selben Server wie der Inhalt (z. B. YouTube-Videowerbung, manche Verlags-Seiten) und leere Werbe-Kästen
  auf der Seite kann er nicht entfernen – dafür zusätzlich **uBlock Origin** im Browser installieren.
