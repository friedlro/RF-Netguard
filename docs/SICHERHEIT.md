# Sicherheitskonzept und Grenzen

## Sicherheitsstufen
| Stufe | Sperrdauer | Verhalten |
|---|---|---|
| low | 10 min | hohe Schwellen, nur das Nötigste blockiert |
| normal | 1 h | empfohlen |
| high | 24 h | strenge Schwellen, riskante Ausgangsports (Telnet, IRC, 4444 …) gesperrt |
| paranoid | 7 d | ausgehend nur erlaubte Ports (`firewall.outbound_allow`) |

## Betriebsarten
* **host** – schützt diesen Rechner; der DNS-Filter bedient zusätzlich das LAN.
* **gateway** – der Rechner ist Router des Netzes: Forward-Filter, optional NAT und Zwang aller DNS-Anfragen auf den Filter.
  Dafür muss `net.ipv4.ip_forward=1` gesetzt sein.

Um das **ganze Netz** mit dem DNS-Filter zu schützen, trage die IP dieses Rechners im Router (DHCP) als DNS-Server ein
oder nutze den Gateway-Modus.

## Grenzen – bitte lesen
* **Keine Inhaltsprüfung des Datenverkehrs.** RF-NetGuard filtert auf IP-/Port-/DNS-Ebene und wertet Verhalten aus, entschlüsselt aber keinen TLS-Verkehr.
* **DNS-Filter umgehbar:** Geräte mit eigenem DoH/DoT (Browser-Einstellung, Smart-TVs) umgehen ihn – im Gateway-Modus wird klassisches DNS (Port 53) erzwungen, DoH nicht.
* **Virenerkennung = ClamAV-Signaturen** (kein Schutz vor ganz neuer Malware) plus einfache Verhaltensregeln; Fehlalarme sind möglich. Die Vollscan-Funde allein lösen bewusst keine Netztrennung aus.
* **Bedrohungslisten sind IPv4-orientiert**; IPv6-Verkehr wird durch die Standardregeln geschützt, aber nicht mit Listen abgeglichen.
* **Kein Ersatz** für Updates, starke Passwörter und Schlüssel-Login bei SSH. Ein bereits vollständig kompromittierter Root-Rechner kann RF-NetGuard selbst abschalten.
* Eine automatische Netztrennung kann auch einen Fehlalarm treffen: Plane einen zweiten Zugang (Konsole/Admin-Adresse) ein.
* Die Listen-URLs (AdGuard, URLhaus, Feodo …) können sich ändern; Ladefehler siehst du in der Oberfläche.
* Getestet wurde in einer Container-Umgebung (Regeln validiert und im Namespace geladen); auf deinem Rechner bitte zuerst `sudo rf-netguard selftest` und einen Testlauf mit eigener Admin-Adresse machen.
