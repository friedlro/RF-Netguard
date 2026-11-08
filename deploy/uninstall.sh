#!/usr/bin/env bash
# RF-NetGuard entfernen. Als root ausführen.
set -u
[ "$(id -u)" -eq 0 ] || { echo "Bitte als root ausführen."; exit 1; }
echo "-- Dienst stoppen"
systemctl disable --now netguard 2>/dev/null || true
echo "-- Firewallregeln entfernen"
for t in "inet netguard" "inet netguard_iso" "ip netguard_nat"; do nft delete table $t 2>/dev/null || true; done
echo "-- Netzwerk-Schnittstellen wieder aktivieren"
for i in $(ls /sys/class/net); do [ "$i" = lo ] || ip link set "$i" up 2>/dev/null || true; done
if [ -f /etc/systemd/resolved.conf.d/netguard.conf ]; then
  rm -f /etc/systemd/resolved.conf.d/netguard.conf
  if [ -e /etc/resolv.conf.netguard-backup ] || [ -L /etc/resolv.conf.netguard-backup ]; then
    rm -f /etc/resolv.conf; mv /etc/resolv.conf.netguard-backup /etc/resolv.conf
  else
    rm -f /etc/resolv.conf; ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
  fi
  systemctl restart systemd-resolved 2>/dev/null || true
fi
rm -f /etc/systemd/system/netguard.service /usr/local/bin/rf-netguard /usr/local/bin/netguard /etc/sysctl.d/90-netguard.conf
systemctl daemon-reload
rm -rf /opt/netguard
echo "Entfernt. Konfiguration (/etc/netguard), Daten (/var/lib/netguard) und Logs (/var/log/netguard) wurden behalten."
echo "Komplett löschen: sudo rm -rf /etc/netguard /var/lib/netguard /var/log/netguard"
