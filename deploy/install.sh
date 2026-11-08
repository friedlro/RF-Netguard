#!/usr/bin/env bash
# RF-NetGuard Installer (Debian/Ubuntu). Als root ausführen: sudo ./deploy/install.sh
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Bitte als root ausführen (sudo)."; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST=/opt/netguard

echo "== RF-NetGuard Installation =="
command -v apt-get >/dev/null || { echo "Nur Debian/Ubuntu (apt) wird vom Installer unterstützt."; exit 1; }

echo "-- Pakete installieren (nftables, ClamAV)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nftables iproute2 clamav clamav-daemon clamav-freshclam ca-certificates curl >/dev/null

need_node=1
if command -v node >/dev/null; then
  major=$(node -p 'process.versions.node.split(".")[0]')
  [ "$major" -ge 18 ] && need_node=0
fi
if [ $need_node -eq 1 ]; then
  echo "-- Node.js >= 18 fehlt, installiere über apt"
  apt-get install -y -qq nodejs >/dev/null
  major=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
  [ "$major" -ge 18 ] || { echo "Die über apt verfügbare Node.js-Version ist zu alt (<18). Bitte Node.js 18+ manuell installieren (https://nodejs.org) und erneut starten."; exit 1; }
fi

echo "-- Dateien nach $DEST kopieren"
mkdir -p "$DEST"
for it in src ui deploy test tools docs package.json README.md LICENSE CHANGELOG.md SECURITY.md config.example.json; do
  [ -e "$SRC/$it" ] && { rm -rf "$DEST/$it"; cp -r "$SRC/$it" "$DEST/"; }
done
mkdir -p /etc/netguard /var/lib/netguard /var/log/netguard
chmod 700 /etc/netguard /var/lib/netguard

cat > /usr/local/bin/rf-netguard <<'WRAP'
#!/bin/sh
exec node /opt/netguard/src/index.js "$@"
WRAP
chmod 755 /usr/local/bin/rf-netguard
ln -sf /usr/local/bin/rf-netguard /usr/local/bin/netguard   # alter Befehlsname bleibt gültig

echo "-- Kernel-Limits für Dateiüberwachung"
cat > /etc/sysctl.d/90-netguard.conf <<'SYS'
fs.inotify.max_user_watches=524288
fs.inotify.max_user_instances=512
SYS
sysctl --system >/dev/null 2>&1 || true

echo "-- Einrichtung"
if [ ! -f /etc/netguard/config.json ]; then
  rf-netguard setup
else
  echo "Vorhandene Konfiguration /etc/netguard/config.json bleibt erhalten."
fi

# Port 53 freimachen (systemd-resolved belegt ihn mit einem Stub)
if ss -lntu 2>/dev/null | grep -qE '127\.0\.0\.53:53|127\.0\.0\.54:53'; then
  DNS_ON=$(node -e 'try{console.log(JSON.parse(require("fs").readFileSync("/etc/netguard/config.json","utf8")).dns.enabled!==false)}catch(e){console.log(true)}')
  if [ "$DNS_ON" = "true" ]; then
    echo "-- systemd-resolved belegt Port 53: Stub-Listener wird deaktiviert"
    mkdir -p /etc/systemd/resolved.conf.d
    printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/netguard.conf
    systemctl restart systemd-resolved || true
    if [ -L /etc/resolv.conf ]; then
      cp -a /etc/resolv.conf /etc/resolv.conf.netguard-backup 2>/dev/null || true
    fi
    # Dieser Rechner nutzt den eigenen Filter
    rm -f /etc/resolv.conf
    printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
  fi
fi

echo "-- Virensignaturen (kann etwas dauern)"
systemctl stop clamav-freshclam 2>/dev/null || true
freshclam --quiet 2>/dev/null || echo "   (freshclam fehlgeschlagen – Signaturen werden später automatisch geladen)"
systemctl enable --now clamav-freshclam 2>/dev/null || true
systemctl enable --now clamav-daemon 2>/dev/null || true

echo "-- Dienst installieren"
cp "$SRC/deploy/netguard.service" /etc/systemd/system/netguard.service
systemctl daemon-reload
systemctl enable netguard >/dev/null
systemctl restart netguard
sleep 3

echo
systemctl --no-pager --lines=0 status netguard | sed -n 1,4p || true
PORT=$(node -p 'try{JSON.parse(require("fs").readFileSync("/etc/netguard/config.json","utf8")).web.port}catch(e){8088}')
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "RF-NetGuard läuft."
echo "  Oberfläche:   http://${IP:-<IP>}:${PORT}"
echo "  Status:       sudo rf-netguard status"
echo "  Notfall aus:  sudo rf-netguard firewall-off"
echo "  Tipp: Test des Virenscanners mit 'sudo rf-netguard selftest'"
echo "  Spätere Updates ohne Neuinstallation: sudo rf-netguard update <Datei|URL>  (siehe README)"
