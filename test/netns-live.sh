#!/usr/bin/env bash
# Echter Verkehrstest in drei Netzwerk-Namespaces: Rechner (mit RF-NetGuard), LAN-Gerät, "Internet".
# Aufruf: sudo bash test/netns-live.sh   (braucht root, ip, nft, python3, node)
set -u
cd "$(dirname "$0")/.."
export NG_TEST_DIR=$(mktemp -d)
fails=0
ok()   { echo "  ✓ $1"; }
bad()  { echo "  ✗ $1"; fails=$((fails+1)); }
expect() { # name, erwartet(0=Verbindung klappt/1=blockiert), kommando...
  local name=$1 want=$2; shift 2
  "$@" >/dev/null 2>&1; local rc=$?
  if { [ "$want" = 0 ] && [ $rc = 0 ]; } || { [ "$want" = 1 ] && [ $rc != 0 ]; }; then ok "$name"; else bad "$name"; fi
}
probe='import socket,sys
s=socket.socket();s.settimeout(2)
try: s.connect((sys.argv[1],int(sys.argv[2])))
except Exception: sys.exit(1)
sys.exit(0)'

unshare -n sleep 120 & LAN=$!
unshare -n sleep 120 & NET=$!
sleep 0.5
cleanup() { kill $LAN $NET $SRV 2>/dev/null; }
trap cleanup EXIT

# Der "Rechner" läuft in einem eigenen Namespace; Orchestrierung per nsenter
unshare -n bash -c '
  HOSTPID=$$
  echo $HOSTPID > '"$NG_TEST_DIR"'/hostpid
  sleep 100
' & HOSTSH=$!
sleep 0.5
H=$(cat "$NG_TEST_DIR/hostpid")
inh() { nsenter -t "$H" -n "$@"; }
inl() { nsenter -t "$LAN" -n "$@"; }
inn() { nsenter -t "$NET" -n "$@"; }

inh ip link set lo up; inl ip link set lo up; inn ip link set lo up
inh ip link add vlan0 type veth peer name vlan1; inh ip link set vlan1 netns $LAN
inh ip link add vnet0 type veth peer name vnet1; inh ip link set vnet1 netns $NET
inh ip addr add 192.168.50.1/24 dev vlan0; inh ip link set vlan0 up
inh ip addr add 198.51.100.1/24 dev vnet0; inh ip link set vnet0 up
inl ip addr add 192.168.50.2/24 dev vlan1; inl ip link set vlan1 up
inn ip addr add 198.51.100.2/24 dev vnet1; inn ip link set vnet1 up

# Dienste: Web-Oberfläche (8088, LAN erlaubt), Port 9999 (nicht freigegeben) auf dem Rechner; "Internet"-Server 80
inh python3 -m http.server 8088 --bind 0.0.0.0 -d /tmp >/dev/null 2>&1 & SRV=$!
inh python3 -m http.server 9999 --bind 0.0.0.0 -d /tmp >/dev/null 2>&1 &
inn python3 -m http.server 80 --bind 0.0.0.0 -d /tmp >/dev/null 2>&1 &
sleep 1
nsenter -t "$H" -n node test/netns-helper.js apply || bad "Regeln anwenden"

echo "== Normalbetrieb"
expect "LAN → Web-Oberfläche (8088)"           0 inl python3 -c "$probe" 192.168.50.1 8088
expect "LAN → nicht freigegebener Port 9999"   1 inl python3 -c "$probe" 192.168.50.1 9999
expect "Internet → Web-Oberfläche blockiert"   1 inn python3 -c "$probe" 198.51.100.1 8088
expect "Rechner → Internet (80)"               0 inh python3 -c "$probe" 198.51.100.2 80

echo "== Nach Netztrennung (keep_lan_access)"
nsenter -t "$H" -n node test/netns-helper.js isolate || bad "Trennung auslösen"
expect "Rechner → Internet blockiert"          1 inh python3 -c "$probe" 198.51.100.2 80
expect "Internet → Rechner blockiert"          1 inn python3 -c "$probe" 198.51.100.1 8088
expect "LAN → Web-Oberfläche weiterhin da"     0 inl python3 -c "$probe" 192.168.50.1 8088
expect "LAN → Port 9999 weiter gesperrt"       1 inl python3 -c "$probe" 192.168.50.1 9999

echo "== Freigabe (Fehlalarm)"
nsenter -t "$H" -n node test/netns-helper.js release || bad "Freigabe"
expect "Rechner → Internet wieder da"          0 inh python3 -c "$probe" 198.51.100.2 80

echo "== Trennung ohne keep_lan_access (zum Vergleich)"
KEEP_LAN=0 nsenter -t "$H" -n node test/netns-helper.js apply
KEEP_LAN=0 nsenter -t "$H" -n node test/netns-helper.js isolate
expect "LAN → Web-Oberfläche gesperrt"         1 inl python3 -c "$probe" 192.168.50.1 8088
KEEP_LAN=0 nsenter -t "$H" -n node test/netns-helper.js release

echo "== Schutz aus"
nsenter -t "$H" -n node test/netns-helper.js off || bad "Schutz aus"
expect "LAN → Port 9999 (Firewall aus)"        0 inl python3 -c "$probe" 192.168.50.1 9999
kill $HOSTSH 2>/dev/null
echo; [ $fails = 0 ] && echo "Alle Verkehrstests bestanden" || echo "$fails Verkehrstest(s) fehlgeschlagen"
exit $fails
