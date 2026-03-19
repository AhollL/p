#!/bin/bash
# ================================================================
#   ZivPanel v4.0 — ZIVPN UDP + Xray (dugong-lewat/1clickxray)
#   Distro  : Debian 11/12 | Ubuntu 20.04/22.04 (AMD64)
#   Creator : zahidbd2 | Xray by dugong-lewat | Panel by PowerMX
#   Xray    : XTLS-Vision + WS + HTTPUpgrade + gRPC + SSL acme.sh
# ================================================================

# ── Warna ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
CYN='\033[0;36m'; WHT='\033[1;37m'; NC='\033[0m'

# ── Path global ───────────────────────────────────────────────────
PANEL_DIR="/etc/zivpanel"
USER_DB="$PANEL_DIR/zivpn-users.db"
XRAY_DB="$PANEL_DIR/xray-users.db"
BW_DB="$PANEL_DIR/xray-bw.db"
SERVER_CONF="$PANEL_DIR/server.conf"
INSTALLED_FLAG="$PANEL_DIR/.installed"

# ZIVPN
ZIVPN_CONF="/etc/zivpn/config.json"
ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_SVC="/etc/systemd/system/zivpn.service"
ENFORCE_EXPIRE="/usr/local/bin/zivpanel-expire"
ENFORCE_QUOTA="/usr/local/bin/zivpanel-quota"

# Xray (dugong structure)
XRAY_BIN="/usr/local/bin/xray"
XRAY_CONF_DIR="/usr/local/etc/xray/config"
XRAY_DIR="/usr/local/etc/xray"
XRAY_CERT="$XRAY_DIR/fullchain.cer"
XRAY_KEY="$XRAY_DIR/private.key"
XRAY_SVC="/etc/systemd/system/xray.service"
DOMAIN_FILE="$XRAY_DIR/dns/domain"

ANTIDDOS="$PANEL_DIR/anti-ddos.sh"
RESTORE_NAT="$PANEL_DIR/restore-nat.sh"
PANEL_BIN="/usr/local/bin/zivpanel"

# GitHub source dugong
DUGONG="raw.githubusercontent.com/dugong-lewat/1clickxray/main"

# ── Helper ────────────────────────────────────────────────────────
die()         { echo -e "${RED}[!] $*${NC}" >&2; exit 1; }
ok()          { echo -e "${GRN}[✓] $*${NC}"; }
warn()        { echo -e "${YLW}[!] $*${NC}"; }
info()        { echo -e "${CYN}[…] $*${NC}"; }
press_enter() { echo; read -rp "  Tekan Enter..." _pe; }
kv()          { printf "%-14s: %s\n" "$1" "$2"; }
confirm()     { read -rp "  $1 [y/N]: " _c; [[ "$_c" == [yY] ]]; }
check_root()  { [[ $EUID -eq 0 ]] || die "Jalankan sebagai root: sudo $0"; }

get_domain()  { cat "$DOMAIN_FILE" 2>/dev/null || echo "-"; }
get_host()    { grep "^HOST=" "$SERVER_CONF" 2>/dev/null | cut -d= -f2 || get_domain; }
get_isp()     { grep "^ISP="  "$SERVER_CONF" 2>/dev/null | cut -d= -f2 || echo "-"; }
save_conf()   { printf 'HOST=%s\nISP=%s\n' "$1" "$2" > "$SERVER_CONF"; }

get_pub_ip() {
    curl -s4 --max-time 4 ifconfig.me 2>/dev/null \
    || curl -s4 --max-time 4 icanhazip.com 2>/dev/null \
    || hostname -I | awk '{print $1}'
}

fetch_isp() {
    local r; r=$(curl -s --max-time 4 "https://ipapi.co/${1}/org/" 2>/dev/null)
    [[ -z "$r" || "$r" == *error* ]] && r="Unknown ISP"
    echo "$r"
}

days_left() {
    local et today_ts
    et=$(date -d "$1" +%s 2>/dev/null) || { echo 0; return; }
    today_ts=$(date -d "$(date +%Y-%m-%d)" +%s)
    echo $(( (et - today_ts) / 86400 ))
}

clean_db()  { sed -i 's/\r//g' "$1" 2>/dev/null; }
count_db()  { [[ -s "$1" ]] && wc -l < "$1" || echo 0; }

make_uuid() {
    local u
    u=$(uuidgen 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '\r\n')
    [[ -z "$u" ]] && u=$(python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null | tr -d '\r\n')
    [[ -z "$u" ]] && u=$(tr -d '\r\n' < /proc/sys/kernel/random/uuid 2>/dev/null)
    echo "$u"
}

init_panel() {
    mkdir -p "$PANEL_DIR"
    for f in "$USER_DB" "$XRAY_DB" "$BW_DB"; do
        [[ ! -f "$f" ]] && touch "$f"
        clean_db "$f"
    done
}

install_shortcut() {
    local self; self=$(realpath "$0")
    if [[ "$self" != "$PANEL_BIN" && ! -f "$PANEL_BIN" ]]; then
        cp "$self" "$PANEL_BIN" && chmod +x "$PANEL_BIN"
        ok "Shortcut dibuat — ketik 'zivpanel'"
    fi
}

# ═════════════════════════════════════════════════════════════════
#  ENFORCEMENT (ZIVPN expire & quota)
# ═════════════════════════════════════════════════════════════════
install_enforcement() {
    cat > "$ENFORCE_EXPIRE" <<'EOF'
#!/bin/bash
DB="/etc/zivpanel/zivpn-users.db"
CFG="/etc/zivpn/config.json"
[[ -f "$DB" && -f "$CFG" ]] || exit 0
TODAY=$(date +%Y-%m-%d)
while IFS='|' read -r u pw exp quota maxip cr; do
    u=$(echo "$u"|tr -d '\r'); pw=$(echo "$pw"|tr -d '\r')
    [[ -z "$u" ]] && continue
    sisa=$(( ( $(date -d "$exp" +%s 2>/dev/null||echo 0) - $(date -d "$TODAY" +%s) ) / 86400 ))
    [[ $sisa -ge 0 ]] && continue
    export _ZPW="$pw"
    python3 -c "
import json,os
p=os.environ.get('_ZPW','')
with open('$CFG') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if p and p in pw: pw.remove(p)
if not pw: pw.append('zi')
c['auth']['config']=pw
with open('$CFG','w') as f: json.dump(c,f,indent=2)
" 2>/dev/null
    systemctl restart zivpn 2>/dev/null
done < "$DB"
EOF
    chmod +x "$ENFORCE_EXPIRE"

    cat > "$ENFORCE_QUOTA" <<'EOF'
#!/bin/bash
DB="/etc/zivpanel/zivpn-users.db"
CFG="/etc/zivpn/config.json"
[[ -f "$DB" && -f "$CFG" ]] || exit 0
while IFS='|' read -r u pw exp quota maxip cr; do
    u=$(echo "$u"|tr -d '\r'); pw=$(echo "$pw"|tr -d '\r')
    [[ -z "$u" || "$quota" == "0" ]] && continue
    limit=$(( quota * 1073741824 ))
    used=0
    for pid in $(pgrep -u "$u" 2>/dev/null); do
        [[ -r "/proc/$pid/io" ]] || continue
        rb=$(awk '/^read_bytes/{print $2}'  /proc/$pid/io 2>/dev/null)
        wb=$(awk '/^write_bytes/{print $2}' /proc/$pid/io 2>/dev/null)
        used=$(( used + ${rb:-0} + ${wb:-0} ))
    done
    [[ $used -le $limit ]] && continue
    export _ZPW="$pw"
    python3 -c "
import json,os
p=os.environ.get('_ZPW','')
with open('$CFG') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if p and p in pw: pw.remove(p)
if not pw: pw.append('zi')
c['auth']['config']=pw
with open('$CFG','w') as f: json.dump(c,f,indent=2)
" 2>/dev/null
    systemctl restart zivpn 2>/dev/null
done < "$DB"
EOF
    chmod +x "$ENFORCE_QUOTA"

    { crontab -l 2>/dev/null | grep -v "zivpanel-expire\|zivpanel-quota"
      echo "*/5 * * * * $ENFORCE_EXPIRE >/dev/null 2>&1"
      echo "*/5 * * * * $ENFORCE_QUOTA  >/dev/null 2>&1"
    } | crontab -
}

# ═════════════════════════════════════════════════════════════════
#  ANTI-DDOS + NAT
# ═════════════════════════════════════════════════════════════════
write_antiddos() {
    local iface; iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    cat > "$ANTIDDOS" <<DDOS
#!/bin/bash
IPT=iptables
IFACE=$iface
\$IPT -P INPUT   ACCEPT
\$IPT -P FORWARD ACCEPT
\$IPT -P OUTPUT  ACCEPT
\$IPT -F INPUT
\$IPT -F FORWARD
\$IPT -A INPUT  -i lo -j ACCEPT
\$IPT -A OUTPUT -o lo -j ACCEPT
\$IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
\$IPT -A INPUT -m conntrack --ctstate INVALID -j DROP
\$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
\$IPT -A INPUT -p tcp --tcp-flags ALL ALL  -j DROP
\$IPT -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
\$IPT -A INPUT -p udp  --dport 5667       -j ACCEPT
\$IPT -A INPUT -p udp  --dport 6000:19999 -j ACCEPT
\$IPT -A INPUT -p tcp  --dport 22         -j ACCEPT
\$IPT -A INPUT -p tcp  --dport 80         -j ACCEPT
\$IPT -A INPUT -p tcp  --dport 443        -j ACCEPT
\$IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 2/s --limit-burst 4 -j ACCEPT
\$IPT -A INPUT -p icmp --icmp-type echo-request -j DROP
\$IPT -A INPUT -p tcp --syn -m multiport ! --dports 22,80,443 -m limit --limit 30/s --limit-burst 60 -j ACCEPT
\$IPT -A INPUT -p tcp --syn -m multiport ! --dports 22,80,443 -j DROP
\$IPT -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m recent --set --name WRATE --rsource
\$IPT -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 120 --name WRATE --rsource -j DROP
\$IPT -A INPUT -p udp -m multiport ! --dports 5667,6000:19999 -m limit --limit 200/s --limit-burst 400 -j ACCEPT
\$IPT -A INPUT -p udp -m multiport ! --dports 5667,6000:19999 -j DROP
\$IPT -A FORWARD -i \$IFACE -j ACCEPT
\$IPT -A FORWARD -o \$IFACE -j ACCEPT
\$IPT -P INPUT   DROP
\$IPT -P FORWARD ACCEPT
\$IPT -P OUTPUT  ACCEPT
iptables-save > /etc/iptables/rules.v4 2>/dev/null
DDOS
    chmod +x "$ANTIDDOS"
}

write_restore_nat() {
    cat > "$RESTORE_NAT" <<'NAT'
#!/bin/bash
IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
[[ -z "$IFACE" ]] && exit 0
iptables -t nat -C PREROUTING -i "$IFACE" -p udp --dport 6000:19999 \
    -j DNAT --to-destination :5667 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$IFACE" -p udp \
       --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -C POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE
iptables -C FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$IFACE" -j ACCEPT
iptables -C FORWARD -o "$IFACE" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -o "$IFACE" -j ACCEPT
NAT
    chmod +x "$RESTORE_NAT"
    [[ ! -f /etc/rc.local ]] && printf '#!/bin/bash\nexit 0\n' > /etc/rc.local && chmod +x /etc/rc.local
    sed -i '/zivpanel\|anti-ddos\|restore-nat/d' /etc/rc.local
    sed -i '/^exit 0/i bash /etc/zivpanel/anti-ddos.sh'   /etc/rc.local
    sed -i '/^exit 0/i bash /etc/zivpanel/restore-nat.sh' /etc/rc.local
}

# ═════════════════════════════════════════════════════════════════
#  XRAY CONFIG — tulis ulang dari DB (dugong structure)
#  Xray listen langsung di port 80 & 443, Nginx hanya untuk gRPC
# ═════════════════════════════════════════════════════════════════
write_xray_config() {
    local domain; domain=$(get_domain)
    # Baca semua user dari DB
    local vless_clients="" vmess_clients="" trojan_clients=""
    if [[ -s "$XRAY_DB" ]]; then
        local _u _uuid _pw _proto _exp _cr
        while IFS='|' read -r _u _uuid _pw _proto _exp _cr; do
            _u=$(echo "$_u"|tr -d '\r')
            _uuid=$(echo "$_uuid"|tr -d '\r')
            _pw=$(echo "$_pw"|tr -d '\r')
            vless_clients+="{\"id\":\"${_uuid}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"${_u}\"},"
            vmess_clients+="{\"id\":\"${_uuid}\",\"alterId\":0,\"email\":\"${_u}\"},"
            trojan_clients+="{\"password\":\"${_pw}\",\"email\":\"${_u}\"},"
        done < "$XRAY_DB"
        vless_clients="${vless_clients%,}"
        vmess_clients="${vmess_clients%,}"
        trojan_clients="${trojan_clients%,}"
    else
        local _ph_uuid; _ph_uuid=$(make_uuid)
        vless_clients="{\"id\":\"${_ph_uuid}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"placeholder\"}"
        vmess_clients="{\"id\":\"${_ph_uuid}\",\"alterId\":0,\"email\":\"placeholder\"}"
        trojan_clients="{\"password\":\"placeholder\",\"email\":\"placeholder\"}"
    fi

    mkdir -p "$XRAY_CONF_DIR"

    # 00_log.json
    cat > "$XRAY_CONF_DIR/00_log.json" <<'LOG'
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  }
}
LOG

    # 01_api.json
    cat > "$XRAY_CONF_DIR/01_api.json" <<'API'
{
  "api": {
    "tag": "api",
    "services": ["StatsService"]
  }
}
API

    # 02_dns.json
    cat > "$XRAY_CONF_DIR/02_dns.json" <<'DNS'
{
  "dns": {
    "servers": ["1.1.1.1","8.8.8.8","localhost"]
  }
}
DNS

    # 03_policy.json
    cat > "$XRAY_CONF_DIR/03_policy.json" <<'POLICY'
{
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  }
}
POLICY

    # 04_inbounds.json — struktur dugong
    cat > "$XRAY_CONF_DIR/04_inbounds.json" <<CFG
{
  "inbounds": [
    {
      "listen": "127.0.0.1",
      "port": 10000,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" },
      "tag": "api"
    },
    {
      "listen": "::",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [${vless_clients}],
        "decryption": "none",
        "fallbacks": [
          { "alpn": "h2", "dest": 4443, "xver": 2 },
          { "dest": 8080, "xver": 2 },
          { "path": "/vless-ws",   "dest": "@vless-ws",   "xver": 2 },
          { "path": "/vmess-ws",   "dest": "@vmess-ws",   "xver": 2 },
          { "path": "/trojan-ws",  "dest": "@trojan-ws",  "xver": 2 },
          { "path": "/vless-hup",  "dest": "@vl-hup",     "xver": 2 },
          { "path": "/vmess-hup",  "dest": "@vm-hup",     "xver": 2 },
          { "path": "/trojan-hup", "dest": "@trojan-hup", "xver": 2 }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [{ "certificateFile": "${XRAY_CERT}", "keyFile": "${XRAY_KEY}" }],
          "alpn": ["h2","http/1.1"],
          "minVersion": "1.2"
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-01"
    },
    {
      "listen": "127.0.0.1",
      "port": 4443,
      "protocol": "trojan",
      "settings": {
        "clients": [${trojan_clients}],
        "fallbacks": [{ "dest": 8443, "xver": 2 }]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none",
        "tcpSettings": { "acceptProxyProtocol": true }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-02"
    },
    {
      "listen": "@vless-ws",
      "protocol": "vless",
      "settings": { "clients": [${vless_clients}], "decryption": "none" },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "acceptProxyProtocol": true, "path": "/vless-ws" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-03"
    },
    {
      "listen": "@vmess-ws",
      "protocol": "vmess",
      "settings": { "clients": [${vmess_clients}] },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "acceptProxyProtocol": true, "path": "/vmess-ws" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-04"
    },
    {
      "listen": "@trojan-ws",
      "protocol": "trojan",
      "settings": { "clients": [${trojan_clients}] },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": { "acceptProxyProtocol": true, "path": "/trojan-ws" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-05"
    },
    {
      "listen": "@vl-hup",
      "protocol": "vless",
      "settings": { "clients": [${vless_clients}], "decryption": "none" },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": { "acceptProxyProtocol": true, "path": "/vless-hup" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-08"
    },
    {
      "listen": "@vm-hup",
      "protocol": "vmess",
      "settings": { "clients": [${vmess_clients}] },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": { "acceptProxyProtocol": true, "path": "/vmess-hup" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-09"
    },
    {
      "listen": "@trojan-hup",
      "protocol": "trojan",
      "settings": { "clients": [${trojan_clients}] },
      "streamSettings": {
        "network": "httpupgrade",
        "security": "none",
        "httpupgradeSettings": { "acceptProxyProtocol": true, "path": "/trojan-hup" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-10"
    },
    {
      "listen": "127.0.0.1",
      "port": 5000,
      "protocol": "vless",
      "settings": { "clients": [${vless_clients}], "decryption": "none" },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": { "multiMode": true, "serviceName": "vless-grpc" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-13"
    },
    {
      "listen": "127.0.0.1",
      "port": 5100,
      "protocol": "vmess",
      "settings": { "clients": [${vmess_clients}] },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": { "multiMode": true, "serviceName": "vmess-grpc" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-14"
    },
    {
      "listen": "127.0.0.1",
      "port": 5200,
      "protocol": "trojan",
      "settings": { "clients": [${trojan_clients}] },
      "streamSettings": {
        "network": "grpc",
        "security": "none",
        "grpcSettings": { "multiMode": true, "serviceName": "trojan-grpc" }
      },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-15"
    },
    {
      "port": 80,
      "protocol": "vless",
      "settings": {
        "clients": [${vless_clients}],
        "decryption": "none",
        "fallbacks": [
          { "dest": 8080, "xver": 2 },
          { "path": "/vless-ws",   "dest": "@vless-ws",   "xver": 2 },
          { "path": "/vmess-ws",   "dest": "@vmess-ws",   "xver": 2 },
          { "path": "/trojan-ws",  "dest": "@trojan-ws",  "xver": 2 },
          { "path": "/vless-hup",  "dest": "@vl-hup",     "xver": 2 },
          { "path": "/vmess-hup",  "dest": "@vm-hup",     "xver": 2 },
          { "path": "/trojan-hup", "dest": "@trojan-hup", "xver": 2 }
        ]
      },
      "streamSettings": { "network": "tcp", "security": "none" },
      "sniffing": { "enabled": true, "destOverride": ["http","tls"] },
      "tag": "in-18"
    }
  ]
}
CFG

    # 05_outbounds.json
    cat > "$XRAY_CONF_DIR/05_outbonds.json" <<'OUT'
{
  "outbounds": [
    { "protocol": "freedom",   "tag": "direct"  },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
OUT

    # 06_routing.json
    cat > "$XRAY_CONF_DIR/06_routing.json" <<'ROUTE'
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "inboundTag": ["api"], "outboundTag": "api" },
      {
        "type": "field",
        "ip": ["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","100.64.0.0/10"],
        "outboundTag": "blocked"
      }
    ]
  }
}
ROUTE

    # 07_stats.json
    cat > "$XRAY_CONF_DIR/07_stats.json" <<'STATS'
{
  "stats": {}
}
STATS
}

write_nginx() {
    local domain; domain=$(get_domain)
    cat > /etc/nginx/nginx.conf <<NGX
user www-data;
pid /run/nginx.pid;
worker_processes auto;
worker_rlimit_nofile 65535;

events {
   multi_accept on;
   worker_connections 65535;
}

http {
   charset utf-8;
   sendfile on;
   tcp_nopush on;
   tcp_nodelay on;
   server_tokens off;
   types_hash_max_size 2048;
   client_max_body_size 16M;
   access_log /var/log/nginx/access.log;
   error_log  /var/log/nginx/error.log warn;
   gzip on;
   gzip_comp_level 5;
   gzip_proxied any;

   include /etc/nginx/conf.d/*.conf;
   include /etc/nginx/sites-enabled/*;

   upstream vless_grpc  { server 127.0.0.1:5000; }
   upstream vmess_grpc  { server 127.0.0.1:5100; }
   upstream trojan_grpc { server 127.0.0.1:5200; }

   server {
       listen 8443 proxy_protocol;
       http2 on;
       set_real_ip_from 127.0.0.1;
       real_ip_header proxy_protocol;
       server_name ${domain} *.${domain};
       root /var/www/html;
       index index.html;
       location /vless-grpc  { grpc_pass grpc://vless_grpc;  }
       location /vmess-grpc  { grpc_pass grpc://vmess_grpc;  }
       location /trojan-grpc { grpc_pass grpc://trojan_grpc; }
   }
   server {
       listen 8080 proxy_protocol default_server;
       listen 8443 proxy_protocol default_server;
       http2 on;
       set_real_ip_from 127.0.0.1;
       real_ip_header proxy_protocol;
   }
}
NGX
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null
    mkdir -p /var/www/html
    systemctl restart nginx 2>/dev/null
}

# ═════════════════════════════════════════════════════════════════
#  SSL via acme.sh (standalone — cocok untuk semua domain)
# ═════════════════════════════════════════════════════════════════
install_ssl() {
    local domain=$1
    info "Install acme.sh..."
    curl -s https://get.acme.sh | sh >/dev/null 2>&1
    source ~/.bashrc 2>/dev/null

    local acme="$HOME/.acme.sh/acme.sh"
    [[ ! -f "$acme" ]] && warn "acme.sh gagal install" && return 1

    "$acme" --register-account \
        -m "$(echo $RANDOM | md5sum | head -c 8)@gmail.com" \
        --server letsencrypt >/dev/null 2>&1

    systemctl stop nginx 2>/dev/null

    "$acme" --issue -d "$domain" --standalone \
        --server letsencrypt \
        --keylength ec-256 \
        --fullchain-file "$XRAY_CERT" \
        --key-file "$XRAY_KEY" \
        --reloadcmd "systemctl restart nginx xray" \
        --force 2>&1 | tail -5

    systemctl start nginx 2>/dev/null

    if [[ -s "$XRAY_CERT" ]]; then
        chmod 644 "$XRAY_CERT"
        chmod 600 "$XRAY_KEY"
        ok "SSL Let's Encrypt aktif untuk $domain"
        return 0
    else
        warn "SSL gagal — pakai self-signed"
        return 1
    fi
}

gen_selfsigned() {
    local domain=${1:-vpn-server}
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 3650 \
        -nodes -x509 -subj "/CN=${domain}" \
        -keyout "$XRAY_KEY" -out "$XRAY_CERT" >/dev/null 2>&1
    chmod 644 "$XRAY_CERT"; chmod 600 "$XRAY_KEY"
}

# ═════════════════════════════════════════════════════════════════
#  XRAY SERVICE
# ═════════════════════════════════════════════════════════════════
install_xray_service() {
    mkdir -p /var/log/xray
    touch /var/log/xray/access.log /var/log/xray/error.log
    chown nobody:nogroup /var/log/xray/*.log 2>/dev/null
    chmod 664 /var/log/xray/*.log 2>/dev/null

    cat > "$XRAY_SVC" <<SVC
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target
[Service]
User=nobody
Group=nogroup
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=${XRAY_BIN} run -confdir ${XRAY_CONF_DIR}/
RestartSec=5
Restart=always
StandardOutput=file:/var/log/xray/access.log
StandardError=file:/var/log/xray/error.log
LimitNOFILE=infinity
OOMScoreAdjust=100
[Install]
WantedBy=multi-user.target
SVC
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable xray >/dev/null 2>&1
}

# ═════════════════════════════════════════════════════════════════
#  BANDWIDTH TRACKING
# ═════════════════════════════════════════════════════════════════
bw_human() {
    local b=${1:-0}
    (( b >= 1073741824 )) && { printf "%.2f GB" "$(echo "scale=2;$b/1073741824"|bc 2>/dev/null||echo 0)"; return; }
    (( b >= 1048576    )) && { printf "%.2f MB" "$(echo "scale=2;$b/1048576"   |bc 2>/dev/null||echo 0)"; return; }
    (( b >= 1024       )) && { printf "%.2f KB" "$(echo "scale=2;$b/1024"      |bc 2>/dev/null||echo 0)"; return; }
    echo "${b} B"
}
bw_get() {
    local line; line=$(grep "^${1}|" "$BW_DB" 2>/dev/null)
    [[ -n "$line" ]] && echo "$line" || echo "${1}|0|0|$(date +%Y-%m-%d)"
}
bw_show() {
    local line; line=$(bw_get "$1")
    IFS='|' read -r _ up dn rd <<< "$line"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  BANDWIDTH — $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "Upload"   "$(bw_human ${up:-0})"
    kv "Download" "$(bw_human ${dn:-0})"
    kv "Total"    "$(bw_human $(( ${up:-0} + ${dn:-0} )))"
    kv "Sejak"    "$rd"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}
bw_reset() {
    sed -i "/^${1}|/d" "$BW_DB" 2>/dev/null
    echo "${1}|0|0|$(date +%Y-%m-%d)" >> "$BW_DB"
    ok "Bandwidth $1 di-reset."
}

# ═════════════════════════════════════════════════════════════════
#  LINK GENERATOR
# ═════════════════════════════════════════════════════════════════
_ue() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1" 2>/dev/null || echo "$1"; }

mk_vless_xtls() {
    local uuid=$1 host=$2 name=$3
    echo "vless://${uuid}@${host}:443?encryption=none&security=tls&type=tcp&flow=xtls-rprx-vision&sni=${host}#${name}-XTLS"
}
mk_vless_ws() {
    local uuid=$1 host=$2 port=$3 tls=$4 name=$5
    local sec; [[ "$tls" == tls ]] && sec="tls" || sec="none"
    local l="vless://${uuid}@${host}:${port}?encryption=none&security=${sec}&type=ws&path=$(_ue /vless-ws)"
    [[ "$tls" == tls ]] && l+="&sni=${host}"
    echo "${l}#${name}-VLess-WS-${port}"
}
mk_vless_hup() {
    local uuid=$1 host=$2 port=$3 tls=$4 name=$5
    local sec; [[ "$tls" == tls ]] && sec="tls" || sec="none"
    local l="vless://${uuid}@${host}:${port}?encryption=none&security=${sec}&type=httpupgrade&path=$(_ue /vless-hup)"
    [[ "$tls" == tls ]] && l+="&sni=${host}"
    echo "${l}#${name}-VLess-HUP-${port}"
}
mk_vless_grpc() {
    local uuid=$1 host=$2 name=$3
    echo "vless://${uuid}@${host}:443?encryption=none&security=tls&type=grpc&serviceName=vless-grpc&sni=${host}#${name}-VLess-gRPC"
}
mk_vmess_ws() {
    local uuid=$1 host=$2 port=$3 tls=$4 name=$5
    local t; [[ "$tls" == tls ]] && t="tls" || t="none"
    local j="{\"v\":\"2\",\"ps\":\"${name}-VMess-WS-${port}\",\"add\":\"${host}\",\"port\":\"${port}\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${host}\",\"path\":\"/vmess-ws\",\"tls\":\"${t}\"}"
    echo "vmess://$(printf '%s' "$j" | base64 | tr -d '\n')"
}
mk_vmess_hup() {
    local uuid=$1 host=$2 port=$3 tls=$4 name=$5
    local sec; [[ "$tls" == tls ]] && sec="tls" || sec="none"
    local l="vmess://${uuid}@${host}:${port}?type=httpupgrade&path=$(_ue /vmess-hup)&security=${sec}"
    [[ "$tls" == tls ]] && l+="&sni=${host}"
    echo "${l}#${name}-VMess-HUP-${port}"
}
mk_vmess_grpc() {
    local uuid=$1 host=$2 name=$3
    local j="{\"v\":\"2\",\"ps\":\"${name}-VMess-gRPC\",\"add\":\"${host}\",\"port\":\"443\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"${host}\",\"path\":\"vmess-grpc\",\"tls\":\"tls\"}"
    echo "vmess://$(printf '%s' "$j" | base64 | tr -d '\n')"
}
mk_trojan_tcp() {
    local pw=$1 host=$2 name=$3
    echo "trojan://${pw}@${host}:443?security=tls&type=tcp&sni=${host}#${name}-Trojan-TCP"
}
mk_trojan_ws() {
    local pw=$1 host=$2 port=$3 tls=$4 name=$5
    local sec; [[ "$tls" == tls ]] && sec="tls" || sec="none"
    local l="trojan://${pw}@${host}:${port}?security=${sec}&type=ws&path=$(_ue /trojan-ws)"
    [[ "$tls" == tls ]] && l+="&sni=${host}"
    echo "${l}#${name}-Trojan-WS-${port}"
}
mk_trojan_hup() {
    local pw=$1 host=$2 port=$3 tls=$4 name=$5
    local sec; [[ "$tls" == tls ]] && sec="tls" || sec="none"
    local l="trojan://${pw}@${host}:${port}?security=${sec}&type=httpupgrade&path=$(_ue /trojan-hup)"
    [[ "$tls" == tls ]] && l+="&sni=${host}"
    echo "${l}#${name}-Trojan-HUP-${port}"
}
mk_trojan_grpc() {
    local pw=$1 host=$2 name=$3
    echo "trojan://${pw}@${host}:443?security=tls&type=grpc&serviceName=trojan-grpc&sni=${host}#${name}-Trojan-gRPC"
}

# ═════════════════════════════════════════════════════════════════
#  AUTO INSTALL
# ═════════════════════════════════════════════════════════════════
do_install() {
    clear
    echo -e "${CYN}"
    echo "  ╔══════════════════════════════════════════╗"
    echo -e "  ║  ${WHT}ZivPanel v4.0 — Instalasi Awal${NC}${CYN}         ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  • ZIVPN UDP  (port 5667 + 6000-19999)  ║"
    echo "  ║  • Xray XTLS-Vision + WS + HUP + gRPC   ║"
    echo "  ║  • SSL via acme.sh (Let's Encrypt)       ║"
    echo "  ║  • Nginx (gRPC proxy)                    ║"
    echo "  ║  • Anti-DDoS + Fail2Ban + WARP           ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    confirm "Mulai instalasi?" || { echo "  Dibatalkan."; exit 0; }

    echo ""
    local pub_ip; pub_ip=$(get_pub_ip)
    echo "  IP Server : $pub_ip"

    # Input domain
    local domain
    while true; do
        read -rp "  Domain (wajib, cth: vpn.example.com): " domain
        domain=$(echo "$domain" | tr -d '\r ')
        [[ -z "$domain" ]] && warn "Domain tidak boleh kosong!" && continue
        [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && break
        warn "Format domain tidak valid!"
    done
    info "Mendeteksi ISP..."
    local isp; isp=$(fetch_isp "$pub_ip")
    echo "  ISP       : $isp"
    read -rp "  Ubah nama ISP? (Enter = pakai): " isp_in
    isp_in=$(echo "$isp_in" | tr -d '\r')
    [[ -n "$isp_in" ]] && isp="$isp_in"
    mkdir -p "$XRAY_DIR/dns"
    echo "$domain" > "$DOMAIN_FILE"
    save_conf "$domain" "$isp"
    echo ""

    # [1/10] Paket sistem
    echo "[1/10] Update & install paket sistem..."
    timedatectl set-timezone Asia/Jakarta 2>/dev/null
    echo "iptables-persistent iptables/autosave_v4 boolean true"  | debconf-set-selections
    echo "iptables-persistent iptables/autosave_v6 boolean false" | debconf-set-selections
    DEBIAN_FRONTEND=noninteractive apt-get update  -y >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl wget unzip openssl python3 bc socat uuid-runtime \
        net-tools iptables-persistent nginx fail2ban jq vnstat lsof \
        build-essential >/dev/null 2>&1
    ok "Paket sistem selesai"

    # [2/10] Nginx mainline
    echo "[2/10] Install Nginx mainline..."
    local os_id; os_id=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    curl -fsSL https://nginx.org/keys/nginx_signing.key 2>/dev/null \
        | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/mainline/${os_id} $(lsb_release -cs) nginx" \
        > /etc/apt/sources.list.d/nginx.list 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx >/dev/null 2>&1
    ok "Nginx siap"

    # [3/10] ZIVPN
    echo "[3/10] Install ZIVPN UDP..."
    systemctl stop zivpn 2>/dev/null
    wget -q "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64" \
        -O "$ZIVPN_BIN" || die "Gagal download ZIVPN"
    chmod +x "$ZIVPN_BIN"
    mkdir -p /etc/zivpn
    cat > "$ZIVPN_CONF" <<'JSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": { "mode": "passwords", "config": ["zi"] }
}
JSON
    openssl req -newkey rsa:2048 -days 3650 -nodes -x509 \
        -subj "/C=US/ST=CA/L=LA/O=VPN/CN=zivpn" \
        -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt >/dev/null 2>&1
    cat > "$ZIVPN_SVC" <<'SVC'
[Unit]
Description=ZIVPN UDP Server
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
SVC
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable zivpn >/dev/null 2>&1
    systemctl start  zivpn
    sleep 1
    systemctl is-active --quiet zivpn && ok "ZIVPN aktif" || warn "ZIVPN belum aktif"

    # [4/10] Xray binary
    echo "[4/10] Download Xray-core..."
    local tmp; tmp=$(mktemp -d)
    local xurl
    xurl=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases/latest" \
        | python3 -c "
import json,sys
d=json.load(sys.stdin)
[print(a['browser_download_url']) for a in d.get('assets',[]) if 'Xray-linux-64.zip' in a['name']]
" 2>/dev/null | head -1)
    [[ -z "$xurl" ]] && xurl="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    wget -q "$xurl" -O "${tmp}/xray.zip"
    if [[ $? -eq 0 ]]; then
        unzip -q "${tmp}/xray.zip" -d "${tmp}/x"
        cp "${tmp}/x/xray" "$XRAY_BIN" && chmod +x "$XRAY_BIN"
        ok "Xray binary siap: $($XRAY_BIN version 2>/dev/null | head -1)"
    else
        die "Gagal download Xray"
    fi
    rm -rf "$tmp"

    # [5/10] SSL
    echo "[5/10] Buat SSL certificate..."
    systemctl stop nginx 2>/dev/null
    if ! install_ssl "$domain"; then
        warn "Fallback ke self-signed cert"
        gen_selfsigned "$domain"
    fi
    systemctl start nginx 2>/dev/null

    # [6/10] Xray config + service
    echo "[6/10] Konfigurasi Xray..."
    write_xray_config
    install_xray_service
    systemctl start xray
    sleep 2
    systemctl is-active --quiet xray && ok "Xray aktif" \
        || { warn "Xray gagal — cek: journalctl -u xray -n 20"; }

    # [7/10] Nginx config
    echo "[7/10] Konfigurasi Nginx..."
    write_nginx
    systemctl restart nginx 2>/dev/null
    ok "Nginx siap"

    # [8/10] WARP (WireProxy)
    echo "[8/10] Install WARP via WireProxy..."
    wget -q "https://github.com/dugong-lewat/1clickxray/raw/main/wireproxy" \
        -O /usr/local/bin/wireproxy 2>/dev/null && chmod +x /usr/local/bin/wireproxy
    if [[ -x /usr/local/bin/wireproxy ]]; then
        cat > /etc/wireproxy.conf <<'WARP'
[Interface]
PrivateKey = 4Osd07VYMrPGDtrJfRaRZ+ynuscBVi4PjzOZmLUJDlE=
Address = 172.16.0.2/32, 2606:4700:110:8fdc:f256:b15d:9e5c:5d1/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
Endpoint = engage.cloudflareclient.com:2408
[Socks5]
BindAddress = 127.0.0.1:40000
WARP
        cat > /etc/systemd/system/wireproxy.service <<'WSVC'
[Unit]
Description=WireProxy WARP
After=network.target
[Service]
ExecStart=/usr/local/bin/wireproxy -c /etc/wireproxy.conf
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
WSVC
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable wireproxy >/dev/null 2>&1
        systemctl start  wireproxy
        sleep 1
        systemctl is-active --quiet wireproxy && ok "WARP aktif" || warn "WARP gagal"
    else
        warn "WireProxy gagal download — WARP dilewati"
    fi

    # [9/10] NAT + Anti-DDoS
    echo "[9/10] NAT + Anti-DDoS..."
    cat > /etc/sysctl.d/99-zivpanel.conf <<'SC'
net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
SC
    sysctl -p /etc/sysctl.d/99-zivpanel.conf >/dev/null 2>&1
    local iface; iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    iptables -t nat -C PREROUTING -i "$iface" -p udp --dport 6000:19999 \
        -j DNAT --to-destination :5667 2>/dev/null \
        || iptables -t nat -A PREROUTING -i "$iface" -p udp \
           --dport 6000:19999 -j DNAT --to-destination :5667
    iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE
    write_antiddos; bash "$ANTIDDOS"
    write_restore_nat
    # Blokir torrent
    iptables -A INPUT -p udp --dport 6881:6889 -j DROP 2>/dev/null
    iptables -A INPUT -p tcp --dport 6881:6889 -j DROP 2>/dev/null
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1 && {
        cat > /etc/fail2ban/jail.local <<'F2B'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1
[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 86400
F2B
        systemctl restart fail2ban 2>/dev/null; systemctl enable fail2ban 2>/dev/null
    }
    ok "NAT + Anti-DDoS aktif"

    # [10/10] Enforcement + cron
    echo "[10/10] Enforcement + cron..."
    install_enforcement >/dev/null 2>&1
    # cron xp (expire check) tiap midnight
    grep -q "zivpanel-expire" /etc/crontab 2>/dev/null \
        || echo "0 0 * * * root $ENFORCE_EXPIRE >/dev/null 2>&1" >> /etc/crontab
    systemctl restart cron 2>/dev/null
    ok "Enforcement aktif"

    touch "$INSTALLED_FLAG"

    # Summary
    local sz; systemctl is-active --quiet zivpn  && sz="${GRN}Running${NC}" || sz="${RED}Stopped${NC}"
    local sx; systemctl is-active --quiet xray   && sx="${GRN}Running${NC}" || sx="${RED}Stopped${NC}"
    local sw; systemctl is-active --quiet wireproxy && sw="${GRN}Running${NC}" || sw="${YLW}Stopped${NC}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "     INSTALASI SELESAI"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "Domain"    "$domain"
    kv "ISP"       "$isp"
    kv "ZIVPN"     "Port 5667 + 6000-19999 UDP"
    printf "%-14s: " "ZIVPN svc";    echo -e "${sz}"
    printf "%-14s: " "Xray svc";     echo -e "${sx}"
    printf "%-14s: " "WARP svc";     echo -e "${sw}"
    kv "Nginx"     "Port 8080+8443 (gRPC proxy)"
    kv "Xray port" "80 + 443 (langsung)"
    kv "Anti-DDoS" "Aktif"
    kv "SSL"       "$(ls -la $XRAY_CERT 2>/dev/null | awk '{print $5}') bytes"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    ok "Ketik 'zivpanel' untuk buka panel"
    echo ""; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  BANNER
# ═════════════════════════════════════════════════════════════════
show_banner() {
    clear
    local ip os upt sz sx sw uz xz ddos
    ip=$(get_pub_ip)
    os=$(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
    upt=$(uptime -p 2>/dev/null | sed 's/up //')
    uz=$(count_db "$USER_DB"); xz=$(count_db "$XRAY_DB")
    systemctl is-active --quiet zivpn    && sz="${GRN}OK${NC}" || sz="${RED}OFF${NC}"
    systemctl is-active --quiet xray     && sx="${GRN}OK${NC}" || sx="${RED}OFF${NC}"
    systemctl is-active --quiet wireproxy && sw="${GRN}OK${NC}" || sw="${YLW}--${NC}"
    iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|limit" \
        && ddos="${GRN}ON${NC}" || ddos="${RED}OFF${NC}"

    echo -e "${CYN}"
    echo "  ╔══════════════════════════════════════════╗"
    echo -e "  ║  ${WHT}ZivPanel v4.0  •  VPN Management${NC}${CYN}       ║"
    echo "  ╠══════════════════════════════════════════╣"
    printf  "  ║  %-8s : %-31s║\n" "IP"     "$ip"
    printf  "  ║  %-8s : %-31s║\n" "Domain" "$(get_domain)"
    printf  "  ║  %-8s : %-31s║\n" "ISP"    "$(get_isp)"
    printf  "  ║  %-8s : %-31s║\n" "OS"     "$os"
    printf  "  ║  %-8s : %-31s║\n" "Uptime" "$upt"
    echo -e "  ║  ZIVPN:${sz}${CYN}(${uz}ak) Xray:${sx}${CYN}(${xz}ak) WARP:${sw}${CYN} DDoS:${ddos}${CYN}  ║"
    echo    "  ╠══════════════════════════════════════════╣"
    echo -e "  ║  ${GRN}[1]${NC}${CYN}  Buat Akun ZIVPN                       ║"
    echo -e "  ║  ${GRN}[2]${NC}${CYN}  Buat Akun Xray                        ║"
    echo -e "  ║  ${GRN}[3]${NC}${CYN}  Detail Akun ZIVPN                     ║"
    echo -e "  ║  ${GRN}[4]${NC}${CYN}  Detail Akun Xray + Link               ║"
    echo -e "  ║  ${RED}[5]${NC}${CYN}  Hapus Akun ZIVPN                      ║"
    echo -e "  ║  ${RED}[6]${NC}${CYN}  Hapus Akun Xray                       ║"
    echo    "  ╠══════════════════════════════════════════╣"
    echo -e "  ║  ${YLW}[7]${NC}${CYN}  Ubah Domain/ISP                       ║"
    echo -e "  ║  ${YLW}[8]${NC}${CYN}  Service Management                    ║"
    echo -e "  ║  ${YLW}[9]${NC}${CYN}  Info VPS                              ║"
    echo -e "  ║  ${YLW}[10]${NC}${CYN} Auto Reboot                           ║"
    echo    "  ╠══════════════════════════════════════════╣"
    echo -e "  ║  ${CYN}[11]${NC}${CYN} Update ZIVPN    ${CYN}[12]${NC}${CYN} Update Xray      ║"
    echo -e "  ║  ${CYN}[13]${NC}${CYN} Renew SSL                             ║"
    echo -e "  ║  ${RED}[14]${NC}${CYN} Hapus ZIVPN     ${RED}[15]${NC}${CYN} Hapus Panel      ║"
    echo -e "  ║  ${WHT}[x]${NC}${CYN}  Keluar                                ║"
    echo    "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ═════════════════════════════════════════════════════════════════
#  [1] BUAT AKUN ZIVPN
# ═════════════════════════════════════════════════════════════════
menu_create_zivpn() {
    clear; echo -e "${CYN}[ BUAT AKUN ZIVPN UDP ]${NC}\n"
    [[ ! -x "$ZIVPN_BIN" ]] && warn "ZIVPN belum terinstall!" && press_enter && return
    local u pw pw2 days quota maxip
    while true; do
        read -rp "  Username      : " u; u=$(echo "$u"|tr -d '\r ')
        [[ -z "$u" ]]                            && warn "Username kosong!"    && continue
        grep -q "^${u}|" "$USER_DB" 2>/dev/null && warn "Username sudah ada!" && continue
        break
    done
    while true; do
        read -rsp "  Password      : " pw; echo; pw=$(echo "$pw"|tr -d '\r')
        [[ -z "$pw" ]] && warn "Password kosong!" && continue
        read -rsp "  Konfirmasi    : " pw2; echo; pw2=$(echo "$pw2"|tr -d '\r')
        [[ "$pw" != "$pw2" ]] && warn "Password tidak cocok!" && continue
        break
    done
    while true; do
        read -rp "  Expired (hari): " days; days=$(echo "$days"|tr -d '\r ')
        [[ "$days" =~ ^[0-9]+$ && $days -gt 0 ]] && break; warn "Angka > 0"
    done
    while true; do
        read -rp "  Quota GB (0=∞): " quota; quota=$(echo "$quota"|tr -d '\r ')
        [[ "$quota" =~ ^[0-9]+$ ]] && break; warn "Masukkan angka"
    done
    while true; do
        read -rp "  Limit IP (0=∞): " maxip; maxip=$(echo "$maxip"|tr -d '\r ')
        [[ "$maxip" =~ ^[0-9]+$ ]] && break; warn "Masukkan angka"
    done
    local exp; exp=$(date -d "+${days} days" +%Y-%m-%d)
    local now; now=$(date +%Y-%m-%d)
    echo "${u}|${pw}|${exp}|${quota}|${maxip}|${now}" >> "$USER_DB"
    if [[ -f "$ZIVPN_CONF" ]]; then
        export _ZPW="$pw"
        python3 -c "
import json,os
p=os.environ.get('_ZPW','')
with open('$ZIVPN_CONF') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if p and p not in pw: pw.append(p)
c['auth']['config']=pw
with open('$ZIVPN_CONF','w') as f: json.dump(c,f,indent=2)
" 2>/dev/null
        systemctl restart zivpn &>/dev/null
    fi
    local ql; [[ "$quota" -eq 0 ]] && ql="Unlimited" || ql="${quota} GB"
    local il; [[ "$maxip"  -eq 0 ]] && il="Unlimited" || il="${maxip} Device"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "       ZIVPN UDP ACCOUNT"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "Domain"   "$(get_domain)"; kv "ISP"      "$(get_isp)"
    kv "Username" "$u";            kv "Password" "$pw"
    kv "Quota"    "$ql";           kv "Limit IP" "$il"
    kv "Expired"  "$exp"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [2] BUAT AKUN XRAY
# ═════════════════════════════════════════════════════════════════
menu_create_xray() {
    clear; echo -e "${CYN}[ BUAT AKUN XRAY ]${NC}\n"
    [[ ! -x "$XRAY_BIN" ]] && warn "Xray belum terinstall!" && press_enter && return

    echo "  Pilih protokol utama (UUID/password berlaku untuk semua transport):"
    echo "  [1] VLess (XTLS-Vision + WS + HTTPUpgrade + gRPC)"
    echo "  [2] VMess (WS + HTTPUpgrade + gRPC)"
    echo "  [3] Trojan (TCP + WS + HTTPUpgrade + gRPC)"
    echo ""
    local proto
    while true; do
        read -rp "  Pilih [1-3]: " _p; _p=$(echo "$_p"|tr -d '\r ')
        case "$_p" in
            1) proto="vless"  && break ;;
            2) proto="vmess"  && break ;;
            3) proto="trojan" && break ;;
            *) warn "Pilih 1, 2, atau 3" ;;
        esac
    done

    local u
    while true; do
        read -rp "  Username      : " u; u=$(echo "$u"|tr -d '\r ')
        [[ -z "$u" ]]                             && warn "Username kosong!"    && continue
        grep -q "^${u}|" "$XRAY_DB" 2>/dev/null  && warn "Username sudah ada!" && continue
        break
    done
    local days
    while true; do
        read -rp "  Expired (hari): " days; days=$(echo "$days"|tr -d '\r ')
        [[ "$days" =~ ^[0-9]+$ && $days -gt 0 ]] && break; warn "Angka > 0"
    done

    local uuid; uuid=$(make_uuid)
    [[ -z "$uuid" ]] && warn "Gagal generate UUID! Install uuid-runtime" && press_enter && return
    local trj_pw; trj_pw=$(openssl rand -hex 16 | tr -d '\r\n')
    local exp; exp=$(date -d "+${days} days" +%Y-%m-%d | tr -d '\r\n')
    local now; now=$(date +%Y-%m-%d | tr -d '\r\n')
    proto=$(echo "$proto" | tr -d '\r\n')

    echo "${u}|${uuid}|${trj_pw}|${proto}|${exp}|${now}" >> "$XRAY_DB"
    echo "${u}|0|0|${now}" >> "$BW_DB"

    write_xray_config
    systemctl restart xray &>/dev/null
    sleep 1

    _show_xray_account "$u" "$uuid" "$trj_pw" "$proto" "$exp"
    press_enter
}

_show_xray_account() {
    local u;    u=$(echo    "$1"|tr -d '\r')
    local uuid; uuid=$(echo "$2"|tr -d '\r')
    local pw;   pw=$(echo   "$3"|tr -d '\r')
    local proto; proto=$(echo "$4"|tr -d '\r')
    local exp;  exp=$(echo  "$5"|tr -d '\r')
    local host; host=$(get_domain)
    local isp;  isp=$(get_isp)
    local sisa; sisa=$(days_left "$exp")

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "     XRAY ACCOUNT — ${proto^^}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "Domain"  "$host"; kv "ISP" "$isp"
    kv "User"    "$u";    kv "Proto" "${proto^^}"
    kv "Expired" "$exp ($sisa hari)"

    case "$proto" in
    vless)
        kv "UUID"    "$uuid"
        echo "────────────────────────────────"
        echo "── XTLS-Vision port 443 :"
        mk_vless_xtls   "$uuid" "$host" "$u"
        echo "── VLess WS port 443 (TLS) :"
        mk_vless_ws     "$uuid" "$host" 443 tls "$u"
        echo "── VLess WS port 80 :"
        mk_vless_ws     "$uuid" "$host" 80  ""  "$u"
        echo "── VLess HTTPUpgrade port 443 (TLS) :"
        mk_vless_hup    "$uuid" "$host" 443 tls "$u"
        echo "── VLess HTTPUpgrade port 80 :"
        mk_vless_hup    "$uuid" "$host" 80  ""  "$u"
        echo "── VLess gRPC port 443 :"
        mk_vless_grpc   "$uuid" "$host" "$u"
        ;;
    vmess)
        kv "UUID"    "$uuid"
        echo "────────────────────────────────"
        echo "── VMess WS port 443 (TLS) :"
        mk_vmess_ws     "$uuid" "$host" 443 tls "$u"
        echo "── VMess WS port 80 :"
        mk_vmess_ws     "$uuid" "$host" 80  ""  "$u"
        echo "── VMess HTTPUpgrade port 443 (TLS) :"
        mk_vmess_hup    "$uuid" "$host" 443 tls "$u"
        echo "── VMess HTTPUpgrade port 80 :"
        mk_vmess_hup    "$uuid" "$host" 80  ""  "$u"
        echo "── VMess gRPC port 443 :"
        mk_vmess_grpc   "$uuid" "$host" "$u"
        ;;
    trojan)
        kv "Password" "$pw"
        echo "────────────────────────────────"
        echo "── Trojan TCP port 443 (TLS) :"
        mk_trojan_tcp   "$pw" "$host" "$u"
        echo "── Trojan WS port 443 (TLS) :"
        mk_trojan_ws    "$pw" "$host" 443 tls "$u"
        echo "── Trojan WS port 80 :"
        mk_trojan_ws    "$pw" "$host" 80  ""  "$u"
        echo "── Trojan HTTPUpgrade port 443 (TLS) :"
        mk_trojan_hup   "$pw" "$host" 443 tls "$u"
        echo "── Trojan HTTPUpgrade port 80 :"
        mk_trojan_hup   "$pw" "$host" 80  ""  "$u"
        echo "── Trojan gRPC port 443 :"
        mk_trojan_grpc  "$pw" "$host" "$u"
        ;;
    *) warn "Protokol tidak dikenal: [$proto]" ;;
    esac
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# ═════════════════════════════════════════════════════════════════
#  [3] DETAIL AKUN ZIVPN
# ═════════════════════════════════════════════════════════════════
menu_detail_zivpn() {
    clear; echo -e "${CYN}[ AKUN ZIVPN UDP ]${NC}\n"
    [[ ! -s "$USER_DB" ]] && warn "Belum ada akun." && press_enter && return
    printf "  %-3s  %-16s  %-12s  %-8s  %-9s  %-9s\n" \
        "No" "Username" "Expired" "Sisa" "Quota" "LimitIP"
    echo "  ───  ────────────────  ────────────  ────────  ─────────  ─────────"
    local no=1
    while IFS='|' read -r u pw exp q mi cr; do
        u=$(echo "$u"|tr -d '\r')
        local sisa; sisa=$(days_left "$exp")
        local ss; [[ $sisa -lt 0 ]] && ss="EXPIRED" || ss="${sisa}hr"
        local ql; [[ "$q"  -eq 0 ]] && ql="Unlim" || ql="${q}GB"
        local il; [[ "$mi" -eq 0 ]] && il="Unlim" || il="${mi}dev"
        printf "  %-3s  %-16s  %-12s  %-8s  %-9s  %-9s\n" \
            "$no" "$u" "$exp" "$ss" "$ql" "$il"
        ((no++))
    done < "$USER_DB"
    echo ""; echo "  Total: $((no-1)) akun"
    echo ""; read -rp "  Username detail (Enter=kembali): " _u
    [[ -z "$_u" ]] && return
    _u=$(echo "$_u"|tr -d '\r ')
    local line; line=$(grep "^${_u}|" "$USER_DB")
    [[ -z "$line" ]] && warn "Tidak ditemukan!" && press_enter && return
    IFS='|' read -r u pw exp q mi cr <<< "$line"
    local sisa; sisa=$(days_left "$exp")
    local ql; [[ "$q"  -eq 0 ]] && ql="Unlimited" || ql="${q} GB"
    local il; [[ "$mi" -eq 0 ]] && il="Unlimited" || il="${mi} Device"
    local st; [[ $sisa -lt 0 ]] && st="EXPIRED" || st="Aktif ($sisa hari)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "Domain"   "$(get_domain)"; kv "ISP"      "$(get_isp)"
    kv "Username" "$u";            kv "Password" "$pw"
    kv "Quota"    "$ql";           kv "LimitIP"  "$il"
    kv "Expired"  "$exp";          kv "Status"   "$st"
    kv "Port UDP" "5667 (+ 6000-19999)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  [1] Perpanjang  [2] Ganti password  [3] Ubah quota  [4] Ubah limit IP  [0] Kembali"
    read -rp "  Pilih: " opt
    case "$opt" in
        1) _zivpn_extend  "$u" "$exp" ;;
        2) _zivpn_chpass  "$u" "$pw"  ;;
        3) _zivpn_chquota "$u"        ;;
        4) _zivpn_chmaxip "$u"        ;;
    esac
}

_zivpn_extend() {
    read -rp "  Tambah hari: " d; d=$(echo "$d"|tr -d '\r ')
    [[ ! "$d" =~ ^[0-9]+$ ]] && warn "Invalid!" && return
    local ne; ne=$(date -d "${2} +${d} days" +%Y-%m-%d)
    awk -F'|' -v u="$1" -v ne="$ne" 'BEGIN{OFS="|"} $1==u{$3=ne}1' \
        "$USER_DB" > /tmp/_zp.$$ && mv /tmp/_zp.$$ "$USER_DB"
    local p; p=$(grep "^${1}|" "$USER_DB" | cut -d'|' -f2 | tr -d '\r')
    export _ZPW="$p"
    python3 -c "
import json,os
p=os.environ.get('_ZPW','')
with open('$ZIVPN_CONF') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if p and p not in pw: pw.append(p)
c['auth']['config']=pw
with open('$ZIVPN_CONF','w') as f: json.dump(c,f,indent=2)
" 2>/dev/null
    systemctl restart zivpn &>/dev/null
    ok "Expired baru: $ne"; press_enter
}
_zivpn_chpass() {
    local old=$2
    read -rsp "  Password baru: " np; echo; np=$(echo "$np"|tr -d '\r')
    [[ -z "$np" ]] && return
    awk -F'|' -v u="$1" -v np="$np" 'BEGIN{OFS="|"} $1==u{$2=np}1' \
        "$USER_DB" > /tmp/_zp.$$ && mv /tmp/_zp.$$ "$USER_DB"
    OLD_PW="$old" NEW_PW="$np" python3 -c "
import json,os
o=os.environ.get('OLD_PW',''); n=os.environ.get('NEW_PW','')
with open('$ZIVPN_CONF') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if o and o in pw: pw.remove(o)
if n and n not in pw: pw.append(n)
c['auth']['config']=pw
with open('$ZIVPN_CONF','w') as f: json.dump(c,f,indent=2)
" 2>/dev/null
    systemctl restart zivpn &>/dev/null
    ok "Password diubah!"; press_enter
}
_zivpn_chquota() {
    read -rp "  Quota baru GB (0=∞): " nq; nq=$(echo "$nq"|tr -d '\r ')
    [[ ! "$nq" =~ ^[0-9]+$ ]] && return
    awk -F'|' -v u="$1" -v nq="$nq" 'BEGIN{OFS="|"} $1==u{$4=nq}1' \
        "$USER_DB" > /tmp/_zp.$$ && mv /tmp/_zp.$$ "$USER_DB"
    ok "Quota: ${nq} GB"; press_enter
}
_zivpn_chmaxip() {
    read -rp "  Limit IP baru (0=∞): " ni; ni=$(echo "$ni"|tr -d '\r ')
    [[ ! "$ni" =~ ^[0-9]+$ ]] && return
    awk -F'|' -v u="$1" -v ni="$ni" 'BEGIN{OFS="|"} $1==u{$5=ni}1' \
        "$USER_DB" > /tmp/_zp.$$ && mv /tmp/_zp.$$ "$USER_DB"
    ok "Limit IP: $ni"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [4] DETAIL AKUN XRAY
# ═════════════════════════════════════════════════════════════════
menu_detail_xray() {
    clear; echo -e "${CYN}[ AKUN XRAY ]${NC}\n"
    [[ ! -s "$XRAY_DB" ]] && warn "Belum ada akun." && press_enter && return
    printf "  %-3s  %-14s  %-7s  %-8s  %-10s\n" "No" "Username" "Proto" "Sisa" "Expired"
    echo "  ───  ──────────────  ───────  ────────  ──────────"
    local no=1
    while IFS='|' read -r u uuid pw proto exp cr; do
        u=$(echo "$u"|tr -d '\r'); proto=$(echo "$proto"|tr -d '\r')
        local sisa; sisa=$(days_left "$exp")
        local ss; [[ $sisa -lt 0 ]] && ss="EXPIRED" || ss="${sisa}hr"
        printf "  %-3s  %-14s  %-7s  %-8s  %-10s\n" "$no" "$u" "${proto^^}" "$ss" "$exp"
        ((no++))
    done < "$XRAY_DB"
    echo ""; echo "  Total: $((no-1)) akun"
    echo ""; read -rp "  Username detail (Enter=kembali): " _u
    [[ -z "$_u" ]] && return
    _u=$(echo "$_u"|tr -d '\r ')
    local line; line=$(grep "^${_u}|" "$XRAY_DB")
    [[ -z "$line" ]] && warn "Tidak ditemukan!" && press_enter && return
    IFS='|' read -r u uuid pw proto exp cr <<< "$line"
    _show_xray_account "$u" "$uuid" "$pw" "$proto" "$exp"
    bw_show "$u"
    echo "  [1] Perpanjang  [2] Reset BW  [0] Kembali"
    read -rp "  Pilih: " opt
    case "$opt" in
        1)
            read -rp "  Tambah hari: " d; d=$(echo "$d"|tr -d '\r ')
            [[ ! "$d" =~ ^[0-9]+$ ]] && press_enter && return
            local ne; ne=$(date -d "${exp} +${d} days" +%Y-%m-%d)
            awk -F'|' -v u="$u" -v ne="$ne" 'BEGIN{OFS="|"} $1==u{$5=ne}1' \
                "$XRAY_DB" > /tmp/_xp.$$ && mv /tmp/_xp.$$ "$XRAY_DB"
            write_xray_config; systemctl restart xray &>/dev/null
            ok "Expired baru: $ne"; press_enter
            ;;
        2) bw_reset "$u"; press_enter ;;
    esac
}

# ═════════════════════════════════════════════════════════════════
#  [5] HAPUS AKUN ZIVPN
# ═════════════════════════════════════════════════════════════════
menu_del_zivpn() {
    clear; echo -e "${CYN}[ HAPUS AKUN ZIVPN ]${NC}\n"
    [[ ! -s "$USER_DB" ]] && warn "Belum ada akun." && press_enter && return
    local no=1
    while IFS='|' read -r u rest; do
        u=$(echo "$u"|tr -d '\r')
        printf "  [%s] %s\n" "$no" "$u"; ((no++))
    done < "$USER_DB"
    echo ""; read -rp "  Username: " _u; _u=$(echo "$_u"|tr -d '\r ')
    local line; line=$(grep "^${_u}|" "$USER_DB")
    [[ -z "$line" ]] && warn "Tidak ditemukan!" && press_enter && return
    local pw; pw=$(echo "$line"|cut -d'|' -f2|tr -d '\r')
    confirm "Yakin hapus '$_u'?" || return
    export _ZPW="$pw"
    python3 -c "
import json,os
p=os.environ.get('_ZPW','')
with open('$ZIVPN_CONF') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if p and p in pw: pw.remove(p)
if not pw: pw.append('zi')
c['auth']['config']=pw
with open('$ZIVPN_CONF','w') as f: json.dump(c,f,indent=2)
" 2>/dev/null
    systemctl restart zivpn &>/dev/null
    sed -i "/^${_u}|/d" "$USER_DB"
    ok "Akun '$_u' dihapus!"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [6] HAPUS AKUN XRAY
# ═════════════════════════════════════════════════════════════════
menu_del_xray() {
    clear; echo -e "${CYN}[ HAPUS AKUN XRAY ]${NC}\n"
    [[ ! -s "$XRAY_DB" ]] && warn "Belum ada akun." && press_enter && return
    local no=1
    while IFS='|' read -r u _ _ proto rest; do
        u=$(echo "$u"|tr -d '\r'); proto=$(echo "$proto"|tr -d '\r')
        printf "  [%s] %-16s  %s\n" "$no" "$u" "${proto^^}"; ((no++))
    done < "$XRAY_DB"
    echo ""; read -rp "  Username: " _u; _u=$(echo "$_u"|tr -d '\r ')
    grep -q "^${_u}|" "$XRAY_DB" || { warn "Tidak ditemukan!"; press_enter; return; }
    confirm "Yakin hapus '$_u'?" || return
    sed -i "/^${_u}|/d" "$XRAY_DB"
    sed -i "/^${_u}|/d" "$BW_DB"
    write_xray_config
    systemctl restart xray &>/dev/null
    ok "Akun '$_u' dihapus!"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [7] UBAH DOMAIN/ISP
# ═════════════════════════════════════════════════════════════════
menu_change_host() {
    clear; echo -e "${CYN}[ UBAH DOMAIN / ISP ]${NC}\n"
    echo "  Domain saat ini : $(get_domain)"
    echo "  ISP saat ini    : $(get_isp)"; echo ""
    read -rp "  Domain baru (Enter=skip): " nd; nd=$(echo "$nd"|tr -d '\r ')
    [[ -z "$nd" ]] && nd=$(get_domain)
    local ni
    echo "  [1] Auto deteksi ISP  [2] Input manual"
    read -rp "  Pilih: " opt
    if [[ "$opt" == "2" ]]; then
        read -rp "  ISP baru: " ni; ni=$(echo "$ni"|tr -d '\r')
        [[ -z "$ni" ]] && ni=$(get_isp)
    else
        ni=$(fetch_isp "$(get_pub_ip)"); echo "  ISP: $ni"
        read -rp "  Ubah? (Enter=pakai): " ov; ov=$(echo "$ov"|tr -d '\r')
        [[ -n "$ov" ]] && ni="$ov"
    fi
    echo "$nd" > "$DOMAIN_FILE"
    save_conf "$nd" "$ni"
    write_nginx 2>/dev/null
    write_xray_config
    systemctl restart xray &>/dev/null
    ok "Domain: $nd | ISP: $ni"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [8] SERVICE MANAGEMENT
# ═════════════════════════════════════════════════════════════════
menu_service() {
    while true; do
        clear; echo -e "${CYN}[ SERVICE MANAGEMENT ]${NC}\n"
        local sz sx sw
        systemctl is-active --quiet zivpn    && sz="${GRN}Running${NC}" || sz="${RED}Stopped${NC}"
        systemctl is-active --quiet xray     && sx="${GRN}Running${NC}" || sx="${RED}Stopped${NC}"
        systemctl is-active --quiet wireproxy && sw="${GRN}Running${NC}" || sw="${YLW}Stopped${NC}"
        echo -e "  ZIVPN: ${sz}   Xray: ${sx}   WARP: ${sw}\n"
        echo "  ZIVPN  : [1] Status  [2] Restart  [3] Stop  [4] Start  [5] Log"
        echo "  Xray   : [6] Status  [7] Restart  [8] Stop  [9] Start  [10] Log"
        echo "  Nginx  : [11] Status [12] Restart"
        echo "  WARP   : [13] Status [14] Restart"
        echo "  Config : [15] Rebuild Xray config"
        echo "  [0] Kembali"
        echo ""; read -rp "  Pilih: " opt; opt=$(echo "$opt"|tr -d '\r ')
        case "$opt" in
            1)  systemctl status zivpn --no-pager -l ;;
            2)  systemctl restart zivpn; sleep 1; systemctl is-active --quiet zivpn && ok "ZIVPN restart!" || warn "Gagal!" ;;
            3)  systemctl stop  zivpn; warn "ZIVPN dihentikan." ;;
            4)  systemctl start zivpn; sleep 1; systemctl is-active --quiet zivpn && ok "ZIVPN OK!" || warn "Gagal!" ;;
            5)  journalctl -u zivpn -n 40 --no-pager ;;
            6)  systemctl status xray --no-pager -l ;;
            7)  systemctl restart xray; sleep 1; systemctl is-active --quiet xray && ok "Xray restart!" || warn "Gagal! Cek: journalctl -u xray -n 20" ;;
            8)  systemctl stop  xray; warn "Xray dihentikan." ;;
            9)  systemctl start xray; sleep 1; systemctl is-active --quiet xray && ok "Xray OK!" || warn "Gagal!" ;;
            10) journalctl -u xray -n 40 --no-pager ;;
            11) systemctl status nginx --no-pager -l ;;
            12) systemctl restart nginx && ok "Nginx restart!" || warn "Nginx error!" ;;
            13) systemctl status wireproxy --no-pager -l ;;
            14) systemctl restart wireproxy; sleep 1; systemctl is-active --quiet wireproxy && ok "WARP restart!" || warn "Gagal!" ;;
            15) write_xray_config; systemctl restart xray &>/dev/null; ok "Config rebuild & restart!" ;;
            0)  return ;;
            *)  warn "Tidak valid!" ;;
        esac
        echo ""; press_enter
    done
}

# ═════════════════════════════════════════════════════════════════
#  [9] INFO VPS
# ═════════════════════════════════════════════════════════════════
menu_info_vps() {
    clear
    local pub priv iface os kern rt rd dt upt
    pub=$(get_pub_ip); priv=$(hostname -I | awk '{print $1}')
    iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    os=$(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
    kern=$(uname -r)
    rt=$(free -m | awk '/^Mem:/{print $2}'); rd=$(free -m | awk '/^Mem:/{print $3}')
    dt=$(df -h / | awk 'NR==2{print $3"/"$2}')
    upt=$(uptime -p 2>/dev/null | sed 's/up //')
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "           INFO VPS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "IP Publik" "$pub";  kv "IP Lokal"  "$priv"
    kv "Interface" "$iface"; kv "Domain"   "$(get_domain)"
    kv "ISP"       "$(get_isp)"
    echo "────────────────────────────────"
    kv "OS"        "$os";   kv "Kernel"   "$kern"
    kv "Uptime"    "$upt"
    kv "RAM"       "${rd}/${rt} MB"; kv "Disk /"  "$dt"
    echo "────────────────────────────────"
    kv "ZIVPN"     "Port 5667 + 6000-19999 UDP"
    kv "Xray"      "Port 80 + 443 (langsung)"
    kv "SSL cert"  "$(ls -la $XRAY_CERT 2>/dev/null | awk '{print $6,$7,$8}' || echo 'tidak ada')"
    kv "IPForward" "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
    kv "ZIVPN akun" "$(count_db "$USER_DB")"
    kv "Xray akun"  "$(count_db "$XRAY_DB")"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [10] AUTO REBOOT
# ═════════════════════════════════════════════════════════════════
menu_auto_reboot() {
    clear; echo -e "${CYN}[ AUTO REBOOT ]${NC}\n"
    local RS="/usr/local/bin/zivpanel-reboot"
    if crontab -l 2>/dev/null | grep -q "zivpanel-reboot"; then
        echo -e "  Status: ${GRN}Aktif${NC} — setiap 00.00 WIB\n"
        echo "  [1] Nonaktifkan  [0] Kembali"
        read -rp "  Pilih: " opt
        if [[ "$opt" == "1" ]]; then
            crontab -l 2>/dev/null | grep -v "zivpanel-reboot" | crontab -
            rm -f "$RS"; warn "Auto reboot dinonaktifkan."
        fi
        press_enter; return
    fi
    echo -e "  Status: ${RED}Tidak aktif${NC}\n"
    confirm "Aktifkan auto reboot jam 00.00 WIB?" || return
    cat > "$RS" <<'RB'
#!/bin/bash
sync; echo 3 > /proc/sys/vm/drop_caches
journalctl --vacuum-time=1d >/dev/null 2>&1
find /tmp -mindepth 1 -mtime +1 -delete 2>/dev/null
sleep 5; /sbin/reboot
RB
    chmod +x "$RS"
    { crontab -l 2>/dev/null | grep -v "zivpanel-reboot"
      echo "0 17 * * * $RS >/dev/null 2>&1  # zivpanel-reboot"
    } | crontab -
    ok "Auto Reboot aktif — setiap 00.00 WIB"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [11] UPDATE ZIVPN
# ═════════════════════════════════════════════════════════════════
menu_update_zivpn() {
    clear; echo -e "${CYN}[ UPDATE ZIVPN ]${NC}\n"
    info "Download ZIVPN terbaru..."
    systemctl stop zivpn 2>/dev/null
    wget -q "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64" \
        -O "${ZIVPN_BIN}.new"
    [[ $? -ne 0 ]] && warn "Gagal download!" && press_enter && return
    mv "${ZIVPN_BIN}.new" "$ZIVPN_BIN" && chmod +x "$ZIVPN_BIN"
    systemctl start zivpn; sleep 1
    systemctl is-active --quiet zivpn && ok "ZIVPN updated & running!" || warn "Gagal start!"
    press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [12] UPDATE XRAY
# ═════════════════════════════════════════════════════════════════
menu_update_xray() {
    clear; echo -e "${CYN}[ UPDATE XRAY ]${NC}\n"
    info "Download Xray terbaru..."
    systemctl stop xray 2>/dev/null
    local tmp; tmp=$(mktemp -d)
    local xurl
    xurl=$(curl -s "https://api.github.com/repos/XTLS/Xray-core/releases/latest" \
        | python3 -c "
import json,sys
d=json.load(sys.stdin)
[print(a['browser_download_url']) for a in d.get('assets',[]) if 'Xray-linux-64.zip' in a['name']]
" 2>/dev/null | head -1)
    [[ -z "$xurl" ]] && xurl="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    wget -q "$xurl" -O "${tmp}/xray.zip"
    if [[ $? -eq 0 ]]; then
        unzip -q "${tmp}/xray.zip" -d "${tmp}/x"
        cp "${tmp}/x/xray" "$XRAY_BIN" && chmod +x "$XRAY_BIN"
        ok "Xray binary updated: $($XRAY_BIN version 2>/dev/null | head -1)"
    else
        warn "Gagal download!"; rm -rf "$tmp"; press_enter; return
    fi
    rm -rf "$tmp"
    systemctl start xray; sleep 1
    systemctl is-active --quiet xray && ok "Xray running!" || warn "Xray gagal start!"
    press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [13] RENEW SSL
# ═════════════════════════════════════════════════════════════════
menu_renew_ssl() {
    clear; echo -e "${CYN}[ RENEW SSL ]${NC}\n"
    local domain; domain=$(get_domain)
    echo "  Domain : $domain"
    echo "  Cert   : $XRAY_CERT"
    local exp_date; exp_date=$(openssl x509 -enddate -noout -in "$XRAY_CERT" 2>/dev/null | cut -d= -f2)
    echo "  Expired: $exp_date"
    echo ""
    echo "  [1] Renew via acme.sh (Let's Encrypt)"
    echo "  [2] Generate self-signed baru"
    echo "  [0] Kembali"
    read -rp "  Pilih: " opt
    case "$opt" in
        1)
            info "Renew SSL via acme.sh..."
            systemctl stop nginx 2>/dev/null
            if install_ssl "$domain"; then
                systemctl restart xray nginx &>/dev/null
                ok "SSL diperbarui!"
            else
                systemctl start nginx 2>/dev/null
                warn "Renew gagal."
            fi
            ;;
        2)
            confirm "Generate self-signed cert baru?" || return
            gen_selfsigned "$domain"
            systemctl restart xray &>/dev/null
            ok "Self-signed cert baru dibuat!"
            ;;
    esac
    press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [14] HAPUS ZIVPN
# ═════════════════════════════════════════════════════════════════
menu_uninstall_zivpn() {
    clear; echo -e "${CYN}[ HAPUS ZIVPN ]${NC}\n"
    confirm "Yakin hapus ZIVPN? (data akun tetap)" || return
    systemctl stop zivpn 2>/dev/null; systemctl disable zivpn 2>/dev/null
    rm -f "$ZIVPN_SVC" "$ZIVPN_BIN" "$ENFORCE_EXPIRE" "$ENFORCE_QUOTA"
    rm -rf /etc/zivpn
    systemctl daemon-reload 2>/dev/null
    { crontab -l 2>/dev/null | grep -v "zivpanel-expire\|zivpanel-quota"; } | crontab -
    local iface; iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    iptables -t nat -D PREROUTING  -i "$iface" -p udp --dport 6000:19999 \
        -j DNAT --to-destination :5667 2>/dev/null
    iptables -t nat -D POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null
    iptables-save > /etc/iptables/rules.v4 2>/dev/null
    ok "ZIVPN dihapus!"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [15] HAPUS PANEL
# ═════════════════════════════════════════════════════════════════
menu_uninstall_panel() {
    clear; echo -e "${CYN}[ HAPUS PANEL ]${NC}\n"
    echo -e "${RED}  PERINGATAN: Semua data akun akan terhapus!${NC}\n"
    confirm "Yakin hapus seluruh panel & semua data?" || return
    { crontab -l 2>/dev/null \
        | grep -v "zivpanel-expire\|zivpanel-quota\|zivpanel-reboot"
    } | crontab -
    rm -rf "$PANEL_DIR"
    rm -f "$PANEL_BIN" "$ENFORCE_EXPIRE" "$ENFORCE_QUOTA" /usr/local/bin/zivpanel-reboot
    ok "Panel dihapus!"
    rm -f "$(realpath "$0")"; exit 0
}

# ═════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════
main() {
    check_root
    local self; self=$(realpath "$0")
    sed -i 's/\r//g' "$self" 2>/dev/null
    init_panel
    install_shortcut
    [[ ! -f "$INSTALLED_FLAG" ]] && do_install
    [[ ! -x "$ENFORCE_EXPIRE" ]] && install_enforcement >/dev/null 2>&1

    while true; do
        show_banner
        read -rp "  Pilih menu: " choice
        choice=$(echo "$choice"|tr -d '\r ')
        case "$choice" in
            1)  menu_create_zivpn    ;;
            2)  menu_create_xray     ;;
            3)  menu_detail_zivpn    ;;
            4)  menu_detail_xray     ;;
            5)  menu_del_zivpn       ;;
            6)  menu_del_xray        ;;
            7)  menu_change_host     ;;
            8)  menu_service         ;;
            9)  menu_info_vps        ;;
            10) menu_auto_reboot     ;;
            11) menu_update_zivpn    ;;
            12) menu_update_xray     ;;
            13) menu_renew_ssl       ;;
            14) menu_uninstall_zivpn ;;
            15) menu_uninstall_panel ;;
            x|X|q|Q) echo -e "\n${GRN}  Sampai jumpa!${NC}\n"; exit 0 ;;
            *) warn "Tidak valid!"; sleep 1 ;;
        esac
    done
}

main "$@"
