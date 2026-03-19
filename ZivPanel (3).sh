#!/bin/bash
# ================================================================
#   ZivPanel v3.0 — ZIVPN UDP + Xray (VMess/VLess/Trojan)
#   Distro  : Debian 11/12 | Ubuntu 20.04/22.04 (AMD64)
#   Creator : zahidbd2 | Panel by PowerMX
#   Build   : Claude v3.0 — clean rewrite, production ready
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

ZIVPN_CONF="/etc/zivpn/config.json"
ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_SVC="/etc/systemd/system/zivpn.service"
ENFORCE_EXPIRE="/usr/local/bin/zivpanel-expire"
ENFORCE_QUOTA="/usr/local/bin/zivpanel-quota"

XRAY_BIN="/usr/local/bin/xray"
XRAY_CONF="/etc/xray/config.json"
XRAY_CERT="/etc/xray/ssl/server.crt"
XRAY_KEY="/etc/xray/ssl/server.key"
XRAY_SVC="/etc/systemd/system/xray.service"
BW_CRON="$PANEL_DIR/bw-update.sh"
ANTIDDOS="$PANEL_DIR/anti-ddos.sh"
RESTORE_NAT="$PANEL_DIR/restore-nat.sh"
PANEL_BIN="/usr/local/bin/zivpanel"

# ── Helper dasar ──────────────────────────────────────────────────
die()         { echo -e "${RED}[!] $*${NC}" >&2; exit 1; }
ok()          { echo -e "${GRN}[✓] $*${NC}"; }
warn()        { echo -e "${YLW}[!] $*${NC}"; }
info()        { echo -e "${CYN}[…] $*${NC}"; }
press_enter() { echo; read -rp "  Tekan Enter..." _pe; }
kv()          { printf "%-13s: %s\n" "$1" "$2"; }

confirm() { read -rp "  $1 [y/N]: " _c; [[ "$_c" == [yY] ]]; }
check_root() { [[ $EUID -eq 0 ]] || die "Jalankan sebagai root: sudo $0"; }

get_host() { grep -oP '(?<=^HOST=).+' "$SERVER_CONF" 2>/dev/null || echo "-"; }
get_isp()  { grep -oP '(?<=^ISP=).+' "$SERVER_CONF"  2>/dev/null || echo "-"; }
save_conf() { printf 'HOST=%s\nISP=%s\n' "$1" "$2" > "$SERVER_CONF"; }

get_pub_ip() {
    curl -s4 --max-time 4 ifconfig.me 2>/dev/null \
    || curl -s4 --max-time 4 api.ipify.org 2>/dev/null \
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

# Bersihkan \r dari file — dipanggil tiap init agar CRLF tidak merusak DB
clean_db() { sed -i 's/\r//g' "$1" 2>/dev/null; }
count_db()  { [[ -s "$1" ]] && wc -l < "$1" || echo 0; }

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

make_uuid() {
    local u
    u=$(uuidgen 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '\r\n')
    [[ -z "$u" ]] && u=$(python3 -c "import uuid; print(uuid.uuid4())" 2>/dev/null | tr -d '\r\n')
    [[ -z "$u" ]] && u=$(tr -d '\r\n' < /proc/sys/kernel/random/uuid 2>/dev/null)
    echo "$u"
}

# ═════════════════════════════════════════════════════════════════
#  ENFORCEMENT
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
#  ANTI-DDOS
# ═════════════════════════════════════════════════════════════════
write_antiddos() {
    local iface; iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    cat > "$ANTIDDOS" <<DDOS
#!/bin/bash
IPT=iptables
IFACE=$iface

# Reset (policy ACCEPT dulu — anti lockout saat flush)
\$IPT -P INPUT   ACCEPT
\$IPT -P FORWARD ACCEPT
\$IPT -P OUTPUT  ACCEPT
\$IPT -F INPUT
\$IPT -F FORWARD
# NAT table TIDAK di-flush — PREROUTING ZIVPN dikelola restore-nat.sh

# 1. Loopback wajib pertama — Xray API 127.0.0.1 butuh ini
\$IPT -A INPUT  -i lo -j ACCEPT
\$IPT -A OUTPUT -o lo -j ACCEPT

# 2. Koneksi established/related
\$IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3. Buang paket invalid
\$IPT -A INPUT -m conntrack --ctstate INVALID -j DROP

# 4. Buang TCP malformed (sebelum ACCEPT port)
\$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
\$IPT -A INPUT -p tcp --tcp-flags ALL ALL  -j DROP
\$IPT -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# 5. ACCEPT port yang dibutuhkan
\$IPT -A INPUT -p udp  --dport 5667       -j ACCEPT
\$IPT -A INPUT -p udp  --dport 6000:19999 -j ACCEPT
\$IPT -A INPUT -p tcp  --dport 22         -j ACCEPT
\$IPT -A INPUT -p tcp  --dport 80         -j ACCEPT
\$IPT -A INPUT -p tcp  --dport 443        -j ACCEPT

# 6. ICMP rate-limit
\$IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 2/s --limit-burst 4 -j ACCEPT
\$IPT -A INPUT -p icmp --icmp-type echo-request -j DROP

# 7. SYN flood — hanya port selain yang sudah di-ACCEPT
\$IPT -A INPUT -p tcp --syn -m multiport ! --dports 22,80,443 \\
     -m limit --limit 30/s --limit-burst 60 -j ACCEPT
\$IPT -A INPUT -p tcp --syn -m multiport ! --dports 22,80,443 -j DROP

# 8. Per-IP rate-limit port 80/443 (120 koneksi baru/menit/IP)
\$IPT -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW \\
     -m recent --set --name WRATE --rsource
\$IPT -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW \\
     -m recent --update --seconds 60 --hitcount 120 --name WRATE --rsource -j DROP

# 9. UDP lain — rate-limit
\$IPT -A INPUT -p udp -m multiport ! --dports 5667,6000:19999 \\
     -m limit --limit 200/s --limit-burst 400 -j ACCEPT
\$IPT -A INPUT -p udp -m multiport ! --dports 5667,6000:19999 -j DROP

# 10. FORWARD untuk NAT ZIVPN
\$IPT -A FORWARD -i \$IFACE -j ACCEPT
\$IPT -A FORWARD -o \$IFACE -j ACCEPT

# 11. Default DROP di akhir (setelah semua ACCEPT terpasang)
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

install_sysctl() {
    cat > /etc/sysctl.d/99-zivpanel.conf <<'SC'
net.ipv4.ip_forward = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
SC
    sysctl -p /etc/sysctl.d/99-zivpanel.conf >/dev/null 2>&1
}

# ═════════════════════════════════════════════════════════════════
#  XRAY CONFIG — tulis ulang dari DB
# ═════════════════════════════════════════════════════════════════
write_xray_config() {
    local vmess="" vless="" trojan=""
    if [[ -s "$XRAY_DB" ]]; then
        local _u _uuid _pw _proto _exp _cr
        while IFS='|' read -r _u _uuid _pw _proto _exp _cr; do
            _u=$(echo "$_u"|tr -d '\r'); _uuid=$(echo "$_uuid"|tr -d '\r')
            _pw=$(echo "$_pw"|tr -d '\r')
            vmess+="{\"id\":\"${_uuid}\",\"alterId\":0,\"email\":\"${_u}\"},"
            vless+="{\"id\":\"${_uuid}\",\"email\":\"${_u}\"},"
            trojan+="{\"password\":\"${_pw}\",\"email\":\"${_u}\"},"
        done < "$XRAY_DB"
        vmess="${vmess%,}"; vless="${vless%,}"; trojan="${trojan%,}"
    else
        vmess="{\"id\":\"00000000-0000-0000-0000-000000000000\",\"alterId\":0,\"email\":\"_\"}"
        vless="{\"id\":\"00000000-0000-0000-0000-000000000000\",\"email\":\"_\"}"
        trojan="{\"password\":\"_placeholder\",\"email\":\"_\"}"
    fi
    mkdir -p "$(dirname "$XRAY_CONF")" "$(dirname "$XRAY_CERT")"
    cat > "$XRAY_CONF" <<CFG
{
  "log": { "loglevel": "warning" },
  "api": { "tag": "api", "services": ["StatsService"] },
  "stats": {},
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  },
  "inbounds": [
    {
      "tag":"vmess-ws-80","listen":"127.0.0.1","port":10001,"protocol":"vmess",
      "settings":{"clients":[${vmess}]},
      "streamSettings":{"network":"ws","wsSettings":{"path":"/vmess-ws"}}
    },
    {
      "tag":"vmess-ws-443","listen":"127.0.0.1","port":10002,"protocol":"vmess",
      "settings":{"clients":[${vmess}]},
      "streamSettings":{"network":"ws","security":"tls",
        "tlsSettings":{"certificates":[{"certificateFile":"${XRAY_CERT}","keyFile":"${XRAY_KEY}"}]},
        "wsSettings":{"path":"/vmess-ws"}}
    },
    {
      "tag":"vmess-grpc","listen":"127.0.0.1","port":10003,"protocol":"vmess",
      "settings":{"clients":[${vmess}]},
      "streamSettings":{"network":"grpc","security":"tls",
        "tlsSettings":{"certificates":[{"certificateFile":"${XRAY_CERT}","keyFile":"${XRAY_KEY}"}]},
        "grpcSettings":{"serviceName":"vmess-grpc"}}
    },
    {
      "tag":"vless-ws-80","listen":"127.0.0.1","port":10011,"protocol":"vless",
      "settings":{"clients":[${vless}],"decryption":"none"},
      "streamSettings":{"network":"ws","wsSettings":{"path":"/vless-ws"}}
    },
    {
      "tag":"vless-ws-443","listen":"127.0.0.1","port":10012,"protocol":"vless",
      "settings":{"clients":[${vless}],"decryption":"none"},
      "streamSettings":{"network":"ws","security":"tls",
        "tlsSettings":{"certificates":[{"certificateFile":"${XRAY_CERT}","keyFile":"${XRAY_KEY}"}]},
        "wsSettings":{"path":"/vless-ws"}}
    },
    {
      "tag":"vless-grpc","listen":"127.0.0.1","port":10013,"protocol":"vless",
      "settings":{"clients":[${vless}],"decryption":"none"},
      "streamSettings":{"network":"grpc","security":"tls",
        "tlsSettings":{"certificates":[{"certificateFile":"${XRAY_CERT}","keyFile":"${XRAY_KEY}"}]},
        "grpcSettings":{"serviceName":"vless-grpc"}}
    },
    {
      "tag":"trojan-ws-443","listen":"127.0.0.1","port":10021,"protocol":"trojan",
      "settings":{"clients":[${trojan}]},
      "streamSettings":{"network":"ws","security":"tls",
        "tlsSettings":{"certificates":[{"certificateFile":"${XRAY_CERT}","keyFile":"${XRAY_KEY}"}]},
        "wsSettings":{"path":"/trojan-ws"}}
    },
    {
      "tag":"trojan-grpc","listen":"127.0.0.1","port":10022,"protocol":"trojan",
      "settings":{"clients":[${trojan}]},
      "streamSettings":{"network":"grpc","security":"tls",
        "tlsSettings":{"certificates":[{"certificateFile":"${XRAY_CERT}","keyFile":"${XRAY_KEY}"}]},
        "grpcSettings":{"serviceName":"trojan-grpc"}}
    },
    {
      "tag":"api","listen":"127.0.0.1","port":10085,
      "protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}
    }
  ],
  "outbounds": [
    {"protocol":"freedom","tag":"direct"},
    {"protocol":"blackhole","tag":"blocked"}
  ],
  "routing": {
    "rules": [
      {"type":"field","inboundTag":["api"],"outboundTag":"api"},
      {
        "type":"field",
        "ip":["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12",
              "192.168.0.0/16","100.64.0.0/10"],
        "outboundTag":"blocked"
      }
    ]
  }
}
CFG
}

write_nginx() {
    local host; host=$(get_host)
    cat > /etc/nginx/sites-available/xray <<NGX
server {
    listen 80;
    server_name ${host} _;
    location /vmess-ws {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
    }
    location /vless-ws {
        proxy_pass http://127.0.0.1:10011;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
    }
}
server {
    listen 443 ssl http2;
    server_name ${host} _;
    ssl_certificate     ${XRAY_CERT};
    ssl_certificate_key ${XRAY_KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    location /vmess-ws {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
    }
    location /vless-ws {
        proxy_pass http://127.0.0.1:10012;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
    }
    location /trojan-ws {
        proxy_pass http://127.0.0.1:10021;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 3600s;
    }
    location /vmess-grpc {
        grpc_pass grpc://127.0.0.1:10003;
        grpc_set_header Host \$host;
        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
    }
    location /vless-grpc {
        grpc_pass grpc://127.0.0.1:10013;
        grpc_set_header Host \$host;
        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
    }
    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:10022;
        grpc_set_header Host \$host;
        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
    }
}
NGX
    ln -sf /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/xray 2>/dev/null
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null
    nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null \
        || warn "Nginx config warning — cek: nginx -t"
}

# ═════════════════════════════════════════════════════════════════
#  BANDWIDTH TRACKING
# ═════════════════════════════════════════════════════════════════
write_bw_cron() {
    cat > "$BW_CRON" <<'BW'
#!/bin/bash
BIN=/usr/local/bin/xray
XRAY_DB=/etc/zivpanel/xray-users.db
BW_DB=/etc/zivpanel/xray-bw.db
[[ -x "$BIN" && -s "$XRAY_DB" ]] || exit 0
systemctl is-active --quiet xray 2>/dev/null || exit 0
ss -tlnp 2>/dev/null | grep -q ":10085" || exit 0
stat_val() {
    "$BIN" api statsquery --server="127.0.0.1:10085" -name "$1" 2>/dev/null \
    | python3 -c "
import sys,json
try: print(json.load(sys.stdin).get('stat',{}).get('value',0))
except: print(0)" 2>/dev/null || echo 0
}
while IFS='|' read -r u uuid pw proto exp cr; do
    u=$(echo "$u"|tr -d '\r')
    [[ -z "$u" ]] && continue
    up=$(stat_val "user>>>${u}>>>traffic>>>uplink")
    dn=$(stat_val "user>>>${u}>>>traffic>>>downlink")
    cur=$(grep "^${u}|" "$BW_DB" 2>/dev/null)
    if [[ -n "$cur" ]]; then
        IFS='|' read -r _ cu cd rd <<< "$cur"
        [[ "${up:-0}" -gt 0 ]] && cu=$up
        [[ "${dn:-0}" -gt 0 ]] && cd=$dn
    else
        cu=${up:-0}; cd=${dn:-0}; rd=$(date +%Y-%m-%d)
    fi
    sed -i "/^${u}|/d" "$BW_DB" 2>/dev/null
    echo "${u}|${cu}|${cd}|${rd}" >> "$BW_DB"
done < "$XRAY_DB"
BW
    chmod +x "$BW_CRON"
    { crontab -l 2>/dev/null | grep -v "zivpanel-bw"
      echo "*/5 * * * * $BW_CRON >/dev/null 2>&1  # zivpanel-bw"
    } | crontab -
}

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
    local tot=$(( ${up:-0} + ${dn:-0} ))
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  BANDWIDTH — $1"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "Upload"   "$(bw_human ${up:-0})"
    kv "Download" "$(bw_human ${dn:-0})"
    kv "Total"    "$(bw_human $tot)"
    kv "Sejak"    "$rd"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

bw_update() {
    systemctl is-active --quiet xray 2>/dev/null || return
    [[ -x "$XRAY_BIN" && -s "$XRAY_DB" ]] || return
    ss -tlnp 2>/dev/null | grep -q ":10085" || return
    bash "$BW_CRON" 2>/dev/null
}

bw_reset() {
    [[ -x "$XRAY_BIN" ]] && ss -tlnp 2>/dev/null | grep -q ":10085" && {
        "$XRAY_BIN" api statsquery --server="127.0.0.1:10085" \
            -name "user>>>${1}>>>traffic>>>uplink"   -reset 2>/dev/null
        "$XRAY_BIN" api statsquery --server="127.0.0.1:10085" \
            -name "user>>>${1}>>>traffic>>>downlink" -reset 2>/dev/null
    }
    sed -i "/^${1}|/d" "$BW_DB" 2>/dev/null
    echo "${1}|0|0|$(date +%Y-%m-%d)" >> "$BW_DB"
    ok "Bandwidth $1 di-reset."
}

# ═════════════════════════════════════════════════════════════════
#  LINK GENERATOR
# ═════════════════════════════════════════════════════════════════
_ue() { python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$1" 2>/dev/null || echo "$1"; }

mk_vmess() {
    local uuid=$1 host=$2 port=$3 net=$4 path=$5 tls=$6 name=$7
    local t; [[ "$tls" == tls ]] && t="tls" || t="none"
    local j="{\"v\":\"2\",\"ps\":\"${name}\",\"add\":\"${host}\",\"port\":\"${port}\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"${net}\",\"type\":\"none\",\"host\":\"${host}\",\"path\":\"${path}\",\"tls\":\"${t}\"}"
    echo "vmess://$(printf '%s' "$j" | base64 | tr -d '\n')"
}

mk_vless() {
    local uuid=$1 host=$2 port=$3 net=$4 path=$5 tls=$6 name=$7
    local sec; [[ "$tls" == tls ]] && sec="tls" || sec="none"
    local ep; ep=$(_ue "$path")
    local l="vless://${uuid}@${host}:${port}?encryption=none&security=${sec}&type=${net}"
    [[ "$net" == ws   ]] && l+="&path=${ep}"
    [[ "$net" == grpc ]] && l+="&serviceName=${ep}"
    [[ "$tls" == tls  ]] && l+="&sni=${host}"
    echo "${l}#${name}"
}

mk_trojan() {
    local pw=$1 host=$2 port=$3 net=$4 path=$5 name=$6
    local ep; ep=$(_ue "$path")
    local l="trojan://${pw}@${host}:${port}?security=tls&type=${net}"
    [[ "$net" == ws   ]] && l+="&path=${ep}"
    [[ "$net" == grpc ]] && l+="&serviceName=${ep}"
    echo "${l}&sni=${host}#${name}"
}

# ═════════════════════════════════════════════════════════════════
#  INSTALL — otomatis saat pertama kali (flag .installed)
# ═════════════════════════════════════════════════════════════════
do_install() {
    clear
    echo -e "${CYN}"
    echo "  ╔══════════════════════════════════════════╗"
    echo -e "  ║  ${WHT}ZivPanel v3.0 — Instalasi Awal${NC}${CYN}         ║"
    echo "  ╠══════════════════════════════════════════╣"
    echo "  ║  • ZIVPN UDP  (port 5667 + 6000-19999)  ║"
    echo "  ║  • Xray-core  (VMess/VLess/Trojan)       ║"
    echo "  ║  • Nginx      (port 80 + 443)            ║"
    echo "  ║  • Anti-DDoS + Fail2Ban                  ║"
    echo "  ║  • Bandwidth tracker                     ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    confirm "Mulai instalasi?" || { echo "  Dibatalkan."; exit 0; }

    echo ""
    local pub_ip; pub_ip=$(get_pub_ip)
    echo "  IP Server  : $pub_ip"
    read -rp "  Host/Domain (Enter = pakai IP): " host
    [[ -z "$host" ]] && host="$pub_ip"
    host=$(echo "$host" | tr -d '\r ')
    info "Mendeteksi ISP..."
    local isp; isp=$(fetch_isp "$pub_ip")
    echo "  ISP        : $isp"
    read -rp "  Ubah nama ISP? (Enter = pakai): " isp_in
    isp_in=$(echo "$isp_in" | tr -d '\r')
    [[ -n "$isp_in" ]] && isp="$isp_in"
    save_conf "$host" "$isp"
    echo ""

    # [1/10] Paket sistem
    echo "[1/10] Update & install paket sistem..."
    echo "iptables-persistent iptables/autosave_v4 boolean true"  | debconf-set-selections
    echo "iptables-persistent iptables/autosave_v6 boolean false" | debconf-set-selections
    DEBIAN_FRONTEND=noninteractive apt-get update  -y >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        curl wget unzip openssl python3 bc socat uuid-runtime \
        net-tools iptables-persistent nginx fail2ban >/dev/null 2>&1
    ok "Paket sistem selesai"

    # [2/10] ZIVPN binary
    echo "[2/10] Download ZIVPN binary..."
    systemctl stop zivpn 2>/dev/null
    wget -q "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64" \
        -O "$ZIVPN_BIN" || die "Gagal download ZIVPN"
    chmod +x "$ZIVPN_BIN"
    ok "ZIVPN binary siap"

    # [3/10] ZIVPN config & service
    echo "[3/10] Konfigurasi ZIVPN..."
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
    systemctl is-active --quiet zivpn && ok "ZIVPN service aktif" || warn "ZIVPN belum aktif"

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
        cp "${tmp}/x/xray" "$XRAY_BIN" 2>/dev/null && chmod +x "$XRAY_BIN"
        ok "Xray binary siap"
    else
        warn "Xray gagal, coba V2Ray fallback..."
        wget -q "https://github.com/v2fly/v2ray-core/releases/latest/download/v2ray-linux-64.zip" \
            -O "${tmp}/xray.zip"
        if [[ $? -eq 0 ]]; then
            unzip -q "${tmp}/xray.zip" -d "${tmp}/x"
            cp "${tmp}/x/v2ray" "$XRAY_BIN" 2>/dev/null && chmod +x "$XRAY_BIN"
            ok "V2Ray binary (fallback) siap"
        else
            warn "Gagal download — install Xray manual lewat menu [12]"
        fi
    fi
    rm -rf "$tmp"

    # [5/10] Geodata (WAJIB untuk Xray)
    echo "[5/10] Download geodata (geoip + geosite)..."
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" \
        -O /usr/local/bin/geoip.dat
    wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" \
        -O /usr/local/bin/geosite.dat
    [[ -s /usr/local/bin/geoip.dat ]] && ok "Geodata siap" \
        || warn "Geodata gagal — routing menggunakan CIDR"

    # [6/10] SSL cert Xray
    echo "[6/10] Buat SSL certificate..."
    mkdir -p "$(dirname "$XRAY_CERT")"
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$host" == "-" ]]; then
        openssl req -newkey rsa:2048 -days 3650 -nodes -x509 \
            -subj "/C=US/ST=CA/L=LA/O=VPN/CN=vpn-server" \
            -keyout "$XRAY_KEY" -out "$XRAY_CERT" >/dev/null 2>&1
        warn "Self-signed cert (IP mode)"
    else
        if command -v certbot &>/dev/null; then
            systemctl stop nginx 2>/dev/null
            certbot certonly --standalone -d "$host" --non-interactive \
                --agree-tos --register-unsafely-without-email >/dev/null 2>&1
            if [[ -f "/etc/letsencrypt/live/${host}/fullchain.pem" ]]; then
                ln -sf "/etc/letsencrypt/live/${host}/fullchain.pem" "$XRAY_CERT"
                ln -sf "/etc/letsencrypt/live/${host}/privkey.pem"   "$XRAY_KEY"
                ok "Let's Encrypt cert aktif"
            else
                openssl req -newkey rsa:2048 -days 3650 -nodes -x509 \
                    -subj "/C=US/ST=CA/L=LA/O=VPN/CN=${host}" \
                    -keyout "$XRAY_KEY" -out "$XRAY_CERT" >/dev/null 2>&1
                warn "Certbot gagal — self-signed"
            fi
        else
            openssl req -newkey rsa:2048 -days 3650 -nodes -x509 \
                -subj "/C=US/ST=CA/L=LA/O=VPN/CN=${host}" \
                -keyout "$XRAY_KEY" -out "$XRAY_CERT" >/dev/null 2>&1
            warn "Self-signed cert"
        fi
    fi
    chmod 600 "$XRAY_KEY" "$XRAY_CERT"
    ok "SSL siap"

    # [7/10] Xray config & service
    echo "[7/10] Konfigurasi Xray..."
    write_xray_config
    cat > "$XRAY_SVC" <<SVC
[Unit]
Description=Xray Service
After=network.target nss-lookup.target
[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
ExecStart=${XRAY_BIN} run -config ${XRAY_CONF}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
SVC
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable xray >/dev/null 2>&1
    systemctl start  xray
    sleep 1
    systemctl is-active --quiet xray && ok "Xray service aktif" \
        || warn "Xray belum aktif — cek: journalctl -u xray -n 20"

    # [8/10] Nginx
    echo "[8/10] Konfigurasi Nginx..."
    write_nginx
    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx 2>/dev/null
    ok "Nginx siap"

    # [9/10] NAT + sysctl + Anti-DDoS
    echo "[9/10] Konfigurasi NAT, Anti-DDoS, sysctl..."
    install_sysctl
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    grep -q "net.ipv4.ip_forward" /etc/sysctl.conf \
        && sed -i 's/.*net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf \
        || echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    local iface; iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    iptables -t nat -C PREROUTING -i "$iface" -p udp --dport 6000:19999 \
        -j DNAT --to-destination :5667 2>/dev/null \
        || iptables -t nat -A PREROUTING -i "$iface" -p udp \
           --dport 6000:19999 -j DNAT --to-destination :5667
    iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE
    write_antiddos; bash "$ANTIDDOS"
    write_restore_nat
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
        systemctl restart fail2ban 2>/dev/null
        systemctl enable  fail2ban 2>/dev/null
    }
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null
    command -v ufw &>/dev/null && {
        ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp
        ufw allow 5667/udp; ufw allow 6000:19999/udp
        ufw --force enable
    } >/dev/null 2>&1
    ok "NAT + Anti-DDoS aktif"

    # [10/10] Enforcement + BW cron
    echo "[10/10] Pasang enforcement & bandwidth tracker..."
    install_enforcement >/dev/null 2>&1
    write_bw_cron
    ok "Enforcement & tracker aktif"

    touch "$INSTALLED_FLAG"

    local sz; systemctl is-active --quiet zivpn && sz="${GRN}Running${NC}" || sz="${RED}Stopped${NC}"
    local sx; systemctl is-active --quiet xray  && sx="${GRN}Running${NC}" || sx="${RED}Stopped${NC}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "     INSTALASI SELESAI"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "Host/IP"   "$host"
    kv "ISP"       "$isp"
    kv "ZIVPN"     "Port 5667 + 6000-19999 UDP"
    printf "%-13s: " "ZIVPN svc"; echo -e "${sz}"
    printf "%-13s: " "Xray svc";  echo -e "${sx}"
    kv "Nginx"     "Port 80 + 443"
    kv "Anti-DDoS" "Aktif"
    kv "Fail2Ban"  "Aktif"
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
    local ip os upt sz sx ddos uz xz
    ip=$(get_pub_ip)
    os=$(lsb_release -ds 2>/dev/null \
        || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
    upt=$(uptime -p 2>/dev/null | sed 's/up //')
    uz=$(count_db "$USER_DB"); xz=$(count_db "$XRAY_DB")
    systemctl is-active --quiet zivpn 2>/dev/null \
        && sz="${GRN}Running${NC}" || sz="${RED}Stopped${NC}"
    if [[ -x "$XRAY_BIN" ]]; then
        systemctl is-active --quiet xray 2>/dev/null \
            && sx="${GRN}Running${NC}" || sx="${RED}Stopped${NC}"
    else
        sx="${YLW}Not Installed${NC}"
    fi
    iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|limit" \
        && ddos="${GRN}ON${NC}" || ddos="${RED}OFF${NC}"

    echo -e "${CYN}"
    echo "  ╔══════════════════════════════════════════╗"
    echo -e "  ║  ${WHT}ZivPanel v3.0  •  VPN Management${NC}${CYN}       ║"
    echo "  ╠══════════════════════════════════════════╣"
    printf  "  ║  %-8s : %-31s║\n" "IP"     "$ip"
    printf  "  ║  %-8s : %-31s║\n" "Host"   "$(get_host)"
    printf  "  ║  %-8s : %-31s║\n" "ISP"    "$(get_isp)"
    printf  "  ║  %-8s : %-31s║\n" "OS"     "$os"
    printf  "  ║  %-8s : %-31s║\n" "Uptime" "$upt"
    echo -e "  ║  ZIVPN : ${sz}${CYN} (${uz} akun)  DDoS: ${ddos}${CYN}       ║"
    echo -e "  ║  Xray  : ${sx}${CYN} (${xz} akun)               ║"
    echo    "  ╠══════════════════════════════════════════╣"
    echo -e "  ║  ${GRN}[1]${NC}${CYN}  Buat Akun ZIVPN                       ║"
    echo -e "  ║  ${GRN}[2]${NC}${CYN}  Buat Akun Xray (VMess/VLess/Trojan)   ║"
    echo -e "  ║  ${GRN}[3]${NC}${CYN}  Detail Akun ZIVPN                     ║"
    echo -e "  ║  ${GRN}[4]${NC}${CYN}  Detail Akun Xray                      ║"
    echo -e "  ║  ${RED}[5]${NC}${CYN}  Hapus Akun ZIVPN                      ║"
    echo -e "  ║  ${RED}[6]${NC}${CYN}  Hapus Akun Xray                       ║"
    echo    "  ╠══════════════════════════════════════════╣"
    echo -e "  ║  ${YLW}[7]${NC}${CYN}  Ubah Host/ISP                         ║"
    echo -e "  ║  ${YLW}[8]${NC}${CYN}  Service Management                    ║"
    echo -e "  ║  ${YLW}[9]${NC}${CYN}  Info VPS                              ║"
    echo -e "  ║  ${YLW}[10]${NC}${CYN} Auto Reboot                           ║"
    echo    "  ╠══════════════════════════════════════════╣"
    echo -e "  ║  ${CYN}[11]${NC}${CYN} Update ZIVPN    ${CYN}[12]${NC}${CYN} Update Xray      ║"
    echo -e "  ║  ${RED}[13]${NC}${CYN} Hapus ZIVPN     ${RED}[14]${NC}${CYN} Hapus Xray       ║"
    echo -e "  ║  ${RED}[15]${NC}${CYN} Hapus Panel                           ║"
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

    local u
    while true; do
        read -rp "  Username      : " u; u=$(echo "$u"|tr -d '\r ')
        [[ -z "$u" ]]                             && warn "Username kosong!"    && continue
        grep -q "^${u}|" "$USER_DB" 2>/dev/null  && warn "Username sudah ada!" && continue
        break
    done
    local pw pw2
    while true; do
        read -rsp "  Password      : " pw; echo; pw=$(echo "$pw"|tr -d '\r')
        [[ -z "$pw" ]]       && warn "Password kosong!"    && continue
        read -rsp "  Konfirmasi    : " pw2; echo; pw2=$(echo "$pw2"|tr -d '\r')
        [[ "$pw" != "$pw2" ]] && warn "Password tidak cocok!" && continue
        break
    done
    local days
    while true; do
        read -rp "  Expired (hari): " days; days=$(echo "$days"|tr -d '\r ')
        [[ "$days" =~ ^[0-9]+$ && $days -gt 0 ]] && break
        warn "Masukkan angka > 0"
    done
    local quota
    while true; do
        read -rp "  Quota GB (0=∞): " quota; quota=$(echo "$quota"|tr -d '\r ')
        [[ "$quota" =~ ^[0-9]+$ ]] && break; warn "Masukkan angka"
    done
    local maxip
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
    kv "Host"     "$(get_host)"
    kv "ISP"      "$(get_isp)"
    kv "Username" "$u"
    kv "Password" "$pw"
    kv "Quota"    "$ql"
    kv "Limit IP" "$il"
    kv "Expired"  "$exp"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [2] BUAT AKUN XRAY — pilih protokol
# ═════════════════════════════════════════════════════════════════
menu_create_xray() {
    clear; echo -e "${CYN}[ BUAT AKUN XRAY ]${NC}\n"
    [[ ! -x "$XRAY_BIN" ]] && warn "Xray belum terinstall!" && press_enter && return

    echo "  Pilih protokol:"
    echo "  [1] VMess"
    echo "  [2] VLess"
    echo "  [3] Trojan"
    echo ""
    local proto
    while true; do
        read -rp "  Pilih [1-3]: " _p; _p=$(echo "$_p"|tr -d '\r ')
        case "$_p" in
            1) proto="vmess"  && break ;;
            2) proto="vless"  && break ;;
            3) proto="trojan" && break ;;
            *) warn "Pilih 1, 2, atau 3" ;;
        esac
    done
    echo -e "  Protokol: ${GRN}${proto^^}${NC}\n"

    local u
    while true; do
        read -rp "  Username      : " u; u=$(echo "$u"|tr -d '\r ')
        [[ -z "$u" ]]                              && warn "Username kosong!"    && continue
        grep -q "^${u}|" "$XRAY_DB" 2>/dev/null   && warn "Username sudah ada!" && continue
        break
    done
    local days
    while true; do
        read -rp "  Expired (hari): " days; days=$(echo "$days"|tr -d '\r ')
        [[ "$days" =~ ^[0-9]+$ && $days -gt 0 ]] && break
        warn "Masukkan angka > 0"
    done

    local uuid; uuid=$(make_uuid)
    if [[ -z "$uuid" ]]; then
        warn "Gagal generate UUID! Install: apt-get install uuid-runtime"
        press_enter; return
    fi
    local trj_pw; trj_pw=$(openssl rand -hex 12 | tr -d '\r\n')
    local exp; exp=$(date -d "+${days} days" +%Y-%m-%d | tr -d '\r\n')
    local now; now=$(date +%Y-%m-%d | tr -d '\r\n')
    proto=$(echo "$proto" | tr -d '\r\n')

    echo "${u}|${uuid}|${trj_pw}|${proto}|${exp}|${now}" >> "$XRAY_DB"
    echo "${u}|0|0|${now}" >> "$BW_DB"

    write_xray_config
    systemctl restart xray &>/dev/null
    nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null

    _show_xray_account "$u" "$uuid" "$trj_pw" "$proto" "$exp"
    press_enter
}

_show_xray_account() {
    local u;    u=$(echo    "$1"|tr -d '\r')
    local uuid; uuid=$(echo "$2"|tr -d '\r')
    local pw;   pw=$(echo   "$3"|tr -d '\r')
    local proto; proto=$(echo "$4"|tr -d '\r')
    local exp;  exp=$(echo  "$5"|tr -d '\r')
    local host; host=$(get_host)
    local isp;  isp=$(get_isp)
    local sisa; sisa=$(days_left "$exp")

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "     XRAY ACCOUNT — ${proto^^}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "Host"    "$host"
    kv "ISP"     "$isp"
    kv "User"    "$u"
    kv "Proto"   "${proto^^}"
    kv "Expired" "$exp ($sisa hari)"

    case "$proto" in
    vmess)
        kv "UUID"    "$uuid"
        echo "────────────────────────────────"
        kv "Port"    "80(WS) / 443(WS+TLS) / 443(gRPC)"
        kv "Path WS" "/vmess-ws"
        kv "svcGRPC" "vmess-grpc"
        echo "── Link WS port 80 :"
        mk_vmess "$uuid" "$host" 80  ws   /vmess-ws  ""  "$u"
        echo "── Link WS port 443 (TLS) :"
        mk_vmess "$uuid" "$host" 443 ws   /vmess-ws  tls "$u"
        echo "── Link gRPC port 443 (TLS) :"
        mk_vmess "$uuid" "$host" 443 grpc vmess-grpc tls "$u"
        ;;
    vless)
        kv "UUID"    "$uuid"
        echo "────────────────────────────────"
        kv "Port"    "80(WS) / 443(WS+TLS) / 443(gRPC)"
        kv "Path WS" "/vless-ws"
        kv "svcGRPC" "vless-grpc"
        echo "── Link WS port 80 :"
        mk_vless "$uuid" "$host" 80  ws   /vless-ws  ""  "$u"
        echo "── Link WS port 443 (TLS) :"
        mk_vless "$uuid" "$host" 443 ws   /vless-ws  tls "$u"
        echo "── Link gRPC port 443 (TLS) :"
        mk_vless "$uuid" "$host" 443 grpc vless-grpc tls "$u"
        ;;
    trojan)
        kv "Password" "$pw"
        echo "────────────────────────────────"
        kv "Port"    "443(WS+TLS) / 443(gRPC)"
        kv "Path WS" "/trojan-ws"
        kv "svcGRPC" "trojan-grpc"
        echo "── Link WS port 443 (TLS) :"
        mk_trojan "$pw" "$host" 443 ws   /trojan-ws  "$u"
        echo "── Link gRPC port 443 (TLS) :"
        mk_trojan "$pw" "$host" 443 grpc trojan-grpc "$u"
        ;;
    *)
        warn "Protokol tidak dikenal: [$proto]"
        ;;
    esac
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# ═════════════════════════════════════════════════════════════════
#  [3] DETAIL AKUN ZIVPN
# ═════════════════════════════════════════════════════════════════
menu_detail_zivpn() {
    clear; echo -e "${CYN}[ AKUN ZIVPN UDP ]${NC}\n"
    if [[ ! -s "$USER_DB" ]]; then warn "Belum ada akun ZIVPN."; press_enter; return; fi

    printf "  %-3s  %-16s  %-12s  %-8s  %-9s  %-9s\n" \
        "No" "Username" "Expired" "Sisa" "Quota" "Limit IP"
    echo "  ───  ────────────────  ────────────  ────────  ─────────  ─────────"
    local no=1
    while IFS='|' read -r u pw exp q mi cr; do
        u=$(echo "$u"|tr -d '\r')
        local sisa; sisa=$(days_left "$exp")
        local ss;   [[ $sisa -lt 0 ]] && ss="EXPIRED" || ss="${sisa}hr"
        local ql;   [[ "$q"  -eq 0 ]] && ql="Unlim"   || ql="${q}GB"
        local il;   [[ "$mi" -eq 0 ]] && il="Unlim"   || il="${mi}dev"
        printf "  %-3s  %-16s  %-12s  %-8s  %-9s  %-9s\n" \
            "$no" "$u" "$exp" "$ss" "$ql" "$il"
        ((no++))
    done < "$USER_DB"
    echo ""; echo "  Total: $((no-1)) akun"
    echo ""; read -rp "  Username untuk detail (Enter=kembali): " _u
    [[ -z "$_u" ]] && return
    _u=$(echo "$_u"|tr -d '\r ')
    local line; line=$(grep "^${_u}|" "$USER_DB")
    [[ -z "$line" ]] && warn "User tidak ditemukan!" && press_enter && return

    IFS='|' read -r u pw exp q mi cr <<< "$line"
    local sisa; sisa=$(days_left "$exp")
    local ql;   [[ "$q"  -eq 0 ]] && ql="Unlimited" || ql="${q} GB"
    local il;   [[ "$mi" -eq 0 ]] && il="Unlimited" || il="${mi} Device"
    local st;   [[ $sisa -lt 0 ]] && st="EXPIRED" || st="Aktif ($sisa hari lagi)"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "     DETAIL AKUN ZIVPN"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "Host"     "$(get_host)"; kv "ISP"      "$(get_isp)"
    kv "Username" "$u";          kv "Password" "$pw"
    kv "Quota"    "$ql";         kv "Limit IP" "$il"
    kv "Expired"  "$exp";        kv "Status"   "$st"
    kv "Dibuat"   "$cr";         kv "Port UDP" "5667 (+ 6000-19999)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  [1] Perpanjang   [2] Ganti password"
    echo "  [3] Ubah quota   [4] Ubah limit IP"
    echo "  [0] Kembali"
    echo ""; read -rp "  Pilih: " opt
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
    if [[ ! -s "$XRAY_DB" ]]; then warn "Belum ada akun Xray."; press_enter; return; fi
    bw_update

    printf "  %-3s  %-14s  %-7s  %-8s  %-10s  %-10s  %-10s\n" \
        "No" "Username" "Proto" "Sisa" "Expired" "Upload" "Download"
    echo "  ───  ──────────────  ───────  ────────  ──────────  ──────────  ──────────"
    local no=1
    while IFS='|' read -r u uuid pw proto exp cr; do
        u=$(echo "$u"|tr -d '\r'); proto=$(echo "$proto"|tr -d '\r')
        local sisa; sisa=$(days_left "$exp")
        local ss;   [[ $sisa -lt 0 ]] && ss="EXPIRED" || ss="${sisa}hr"
        local bwl;  bwl=$(bw_get "$u")
        local bu bd; IFS='|' read -r _ bu bd _ <<< "$bwl"
        printf "  %-3s  %-14s  %-7s  %-8s  %-10s  %-10s  %-10s\n" \
            "$no" "$u" "${proto^^}" "$ss" "$exp" \
            "$(bw_human ${bu:-0})" "$(bw_human ${bd:-0})"
        ((no++))
    done < "$XRAY_DB"
    echo ""; echo "  Total: $((no-1)) akun"
    echo ""; read -rp "  Username untuk detail (Enter=kembali): " _u
    [[ -z "$_u" ]] && return
    _u=$(echo "$_u"|tr -d '\r ')
    local line; line=$(grep "^${_u}|" "$XRAY_DB")
    [[ -z "$line" ]] && warn "User tidak ditemukan!" && press_enter && return

    IFS='|' read -r u uuid pw proto exp cr <<< "$line"
    _show_xray_account "$u" "$uuid" "$pw" "$proto" "$exp"
    bw_show "$u"

    echo "  [1] Perpanjang   [2] Reset Bandwidth   [0] Kembali"
    echo ""; read -rp "  Pilih: " opt
    case "$opt" in
        1)
            read -rp "  Tambah hari: " d; d=$(echo "$d"|tr -d '\r ')
            [[ ! "$d" =~ ^[0-9]+$ ]] && press_enter && return
            local ne; ne=$(date -d "${exp} +${d} days" +%Y-%m-%d)
            awk -F'|' -v u="$u" -v ne="$ne" 'BEGIN{OFS="|"} $1==u{$5=ne}1' \
                "$XRAY_DB" > /tmp/_xp.$$ && mv /tmp/_xp.$$ "$XRAY_DB"
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
    nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null
    ok "Akun '$_u' dihapus!"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [7] UBAH HOST/ISP
# ═════════════════════════════════════════════════════════════════
menu_change_host() {
    clear; echo -e "${CYN}[ UBAH HOST / ISP ]${NC}\n"
    echo "  Host saat ini : $(get_host)"
    echo "  ISP saat ini  : $(get_isp)"; echo ""
    read -rp "  Host baru (Enter=skip): " nh; nh=$(echo "$nh"|tr -d '\r')
    [[ -z "$nh" ]] && nh=$(get_host)
    echo "  [1] Auto deteksi ISP  [2] Input manual"
    read -rp "  Pilih: " opt
    local ni
    if [[ "$opt" == "2" ]]; then
        read -rp "  ISP baru: " ni; ni=$(echo "$ni"|tr -d '\r')
        [[ -z "$ni" ]] && ni=$(get_isp)
    else
        ni=$(fetch_isp "$(get_pub_ip)"); echo "  ISP: $ni"
        read -rp "  Ubah? (Enter=pakai): " ov; ov=$(echo "$ov"|tr -d '\r')
        [[ -n "$ov" ]] && ni="$ov"
    fi
    save_conf "$nh" "$ni"
    write_nginx 2>/dev/null
    ok "Host: $nh | ISP: $ni"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [8] SERVICE MANAGEMENT
# ═════════════════════════════════════════════════════════════════
menu_service() {
    while true; do
        clear; echo -e "${CYN}[ SERVICE MANAGEMENT ]${NC}\n"
        local sz sx
        systemctl is-active --quiet zivpn \
            && sz="${GRN}Running${NC}" || sz="${RED}Stopped${NC}"
        systemctl is-active --quiet xray \
            && sx="${GRN}Running${NC}" || sx="${RED}Stopped${NC}"
        echo -e "  ZIVPN: ${sz}     Xray: ${sx}\n"
        echo "  ZIVPN : [1] Status  [2] Restart  [3] Stop  [4] Start  [5] Log"
        echo "  Xray  : [6] Status  [7] Restart  [8] Stop  [9] Start  [10] Log"
        echo "  Nginx : [11] Status [12] Reload  [13] Rebuild config Xray"
        echo "  Lain  : [14] iptables  [15] Fail2Ban  [0] Kembali"
        echo ""; read -rp "  Pilih: " opt; opt=$(echo "$opt"|tr -d '\r ')
        case "$opt" in
            1)  systemctl status zivpn --no-pager -l ;;
            2)  systemctl restart zivpn; sleep 1
                systemctl is-active --quiet zivpn && ok "ZIVPN restart!" || warn "Gagal!" ;;
            3)  systemctl stop  zivpn; warn "ZIVPN dihentikan." ;;
            4)  systemctl start zivpn; sleep 1
                systemctl is-active --quiet zivpn && ok "ZIVPN running!" || warn "Gagal!" ;;
            5)  journalctl -u zivpn -n 40 --no-pager ;;
            6)  systemctl status xray --no-pager -l ;;
            7)  systemctl restart xray; sleep 1
                systemctl is-active --quiet xray && ok "Xray restart!" || warn "Gagal!" ;;
            8)  systemctl stop  xray; warn "Xray dihentikan." ;;
            9)  systemctl start xray; sleep 1
                systemctl is-active --quiet xray && ok "Xray running!" || warn "Gagal!" ;;
            10) journalctl -u xray -n 40 --no-pager ;;
            11) systemctl status nginx --no-pager -l ;;
            12) nginx -t && systemctl reload nginx && ok "Nginx reload!" || warn "Nginx error!" ;;
            13) write_xray_config; systemctl restart xray &>/dev/null
                nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null
                ok "Config di-rebuild & restart!" ;;
            14) iptables -L INPUT -n --line-numbers ;;
            15) fail2ban-client status sshd 2>/dev/null || warn "Fail2Ban tidak aktif." ;;
            0)  return ;;
            *)  warn "Pilihan tidak valid!" ;;
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
    rt=$(free -m | awk '/^Mem:/{print $2}')
    rd=$(free -m | awk '/^Mem:/{print $3}')
    dt=$(df -h / | awk 'NR==2{print $3"/"$2}')
    upt=$(uptime -p 2>/dev/null | sed 's/up //')
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "           INFO VPS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    kv "IP Publik"  "$pub"; kv "IP Lokal" "$priv"
    kv "Interface"  "$iface"
    kv "Host"       "$(get_host)"; kv "ISP" "$(get_isp)"
    echo "────────────────────────────────"
    kv "OS"         "$os"; kv "Kernel" "$kern"
    kv "Uptime"     "$upt"
    kv "RAM"        "${rd}/${rt} MB"; kv "Disk /" "$dt"
    echo "────────────────────────────────"
    kv "ZIVPN"      "Port 5667 + 6000-19999 UDP"
    kv "Xray"       "Port 80 + 443 (Nginx)"
    kv "IPForward"  "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
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
    local active=false
    crontab -l 2>/dev/null | grep -q "zivpanel-reboot" && active=true
    if $active; then
        echo -e "  Status: ${GRN}Aktif${NC} — setiap 00.00 WIB\n"
        echo "  [1] Nonaktifkan   [0] Kembali"
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
swapoff -a && swapon -a 2>/dev/null
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
    info "Mengunduh versi terbaru..."
    systemctl stop zivpn 2>/dev/null
    wget -q "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64" \
        -O "${ZIVPN_BIN}.new"
    if [[ $? -ne 0 ]]; then warn "Gagal download!"; press_enter; return; fi
    mv "${ZIVPN_BIN}.new" "$ZIVPN_BIN" && chmod +x "$ZIVPN_BIN"
    systemctl start zivpn; sleep 1
    systemctl is-active --quiet zivpn \
        && ok "ZIVPN diupdate & running!" || warn "Gagal start!"
    press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [12] UPDATE XRAY
# ═════════════════════════════════════════════════════════════════
menu_update_xray() {
    clear; echo -e "${CYN}[ UPDATE XRAY ]${NC}\n"
    info "Mengunduh Xray versi terbaru..."
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
        wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" \
            -O /usr/local/bin/geoip.dat 2>/dev/null
        wget -q "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" \
            -O /usr/local/bin/geosite.dat 2>/dev/null
        sed -i "s|^ExecStart=.*|ExecStart=${XRAY_BIN} run -config ${XRAY_CONF}|" \
            "$XRAY_SVC" 2>/dev/null
        systemctl daemon-reload >/dev/null 2>&1
        ok "Xray binary & geodata diperbarui"
    else
        warn "Gagal download!"; rm -rf "$tmp"; press_enter; return
    fi
    rm -rf "$tmp"
    systemctl start xray; sleep 1
    systemctl is-active --quiet xray \
        && ok "Xray running!" || warn "Xray gagal start!"
    press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [13] HAPUS ZIVPN (service saja, data akun tetap)
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
    iptables -P INPUT ACCEPT; iptables -P FORWARD ACCEPT
    iptables -F INPUT; iptables -F FORWARD
    iptables-save > /etc/iptables/rules.v4 2>/dev/null
    rm -f /etc/sysctl.d/99-zivpanel.conf
    sysctl --system >/dev/null 2>&1
    ok "ZIVPN dihapus!"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [14] HAPUS XRAY (service saja, data akun tetap)
# ═════════════════════════════════════════════════════════════════
menu_uninstall_xray() {
    clear; echo -e "${CYN}[ HAPUS XRAY ]${NC}\n"
    confirm "Yakin hapus Xray? (data akun tetap)" || return
    systemctl stop xray 2>/dev/null; systemctl disable xray 2>/dev/null
    rm -f "$XRAY_SVC" "$XRAY_BIN"
    rm -rf /etc/xray
    systemctl daemon-reload 2>/dev/null
    rm -f /etc/nginx/sites-enabled/xray /etc/nginx/sites-available/xray
    nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null
    { crontab -l 2>/dev/null | grep -v "zivpanel-bw"; } | crontab -
    rm -f "$BW_CRON"
    ok "Xray dihapus!"; press_enter
}

# ═════════════════════════════════════════════════════════════════
#  [15] HAPUS PANEL (semua data)
# ═════════════════════════════════════════════════════════════════
menu_uninstall_panel() {
    clear; echo -e "${CYN}[ HAPUS PANEL ]${NC}\n"
    echo -e "${RED}  PERINGATAN: Semua data akun akan terhapus!${NC}\n"
    confirm "Yakin hapus seluruh panel & semua data?" || return
    { crontab -l 2>/dev/null \
        | grep -v "zivpanel-expire\|zivpanel-quota\|zivpanel-bw\|zivpanel-reboot"
    } | crontab -
    rm -rf "$PANEL_DIR"
    rm -f "$PANEL_BIN" "$ENFORCE_EXPIRE" "$ENFORCE_QUOTA" \
          /usr/local/bin/zivpanel-reboot
    ok "Panel dihapus!"
    rm -f "$(realpath "$0")"; exit 0
}

# ═════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════
main() {
    check_root

    # Self-clean \r (antisipasi download dari Pastebin/Windows CRLF)
    local self; self=$(realpath "$0")
    sed -i 's/\r//g' "$self" 2>/dev/null

    init_panel
    install_shortcut

    # Auto-install saat pertama kali
    if [[ ! -f "$INSTALLED_FLAG" ]]; then
        do_install
    fi

    # Pasang enforcement jika belum ada
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
            13) menu_uninstall_zivpn ;;
            14) menu_uninstall_xray  ;;
            15) menu_uninstall_panel ;;
            x|X|q|Q) echo -e "\n${GRN}  Sampai jumpa!${NC}\n"; exit 0 ;;
            *) warn "Pilihan tidak valid!"; sleep 1 ;;
        esac
    done
}

main "$@"
