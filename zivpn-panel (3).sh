#!/bin/bash
# ================================================================
#   ZIVPN UDP Panel CLI + Installer + Anti-DDoS
#   Support : Debian 11 / 12 | Ubuntu 20.04 / 22.04 (AMD64)
#   Installer: github.com/zahidbd2/udp-zivpn (zi.sh)
#   Creator  : zahidbd2  |  Panel by PowerMX
#   v1.1 — Bug fixes: UFW/iptables conflict, FORWARD chain,
#          extend_expired read order, username validation,
#          iptables quota accounting, UDP IP-limit, mktemp
# ================================================================

# ── Warna ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

# ── Path ─────────────────────────────────────────────────────
PANEL_DIR="/etc/zivpn-panel"
USER_DB="$PANEL_DIR/users.db"
CONFIG_JSON="/etc/zivpn/config.json"
ZIVPN_BIN="/usr/local/bin/zivpn"
PANEL_SCRIPT="/usr/local/bin/zivpn-panel"
SERVER_CONF="$PANEL_DIR/server.conf"
ENFORCE_EXPIRE="/usr/local/bin/zivpn-expire-check"
ENFORCE_IP="/usr/local/bin/zivpn-ip-check"
ENFORCE_QUOTA="/usr/local/bin/zivpn-quota-check"
REBOOT_SCRIPT="/usr/local/bin/zivpn-autoreboot"
ANTIDDOS_SCRIPT="/etc/zivpn-panel/anti-ddos.sh"

# ── Cek root ─────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} Jalankan sebagai root: sudo $0"
        exit 1
    fi
}

# ── Init direktori ───────────────────────────────────────────
init_panel() {
    mkdir -p "$PANEL_DIR"
    [[ ! -f "$USER_DB" ]] && touch "$USER_DB"
}

# ── Helper: baca / tulis server.conf ─────────────────────────
get_host() { grep -oP '(?<=^HOST=).+' "$SERVER_CONF" 2>/dev/null || echo "-"; }
get_isp()  { grep -oP '(?<=^ISP=).+' "$SERVER_CONF"  2>/dev/null || echo "-"; }

save_server_conf() {
    local host=$1 isp=$2
    cat > "$SERVER_CONF" <<EOF
HOST=${host}
ISP=${isp}
EOF
}

fetch_isp() {
    local ip=$1 isp
    isp=$(curl -s --max-time 4 "https://ipapi.co/${ip}/org/" 2>/dev/null \
       || curl -s --max-time 4 "http://ip-api.com/line/${ip}?fields=isp" 2>/dev/null)
    [[ -z "$isp" || "$isp" == *"error"* ]] && isp="Unknown ISP"
    echo "$isp"
}

# ── Helper: sisa hari expired ─────────────────────────────────
days_remaining() {
    local expire=$1
    echo $(( ( $(date -d "$expire" +%s) - $(date -d "$(date +%Y-%m-%d)" +%s) ) / 86400 ))
}

# ── Install shortcut ──────────────────────────────────────────
install_shortcut() {
    local self; self=$(realpath "$0")
    if [[ "$self" != "$PANEL_SCRIPT" ]] && [[ ! -f "$PANEL_SCRIPT" ]]; then
        cp "$self" "$PANEL_SCRIPT" 2>/dev/null
        chmod +x "$PANEL_SCRIPT" 2>/dev/null
        echo -e "  ${GREEN}✓ Shortcut dibuat — ketik 'zivpn-panel' untuk membuka panel${NC}"
        sleep 1
    fi
}

# ── Validasi username ─────────────────────────────────────────
validate_username() {
    local uname=$1
    if [[ ! "$uname" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_-]*$ ]]; then
        echo -e "  ${RED}Username hanya boleh: huruf, angka, underscore, dash!${NC}"
        return 1
    fi
    if [[ ${#uname} -lt 2 || ${#uname} -gt 32 ]]; then
        echo -e "  ${RED}Username harus 2-32 karakter!${NC}"
        return 1
    fi
    return 0
}

# ════════════════════════════════════════════════════════════
#  ENFORCEMENT ENGINE
#  1. zivpn-expire-check  — cek expired tiap 5 menit
#  2. zivpn-ip-check      — cek limit IP tiap 1 menit
#  3. zivpn-quota-check   — cek kuota tiap 5 menit
# ════════════════════════════════════════════════════════════
install_enforcement() {
    # ── 1. Script cek expired ────────────────────────────
    cat > "$ENFORCE_EXPIRE" <<EXPEOF
#!/bin/bash
# zivpn-expire-check — cek expired tiap 5 menit
USER_DB="$USER_DB"
CONFIG_JSON="$CONFIG_JSON"
LOG="/var/log/zivpn-enforce.log"
[[ ! -f "\$USER_DB" ]] && exit 0
TODAY=\$(date +"%Y-%m-%d")
while IFS='|' read -r uname pass expire quota maxip acctype created used; do
    [[ -z "\$uname" ]] && continue
    expire_ts=\$(date -d "\$expire" +%s 2>/dev/null) || continue
    today_ts=\$(date -d "\$TODAY" +%s)
    sisa=\$(( (expire_ts - today_ts) / 86400 ))
    if [[ \$sisa -lt 0 ]]; then
        if id "\$uname" &>/dev/null; then
            pkill -u "\$uname" 2>/dev/null
            usermod -L "\$uname" 2>/dev/null
            echo "[\$(date '+%Y-%m-%d %H:%M:%S')] EXPIRED lock: \$uname (exp:\$expire)" >> "\$LOG"
        fi
        if [[ -f "\$CONFIG_JSON" ]]; then
            python3 - <<PYEOF 2>/dev/null
import json
with open('\$CONFIG_JSON') as f: c = json.load(f)
pw = c.get('auth',{}).get('config',[])
changed = False
if '\$pass' in pw: pw.remove('\$pass'); changed = True
if not pw: pw.append('zi')
if changed:
    c['auth']['config'] = pw
    with open('\$CONFIG_JSON','w') as f: json.dump(c,f,indent=2)
PYEOF
            python3 -c "
import json
with open('\$CONFIG_JSON') as f: c=json.load(f)
exit(0 if '\$pass' not in c.get('auth',{}).get('config',[]) else 1)
" 2>/dev/null && systemctl restart zivpn.service 2>/dev/null && \
            echo "[\$(date '+%Y-%m-%d %H:%M:%S')] EXPIRED UDP removed: \$uname" >> "\$LOG"
        fi
    fi
done < "\$USER_DB"
EXPEOF
    chmod +x "$ENFORCE_EXPIRE"

    # ── 2. Script cek limit IP/sesi ──────────────────────
    cat > "$ENFORCE_IP" <<IPEOF
#!/bin/bash
# zivpn-ip-check — cek limit IP tiap 1 menit
USER_DB="$USER_DB"
LOG="/var/log/zivpn-enforce.log"
[[ ! -f "\$USER_DB" ]] && exit 0
while IFS='|' read -r uname pass expire quota maxip acctype created used; do
    [[ -z "\$uname" ]] && continue
    [[ "\$maxip" == "0" ]] && continue
    # SSH sessions
    ssh_ips=\$(who 2>/dev/null | grep "^\${uname} " | awk '{print \$5}' | tr -d '()' | sort -u)
    # UDP VPN connections (port 5667) - count unique source IPs (peer address is field $5)
    udp_ips=\$(ss -unp 2>/dev/null | grep ":5667" | awk '{split(\$5,a,":");print a[1]}' | sort -u)
    # Combine unique IPs
    active_ips=\$(echo -e "\${ssh_ips}\n\${udp_ips}" | grep -v '^$' | sort -u | wc -l)
    if [[ \$active_ips -gt \$maxip ]]; then
        excess=\$(( active_ips - maxip ))
        old_pids=\$(who 2>/dev/null | grep "^\${uname} " | awk '{print \$2}' | while read pts; do
            fuser /dev/\$pts 2>/dev/null | awk '{print \$1}'
        done | head -n \$excess)
        for pid in \$old_pids; do
            [[ -n "\$pid" ]] && kill -HUP "\$pid" 2>/dev/null
        done
        echo "[\$(date '+%Y-%m-%d %H:%M:%S')] IP LIMIT kick \$excess: \$uname (limit:\$maxip aktif:\$active_ips)" >> "\$LOG"
    fi
done < "\$USER_DB"
IPEOF
    chmod +x "$ENFORCE_IP"

    # ── 3. Script cek kuota ──────────────────────────────
    cat > "$ENFORCE_QUOTA" <<QTEOF
#!/bin/bash
# zivpn-quota-check — cek kuota tiap 5 menit (iptables accounting)
USER_DB="$USER_DB"
CONFIG_JSON="$CONFIG_JSON"
LOG="/var/log/zivpn-enforce.log"
[[ ! -f "\$USER_DB" ]] && exit 0
while IFS='|' read -r uname pass expire quota maxip acctype created used; do
    [[ -z "\$uname" ]] && continue
    [[ "\$quota" == "0" ]] && continue
    # Buat iptables accounting chain jika belum ada
    chain="ZIVPN_\${uname}"
    if ! iptables -L "\$chain" -n &>/dev/null; then
        iptables -N "\$chain" 2>/dev/null
        iptables -A "\$chain" -j RETURN
        # Tambah ke OUTPUT untuk user ini (-m owner hanya berlaku di OUTPUT chain)
        if id "\$uname" &>/dev/null; then
            iptables -I OUTPUT -m owner --uid-owner "\$(id -u "\$uname")" -j "\$chain" 2>/dev/null
        fi
    fi
    # Baca bytes dari iptables chain dan reset counter
    session_bytes=\$(iptables -L "\$chain" -nvx 2>/dev/null | awk 'NR>2{sum+=\$2}END{print sum+0}')
    iptables -Z "\$chain" 2>/dev/null
    # Hitung total: used_gb dari DB (field $8) + session bytes dikonversi ke GB
    used_gb=\${used:-0}
    session_gb=\$(( session_bytes / 1024 / 1024 / 1024 ))
    new_used=\$(( used_gb + session_gb ))
    # Update used di DB jika ada perubahan
    if [[ \$new_used -gt \$used_gb ]]; then
        tmpdb=\$(mktemp)
        awk -F'|' -v u="\$uname" -v nu="\$new_used" 'BEGIN{OFS="|"} \$1==u{\$8=nu}1' \
            "\$USER_DB" > "\$tmpdb" && mv "\$tmpdb" "\$USER_DB"
    fi
    # Cek apakah kuota terlampaui
    quota_gb=\$quota
    if [[ \$new_used -ge \$quota_gb ]] && [[ \$quota_gb -gt 0 ]]; then
        if id "\$uname" &>/dev/null; then
            pkill -u "\$uname" 2>/dev/null; usermod -L "\$uname" 2>/dev/null
            echo "[\$(date '+%Y-%m-%d %H:%M:%S')] QUOTA EXCEEDED: \$uname (\${quota_gb}GB used:\${new_used}GB)" >> "\$LOG"
        fi
        if [[ -f "\$CONFIG_JSON" ]]; then
            python3 -c "
import json
with open('\$CONFIG_JSON') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if '\$pass' in pw: pw.remove('\$pass')
if not pw: pw.append('zi')
c['auth']['config']=pw
with open('\$CONFIG_JSON','w') as f: json.dump(c,f,indent=2)
" 2>/dev/null
            systemctl restart zivpn.service 2>/dev/null
        fi
    fi
done < "\$USER_DB"
QTEOF
    chmod +x "$ENFORCE_QUOTA"

    # ── Pasang cron ketiga daemon ────────────────────────
    (
        crontab -l 2>/dev/null | grep -v "zivpn-expire-check\|zivpn-ip-check\|zivpn-quota-check"
        echo "*/5 * * * * $ENFORCE_EXPIRE >> /var/log/zivpn-enforce.log 2>&1  # zivpn-expire-check"
        echo "*/1 * * * * $ENFORCE_IP    >> /var/log/zivpn-enforce.log 2>&1  # zivpn-ip-check"
        echo "*/5 * * * * $ENFORCE_QUOTA >> /var/log/zivpn-enforce.log 2>&1  # zivpn-quota-check"
    ) | crontab -

    # ── PAM maxlogins untuk SSH ──────────────────────────
    [[ ! -f /etc/security/limits.d/zivpn.conf ]] && \
        echo "# ZIVPN Panel — SSH session limits" > /etc/security/limits.d/zivpn.conf
    if [[ -f /etc/pam.d/sshd ]] && ! grep -q "pam_limits" /etc/pam.d/sshd; then
        echo "session required pam_limits.so" >> /etc/pam.d/sshd
    fi
}

_write_pam_limit() {
    local uname=$1 maxip=$2
    sed -i "/^${uname} /d" /etc/security/limits.d/zivpn.conf 2>/dev/null
    [[ "$maxip" -gt 0 ]] && echo "${uname}  hard  maxlogins  ${maxip}" >> /etc/security/limits.d/zivpn.conf
}

_remove_pam_limit() {
    sed -i "/^${1} /d" /etc/security/limits.d/zivpn.conf 2>/dev/null
}

# ════════════════════════════════════════════════════════════
#  ANTI-DDoS ENGINE
#  Digabung aman dengan ZIVPN — whitelist port VPN DULU,
#  baru pasang rate-limit & drop rules.
#  Tidak memakai ufw policy DROP agar tidak konflik.
# ════════════════════════════════════════════════════════════
install_antiddos() {
    local iface
    iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

    # ── Tulis script anti-DDoS ────────────────────────────
    cat > "$ANTIDDOS_SCRIPT" <<DDOSEOF
#!/bin/bash
# ================================================================
#  ZIVPN Anti-DDoS Rules
#  PENTING: port ZIVPN di-whitelist SEBELUM semua drop/limit rules
#  Aman untuk koneksi ZIVPN UDP tetap berjalan
# ================================================================

IPT="iptables"
IFACE="${iface}"

echo "[Anti-DDoS] Memasang rules pada interface: \$IFACE"

# ── Flush chain INPUT saja, jangan flush NAT (ZIVPN forwarding) ──
\$IPT -F INPUT

# ── 1. Izinkan loopback ──────────────────────────────────────────
\$IPT -A INPUT -i lo -j ACCEPT

# ── 2. Izinkan koneksi ESTABLISHED/RELATED (wajib untuk UDP VPN) ─
\$IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ── 3. WHITELIST PORT ZIVPN (harus SEBELUM semua rule limit/drop) ─
# Port utama ZIVPN UDP
\$IPT -A INPUT -p udp --dport 5667 -j ACCEPT
# Port range forwarding ZIVPN
\$IPT -A INPUT -p udp --dport 6000:19999 -j ACCEPT

# ── 4. Izinkan SSH ────────────────────────────────────────────────
\$IPT -A INPUT -p tcp --dport 22 -j ACCEPT

# ── 5. Izinkan HTTP/HTTPS ─────────────────────────────────────────
\$IPT -A INPUT -p tcp --dport 80  -j ACCEPT
\$IPT -A INPUT -p tcp --dport 443 -j ACCEPT

# ── 6. Blokir paket NULL scan ─────────────────────────────────────
\$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# ── 7. Blokir Xmas scan ──────────────────────────────────────────
\$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# ── 8. Blokir NEW TCP tanpa SYN ──────────────────────────────────
\$IPT -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

# ── 9. Proteksi SYN flood (hanya TCP, bukan UDP) ─────────────────
\$IPT -A INPUT -p tcp --syn -m limit --limit 30/s --limit-burst 60 -j ACCEPT
\$IPT -A INPUT -p tcp --syn -j DROP

# ── 10. Rate-limit ICMP ping flood ───────────────────────────────
\$IPT -A INPUT -p icmp --icmp-type echo-request \
     -m limit --limit 2/s --limit-burst 4 -j ACCEPT
\$IPT -A INPUT -p icmp --icmp-type echo-request -j DROP

# ── 11. Rate-limit UDP flood di port SELAIN ZIVPN ────────────────
# Port ZIVPN sudah di-ACCEPT di atas, jadi rule ini tidak menyentuh
# traffic VPN. Hanya UDP di port lain yang dibatasi.
\$IPT -A INPUT -p udp -m multiport ! --dports 5667,6000:19999 \
     -m limit --limit 200/s --limit-burst 400 -j ACCEPT
\$IPT -A INPUT -p udp -m multiport ! --dports 5667,6000:19999 -j DROP

# ── 12. Blokir koneksi baru berlebihan per IP (brute force) ──────
\$IPT -A INPUT -p tcp -m conntrack --ctstate NEW \
     -m recent --set --name CONN_RATE --rsource
\$IPT -A INPUT -p tcp -m conntrack --ctstate NEW \
     -m recent --update --seconds 60 --hitcount 30 \
     --name CONN_RATE --rsource -j DROP

# ── 13. Policy INPUT DROP untuk sisa yang tidak cocok ────────────
\$IPT -P INPUT DROP
# FORWARD harus ACCEPT agar ZIVPN NAT PREROUTING tetap bekerja
\$IPT -P FORWARD ACCEPT
\$IPT -P OUTPUT ACCEPT

# ── 14. Simpan rules ──────────────────────────────────────────────
iptables-save > /etc/iptables/rules.v4 2>/dev/null
echo "[Anti-DDoS] ✓ Rules terpasang — ZIVPN UDP tetap berjalan"
DDOSEOF
    chmod +x "$ANTIDDOS_SCRIPT"

    # ── Tulis sysctl anti-DDoS ────────────────────────────
    cat > /etc/sysctl.d/99-zivpn-antiddos.conf <<'SYSCTLEOF'
# ── ZIVPN Anti-DDoS Kernel Tuning ────────────────────────────────
# Proteksi SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_max_syn_backlog = 4096

# Tolak ICMP redirect & source routing
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0

# Anti IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Abaikan ICMP broadcast (Smurf attack)
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log paket mencurigakan
net.ipv4.conf.all.log_martians = 1

# Buffer jaringan besar (wajib untuk ZIVPN UDP performa tinggi)
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# Tutup TIME_WAIT cepat
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_orphans = 65536

# UDP buffer besar untuk ZIVPN
net.core.rmem_default = 26214400
net.core.wmem_default = 26214400
SYSCTLEOF

    # ── Konfigurasi Fail2Ban ──────────────────────────────
    if command -v fail2ban-server &>/dev/null || apt-get install -y fail2ban >/dev/null 2>&1; then
        cat > /etc/fail2ban/jail.local <<'F2BEOF'
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

[sshd-ddos]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 10
findtime = 30
bantime  = 86400
F2BEOF
        systemctl restart fail2ban 2>/dev/null
        systemctl enable  fail2ban 2>/dev/null
    fi

    # ── Terapkan sysctl sekarang ──────────────────────────
    sysctl -p /etc/sysctl.d/99-zivpn-antiddos.conf >/dev/null 2>&1

    # ── Jalankan iptables rules ───────────────────────────
    bash "$ANTIDDOS_SCRIPT"

    # ── Pastikan iptables-persistent terinstall ───────────
    if ! dpkg -l iptables-persistent &>/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1
    fi
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4 2>/dev/null

    # ── Pasang di rc.local agar aktif setelah reboot ──────
    if [[ ! -f /etc/rc.local ]]; then
        echo '#!/bin/bash' > /etc/rc.local
        echo 'exit 0' >> /etc/rc.local
        chmod +x /etc/rc.local
    fi
    if ! grep -q "zivpn-panel" /etc/rc.local; then
        sed -i '/^exit 0/i bash /etc/zivpn-panel/anti-ddos.sh' /etc/rc.local
    fi
}

# ── Banner ────────────────────────────────────────────────────
show_banner() {
    clear
    local ip os uptime_info svc_status total_users zivpn_status cur_host cur_isp ddos_status
    ip=$(curl -s4 --max-time 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    os=$(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
    uptime_info=$(uptime -p 2>/dev/null | sed 's/up //' || uptime | sed 's/.*up //;s/,.*//')
    if systemctl is-active --quiet zivpn.service 2>/dev/null; then
        svc_status="${GREEN}● Running${NC}"
    else
        svc_status="${RED}● Stopped${NC}"
    fi
    total_users=$(grep -c "." "$USER_DB" 2>/dev/null || echo 0)
    [[ -f "$ZIVPN_BIN" ]] && zivpn_status="${GREEN}Terpasang${NC}" || zivpn_status="${RED}Belum terpasang${NC}"
    cur_host=$(get_host); cur_isp=$(get_isp)
    if iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|limit"; then
        ddos_status="${GREEN}● Aktif${NC}"
    else
        ddos_status="${RED}● Tidak aktif${NC}"
    fi

    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}${BOLD}        ZIVPN UDP Panel CLI  v1.1                    ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW}    Debian 11/12  |  Ubuntu 20.04/22.04  [AMD64]     ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    printf  "${CYAN}║${NC}  %-12s: ${WHITE}%-39s${CYAN}║${NC}\n" "IP Server"   "$ip"
    printf  "${CYAN}║${NC}  %-12s: ${WHITE}%-39s${CYAN}║${NC}\n" "ISP"         "$cur_isp"
    printf  "${CYAN}║${NC}  %-12s: ${WHITE}%-39s${CYAN}║${NC}\n" "Host/Domain" "$cur_host"
    printf  "${CYAN}║${NC}  %-12s: ${WHITE}%-39s${CYAN}║${NC}\n" "OS"          "$os"
    printf  "${CYAN}║${NC}  %-12s: ${WHITE}%-39s${CYAN}║${NC}\n" "Uptime"      "$uptime_info"
    echo -e "${CYAN}║${NC}  Binary       : ${zivpn_status}   Service : ${svc_status}"
    echo -e "${CYAN}║${NC}  Anti-DDoS    : ${ddos_status}"
    printf  "${CYAN}║${NC}  %-12s: ${WHITE}%-39s${CYAN}║${NC}\n" "Total User"  "$total_users akun"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}[0]${NC}  Install ZIVPN UDP                             ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}[1]${NC}  Buat Akun SSH / UDP                           ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}[2]${NC}  Cek / List Semua User                         ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}[3]${NC}  Detail User                                   ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${RED}[4]${NC}  Hapus Akun                                    ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}[5]${NC}  Restart / Status Service                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}[8]${NC}  Ubah Host / Domain & ISP                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}[9]${NC}  Detail Info VPS                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${YELLOW}[A]${NC}  Auto Reboot Harian (00.00 WIB)                ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${RED}[6]${NC}  Uninstall ZIVPN                               ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${RED}[7]${NC}  Uninstall Panel                               ${CYAN}║${NC}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${WHITE}[x]${NC}  Keluar                                        ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ════════════════════════════════════════════════════════════
#  [0] INSTALL ZIVPN + Anti-DDoS
# ════════════════════════════════════════════════════════════
install_zivpn() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}${WHITE}       INSTALL ZIVPN UDP SERVER (AMD64)              ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW}   src: github.com/zahidbd2/udp-zivpn — zi.sh        ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}\n"

    # Cek arsitektur
    local arch; arch=$(uname -m)
    if [[ "$arch" != "x86_64" ]]; then
        echo -e "  ${RED}✗ Hanya mendukung AMD64/x86_64. Terdeteksi: ${arch}${NC}\n"
        read -rp "  Tekan Enter untuk kembali..."; return
    fi

    # Cek OS
    local os_id os_ver os_ok=false
    os_id=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"')
    os_ver=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release 2>/dev/null | tr -d '"')
    case "${os_id}-${os_ver}" in
        debian-11|debian-12|ubuntu-20.04|ubuntu-22.04) os_ok=true ;;
    esac
    if [[ "$os_ok" == "false" ]]; then
        echo -e "  ${YELLOW}⚠  OS: ${os_id} ${os_ver} — belum diuji.${NC}"
        read -rp "  Tetap lanjutkan? [y/N]: " force_ok
        [[ "$force_ok" != "y" && "$force_ok" != "Y" ]] && return
    fi

    # Cek sudah terpasang
    if [[ -f "$ZIVPN_BIN" ]]; then
        echo -e "  ${YELLOW}⚠  ZIVPN sudah terpasang. Reinstall akan menimpa.${NC}\n"
        read -rp "  Lanjutkan? [y/N]: " confirm
        [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return
    fi

    # ── [1/8] Update sistem ──────────────────────────────
    echo -e "\n  ${YELLOW}[1/8]${NC} Memperbarui sistem..."
    apt-get update -y >/dev/null 2>&1
    apt-get upgrade -y >/dev/null 2>&1
    apt-get install -y curl wget openssl python3 iptables-persistent \
        fail2ban net-tools >/dev/null 2>&1
    echo -e "  ${GREEN}      ✓ Sistem & paket diperbarui${NC}"

    # ── [2/8] Stop service lama ──────────────────────────
    echo -e "  ${YELLOW}[2/8]${NC} Menghentikan service lama..."
    systemctl stop zivpn.service >/dev/null 2>&1

    # ── [3/8] Download binary AMD64 ─────────────────────
    echo -e "  ${YELLOW}[3/8]${NC} Mengunduh ZIVPN binary (AMD64 v1.4.9)..."
    wget -q "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64" \
        -O "$ZIVPN_BIN"
    if [[ $? -ne 0 ]]; then
        echo -e "  ${RED}✗ Gagal mengunduh! Cek koneksi internet.${NC}\n"
        read -rp "  Tekan Enter untuk kembali..."; return
    fi
    chmod +x "$ZIVPN_BIN"
    mkdir -p /etc/zivpn
    echo -e "  ${GREEN}      ✓ Binary berhasil diunduh${NC}"

    # ── [4/8] config.json + sertifikat ──────────────────
    echo -e "  ${YELLOW}[4/8]${NC} Membuat konfigurasi & sertifikat SSL..."
    cat > "$CONFIG_JSON" <<'CONFJSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {
    "mode": "passwords",
    "config": ["zi"]
  }
}
CONFJSON
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
        -keyout "/etc/zivpn/zivpn.key" \
        -out    "/etc/zivpn/zivpn.crt" >/dev/null 2>&1
    echo -e "  ${GREEN}      ✓ Konfigurasi & sertifikat siap${NC}"

    # ── [5/8] Systemd service ────────────────────────────
    echo -e "  ${YELLOW}[5/8]${NC} Membuat systemd service..."
    cat > /etc/systemd/system/zivpn.service <<'SVCEOF'
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload >/dev/null 2>&1
    echo -e "  ${GREEN}      ✓ Service dibuat${NC}"

    # ── [6/8] Host / Domain & ISP ───────────────────────
    echo -e "  ${YELLOW}[6/8]${NC} Konfigurasi Host / Domain & ISP..."
    echo ""
    local server_ip
    server_ip=$(curl -s4 --max-time 4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    read -rp "  Host/Domain (kosong = IP ${server_ip}): " input_host
    [[ -z "$input_host" ]] && input_host="$server_ip"
    echo -e "  ${YELLOW}  Mendeteksi ISP...${NC}"
    local auto_isp; auto_isp=$(fetch_isp "$server_ip")
    echo -e "  ISP terdeteksi : ${WHITE}${auto_isp}${NC}"
    read -rp "  Ubah ISP? (kosong = pakai '$auto_isp'): " input_isp
    [[ -z "$input_isp" ]] && input_isp="$auto_isp"
    save_server_conf "$input_host" "$input_isp"
    echo -e "  ${GREEN}      ✓ Host: ${input_host} | ISP: ${input_isp}${NC}"

    # ── [7/8] Password awal + enable + iptables ─────────
    echo -e "  ${YELLOW}[7/8]${NC} Konfigurasi password & port..."
    echo ""
    read -rp "  Password UDP (pisah koma, Enter='zi'): " input_config
    if [[ -n "$input_config" ]]; then
        IFS=',' read -r -a config_arr <<< "$input_config"
        local pw_json
        pw_json=$(printf '"%s",' "${config_arr[@]}" | sed 's/,$//')
        sed -i -E "s|\"config\": \[\"zi\"\]|\"config\": [${pw_json}]|" "$CONFIG_JSON"
        for pw in "${config_arr[@]}"; do
            local cdate expire_date
            cdate=$(date +"%Y-%m-%d")
            expire_date=$(date -d "+365 days" +"%Y-%m-%d")
            echo "udp_${pw}|${pw}|${expire_date}|0|0|UDP Only|${cdate}|0" >> "$USER_DB"
        done
    fi

    systemctl enable zivpn.service >/dev/null 2>&1
    systemctl start  zivpn.service

    # Nonaktifkan UFW agar tidak konflik dengan iptables rules
    command -v ufw &>/dev/null && ufw disable >/dev/null 2>&1
    # iptables PREROUTING forwarding (zi.sh)
    local iface
    iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 6000:19999 \
        -j DNAT --to-destination :5667 2>/dev/null

    # ── [8/8] Anti-DDoS + Enforcement + Sysctl ──────────
    echo -e "  ${YELLOW}[8/8]${NC} Memasang Anti-DDoS, Enforcement, & Sysctl..."
    install_antiddos
    install_enforcement >/dev/null 2>&1
    echo -e "  ${GREEN}      ✓ Anti-DDoS, enforcement, sysctl aktif${NC}"

    echo ""
    sleep 1
    if systemctl is-active --quiet zivpn.service; then
        echo -e "  ${GREEN}╔══════════════════════════════════════════╗${NC}"
        echo -e "  ${GREEN}║  ✓  ZIVPN UDP + Anti-DDoS Installed    ║${NC}"
        echo -e "  ${GREEN}╠══════════════════════════════════════════╣${NC}"
        printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Host/Domain" "$input_host"
        printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "ISP"         "$input_isp"
        printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Port UDP"    "5667"
        printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Forwarding"  "6000 – 19999"
        printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Anti-DDoS"   "Aktif (iptables+sysctl)"
        printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Fail2Ban"    "Aktif"
        printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Enforcement" "Expired+IP+Kuota aktif"
        echo -e "  ${GREEN}╚══════════════════════════════════════════╝${NC}"
    else
        echo -e "  ${RED}✗ Service gagal start. Cek: journalctl -u zivpn${NC}"
    fi
    echo ""
    read -rp "  Tekan Enter untuk kembali ke menu..."
}

# ════════════════════════════════════════════════════════════
#  [1] BUAT AKUN
# ════════════════════════════════════════════════════════════
create_account() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}${WHITE}           BUAT AKUN BARU                 ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}\n"

    while true; do
        read -rp "  Username          : " username
        [[ -z "$username" ]] && echo -e "  ${RED}Username tidak boleh kosong!${NC}" && continue
        validate_username "$username" || continue
        id "$username" &>/dev/null && echo -e "  ${RED}User sistem '${username}' sudah ada!${NC}" && continue
        grep -q "^${username}|" "$USER_DB" 2>/dev/null && echo -e "  ${RED}Sudah terdaftar di panel!${NC}" && continue
        break
    done

    while true; do
        read -rsp "  Password          : " password; echo ""
        [[ -z "$password" ]] && echo -e "  ${RED}Password tidak boleh kosong!${NC}" && continue
        read -rsp "  Konfirmasi Pass   : " password2; echo ""
        [[ "$password" != "$password2" ]] && echo -e "  ${RED}Password tidak cocok!${NC}" && continue
        break
    done

    while true; do
        read -rp "  Expired (hari)    : " expired_days
        [[ "$expired_days" =~ ^[0-9]+$ ]] && [[ $expired_days -gt 0 ]] && break
        echo -e "  ${RED}Masukkan angka hari valid (contoh: 30)!${NC}"
    done
    local expire_date; expire_date=$(date -d "+${expired_days} days" +"%Y-%m-%d")

    while true; do
        read -rp "  Limit Kuota GB    : [0=unlimited] " quota_gb
        [[ "$quota_gb" =~ ^[0-9]+$ ]] && break
        echo -e "  ${RED}Masukkan angka!${NC}"
    done

    while true; do
        read -rp "  Limit IP/Device   : [0=unlimited] " max_ip
        [[ "$max_ip" =~ ^[0-9]+$ ]] && break
        echo -e "  ${RED}Masukkan angka!${NC}"
    done

    echo ""
    echo -e "  Tipe akun: ${GREEN}[1]${NC}SSH+UDP  ${GREEN}[2]${NC}SSH Only  ${GREEN}[3]${NC}UDP Only"
    read -rp "  Pilih [1/2/3, default=1]: " acc_type
    case "$acc_type" in
        2) acc_label="SSH Only" ;;
        3) acc_label="UDP Only" ;;
        *) acc_label="SSH+UDP"; acc_type=1 ;;
    esac

    echo -e "\n  ${YELLOW}Membuat akun...${NC}"

    if [[ "$acc_type" != "3" ]]; then
        useradd -m -s /bin/bash "$username" &>/dev/null
        echo "${username}:${password}" | chpasswd
        chage -E "$expire_date" "$username" &>/dev/null
        _write_pam_limit "$username" "$max_ip"
    fi

    if [[ "$acc_type" != "2" ]] && [[ -f "$CONFIG_JSON" ]]; then
        python3 - <<PYEOF 2>/dev/null
import json
with open('$CONFIG_JSON') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if '$password' not in pw: pw.append('$password')
c['auth']['config']=pw
with open('$CONFIG_JSON','w') as f: json.dump(c,f,indent=2)
PYEOF
        systemctl restart zivpn.service &>/dev/null
    fi

    local created_date; created_date=$(date +"%Y-%m-%d")
    echo "${username}|${password}|${expire_date}|${quota_gb}|${max_ip}|${acc_label}|${created_date}|0" >> "$USER_DB"

    local qlabel iplabel srv_host srv_isp
    [[ "$quota_gb" -eq 0 ]] && qlabel="Unlimited" || qlabel="${quota_gb} GB"
    [[ "$max_ip"   -eq 0 ]] && iplabel="Unlimited" || iplabel="${max_ip} device"
    srv_host=$(get_host); srv_isp=$(get_isp)

    echo ""
    echo -e "  ${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}║${WHITE}${BOLD}        AKUN BERHASIL DIBUAT              ${NC}${GREEN}║${NC}"
    echo -e "  ${GREEN}╠══════════════════════════════════════════╣${NC}"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Nama"        "$username"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Password"    "$password"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "ISP"         "$srv_isp"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Host/Domain" "$srv_host"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Expired"     "$expire_date ($expired_days hari)"
    echo -e "  ${GREEN}╠══════════════════════════════════════════╣${NC}"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Tipe"        "$acc_label"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Limit Kuota" "$qlabel"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Limit IP"    "$iplabel"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Dibuat"      "$created_date"
    echo -e "  ${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    read -rp "  Tekan Enter untuk kembali ke menu..."
}

# ════════════════════════════════════════════════════════════
#  [2] LIST USER
# ════════════════════════════════════════════════════════════
list_users() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}${WHITE}                     DAFTAR AKUN ZIVPN                              ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠════╦══════════════╦════════════╦═════════╦══════════╦══════════════╣${NC}"
    echo -e "${CYAN}║${WHITE} No ${CYAN}║${WHITE} Username     ${CYAN}║${WHITE} Expired    ${CYAN}║${WHITE} Sisa    ${CYAN}║${WHITE} Kuota    ${CYAN}║${WHITE} Tipe         ${CYAN}║${NC}"
    echo -e "${CYAN}╠════╬══════════════╬════════════╬═════════╬══════════╬══════════════╣${NC}"

    if [[ ! -s "$USER_DB" ]]; then
        echo -e "${CYAN}║${NC}  ${YELLOW}Belum ada akun terdaftar.${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════╝${NC}"
        read -rp "  Tekan Enter untuk kembali..."; return
    fi

    local no=1
    while IFS='|' read -r uname pass expire quota maxip acctype created used; do
        local sisa; sisa=$(days_remaining "$expire")
        local sisa_str color
        if   [[ $sisa -lt 0  ]]; then color="${RED}";    sisa_str="EXPIRED"
        elif [[ $sisa -le 3  ]]; then color="${YELLOW}"; sisa_str="${sisa}h"
        else                          color="${GREEN}";  sisa_str="${sisa}h"
        fi
        local qlabel; [[ "$quota" -eq 0 ]] && qlabel="Unlimited" || qlabel="${quota} GB"
        printf "${CYAN}║${NC} %-3s ${CYAN}║${NC} %-12s ${CYAN}║${NC} %-10s ${CYAN}║${NC} ${color}%-7s${NC} ${CYAN}║${NC} %-8s ${CYAN}║${NC} %-12s ${CYAN}║${NC}\n" \
            "$no" "$uname" "$expire" "$sisa_str" "$qlabel" "$acctype"
        ((no++))
    done < "$USER_DB"

    echo -e "${CYAN}╚════╩══════════════╩════════════╩═════════╩══════════╩══════════════╝${NC}"
    echo -e "  Total: ${WHITE}$((no-1)) akun${NC}"; echo ""
    read -rp "  Tekan Enter untuk kembali ke menu..."
}

# ════════════════════════════════════════════════════════════
#  [3] DETAIL USER
# ════════════════════════════════════════════════════════════
detail_user() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}${WHITE}             DETAIL USER                  ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}\n"

    if [[ ! -s "$USER_DB" ]]; then
        echo -e "  ${RED}Belum ada akun terdaftar.${NC}\n"
        read -rp "  Tekan Enter untuk kembali..."; return
    fi

    read -rp "  Masukkan username : " username
    validate_username "$username" || { read -rp "  Tekan Enter untuk kembali..."; return; }
    local user_line; user_line=$(grep "^${username}|" "$USER_DB")
    if [[ -z "$user_line" ]]; then
        echo -e "\n  ${RED}User '${username}' tidak ditemukan!${NC}\n"
        read -rp "  Tekan Enter untuk kembali..."; return
    fi

    IFS='|' read -r uname pass expire quota maxip acctype created used <<< "$user_line"

    local sisa; sisa=$(days_remaining "$expire")
    local status_str status_color
    if   [[ $sisa -lt 0  ]]; then status_color="${RED}";    status_str="EXPIRED"
    elif [[ $sisa -le 3  ]]; then status_color="${YELLOW}"; status_str="Aktif – ${sisa} hari lagi ⚠"
    else                          status_color="${GREEN}";  status_str="Aktif – ${sisa} hari lagi"
    fi

    local active_sessions active_ips
    active_sessions=$(who 2>/dev/null | grep -c "^${uname} " || echo 0)
    active_ips=$(who 2>/dev/null | grep "^${uname} " | awk '{print $5}' | tr -d '()' | sort -u | tr '\n' ' ')
    [[ -z "$active_ips" ]] && active_ips="–"

    local qlabel iplabel
    [[ "$quota" -eq 0 ]] && qlabel="Unlimited" || qlabel="${quota} GB"
    [[ "$maxip" -eq 0 ]] && iplabel="Unlimited" || iplabel="${maxip} device"

    echo ""
    echo -e "  ${CYAN}╔══════════════════════════════════════════╗${NC}"
    printf  "  ${CYAN}║${NC}  %-14s: ${WHITE}%-24s${CYAN}║${NC}\n" "Username"    "$uname"
    printf  "  ${CYAN}║${NC}  %-14s: ${WHITE}%-24s${CYAN}║${NC}\n" "Password"    "$pass"
    printf  "  ${CYAN}║${NC}  %-14s: ${WHITE}%-24s${CYAN}║${NC}\n" "Tipe Akun"   "$acctype"
    printf  "  ${CYAN}║${NC}  %-14s: ${WHITE}%-24s${CYAN}║${NC}\n" "Dibuat"      "$created"
    echo -e "  ${CYAN}╠══════════════════════════════════════════╣${NC}"
    printf  "  ${CYAN}║${NC}  %-14s: ${WHITE}%-24s${CYAN}║${NC}\n" "Expired"     "$expire"
    printf  "  ${CYAN}║${NC}  %-14s: "                             "Status"
    echo -e "${status_color}${status_str}${NC}"
    echo -e "  ${CYAN}╠══════════════════════════════════════════╣${NC}"
    printf  "  ${CYAN}║${NC}  %-14s: ${WHITE}%-24s${CYAN}║${NC}\n" "Limit Kuota" "$qlabel"
    printf  "  ${CYAN}║${NC}  %-14s: ${WHITE}%-24s${CYAN}║${NC}\n" "Limit IP"    "$iplabel"
    echo -e "  ${CYAN}╠══════════════════════════════════════════╣${NC}"
    printf  "  ${CYAN}║${NC}  %-14s: ${WHITE}%-24s${CYAN}║${NC}\n" "Sesi Aktif"  "$active_sessions sesi"
    printf  "  ${CYAN}║${NC}  %-14s: ${WHITE}%-24s${CYAN}║${NC}\n" "IP Aktif"    "$active_ips"
    echo -e "  ${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}Opsi edit:${NC}"
    echo -e "  ${GREEN}[1]${NC} Perpanjang expired   ${GREEN}[2]${NC} Ganti password"
    echo -e "  ${GREEN}[3]${NC} Ubah limit kuota     ${GREEN}[4]${NC} Ubah limit IP"
    echo -e "  ${GREEN}[0]${NC} Kembali"
    echo ""; read -rp "  Pilih opsi: " sub_opt
    case "$sub_opt" in
        1) _extend_expired  "$username" ;;
        2) _change_password "$username" "$pass" ;;
        3) _change_quota    "$username" ;;
        4) _change_maxip    "$username" ;;
        *) return ;;
    esac
}

_extend_expired() {
    local username=$1
    read -rp "  Tambah berapa hari? : " add_days
    [[ ! "$add_days" =~ ^[0-9]+$ ]] && echo -e "  ${RED}Input tidak valid!${NC}" && return
    local cur pass acctype
    cur=$(grep "^${username}|" "$USER_DB" | cut -d'|' -f3)
    pass=$(grep "^${username}|" "$USER_DB" | cut -d'|' -f2)
    acctype=$(grep "^${username}|" "$USER_DB" | cut -d'|' -f6)
    local new_exp; new_exp=$(date -d "${cur} +${add_days} days" +"%Y-%m-%d")
    local tmpdb; tmpdb=$(mktemp)
    awk -F'|' -v u="$username" -v ne="$new_exp" 'BEGIN{OFS="|"} $1==u{$3=ne}1' \
        "$USER_DB" > "$tmpdb" && mv "$tmpdb" "$USER_DB"
    # Unlock user jika sebelumnya di-lock karena expired
    usermod -U "$username" 2>/dev/null
    chage -E "$new_exp" "$username" &>/dev/null
    # Tambah kembali password ke ZIVPN jika UDP
    if [[ "$acctype" != "SSH Only" ]] && [[ -f "$CONFIG_JSON" ]]; then
        python3 - <<PYEOF 2>/dev/null
import json
with open('$CONFIG_JSON') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if '$pass' not in pw: pw.append('$pass')
c['auth']['config']=pw
with open('$CONFIG_JSON','w') as f: json.dump(c,f,indent=2)
PYEOF
        systemctl restart zivpn.service &>/dev/null
    fi
    echo -e "\n  ${GREEN}✓ Expired diperbarui: ${new_exp} | Akun di-unlock${NC}\n"
    read -rp "  Tekan Enter untuk kembali..."
}

_change_password() {
    local username=$1 old_pass=$2
    read -rsp "  Password baru : " new_pass; echo ""
    [[ -z "$new_pass" ]] && echo -e "  ${RED}Password kosong!${NC}" && return
    echo "${username}:${new_pass}" | chpasswd 2>/dev/null
    local tmpdb; tmpdb=$(mktemp)
    awk -F'|' -v u="$username" -v np="$new_pass" 'BEGIN{OFS="|"} $1==u{$2=np}1' \
        "$USER_DB" > "$tmpdb" && mv "$tmpdb" "$USER_DB"
    if [[ -f "$CONFIG_JSON" ]]; then
        python3 - <<PYEOF 2>/dev/null
import json
with open('$CONFIG_JSON') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if '$old_pass' in pw: pw.remove('$old_pass')
if '$new_pass' not in pw: pw.append('$new_pass')
c['auth']['config']=pw
with open('$CONFIG_JSON','w') as f: json.dump(c,f,indent=2)
PYEOF
        systemctl restart zivpn.service &>/dev/null
    fi
    echo -e "\n  ${GREEN}✓ Password berhasil diubah!${NC}\n"
    read -rp "  Tekan Enter untuk kembali..."
}

_change_quota() {
    local username=$1
    read -rp "  Limit kuota baru GB (0=unlimited) : " nq
    [[ ! "$nq" =~ ^[0-9]+$ ]] && echo -e "  ${RED}Input tidak valid!${NC}" && return
    local tmpdb; tmpdb=$(mktemp)
    awk -F'|' -v u="$username" -v nq="$nq" 'BEGIN{OFS="|"} $1==u{$4=nq}1' \
        "$USER_DB" > "$tmpdb" && mv "$tmpdb" "$USER_DB"
    local lbl; [[ "$nq" -eq 0 ]] && lbl="Unlimited" || lbl="${nq} GB"
    echo -e "\n  ${GREEN}✓ Limit kuota: ${lbl}${NC}\n"
    read -rp "  Tekan Enter untuk kembali..."
}

_change_maxip() {
    local username=$1
    read -rp "  Limit IP baru (0=unlimited) : " ni
    [[ ! "$ni" =~ ^[0-9]+$ ]] && echo -e "  ${RED}Input tidak valid!${NC}" && return
    local tmpdb; tmpdb=$(mktemp)
    awk -F'|' -v u="$username" -v ni="$ni" 'BEGIN{OFS="|"} $1==u{$5=ni}1' \
        "$USER_DB" > "$tmpdb" && mv "$tmpdb" "$USER_DB"
    _write_pam_limit "$username" "$ni"
    local lbl; [[ "$ni" -eq 0 ]] && lbl="Unlimited" || lbl="${ni} device"
    echo -e "\n  ${GREEN}✓ Limit IP: ${lbl} (PAM + daemon aktif)${NC}\n"
    read -rp "  Tekan Enter untuk kembali..."
}

# ════════════════════════════════════════════════════════════
#  [4] HAPUS AKUN
# ════════════════════════════════════════════════════════════
delete_account() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}${RED}              HAPUS AKUN                  ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}\n"

    if [[ ! -s "$USER_DB" ]]; then
        echo -e "  ${RED}Belum ada akun terdaftar.${NC}\n"
        read -rp "  Tekan Enter untuk kembali..."; return
    fi

    local no=1
    echo -e "  ${YELLOW}Daftar akun:${NC}"
    while IFS='|' read -r uname rest; do
        echo -e "  ${GREEN}[${no}]${NC} ${uname}"; ((no++))
    done < "$USER_DB"
    echo ""

    read -rp "  Username yang akan dihapus : " username
    validate_username "$username" || { read -rp "  Tekan Enter untuk kembali..."; return; }
    local user_line; user_line=$(grep "^${username}|" "$USER_DB")
    if [[ -z "$user_line" ]]; then
        echo -e "\n  ${RED}User '${username}' tidak ditemukan!${NC}\n"
        read -rp "  Tekan Enter untuk kembali..."; return
    fi

    IFS='|' read -r uname pass expire quota maxip acctype created used <<< "$user_line"

    echo -e "\n  ${YELLOW}Yakin hapus '${WHITE}${username}${YELLOW}'? [y/N]${NC}"
    read -rp "  Konfirmasi : " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && echo -e "  ${YELLOW}Dibatalkan.${NC}" && return

    if id "$username" &>/dev/null; then
        pkill -u "$username" 2>/dev/null
        userdel -r "$username" &>/dev/null
    fi
    _remove_pam_limit "$username"

    if [[ -f "$CONFIG_JSON" ]]; then
        python3 - <<PYEOF 2>/dev/null
import json
with open('$CONFIG_JSON') as f: c=json.load(f)
pw=c.get('auth',{}).get('config',[])
if '$pass' in pw: pw.remove('$pass')
if not pw: pw.append('zi')
c['auth']['config']=pw
with open('$CONFIG_JSON','w') as f: json.dump(c,f,indent=2)
PYEOF
        systemctl restart zivpn.service &>/dev/null
    fi

    local tmpdb; tmpdb=$(mktemp)
    awk -F'|' -v u="$username" '$1!=u' "$USER_DB" > "$tmpdb" && mv "$tmpdb" "$USER_DB"
    echo -e "\n  ${GREEN}✓ Akun '${username}' berhasil dihapus!${NC}\n"
    read -rp "  Tekan Enter untuk kembali ke menu..."
}

# ════════════════════════════════════════════════════════════
#  [5] RESTART / STATUS SERVICE
# ════════════════════════════════════════════════════════════
service_management() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}${WHITE}        MANAJEMEN SERVICE ZIVPN           ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}\n"
    echo -e "  ${GREEN}[1]${NC} Status service"
    echo -e "  ${GREEN}[2]${NC} Restart service"
    echo -e "  ${GREEN}[3]${NC} Stop service"
    echo -e "  ${GREEN}[4]${NC} Start service"
    echo -e "  ${GREEN}[5]${NC} Log service (20 baris)"
    echo -e "  ${GREEN}[6]${NC} Log enforcement (expire/IP/kuota)"
    echo -e "  ${GREEN}[7]${NC} Cek IP banned Fail2Ban"
    echo -e "  ${GREEN}[8]${NC} Lihat rules iptables aktif"
    echo -e "  ${GREEN}[0]${NC} Kembali"
    echo ""; read -rp "  Pilih opsi: " svc_opt

    case "$svc_opt" in
        1) echo ""; systemctl status zivpn.service --no-pager -l ;;
        2) systemctl restart zivpn.service; sleep 1
           systemctl is-active --quiet zivpn.service \
               && echo -e "\n  ${GREEN}✓ Direstart!${NC}" \
               || echo -e "\n  ${RED}✗ Gagal restart!${NC}" ;;
        3) systemctl stop zivpn.service; echo -e "\n  ${YELLOW}Service dihentikan.${NC}" ;;
        4) systemctl start zivpn.service; sleep 1
           systemctl is-active --quiet zivpn.service \
               && echo -e "\n  ${GREEN}✓ Distart!${NC}" \
               || echo -e "\n  ${RED}✗ Gagal start!${NC}" ;;
        5) echo ""; journalctl -u zivpn.service -n 20 --no-pager ;;
        6) echo ""; tail -n 30 /var/log/zivpn-enforce.log 2>/dev/null || echo "  Log kosong." ;;
        7) echo ""; fail2ban-client status sshd 2>/dev/null || echo "  Fail2Ban tidak aktif." ;;
        8) echo ""; iptables -L INPUT -n --line-numbers 2>/dev/null ;;
        *) return ;;
    esac
    echo ""; read -rp "  Tekan Enter untuk kembali ke menu..."
}

# ════════════════════════════════════════════════════════════
#  [8] UBAH HOST / DOMAIN & ISP
# ════════════════════════════════════════════════════════════
change_host() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${BOLD}${WHITE}       UBAH HOST / DOMAIN & ISP           ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}\n"

    local cur_host cur_isp; cur_host=$(get_host); cur_isp=$(get_isp)
    echo -e "  Host/Domain saat ini : ${WHITE}${cur_host}${NC}"
    echo -e "  ISP saat ini         : ${WHITE}${cur_isp}${NC}"; echo ""

    read -rp "  Host/Domain baru (kosong = tidak diubah): " new_host
    [[ -z "$new_host" ]] && new_host="$cur_host"

    echo -e "  ${YELLOW}[1]${NC} Deteksi ISP otomatis  ${YELLOW}[2]${NC} Masukkan manual"
    read -rp "  Pilih [1/2, default=1]: " isp_opt

    local new_isp
    if [[ "$isp_opt" == "2" ]]; then
        read -rp "  ISP baru : " new_isp; [[ -z "$new_isp" ]] && new_isp="$cur_isp"
    else
        echo -e "  ${YELLOW}Mendeteksi ISP...${NC}"
        local server_ip; server_ip=$(curl -s4 --max-time 4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
        new_isp=$(fetch_isp "$server_ip")
        echo -e "  ISP terdeteksi : ${WHITE}${new_isp}${NC}"
        read -rp "  Ubah? (kosong = gunakan): " override_isp
        [[ -n "$override_isp" ]] && new_isp="$override_isp"
    fi

    save_server_conf "$new_host" "$new_isp"
    echo ""; echo -e "  ${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}║${WHITE}${BOLD}       PENGATURAN DIPERBARUI              ${NC}${GREEN}║${NC}"
    echo -e "  ${GREEN}╠══════════════════════════════════════════╣${NC}"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "Host/Domain" "$new_host"
    printf  "  ${GREEN}║${NC}  %-14s: ${WHITE}%-23s${GREEN}║${NC}\n" "ISP"         "$new_isp"
    echo -e "  ${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""; read -rp "  Tekan Enter untuk kembali ke menu..."
}

# ════════════════════════════════════════════════════════════
#  [9] DETAIL INFO VPS
# ════════════════════════════════════════════════════════════
detail_vps() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}${BOLD}            DETAIL INFO VPS                          ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"; echo ""

    local pub_ip priv_ip iface mac cur_host cur_isp
    pub_ip=$(curl -s4 --max-time 4 ifconfig.me 2>/dev/null || echo "N/A")
    priv_ip=$(hostname -I | awk '{print $1}')
    iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    mac=$(cat /sys/class/net/"${iface}"/address 2>/dev/null || echo "N/A")
    cur_host=$(get_host); cur_isp=$(get_isp)

    local os_name kernel arch hostname_str
    os_name=$(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
    kernel=$(uname -r); arch=$(uname -m); hostname_str=$(hostname)

    local cpu_model cpu_cores cpu_threads cpu_freq cpu_usage
    cpu_model=$(grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//')
    cpu_cores=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null)
    cpu_threads=$(nproc 2>/dev/null || echo "$cpu_cores")
    cpu_freq=$(grep -m1 "cpu MHz" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//' | cut -d. -f1)
    [[ -n "$cpu_freq" ]] && cpu_freq="${cpu_freq} MHz" || cpu_freq="N/A"
    cpu_usage=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    [[ -n "$cpu_usage" ]] && cpu_usage="${cpu_usage}%" || cpu_usage="N/A"

    local ram_total ram_used ram_free ram_cached ram_pct
    ram_total=$(free -m | awk '/^Mem:/{print $2}')
    ram_used=$(free -m  | awk '/^Mem:/{print $3}')
    ram_free=$(free -m  | awk '/^Mem:/{print $4}')
    ram_cached=$(free -m | awk '/^Mem:/{print $6}')
    [[ "$ram_total" -gt 0 ]] && ram_pct=$(( ram_used * 100 / ram_total )) || ram_pct=0

    local swap_total swap_used swap_free
    swap_total=$(free -m | awk '/^Swap:/{print $2}')
    swap_used=$(free -m  | awk '/^Swap:/{print $3}')
    swap_free=$(free -m  | awk '/^Swap:/{print $4}')

    local disk_total disk_used disk_free disk_pct
    disk_total=$(df -h / | awk 'NR==2{print $2}')
    disk_used=$(df -h  / | awk 'NR==2{print $3}')
    disk_free=$(df -h  / | awk 'NR==2{print $4}')
    disk_pct=$(df /    | awk 'NR==2{print $5}')

    local uptime_str load_avg sys_time sys_tz boot_time
    uptime_str=$(uptime -p 2>/dev/null | sed 's/up //')
    load_avg=$(cat /proc/loadavg | awk '{print $1" "$2" "$3}')
    sys_time=$(date '+%Y-%m-%d %H:%M:%S')
    sys_tz=$(timedatectl 2>/dev/null | grep "Time zone" | awk '{print $3" "$4" "$5}' || date '+%Z %z')
    boot_time=$(who -b 2>/dev/null | awk '{print $3" "$4}')

    local rx_bytes tx_bytes rx_hr tx_hr
    rx_bytes=$(cat /sys/class/net/"${iface}"/statistics/rx_bytes 2>/dev/null || echo 0)
    tx_bytes=$(cat /sys/class/net/"${iface}"/statistics/tx_bytes 2>/dev/null || echo 0)
    rx_hr=$(numfmt --to=iec --suffix=B "$rx_bytes" 2>/dev/null || echo "${rx_bytes}B")
    tx_hr=$(numfmt --to=iec --suffix=B "$tx_bytes" 2>/dev/null || echo "${tx_bytes}B")

    local total_proc login_users
    total_proc=$(ps aux | wc -l)
    login_users=$(who 2>/dev/null | wc -l)

    local zivpn_ver svc_status_str total_users
    [[ -f "$ZIVPN_BIN" ]] && zivpn_ver="v1.4.9" || zivpn_ver="Tidak terpasang"
    systemctl is-active --quiet zivpn.service 2>/dev/null \
        && svc_status_str="${GREEN}Running${NC}" || svc_status_str="${RED}Stopped${NC}"
    total_users=$(grep -c "." "$USER_DB" 2>/dev/null || echo 0)

    local ddos_str f2b_banned ar_status
    iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|limit" \
        && ddos_str="${GREEN}Aktif${NC}" || ddos_str="${RED}Tidak aktif${NC}"
    f2b_banned=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP" | awk -F: '{print $2}' | xargs)
    [[ -z "$f2b_banned" ]] && f2b_banned="0 IP"
    crontab -l 2>/dev/null | grep -q "zivpn-autoreboot" \
        && ar_status="${GREEN}Aktif${NC}" || ar_status="${YELLOW}Tidak aktif${NC}"

    echo -e "  ${CYAN}┌─────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${WHITE}${BOLD}  🌐 JARINGAN                                    ${NC}${CYAN}│${NC}"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "IP Publik"    "$pub_ip"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "IP Lokal"     "$priv_ip"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Interface"    "$iface"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "MAC Address"  "$mac"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "ISP"          "$cur_isp"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Host/Domain"  "$cur_host"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "TX (total)"   "$tx_hr"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "RX (total)"   "$rx_hr"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    echo -e "  ${CYAN}│${WHITE}${BOLD}  🖥️  SISTEM                                     ${NC}${CYAN}│${NC}"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Hostname"      "$hostname_str"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "OS"            "$os_name"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Kernel"        "$kernel"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Arsitektur"    "$arch"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Waktu Sistem"  "$sys_time"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Timezone"      "$sys_tz"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Boot Terakhir" "$boot_time"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Uptime"        "$uptime_str"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Load Avg"      "$load_avg"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    echo -e "  ${CYAN}│${WHITE}${BOLD}  ⚡ CPU                                         ${NC}${CYAN}│${NC}"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Model"          "$cpu_model"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Core/Thread"    "${cpu_cores}c / ${cpu_threads}t"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Frekuensi"      "$cpu_freq"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Penggunaan"     "$cpu_usage"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    echo -e "  ${CYAN}│${WHITE}${BOLD}  💾 MEMORI                                      ${NC}${CYAN}│${NC}"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "RAM Total"     "${ram_total} MB"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "RAM Dipakai"   "${ram_used} MB (${ram_pct}%)"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "RAM Bebas"     "${ram_free} MB"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Cache"         "${ram_cached} MB"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Swap Total"    "${swap_total} MB"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Swap Dipakai"  "${swap_used} MB"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Swap Bebas"    "${swap_free} MB"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    echo -e "  ${CYAN}│${WHITE}${BOLD}  💿 DISK                                        ${NC}${CYAN}│${NC}"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Total"        "$disk_total"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Dipakai"      "$disk_used ($disk_pct)"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Bebas"        "$disk_free"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    echo -e "  ${CYAN}│${WHITE}${BOLD}  📡 ZIVPN & KEAMANAN                           ${NC}${CYAN}│${NC}"
    echo -e "  ${CYAN}├─────────────────────────────────────────────────┤${NC}"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Versi ZIVPN"   "$zivpn_ver"
    printf  "  ${CYAN}│${NC}  %-16s: "                             "Service"
    echo -e "${svc_status_str}"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Total Akun"    "$total_users akun"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Port UDP"      "5667 | Forward: 6000-19999"
    printf  "  ${CYAN}│${NC}  %-16s: "                             "Anti-DDoS"
    echo -e "${ddos_str}"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Fail2Ban Ban"  "$f2b_banned"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "Proses"        "$total_proc"
    printf  "  ${CYAN}│${NC}  %-16s: ${WHITE}%-28s${CYAN}│${NC}\n" "User Login"    "$login_users sesi"
    printf  "  ${CYAN}│${NC}  %-16s: "                             "Auto Reboot"
    echo -e "${ar_status}"
    echo -e "  ${CYAN}└─────────────────────────────────────────────────┘${NC}"
    echo ""; read -rp "  Tekan Enter untuk kembali ke menu..."
}

# ════════════════════════════════════════════════════════════
#  [A] AUTO REBOOT HARIAN 00.00 WIB
# ════════════════════════════════════════════════════════════
setup_auto_reboot() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${WHITE}${BOLD}    AUTO REBOOT HARIAN — 00.00 WIB (17:00 UTC)      ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}\n"

    local is_active=false
    crontab -l 2>/dev/null | grep -q "zivpn-autoreboot" && is_active=true

    if [[ "$is_active" == true ]]; then
        echo -e "  Status   : ${GREEN}● Aktif${NC}"
        echo -e "  Jadwal   : ${WHITE}Setiap hari 00.00 WIB${NC}"
        echo -e "  Script   : ${WHITE}${REBOOT_SCRIPT}${NC}"; echo ""
        echo -e "  ${YELLOW}[1]${NC} Lihat isi script"
        echo -e "  ${YELLOW}[2]${NC} Lihat log reboot terakhir"
        echo -e "  ${RED}[3]${NC} Nonaktifkan"
        echo -e "  ${GREEN}[0]${NC} Kembali"
        echo ""; read -rp "  Pilih: " opt
        case "$opt" in
            1) echo ""; cat "$REBOOT_SCRIPT" 2>/dev/null ;;
            2) echo ""; tail -n 30 /var/log/zivpn-reboot.log 2>/dev/null || echo "  Log belum ada." ;;
            3) crontab -l 2>/dev/null | grep -v "zivpn-autoreboot" | crontab -
               rm -f "$REBOOT_SCRIPT"
               echo -e "\n  ${YELLOW}✓ Auto reboot dinonaktifkan.${NC}" ;;
            *) ;;
        esac
        echo ""; read -rp "  Tekan Enter..."; return
    fi

    echo -e "  Status   : ${RED}● Tidak aktif${NC}"; echo ""
    echo -e "  Akan dilakukan tiap jam ${WHITE}00.00 WIB${NC}:"
    echo -e "  ${CYAN}•${NC} Flush cache kernel"
    echo -e "  ${CYAN}•${NC} Bersihkan log journald (>1 hari)"
    echo -e "  ${CYAN}•${NC} Bersihkan /tmp (>1 hari)"
    echo -e "  ${CYAN}•${NC} Hapus log lama *.gz *.1 (>3 hari)"
    echo -e "  ${CYAN}•${NC} Flush swap"
    echo -e "  ${CYAN}•${NC} Reboot server"; echo ""
    read -rp "  Aktifkan? [y/N]: " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && echo -e "  ${YELLOW}Dibatalkan.${NC}" && return

    cat > "$REBOOT_SCRIPT" <<'REBOOTEOF'
#!/bin/bash
LOG="/var/log/zivpn-reboot.log"
echo "============================================" >> "$LOG"
echo "  Auto Reboot: $(date '+%Y-%m-%d %H:%M:%S WIB')" >> "$LOG"
echo "============================================" >> "$LOG"
echo "[1] Flush cache kernel..." >> "$LOG"
sync; echo 3 > /proc/sys/vm/drop_caches
sysctl -w vm.drop_caches=3 >> "$LOG" 2>&1
echo "[2] Bersihkan log journald..." >> "$LOG"
journalctl --vacuum-time=1d >> "$LOG" 2>&1
echo "[3] Bersihkan /tmp..." >> "$LOG"
find /tmp -mindepth 1 -mtime +1 -delete 2>/dev/null
echo "[4] Bersihkan log lama..." >> "$LOG"
find /var/log -name "*.gz" -mtime +3 -delete 2>/dev/null
find /var/log -name "*.1"  -mtime +3 -delete 2>/dev/null
echo "[5] Flush swap..." >> "$LOG"
swapoff -a && swapon -a 2>/dev/null
echo "[6] Info sebelum reboot:" >> "$LOG"
free -m >> "$LOG"; df -h / >> "$LOG"
tail -n 500 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
echo "  Reboot dalam 5 detik..." >> "$LOG"
sleep 5; /sbin/reboot
REBOOTEOF
    chmod +x "$REBOOT_SCRIPT"
    ( crontab -l 2>/dev/null | grep -v "zivpn-autoreboot"
      echo "0 17 * * * $REBOOT_SCRIPT >> /var/log/zivpn-reboot.log 2>&1 # zivpn-autoreboot"
    ) | crontab -

    local tz; tz=$(timedatectl 2>/dev/null | grep "Time zone" | awk '{print $3}' || echo "UTC")
    echo -e "\n  ${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}║  ✓  Auto Reboot Diaktifkan              ║${NC}"
    echo -e "  ${GREEN}╠══════════════════════════════════════════╣${NC}"
    printf  "  ${GREEN}║${NC}  %-16s: ${WHITE}%-21s${GREEN}║${NC}\n" "Jadwal"    "Setiap hari 00.00 WIB"
    printf  "  ${GREEN}║${NC}  %-16s: ${WHITE}%-21s${GREEN}║${NC}\n" "Cron"      "0 17 * * * (UTC)"
    printf  "  ${GREEN}║${NC}  %-16s: ${WHITE}%-21s${GREEN}║${NC}\n" "Timezone"  "$tz (server)"
    printf  "  ${GREEN}║${NC}  %-16s: ${WHITE}%-21s${GREEN}║${NC}\n" "Log"       "/var/log/zivpn-reboot.log"
    echo -e "  ${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo -e "\n  ${YELLOW}ℹ  Set timezone WIB: timedatectl set-timezone Asia/Jakarta${NC}"
    echo ""; read -rp "  Tekan Enter untuk kembali ke menu..."
}

# ════════════════════════════════════════════════════════════
#  [6] UNINSTALL ZIVPN
# ════════════════════════════════════════════════════════════
uninstall_zivpn() {
    clear
    echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║${BOLD}${WHITE}           UNINSTALL ZIVPN UDP                       ${NC}${RED}║${NC}"
    echo -e "${RED}║${YELLOW}   src: github.com/zahidbd2/udp-zivpn uninstall.sh   ${NC}${RED}║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}\n"
    echo -e "  ${RED}⚠  Yang akan dihapus:${NC}"
    echo -e "     • Binary, config, service ZIVPN"
    echo -e "     • Rules iptables port 6000-19999"
    echo -e "     • Script enforcement (expire/IP/kuota)"
    echo -e "     • Rules anti-DDoS iptables"
    echo -e "     • Sysctl anti-DDoS"; echo ""
    read -rp "  Yakin uninstall ZIVPN + Anti-DDoS? [y/N]: " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && echo -e "  ${YELLOW}Dibatalkan.${NC}" && return

    echo -e "\n  ${YELLOW}Uninstalling ZiVPN ...${NC}"
    systemctl stop    zivpn.service zivpn_backfill.service 2>/dev/null
    systemctl disable zivpn.service zivpn_backfill.service 2>/dev/null
    rm -f /etc/systemd/system/zivpn.service /etc/systemd/system/zivpn_backfill.service
    systemctl daemon-reload 2>/dev/null
    killall zivpn 2>/dev/null
    rm -rf /etc/zivpn
    rm -f  "$ZIVPN_BIN" "$ENFORCE_EXPIRE" "$ENFORCE_IP" "$ENFORCE_QUOTA"

    # Hapus cron enforcement
    crontab -l 2>/dev/null | grep -v "zivpn-expire-check\|zivpn-ip-check\|zivpn-quota-check" | crontab -

    # Hapus iptables PREROUTING forwarding
    local iface
    iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    iptables -t nat -D PREROUTING -i "$iface" -p udp --dport 6000:19999 \
        -j DNAT --to-destination :5667 2>/dev/null

    # Reset iptables ke policy ACCEPT (hapus anti-DDoS rules)
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -F INPUT
    iptables -F FORWARD
    iptables-save > /etc/iptables/rules.v4 2>/dev/null

    # Hapus sysctl anti-DDoS
    rm -f /etc/sysctl.d/99-zivpn-antiddos.conf
    sysctl --system >/dev/null 2>&1

    echo -e "  ${YELLOW}Cleaning Cache & Swap${NC}"
    echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
    swapoff -a && swapon -a 2>/dev/null

    echo ""
    pgrep "zivpn" >/dev/null && echo -e "  ${RED}Server Running — coba lagi${NC}" || echo -e "  ${GREEN}Server Stopped${NC}"
    [[ -e "$ZIVPN_BIN" ]] && echo -e "  ${RED}Files still remaining${NC}" || echo -e "  ${GREEN}Successfully Removed${NC}"
    echo -e "  ${YELLOW}Done. Data panel: ${PANEL_DIR}${NC}"
    echo ""; read -rp "  Tekan Enter untuk kembali ke menu..."
}

# ════════════════════════════════════════════════════════════
#  [7] UNINSTALL PANEL
# ════════════════════════════════════════════════════════════
uninstall_panel() {
    clear
    echo -e "${RED}╔══════════════════════════════════════════╗${NC}"
    echo -e "${RED}║${BOLD}${WHITE}          UNINSTALL PANEL ZIVPN           ${NC}${RED}║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════╝${NC}\n"
    echo -e "  ${RED}⚠  Yang akan dihapus:${NC}"
    echo -e "     • Database akun : ${PANEL_DIR}"
    echo -e "     • Shortcut      : ${PANEL_SCRIPT}"
    echo -e "     • Script panel  : $(realpath "$0")"; echo ""
    read -rp "  Yakin? [y/N]: " confirm
    [[ "$confirm" != "y" && "$confirm" != "Y" ]] && echo -e "  ${YELLOW}Dibatalkan.${NC}" && return
    crontab -l 2>/dev/null | grep -v "zivpn-autoreboot" | crontab -
    rm -rf "$PANEL_DIR"
    rm -f  "$PANEL_SCRIPT" "$REBOOT_SCRIPT"
    local self; self=$(realpath "$0")
    echo -e "\n  ${GREEN}✓ Panel berhasil diuninstall!${NC}\n"
    rm -f "$self"; exit 0
}

# ════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════
main() {
    check_root
    init_panel
    install_shortcut

    # Pasang enforcement daemon otomatis jika belum ada
    if [[ ! -f "$ENFORCE_EXPIRE" ]] || [[ ! -f "$ENFORCE_IP" ]] || [[ ! -f "$ENFORCE_QUOTA" ]]; then
        install_enforcement >/dev/null 2>&1
    fi

    while true; do
        show_banner
        read -rp "  Pilih menu [0-9 / A / x]: " choice
        case "$choice" in
            0) install_zivpn      ;;
            1) create_account     ;;
            2) list_users         ;;
            3) detail_user        ;;
            4) delete_account     ;;
            5) service_management ;;
            6) uninstall_zivpn    ;;
            7) uninstall_panel    ;;
            8) change_host        ;;
            9) detail_vps         ;;
            a|A) setup_auto_reboot ;;
            x|X|q|Q)
                echo -e "\n  ${GREEN}Sampai jumpa!${NC}\n"; exit 0 ;;
            *)
                echo -e "\n  ${RED}Pilihan tidak valid!${NC}"; sleep 1 ;;
        esac
    done
}

main "$@"
