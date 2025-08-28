#!/usr/bin/env bash
# Harden a Linux server with optional modules.
# Works on Debian/Ubuntu and RHEL/Rocky-like.
# Usage examples (see README.md).

set -euo pipefail

# ---------- Aux ----------
red()   { printf "\033[1;31m%s\033[0m\n" "$*"; }
green() { printf "\033[1;32m%s\033[0m\n" "$*"; }
blue()  { printf "\033[1;34m%s\033[0m\n" "$*"; }
yellow(){ printf "\033[1;33m%s\033[0m\n" "$*"; }

need_root() { [ "$EUID" -eq 0 ] || { red "Ejecuta como root (sudo)."; exit 1; }; }
ts() { date +"%Y%m%d-%H%M%S"; }
backup_dir="/root/hardening-backups/$(ts)"
mkdir -p "$backup_dir"

usage() {
  cat <<'EOF'
harden.sh - automatiza tareas comunes de hardening

Flags:
  --all                       Ejecuta (casi) todo: firewall, SSH, fail2ban, journald, parches, auditd, lynis
  --firewall [auto|ufw|nft|skip]
  --allow-ports "22,80,443"   Puertos a permitir además del SSH (coma-separados)
  --ssh-port N                Fuerza puerto SSH si quieres cambiarlo
  --harden-ssh                Endurecer SSH (root no, sin password, sólo claves)
  --mfa                       Habilita OTP (Google Authenticator) para SSH (publickey + OTP)
  --fail2ban                  Instala y configura fail2ban (envía email si --email)
  --email "admin@ejemplo"     Correo para alertas fail2ban (opcional)
  --journald                  Persistencia y límites de journal
  --unattended-upgrades       Parches automáticos
  --auditd                    Auditoría básica (auditd + reglas)
  --lynis                     Instala lynis y crea cron semanal
  --backups                   Configura backup diario con restic (si hay variables RESTIC_*)
  --skip-reboot               No sugiere reinicio
  -h|--help                   Ayuda

Ejemplos:
  sudo bash harden.sh --all --firewall ufw --allow-ports "22,80,443" --email ops@midominio.com
  sudo bash harden.sh --harden-ssh --mfa --fail2ban --email sec@midominio.com
  sudo bash harden.sh --backups   # requiere RESTIC_REPOSITORY, RESTIC_PASSWORD, etc.
EOF
}

# ---------- Parse CLI ----------
ALL=0; MFA=0; FAIL2BAN=0; JOURNALD=0; AUTO_UPDATES=0; AUDITD=0; LYNIS=0; BACKUPS=0; HARDEN_SSH=0
FIREWALL="auto"; ALLOW_PORTS=""; ALERT_EMAIL=""; SSH_PORT=""
SKIP_REBOOT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all) ALL=1 ;;
    --mfa) MFA=1 ;;
    --fail2ban) FAIL2BAN=1 ;;
    --journald) JOURNALD=1 ;;
    --unattended-upgrades) AUTO_UPDATES=1 ;;
    --auditd) AUDITD=1 ;;
    --lynis) LYNIS=1 ;;
    --backups) BACKUPS=1 ;;
    --harden-ssh) HARDEN_SSH=1 ;;
    --firewall) FIREWALL="${2:-auto}"; shift ;;
    --allow-ports) ALLOW_PORTS="${2:-}"; shift ;;
    --email) ALERT_EMAIL="${2:-}"; shift ;;
    --ssh-port) SSH_PORT="${2:-}"; shift ;;
    --skip-reboot) SKIP_REBOOT=1 ;;
    -h|--help) usage; exit 0 ;;
    *) red "Flag desconocida: $1"; usage; exit 1 ;;
  esac
  shift
done

if [[ $ALL -eq 1 ]]; then
  HARDEN_SSH=1; FAIL2BAN=1; JOURNALD=1; AUTO_UPDATES=1; AUDITD=1; LYNIS=1
  # Firewall por defecto con auto detección
fi

need_root

# ---------- OS detect & pkg helpers ----------
. /etc/os-release || { red "No se pudo leer /etc/os-release"; exit 1; }
OS_FAMILY="unknown"
PKG_INSTALL=""
PKG_UPDATE=""
case "$ID" in
  debian|ubuntu)
    OS_FAMILY="debian"
    PKG_UPDATE="apt-get update -y"
    PKG_INSTALL="DEBIAN_FRONTEND=noninteractive apt-get install -y"
    ;;
  rhel|rocky|almalinux|centos)
    OS_FAMILY="rhel"
    # dnf si existe, si no yum
    if command -v dnf >/dev/null 2>&1; then
      PKG_UPDATE="dnf makecache -y"
      PKG_INSTALL="dnf install -y"
    else
      PKG_UPDATE="yum makecache -y"
      PKG_INSTALL="yum install -y"
    fi
    ;;
  *)
    yellow "ID=$ID no reconocido; se intentará compatibilidad genérica"
    if command -v apt-get >/dev/null 2>&1; then
      OS_FAMILY="debian"; PKG_UPDATE="apt-get update -y"; PKG_INSTALL="DEBIAN_FRONTEND=noninteractive apt-get install -y"
    elif command -v dnf >/dev/null 2>&1; then
      OS_FAMILY="rhel"; PKG_UPDATE="dnf makecache -y"; PKG_INSTALL="dnf install -y"
    elif command -v yum >/dev/null 2>&1; then
      OS_FAMILY="rhel"; PKG_UPDATE="yum makecache -y"; PKG_INSTALL="yum install -y"
    else
      red "No se detectó gestor de paquetes compatible"; exit 1
    fi
    ;;
esac

run() { bash -lc "$*"; }

# ---------- Helpers ----------
ensure_pkg() {
  local pkgs=("$@")
  blue "Instalando paquetes: ${pkgs[*]}"
  run "$PKG_UPDATE"
  run "$PKG_INSTALL ${pkgs[*]}"
}

file_set_kv() {
  # Asegura "Key value" en archivo conf (agrega al final si no existe)
  local file="$1" key="$2" value="$3"
  mkdir -p "$(dirname "$file")"
  touch "$file"
  if grep -Eiq "^\s*#?\s*${key}\b" "$file"; then
    cp -a "$file" "$backup_dir/$(basename "$file").bak"
    sed -ri "s|^\s*#?\s*(${key})\b.*|\1 $value|I" "$file"
  else
    cp -a "$file" "$backup_dir/$(basename "$file").bak"
    echo "$key $value" >> "$file"
  fi
}

append_if_missing() {
  local file="$1"; shift
  local line="$*"
  grep -Fxq "$line" "$file" || echo "$line" >> "$file"
}

# Detect SSH port actual si no se fuerza
detect_ssh_port() {
  if [[ -n "$SSH_PORT" ]]; then echo "$SSH_PORT"; return; fi
  if command -v sshd >/dev/null 2>&1; then
    local p
    p="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')" || true
    [[ -n "$p" ]] && { echo "$p"; return; }
  fi
  # fallback al archivo
  if [[ -f /etc/ssh/sshd_config ]]; then
    local p
    p="$(awk '/^\s*Port /{print $2; exit}' /etc/ssh/sshd_config)" || true
    [[ -n "$p" ]] && { echo "$p"; return; }
  fi
  echo "22"
}

# ---------- Modules ----------
setup_firewall() {
  local mode="$1" allow_ports_csv="$2" sshp="$3"
  local allow_ports=()
  IFS=',' read -r -a allow_ports <<<"$allow_ports_csv"

  if [[ "$mode" == "auto" ]]; then
    if [[ "$OS_FAMILY" == "debian" ]] && command -v ufw >/dev/null 2>&1; then
      mode="ufw"
    elif [[ "$OS_FAMILY" == "debian" ]]; then
      mode="ufw"
    else
      mode="nft"
    fi
  fi

  if [[ "$mode" == "ufw" ]]; then
    blue "[Firewall] Configurando UFW"
    ensure_pkg ufw
    ufw --force reset || true
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow "$sshp"/tcp
    for p in "${allow_ports[@]}"; do
      p_trim="$(echo "$p" | xargs)"
      [[ -n "$p_trim" && "$p_trim" != "$sshp" ]] && ufw allow "$p_trim"/tcp
    done
    yes | ufw enable
    ufw status verbose
    green "UFW configurado (SSH $sshp permitido)."
  elif [[ "$mode" == "nft" ]]; then
    blue "[Firewall] Configurando nftables"
    ensure_pkg nftables
    cp -a /etc/nftables.conf "$backup_dir/nftables.conf.bak" 2>/dev/null || true
    cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  set allowed_tcp { type inet_service; flags interval; elements = { $sshp$( [[ -n "$allow_ports_csv" ]] && printf ", %s" "$(echo "$allow_ports_csv" | tr -d ' ' | sed "s/,/, /g")" ) } }

  chain input {
    type filter hook input priority 0;
    policy drop;

    ct state established,related accept
    iif "lo" accept
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    tcp dport @allowed_tcp accept
    udp dport @allowed_tcp accept
  }

  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
    systemctl enable nftables
    systemctl restart nftables
    green "nftables configurado (SSH $sshp permitido)."
  elif [[ "$mode" == "skip" ]]; then
    yellow "Firewall omitido (--firewall skip)."
  else
    red "Modo firewall no válido: $mode"; exit 1
  fi
}

harden_ssh() {
  blue "[SSH] Endureciendo configuración"
  ensure_pkg openssh-server || true
  local f="/etc/ssh/sshd_config"
  cp -a "$f" "$backup_dir/sshd_config.bak"

  local port_new
  port_new="$(detect_ssh_port)"
  [[ -n "$SSH_PORT" ]] && port_new="$SSH_PORT"

  # Asegurar claves, desactivar root y passwords
  sed -ri 's/^\s*#?\s*PermitRootLogin\s+.*/PermitRootLogin no/I' "$f" || true
  sed -ri 's/^\s*#?\s*PasswordAuthentication\s+.*/PasswordAuthentication no/I' "$f" || true
  sed -ri 's/^\s*#?\s*PubkeyAuthentication\s+.*/PubkeyAuthentication yes/I' "$f" || true
  # KbdInteractive/Challenge según versión
  if sshd -T 2>/dev/null | grep -q '^kbdinteractiveauthentication'; then
    sed -ri 's/^\s*#?\s*KbdInteractiveAuthentication\s+.*/KbdInteractiveAuthentication no/I' "$f" || append_if_missing "$f" "KbdInteractiveAuthentication no"
  else
    sed -ri 's/^\s*#?\s*ChallengeResponseAuthentication\s+.*/ChallengeResponseAuthentication no/I' "$f" || append_if_missing "$f" "ChallengeResponseAuthentication no"
  fi

  if ! grep -Eq '^\s*Port\s+' "$f"; then
    echo "Port $port_new" >> "$f"
  elif [[ -n "$SSH_PORT" ]]; then
    sed -ri "s/^\s*#?\s*Port\s+.*/Port $port_new/" "$f"
  fi

  systemctl reload sshd || systemctl reload ssh || true
  green "SSH endurecido. Puerto: $port_new. Root login: NO. Password: NO."
}

enable_mfa() {
  blue "[SSH] Habilitando OTP (Google Authenticator)"
  if [[ "$OS_FAMILY" == "debian" ]]; then
    ensure_pkg libpam-google-authenticator
  else
    # RHEL requiere EPEL
    if ! rpm -qa | grep -qi epel-release >/dev/null 2>&1; then
      $PKG_INSTALL epel-release -y || true
    fi
    ensure_pkg google-authenticator qrencode libpam
    # paquete nombre alternativo:
    $PKG_INSTALL libpam-google-authenticator -y || true
  fi

  local f="/etc/ssh/sshd_config"
  cp -a "$f" "$backup_dir/sshd_config.mfa.bak"

  # PAM: requiere línea en /etc/pam.d/sshd
  local pamf="/etc/pam.d/sshd"
  cp -a "$pamf" "$backup_dir/sshd.pam.bak"
  if ! grep -Eq 'pam_google_authenticator\.so' "$pamf"; then
    # nullok: no bloquea usuarios que aún no se han enrolado
    echo "auth required pam_google_authenticator.so nullok" >> "$pamf"
  fi

  # SSHD: forzar combinación de publickey + OTP
  if sshd -T 2>/dev/null | grep -q '^kbdinteractiveauthentication'; then
    sed -ri 's/^\s*#?\s*KbdInteractiveAuthentication\s+.*/KbdInteractiveAuthentication yes/I' "$f" || append_if_missing "$f" "KbdInteractiveAuthentication yes"
  else
    sed -ri 's/^\s*#?\s*ChallengeResponseAuthentication\s+.*/ChallengeResponseAuthentication yes/I' "$f" || append_if_missing "$f" "ChallengeResponseAuthentication yes"
  fi
  if grep -Eq '^\s*AuthenticationMethods\s+' "$f"; then
    sed -ri 's/^\s*AuthenticationMethods\s+.*/AuthenticationMethods publickey,keyboard-interactive/' "$f"
  else
    echo "AuthenticationMethods publickey,keyboard-interactive" >> "$f"
  fi

  systemctl reload sshd || systemctl reload ssh || true
  green "MFA habilitado (publickey + OTP). Enrola usuarios con: google-authenticator -t -f -r 3 -R 30 -d"
  yellow "IMPORTANTE: mientras exista 'nullok' en PAM, usuarios no enrolados podrán entrar con solo clave pública."
}

setup_fail2ban() {
  blue "[Fail2ban] Instalando y configurando"
  ensure_pkg fail2ban
  local j="/etc/fail2ban/jail.local"
  cp -a /etc/fail2ban/jail.conf "$backup_dir/jail.conf.bak" 2>/dev/null || true

  cat > "$j" <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
destemail = ${ALERT_EMAIL}
sender = fail2ban@$(hostname -f)
mta = sendmail
# action_mw: ban + mail con whois (requiere correo funcional en el host)
action = %(action_mw)s

[sshd]
enabled = true
backend = systemd
port = ssh
logpath = %(sshd_log)s
EOF
  systemctl enable --now fail2ban
  systemctl restart fail2ban
  fail2ban-client status sshd || true
  green "Fail2ban activo. Asegura que el host pueda enviar correo si definiste --email."
}

setup_journald() {
  blue "[Journald] Persistencia y límites"
  local f="/etc/systemd/journald.conf"
  cp -a "$f" "$backup_dir/journald.conf.bak" 2>/dev/null || true
  sed -ri 's/^\s*#?\s*Storage=.*/Storage=persistent/' "$f" || append_if_missing "$f" "Storage=persistent"
  if grep -Eq '^\s*#?\s*SystemMaxUse=' "$f"; then
    sed -ri 's/^\s*#?\s*SystemMaxUse=.*/SystemMaxUse=500M/' "$f"
  else
    echo "SystemMaxUse=500M" >> "$f"
  fi
  if grep -Eq '^\s*#?\s*RateLimitIntervalSec=' "$f"; then
    sed -ri 's/^\s*#?\s*RateLimitIntervalSec=.*/RateLimitIntervalSec=30s/' "$f"
  else
    echo "RateLimitIntervalSec=30s" >> "$f"
  fi
  if grep -Eq '^\s*#?\s*RateLimitBurst=' "$f"; then
    sed -ri 's/^\s*#?\s*RateLimitBurst=.*/RateLimitBurst=1000/' "$f"
  else
    echo "RateLimitBurst=1000" >> "$f"
  fi
  systemctl restart systemd-journald
  green "Journald configurado con almacenamiento persistente y límites."
}

setup_unattended() {
  blue "[Actualizaciones] Configurando parches automáticos"
  if [[ "$OS_FAMILY" == "debian" ]]; then
    ensure_pkg unattended-upgrades
    # Activar periodicidad
    cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    # Mantener reboot manual por defecto (puedes cambiar a true)
    if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
      cp -a /etc/apt/apt.conf.d/50unattended-upgrades "$backup_dir/50unattended-upgrades.bak"
      sed -ri 's#^//\s*"\$\{distro_id\}:\$\{distro_codename\}-security";#        "${distro_id}:${distro_codename}-security";#' /etc/apt/apt.conf.d/50unattended-upgrades || true
      append_if_missing /etc/apt/apt.conf.d/50unattended-upgrades 'Unattended-Upgrade::Automatic-Reboot "false";'
    fi
    systemctl enable --now unattended-upgrades
    green "unattended-upgrades habilitado."
  else
    ensure_pkg dnf-automatic
    local f="/etc/dnf/automatic.conf"
    cp -a "$f" "$backup_dir/automatic.conf.bak" 2>/dev/null || true
    sed -ri 's/^\s*apply_updates\s*=.*/apply_updates = yes/' "$f" || append_if_missing "$f" "apply_updates = yes"
    systemctl enable --now dnf-automatic.timer
    green "dnf-automatic.timer habilitado."
  fi
}

setup_auditd() {
  blue "[Auditoría] auditd + reglas base"
  if [[ "$OS_FAMILY" == "debian" ]]; then
    ensure_pkg auditd audispd-plugins
  else
    ensure_pkg audit audit-libs audispd-plugins || ensure_pkg audit
  fi
  mkdir -p /etc/audit/rules.d
  local r="/etc/audit/rules.d/99-hardening.rules"
  cp -a "$r" "$backup_dir/99-hardening.rules.bak" 2>/dev/null || true
  cat > "$r" <<'EOF'
# Monitoreo básico de archivos sensibles
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group  -p wa -k identity
-w /etc/sudoers -p wa -k sudo
-w /etc/ssh/sshd_config -p wa -k sshd
# Cambios en binarios críticos (suid/sgid)
-a always,exit -F arch=b64 -S chmod,chown,fchmod,fchown -F auid>=1000 -F auid!=unset -k perm_change
# Accesos a /var/log
-w /var/log/ -p wa -k logwatch
# Configuración de firewall
-w /etc/nftables.conf -p wa -k firewall
EOF
  if command -v augenrules >/dev/null 2>&1; then
    augenrules --load
  else
    service auditd restart || systemctl restart auditd
  fi
  systemctl enable auditd || true
  green "auditd activo con reglas base."
}

setup_lynis() {
  blue "[Lynis] Instalando y programando auditoría semanal"
  if [[ "$OS_FAMILY" == "debian" ]]; then
    ensure_pkg lynis
  else
    # RHEL requiere EPEL
    if ! rpm -qa | grep -qi epel-release >/dev/null 2>&1; then
      $PKG_INSTALL epel-release -y || true
    fi
    ensure_pkg lynis || true
  fi
  # Cron semanal
  (crontab -l 2>/dev/null || true; echo '0 4 * * 1 /usr/sbin/lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat') | crontab -
  green "Lynis instalado. Cron semanal (lunes 04:00)."
}

setup_backups() {
  blue "[Backups] Configurando restic (si variables definidas)"
  local need_vars=(RESTIC_REPOSITORY RESTIC_PASSWORD BACKUP_PATHS)
  local missing=0
  for v in "${need_vars[@]}"; do
    if [[ -z "${!v:-}" ]]; then
      yellow "Variable $v no definida; backups omitidos. (Define RESTIC_REPOSITORY, RESTIC_PASSWORD, BACKUP_PATHS)"
      missing=1
    fi
  done
  [[ $missing -eq 1 ]] && return 0

  if [[ "$OS_FAMILY" == "debian" ]]; then
    ensure_pkg restic
  else
    ensure_pkg restic || true
  fi

  mkdir -p /etc/restic
  # Guardar env
  cp -a /etc/restic/env "$backup_dir/restic-env.bak" 2>/dev/null || true
  cat >/etc/restic/env <<EOF
export RESTIC_REPOSITORY="${RESTIC_REPOSITORY}"
export RESTIC_PASSWORD="${RESTIC_PASSWORD}"
export RESTIC_PASSWORD_FILE="${RESTIC_PASSWORD_FILE:-}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
export RESTIC_COMPRESSION="${RESTIC_COMPRESSION:-auto}"
EOF

  # Guardar paths
  cp -a /etc/restic/backup.conf "$backup_dir/restic-backup.conf.bak" 2>/dev/null || true
  printf "%s\n" $BACKUP_PATHS > /etc/restic/backup.conf

  # Cron diario 02:15 (backup + políticas)
  (crontab -l 2>/dev/null || true; echo '15 2 * * * . /etc/restic/env && /usr/bin/restic backup --one-file-system --tag auto $(cat /etc/restic/backup.conf) && /usr/bin/restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune') | crontab -
  green "Restic programado diario 02:15. Repositorio: ${RESTIC_REPOSITORY}"
}

# ---------- Run ----------
main() {
  local sshp
  sshp="$(detect_ssh_port)"

  # Firewall
  if [[ "$FIREWALL" != "skip" ]]; then
    setup_firewall "$FIREWALL" "$ALLOW_PORTS" "$sshp"
  else
    yellow "Saltando firewall por petición (--firewall skip)."
  fi

  # SSH
  if [[ $HARDEN_SSH -eq 1 ]]; then
    harden_ssh
    [[ $MFA -eq 1 ]] && enable_mfa
  else
    [[ $MFA -eq 1 ]] && { yellow "Habilitaré MFA pero igualmente endureceré SSH base."; harden_ssh; enable_mfa; }
  fi

  # Otros módulos
  [[ $FAIL2BAN -eq 1 ]] && setup_fail2ban
  [[ $JOURNALD -eq 1 ]] && setup_journald
  [[ $AUTO_UPDATES -eq 1 ]] && setup_unattended
  [[ $AUDITD -eq 1 ]] && setup_auditd
  [[ $LYNIS -eq 1 ]] && setup_lynis
  [[ $BACKUPS -eq 1 ]] && setup_backups

  blue "Backups de config tocada en: $backup_dir"
  if [[ $SKIP_REBOOT -eq 0 ]]; then
    yellow "Sugerido: reinicia fuera de horario si hubo muchos cambios de base."
  fi

  green "Hardening finalizado."
}

main
