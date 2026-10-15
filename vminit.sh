#!/usr/bin/env bash
#
# vminit: interactive setup and hardening for a fresh Linux VM
#
# Supported: Ubuntu, Debian (apt) and Fedora, RHEL, Rocky, Alma, CentOS Stream (dnf)
#
# All logic lives in main() which is only called on the very last line, so a
# partially downloaded script can never run half way.

set -uo pipefail

readonly VMINIT_VERSION="1.0.0"
readonly LOG_FILE="/var/log/vminit.log"
readonly TTY="/dev/tty"
BACKUP_DIR="/root/vminit-backup-$(date +%Y%m%d-%H%M%S)"

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

DEFAULT_PACKAGES="curl wget git vim htop tmux unzip jq ca-certificates"

# Matches an SSH public key (type + base64 body), ignoring any options before it
KEY_RE='(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) AAAA[A-Za-z0-9+/]+=*'

# ---------------------------------------------------------------------------
# State (filled in by the questions)
# ---------------------------------------------------------------------------
DO_UPDATE=0 DO_PACKAGES=0 DO_HOSTNAME=0 DO_TZ=0 DO_USER=0 DO_SSH=0
DO_FIREWALL=0 DO_FAIL2BAN=0 DO_AUTOUPDATE=0 DO_SYSCTL=0 DO_SWAP=0

PACKAGES="" NEW_HOSTNAME="" NEW_TZ="" NEW_USER="" USER_PASSWORD=""
COPY_KEYS=0 GH_USER="" GH_KEYS="" PASTED_KEY=""
EXISTING_KEY_SOURCES=()
ORIG_SSH_PORT=22 SSH_PORT=22 SSH_NO_ROOT=0 SSH_NO_PASSWORD=0
EXTRA_PORTS="" AUTO_REBOOT=0 REBOOT_TIME="04:00" SWAP_SIZE=""

PKG="" SUDO_GROUP="" SSH_SERVICE="sshd" OS_ID="" OS_NAME="" OS_VERSION_ID=""
PKG_REFRESHED=0
RESULTS=()

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m'
  C_RED=$'\e[31m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_BLUE=$'\e[34m' C_CYAN=$'\e[36m'
else
  C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN=""
fi

log()     { printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$LOG_FILE" 2>/dev/null || true; }
info()    { printf '%s\n' "${C_BLUE}::${C_RESET} $*"; log "INFO $*"; }
ok()      { printf '%s\n' "  ${C_GREEN}✓${C_RESET} $*"; log "OK $*"; }
warn()    { printf '%s\n' "  ${C_YELLOW}!${C_RESET} $*" >&2; log "WARN $*"; }
err()     { printf '%s\n' "  ${C_RED}✗${C_RESET} $*" >&2; log "ERROR $*"; }
die()     { printf '%s\n' "${C_RED}error:${C_RESET} $*" >&2; log "FATAL $*"; exit 1; }
section() { printf '\n%s\n' "${C_BOLD}${C_CYAN}==> $*${C_RESET}"; log "SECTION $*"; }

# Run a command quietly, send its output to the log, print done/failed.
run() {
  local desc="$1" rc=0
  shift
  printf '  %s ... ' "$desc"
  log "RUN $*"
  "$@" >>"$LOG_FILE" 2>&1 || rc=$?
  if (( rc == 0 )); then
    printf '%s\n' "${C_GREEN}done${C_RESET}"
    return 0
  fi
  printf '%s\n' "${C_RED}failed${C_RESET}"
  log "FAILED (exit $rc): $*"
  tail -n 10 "$LOG_FILE" 2>/dev/null | sed 's/^/      /'
  return "$rc"
}

# ---------------------------------------------------------------------------
# Prompt helpers (read from /dev/tty so they work with `curl | bash`)
# ---------------------------------------------------------------------------
ask() {
  local prompt="$1" default="${2:-}" answer=""
  if [[ -n "$default" ]]; then
    printf '%s' "${C_BOLD}?${C_RESET} ${prompt} ${C_DIM}[${default}]${C_RESET}: " >"$TTY"
  else
    printf '%s' "${C_BOLD}?${C_RESET} ${prompt}: " >"$TTY"
  fi
  IFS= read -r answer <"$TTY" || answer=""
  printf '%s' "${answer:-$default}"
}

ask_yn() {
  local prompt="$1" default="${2:-Y}" answer="" hint
  if [[ "$default" =~ ^[Yy] ]]; then hint="Y/n"; else hint="y/N"; fi
  while true; do
    printf '%s' "${C_BOLD}?${C_RESET} ${prompt} ${C_DIM}[${hint}]${C_RESET}: " >"$TTY"
    IFS= read -r answer <"$TTY" || answer=""
    answer="${answer:-$default}"
    case "$answer" in
      [Yy] | [Yy][Ee][Ss]) return 0 ;;
      [Nn] | [Nn][Oo]) return 1 ;;
      *) printf '  Please answer y or n.\n' >"$TTY" ;;
    esac
  done
}

ask_secret() {
  local prompt="$1" answer=""
  printf '%s' "${C_BOLD}?${C_RESET} ${prompt}: " >"$TTY"
  IFS= read -rs answer <"$TTY" || answer=""
  printf '\n' >"$TTY"
  printf '%s' "$answer"
}

# ---------------------------------------------------------------------------
# Validation and small utilities
# ---------------------------------------------------------------------------
valid_hostname() {
  local re='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
  [[ "$1" =~ $re ]] && (( ${#1} <= 253 ))
}
valid_username() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$1" != "root" ]]; }
valid_port()     { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
valid_portspec() {
  local spec="$1" num
  [[ "$spec" =~ ^([0-9]+)(/(tcp|udp))?$ ]] || return 1
  num="${BASH_REMATCH[1]}"
  valid_port "$num"
}
valid_pubkey()   { local re="^${KEY_RE}"; [[ "$1" =~ $re ]]; }
valid_timezone() {
  if command -v timedatectl >/dev/null 2>&1 && timedatectl list-timezones >/dev/null 2>&1; then
    timedatectl list-timezones | grep -qx "$1"
  else
    [[ -f "/usr/share/zoneinfo/$1" ]]
  fi
}

count_keys() {
  local n
  n=$(grep -cE "$KEY_RE" "$1" 2>/dev/null)
  printf '%s' "${n:-0}"
}
extract_keys() { grep -oE "$KEY_RE" "$1" 2>/dev/null || true; }
user_home()    { getent passwd "$1" | cut -d: -f6; }

# The account you will log in with after this script runs
login_user() {
  if (( DO_USER )) && [[ -n "$NEW_USER" ]]; then
    printf '%s' "$NEW_USER"
  elif [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
    printf '%s' "$SUDO_USER"
  fi
}

login_user_has_keys() {
  local u h
  u=$(login_user)
  [[ -n "$u" ]] || u=root
  h=$(user_home "$u")
  [[ -n "$h" ]] || return 1
  (( $(count_keys "$h/.ssh/authorized_keys") > 0 ))
}

# Used while asking questions, before anything is installed
planned_keys_exist() {
  if (( DO_USER )); then
    (( COPY_KEYS )) && return 0
    [[ -n "$GH_KEYS" || -n "$PASTED_KEY" ]] && return 0
    local h
    h=$(user_home "$NEW_USER")
    [[ -n "$h" ]] && (( $(count_keys "$h/.ssh/authorized_keys") > 0 )) && return 0
    return 1
  fi
  login_user_has_keys
}

backup_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  [[ -e "${BACKUP_DIR}${f}" ]] && return 0
  mkdir -p "${BACKUP_DIR}$(dirname "$f")" && cp -a "$f" "${BACKUP_DIR}${f}"
}

restore_file() {
  local f="$1"
  [[ -e "${BACKUP_DIR}${f}" ]] && cp -a "${BACKUP_DIR}${f}" "$f"
}

primary_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null |
    awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

reboot_needed() {
  [[ -f /var/run/reboot-required ]] && return 0
  if command -v needs-restarting >/dev/null 2>&1; then
    needs-restarting -r >/dev/null 2>&1 || return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# OS and package manager
# ---------------------------------------------------------------------------
detect_ssh_service() {
  if systemctl list-unit-files 2>/dev/null | grep -qE '^ssh\.service'; then
    SSH_SERVICE=ssh
  else
    SSH_SERVICE=sshd
  fi
}

detect_os() {
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release, unsupported system."
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_NAME="${PRETTY_NAME:-$OS_ID}"
  OS_VERSION_ID="${VERSION_ID:-}"

  if command -v apt-get >/dev/null 2>&1; then
    PKG=apt
    SUDO_GROUP=sudo
  elif command -v dnf >/dev/null 2>&1; then
    PKG=dnf
    SUDO_GROUP=wheel
  else
    die "Neither apt-get nor dnf found. vminit supports Debian/Ubuntu and Fedora/RHEL family."
  fi
  command -v systemctl >/dev/null 2>&1 || die "systemd is required."
  detect_ssh_service
}

is_rhel_like() { [[ "$PKG" == "dnf" && "$OS_ID" != "fedora" ]]; }

APT_OPTS=(-y -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

pkg_refresh() {
  case "$PKG" in
    apt) apt-get -o DPkg::Lock::Timeout=600 update ;;
    dnf) dnf -y makecache ;;
  esac
}

pkg_upgrade() {
  case "$PKG" in
    apt) apt-get "${APT_OPTS[@]}" --with-new-pkgs upgrade ;;
    dnf) dnf -y upgrade --refresh ;;
  esac
}

pkg_install() {
  case "$PKG" in
    apt) apt-get "${APT_OPTS[@]}" install "$@" ;;
    dnf) dnf -y install "$@" ;;
  esac
}

ensure_pkg_lists() {
  (( PKG_REFRESHED )) && return 0
  run "Refreshing package lists" pkg_refresh && PKG_REFRESHED=1
}

ensure_epel() {
  is_rhel_like || return 0
  rpm -q epel-release >/dev/null 2>&1 && return 0
  run "Enabling EPEL repository" dnf -y install epel-release && return 0
  local major="${OS_VERSION_ID%%.*}"
  run "Enabling EPEL repository (direct download)" \
    dnf -y install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${major}.noarch.rpm"
}

current_ssh_port() {
  local p="" bin
  bin=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
  if [[ -x "$bin" ]]; then
    mkdir -p /run/sshd 2>/dev/null
    p=$("$bin" -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')
  fi
  printf '%s' "${p:-22}"
}

wait_for_cloud_init() {
  if command -v cloud-init >/dev/null 2>&1 &&
    cloud-init status 2>/dev/null | grep -qE 'status: (running|not started)'; then
    info "cloud-init is still running, waiting for it to finish first..."
    cloud-init status --wait >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
# Questions
# ---------------------------------------------------------------------------
collect_answers() {
  section "Questions"
  printf '%s\n' "${C_DIM}Answer everything up front. Nothing changes until you confirm the plan.${C_RESET}"

  # Updates and packages
  ask_yn "Update all installed packages?" Y && DO_UPDATE=1
  if ask_yn "Install common tools?" Y; then
    DO_PACKAGES=1
    PACKAGES=$(ask "Packages (space separated)" "$DEFAULT_PACKAGES")
  fi

  # Hostname
  if ask_yn "Change hostname? (currently: $(hostname))" N; then
    DO_HOSTNAME=1
    while true; do
      NEW_HOSTNAME=$(ask "New hostname" "")
      valid_hostname "$NEW_HOSTNAME" && break
      warn "Invalid hostname. Use letters, digits, hyphens and dots."
    done
  fi

  # Timezone
  local cur_tz
  cur_tz=$(timedatectl show -p Timezone --value 2>/dev/null || echo "unknown")
  if ask_yn "Set timezone? (currently: ${cur_tz})" N; then
    DO_TZ=1
    while true; do
      NEW_TZ=$(ask "Timezone (UTC, Europe/Berlin, America/New_York...)" "UTC")
      valid_timezone "$NEW_TZ" && break
      warn "Unknown timezone. Run 'timedatectl list-timezones' to see valid names."
    done
  fi

  # Sudo user
  if ask_yn "Create (or configure) a non-root sudo user?" Y; then
    DO_USER=1
    while true; do
      NEW_USER=$(ask "Username" "")
      valid_username "$NEW_USER" && break
      warn "Invalid username. Lowercase letters, digits, _ and -, starting with a letter."
    done
    id "$NEW_USER" >/dev/null 2>&1 && info "User $NEW_USER already exists. It will be added to '$SUDO_GROUP' and get keys."

    local src_user src_home f
    for src_user in $(printf '%s\n' root "${SUDO_USER:-}" | awk 'NF && !seen[$0]++'); do
      [[ "$src_user" == "$NEW_USER" ]] && continue
      src_home=$(user_home "$src_user")
      [[ -n "$src_home" ]] || continue
      f="$src_home/.ssh/authorized_keys"
      (( $(count_keys "$f") > 0 )) && EXISTING_KEY_SOURCES+=("$f")
    done
    if (( ${#EXISTING_KEY_SOURCES[@]} > 0 )); then
      ask_yn "Copy existing SSH keys from ${EXISTING_KEY_SOURCES[*]} to $NEW_USER?" Y && COPY_KEYS=1
    fi

    if ask_yn "Import public SSH keys from a GitHub account?" Y; then
      while true; do
        GH_USER=$(ask "GitHub username (blank to skip)" "")
        [[ -z "$GH_USER" ]] && break
        if [[ ! "$GH_USER" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}$ ]]; then
          warn "That does not look like a GitHub username."
          continue
        fi
        GH_KEYS=$(curl -fsSL --max-time 15 "https://github.com/${GH_USER}.keys" 2>/dev/null | grep -oE "$KEY_RE" || true)
        if [[ -n "$GH_KEYS" ]]; then
          ok "Found $(printf '%s\n' "$GH_KEYS" | wc -l | tr -d ' ') key(s) on github.com/${GH_USER}"
          break
        fi
        warn "No keys found for github.com/${GH_USER} (or GitHub unreachable)."
        GH_USER=""
      done
    fi

    if ask_yn "Paste an SSH public key manually?" N; then
      while true; do
        PASTED_KEY=$(ask "Public key (ssh-ed25519 AAAA...), blank to skip" "")
        [[ -z "$PASTED_KEY" ]] && break
        valid_pubkey "$PASTED_KEY" && break
        warn "That does not look like an SSH public key."
      done
    fi

    if ask_yn "Set a password for $NEW_USER? (if no, sudo will not ask for one)" Y; then
      local p1 p2
      while true; do
        p1=$(ask_secret "Password for $NEW_USER")
        p2=$(ask_secret "Confirm password")
        if [[ -z "$p1" ]]; then
          warn "Password cannot be empty."
        elif [[ "$p1" != "$p2" ]]; then
          warn "Passwords do not match."
        else
          USER_PASSWORD="$p1"
          break
        fi
      done
    fi
  fi

  # SSH
  ORIG_SSH_PORT=$(current_ssh_port)
  SSH_PORT="$ORIG_SSH_PORT"
  if ask_yn "Harden SSH?" Y; then
    DO_SSH=1
    while true; do
      SSH_PORT=$(ask "SSH port" "$ORIG_SSH_PORT")
      valid_port "$SSH_PORT" && break
      warn "Port must be a number between 1 and 65535."
    done
    if ask_yn "Disable root login over SSH?" Y; then
      SSH_NO_ROOT=1
      [[ -z "$(login_user)" ]] &&
        warn "There is no other login user, so root will be limited to key logins instead of fully blocked."
    fi
    if ask_yn "Disable password logins (SSH keys only)?" Y; then
      SSH_NO_PASSWORD=1
      planned_keys_exist ||
        warn "No SSH keys are planned for the login user. Password login will stay ON unless a key exists when this step runs."
    fi
  fi

  # Firewall
  if ask_yn "Enable a firewall (deny incoming except SSH)?" Y; then
    DO_FIREWALL=1
    local p bad
    while true; do
      EXTRA_PORTS=$(ask "Other ports to open, space separated (e.g. 80 443 51820/udp), blank for none" "")
      bad=""
      for p in $EXTRA_PORTS; do valid_portspec "$p" || bad="$p"; done
      [[ -z "$bad" ]] && break
      warn "Invalid port: $bad"
    done
  fi

  # fail2ban
  ask_yn "Install fail2ban (bans IPs that brute force SSH)?" Y && DO_FAIL2BAN=1

  # Auto updates
  if ask_yn "Enable automatic security updates?" Y; then
    DO_AUTOUPDATE=1
    if ask_yn "Allow automatic reboots when an update requires one?" N; then
      AUTO_REBOOT=1
      if [[ "$PKG" == "apt" ]]; then
        while true; do
          REBOOT_TIME=$(ask "Reboot time (HH:MM, server time)" "04:00")
          [[ "$REBOOT_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] && break
          warn "Use 24h format, like 04:00."
        done
      fi
    fi
  fi

  # sysctl
  ask_yn "Apply kernel and network hardening (sysctl)?" Y && DO_SYSCTL=1

  # Swap
  if swapon --show --noheadings 2>/dev/null | grep -q .; then
    info "Swap is already configured, skipping swap."
  elif ask_yn "No swap found. Create a swap file?" Y; then
    DO_SWAP=1
    local ram_mb default_swap
    ram_mb=$(awk '/MemTotal/ { print int($2 / 1024) }' /proc/meminfo)
    if (( ram_mb < 4096 )); then default_swap="2G"; else default_swap="4G"; fi
    while true; do
      SWAP_SIZE=$(ask "Swap size (e.g. 512M, 2G)" "$default_swap")
      [[ "$SWAP_SIZE" =~ ^[1-9][0-9]*[MG]$ ]] && break
      warn "Use a number followed by M or G."
    done
  fi
}

show_plan() {
  section "Plan for ${OS_NAME}"
  local any=0
  item() { printf '  %s+%s %s\n' "$C_GREEN" "$C_RESET" "$*"; any=1; }

  (( DO_UPDATE ))   && item "Update all packages"
  (( DO_PACKAGES )) && item "Install: $PACKAGES"
  (( DO_HOSTNAME )) && item "Hostname: $NEW_HOSTNAME"
  (( DO_TZ ))       && item "Timezone: $NEW_TZ"
  if (( DO_USER )); then
    local keys=() pw
    (( COPY_KEYS )) && keys+=("existing keys")
    [[ -n "$GH_KEYS" ]] && keys+=("github:$GH_USER")
    [[ -n "$PASTED_KEY" ]] && keys+=("pasted key")
    if [[ -n "$USER_PASSWORD" ]]; then pw="password set"; else pw="passwordless sudo"; fi
    item "Sudo user: $NEW_USER ($pw, keys: ${keys[*]:-none})"
  fi
  (( DO_SWAP ))     && item "Swap file: $SWAP_SIZE at /swapfile"
  (( DO_SYSCTL ))   && item "Kernel and network sysctl hardening"
  if (( DO_SSH )); then
    local s="SSH: port $SSH_PORT"
    (( SSH_NO_ROOT )) && s+=", no root login"
    (( SSH_NO_PASSWORD )) && s+=", keys only"
    item "$s, max 4 auth tries, idle timeout"
  fi
  if (( DO_FIREWALL )); then
    local fw="ufw"
    [[ "$PKG" == "dnf" ]] && fw="firewalld"
    item "Firewall ($fw): allow ${SSH_PORT}/tcp${EXTRA_PORTS:+ and $EXTRA_PORTS}, deny other incoming"
  fi
  (( DO_FAIL2BAN )) && item "fail2ban: ban for 1h after 5 failed SSH logins in 10m"
  if (( DO_AUTOUPDATE )); then
    local r="no auto reboot"
    (( AUTO_REBOOT )) && r="auto reboot when needed${REBOOT_TIME:+ at $REBOOT_TIME}"
    [[ "$PKG" == "dnf" ]] && (( AUTO_REBOOT )) && r="auto reboot when needed"
    item "Automatic security updates ($r)"
  fi

  if (( any == 0 )); then
    info "Nothing selected. Exiting without changes."
    exit 0
  fi
  printf '\n'
}

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
do_step() {
  local name="$1" fn="$2"
  section "$name"
  if "$fn"; then
    RESULTS+=("${C_GREEN}✓${C_RESET} $name")
  else
    RESULTS+=("${C_RED}✗${C_RESET} $name ${C_DIM}(check $LOG_FILE)${C_RESET}")
  fi
}

step_update() {
  ensure_pkg_lists || return 1
  run "Upgrading packages (this can take a while)" pkg_upgrade
}

step_packages() {
  local -a pkgs failed=()
  local p
  read -ra pkgs <<<"$PACKAGES"
  (( ${#pkgs[@]} > 0 )) || return 0
  ensure_epel
  ensure_pkg_lists || return 1
  run "Installing ${pkgs[*]}" pkg_install "${pkgs[@]}" && return 0
  warn "Bulk install failed, trying packages one by one"
  for p in "${pkgs[@]}"; do
    run "Installing $p" pkg_install "$p" || failed+=("$p")
  done
  if (( ${#failed[@]} > 0 )); then
    warn "Could not install: ${failed[*]}"
    return 1
  fi
}

step_hostname() {
  backup_file /etc/hosts
  backup_file /etc/hostname
  run "Setting hostname to $NEW_HOSTNAME" hostnamectl set-hostname "$NEW_HOSTNAME" || return 1

  local short="${NEW_HOSTNAME%%.*}" entry
  if [[ "$short" == "$NEW_HOSTNAME" ]]; then
    entry="127.0.1.1 $NEW_HOSTNAME"
  else
    entry="127.0.1.1 $NEW_HOSTNAME $short"
  fi
  if grep -qE '^127\.0\.1\.1[[:space:]]' /etc/hosts; then
    sed -i -E "s/^127\.0\.1\.1[[:space:]].*/${entry}/" /etc/hosts
  else
    printf '%s\n' "$entry" >>/etc/hosts
  fi
  ok "/etc/hosts updated"

  if [[ -d /etc/cloud/cloud.cfg.d ]]; then
    printf 'preserve_hostname: true\n' >/etc/cloud/cloud.cfg.d/99-vminit-hostname.cfg
    ok "cloud-init told to keep this hostname on reboot"
  fi
}

step_timezone() {
  run "Setting timezone to $NEW_TZ" timedatectl set-timezone "$NEW_TZ" || return 1
  run "Enabling network time sync" timedatectl set-ntp true || warn "Could not enable NTP (no time sync service installed?)"
  return 0
}

install_keys_for_user() {
  local home group ssh_dir ak tmp src n
  home=$(user_home "$NEW_USER")
  group=$(id -gn "$NEW_USER")
  ssh_dir="$home/.ssh"
  ak="$ssh_dir/authorized_keys"

  install -d -m 700 -o "$NEW_USER" -g "$group" "$ssh_dir"
  tmp=$(mktemp)
  [[ -f "$ak" ]] && cat "$ak" >>"$tmp"
  if (( COPY_KEYS )); then
    for src in "${EXISTING_KEY_SOURCES[@]}"; do
      # Only the key itself, so restrictions like command="..." on root's keys are not copied
      extract_keys "$src" >>"$tmp"
    done
  fi
  [[ -n "$GH_KEYS" ]] && printf '%s\n' "$GH_KEYS" >>"$tmp"
  [[ -n "$PASTED_KEY" ]] && printf '%s\n' "$PASTED_KEY" >>"$tmp"

  awk 'NF && !seen[$0]++' "$tmp" >"$ak"
  rm -f "$tmp"
  chown "$NEW_USER:$group" "$ak"
  chmod 600 "$ak"
  command -v restorecon >/dev/null 2>&1 && restorecon -R "$ssh_dir" >/dev/null 2>&1

  n=$(count_keys "$ak")
  if (( n > 0 )); then
    ok "$n SSH key(s) in $ak"
  else
    warn "No SSH keys installed for $NEW_USER"
  fi
}

step_user() {
  if id "$NEW_USER" >/dev/null 2>&1; then
    ok "User $NEW_USER already exists"
  else
    run "Creating user $NEW_USER" useradd -m -s /bin/bash "$NEW_USER" || return 1
  fi
  run "Adding $NEW_USER to $SUDO_GROUP" usermod -aG "$SUDO_GROUP" "$NEW_USER" || return 1

  if [[ -n "$USER_PASSWORD" ]]; then
    if printf '%s:%s\n' "$NEW_USER" "$USER_PASSWORD" | chpasswd 2>>"$LOG_FILE"; then
      ok "Password set for $NEW_USER"
    else
      err "Could not set password"
      return 1
    fi
    USER_PASSWORD="set"
  else
    local f="/etc/sudoers.d/90-vminit-${NEW_USER}"
    printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$NEW_USER" >"$f"
    chmod 440 "$f"
    if visudo -cf "$f" >>"$LOG_FILE" 2>&1; then
      ok "Passwordless sudo enabled for $NEW_USER"
    else
      rm -f "$f"
      err "sudoers validation failed, removed $f"
      return 1
    fi
  fi

  install_keys_for_user
}

make_swapfile() {
  local file="$1" mb="$2" method="$3"
  rm -f "$file"
  case "$method" in
    fallocate) fallocate -l "${mb}M" "$file" ;;
    dd) dd if=/dev/zero of="$file" bs=1M count="$mb" status=none ;;
  esac || return 1
  chmod 600 "$file" && mkswap "$file" && swapon "$file"
}

step_swap() {
  local file=/swapfile num unit mb avail
  if [[ "$(findmnt -no FSTYPE / 2>/dev/null)" == "btrfs" ]]; then
    warn "Root filesystem is btrfs, which needs special swap file handling. Skipping."
    return 1
  fi
  if [[ -e "$file" ]]; then
    warn "$file already exists, skipping"
    return 1
  fi

  num="${SWAP_SIZE%[MG]}"
  unit="${SWAP_SIZE: -1}"
  mb="$num"
  [[ "$unit" == "G" ]] && mb=$(( num * 1024 ))
  avail=$(df -Pm / | awk 'NR == 2 { print $4 }')
  if (( avail < mb + 1024 )); then
    warn "Not enough disk space for ${SWAP_SIZE} swap (${avail}M free). Skipping."
    return 1
  fi

  if ! run "Creating ${SWAP_SIZE} swap file" make_swapfile "$file" "$mb" fallocate; then
    run "Retrying with dd (slower)" make_swapfile "$file" "$mb" dd || { rm -f "$file"; return 1; }
  fi

  backup_file /etc/fstab
  grep -qE "^${file}[[:space:]]" /etc/fstab || printf '%s none swap sw 0 0\n' "$file" >>/etc/fstab
  ok "Added to /etc/fstab"

  printf '# Managed by vminit\nvm.swappiness = 10\n' >/etc/sysctl.d/99-vminit-swap.conf
  sysctl -p /etc/sysctl.d/99-vminit-swap.conf >>"$LOG_FILE" 2>&1 && ok "vm.swappiness set to 10"
  return 0
}

step_sysctl() {
  local f=/etc/sysctl.d/99-vminit-hardening.conf
  cat >"$f" <<'EOF'
# Managed by vminit

# Reverse path filtering (anti spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects and do not send them (this is not a router)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# No source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# SYN flood protection, log odd packets, ignore broadcast pings
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Kernel info leaks and ptrace
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1

# Filesystem protections
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
  ok "Wrote $f"
  if sysctl -p "$f" >>"$LOG_FILE" 2>&1; then
    ok "Settings applied"
  else
    warn "Some settings are not supported by this kernel (details in $LOG_FILE). The rest were applied."
  fi
  return 0
}

step_ssh() {
  local main=/etc/ssh/sshd_config dropin_dir=/etc/ssh/sshd_config.d
  local sshd_bin target conf root_setting="" no_pw=0 f tmp
  local -a touched=("$main")

  if ! command -v sshd >/dev/null 2>&1 && [[ ! -x /usr/sbin/sshd ]]; then
    ensure_pkg_lists
    run "Installing OpenSSH server" pkg_install openssh-server || return 1
    detect_ssh_service
  fi
  sshd_bin=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)

  # Lockout guards
  if (( SSH_NO_ROOT )); then
    if [[ -n "$(login_user)" ]]; then
      root_setting="no"
    else
      root_setting="prohibit-password"
      warn "No non-root login user, so using 'PermitRootLogin prohibit-password' to avoid a lockout."
    fi
  fi
  if (( SSH_NO_PASSWORD )); then
    if login_user_has_keys; then
      no_pw=1
    else
      warn "No SSH key found for '$(login_user || true)'. Leaving password login ENABLED to avoid a lockout."
    fi
  fi

  conf="# Managed by vminit ${VMINIT_VERSION} ($(date '+%F %T'))
Port ${SSH_PORT}
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2"
  [[ -n "$root_setting" ]] && conf+=$'\n'"PermitRootLogin ${root_setting}"
  (( no_pw )) && conf+=$'\n'"PasswordAuthentication no"

  # Back up everything we might touch
  backup_file "$main"
  if [[ -d "$dropin_dir" ]]; then
    for f in "$dropin_dir"/*.conf; do
      [[ -e "$f" && "$f" != "$dropin_dir/00-vminit.conf" ]] || continue
      backup_file "$f"
      touched+=("$f")
    done
  fi

  # Port is additive in sshd, so comment out any other Port lines
  for f in "${touched[@]}"; do
    sed -i -E 's/^([[:space:]]*Port[[:space:]]+)/# vminit: \1/' "$f"
  done

  if [[ -d "$dropin_dir" ]] && grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$main"; then
    # 00 so it loads first: for most sshd options the first value wins
    target="$dropin_dir/00-vminit.conf"
    printf '%s\n' "$conf" >"$target"
    chmod 600 "$target"
  else
    # No drop-in support (e.g. RHEL 8): put our block at the top of sshd_config
    target="$main"
    tmp=$(mktemp)
    {
      printf '# >>> vminit >>>\n%s\n# <<< vminit <<<\n\n' "$conf"
      sed '/^# >>> vminit >>>$/,/^# <<< vminit <<<$/d' "$main"
    } >"$tmp"
    cat "$tmp" >"$main"
    rm -f "$tmp"
  fi
  ok "Wrote SSH settings to $target"

  # SELinux must know about a non standard SSH port
  if [[ "$SSH_PORT" != "22" ]] && command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" != "Disabled" ]]; then
    if ! command -v semanage >/dev/null 2>&1; then
      ensure_pkg_lists
      run "Installing SELinux tools" pkg_install policycoreutils-python-utils || return 1
    fi
    if ! semanage port -l | grep -E '^ssh_port_t' | grep -qw "$SSH_PORT"; then
      run "Allowing port $SSH_PORT for SSH in SELinux" semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" ||
        run "Updating SELinux port label" semanage port -m -t ssh_port_t -p tcp "$SSH_PORT" || return 1
    fi
  fi

  # Validate before restarting, roll back if broken
  mkdir -p /run/sshd
  if ! "$sshd_bin" -t >>"$LOG_FILE" 2>&1; then
    err "New SSH config failed validation, rolling back"
    for f in "${touched[@]}"; do restore_file "$f"; done
    [[ "$target" != "$main" ]] && rm -f "$target"
    return 1
  fi
  ok "SSH config validated"

  # Ubuntu 22.10+ uses socket activation, which ignores Port in sshd_config
  if [[ "$SSH_PORT" != "$ORIG_SSH_PORT" ]] &&
    { systemctl is-enabled ssh.socket >/dev/null 2>&1 || systemctl is-active ssh.socket >/dev/null 2>&1; }; then
    run "Switching from ssh.socket to ssh.service" systemctl disable --now ssh.socket
    rm -f /etc/systemd/system/ssh.service.d/00-socket.conf /etc/systemd/system/ssh.socket.d/addresses.conf
    systemctl daemon-reload
    run "Enabling ssh.service" systemctl enable --now ssh.service || return 1
  fi

  run "Restarting $SSH_SERVICE" systemctl restart "$SSH_SERVICE" || return 1
  sleep 1
  if ss -tln 2>/dev/null | grep -qE "[:.]${SSH_PORT}[[:space:]]"; then
    ok "SSH is listening on port $SSH_PORT"
  else
    warn "Could not confirm SSH is listening on port $SSH_PORT. Check 'ss -tlnp' before logging out."
  fi
  return 0
}

step_firewall() {
  local -a ports
  local p
  read -ra ports <<<"$EXTRA_PORTS"
  ensure_pkg_lists

  if [[ "$PKG" == "apt" ]]; then
    command -v ufw >/dev/null 2>&1 || run "Installing ufw" pkg_install ufw || return 1
    run "Default: deny incoming" ufw default deny incoming || return 1
    run "Default: allow outgoing" ufw default allow outgoing || return 1
    run "Allow SSH ${SSH_PORT}/tcp (rate limited)" ufw limit "${SSH_PORT}/tcp" || return 1
    for p in "${ports[@]}"; do
      [[ "$p" == */* ]] || p="$p/tcp"
      run "Allow $p" ufw allow "$p"
    done
    run "Enabling ufw" ufw --force enable || return 1
  else
    rpm -q firewalld >/dev/null 2>&1 || run "Installing firewalld" pkg_install firewalld || return 1
    run "Starting firewalld" systemctl enable --now firewalld || return 1
    run "Allow SSH ${SSH_PORT}/tcp" firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" || return 1
    if [[ "$SSH_PORT" != "22" ]]; then
      run "Closing default SSH port 22" firewall-cmd --permanent --remove-service=ssh || true
    fi
    for p in "${ports[@]}"; do
      [[ "$p" == */* ]] || p="$p/tcp"
      run "Allow $p" firewall-cmd --permanent --add-port="$p"
    done
    run "Reloading firewalld" firewall-cmd --reload || return 1
  fi
}

step_fail2ban() {
  local -a pk=(fail2ban)
  local banaction="" f=/etc/fail2ban/jail.d/vminit.local
  ensure_pkg_lists
  if [[ "$PKG" == "apt" ]]; then
    pk+=(python3-systemd)
  else
    ensure_epel || return 1
  fi
  run "Installing fail2ban" pkg_install "${pk[@]}" || return 1

  if [[ "$PKG" == "apt" ]]; then
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
      banaction="ufw"
    else
      run "Installing nftables" pkg_install nftables
      banaction="nftables-multiport"
    fi
  fi

  {
    printf '# Managed by vminit\n[DEFAULT]\n'
    printf 'bantime = 1h\nfindtime = 10m\nmaxretry = 5\nbackend = systemd\n'
    [[ -n "$banaction" ]] && printf 'banaction = %s\n' "$banaction"
    printf '\n[sshd]\nenabled = true\nport = %s\n' "$SSH_PORT"
  } >"$f"
  ok "Wrote $f"

  run "Enabling fail2ban" systemctl enable fail2ban || return 1
  run "Starting fail2ban" systemctl restart fail2ban || return 1
  sleep 2
  if fail2ban-client status sshd >>"$LOG_FILE" 2>&1; then
    ok "sshd jail is active"
  else
    warn "fail2ban is running but the sshd jail did not report status yet. Check: fail2ban-client status sshd"
  fi
  return 0
}

step_autoupdate() {
  ensure_pkg_lists
  if [[ "$PKG" == "apt" ]]; then
    run "Installing unattended-upgrades" pkg_install unattended-upgrades || return 1
    cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    local reboot="false"
    (( AUTO_REBOOT )) && reboot="true"
    cat >/etc/apt/apt.conf.d/52vminit-unattended-upgrades <<EOF
// Managed by vminit
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "${reboot}";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_TIME}";
EOF
    ok "Configured unattended-upgrades"
    run "Enabling unattended-upgrades" systemctl enable --now unattended-upgrades || return 1
  else
    run "Installing dnf-automatic" pkg_install dnf-automatic || return 1
    local f=/etc/dnf/automatic.conf
    if [[ -f "$f" ]]; then
      backup_file "$f"
      sed -i -E 's/^[[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/' "$f"
      sed -i -E 's/^[[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = security/' "$f"
      if (( AUTO_REBOOT )); then
        if grep -qE '^[[:space:]]*reboot[[:space:]]*=' "$f"; then
          sed -i -E 's/^[[:space:]]*reboot[[:space:]]*=.*/reboot = when-needed/' "$f"
        else
          warn "This dnf-automatic version has no auto reboot option. Updates will apply without rebooting."
        fi
      fi
    else
      # dnf5 (Fedora 41+) ships no config file by default
      mkdir -p /etc/dnf
      {
        printf '# Managed by vminit\n[commands]\nupgrade_type = security\napply_updates = yes\n'
        (( AUTO_REBOOT )) && printf 'reboot = when-needed\n'
        printf '\n[emitters]\nemit_via = stdio\n'
      } >"$f"
    fi
    ok "Configured $f"
    run "Enabling dnf-automatic timer" systemctl enable --now dnf-automatic.timer ||
      run "Enabling dnf5-automatic timer" systemctl enable --now dnf5-automatic.timer || return 1
  fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
  local r who ip
  section "Summary"
  for r in "${RESULTS[@]}"; do printf '  %s\n' "$r"; done

  who=$(login_user)
  [[ -n "$who" ]] || who=root
  ip=$(primary_ip)

  printf '\n%s\n' "${C_BOLD}${C_YELLOW}IMPORTANT:${C_RESET} keep this session open and test a NEW login from another terminal:"
  printf '\n    %s\n\n' "${C_BOLD}ssh -p ${SSH_PORT} ${who}@<server-ip>${C_RESET}"
  [[ -n "$ip" ]] && printf '  This machine'"'"'s primary IP is %s (use the public IP if you connect over the internet).\n' "$ip"
  if [[ "$SSH_PORT" != "$ORIG_SSH_PORT" ]]; then
    printf '  SSH moved from port %s to %s. If your cloud provider has its own firewall\n' "$ORIG_SSH_PORT" "$SSH_PORT"
    printf '  (AWS security group, GCP firewall rule, Azure NSG...), open %s there too.\n' "$SSH_PORT"
  fi
  printf '\n  Log file: %s\n' "$LOG_FILE"
  [[ -d "$BACKUP_DIR" ]] && printf '  Backups:  %s\n' "$BACKUP_DIR"

  if reboot_needed; then
    printf '\n'
    warn "A reboot is recommended to finish applying updates."
    if ask_yn "Reboot now? (test your new SSH login first!)" N; then
      info "Rebooting..."
      systemctl reboot
    fi
  fi
  printf '\n%s\n' "${C_GREEN}${C_BOLD}vminit finished.${C_RESET}"
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
vminit ${VMINIT_VERSION}: interactive setup and hardening for a fresh Linux VM

Usage:
  curl -fsSL <raw-url>/vminit.sh | sudo bash
  sudo bash vminit.sh [--help] [--version]

It asks a series of questions, shows you the full plan, and only changes
things after you confirm. Output is logged to ${LOG_FILE}.
EOF
}

parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      -h | --help) usage; exit 0 ;;
      -v | --version) printf 'vminit %s\n' "$VMINIT_VERSION"; exit 0 ;;
      *) die "Unknown option: $1 (try --help)" ;;
    esac
    shift
  done
}

main() {
  parse_args "$@"

  printf '\n%s\n' "${C_BOLD}${C_CYAN}vminit ${VMINIT_VERSION}${C_RESET}  ${C_DIM}setup and harden a fresh VM${C_RESET}"

  [[ "$EUID" -eq 0 ]] || die "Run as root, for example: curl -fsSL <url> | sudo bash"
  { : <"$TTY"; } 2>/dev/null || die "No terminal available. Run this from an interactive SSH session."

  touch "$LOG_FILE" && chmod 600 "$LOG_FILE"
  log "==== vminit ${VMINIT_VERSION} started ===="

  detect_os
  info "Detected ${OS_NAME} (package manager: ${PKG})"

  collect_answers
  show_plan
  if ! ask_yn "Apply this plan?" Y; then
    info "Aborted. Nothing was changed."
    exit 0
  fi

  wait_for_cloud_init

  (( DO_UPDATE ))     && do_step "System update" step_update
  (( DO_PACKAGES ))   && do_step "Packages" step_packages
  (( DO_HOSTNAME ))   && do_step "Hostname" step_hostname
  (( DO_TZ ))         && do_step "Timezone" step_timezone
  (( DO_USER ))       && do_step "Sudo user" step_user
  (( DO_SWAP ))       && do_step "Swap" step_swap
  (( DO_SYSCTL ))     && do_step "Kernel hardening" step_sysctl
  (( DO_SSH ))        && do_step "SSH hardening" step_ssh
  (( DO_FIREWALL ))   && do_step "Firewall" step_firewall
  (( DO_FAIL2BAN ))   && do_step "fail2ban" step_fail2ban
  (( DO_AUTOUPDATE )) && do_step "Automatic updates" step_autoupdate

  print_summary
}

# stdin is redirected so nothing we run can swallow the rest of a piped script
main "$@" </dev/null
