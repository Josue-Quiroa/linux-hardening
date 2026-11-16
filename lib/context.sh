# shellcheck shell=bash
# =============================================================================
# lib/context.sh — Descubre el contexto ANTES de cambiar nada.
#
# POR QUÉ: la causa nº1 de desastres con scripts de hardening es el bloqueo
# del propio administrador (SSH sin clave válida, firewall sin el puerto SSH).
# Aquí detectamos: puertos SSH reales, la IP desde la que estás conectado,
# usuarios administradores con claves, si el host enruta tráfico (Docker/K8s),
# etc. Los módulos consultan estas variables para aplicar salvaguardas.
# =============================================================================

UID_MIN_VAL=1000
INVOKING_USER=""
SSH_CLIENT_IP=""
ADMIN_KEY_USERS=""     # admins (sudo/wheel) con authorized_keys no vacío
ROUTER_DETECTED=0

detect_context() {
  UID_MIN_VAL=$(get_config_value /etc/login.defs UID_MIN 2>/dev/null || echo 1000)
  [[ "$UID_MIN_VAL" =~ ^[0-9]+$ ]] || UID_MIN_VAL=1000

  # Usuario real que lanzó el script (aunque sea vía sudo)
  INVOKING_USER="${SUDO_USER:-$(logname 2>/dev/null || true)}"
  [[ -z "$INVOKING_USER" || "$INVOKING_USER" == root ]] && INVOKING_USER="${INVOKING_USER:-root}"

  # IP del cliente SSH de esta sesión (sudo suele borrar SSH_CONNECTION)
  SSH_CLIENT_IP="${SSH_CONNECTION:-}"; SSH_CLIENT_IP="${SSH_CLIENT_IP%% *}"
  if [[ -z "$SSH_CLIENT_IP" ]]; then
    SSH_CLIENT_IP=$(who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F:.]*\)).*/\1/p' | head -n1 || true)
  fi

  # Puertos SSH reales (sshd -T es la verdad: incluye drop-ins)
  if [[ -z "$SSH_PORTS" ]]; then
    if is_root && have sshd; then
      SSH_PORTS=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u | tr '\n' ' ' || true)
    fi
    if [[ -z "$SSH_PORTS" ]]; then
      SSH_PORTS=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
        | awk 'tolower($1)=="port"{print $2}' | sort -u | tr '\n' ' ' || true)
    fi
    SSH_PORTS=$(trim "${SSH_PORTS:-22}")
    [[ -n "$SSH_PORTS" ]] || SSH_PORTS=22
  fi
  SSH_PORTS=${SSH_PORTS//,/ }

  # Administradores: lista explícita + quien invoca + miembros de sudo/wheel/admin
  local u g admins="${ADMIN_USERS//,/ }"
  [[ -n "$INVOKING_USER" && "$INVOKING_USER" != root ]] && admins+=" $INVOKING_USER"
  for g in sudo wheel admin; do
    admins+=" $(getent group "$g" 2>/dev/null | awk -F: '{gsub(","," ",$4); print $4}' || true)"
  done
  ADMIN_USERS=$(tr ' ' '\n' <<<"$admins" | awk 'NF' | sort -u | tr '\n' ' ')
  ADMIN_USERS=$(trim "$ADMIN_USERS")

  ADMIN_KEY_USERS=""
  for u in $ADMIN_USERS; do
    if user_has_ssh_keys "$u"; then ADMIN_KEY_USERS+="$u "; fi
  done
  ADMIN_KEY_USERS=$(trim "$ADMIN_KEY_USERS")

  # ¿Enruta tráfico? (ip_forward=1, Docker, Kubernetes, libvirt...)
  case "$IS_ROUTER" in
    1) ROUTER_DETECTED=1 ;;
    0) ROUTER_DETECTED=0 ;;
    *) if [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" == 1 ]] || have docker || have kubelet \
          || [[ -d /etc/kubernetes || -d /var/lib/docker ]]; then ROUTER_DETECTED=1; fi ;;
  esac
}

user_home() { getent passwd "$1" | cut -d: -f6; }

user_has_ssh_keys() { # ¿tiene el usuario alguna clave pública válida?
  local h f
  h=$(user_home "$1") || return 1
  [[ -n "$h" ]] || return 1
  for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
    [[ -r "$f" ]] && grep -Eq '^[^#]*(ssh-(ed25519|rsa|dss)|ecdsa-sha2-|sk-)' "$f" && return 0
  done
  return 1
}

# Usuarios "humanos": UID >= UID_MIN, no nobody, con shell de login.
human_users() {
  getent passwd | awk -F: -v min="$UID_MIN_VAL" \
    '$3>=min && $3<65534 && $7!~/(nologin|false|sync|shutdown|halt)$/ {print $1}'
}

print_context() {
  log_info "Sistema: ${OS_NAME} (familia ${OS_FAMILY}, ${PKG_MGR:-sin gestor}), arquitectura ${ARCH}"
  log_info "systemd: $( ((HAS_SYSTEMD)) && echo sí || echo no) | contenedor: $( ((IN_CONTAINER)) && echo sí || echo no) | enrutador/Docker/K8s: $( ((ROUTER_DETECTED)) && echo sí || echo no)"
  log_info "Puertos SSH: ${SSH_PORTS} | IP de tu sesión SSH: ${SSH_CLIENT_IP:-ninguna (consola o no detectada)}"
  log_info "Administradores: ${ADMIN_USERS:-ninguno} | con claves SSH: ${ADMIN_KEY_USERS:-NINGUNO}"
  [[ -n "$ADMIN_IPS" ]] && log_info "IPs de administración: ${ADMIN_IPS}"
  return 0
}
