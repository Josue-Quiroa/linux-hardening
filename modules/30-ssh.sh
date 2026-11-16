# shellcheck shell=bash
# =============================================================================
# 30-ssh — Endurecimiento de OpenSSH SIN riesgo de quedarse fuera
#
# POR QUÉ: SSH es la puerta principal de un servidor. Fuentes: CIS 5.1.x,
# Mozilla OpenSSH guidelines, ssh-audit.com hardening guides (2024-2025),
# dev-sec ssh_hardening, DISA STIG.
#
# DISEÑO ANTI-BLOQUEO (lo más importante de este módulo):
#  1. Se usa un drop-in /etc/ssh/sshd_config.d/01-hardening.conf. En sshd gana
#     el PRIMER valor leído, por eso "01-" (antes que 50-cloud-init.conf, que a
#     menudo pone PasswordAuthentication yes).
#  2. Antes de escribir, se valida la configuración candidata con `sshd -t`.
#     Después de escribir se vuelve a validar; si falla, se restaura el backup.
#  3. Se verifica con `sshd -T` que el valor efectivo es el deseado.
#  4. PasswordAuthentication=no SOLO si existe un admin con authorized_keys.
#     PermitRootLogin=no SOLO si existe un admin no-root (sudo/wheel).
#  5. NUNCA se cambia el puerto. `reload` no corta las sesiones abiertas.
#  6. En RHEL los algoritmos los gobierna crypto-policies: se usa esa vía.
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 30 ssh 1 "Servidor OpenSSH"

SSHD_DROPIN_DIR=/etc/ssh/sshd_config.d
SSHD_DROPIN=$SSHD_DROPIN_DIR/01-hardening.conf
SSHD_MAIN=/etc/ssh/sshd_config

# Algoritmos preferidos (ssh-audit 2024/2025 + ML-KEM post-cuántico de OpenSSH 9.9+).
# Se intersectan con lo que soporta el binario instalado (ssh -Q).
SSH_PREF_KEX="mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group18-sha512 diffie-hellman-group-exchange-sha256 diffie-hellman-group16-sha512"
SSH_PREF_CIPHERS="chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes256-ctr aes192-ctr aes128-gcm@openssh.com aes128-ctr"
SSH_PREF_MACS="hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com"

declare -gA SSH_DESIRED=() SSH_WHY=()
# IDs estables por directiva (para reportes comparables entre ejecuciones/niveles)
SSH_ID_LIST=(PermitEmptyPasswords HostbasedAuthentication IgnoreRhosts PermitUserEnvironment
  MaxAuthTries LoginGraceTime LogLevel ClientAliveInterval ClientAliveCountMax UsePAM
  X11Forwarding PermitRootLogin Banner PasswordAuthentication KbdInteractiveAuthentication
  KexAlgorithms Ciphers MACs AllowTcpForwarding AllowAgentForwarding AllowStreamLocalForwarding
  PermitTunnel GatewayPorts MaxSessions MaxStartups AllowGroups RequiredRSASize AllowUsers)
ssh_id() { local i; for i in "${!SSH_ID_LIST[@]}"; do [[ "${SSH_ID_LIST[$i]}" == "$1" ]] && { printf 'SSH-%02d' $((i+1)); return; }; done; echo SSH-XX; }

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
# Metadatos de cada directiva del drop-in (ID estable = posición en SSH_ID_LIST)
_ssh_meta() { # _ssh_meta Directiva niveles riesgo "descripción" "puede romper"
  ctl_meta "$(ssh_id "$1")" "$2" cambio "$3" "recarga:sshd" "sshd: $4" "/etc/ssh/sshd_config.d/01-hardening.conf" "$5"
}
_ssh_meta PermitEmptyPasswords 1 bajo "PermitEmptyPasswords no" "Nada"
_ssh_meta HostbasedAuthentication 1 bajo "HostbasedAuthentication no" "Confianza por host heredada (.shosts)"
_ssh_meta IgnoreRhosts 1 bajo "IgnoreRhosts yes" "Nada"
_ssh_meta PermitUserEnvironment 1 bajo "PermitUserEnvironment no" "Entornos inyectados vía ~/.ssh/environment"
_ssh_meta MaxAuthTries 1 bajo "MaxAuthTries 4 (pánico: 3)" "Clientes con muchas claves en el agente (usar IdentitiesOnly)"
_ssh_meta LoginGraceTime 1 bajo "LoginGraceTime 60 (pánico: 30)" "Logins muy lentos (2FA manual)"
_ssh_meta LogLevel 1 bajo "LogLevel VERBOSE" "Más volumen de log"
_ssh_meta ClientAliveInterval 1 bajo "ClientAliveInterval 300" "Sesiones inactivas se cierran a los ~15 min sin respuesta"
_ssh_meta ClientAliveCountMax 1 bajo "ClientAliveCountMax 3" "Idem"
_ssh_meta UsePAM 1 bajo "UsePAM yes" "Nada"
_ssh_meta X11Forwarding 2 bajo "X11Forwarding no" "Aplicaciones gráficas remotas por ssh -X"
_ssh_meta PermitRootLogin 2 medio "PermitRootLogin prohibit-password (máximo: no, si hay admin no-root)" "Login de root con contraseña; en máximo, cualquier login directo de root"
_ssh_meta Banner 2 bajo "Banner /etc/issue.net" "Clientes automatizados que parsean la salida (raro)"
_ssh_meta PasswordAuthentication 2 alto "PasswordAuthentication no (sólo si un admin tiene authorized_keys)" "Usuarios que entran con contraseña"
_ssh_meta KbdInteractiveAuthentication 2 alto "KbdInteractiveAuthentication no" "Login por contraseña/OTP vía keyboard-interactive (se omite si hay 2FA)"
_ssh_meta KexAlgorithms 2 medio "KexAlgorithms modernos (ML-KEM/sntrup/curve25519/DH16-18) — Debian/Ubuntu" "Clientes SSH antiguos (PuTTY < 0.68, jsch/paramiko viejos, equipos de red)"
_ssh_meta Ciphers 2 medio "Ciphers sin CBC/3DES" "Clientes muy antiguos"
_ssh_meta MACs 2 medio "MACs sólo etm SHA-2" "Clientes muy antiguos"
_ssh_meta AllowTcpForwarding 3 medio "AllowTcpForwarding no" "Túneles ssh -L/-R, ProxyJump a través del host, VS Code Remote port forwarding"
_ssh_meta AllowAgentForwarding 3 medio "AllowAgentForwarding no" "ssh -A (saltos con tu agente)"
_ssh_meta AllowStreamLocalForwarding 3 bajo "AllowStreamLocalForwarding no" "Reenvío de sockets unix (docker remoto por ssh)"
_ssh_meta PermitTunnel 3 bajo "PermitTunnel no" "VPN improvisadas con ssh -w"
_ssh_meta GatewayPorts 3 bajo "GatewayPorts no" "Exponer reenvíos remotos a la red"
_ssh_meta MaxSessions 3 bajo "MaxSessions 4" "Multiplexación intensiva (ControlMaster con muchas sesiones, Ansible con muchos forks)"
_ssh_meta MaxStartups 3 bajo "MaxStartups 10:30:60" "Ráfagas de conexiones simultáneas (orquestadores)"
_ssh_meta AllowGroups 3 alto "AllowGroups (sólo si SSH_ALLOW_GROUPS está definido)" "Usuarios fuera de esos grupos"
_ssh_meta RequiredRSASize 3 medio "RequiredRSASize 3072" "Claves RSA de 1024/2048 bits"
_ssh_meta AllowUsers 4 alto "PÁNICO: AllowUsers = administradores" "Cualquier otro usuario por SSH"
ctl_meta SSH-90 1 cambio bajo "recarga:sshd" "Permisos de sshd_config y claves de host" "/etc/ssh/sshd_config, /etc/ssh/ssh_host_*" "Nada"
ctl_meta SSH-91 3 cambio bajo "recarga:sshd;afecta a conexiones nuevas" "Eliminar grupos Diffie-Hellman < 3072 bits" "/etc/ssh/moduli" "Clientes que sólo negocian DH-GEX débil"
ctl_meta SSH-92 2 cambio medio "reinicio;servicios que usan TLS/SSH la aplican al reiniciarse" "RHEL: crypto-policy DEFAULT (medio) / DEFAULT:NO-SHA1 (máximo)" \
  "/etc/crypto-policies/config (update-crypto-policies)" "Conexiones TLS/SSH a sistemas legacy con SHA-1 o claves cortas"
ctl_meta SSH-SG 2 aviso bajo ninguno "Salvaguardas anti-bloqueo aplicadas (directivas omitidas y por qué)" "-" "Nada"

SSH_ORDER=()
SSH_SKIPPED=""   # directivas omitidas por salvaguarda (se reportan)

ssh_supported_list() { # ssh_supported_list <kex|cipher|mac> <preferidos>
  local q=$1 a out="" sup
  sup=$(ssh -Q "$q" 2>/dev/null) || { echo ""; return 0; }
  for a in $2; do grep -qxF "$a" <<<"$sup" && out+="${out:+,}$a"; done
  echo "$out"
}

ssh_set() { # ssh_set <Directiva> <valor> <por qué>
  [[ -n "${SSH_DESIRED[$1]+x}" ]] || SSH_ORDER+=("$1")
  SSH_DESIRED[$1]=$2; SSH_WHY[$1]=$3
}

sshd_supports() { # ¿acepta sshd esta directiva? (p.ej. RequiredRSASize desde 9.4)
  local t; t=$(mktemp "${RUN_TMP:-/tmp}/sshdopt.XXXXXX")
  printf '%s %s\n' "$1" "$2" >"$t"
  sshd -t -f "$t" 2>&1 | grep -qiE 'Bad configuration option|Unsupported option|deprecated' && { rm -f "$t"; return 1; }
  rm -f "$t"; return 0
}

# Usuarios administradores no-root que podrán entrar si se restringe root
ssh_nonroot_admin_ok() {
  local u pw
  for u in $ADMIN_USERS; do
    [[ "$u" == root ]] && continue
    user_has_ssh_keys "$u" && return 0
    pw=$(getent shadow "$u" 2>/dev/null | cut -d: -f2)
    [[ -n "$pw" && "$pw" != \!* && "$pw" != \** ]] && return 0
  done
  return 1
}

ssh_build_desired() {
  ssh_set PermitEmptyPasswords no "nunca aceptar contraseñas vacías"
  ssh_set HostbasedAuthentication no "confianza por host (.rhosts/.shosts) es suplantable"
  ssh_set IgnoreRhosts yes "ignorar .rhosts heredados"
  ssh_set PermitUserEnvironment no "evita que el usuario inyecte LD_PRELOAD y similares"
  ssh_set MaxAuthTries 4 "limita intentos por conexión (fuerza bruta)"
  ssh_set LoginGraceTime 60 "cierra conexiones que no se autentican (DoS)"
  ssh_set LogLevel VERBOSE "registra la huella de la clave usada en cada login (forense)"
  ssh_set ClientAliveInterval 300 "detecta y cierra sesiones muertas"
  ssh_set ClientAliveCountMax 3 "junto con el anterior: ~15 min sin respuesta"
  ssh_set UsePAM yes "necesario para faillock, límites y auditoría de PAM"
  if (( LEVEL_NUM >= 2 )); then
    ssh_set X11Forwarding no "X11 forwarding expone el display del cliente"
    ssh_set PermitRootLogin prohibit-password "root sólo con clave, nunca con contraseña"
    ssh_set Banner /etc/issue.net "aviso legal previo al login (requisito CIS/STIG)"
    if user_has_ssh_keys root || [[ -n "$ADMIN_KEY_USERS" ]]; then
      if grep -RqsiE '^[[:space:]]*AuthenticationMethods.*keyboard-interactive' "$SSHD_MAIN" "$SSHD_DROPIN_DIR"; then
        SSH_SKIPPED+="PasswordAuthentication(2FA keyboard-interactive en uso) "
      else
        ssh_set PasswordAuthentication no "sólo claves: elimina la fuerza bruta de contraseñas"
        ssh_set KbdInteractiveAuthentication no "evita contraseñas vía keyboard-interactive"
      fi
    else
      SSH_SKIPPED+="PasswordAuthentication(ningún admin con authorized_keys: se mantendría el acceso por contraseña) "
    fi
    if is_debian; then
      local kex ciphers macs
      kex=$(ssh_supported_list kex "$SSH_PREF_KEX"); ciphers=$(ssh_supported_list cipher "$SSH_PREF_CIPHERS")
      macs=$(ssh_supported_list mac "$SSH_PREF_MACS")
      [[ -n "$kex" ]] && ssh_set KexAlgorithms "$kex" "sólo intercambio de claves moderno (incl. post-cuántico si existe)"
      [[ -n "$ciphers" ]] && ssh_set Ciphers "$ciphers" "sin CBC/3DES/arcfour"
      [[ -n "$macs" ]] && ssh_set MACs "$macs" "sólo MACs encrypt-then-MAC, sin SHA1/MD5"
    fi
  fi
  if (( LEVEL_NUM >= 3 )); then
    if ssh_nonroot_admin_ok; then
      ssh_set PermitRootLogin no "root nunca entra directamente: trazabilidad vía sudo"
    else
      SSH_SKIPPED+="PermitRootLogin=no(no hay admin no-root utilizable) "
    fi
    ssh_set AllowTcpForwarding no "evita usar el servidor como pivote/túnel"
    ssh_set AllowAgentForwarding no "un root comprometido podría usar tu agente SSH"
    ssh_set AllowStreamLocalForwarding no "idem para sockets unix"
    ssh_set PermitTunnel no "sin túneles tun/tap"
    ssh_set GatewayPorts no "los reenvíos no se exponen a la red"
    ssh_set MaxSessions 4 "limita multiplexación por conexión"
    ssh_set MaxStartups 10:30:60 "limita conexiones no autenticadas concurrentes"
    [[ -n "$SSH_ALLOW_GROUPS" ]] && ssh_set AllowGroups "${SSH_ALLOW_GROUPS//,/ }" "sólo estos grupos pueden entrar"
    if sshd_supports RequiredRSASize 3072; then ssh_set RequiredRSASize 3072 "rechaza claves RSA < 3072 bits"; fi
  fi
  if (( LEVEL_NUM >= 4 )); then
    ssh_set MaxAuthTries 3 "pánico: menos intentos"
    ssh_set LoginGraceTime 30 "pánico: menos tiempo para autenticarse"
    ssh_set ClientAliveInterval 120 "pánico: sesiones inactivas se cierran antes"
    ssh_set ClientAliveCountMax 2 "pánico"
    ssh_set MaxSessions 2 "pánico"
    ssh_set MaxStartups 3:50:10 "pánico"
    local allow="${ADMIN_KEY_USERS:-$ADMIN_USERS}"
    if [[ -n "$allow" ]]; then
      ssh_set AllowUsers "$allow" "pánico: sólo administradores pueden entrar"
    else
      SSH_SKIPPED+="AllowUsers(no se detectaron administradores) "
    fi
  fi
}

ssh_dropin_content() {
  local k
  echo "# Gestionado por harden.sh (nivel $(level_name "$LEVEL_NUM")) — $(date +%F)"
  echo "# En sshd gana el PRIMER valor leído: este archivo se llama 01-* para preceder"
  echo "# a otros drop-ins (p.ej. 50-cloud-init.conf). Rollback: borrar y recargar sshd."
  for k in "${SSH_ORDER[@]}"; do
    printf '\n# %s\n%s %s\n' "${SSH_WHY[$k]}" "$k" "${SSH_DESIRED[$k]}"
  done
}

# Valor efectivo según sshd -T (claves en minúsculas)
sshd_effective() { # sshd_effective <directiva> [archivo_config]
  local cfg=${2:-$SSHD_MAIN}
  sshd -T -f "$cfg" -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null \
    | awk -v k="${1,,}" 'tolower($1)==k {$1=""; sub(/^ /,""); v=(v=="" ? $0 : v" "$0)} END{print v}'
}

ssh_norm() { # normaliza valores equivalentes
  local v=${1,,}
  v=${v//without-password/prohibit-password}
  echo "${v// /,}"
}

ssh_preconditions() {
  have sshd || [[ -x /usr/sbin/sshd ]] || { note "openssh-server no instalado"; return 2; }
  is_root || { note "requiere root (sshd -T necesita leer las host keys)"; return 2; }
  return 0
}

ssh_directive_check() {
  local _SSHK=$_BKEY
  local rc=0; ssh_preconditions || rc=$?; (( rc == 0 )) || return "$rc"
  local want got
  want=$(ssh_norm "${SSH_DESIRED[$_SSHK]}")
  got=$(ssh_norm "$(sshd_effective "$_SSHK")")
  [[ "$got" == "$want" ]] || { note "actual='${got:-?}'"; return 1; }
  # Debe estar en nuestro drop-in (persistencia gestionada)
  grep -qiE "^${_SSHK}[[:space:]]" "$SSHD_DROPIN" 2>/dev/null || { note "efectivo pero no gestionado por el drop-in"; return 1; }
}

ssh_ensure_include() {
  # Algunas distros antiguas no incluyen sshd_config.d: se añade al PRINCIPIO.
  if ! grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_MAIN"; then
    { echo "# Añadido por harden.sh: cargar drop-ins (deben ir al principio)"
      echo "Include /etc/ssh/sshd_config.d/*.conf"
      cat "$SSHD_MAIN"; } | write_file "$SSHD_MAIN" 600
  fi
}

ssh_dropin_apply() {
  local tmpd svc k
  tmpd=$(mktemp -d "${RUN_TMP:-/tmp}/sshd.XXXXXX")
  ssh_dropin_content >"$tmpd/01-hardening.conf"
  printf 'Include %s\nInclude %s\n' "$tmpd/01-hardening.conf" "$SSHD_MAIN" >"$tmpd/candidate"
  # 1) Validar ANTES de tocar nada
  if ! sshd -t -f "$tmpd/candidate" 2>"$tmpd/err"; then
    note "configuración candidata inválida: $(head -n1 "$tmpd/err")"; rm -rf "$tmpd"; return 1
  fi
  # 2) Verificar que el valor efectivo será el esperado (nadie lo define antes)
  for k in "${_BFAILING[@]}"; do
    if [[ "$(ssh_norm "$(sshd_effective "$k" "$tmpd/candidate")")" != "$(ssh_norm "${SSH_DESIRED[$k]}")" ]]; then
      note "otra configuración tiene prioridad sobre $k (revisar $SSHD_MAIN y bloques Match)"
    fi
  done
  # 3) Escribir, validar de nuevo y recargar (o restaurar si falla)
  ssh_ensure_include
  write_file "$SSHD_DROPIN" 600 <"$tmpd/01-hardening.conf"
  rm -rf "$tmpd"
  (( DRY_RUN )) && return 0
  if ! sshd -t; then
    log_error "sshd -t falla tras el cambio: restaurando"
    if [[ -f "$BACKUP_DIR/files$SSHD_DROPIN" ]]; then cp -a "$BACKUP_DIR/files$SSHD_DROPIN" "$SSHD_DROPIN"; else rm -f "$SSHD_DROPIN"; fi
    return 1
  fi
  svc=$(ssh_service_name)
  svc_reload_or_restart "$svc" || svc_reload_or_restart "${svc}.service" || true
}

# --- Permisos de archivos SSH (CIS 5.1.1-5.1.3) --------------------------------
ssh_perms_check() {
  [[ -d /etc/ssh ]] || { note "sin /etc/ssh"; return 2; }
  local f bad=""
  perms_ok "$SSHD_MAIN" 600 root:root || bad+="$SSHD_MAIN "
  for f in /etc/ssh/ssh_host_*_key; do
    [[ -e "$f" ]] || continue
    if getent group ssh_keys >/dev/null && [[ "$(stat -c %G "$f")" == ssh_keys ]]; then
      perms_ok "$f" 640 root:ssh_keys || bad+="$f "
    else
      perms_ok "$f" 600 root:root || bad+="$f "
    fi
  done
  for f in /etc/ssh/ssh_host_*_key.pub; do [[ -e "$f" ]] && { perms_ok "$f" 644 root:root || bad+="$f "; }; done
  [[ -z "$bad" ]] || { note "$bad"; return 1; }
}
ssh_perms_apply() {
  local f
  ensure_perms "$SSHD_MAIN" 600 root:root
  for f in /etc/ssh/ssh_host_*_key; do
    [[ -e "$f" ]] || continue
    if getent group ssh_keys >/dev/null && [[ "$(stat -c %G "$f")" == ssh_keys ]]; then ensure_perms "$f" 640 root:ssh_keys
    else ensure_perms "$f" 600 root:root; fi
  done
  for f in /etc/ssh/ssh_host_*_key.pub; do [[ -e "$f" ]] && ensure_perms "$f" 644 root:root; done
  return 0
}

# --- Módulos DH pequeños (ssh-audit) ---------------------------------------------
moduli_check() {
  [[ -f /etc/ssh/moduli ]] || { note "sin /etc/ssh/moduli"; return 2; }
  local n; n=$(awk '$1!~/^#/ && NF>=5 && $5<3071' /etc/ssh/moduli | wc -l)
  (( n == 0 )) || { note "$n módulos < 3072 bits"; return 1; }
}
moduli_apply() {
  awk '$1~/^#/ || $5>=3071' /etc/ssh/moduli | write_file /etc/ssh/moduli 644
}

# --- RHEL crypto-policies (CIS RHEL 1.6.x) ----------------------------------------
cp_check() {
  is_rhel || return 2
  have update-crypto-policies || { note "crypto-policies no disponible"; return 2; }
  local cur; cur=$(update-crypto-policies --show 2>/dev/null)
  if (( LEVEL_NUM >= 3 )); then [[ "$cur" == *NO-SHA1* || "$cur" == FUTURE* ]] || { note "actual=$cur"; return 1; }
  else [[ "$cur" != LEGACY* ]] || { note "actual=$cur"; return 1; }; fi
}
cp_apply() {
  backup_file /etc/crypto-policies/config
  record_action CRYPTO_POLICY "$(update-crypto-policies --show 2>/dev/null || echo DEFAULT)"
  if (( LEVEL_NUM >= 3 )); then run_cmd update-crypto-policies --set DEFAULT:NO-SHA1
  else run_cmd update-crypto-policies --set DEFAULT; fi
  note "afecta a TODO el sistema (TLS, SSH, IPsec); los servicios lo cargan al reiniciarse"
  return 4
}

module_ssh() {
  local rc=0
  ssh_preconditions || rc=$?
  if (( rc == 2 )); then
    record_result SSH-00 1 OMITIDO "Servidor OpenSSH" "$(_take_note)"; return 0
  fi
  ssh_build_desired
  [[ -n "$SSH_SKIPPED" ]] && log_warn "SSH — omitido por salvaguarda anti-bloqueo: $SSH_SKIPPED"
  local k items=() order=()
  for k in "${SSH_ORDER[@]}"; do
    if in_list "$(ssh_id "$k")" "$SKIP_CONTROLS"; then
      record_result "$(ssh_id "$k")" 1 OMITIDO "sshd: $k" "excluido con --skip-control"; continue
    fi
    _safe_gate "$(ssh_id "$k")" 1 "sshd: $k" && continue   # --safe: fuera del drop-in
    order+=("$k")
    items+=("$(ssh_id "$k")|1|sshd: $k ${SSH_DESIRED[$k]:0:60}|$k")
  done
  SSH_ORDER=("${order[@]}")
  # El drop-in se valida y escribe UNA vez con todas las directivas pendientes
  control_batch ssh_directive_check ssh_dropin_apply "${items[@]}"
  local s
  for s in $SSH_SKIPPED; do
    record_result SSH-SG 2 OMITIDO "Salvaguarda anti-bloqueo: ${s%%(*}" "${s#*(}"
  done
  control SSH-90 1 "Permisos de sshd_config y claves de host" ssh_perms_check ssh_perms_apply
  control SSH-91 3 "Eliminar módulos Diffie-Hellman < 3072 bits" moduli_check moduli_apply
  control SSH-92 2 "Política criptográfica del sistema (RHEL): $( ((LEVEL_NUM>=3)) && echo DEFAULT:NO-SHA1 || echo 'no LEGACY')" cp_check cp_apply
}
