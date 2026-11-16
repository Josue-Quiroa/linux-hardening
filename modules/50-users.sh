# shellcheck shell=bash
# =============================================================================
# 50-users — Cuentas, contraseñas, PAM, sudo y permisos de archivos críticos
#
# POR QUÉ: credenciales débiles y permisos laxos son la vía más común de
# escalada. Fuentes: CIS 5.3-5.4 y 7.1 (Ubuntu 24.04 / RHEL 9), NIST SP 800-63B
# (longitud > complejidad; caducidad anual en vez de 90 días), DISA STIG.
#  basico : permisos de passwd/shadow/group/cron, sudo con log y use_pty,
#           UID 0 único, cuentas sin contraseña (informe)
#  medio  : pwquality (14+), faillock (5 intentos/15 min), login.defs (SHA512/
#           yescrypt, caducidad 365d), umask 027, bloquear cuentas sin contraseña
#  maximo : cuentas de sistema sin shell, inactividad 45d, su sólo para un
#           grupo, TMOUT, home 750, informe de SUID/SGID y archivos sin dueño
#  panico : bloqueo de cuentas humanas que no sean admin (incluye claves SSH),
#           faillock 3 intentos, opcionalmente cerrar sus sesiones
# PAM SE TOCA CON LAS HERRAMIENTAS OFICIALES (pam-auth-update / authselect),
# nunca editando /etc/pam.d a mano: es la forma de no romper el login.
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 50 users 1 "Usuarios, contraseñas, PAM, sudo y permisos"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta USR-01 1 cambio bajo inmediato "Permisos de passwd/shadow/group/gshadow" "/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow (+ copias -)" "Nada"
ctl_meta USR-02 1 cambio bajo inmediato "Permisos de crontab y /etc/cron.*" "/etc/crontab, /etc/cron.{d,daily,hourly,weekly,monthly}" "Usuarios no root que leían esos directorios"
ctl_meta USR-03 1 cambio bajo inmediato "sudo con use_pty y log propio" "/etc/sudoers.d/50-hardening (validado con visudo)" "Rarezas con sudo en pipelines sin TTY"
ctl_meta USR-04 1 aviso bajo ninguno "Sólo root con UID 0" "-" "Nada"
ctl_meta USR-05 1 cambio medio inmediato "Cuentas sin contraseña (básico: informe; medio+: bloqueo)" "/etc/shadow (passwd -l)" "Cuentas que entraban sin contraseña"
ctl_meta USR-06 2 cambio bajo sesion "Calidad de contraseñas pwquality (14+ caracteres)" "/etc/security/pwquality.conf.d/60-hardening.conf" "Cambios de contraseña con claves cortas o simples"
ctl_meta USR-07 2 cambio medio sesion "Bloqueo tras intentos fallidos (faillock 5/900 s; pánico 3/1800 s)" \
  "/etc/security/faillock.conf, pam-auth-update (Debian) / authselect with-faillock (RHEL), /etc/pam.d/*" "Usuarios bloqueados temporalmente; cuentas de servicio que fallan login en bucle"
ctl_meta USR-08 2 cambio bajo sesion "login.defs: yescrypt/SHA512, caducidad 365 d, UMASK 027" "/etc/login.defs" "Las contraseñas caducan a los 365 días (cuentas nuevas)"
ctl_meta USR-09 2 cambio bajo sesion "umask 027 en shells de login" "/etc/profile.d/60-hardening-umask.sh" "Archivos nuevos no legibles por 'otros' (web roots compartidos, grupos de trabajo)"
ctl_meta USR-10 3 cambio medio inmediato "Cuentas de sistema sin shell de login (excepto KEEP_SHELL_USERS)" "/etc/passwd (usermod -s nologin)" \
  "'su - postgres', scripts que hacen su a cuentas de servicio con shell"
ctl_meta USR-11 3 cambio bajo inmediato "Desactivar cuentas 45 días después de caducar la contraseña" "/etc/default/useradd, /etc/shadow (chage)" "Cuentas humanas olvidadas sin login"
ctl_meta USR-12 3 cambio medio sesion "su restringido a un grupo vacío (usar sudo)" "/etc/pam.d/su, grupo sugroup" "Usuarios que usan 'su' en lugar de sudo"
ctl_meta USR-13 3 cambio medio sesion "TMOUT=900 en shells interactivas" "/etc/profile.d/60-hardening-tmout.sh" "Sesiones de consola inactivas (screen/tmux recomendados)"
ctl_meta USR-14 3 cambio bajo inmediato "Directorios home con permisos 750" "/home/*" "Webs en ~/public_html, compartición entre usuarios"
ctl_meta USR-15 3 aviso bajo ninguno "Inventario de binarios SUID/SGID" "-" "Nada"
ctl_meta USR-16 3 aviso bajo ninguno "Archivos sin propietario/grupo válido" "-" "Nada"
ctl_meta USR-17 3 cambio medio inmediato "Quitar escritura global a archivos regulares" "archivos world-writable (chmod o-w)" "Aplicaciones que dependían de archivos escribibles por todos"
ctl_meta USR-18 2 aviso bajo ninguno "Reglas sudo NOPASSWD" "-" "Nada"
ctl_meta USR-19 4 cambio alto inmediato "PÁNICO: bloquear cuentas humanas no-admin (contraseña y claves)" "/etc/shadow (usermod -L -e 1)" "Todos los usuarios no administradores (y sus sesiones si PANIC_KILL_SESSIONS=1)"


# --- USR-01: permisos de archivos de cuentas (CIS 7.1.x) ----------------------
acct_files() { # ruta|modo_max|propietario
  local sg=root
  getent group shadow >/dev/null && sg=shadow
  echo "/etc/passwd|644|root:root"
  echo "/etc/passwd-|644|root:root"
  echo "/etc/group|644|root:root"
  echo "/etc/group-|644|root:root"
  if is_rhel; then
    echo "/etc/shadow|000|root:root"; echo "/etc/shadow-|000|root:root"
    echo "/etc/gshadow|000|root:root"; echo "/etc/gshadow-|000|root:root"
  else
    echo "/etc/shadow|640|root:$sg"; echo "/etc/shadow-|640|root:$sg"
    echo "/etc/gshadow|640|root:$sg"; echo "/etc/gshadow-|640|root:$sg"
  fi
  echo "/etc/security/opasswd|600|root:root"
}
acct_perms_check() {
  local l f m o bad=""
  while IFS='|' read -r f m o; do
    [[ -e "$f" ]] || continue
    perms_ok "$f" "$m" "$o" || bad+="$f($(stat -c '%a %U:%G' "$f")) "
  done < <(acct_files)
  [[ -z "$bad" ]] || { note "$bad"; return 1; }
}
acct_perms_apply() {
  local f m o
  while IFS='|' read -r f m o; do
    [[ -e "$f" ]] || continue
    perms_ok "$f" "$m" "$o" || ensure_perms "$f" "$m" "$o"
  done < <(acct_files)
}

# --- USR-02: cron y at sólo accesibles por root (CIS 2.4.1.x) -----------------
cron_paths() { echo "/etc/crontab|600"; local d; for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do echo "$d|700"; done; }
cron_perms_check() {
  local f m bad=""
  while IFS='|' read -r f m; do [[ -e "$f" ]] && { perms_ok "$f" "$m" root:root || bad+="$f "; }; done < <(cron_paths)
  [[ -z "$bad" ]] || { note "$bad"; return 1; }
}
cron_perms_apply() { local f m; while IFS='|' read -r f m; do [[ -e "$f" ]] && ensure_perms "$f" "$m" root:root; done < <(cron_paths); return 0; }

# --- USR-03: sudo con log propio y use_pty (CIS 5.2.x) --------------------------
SUDO_DROPIN=/etc/sudoers.d/50-hardening
sudo_check() {
  have sudo || have visudo || { note "sudo no instalado"; return 2; }
  [[ -f "$SUDO_DROPIN" ]] && grep -q 'use_pty' "$SUDO_DROPIN" && grep -q 'logfile' "$SUDO_DROPIN"
}
sudo_apply() {
  local tmp; tmp=$(mktemp "${RUN_TMP:-/tmp}/sudo.XXXXXX")
  cat >"$tmp" <<'CONF'
# Gestionado por harden.sh
# use_pty: un proceso lanzado con sudo no puede inyectar teclas en tu terminal tras salir.
Defaults use_pty
# Registro dedicado de TODO lo ejecutado con sudo (forense / auditoría).
Defaults logfile="/var/log/sudo.log"
# Pedir de nuevo la contraseña a los 5 minutos (valor por defecto explícito).
Defaults timestamp_timeout=5
CONF
  # Validar SIEMPRE con visudo antes de instalar: un sudoers roto deja sin sudo.
  if have visudo && ! visudo -cqf "$tmp"; then note "visudo rechazó el archivo"; rm -f "$tmp"; return 1; fi
  write_file "$SUDO_DROPIN" 440 <"$tmp"
  rm -f "$tmp"
  if have visudo && ! (( DRY_RUN )) && ! visudo -cq; then
    log_error "sudoers global inválido tras el cambio: restaurando"; rm -f "$SUDO_DROPIN"; return 1
  fi
}

# --- USR-04: un único UID 0 (CIS 5.4.2.1) ------------------------------------------
uid0_check() {
  local l; l=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | tr '\n' ' ')
  [[ -z "$l" ]] || { note "cuentas con UID 0 además de root: $l"; return 1; }
}

# --- USR-05: cuentas sin contraseña (CIS 7.2.2) -------------------------------------
empty_pw_users() { awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null; }
empty_pw_check() {
  [[ -r /etc/shadow ]] || { note "requiere root"; return 2; }
  local l; l=$(empty_pw_users | tr '\n' ' ')
  [[ -z "$l" ]] || { note "sin contraseña: $l"; return 1; }
}
empty_pw_apply() {
  local u
  backup_account_db
  for u in $(empty_pw_users); do record_action USER_LOCKED "$u"; run_cmd passwd -l "$u"; done
}

# --- USR-06: calidad de contraseñas (pwquality) -------------------------------------
PWQ_DROPIN=/etc/security/pwquality.conf.d/60-hardening.conf
pwq_content() {
  cat <<CONF
# Gestionado por harden.sh. NIST 800-63B y CIS: la LONGITUD es lo que más protege.
minlen = 14
minclass = $( ((LEVEL_NUM>=3)) && echo 4 || echo 3)
maxrepeat = 3
maxsequence = 3
dictcheck = 1
usercheck = 1
difok = 2
enforce_for_root
CONF
}
pwq_check() {
  local want; want=$(pwq_content)
  [[ -f "$PWQ_DROPIN" && "$(<"$PWQ_DROPIN")" == "$want" ]] || return 1
  if is_debian; then pkg_installed libpam-pwquality || return 1; fi
}
pwq_apply() {
  is_debian && pkg_install libpam-pwquality
  pwq_content | write_file "$PWQ_DROPIN" 644
}

# --- USR-07: bloqueo tras intentos fallidos (faillock) --------------------------------
faillock_values() { if (( LEVEL_NUM >= 4 )); then echo "3 1800"; else echo "5 900"; fi; }
faillock_check() {
  local deny unlock cur_deny cur_unlock
  read -r deny unlock <<<"$(faillock_values)"
  cur_deny=$(get_config_value /etc/security/faillock.conf deny '[[:space:]]*=[[:space:]]*' 2>/dev/null || true)
  cur_unlock=$(get_config_value /etc/security/faillock.conf unlock_time '[[:space:]]*=[[:space:]]*' 2>/dev/null || true)
  [[ "$cur_deny" == "$deny" && "$cur_unlock" == "$unlock" ]] || { note "deny=${cur_deny:-?} unlock_time=${cur_unlock:-?}"; return 1; }
  # Debe estar ACTIVO en la pila PAM
  if is_debian; then
    grep -qs 'pam_faillock.so' /etc/pam.d/common-auth || { note "pam_faillock no está en common-auth"; return 1; }
  else
    grep -qs 'pam_faillock.so' /etc/pam.d/system-auth || { note "pam_faillock no está en system-auth"; return 1; }
  fi
}
faillock_apply() {
  local deny unlock
  read -r deny unlock <<<"$(faillock_values)"
  [[ -f /etc/security/faillock.conf ]] || : | write_file /etc/security/faillock.conf 644
  set_config_value /etc/security/faillock.conf deny "$deny" " = "
  set_config_value /etc/security/faillock.conf unlock_time "$unlock" " = "
  set_config_value /etc/security/faillock.conf fail_interval 900 " = "
  if is_debian; then
    have pam-auth-update || { note "pam-auth-update no disponible"; return 3; }
    # Perfiles oficiales del CIS Ubuntu 24.04 (5.3.2.2): se activan con pam-auth-update
    write_file /usr/share/pam-configs/faillock 644 <<'PAM'
Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
PAM
    write_file /usr/share/pam-configs/faillock_notify 644 <<'PAM'
Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so
PAM
    backup_file /etc/pam.d/common-auth; backup_file /etc/pam.d/common-account
    run_cmd pam-auth-update --enable faillock faillock_notify
  else
    if have authselect && authselect current >/dev/null 2>&1; then
      backup_file /etc/authselect/authselect.conf
      run_cmd authselect enable-feature with-faillock
    else
      note "authselect no gestiona PAM en este sistema: activar pam_faillock manualmente"; return 3
    fi
  fi
  note "desbloquear un usuario: faillock --user USUARIO --reset"
}

# --- USR-08: login.defs (hash, caducidad, umask) ---------------------------------------
logindefs_wanted() {
  local hash=SHA512
  grep -qs yescrypt /etc/pam.d/common-password && hash=YESCRYPT
  echo "ENCRYPT_METHOD|$hash"
  echo "PASS_MAX_DAYS|365"
  echo "PASS_MIN_DAYS|1"
  echo "PASS_WARN_AGE|7"
  echo "UMASK|027"
  echo "LOG_OK_LOGINS|yes"
}
logindefs_check() {
  local k v cur bad=""
  while IFS='|' read -r k v; do
    cur=$(get_config_value /etc/login.defs "$k" 2>/dev/null || true)
    [[ "${cur^^}" == "${v^^}" ]] || bad+="$k=${cur:-?} "
  done < <(logindefs_wanted)
  [[ -z "$bad" ]] || { note "$bad"; return 1; }
}
logindefs_apply() {
  local k v
  while IFS='|' read -r k v; do set_config_value /etc/login.defs "$k" "$v" $'\t'; done < <(logindefs_wanted)
  note "caducidad: sólo afecta a contraseñas nuevas; usa 'chage' para las existentes"
}

# --- USR-09: umask por defecto en shells -------------------------------------------------
UMASK_FILE=/etc/profile.d/60-hardening-umask.sh
umask_check() { [[ -f "$UMASK_FILE" ]] && grep -q 'umask 027' "$UMASK_FILE"; }
umask_apply() {
  write_file "$UMASK_FILE" 644 <<'SH'
# Gestionado por harden.sh: archivos nuevos no legibles por "otros" (CIS 5.4.3.3).
umask 027
SH
}

# --- USR-10: cuentas de sistema sin shell de login (CIS 5.4.2.7) ----------------------------
sys_shell_users() {
  local nologin; nologin=$(command -v nologin || echo /usr/sbin/nologin)
  awk -F: -v min="$UID_MIN_VAL" -v nl="$nologin" \
    '$3<min && $1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $7!~/(nologin|false)$/ && $7!="" {print $1"|"$7}' /etc/passwd \
    | while IFS='|' read -r u sh; do in_list "$u" "$KEEP_SHELL_USERS" || printf '%s|%s\n' "$u" "$sh"; done
}
sys_shell_check() { local l; l=$(sys_shell_users | cut -d'|' -f1 | tr '\n' ' '); [[ -z "$l" ]] || { note "$l"; return 1; }; }
sys_shell_apply() {
  local u sh nologin; nologin=$(command -v nologin || echo /usr/sbin/nologin)
  backup_account_db
  while IFS='|' read -r u sh; do
    in_list "$u" "$ADMIN_USERS" && continue
    record_action USER_SHELL "$u" "$sh"
    run_cmd usermod -s "$nologin" "$u"
  done < <(sys_shell_users)
}

# --- USR-11: bloqueo por inactividad (CIS 5.4.1.5) -----------------------------------------
inactive_check() { [[ "$(useradd -D 2>/dev/null | awk -F= '/^INACTIVE/{print $2}')" =~ ^([1-9]|[1-3][0-9]|4[0-5])$ ]]; }
inactive_apply() {
  local m; m=$(stat -c '%a' /etc/default/useradd 2>/dev/null || echo 644)
  backup_account_db
  # useradd -D reescribe el archivo con el umask del proceso (077): se restaura el modo original
  ( umask 022; run_cmd useradd -D -f 45 )
  [[ -e /etc/default/useradd ]] && run_cmd chmod "$m" /etc/default/useradd
  return 0
}

# --- USR-12: su restringido a un grupo vacío (CIS 5.3.x pam_wheel) -------------------------
SU_GROUP=sugroup
su_check() { grep -Eqs "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group=${SU_GROUP}" /etc/pam.d/su; }
su_apply() {
  [[ -f /etc/pam.d/su ]] || { note "sin /etc/pam.d/su"; return 3; }
  if ! getent group "$SU_GROUP" >/dev/null; then
    backup_account_db
    run_cmd groupadd "$SU_GROUP"
    record_action GROUP_ADDED "$SU_GROUP"
  fi
  { echo "# harden.sh: sólo miembros de '${SU_GROUP}' (vacío) pueden usar su. Usa sudo."
    echo "auth required pam_wheel.so use_uid group=${SU_GROUP}"
    cat /etc/pam.d/su; } | write_file /etc/pam.d/su 644
  note "para permitir su a alguien: usermod -aG ${SU_GROUP} USUARIO"
}

# --- USR-13: TMOUT en shells interactivas ----------------------------------------------------
TMOUT_FILE=/etc/profile.d/60-hardening-tmout.sh
tmout_check() { [[ -f "$TMOUT_FILE" ]]; }
tmout_apply() {
  write_file "$TMOUT_FILE" 644 <<'SH'
# Gestionado por harden.sh: cerrar shells inactivas tras 15 min (CIS 5.4.3.2).
TMOUT=900
readonly TMOUT
export TMOUT
SH
}

# --- USR-14: directorios home 750 (CIS 7.2.9) -------------------------------------------------
home_bad() {
  local u h
  for u in $(human_users); do
    h=$(user_home "$u"); [[ -d "$h" ]] || continue
    perms_ok "$h" 750 || echo "$h"
  done
}
home_check() { local l; l=$(home_bad | tr '\n' ' '); [[ -z "$l" ]] || { note "$l"; return 1; }; }
home_apply() { local h; for h in $(home_bad); do ensure_perms "$h" 750; done; return 0; }

# --- USR-15/16: informes SUID/SGID y archivos sin dueño (sólo informe) -----------------------
suid_report() {
  local out="${RUN_DIR}/suid-sgid.txt"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m %u:%g %p\n' 2>/dev/null | sort >"$out" || true
  note "$(wc -l <"$out") binarios SUID/SGID listados en $out — revisar los no estándar"
  return 1
}
unowned_check() {
  local l; l=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 50 | tr '\n' ' ')
  [[ -z "$l" ]] || { note "${l:0:300}"; return 1; }
}
ww_check() {
  local l; l=$(find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -n 50 | tr '\n' ' ')
  [[ -z "$l" ]] || { note "archivos escribibles por todos: ${l:0:300}"; return 1; }
}
ww_apply() { local f; while IFS= read -r f; do [[ -n "$f" ]] && run_cmd chmod o-w "$f"; done < <(find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null || true); }

# --- PÁNICO: bloquear cuentas no-admin y cerrar sus sesiones -----------------------------------
lock_targets() {
  local u
  for u in $(human_users); do
    in_list "$u" "$ADMIN_USERS" && continue
    [[ "$u" == "$INVOKING_USER" ]] && continue
    # ya bloqueada y expirada -> no es objetivo
    if [[ "$(passwd -S "$u" 2>/dev/null | awk '{print $2}')" =~ ^(L|LK)$ ]] && \
       [[ "$(getent shadow "$u" | cut -d: -f8)" == 1 ]]; then continue; fi
    echo "$u"
  done
}
lock_check() {
  is_root || { note "requiere root"; return 2; }
  local l; l=$(lock_targets | tr '\n' ' ')
  [[ -z "$l" ]] || { note "cuentas a bloquear: $l"; return 1; }
}
lock_apply() {
  [[ -n "$ADMIN_USERS" ]] || { note "no hay administradores identificados: no se bloquea a nadie (usa --admin-user)"; return 3; }
  local u
  backup_account_db
  for u in $(lock_targets); do
    record_action USER_LOCKED "$u"
    # -L bloquea la contraseña; -e 1 expira la cuenta => PAM también rechaza claves SSH
    run_cmd usermod -L -e 1 "$u"
    if (( PANIC_KILL_SESSIONS )); then
      if have loginctl && (( HAS_SYSTEMD )); then run_cmd loginctl terminate-user "$u" || true
      else run_cmd pkill -KILL -u "$u" || true; fi
    fi
  done
  (( PANIC_KILL_SESSIONS )) || note "sesiones abiertas NO cerradas (PANIC_KILL_SESSIONS=1 para cerrarlas)"
}
nopasswd_check() {
  local l; l=$(grep -RlsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | tr '\n' ' ')
  [[ -z "$l" ]] || { note "reglas NOPASSWD en: $l (revisar: muy usadas para persistencia)"; return 1; }
}

module_users() {
  control USR-01 1 "Permisos de passwd/shadow/group/gshadow" acct_perms_check acct_perms_apply
  control USR-02 1 "Permisos de crontab y /etc/cron.* (sólo root)" cron_perms_check cron_perms_apply
  control USR-03 1 "sudo: use_pty y log en /var/log/sudo.log" sudo_check sudo_apply
  advise  USR-04 1 "Sólo root tiene UID 0" uid0_check
  if (( LEVEL_NUM == 1 )); then advise USR-05 1 "Ninguna cuenta sin contraseña" empty_pw_check
  else control USR-05 2 "Bloquear cuentas sin contraseña" empty_pw_check empty_pw_apply; fi
  control USR-06 2 "Calidad de contraseñas (pwquality: 14+ caracteres)" pwq_check pwq_apply
  control USR-07 2 "Bloqueo tras intentos fallidos (faillock $(faillock_values | awk '{print $1" intentos/"$2"s"}'))" faillock_check faillock_apply
  control USR-08 2 "login.defs: hash fuerte, caducidad 365d, UMASK 027" logindefs_check logindefs_apply
  control USR-09 2 "umask 027 en shells de login" umask_check umask_apply
  control USR-10 3 "Cuentas de sistema sin shell de login" sys_shell_check sys_shell_apply
  control USR-11 3 "Desactivar cuentas tras 45 días de contraseña caducada" inactive_check inactive_apply
  control USR-12 3 "su restringido a un grupo vacío (usar sudo)" su_check su_apply
  control USR-13 3 "TMOUT=900 en shells interactivas" tmout_check tmout_apply
  control USR-14 3 "Directorios home con permisos 750" home_check home_apply
  advise  USR-15 3 "Inventario de binarios SUID/SGID" suid_report
  advise  USR-16 3 "Archivos sin propietario/grupo válido" unowned_check
  control USR-17 3 "Archivos regulares escribibles por todos" ww_check ww_apply
  advise  USR-18 2 "Reglas sudo NOPASSWD" nopasswd_check
  control USR-19 4 "PÁNICO: bloquear cuentas humanas no-admin (contraseña y claves)" lock_check lock_apply
}
