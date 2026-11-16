# shellcheck shell=bash
# =============================================================================
# 70-logging — journald persistente, auditd con reglas tipo CIS, logs remotos
#
# POR QUÉ: sin registros fiables no hay detección ni forense. Fuentes: CIS 6.2
# (journald/rsyslog) y 6.3 (auditd), DISA STIG, Lynis (LOGG-*, ACCT-9628).
#  basico : journald persistente y comprimido; permisos de /var/log
#  medio  : auditd + reglas CIS (identidad, sudo, hora, red, módulos, accesos
#           denegados, borrados, cambios de permisos, MAC, sesiones...)
#           + envío remoto si LOG_REMOTE_HOST está definido
#  maximo : auditd.conf conservador (no rota/borra logs), audit=1 en el kernel,
#           reglas INMUTABLES (-e 2: un atacante root no puede apagar la auditoría
#           sin reiniciar — y el reinicio queda registrado)
#  panico : registrar TODAS las ejecuciones (execve) para reconstruir el incidente
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 70 logging 1 "Registro (journald, auditd, logs remotos)"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta LOG-01 1 cambio bajo "recarga:systemd-journald" "journald persistente y comprimido" "/etc/systemd/journald.conf.d/60-hardening.conf, /var/log/journal" "Uso de disco en /var/log/journal (limitado)"
ctl_meta LOG-02 2 cambio bajo inmediato "Permisos restrictivos en /var/log" "/var/log/*" "Herramientas no root que leían logs (añadirlas al grupo adm)"
ctl_meta LOG-03 2 cambio bajo inmediato "auditd instalado y activo" "paquete auditd/audit, servicio auditd" "Agentes que usan el socket de auditoría (osquery, wazuh, algunos EDR) compiten con auditd"
ctl_meta LOG-04 2 cambio bajo "recarga:auditd;augenrules --load" "Reglas de auditoría tipo CIS" "/etc/audit/rules.d/60-hardening.rules" "Algo de CPU/disco en hosts con mucha actividad"
ctl_meta LOG-05 3 cambio medio "recarga:auditd" "auditd.conf: no rotar-borrar, avisar/suspender sin disco" "/etc/audit/auditd.conf" "Si se llena el disco de auditoría se suspende el registro (desviación consciente de CIS: halt)"
ctl_meta LOG-06 3 cambio bajo reinicio "audit=1 audit_backlog_limit=8192 en el arranque" "/etc/default/grub.d/60-hardening-audit.cfg + update-grub | grubby (RHEL)" "Nada habitual"
ctl_meta LOG-07 4 cambio medio "recarga:auditd" "PÁNICO: auditar todas las ejecuciones y conexiones" "/etc/audit/rules.d/61-hardening-panic.rules" "Mucho volumen de log y CPU en servidores con carga"
ctl_meta LOG-08 3 cambio alto "reinicio;las reglas quedan bloqueadas hasta reiniciar" "Reglas de auditoría inmutables (-e 2)" "/etc/audit/rules.d/99-hardening-finalize.rules" \
  "Cambiar reglas de auditd (incluido el rollback de reglas) exige reiniciar"
ctl_meta LOG-09 2 cambio bajo "recarga:rsyslog" "Envío de logs a servidor central (si LOG_REMOTE_HOST)" "/etc/rsyslog.d/60-hardening-remote.conf" "Tráfico de red hacia el servidor de logs (abrir en FW_ALLOW_OUT en máximo)"


JOURNALD_DROPIN=/etc/systemd/journald.conf.d/60-hardening.conf
AUDIT_RULES=/etc/audit/rules.d/60-hardening.rules
AUDIT_PANIC_RULES=/etc/audit/rules.d/61-hardening-panic.rules
AUDIT_FINAL_RULES=/etc/audit/rules.d/99-hardening-finalize.rules
AUDITD_CONF=/etc/audit/auditd.conf

# --- LOG-01 journald ----------------------------------------------------------
journald_content() {
  cat <<'CONF'
# Gestionado por harden.sh: logs persistentes entre reinicios (CIS 6.2.1.x).
[Journal]
Storage=persistent
Compress=yes
# Límite de disco para no llenar /var (ajustable)
SystemMaxUse=1G
CONF
}
journald_check() {
  (( HAS_SYSTEMD )) || { note "sin systemd"; return 2; }
  [[ -f "$JOURNALD_DROPIN" && "$(<"$JOURNALD_DROPIN")" == "$(journald_content)" ]] || return 1
  [[ -d /var/log/journal ]] || { note "/var/log/journal no existe aún"; return 1; }
}
journald_apply() {
  journald_content | write_file "$JOURNALD_DROPIN" 644
  if [[ ! -d /var/log/journal ]]; then
    if getent group systemd-journal >/dev/null; then run_cmd install -d -m 2755 -g systemd-journal /var/log/journal
    else run_cmd install -d -m 755 /var/log/journal; fi
    record_action NEWDIR /var/log/journal
  fi
  run_cmd systemctl restart systemd-journald
}

# --- LOG-02 permisos de /var/log ------------------------------------------------
varlog_bad() { find /var/log -type f \( -perm -o+r -o -perm -o+w -o -perm -g+w \) ! -name 'lastlog' ! -name 'wtmp*' ! -name 'btmp*' ! -name '*.journal*' 2>/dev/null | head -n 500 || true; }
varlog_check() { local n; n=$(varlog_bad | wc -l); (( n == 0 )) || { note "$n archivos con permisos laxos"; return 1; }; }
varlog_apply() { local f; while IFS= read -r f; do [[ -n "$f" ]] && run_cmd chmod g-wx,o-rwx "$f"; done < <(varlog_bad); return 0; }

# --- LOG-03 auditd instalado y activo ---------------------------------------------
audit_pkg() { if is_debian; then echo "auditd audispd-plugins"; else echo audit; fi; }
auditd_check() {
  (( IN_CONTAINER )) && { note "contenedor: auditd no funciona dentro"; return 2; }
  local p; for p in $(audit_pkg); do [[ "$p" == audispd-plugins ]] && continue; pkg_installed "$p" || { note "$p no instalado"; return 1; }; done
  (( HAS_SYSTEMD )) || return 0
  svc_enabled auditd && svc_active auditd
}
auditd_apply() {
  # shellcheck disable=SC2046
  pkg_install $(audit_pkg)
  (( HAS_SYSTEMD )) && svc_enable_now auditd
  return 0
}

# --- LOG-04 reglas de auditoría ------------------------------------------------------
audit_arches() { if [[ "$ARCH" == x86_64 ]]; then echo "b64 b32"; else echo b64; fi; }

audit_rules_content() {
  local a w p uidmin=$UID_MIN_VAL f
  echo "## Gestionado por harden.sh — reglas de auditoría tipo CIS (Ubuntu 24.04 / RHEL 9 sección 6.3.3)"
  echo "## Claves (-k) para buscar con: ausearch -k <clave> -i   |   aureport -k"
  echo "-b 8192"
  echo "-f 1"
  echo "## Cambios en sudoers (scope) y uso de sudo"
  for w in /etc/sudoers /etc/sudoers.d /var/log/sudo.log; do [[ -e "$w" || "$w" == /var/log/sudo.log ]] && echo "-w $w -p wa -k scope"; done
  for a in $(audit_arches); do
    echo "## [$a] Acciones ejecutadas como otro usuario (sudo/su)"
    echo "-a always,exit -F arch=$a -C euid!=uid -F auid!=4294967295 -S execve -k user_emulation"
    echo "## [$a] Cambios de fecha/hora"
    echo "-a always,exit -F arch=$a -S adjtimex,settimeofday,clock_settime -k time-change"
    echo "## [$a] Cambios de hostname/dominio"
    echo "-a always,exit -F arch=$a -S sethostname,setdomainname -k system-locale"
    echo "## [$a] Accesos denegados a archivos"
    echo "-a always,exit -F arch=$a -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$uidmin -F auid!=4294967295 -k access"
    echo "-a always,exit -F arch=$a -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$uidmin -F auid!=4294967295 -k access"
    echo "## [$a] Cambios de permisos/propietario/atributos"
    echo "-a always,exit -F arch=$a -S chmod,fchmod,fchmodat -F auid>=$uidmin -F auid!=4294967295 -k perm_mod"
    echo "-a always,exit -F arch=$a -S chown,fchown,lchown,fchownat -F auid>=$uidmin -F auid!=4294967295 -k perm_mod"
    echo "-a always,exit -F arch=$a -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$uidmin -F auid!=4294967295 -k perm_mod"
    echo "## [$a] Montajes"
    echo "-a always,exit -F arch=$a -S mount -F auid>=$uidmin -F auid!=4294967295 -k mounts"
    echo "## [$a] Borrados/renombrados por usuarios"
    echo "-a always,exit -F arch=$a -S rename,unlink,unlinkat,renameat -F auid>=$uidmin -F auid!=4294967295 -k delete"
    echo "## [$a] Carga/descarga de módulos del kernel"
    echo "-a always,exit -F arch=$a -S init_module,finit_module,delete_module -k kernel_modules"
  done
  echo "-w /etc/localtime -p wa -k time-change"
  echo "## Entorno de red"
  for w in /etc/issue /etc/issue.net /etc/hosts /etc/hostname /etc/network /etc/netplan /etc/NetworkManager /etc/sysconfig/network /etc/sysconfig/network-scripts; do
    [[ -e "$w" ]] && echo "-w $w -p wa -k system-locale"
  done
  echo "## Identidad (usuarios, grupos, PAM, NSS)"
  for w in /etc/group /etc/passwd /etc/gshadow /etc/shadow /etc/security/opasswd /etc/nsswitch.conf /etc/pam.conf /etc/pam.d; do
    [[ -e "$w" ]] && echo "-w $w -p wa -k identity"
  done
  echo "## Sesiones y logins"
  for w in /var/run/utmp /var/log/wtmp /var/log/btmp; do [[ -e "$w" ]] && echo "-w $w -p wa -k session"; done
  for w in /var/log/lastlog /var/run/faillock; do [[ -e "$w" ]] && echo "-w $w -p wa -k logins"; done
  echo "## Políticas MAC (AppArmor/SELinux)"
  for w in /etc/apparmor /etc/apparmor.d /etc/selinux /usr/share/selinux; do [[ -e "$w" ]] && echo "-w $w -p wa -k MAC-policy"; done
  echo "## Herramientas sensibles"
  for p in chcon setfacl chacl usermod kmod; do
    f=$(command -v "$p" 2>/dev/null || true)
    [[ -n "$f" ]] && echo "-a always,exit -F path=$(readlink -f "$f") -F perm=x -F auid>=$uidmin -F auid!=4294967295 -k perm_chng_$p"
  done
  echo "## Persistencia: cron, systemd, SSH"
  for w in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /var/spool/cron /etc/systemd/system /etc/ssh/sshd_config /etc/ssh/sshd_config.d /root/.ssh /etc/ld.so.preload; do
    [[ -e "$w" ]] && echo "-w $w -p wa -k persistence"
  done
  echo "## Ejecución de binarios privilegiados (SUID/SGID) por usuarios"
  { find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null || true; } | sort | head -n 300 | while IFS= read -r f; do
    echo "-a always,exit -F path=$f -F perm=x -F auid>=$uidmin -F auid!=4294967295 -k privileged"
  done || true
}
audit_rules_check() {
  (( IN_CONTAINER )) && { note "contenedor"; return 2; }
  [[ -f "$AUDIT_RULES" && "$(<"$AUDIT_RULES")" == "$(audit_rules_content)" ]] || { note "archivo de reglas ausente o desactualizado"; return 1; }
  if is_root && have auditctl && auditctl -s 2>/dev/null | grep -q 'enabled [12]'; then
    auditctl -l 2>/dev/null | grep -q 'key=identity' || { note "reglas no cargadas en el kernel"; return 1; }
  fi
}
audit_rules_apply() {
  # shellcheck disable=SC2046
  have auditctl || pkg_install $(audit_pkg)
  audit_rules_content | write_file "$AUDIT_RULES" 640
  audit_load
}
audit_load() {
  if is_root && have auditctl && auditctl -s 2>/dev/null | grep -q 'enabled 2'; then
    note "reglas inmutables cargadas (-e 2): los cambios se aplicarán tras REINICIAR"; return 4
  fi
  if have augenrules; then
    # augenrules regenera audit.rules (y deja audit.rules.prev): se respaldan para el rollback
    (( DRY_RUN )) || { backup_file /etc/audit/audit.rules; backup_file /etc/audit/audit.rules.prev; }
    run_cmd augenrules --load >/dev/null 2>&1 || { note "reglas escritas pero no cargadas ahora (¿auditd parado?); se cargarán al arrancar auditd"; return 4; }
  elif (( HAS_SYSTEMD )); then run_cmd systemctl restart auditd; fi
  return 0
}

# --- LOG-05 auditd.conf conservador -----------------------------------------------------
auditd_conf_wanted() {
  echo "max_log_file|32"
  echo "max_log_file_action|keep_logs"     # CIS: nunca borrar logs de auditoría
  echo "space_left_action|email"
  echo "action_mail_acct|root"
  # CIS L2 pide 'halt' o 'single'. Usamos 'suspend' para no apagar producción
  # por disco lleno: desviación DOCUMENTADA (cámbialo si tu política lo exige).
  echo "admin_space_left_action|suspend"
  echo "disk_full_action|suspend"
  echo "disk_error_action|syslog"
}
auditd_conf_check() {
  [[ -f "$AUDITD_CONF" ]] || { note "sin $AUDITD_CONF"; return 1; }
  local k v cur bad=""
  while IFS='|' read -r k v; do
    cur=$(get_config_value "$AUDITD_CONF" "$k" '[[:space:]]*=[[:space:]]*' 2>/dev/null || true)
    [[ "${cur,,}" == "${v,,}" ]] || bad+="$k=${cur:-?} "
  done < <(auditd_conf_wanted)
  [[ -z "$bad" ]] || { note "$bad"; return 1; }
}
auditd_conf_apply() {
  # shellcheck disable=SC2046
  [[ -f "$AUDITD_CONF" ]] || pkg_install $(audit_pkg)
  local k v
  while IFS='|' read -r k v; do set_config_value "$AUDITD_CONF" "$k" "$v" " = "; done < <(auditd_conf_wanted)
  # auditd no admite "systemctl restart" en RHEL: se usa service
  if (( HAS_SYSTEMD )); then run_cmd service auditd restart >/dev/null 2>&1 || note "reiniciar auditd manualmente"; fi
}

# --- LOG-06 audit=1 en el arranque -----------------------------------------------------
GRUB_DROPIN=/etc/default/grub.d/60-hardening-audit.cfg
KARGS="audit=1 audit_backlog_limit=8192"
bootaudit_check() {
  (( IN_CONTAINER )) && return 2
  grep -qw 'audit=1' /proc/cmdline && return 0
  note "audit=1 no está en la línea de comandos del kernel actual"
  return 1
}
bootaudit_apply() {
  if is_rhel && have grubby; then
    run_cmd grubby --update-kernel=ALL --args="$KARGS"
  elif [[ -d /etc/default/grub.d || -f /etc/default/grub ]]; then
    # shellcheck disable=SC2016  # $GRUB_CMDLINE_LINUX debe quedar literal en el archivo
    printf '# Gestionado por harden.sh: auditar procesos que arrancan antes que auditd\nGRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX %s"\n' "$KARGS" \
      | write_file "$GRUB_DROPIN" 644
    if have update-grub; then run_cmd update-grub
    elif have grub2-mkconfig; then run_cmd grub2-mkconfig -o /boot/grub2/grub.cfg
    else note "regenerar la configuración de GRUB manualmente"; fi
  else
    note "GRUB no detectado"; return 3
  fi
  return 4
}

# --- LOG-07 pánico: auditar TODAS las ejecuciones ----------------------------------------
panic_audit_content() {
  local a
  echo "## harden.sh PÁNICO: registrar toda ejecución de programas (alto volumen de logs)"
  for a in $(audit_arches); do
    echo "-a always,exit -F arch=$a -S execve,execveat -k panic_exec"
    echo "-a always,exit -F arch=$a -S connect -F a2!=110 -F success=1 -k panic_connect"
  done
}
panic_audit_check() {
  (( IN_CONTAINER )) && return 2
  [[ -f "$AUDIT_PANIC_RULES" && "$(<"$AUDIT_PANIC_RULES")" == "$(panic_audit_content)" ]]
}
panic_audit_apply() { panic_audit_content | write_file "$AUDIT_PANIC_RULES" 640; audit_load; }

# --- LOG-08 reglas inmutables ------------------------------------------------------------------
immutable_check() {
  (( IN_CONTAINER )) && return 2
  grep -qsx -- '-e 2' "$AUDIT_FINAL_RULES"
}
immutable_apply() {
  printf '## harden.sh: configuración de auditoría INMUTABLE hasta el próximo reinicio\n-e 2\n' \
    | write_file "$AUDIT_FINAL_RULES" 640
  audit_load || true
  note "a partir de ahora cambiar reglas de auditoría requiere reiniciar"
}

# --- LOG-09 envío remoto ---------------------------------------------------------------------
REMOTE_CONF=/etc/rsyslog.d/60-hardening-remote.conf
remote_check() {
  if [[ -z "$LOG_REMOTE_HOST" ]]; then
    grep -RqsE '^[^#]*(@@?[A-Za-z0-9]|omfwd)' /etc/rsyslog.conf /etc/rsyslog.d && return 0
    note "sin envío de logs a un servidor central (define LOG_REMOTE_HOST)"; return 1
  fi
  [[ -f "$REMOTE_CONF" ]] && grep -q "$LOG_REMOTE_HOST" "$REMOTE_CONF"
}
remote_apply() {
  [[ -n "$LOG_REMOTE_HOST" ]] || { note "define LOG_REMOTE_HOST=host:puerto en conf/hardening.conf"; return 3; }
  pkg_install rsyslog
  local host=${LOG_REMOTE_HOST%:*} port=${LOG_REMOTE_HOST##*:}
  [[ "$port" == "$LOG_REMOTE_HOST" ]] && port=514
  write_file "$REMOTE_CONF" 644 <<CONF
# Gestionado por harden.sh: copia de todos los logs a un servidor central (TCP,
# con cola en disco para no perder eventos si el servidor cae). Un atacante con
# root puede borrar logs LOCALES, no los ya enviados.
*.* action(type="omfwd" target="$host" port="$port" protocol="tcp"
           action.resumeRetryCount="-1" queue.type="LinkedList"
           queue.filename="harden_fwd" queue.saveOnShutdown="on")
CONF
  (( HAS_SYSTEMD )) && run_cmd systemctl restart rsyslog
  return 0
}

module_logging() {
  control LOG-01 1 "journald persistente y comprimido" journald_check journald_apply
  control LOG-02 2 "Permisos restrictivos en /var/log" varlog_check varlog_apply
  control LOG-03 2 "auditd instalado y activo" auditd_check auditd_apply
  control LOG-04 2 "Reglas de auditoría tipo CIS (identidad, sudo, red, módulos...)" audit_rules_check audit_rules_apply
  control LOG-05 3 "auditd.conf: no borrar logs, avisar/suspender si falta disco" auditd_conf_check auditd_conf_apply
  control LOG-06 3 "Auditoría desde el arranque (audit=1 audit_backlog_limit=8192)" bootaudit_check bootaudit_apply
  control LOG-07 4 "PÁNICO: auditar todas las ejecuciones y conexiones salientes" panic_audit_check panic_audit_apply
  control LOG-08 3 "Reglas de auditoría inmutables (-e 2)" immutable_check immutable_apply
  if [[ -n "$LOG_REMOTE_HOST" ]]; then control LOG-09 2 "Envío de logs a $LOG_REMOTE_HOST" remote_check remote_apply
  else advise LOG-09 2 "Envío de logs a un servidor central" remote_check; fi
}
