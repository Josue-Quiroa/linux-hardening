# shellcheck shell=bash
# =============================================================================
# 90-misc — Core dumps, Ctrl-Alt-Supr, banners, GRUB, hora, cron/at, compiladores
#
# POR QUÉ:
#  * Core dumps: pueden contener contraseñas/claves en memoria (CIS 1.5.x).
#  * Ctrl-Alt-Supr: reinicio accidental o desde consola sin credenciales (CIS/STIG).
#  * Banners: aviso legal (STIG) y NO revelar versión de SO (reconocimiento).
#  * grub.cfg legible sólo por root; contraseña de GRUB (manual, CIS 1.4.1).
#  * Hora sincronizada: sin ella los logs no sirven como evidencia.
#  * cron.allow/at.allow: sólo usuarios autorizados programan tareas (persistencia).
#  * Compiladores en producción facilitan compilar exploits localmente (Lynis HRDN-7222).
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 90 misc 1 "Core dumps, banners, GRUB, hora, cron/at"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta MSC-01 1 cambio bajo "sesion;procesos nuevos" "Core dumps deshabilitados" "/etc/security/limits.d/60-hardening.conf, /etc/systemd/coredump.conf.d/60-hardening.conf" "Depuración post-mortem con core dumps"
ctl_meta MSC-02 1 cambio bajo inmediato "Ctrl-Alt-Supr no reinicia" "ctrl-alt-del.target (mask)" "Reinicio desde teclado/consola virtual"
ctl_meta MSC-03 2 cambio bajo inmediato "Banners legales sin información del SO" "/etc/issue, /etc/issue.net, /etc/motd" "Nada"
ctl_meta MSC-04 2 cambio bajo inmediato "grub.cfg legible sólo por root" "/boot/grub/grub.cfg | /boot/grub2/grub.cfg" "Nada"
ctl_meta MSC-05 2 cambio bajo inmediato "Sincronización horaria activa" "chrony / systemd-timesyncd" "Nada (necesita salida NTP 123/udp)"
ctl_meta MSC-06 3 cambio medio inmediato "cron/at restringidos (cron.allow, at.allow)" "/etc/cron.allow, /etc/at.allow" "Crontabs de usuarios no listados"
ctl_meta MSC-07 3 aviso bajo ninguno "Contraseña en GRUB (manual)" "-" "Nada"
ctl_meta MSC-08 3 aviso bajo ninguno "Compiladores instalados" "-" "Nada"


LIMITS_FILE=/etc/security/limits.d/60-hardening.conf
COREDUMP_DROPIN=/etc/systemd/coredump.conf.d/60-hardening.conf

core_check() {
  file_has_line "$LIMITS_FILE" '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' || return 1
  if [[ -d /etc/systemd ]] && have coredumpctl; then file_has_line "$COREDUMP_DROPIN" '^Storage=none'; fi
}
core_apply() {
  printf '# Gestionado por harden.sh: sin core dumps (pueden contener secretos)\n*    hard    core    0\n' \
    | write_file "$LIMITS_FILE" 644
  if [[ -d /etc/systemd ]]; then
    printf '# Gestionado por harden.sh\n[Coredump]\nStorage=none\nProcessSizeMax=0\n' | write_file "$COREDUMP_DROPIN" 644
  fi
}

cad_check() { (( HAS_SYSTEMD )) || return 2; svc_masked ctrl-alt-del.target; }
cad_apply() { svc_mask ctrl-alt-del.target; }

BANNER_TEXT='AVISO: Sistema de uso exclusivo para personal autorizado.
Toda actividad puede ser monitorizada y registrada. El acceso o uso no
autorizado está prohibido y puede ser perseguido legalmente.
AUTHORIZED USE ONLY. All activity may be monitored and recorded.'
banner_check() {
  local f bad=""
  for f in /etc/issue /etc/issue.net; do
    [[ -f "$f" && "$(<"$f")" == "$BANNER_TEXT" ]] || bad+="$f "
  done
  if [[ -f /etc/motd ]] && grep -Eq '\\[mrsv]' /etc/motd; then bad+="/etc/motd "; fi
  [[ -z "$bad" ]] || { note "$bad"; return 1; }
}
banner_apply() {
  local f
  for f in /etc/issue /etc/issue.net; do printf '%s\n' "$BANNER_TEXT" | write_file "$f" 644; done
  if [[ -f /etc/motd ]] && grep -Eq '\\[mrsv]' /etc/motd; then sed -E 's/\\[mrsv]//g' /etc/motd | write_file /etc/motd 644; fi
  return 0
}

grub_cfgs() { local f; for f in /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/grub2/grubenv /boot/grub2/user.cfg; do [[ -f "$f" ]] && echo "$f"; done; return 0; }
grubperm_check() {
  local f bad="" n=0
  for f in $(grub_cfgs); do n=1; perms_ok "$f" 600 root:root || bad+="$f "; done
  (( n )) || { note "grub.cfg no encontrado (¿UEFI en vfat o sin GRUB?)"; return 2; }
  [[ -z "$bad" ]] || { note "$bad"; return 1; }
}
grubperm_apply() { local f; for f in $(grub_cfgs); do ensure_perms "$f" 600 root:root; done; return 0; }
grubpw_check() {
  local f; f=$(grub_cfgs | head -n1)
  [[ -n "$f" ]] || return 2
  [[ -r "$f" ]] || { note "requiere root"; return 2; }
  grep -qs 'password_pbkdf2' "$f" && return 0
  note "sin contraseña de GRUB: grub-mkpasswd-pbkdf2 (Debian) / grub2-setpassword (RHEL). Planificar acceso a consola."
  return 1
}

timesync_check() {
  (( HAS_SYSTEMD )) || return 2
  (( IN_CONTAINER )) && return 2
  svc_active chronyd || svc_active chrony || svc_active systemd-timesyncd || svc_active ntpd || svc_active ntpsec || { note "sin servicio de hora activo"; return 1; }
}
timesync_apply() {
  if is_rhel; then pkg_install chrony; svc_enable_now chronyd
  elif svc_exists systemd-timesyncd.service; then svc_enable_now systemd-timesyncd
  else pkg_install chrony; svc_enable_now chrony; fi
}

cronallow_users() { echo root; local u; for u in $ADMIN_USERS; do echo "$u"; done; }
cronallow_check() {
  local f bad=""
  for f in /etc/cron.allow /etc/at.allow; do
    [[ -f "$f" ]] || { bad+="$f(no existe) "; continue; }
    perms_ok "$f" 640 root:root || perms_ok "$f" 640 root:crontab || bad+="$f(permisos) "
  done
  [[ -z "$bad" ]] || { note "$bad"; return 1; }
}
cronallow_apply() {
  local f
  for f in /etc/cron.allow /etc/at.allow; do
    if [[ -f "$f" ]]; then ensure_perms "$f" 640 root:root
    else cronallow_users | sort -u | write_file "$f" 640; fi
  done
  note "sólo pueden usar cron/at: $(cronallow_users | sort -u | tr '\n' ' ')"
}

compilers_check() {
  local c l=""
  for c in gcc cc g++ clang make as; do have "$c" && l+="$c "; done
  [[ -z "$l" ]] || { note "presentes: $l(desinstalar o restringir a un grupo en producción)"; return 1; }
}

module_misc() {
  control MSC-01 1 "Core dumps deshabilitados" core_check core_apply
  control MSC-02 1 "Ctrl-Alt-Supr no reinicia el sistema" cad_check cad_apply
  control MSC-03 2 "Banners de aviso legal sin información del SO" banner_check banner_apply
  control MSC-04 2 "grub.cfg legible sólo por root" grubperm_check grubperm_apply
  control MSC-05 2 "Sincronización horaria activa" timesync_check timesync_apply
  control MSC-06 3 "cron/at restringidos (cron.allow, at.allow)" cronallow_check cronallow_apply
  advise  MSC-07 3 "Contraseña en el gestor de arranque (GRUB)" grubpw_check
  advise  MSC-08 3 "Compiladores instalados" compilers_check
}
